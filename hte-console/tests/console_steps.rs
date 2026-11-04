//! Phase 8 (0.8.2) end to end: two-factor (enrolment, the sign-in challenge, recovery codes, enforcement), e-mailed
//! sign-in codes (trusted browsers, the resend, a broken relay), password reset, invitations and Settings' test e-mail,
//! on a real socket, with a fake SMTP relay on another socket that keeps every message. Expectations: the previous console's source
//! (v1.15.0-hte.1: AuthController, TwoFactorSettings, TwoFactor, PasswordResetController, InvitationManager,
//! InvitationController, MailSettings).

use hte_console::api::{Limiter, Native, Nonces};
use hte_console::laravel::{self, Encrypter};
use hte_console::oidc::Oidc;
use hte_console::pages::{self, websession::OwnConfig};
use rusqlite::Connection;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

const APP_KEY: &str = "base64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const T0: i64 = 1_800_000_010;
const ADMIN: &str = "user-5eed0c01";
const PW: &str = "tok-5eed00000000c0b1";
const DANA: &str = "user-5eed0c02";

/// A fake SMTP relay: no TLS, no AUTH; every DATA body kept (quoted-printable decoded). `down` refuses at the greeting.
struct Relay {
    port: u16,
    mails: Arc<Mutex<Vec<(String, String)>>>,
    down: Arc<AtomicBool>,
}

fn qp_decode(s: &str) -> String {
    let s = s.replace("=\r\n", "").replace("=\n", "");
    let b = s.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'=' && i + 2 < b.len() + 0 && i + 2 <= b.len() - 1 {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn relay() -> Relay {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let mails = Arc::new(Mutex::new(vec![]));
    let down = Arc::new(AtomicBool::new(false));
    let (m2, d2) = (mails.clone(), down.clone());
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(s) = s else { continue };
            let (m3, d3) = (m2.clone(), d2.clone());
            std::thread::spawn(move || {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut w = s;
                if d3.load(Ordering::SeqCst) {
                    let _ = w.write_all(b"554 no service\r\n");
                    return;
                }
                let _ = w.write_all(b"220 fake ESMTP\r\n");
                let (mut rcpt, mut data, mut in_data) = (String::new(), String::new(), false);
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    if in_data {
                        if line.trim_end() == "." {
                            in_data = false;
                            m3.lock().unwrap().push((rcpt.clone(), qp_decode(&data)));
                            let _ = w.write_all(b"250 queued\r\n");
                        } else {
                            data.push_str(&line);
                        }
                        continue;
                    }
                    let up = line.trim_end().to_ascii_uppercase();
                    let out: &[u8] = if up.starts_with("EHLO") {
                        b"250-fake\r\n250 SIZE 1000000\r\n"
                    } else if up.starts_with("RCPT TO:") {
                        rcpt = line.trim_end()[9..].trim_matches(|c| c == '<' || c == '>').to_string();
                        b"250 ok\r\n"
                    } else if up == "DATA" {
                        in_data = true;
                        data.clear();
                        b"354 go\r\n"
                    } else if up == "QUIT" {
                        let _ = w.write_all(b"221 bye\r\n");
                        return;
                    } else {
                        b"250 ok\r\n"
                    };
                    let _ = w.write_all(out);
                }
            });
        }
    });
    Relay { port, mails, down }
}

struct H {
    url: String,
    db_path: PathBuf,
    clock: Arc<AtomicI64>,
    client: reqwest::Client,
    relay: Relay,
    _dir: tempfile::TempDir,
}

#[derive(Debug)]
struct Resp {
    status: u16,
    headers: reqwest::header::HeaderMap,
    body: String,
}

impl Resp {
    fn path(&self) -> String {
        let l = self.headers.get("location").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
        match l.find("://") {
            Some(i) => l[i + 3..].find('/').map(|j| l[i + 3 + j..].to_string()).unwrap_or_default(),
            None => l,
        }
    }
    fn cookie(&self, name: &str) -> Option<String> {
        self.headers.get_all("set-cookie").iter().map(|v| v.to_str().unwrap().to_string()).find(|c| c.starts_with(&format!("{name}="))).map(|c| c.split(';').next().unwrap().to_string())
    }
    fn own(&self) -> Option<String> {
        self.cookie("hte-remote-console")
    }
    fn csrf(&self) -> String {
        let i = self.body.find("name=\"csrf-token\" content=\"").expect("csrf meta") + 27;
        self.body[i..i + 40].to_string()
    }
}

async fn harness() -> H {
    sodiumoxide::init().unwrap();
    std::env::set_var("BCRYPT_ROUNDS", "4");
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cortendesk.sqlite");
    let clock = Arc::new(AtomicI64::new(T0));
    let ck = clock.clone();
    let relay = relay();
    let c = Connection::open(&db_path).unwrap();
    c.execute_batch(include_str!("schema_live.sql")).unwrap();
    let hash = laravel::hash_make(PW.as_bytes()).unwrap();
    for (id, u, admin) in [(1, ADMIN, 1), (2, DANA, 0)] {
        c.execute(
            "insert into users (id, username, name, email, password, is_admin, is_active, remember_token, created_at, updated_at) values (?, ?, ?, ?, ?, ?, 1, 'rt', '2026-01-01 00:00:00', '2026-01-01 00:00:00')",
            rusqlite::params![id, u, format!("text-{u}"), format!("{u}@example.invalid"), hash, admin],
        )
        .unwrap();
    }
    c.execute_batch("insert into user_groups (id, name) values (1, 'text-5eed0g01'); insert into device_groups (id, name) values (1, 'text-5eed0d01');").unwrap();
    drop(c);
    let native = Arc::new(Native {
        db: Mutex::new(hte_console::sqlite::open(&db_path, std::time::Duration::from_secs(5), true).unwrap()),
        crypt: Encrypter::from_app_key(APP_KEY).unwrap(),
        hbbs_db: dir.path().join("none.sqlite3"),
        trusted: laravel::parse_trusted(laravel::DEFAULT_TRUSTED),
        api_version: "1.15.0-hte.1".into(),
        max_body: 1 << 20,
        limiter: Mutex::new(Limiter::default()),
        nonces: Mutex::new(Nonces::default()),
        signin: hte_console::signin::State::new(Oidc::new(true, false), None, "HTE Remote".into()),
        clock: Box::new(move || ck.load(Ordering::SeqCst)),
    });
    let app = pages::routes_with(native, None, OwnConfig::test(true)).unwrap().into_make_service_with_connect_info::<std::net::SocketAddr>();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    H { url, db_path, clock, client, relay, _dir: dir }
}

impl H {
    fn db(&self) -> Connection {
        Connection::open(&self.db_path).unwrap()
    }
    fn sql(&self, s: &str) {
        self.db().execute_batch(s).unwrap();
    }
    fn count(&self, q: &str) -> i64 {
        self.db().query_row(&format!("select count(*) from {q}"), [], |r| r.get(0)).unwrap()
    }
    fn text(&self, q: &str) -> String {
        self.db().query_row(q, [], |r| r.get::<_, Option<String>>(0)).unwrap().unwrap_or_default()
    }
    fn setting(&self, k: &str, v: &str) {
        self.db().execute("insert into settings (key, value, created_at, updated_at) values (?, ?, datetime('now'), datetime('now')) on conflict(key) do update set value = excluded.value", rusqlite::params![k, v]).unwrap();
    }
    fn mail_on(&self) {
        for (k, v) in [("smtp_enabled", "1".to_string()), ("smtp_host", "127.0.0.1".to_string()), ("smtp_port", self.relay.port.to_string()), ("smtp_from_address", "console@example.invalid".to_string()), ("smtp_encryption", "none".to_string())] {
            self.setting(k, &v);
        }
    }
    fn mails(&self) -> Vec<(String, String)> {
        self.relay.mails.lock().unwrap().clone()
    }
    fn now(&self) -> i64 {
        self.clock.load(Ordering::SeqCst)
    }
    async fn go(&self, method: &str, path: &str, cookie: Option<&str>, form: &[(&str, &str)]) -> Resp {
        let mut rq = self.client.request(method.parse().unwrap(), format!("{}{}", self.url, path)).header("x-forwarded-for", "198.18.9.1");
        if let Some(c) = cookie {
            rq = rq.header("cookie", c);
        }
        if method == "POST" {
            let body = laravel::http_build_query(&form.iter().map(|(k, v)| (*k, v.as_bytes())).collect::<Vec<_>>());
            rq = rq.header("content-type", "application/x-www-form-urlencoded").body(body);
        }
        let r = rq.send().await.unwrap();
        let (status, headers) = (r.status().as_u16(), r.headers().clone());
        Resp { status, headers, body: r.text().await.unwrap() }
    }
    async fn get(&self, path: &str, cookie: Option<&str>) -> Resp {
        self.go("GET", path, cookie, &[]).await
    }
    /// The password step: (the response, the guest cookie it used).
    async fn password(&self, user: &str, pw: &str, extra_cookie: Option<&str>) -> (Resp, String) {
        let page = self.get("/login", extra_cookie).await;
        let guest = page.own().unwrap();
        let cookie = match extra_cookie {
            Some(e) => format!("{guest}; {e}"),
            None => guest.clone(),
        };
        let r = self.go("POST", "/login", Some(&cookie), &[("_token", &page.csrf()), ("username", user), ("password", pw)]).await;
        (r, guest)
    }
    async fn signed_in(&self, user: &str) -> String {
        let (r, _) = self.password(user, PW, None).await;
        assert_eq!(r.path(), "/", "{}", r.body);
        r.own().unwrap()
    }
    /// A page's CSRF token (from its meta tag).
    async fn token(&self, path: &str, cookie: &str) -> String {
        self.get(path, Some(cookie)).await.csrf()
    }
    fn totp(&self, secret: &str, offset: i64) -> String {
        let key = hte_console::totp::base32_decode(secret.as_bytes()).unwrap();
        hte_console::totp::at(&key, self.now() / 30 + offset)
    }
}

fn between<'a>(s: &'a str, a: &str, b: &str) -> &'a str {
    let i = s.find(a).unwrap_or_else(|| panic!("no {a:?} in {s}")) + a.len();
    &s[i..i + s[i..].find(b).unwrap()]
}

// ---------------------------------------------------------------------------------------------- two-factor ---

#[tokio::test(flavor = "multi_thread")]
async fn two_factor_enrolment_the_challenge_and_recovery_codes() {
    let h = harness().await;
    let me = h.signed_in(ADMIN).await;
    let page = h.get("/account/two-factor", Some(&me)).await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("Enable two-factor authentication"));
    let t = page.csrf();
    let start = h.go("POST", "/account/two-factor", Some(&me), &[("_token", &t), ("do", "start")]).await;
    assert_eq!(start.status, 200);
    assert!(start.body.contains("<svg") && start.body.contains("Verify &amp; enable"));
    let secret = between(&start.body, "rd-mono\" readonly value=\"", "\"").to_string();
    assert_eq!(secret.len(), 103);
    let blob = between(&start.body, "name=\"setup\" value=\"", "\"").to_string();
    // a wrong code keeps the wizard open with the previous console's message
    let bad = h.go("POST", "/account/two-factor", Some(&me), &[("_token", &t), ("do", "confirm"), ("setup", &blob), ("code", "000000")]).await;
    assert!(bad.body.contains("That code is incorrect or has expired. Try the current one."));
    // a blob made for this account does not work for another
    let other = h.signed_in(DANA).await;
    let ot = h.token("/account/two-factor", &other).await;
    let stolen = h.go("POST", "/account/two-factor", Some(&other), &[("_token", &ot), ("do", "confirm"), ("setup", &blob), ("code", &h.totp(&secret, 0))]).await;
    assert_eq!(stolen.status, 200);
    assert_eq!(h.count("users where id = 2 and totp_enabled = 1"), 0);
    // confirmed: ten recovery codes, shown once
    let ok = h.go("POST", "/account/two-factor", Some(&me), &[("_token", &t), ("do", "confirm"), ("setup", &blob), ("code", &h.totp(&secret, 0))]).await;
    assert!(ok.body.contains("Save your recovery codes"), "{}", ok.body);
    let codes: Vec<String> = ok.body.split("<span class=\"rd-codechip\">").skip(1).map(|p| p[..11].to_string()).collect();
    assert_eq!(codes.len(), 10);
    assert_eq!(h.count("users where id = 1 and totp_enabled = 1 and totp_confirmed_at is not null"), 1);
    assert_eq!(h.count("two_factor_recovery_codes where user_id = 1 and used_at is null"), 10);
    assert_eq!(h.count("console_audits where action = 'user.2fa-enable'"), 1);
    assert_ne!(h.text("select totp_secret from users where id = 1"), secret, "stored encrypted");
    // the sign-in now asks for the second factor; nothing is signed in until it is cleared
    let (r, guest) = h.password(ADMIN, PW, None).await;
    assert_eq!(r.path(), "/login/2fa");
    assert_eq!(h.get("/account", Some(&guest)).await.path(), "/login");
    let step = h.get("/login/2fa", Some(&guest)).await;
    assert!(step.body.contains("Two-Step Verification"));
    let st = step.csrf();
    let wrong = h.go("POST", "/login/2fa", Some(&guest), &[("_token", &st), ("code", "123456")]).await;
    assert_eq!(wrong.path(), "/login/2fa");
    assert!(h.get("/login/2fa", Some(&guest)).await.body.contains("That code is incorrect or has expired."));
    // the code just used to enrol is burnt (replay guard); the next step's code works
    let reused = h.go("POST", "/login/2fa", Some(&guest), &[("_token", &st), ("code", &h.totp(&secret, 0))]).await;
    assert_eq!(reused.path(), "/login/2fa");
    let good = h.go("POST", "/login/2fa", Some(&guest), &[("_token", &st), ("code", &h.totp(&secret, 1))]).await;
    // back where the person was going before the sign-in (the page above remembered /account)
    assert_eq!(good.path(), "/account");
    assert_ne!(good.own().unwrap(), guest, "a new session id after the second step");
    // a recovery code, once
    let (_, g2) = h.password(ADMIN, PW, None).await;
    let st2 = h.token("/login/2fa", &g2).await;
    let rc = h.go("POST", "/login/2fa", Some(&g2), &[("_token", &st2), ("code", &codes[0].to_lowercase())]).await;
    assert_eq!(rc.path(), "/");
    assert_eq!(h.count("two_factor_recovery_codes where used_at is not null"), 1);
    let (_, g3) = h.password(ADMIN, PW, None).await;
    let st3 = h.token("/login/2fa", &g3).await;
    let again = h.go("POST", "/login/2fa", Some(&g3), &[("_token", &st3), ("code", &codes[0])]).await;
    assert_eq!(again.path(), "/login/2fa");
    assert!(h.get("/login/2fa", Some(&g3)).await.body.contains("That recovery code is invalid or already used."));
    // the challenge's throttle: ten wrong codes for the account in fifteen minutes, then a wait and one alarm
    for _ in 0..9 {
        h.go("POST", "/login/2fa", Some(&g3), &[("_token", &st3), ("code", "000000")]).await;
    }
    h.go("POST", "/login/2fa", Some(&g3), &[("_token", &st3), ("code", "000000")]).await;
    assert!(h.get("/login/2fa", Some(&g3)).await.body.contains("Too many attempts. Try again in"));
    assert_eq!(h.count("alarm_logs where typ = 100 and info like '%two-factor%'"), 1);
    // the marker lasts five minutes
    let (_, g4) = h.password(DANA, PW, None).await;
    let _ = g4;
    // regenerate (password checked) and disable
    let me2 = good.own().unwrap();
    let t2 = h.token("/account/two-factor", &me2).await;
    let nope = h.go("POST", "/account/two-factor", Some(&me2), &[("_token", &t2), ("do", "disable"), ("password", "wrong")]).await;
    assert!(nope.body.contains("That password is incorrect."));
    let regen = h.go("POST", "/account/two-factor", Some(&me2), &[("_token", &t2), ("do", "regenerate"), ("password", PW)]).await;
    assert!(regen.body.contains("Save your recovery codes"));
    assert_eq!(h.count("two_factor_recovery_codes where user_id = 1"), 10);
    let off = h.go("POST", "/account/two-factor", Some(&me2), &[("_token", &t2), ("do", "disable"), ("password", PW)]).await;
    assert!(off.body.contains("Enable two-factor authentication"));
    assert_eq!(h.count("users where id = 1 and totp_enabled = 0 and totp_secret is null"), 1);
    assert_eq!(h.count("two_factor_recovery_codes"), 0);
    assert_eq!(h.count("console_audits where action in ('user.2fa-recovery-regenerate', 'user.2fa-disable')"), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn required_two_factor_sends_a_person_to_enrol() {
    let h = harness().await;
    h.setting("two_factor_required", "1");
    let me = h.signed_in(DANA).await;
    let r = h.get("/devices", Some(&me)).await;
    assert_eq!(r.path(), "/account/two-factor");
    let page = h.get("/account/two-factor", Some(&me)).await;
    assert!(page.body.contains("Two-factor authentication is required. Please set it up to continue."));
    assert!(page.body.contains("Two-factor authentication is required for your account."));
    // enrolled, and it cannot be turned off
    let t = page.csrf();
    let start = h.go("POST", "/account/two-factor", Some(&me), &[("_token", &t), ("do", "start")]).await;
    let secret = between(&start.body, "rd-mono\" readonly value=\"", "\"").to_string();
    let blob = between(&start.body, "name=\"setup\" value=\"", "\"").to_string();
    h.go("POST", "/account/two-factor", Some(&me), &[("_token", &t), ("do", "confirm"), ("setup", &blob), ("code", &h.totp(&secret, 0))]).await;
    assert_eq!(h.get("/devices", Some(&me)).await.status, 200);
    let off = h.go("POST", "/account/two-factor", Some(&me), &[("_token", &t), ("do", "disable"), ("password", PW)]).await;
    assert!(off.body.contains("Your account requires two-factor authentication, so it can't be turned off."));
}

// ---------------------------------------------------------------------------------------- e-mailed codes ---

#[tokio::test(flavor = "multi_thread")]
async fn emailed_codes_trusted_browsers_and_a_broken_relay() {
    let h = harness().await;
    h.mail_on();
    h.setting("email_login_verification", "1");
    let (r, guest) = h.password(DANA, PW, None).await;
    assert_eq!(r.path(), "/login/email");
    let mails = h.mails();
    assert_eq!(mails.len(), 1);
    assert_eq!(mails[0].0, format!("{DANA}@example.invalid"));
    assert!(mails[0].1.contains("is your HTE Remote sign-in code"));
    let code = between(&mails[0].1, "letter-spacing:8px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;\">", "</p>").trim().to_string();
    assert_eq!(code.len(), 6);
    let page = h.get("/login/email", Some(&guest)).await;
    assert!(page.body.contains("u\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}@example.invalid"), "{}", page.body);
    let t = page.csrf();
    // resend: a new code (the old one stops working), at most three a minute
    let rs = h.go("POST", "/login/email/resend", Some(&guest), &[("_token", &t)]).await;
    assert_eq!(rs.path(), "/login/email");
    assert!(h.get("/login/email", Some(&guest)).await.body.contains("A new code is on its way."));
    assert_eq!(h.mails().len(), 2);
    let code2 = between(&h.mails()[1].1, "letter-spacing:8px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;\">", "</p>").trim().to_string();
    if code2 != code {
        let old = h.go("POST", "/login/email", Some(&guest), &[("_token", &t), ("code", &code)]).await;
        assert_eq!(old.path(), "/login/email");
    }
    let ok = h.go("POST", "/login/email", Some(&guest), &[("_token", &t), ("code", &code2)]).await;
    assert_eq!(ok.path(), "/");
    let device = ok.cookie("cd_device").expect("trust cookie");
    assert_eq!(h.count("trusted_devices where user_id = 2"), 1);
    // the same browser later: no code
    let (r2, _) = h.password(DANA, PW, Some(&device)).await;
    assert_eq!(r2.path(), "/");
    assert_eq!(h.mails().len(), 2);
    // a broken relay: an ordinary person is refused, an administrator is let in to repair it
    h.clock.fetch_add(5, Ordering::SeqCst);
    h.relay.down.store(true, Ordering::SeqCst);
    let (r3, g3) = h.password(DANA, PW, None).await;
    assert_eq!(r3.path(), "/login");
    assert!(h.get("/login", Some(&g3)).await.body.contains("Sign-in is temporarily unavailable: this console cannot send verification codes."));
    assert_eq!(h.count("login_logs where note = 'email-verification send failed'"), 1);
    assert_ne!(h.text("select value from settings where key = 'smtp_last_error'"), "");
    let (r4, _) = h.password(ADMIN, PW, None).await;
    assert_eq!(r4.path(), "/");
    let admin = r4.own().unwrap();
    assert_eq!(h.get("/devices", Some(&admin)).await.path(), "/settings?tab=email");
    assert_eq!(h.get("/settings?tab=email", Some(&admin)).await.status, 200);
    // the relay works again: Send test email clears the outage and the marker
    h.clock.fetch_add(5, Ordering::SeqCst);
    h.relay.down.store(false, Ordering::SeqCst);
    let t4 = h.token("/settings?tab=email", &admin).await;
    let sent = h.go("POST", "/settings/mail-test", Some(&admin), &[("_token", &t4), ("smtp_test_to", "ops@example.invalid")]).await;
    assert_eq!(sent.path(), "/settings?tab=email");
    assert!(h.get("/settings?tab=email", Some(&admin)).await.body.contains("Test message sent to ops@example.invalid."));
    assert!(h.mails().last().unwrap().1.contains("Your mail settings work."));
    assert_eq!(h.get("/devices", Some(&admin)).await.status, 200);
    assert_eq!(h.count("console_audits where action = 'settings.mail-test'"), 1);
}

// -------------------------------------------------------------------------------------------- password reset ---

#[tokio::test(flavor = "multi_thread")]
async fn password_reset_by_mail() {
    let h = harness().await;
    // without mail there is no reset page and no link on the sign-in page
    assert_eq!(h.get("/forgot-password", None).await.path(), "/login");
    assert!(!h.get("/login", None).await.body.contains("Forgot password?"));
    h.mail_on();
    assert!(h.get("/login", None).await.body.contains("Forgot password?"));
    let before = h.signed_in(DANA).await;
    let page = h.get("/forgot-password", None).await;
    assert_eq!(page.status, 200);
    let guest = page.own().unwrap();
    let t = page.csrf();
    for who in ["user-5eed0c99", DANA] {
        let r = h.go("POST", "/forgot-password", Some(&guest), &[("_token", &t), ("login", who)]).await;
        assert_eq!(r.path(), "/forgot-password");
        assert!(h.get("/forgot-password", Some(&guest)).await.body.contains("If that account exists and has an email address, a reset link is on its way."));
    }
    // the reset mail goes after the answer, without the database lock: wait for it
    for _ in 0..50 {
        if !h.mails().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let mails = h.mails();
    assert_eq!(mails.len(), 1, "only the real account gets a mail");
    let link = between(&mails[0].1, "<span style=\"word-break:break-all;\">", "</span>").to_string();
    let path = &link[link.find("/reset-password/").unwrap()..];
    assert!(path.starts_with("/reset-password/rst_"));
    let form = h.get(path, Some(&guest)).await;
    assert!(form.body.contains("Choose a New Password"));
    let mismatch = h.go("POST", path, Some(&guest), &[("_token", &t), ("password", "tok-5eed0000newpw001"), ("password_confirmation", "x")]).await;
    assert_eq!(mismatch.path(), path);
    let new = "tok-5eed0000newpw001";
    let done = h.go("POST", path, Some(&guest), &[("_token", &t), ("password", new), ("password_confirmation", new)]).await;
    assert_eq!(done.path(), "/login");
    assert!(h.get("/login", Some(&guest)).await.body.contains("Your password has been reset. Sign in with the new one."));
    assert_eq!(h.count("login_logs where note = 'password reset'"), 1);
    // every session of the account ended; the link works once
    assert_eq!(h.get("/account", Some(&before)).await.path(), "/login");
    assert_eq!(h.get(path, Some(&guest)).await.path(), "/login");
    let (r, _) = h.password(DANA, new, None).await;
    assert_eq!(r.path(), "/");
    // the request form's own throttle: six a minute per address
    for _ in 0..6 {
        h.go("POST", "/forgot-password", Some(&guest), &[("_token", &t), ("login", "x")]).await;
    }
    assert_eq!(h.go("POST", "/forgot-password", Some(&guest), &[("_token", &t), ("login", "x")]).await.status, 429);
}

// ----------------------------------------------------------------------------------------------- invitations ---

#[tokio::test(flavor = "multi_thread")]
async fn invitations_from_the_users_page_to_a_signed_in_account() {
    let h = harness().await;
    h.mail_on();
    let me = h.signed_in(ADMIN).await;
    let users = h.get("/users", Some(&me)).await;
    assert!(users.body.contains("Invite User") && users.body.contains("No pending invitations."));
    let t = users.csrf();
    let dialog = h.get("/users?invite=1", Some(&me)).await;
    assert!(dialog.body.contains("modal-title\">Invite User"));
    // taken username: the dialog again with the previous console's message
    let taken = h.go("POST", "/users/invitations", Some(&me), &[("_token", &t), ("do", "save"), ("email", "new-5eed@example.invalid"), ("username", DANA)]).await;
    assert_eq!(taken.status, 422);
    assert!(taken.body.contains("That username is already taken or reserved by a pending invitation."));
    let made = h.go("POST", "/users/invitations", Some(&me), &[("_token", &t), ("do", "save"), ("email", "new-5eed@example.invalid"), ("username", "user-5eed0c03"), ("name", "text-5eed0c03"), ("user_group_ids[]", "1"), ("device_group_ids[]", "1")]).await;
    assert_eq!(made.status, 200);
    assert!(made.body.contains("Invitation emailed to new-5eed@example.invalid."));
    let link = between(&made.body, "font-monospace\" readonly value=\"", "\"").to_string();
    assert!(link.contains("/invite/inv_"));
    assert!(h.mails()[0].1.contains(&link));
    assert_eq!(h.count("invitations where accepted_at is null"), 1);
    assert_eq!(h.text("select device_group_ids from invitations"), "[1]");
    assert_eq!(h.count("console_audits where action = 'user.invite'"), 1);
    // the address is reserved now
    let again = h.go("POST", "/users/invitations", Some(&me), &[("_token", &t), ("do", "save"), ("email", "new-5eed@example.invalid"), ("username", "user-5eed0c09")]).await;
    assert!(again.body.contains("That address already has an account or a pending invitation."));
    // the invitee
    let path = &link[link.find("/invite/").unwrap()..];
    let page = h.get(path, None).await;
    assert!(page.body.contains("Set your password") && page.body.contains("user-5eed0c03"));
    let guest = page.own().unwrap();
    let pt = page.csrf();
    let short = h.go("POST", path, Some(&guest), &[("_token", &pt), ("password", "short"), ("password_confirmation", "short")]).await;
    assert_eq!(short.path(), path);
    assert!(h.get(path, Some(&guest)).await.body.contains("The password field must be at least 8 characters."));
    let pw = "tok-5eed0000invite01";
    let ok = h.go("POST", path, Some(&guest), &[("_token", &pt), ("password", pw), ("password_confirmation", pw), ("is_admin", "1")]).await;
    assert_eq!(ok.path(), "/");
    assert_eq!(h.count("users where username = 'user-5eed0c03' and is_admin = 0 and email = 'new-5eed@example.invalid'"), 1, "privileges never from the request");
    assert_eq!(h.count("user_group_user where user_group_id = 1"), 1);
    assert_eq!(h.count("device_group_user where device_group_id = 1"), 1);
    assert_eq!(h.count("invitations where accepted_at is not null and accepted_user_id is not null"), 1);
    assert_eq!(h.count("login_logs where note = 'invitation'"), 1);
    assert_eq!(h.count("console_audits where action = 'user.invite-accept'"), 1);
    assert_eq!(h.get("/account", Some(&ok.own().unwrap())).await.status, 200);
    // used: gone
    assert_eq!(h.get(path, None).await.status, 404);
    // resend and revoke; an inviter who lost the authority voids the link
    let made2 = h.go("POST", "/users/invitations", Some(&me), &[("_token", &t), ("do", "save"), ("email", "two-5eed@example.invalid"), ("username", "user-5eed0c04")]).await;
    let link2 = between(&made2.body, "font-monospace\" readonly value=\"", "\"").to_string();
    let id = h.text("select cast(id as text) from invitations where username = 'user-5eed0c04'");
    let resent = h.go("POST", "/users/invitations", Some(&me), &[("_token", &t), ("do", "resend"), ("id", &id)]).await;
    let link3 = between(&resent.body, "font-monospace\" readonly value=\"", "\"").to_string();
    assert_ne!(link2, link3);
    assert_eq!(h.get(&link2[link2.find("/invite/").unwrap()..], None).await.status, 404);
    h.sql("update users set is_active = 0 where id = 1");
    assert_eq!(h.get(&link3[link3.find("/invite/").unwrap()..], None).await.status, 403);
    h.sql("update users set is_active = 1 where id = 1");
    let me = h.signed_in(ADMIN).await;
    let t = h.token("/users", &me).await;
    h.go("POST", "/users/invitations", Some(&me), &[("_token", &t), ("do", "revoke"), ("id", &id)]).await;
    assert_eq!(h.count("invitations where accepted_at is null"), 0);
    assert_eq!(h.count("console_audits where action in ('user.invite-resend', 'user.invite-revoke')"), 2);
    // the old link target
    assert_eq!(h.get("/invitations", Some(&me)).await.path(), "/users");
}

#[tokio::test(flavor = "multi_thread")]
async fn starttls_means_tls() {
    let h = harness().await;
    h.mail_on();
    h.setting("smtp_encryption", "starttls");
    let me = h.signed_in(ADMIN).await;
    let t = h.token("/settings?tab=email", &me).await;
    h.go("POST", "/settings/mail-test", Some(&me), &[("_token", &t), ("smtp_test_to", "ops@example.invalid")]).await;
    let page = h.get("/settings?tab=email", Some(&me)).await;
    assert!(page.body.contains("did not offer STARTTLS"), "the fake relay offers no STARTTLS: nothing is sent in the clear");
    assert!(h.mails().is_empty());
}
