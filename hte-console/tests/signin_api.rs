//! Phase 2 end to end: the client sign-in routes on a real socket, against a temporary database made from
//! tests/schema.sql and the replay's own seed (fixtures/signin/*.sql), with the fake identity provider of
//! src/fake_idp.rs on another socket. Expectations come from the previous console's source (v1.15.0-hte.1); each test names the
//! The previous console behaviour it pins, or the hardening rule it proves (crate README, "Phase 2: deliberate differences").

use hte_console::api::{router, Limiter, Native, Nonces};
use hte_console::fake_idp::{Config as IdpConfig, FakeIdp};
use hte_console::laravel::{self, Encrypter};
use hte_console::oidc::{Oidc, OidcError, Settings};
use hte_console::php::{self, Val};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, Once};

const APP_KEY: &str = "base64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const SECRET: &str = "tok-5eed00000000c11e";
const PW: &str = "tok-5eed00000000b002";
const SEED: &str = include_str!("../fixtures/signin/0000000000002-signin-seed.sql");
const T0: i64 = 1_800_000_000;

/// Everything every test logs, to prove no secret ever reaches the log.
static LOG: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static LOG_ONCE: Once = Once::new();

struct LogWriter;
impl Write for LogWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        LOG.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn capture_logs() {
    LOG_ONCE.call_once(|| {
        let sub = tracing_subscriber::fmt().with_writer(|| LogWriter).with_ansi(false).with_max_level(tracing::Level::DEBUG).finish();
        let _ = tracing::subscriber::set_global_default(sub);
    });
}

struct H {
    url: String,
    idp: String,
    db_path: PathBuf,
    clock: Arc<AtomicI64>,
    client: reqwest::Client,
    native: Arc<Native>,
    fake: Arc<FakeIdp>,
    _dir: tempfile::TempDir,
}

struct Resp {
    status: u16,
    ct: String,
    headers: reqwest::header::HeaderMap,
    body: String,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|_| panic!("not JSON: {:?}", self.body))
    }
}

struct Opts {
    real_time: bool,
    public_url: Option<&'static str>,
    allow_http: bool,
    env_disabled: bool,
    tenant: Option<&'static str>,
}

impl Default for Opts {
    fn default() -> Self {
        Opts { real_time: false, public_url: None, allow_http: true, env_disabled: false, tenant: None }
    }
}

async fn harness() -> H {
    harness_with(Opts::default()).await
}

async fn harness_with(o: Opts) -> H {
    capture_logs();
    sodiumoxide::init().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cortendesk.sqlite");
    let clock = Arc::new(AtomicI64::new(if o.real_time { chrono::Utc::now().timestamp() } else { T0 }));
    let (ck1, ck2) = (clock.clone(), clock.clone());
    let real = o.real_time;
    let now_fn = move |c: &AtomicI64| if real { chrono::Utc::now().timestamp() } else { c.load(Ordering::SeqCst) };
    // the fake provider first: its URL is the issuer the seed names
    let idp_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let idp = format!("http://{}", idp_l.local_addr().unwrap());
    let fake = FakeIdp::new(IdpConfig {
        issuer: idp.clone(),
        client_id: "client-seed".into(),
        client_secret: SECRET.into(),
        tenant: o.tenant.map(str::to_string),
        clock: Arc::new(move || now_fn(&ck1)),
    });
    let idp_app = fake.router();
    tokio::spawn(async move { axum::serve(idp_l, idp_app).await.unwrap() });

    let crypt = Encrypter::from_app_key(APP_KEY).unwrap();
    let c = Connection::open(&db_path).unwrap();
    c.execute_batch(include_str!("schema.sql")).unwrap();
    c.execute_batch(&hte_console::seed::expand(SEED, &idp, &crypt).unwrap()).unwrap();
    drop(c);
    let native = Arc::new(Native {
        db: Mutex::new(hte_console::sqlite::open(&db_path, std::time::Duration::from_secs(5), true).unwrap()),
        crypt,
        hbbs_db: dir.path().join("none.sqlite3"),
        trusted: laravel::parse_trusted(laravel::DEFAULT_TRUSTED),
        api_version: "1.15.0-hte.1".into(),
        max_body: 1 << 20,
        limiter: Mutex::new(Limiter::default()),
        nonces: Mutex::new(Nonces::default()),
        signin: hte_console::signin::State::new(Oidc::new(o.allow_http, o.env_disabled), o.public_url.map(str::to_string), "HTE Remote".into()),
        clock: Box::new(move || if real { chrono::Utc::now().timestamp() } else { ck2.load(Ordering::SeqCst) }),
    });
    let app = router(native.clone(), None).into_make_service_with_connect_info::<std::net::SocketAddr>();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    H { url, idp, db_path, clock, client, native, fake, _dir: dir }
}

impl H {
    fn db(&self) -> Connection {
        Connection::open(&self.db_path).unwrap()
    }
    fn sql(&self, s: &str) {
        self.db().execute_batch(s).unwrap();
    }
    fn one<T: rusqlite::types::FromSql>(&self, q: &str) -> T {
        self.db().query_row(q, [], |r| r.get(0)).unwrap()
    }
    fn count(&self, q: &str) -> i64 {
        self.one(&format!("select count(*) from {q}"))
    }
    fn advance(&self, s: i64) {
        self.clock.fetch_add(s, Ordering::SeqCst);
    }
    fn now(&self) -> i64 {
        self.clock.load(Ordering::SeqCst)
    }
    async fn req(&self, method: &str, path: &str, body: Option<Value>, headers: &[(&str, &str)]) -> Resp {
        let mut rq = self.client.request(method.parse().unwrap(), format!("{}{}", self.url, path)).header("x-forwarded-for", "198.18.9.1");
        for (k, v) in headers {
            rq = rq.header(*k, *v);
        }
        if let Some(b) = body {
            rq = rq.header("content-type", "application/json").body(serde_json::to_vec(&b).unwrap());
        }
        let r = rq.send().await.unwrap();
        let status = r.status().as_u16();
        let headers = r.headers().clone();
        let ct = headers.get("content-type").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
        Resp { status, ct, headers, body: r.text().await.unwrap() }
    }
    async fn post(&self, path: &str, body: Value) -> Resp {
        self.req("POST", path, Some(body), &[]).await
    }
    async fn login(&self, user: &str, pw: &str, id: &str) -> Resp {
        self.post("/api/login", json!({"username": user, "password": pw, "id": id, "uuid": "UExBQ0VIT0xERVIhAAAA2A==", "deviceInfo": {"os": "Windows", "type": "client", "name": "text-5eed0d01"}})).await
    }
    async fn current_user(&self, token: &str) -> Resp {
        self.req("POST", "/api/currentUser", None, &[("authorization", &format!("Bearer {token}"))]).await
    }
    async fn tfa_challenge(&self) -> String {
        self.login("user-5eed0006", PW, "990000205").await.json()["secret"].as_str().unwrap().to_string()
    }
    async fn tfa_code(&self, secret: String, code: String) -> Value {
        self.post("/api/login", json!({"type": "tfa_code", "secret": secret, "id": "990000205", "tfaCode": code})).await.json()
    }
    /// POST /api/oidc/auth: (code, authorize URL)
    async fn oidc_start(&self, id: &str) -> (String, String) {
        let r = self.post("/api/oidc/auth", json!({"id": id, "uuid": "UExBQ0VIT0xERVIhAAAA2A==", "op": "sso"})).await;
        let v = r.json();
        (v["code"].as_str().unwrap_or_else(|| panic!("{}", r.body)).to_string(), v["url"].as_str().unwrap().to_string())
    }
    /// The browser: the authorize URL at the fake provider, then the callback it redirects to (path and query).
    async fn authorize(&self, url: &str, mode: &str, profile: &str) -> String {
        let r = self.client.get(format!("{url}&hte_fake={mode}&hte_user={profile}")).send().await.unwrap();
        assert_eq!(r.status().as_u16(), 302, "authorize");
        let loc = url::Url::parse(r.headers()["location"].to_str().unwrap()).unwrap();
        format!("{}?{}", loc.path(), loc.query().unwrap_or(""))
    }
    async fn callback(&self, path_query: &str) -> Resp {
        self.req("GET", path_query, None, &[]).await
    }
    async fn poll(&self, code: &str, id: &str) -> Resp {
        self.req("GET", &format!("/api/oidc/auth-query?code={code}&id={id}&uuid=UExBQ0VIT0xERVIhAAAA2A%3D%3D"), None, &[]).await
    }
    /// One whole SSO sign-in: start, browser, poll. Returns (callback page, poll answer).
    async fn sso(&self, id: &str, mode: &str, profile: &str) -> (Resp, Resp) {
        let (code, url) = self.oidc_start(id).await;
        let cb = self.authorize(&url, mode, profile).await;
        let page = self.callback(&cb).await;
        (page, self.poll(&code, id).await)
    }
}

// ----------------------------------------------------------------------------------- the synthetic fixtures ---

#[tokio::test(flavor = "multi_thread")]
async fn synthetic_signin_fixtures_replay_with_no_differences() {
    let h = harness_with(Opts { real_time: true, ..Default::default() }).await;
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/signin");
    let s = hte_console::sanitise::Sanitiser::new(Some("test"), &[]);
    let r = hte_console::replay::run(&dir, &h.url, &s).await.unwrap();
    assert!(r.total > 140, "{} fixtures", r.total);
    assert!(r.differences.is_empty(), "{} differences:\n{}", r.differences.len(), r.differences.join("\n"));
    // and what the previous console would have written
    assert_eq!(h.one::<String>("select status from devices where rustdesk_id = '990000201'"), "active");
    assert_eq!(h.one::<i64>("select user_id from devices where rustdesk_id = '990000201'"), 910002);
    let anna: i64 = h.one("select id from users where username = '990005001'");
    assert_eq!(h.one::<i64>("select user_id from devices where rustdesk_id = '990000202'"), anna);
    assert_eq!(h.one::<String>("select auth_provider from users where id = (select id from users where username = '990005001')"), "oidc");
    assert!(h.one::<String>(&format!("select password from users where id = {anna}")).starts_with("$2y$12$"));
    assert_eq!(h.one::<String>("select oidc_sub from users where id = 910008"), "sub-5eed-linked");
    assert_eq!(h.one::<String>("select name from users where id = 910009"), "text-5eed0a09");
    assert_eq!(h.count("alarm_logs where typ = 100"), 0, "seven wrong codes stay under the per-account limit of ten");
    assert_eq!(h.count("oidc_auth_requests"), 0, "every request collected or failed and collected");
    assert_eq!(h.count("devices where rustdesk_id = '990000204' and deleted_at is not null and user_id is null"), 1);
    // no secret of the run reached the log
    let log = String::from_utf8_lossy(&LOG.lock().unwrap()).into_owned();
    for secret in [SECRET, PW, "tok-5eed00000000b004", "GEZDGNBVGY3TQOJQ"] {
        assert!(!log.contains(secret), "the log holds {secret}");
    }
    let tokens: Vec<String> = h.db().prepare("select token from client_tokens").unwrap().query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
    assert!(!tokens.is_empty());
    for t in tokens {
        assert!(!log.contains(&t), "the log holds a client token");
    }
}

// -------------------------------------------------------------------------------------------- formats ---

#[test]
fn laravel_password_and_token_formats() {
    // the password_verify documentation's example (a hash the previous console made)
    assert!(laravel::hash_check(b"rasmuslerdorf", &Val::str("$2y$07$BCryptRequires22Chrcte/VlQH0piJtjXl.0t1XkA8pw9dMXTpOq")).unwrap());
    assert!(!laravel::hash_check(b"rasmuslerdorF", &Val::str("$2y$07$BCryptRequires22Chrcte/VlQH0piJtjXl.0t1XkA8pw9dMXTpOq")).unwrap());
    // Apache's htpasswd -B (also $2y$) for the seeded password
    assert!(laravel::hash_check(PW.as_bytes(), &Val::str("$2y$12$3wIwkZeCjcZyF8sX1rS5feMamonmbx8BhEuI6ocFNk.2/XQn8QAe2")).unwrap());
    // what Laravel refuses: not $2y$ (password_get_info says unknown) -> RuntimeException (500); empty -> false
    assert!(laravel::hash_check(PW.as_bytes(), &Val::str("$2b$12$3wIwkZeCjcZyF8sX1rS5feMamonmbx8BhEuI6ocFNk.2/XQn8QAe2")).is_err());
    assert!(laravel::hash_check(PW.as_bytes(), &Val::str("plain")).is_err());
    assert!(!laravel::hash_check(PW.as_bytes(), &Val::str("")).unwrap());
    // The previous console's crypt reads a C string: a NUL ends the password; 72 bytes are used
    let h = laravel::hash_make(b"abc").unwrap();
    assert!(h.starts_with("$2y$12$") && h.len() == 60);
    assert!(laravel::hash_check(b"abc\0whatever", &Val::str(&h)).unwrap());
    let long = "x".repeat(72);
    let h = laravel::hash_make(long.as_bytes()).unwrap();
    assert!(laravel::hash_check(format!("{long}tail").as_bytes(), &Val::str(&h)).unwrap());
    // Str::random
    let t = laravel::str_random(48);
    assert!(t.len() == 48 && t.bytes().all(|b| b.is_ascii_alphanumeric()));
    // bearerToken(): the last "Bearer ", case-insensitive, cut at a comma
    assert_eq!(laravel::bearer_token(Some(b"Bearer abc")), Some(b"abc".to_vec()));
    assert_eq!(laravel::bearer_token(Some(b"bearer x, Basic y")), Some(b"x".to_vec()));
    assert_eq!(laravel::bearer_token(Some(b"Bearer a Bearer b")), Some(b"b".to_vec()));
    assert_eq!(laravel::bearer_token(Some(b"Basic abc")), None);
    assert_eq!(laravel::bearer_token(None), None);
}

// ------------------------------------------------------------------------------------------- password ---

#[tokio::test(flavor = "multi_thread")]
async fn token_issue_expiry_and_last_used() {
    let h = harness().await;
    let r = h.login("user-5eed0002", PW, "990000201").await;
    let v = r.json();
    let token = v["access_token"].as_str().unwrap().to_string();
    assert_eq!(token.len(), 48);
    assert_eq!(v["user"], json!({"name": "user-5eed0002", "display_name": "text-5eed0002", "email": "user-5eed000002@example.invalid", "note": "", "status": 1, "is_admin": true, "info": {}}));
    // the body itself: slashes escaped and `info` an object, as the previous console's json_encode writes it
    assert!(r.body.contains(r#""info":{}"#), "{}", r.body);
    assert_eq!(h.one::<String>("select expires_at from client_tokens"), laravel::ts(T0 + 30 * 86_400));
    assert_eq!(h.one::<String>("select device_id from client_tokens"), "990000201");
    assert_eq!(h.one::<String>("select device_os from client_tokens"), "Windows");
    assert_eq!(h.one::<String>("select client_type from client_tokens"), "client");
    // the rate-limit headers are the route's own 20 (fewer left than the group's 240)
    assert_eq!(r.headers["x-ratelimit-limit"], "20");
    assert_eq!(r.headers["x-ratelimit-remaining"], "19");
    h.advance(100);
    assert_eq!(h.current_user(&token).await.status, 200);
    assert_eq!(h.one::<String>("select last_used_at from client_tokens"), laravel::ts(T0 + 100));
    // valid through the 30th day, not after
    h.advance(30 * 86_400 - 101);
    assert_eq!(h.current_user(&token).await.status, 200);
    h.advance(1);
    let r = h.current_user(&token).await;
    assert_eq!((r.status, r.json()), (401, json!({"message": "Unauthenticated."})));
    // a disabled user's token stops working at once
    let t2 = h.login("user-5eed0002", PW, "990000203").await.json()["access_token"].as_str().unwrap().to_string();
    h.sql("update users set is_active = 0 where id = 910002");
    assert_eq!(h.current_user(&t2).await.status, 401);
    // "0" is no bearer at all
    assert_eq!(h.current_user("0").await.status, 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_users_take_as_long_as_wrong_passwords() {
    let h = harness().await;
    // warm the dummy hash
    h.login("user-5eed00ff", PW, "990000201").await;
    let time = |user: &'static str, pw: &'static str| {
        let h = &h;
        async move {
            let t = std::time::Instant::now();
            assert_eq!(h.login(user, pw, "990000201").await.json(), json!({"error": "Wrong credentials"}));
            t.elapsed()
        }
    };
    let wrong = time("user-5eed0002", "tok-5eed0000000bad02").await;
    let unknown = time("user-5eed00ff", PW).await;
    let inactive = time("user-5eed0003", PW).await;
    let empty = time("user-5eed0002", "").await;
    // one bcrypt check each (the previous console answers an unknown name without one); generous bounds for a debug build
    for (what, d) in [("unknown", unknown), ("inactive", inactive), ("empty", empty)] {
        assert!(d * 3 > wrong, "{what} took {d:?}, a wrong password {wrong:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn login_rules_from_settings() {
    let h = harness().await;
    // force-SSO: password sign-in off while SSO is usable
    h.sql("insert into settings (key, value) values ('oidc_disable_local_login', '1')");
    assert_eq!(h.login("user-5eed0002", PW, "990000201").await.json(), json!({"error": "Password sign-in is disabled. Use single sign-on."}));
    // ... and back on, by itself, when SSO is not usable (break-glass): a missing secret
    h.sql("update settings set value = '' where key = 'oidc_client_secret'");
    assert!(h.login("user-5eed0002", PW, "990000201").await.json()["access_token"].is_string());
    assert_eq!(h.req("GET", "/api/login-options", None, &[]).await.body, "[]");
    h.sql("update settings set value = 'tok-5eed00000000c11e' where key = 'oidc_client_secret'; delete from settings where key = 'oidc_disable_local_login'");
    // 2FA required but not enrolled
    h.sql("insert into settings (key, value) values ('two_factor_required_admins', '1')");
    assert_eq!(
        h.login("user-5eed0002", PW, "990000201").await.json(),
        json!({"error": "Two-factor authentication is required. Set it up in the web console, then sign in again."})
    );
    h.sql("delete from settings where key = 'two_factor_required_admins'; insert into roles (id, name, permissions, require_two_factor) values (1, 'r', '{}', 1); update users set role_id = 1 where id = 910008");
    assert_eq!(h.login("user-5eed0008", PW, "990000201").await.json()["error"], "Two-factor authentication is required. Set it up in the web console, then sign in again.");
    // emailed codes on: hte-console sends no mail, so it answers as the previous console does when the mail cannot go
    h.sql("insert into settings (key, value) values ('email_login_verification', '1'), ('smtp_enabled', '1'), ('smtp_host', 'host-5eed0001'), ('smtp_from_address', 'user-5eed00f001@example.invalid')");
    assert_eq!(
        h.login("user-5eed0002", PW, "990000201").await.json()["error"],
        "Sign-in is temporarily unavailable: this console cannot send verification codes. Contact an administrator."
    );
    assert_eq!(h.count("client_tokens"), 1, "only the break-glass sign-in above issued a token");
}

#[tokio::test(flavor = "multi_thread")]
async fn kill_switch_hides_sso_and_keeps_passwords() {
    let h = harness_with(Opts { env_disabled: true, ..Default::default() }).await;
    h.sql("insert into settings (key, value) values ('oidc_disable_local_login', '1')");
    assert_eq!(h.req("GET", "/api/login-options", None, &[]).await.body, "[]");
    assert!(h.login("user-5eed0002", PW, "990000201").await.json()["access_token"].is_string());
    assert_eq!(h.post("/api/oidc/auth", json!({"id": "990000201"})).await.json(), json!({"error": "Single sign-on is not enabled on this server."}));
}

#[tokio::test(flavor = "multi_thread")]
async fn totp_prompt_expires_and_counts_tries() {
    let h = harness().await;
    let key = hte_console::totp::base32_decode(hte_console::totp::REPLAY_SECRET.as_bytes()).unwrap();
    // a prompt lives 600 seconds
    let s = h.tfa_challenge().await;
    h.advance(601);
    let now = h.now();
    assert_eq!(h.tfa_code(s, hte_console::totp::at(&key, now / 30)).await, json!({"error": "Your sign-in expired. Sign in again."}));
    // five wrong codes end a prompt
    let s = h.tfa_challenge().await;
    for _ in 0..4 {
        assert_eq!(h.tfa_code(s.clone(), "999999".into()).await["error"], "That code is incorrect or has expired.");
    }
        assert_eq!(h.tfa_code(s.clone(), "999999".into()).await["error"], "That code is incorrect or has expired.");
    let now = h.now();
    assert_eq!(h.tfa_code(s, hte_console::totp::at(&key, now / 30)).await["error"], "Your sign-in expired. Sign in again.");
    // a code from the email field, with separators (digits only are kept)
    let s = h.tfa_challenge().await;
    let c = hte_console::totp::at(&key, h.now() / 30);
    let v = h.post("/api/login", json!({"type": "tfa_code", "secret": s, "id": "990000205", "tfaCode": "", "verificationCode": format!("{} {}", &c[..3], &c[3..])})).await.json();
    assert!(v["access_token"].is_string(), "{v}");
    assert_eq!(h.one::<i64>("select totp_last_timestep from users where id = 910006"), h.now() / 30);
    assert_eq!(h.count("login_logs where note = 'wrong verification code'"), 5);
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_codes_are_counted_per_account_not_per_address() {
    let h = harness().await;
    // ten wrong codes in two prompts from one address ...
    for _ in 0..2 {
        let s = h.tfa_challenge().await;
        for _ in 0..5 {
            assert_eq!(h.tfa_code(s.clone(), "999999".into()).await["error"].as_str().map(|e| e.starts_with("Too many")), Some(false));
        }
    }
    // ... leave a second address no fresh allowance, even with the right code
    let key = hte_console::totp::base32_decode(hte_console::totp::REPLAY_SECRET.as_bytes()).unwrap();
    let s = h.tfa_challenge().await;
    let good = hte_console::totp::at(&key, h.now() / 30);
    let v = h
        .req("POST", "/api/login", Some(json!({"type": "tfa_code", "secret": s, "id": "990000205", "tfaCode": good})), &[("x-forwarded-for", "198.18.9.200")])
        .await
        .json();
    assert!(v["error"].as_str().unwrap().starts_with("Too many attempts. Try again in "), "{v}");
    assert_eq!(h.count("alarm_logs where typ = 100 and info like '%client-two-factor%'"), 1);
    // the window is fifteen minutes
    h.advance(901);
    let now = h.now();
    let s = h.tfa_challenge().await;
    let v = h.tfa_code(s, hte_console::totp::at(&key, now / 30)).await;
    assert!(v["access_token"].is_string(), "{v}");
}

// ------------------------------------------------------------------------------------------------- OIDC ---

#[tokio::test(flavor = "multi_thread")]
async fn sso_sign_in_approves_and_owns_the_pending_device() {
    let h = harness().await;
    let (code, url) = h.oidc_start("990000202").await;
    // PKCE: the challenge in the URL is S256 of the verifier kept on the row; state and nonce are the row's
    let q: std::collections::HashMap<String, String> = url::Url::parse(&url).unwrap().query_pairs().into_owned().collect();
    let (verifier, state, nonce): (String, String, String) = h.db().query_row("select verifier, state, nonce from oidc_auth_requests", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
    assert_eq!(verifier.len(), 96);
    assert_eq!(q["code_challenge"], hte_console::oidc::code_challenge(&verifier));
    assert_eq!((q["state"].as_str(), q["nonce"].as_str(), q["code_challenge_method"].as_str()), (state.as_str(), nonce.as_str(), "S256"));
    assert_eq!(q["scope"], "openid email profile");
    assert!(url.starts_with(&format!("{}/authorize?response_type=code&client_id=client-seed&redirect_uri=http%3A%2F%2F127.0.0.1%3A", h.idp)), "{url}");
    assert_eq!(h.one::<String>("select expires_at from oidc_auth_requests"), laravel::ts(T0 + 300));
    let cb = h.authorize(&url, "ok", "anna").await;
    let page = h.callback(&cb).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.ct.starts_with("text/html"));
    assert!(page.body.contains("You are signed in as text-5eed0a01. You can close this tab and return to HTE Remote."));
    assert!(page.headers.get("set-cookie").is_none(), "no console session is opened by this page");
    let v = h.poll(&code, "990000202").await.json();
    assert_eq!(v["type"], "access_token");
    assert_eq!(v["user"]["name"], "990005001");
    let anna: i64 = h.one("select id from users where username = '990005001'");
    assert_eq!(h.one::<String>("select status from devices where rustdesk_id = '990000202'"), "active");
    assert_eq!(h.one::<i64>("select user_id from devices where rustdesk_id = '990000202'"), anna);
    assert!(h.one::<Option<String>>("select registered_ip from devices where rustdesk_id = '990000202'").is_none());
    assert_eq!(h.count(&format!("login_logs where user_id = {anna} and successful = 1 and client = 'client' and username = '990005001'")), 1);
    // a device that already has an owner keeps it; without the setting nothing is approved
    h.sql("insert into devices (rustdesk_id, uuid, status, user_id) values ('990000210', '', 'pending', 910002)");
    h.sso("990000210", "ok", "anna").await;
    assert_eq!(h.one::<i64>("select user_id from devices where rustdesk_id = '990000210'"), 910002);
    assert_eq!(h.one::<String>("select status from devices where rustdesk_id = '990000210'"), "active");
    h.sql("insert into devices (rustdesk_id, uuid, status) values ('990000211', '', 'pending'); update settings set value = '0' where key = 'auto_approve_signed_in'");
    h.sso("990000211", "ok", "anna").await;
    assert_eq!(h.one::<String>("select status from devices where rustdesk_id = '990000211'"), "pending");
}

#[tokio::test(flavor = "multi_thread")]
async fn state_is_single_use_and_requests_expire() {
    let h = harness().await;
    // HARDENED: a second use of a completed state is refused (the previous console exchanged again and overwrote the result)
    let (code, url) = h.oidc_start("990000220").await;
    let cb = h.authorize(&url, "ok", "anna").await;
    assert_eq!(h.callback(&cb).await.status, 200);
    let again = h.callback(&cb).await;
    assert_eq!(again.status, 400);
    assert!(again.body.contains("This sign-in request has expired."));
    // ... and a fresh code for the same state cannot replace the token the client is about to collect
    let fresh = h.authorize(&url, "ok", "outsider").await;
    assert_eq!(h.callback(&fresh).await.status, 400);
    assert_eq!(h.poll(&code, "990000220").await.json()["user"]["name"], "990005001");
    // a failed state is final too
    let (code, url) = h.oidc_start("990000221").await;
    let cb = h.authorize(&url, "wrong-nonce", "anna").await;
    assert_eq!(h.callback(&cb).await.status, 403);
    let ok = h.authorize(&url, "ok", "anna").await;
    assert_eq!(h.callback(&ok).await.status, 400);
    assert_eq!(h.poll(&code, "990000221").await.json()["error"], "The ID token nonce did not match. Please try signing in again.");
    // a request lives 300 seconds, for the browser and for the poll
    let (code, url) = h.oidc_start("990000222").await;
    let cb = h.authorize(&url, "ok", "anna").await;
    h.advance(301);
    assert_eq!(h.callback(&cb).await.status, 400);
    assert_eq!(h.poll(&code, "990000222").await.json(), json!({"error": "No authed oidc is found"}));
    // an unknown state, an empty one
    assert_eq!(h.callback("/login/oidc/client-callback?state=nope&code=x").await.status, 400);
    assert_eq!(h.callback("/login/oidc/client-callback").await.status, 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn id_token_rules_php_and_hardened() {
    let h = harness().await;
    let error = |p: (Resp, Resp)| {
        assert_eq!(p.0.status, 403, "{}", p.0.body);
        p.1.json()["error"].as_str().unwrap().to_string()
    };
    // as the previous console
    assert_eq!(error(h.sso("990000230", "alg-none", "anna").await), "The ID token was signed with an algorithm this provider does not advertise (none).");
    assert_eq!(error(h.sso("990000231", "expired", "anna").await), "The ID token failed verification: Expired token");
    assert!(error(h.sso("990000232", "nbf-future", "anna").await).starts_with("The ID token failed verification: Cannot handle token with nbf prior to 2027-01-15T08:10:00+00:00"));
    // HARDENED: no exp at all is refused (the previous console's JWT library lets such a token through)
    assert_eq!(error(h.sso("990000233", "no-exp", "anna").await), "The ID token failed verification: Expired token");
    // HARDENED: several audiences need azp = this client (the previous console accepted any list holding the client id)
    assert_eq!(error(h.sso("990000234", "multi-aud", "anna").await), "The ID token was not issued for this client.");
    let (page, poll) = h.sso("990000235", "multi-aud-azp", "anna").await;
    assert_eq!(page.status, 200);
    assert!(poll.json()["access_token"].is_string());
}

#[tokio::test(flavor = "multi_thread")]
async fn tokens_checked_directly() {
    let h = harness().await;
    let s = Settings { enabled: "1".into(), discovery_url: h.idp.clone(), client_id: "client-seed".into(), client_secret: SECRET.into(), ..Default::default() };
    let oidc = Oidc::new(true, false);
    let d = oidc.discovery(&s).await.unwrap();
    let now = T0;
    let check = |mode: &'static str| {
        let (oidc, s, d, fake) = (&oidc, &s, &d, h.fake.clone());
        async move { oidc.verify_id_token(s, d, &fake.id_token(mode, "anna", "n-1"), "n-1", now).await }
    };
    assert!(check("ok").await.is_ok());
    // HARDENED: HS256 refused even when the provider advertises it (the previous console would verify it with the client secret)
    let mut d_hs = d.clone();
    if let Val::Arr(a) = &mut d_hs {
        let mut l = php::Arr::new();
        l.push(Val::str("RS256"));
        l.push(Val::str("HS256"));
        a.set(php::Key::from_bytes(b"id_token_signing_alg_values_supported"), Val::Arr(l));
    }
    let hs = h.fake.id_token("alg-hs256", "anna", "n-1");
    assert_eq!(
        oidc.verify_id_token(&s, &d_hs, &hs, "n-1", now).await,
        Err(OidcError::Msg("The ID token was signed with an algorithm this provider does not advertise (HS256).".into()))
    );
    // a nonce is always required; an empty expected nonce matches nothing
    assert!(matches!(oidc.verify_id_token(&s, &d, &h.fake.id_token("ok", "anna", ""), "", now).await, Err(OidcError::Msg(m)) if m.contains("nonce")));
    // a token for another moment: exp/nbf/iat with 60 s of skew
    assert!(oidc.verify_id_token(&s, &d, &h.fake.id_token("ok", "anna", "n-1"), "n-1", now + 3600 + 59).await.is_ok());
    assert!(oidc.verify_id_token(&s, &d, &h.fake.id_token("ok", "anna", "n-1"), "n-1", now + 3600 + 60).await.is_err());
    // garbage never panics
    for jwt in ["", ".", "..", "a.b.c", "eyJhbGciOiJSUzI1NiJ9..", "eyJhbGciOiJSUzI1NiIsImtpZCI6ImthIn0.e30.AAAA", "x.y.z.w"] {
        assert!(oidc.verify_id_token(&s, &d, jwt, "n-1", now).await.is_err(), "{jwt}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn entra_tenant_must_match() {
    // a provider whose issuer is a Microsoft tenant: tid must be that tenant
    let tenant = "9188040d-6c67-4c5b-b112-36a304b66dad";
    let h = harness_with(Opts { tenant: Some(tenant), ..Default::default() }).await;
    let oidc = Oidc::new(true, false);
    let s = Settings { client_id: "client-seed".into(), client_secret: SECRET.into(), discovery_url: h.idp.clone(), ..Default::default() };
    let ms = format!("https://login.microsoftonline.com/{tenant}/v2.0");
    let d = php::json_decode(format!(r#"{{"issuer":"{ms}","jwks_uri":"{}/jwks"}}"#, h.idp).as_bytes(), &Default::default()).unwrap();
    let fake = FakeIdp::new(IdpConfig { issuer: ms.clone(), client_id: "client-seed".into(), client_secret: SECRET.into(), tenant: Some(tenant.into()), clock: Arc::new(|| T0) });
    assert!(oidc.verify_id_token(&s, &d, &fake.id_token("ok", "anna", "n"), "n", T0).await.is_ok());
    assert_eq!(oidc.verify_id_token(&s, &d, &fake.id_token("wrong-tid", "anna", "n"), "n", T0).await, Err(OidcError::Msg("The ID token was issued by an unexpected issuer.".into())));
    let no_tid = FakeIdp::new(IdpConfig { issuer: ms, client_id: "client-seed".into(), client_secret: SECRET.into(), tenant: None, clock: Arc::new(|| T0) });
    assert!(oidc.verify_id_token(&s, &d, &no_tid.id_token("ok", "anna", "n"), "n", T0).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn jwks_cache_is_bounded_and_refetches_for_rotation() {
    let h = harness().await;
    let s = Settings { enabled: "1".into(), discovery_url: h.idp.clone(), client_id: "client-seed".into(), client_secret: SECRET.into(), ..Default::default() };
    let mut oidc = Oidc::new(true, false);
    let d = oidc.discovery(&s).await.unwrap();
    for _ in 0..3 {
        assert!(oidc.verify_id_token(&s, &d, &h.fake.id_token("ok", "anna", "n"), "n", T0).await.is_ok());
    }
    assert_eq!(h.fake.jwks_fetches(), 1, "cached");
    // an unknown kid right after a fetch does not fetch again (at most once a minute)
    assert!(oidc.verify_id_token(&s, &d, &h.fake.id_token("unknown-kid", "anna", "n"), "n", T0).await.is_err());
    assert_eq!(h.fake.jwks_fetches(), 1);
    // with the minute passed, it does, once
    oidc.jwks_refetch = std::time::Duration::ZERO;
    assert!(oidc.verify_id_token(&s, &d, &h.fake.id_token("unknown-kid", "anna", "n"), "n", T0).await.is_err());
    assert_eq!(h.fake.jwks_fetches(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn pkce_and_client_secret_reach_the_provider() {
    let h = harness().await;
    // a verifier that does not match the challenge: the provider refuses the code
    let (code, url) = h.oidc_start("990000240").await;
    let cb = h.authorize(&url, "ok", "anna").await;
    // the first character always changes (a random verifier starts with 'x' one time in 64)
    h.sql("update oidc_auth_requests set verifier = case when substr(verifier, 1, 1) = 'x' then 'y' else 'x' end || substr(verifier, 2)");
    let page = h.callback(&cb).await;
    assert_eq!(page.status, 403);
    assert!(page.body.contains("Token exchange failed (400). Check the client ID and secret."));
    assert_eq!(h.poll(&code, "990000240").await.json()["error"], "Token exchange failed (400). Check the client ID and secret.");
    // a wrong client secret
    h.sql("update settings set value = 'tok-5eed00000000c11f' where key = 'oidc_client_secret'");
    let (page, _) = h.sso("990000241", "ok", "anna").await;
    assert!(page.body.contains("Token exchange failed (401)."), "{}", page.body);
    assert!(!page.body.contains("tok-5eed00000000c11f"), "the secret is never shown");
    // the stored secret may be Laravel-encrypted (as the console's settings page writes it)
    let enc = Encrypter::from_app_key(APP_KEY).unwrap().encrypt_string(SECRET.as_bytes());
    h.sql(&format!("update settings set value = '{enc}' where key = 'oidc_client_secret'"));
    let (page, _) = h.sso("990000242", "ok", "anna").await;
    assert_eq!(page.status, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn redirect_uri_comes_from_the_public_url_not_the_host_header() {
    let h = harness_with(Opts { public_url: Some("https://remote.example.test/"), ..Default::default() }).await;
    let r = h.req("POST", "/api/oidc/auth", Some(json!({"id": "990000250"})), &[("host", "evil.example.test")]).await;
    let url = r.json()["url"].as_str().unwrap().to_string();
    let q: std::collections::HashMap<String, String> = url::Url::parse(&url).unwrap().query_pairs().into_owned().collect();
    assert_eq!(q["redirect_uri"], "https://remote.example.test/login/oidc/client-callback");
    // the page's links too
    let (code, url) = h.oidc_start("990000251").await;
    let _ = code;
    let page = h.req("GET", &h.authorize(&url, "deny", "anna").await, None, &[("host", "evil.example.test")]).await;
    assert!(page.body.contains(concat!("https://remote.example.test/assets/css/hte-auth.css?v=", env!("CARGO_PKG_VERSION"))));
    assert!(!page.body.contains("evil"));
    // without a public URL: as Laravel (https from X-Forwarded-Proto, the Host header), and a Host Symfony refuses
    let h = harness().await;
    let r = h.req("POST", "/api/oidc/auth", Some(json!({"id": "990000252"})), &[("host", "remote.example.test"), ("x-forwarded-proto", "https")]).await;
    let url = r.json()["url"].as_str().unwrap().to_string();
    assert!(url.contains("redirect_uri=https%3A%2F%2Fremote.example.test%2Flogin%2Foidc%2Fclient-callback"), "{url}");
    let r = h.req("POST", "/api/oidc/auth", Some(json!({"id": "990000253"})), &[("host", "bad host/x")]).await;
    assert_eq!((r.status, r.json()), (404, json!({"message": "Bad hostname provided."})));
    assert_eq!(h.count("oidc_auth_requests where device_id = '990000253'"), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn provider_over_http_is_refused_unless_allowed() {
    let h = harness_with(Opts { allow_http: false, ..Default::default() }).await;
    let r = h.post("/api/oidc/auth", json!({"id": "990000260"})).await;
    let e = r.json()["error"].as_str().unwrap().to_string();
    assert!(e.starts_with("Could not read the provider's configuration from http://127.0.0.1:"), "{e}");
    assert_eq!(h.count("oidc_auth_requests"), 0, "the row is deleted again");
}

#[tokio::test(flavor = "multi_thread")]
async fn oidc_resolver_policies() {
    let h = harness().await;
    // pending policy: the account is created and waits
    h.sql("update settings set value = 'pending' where key = 'oidc_new_user_policy'");
    let (page, poll) = h.sso("990000270", "ok", "anna").await;
    assert_eq!(page.status, 403);
    assert_eq!(poll.json()["error"], "Your account has been created and is waiting for administrator approval.");
    assert_eq!(h.one::<String>("select oidc_status from users where username = '990005001'"), "pending");
    // and the next sign-in says so
    let (_, poll) = h.sso("990000271", "ok", "anna").await;
    assert_eq!(poll.json()["error"], "Your account is waiting for administrator approval.");
    // deny policy: nobody new
    h.sql("delete from users where username = '990005001'; update settings set value = 'deny' where key = 'oidc_new_user_policy'");
    let (_, poll) = h.sso("990000272", "ok", "anna").await;
    assert_eq!(poll.json()["error"], "No console account matches this sign-in. Contact your administrator.");
    // verified email required and the provider says nothing: no link
    h.sql("insert into settings (key, value) values ('oidc_require_verified_email', '1')");
    let (_, poll) = h.sso("990000273", "ok", "linked").await;
    assert!(poll.json()["error"].as_str().unwrap().starts_with("Your identity provider did not say whether this email address is verified"));
    assert!(h.one::<Option<String>>("select oidc_sub from users where id = 910008").is_none());
    // a default group for new people
    h.sql("delete from settings where key = 'oidc_require_verified_email'; update settings set value = 'active' where key = 'oidc_new_user_policy'; insert into user_groups (id, name) values (5, 'g'); insert into settings (key, value) values ('oidc_default_group_id', '5'), ('oidc_default_admin', '1')");
    let (page, poll) = h.sso("990000274", "ok", "anna").await;
    assert_eq!(page.status, 200);
    assert_eq!(poll.json()["user"]["is_admin"], true);
    assert_eq!(h.count("user_group_user where user_group_id = 5"), 1);
}

// --------------------------------------------------------------------------------------- HTTP and bad input ---

#[tokio::test(flavor = "multi_thread")]
async fn http_edges() {
    let h = harness().await;
    // bodies are capped (a sign-in is a few hundred bytes)
    let big = json!({"username": "x".repeat(70_000)});
    let r = h.post("/api/login", big).await;
    assert_eq!((r.status, r.json()), (413, json!({"message": "The POST data is too large."})));
    // CORS preflight on api/*, none on the page
    let r = h.req("OPTIONS", "/api/login", None, &[("access-control-request-method", "POST"), ("origin", "https://x.example.test")]).await;
    assert_eq!(r.status, 204);
    let r = h.req("OPTIONS", "/login/oidc/client-callback", None, &[("access-control-request-method", "GET")]).await;
    assert_eq!(r.status, 200);
    assert!(r.headers.get("access-control-allow-origin").is_none());
    // wrong methods
    assert_eq!(h.req("POST", "/login/oidc/client-callback", None, &[]).await.status, 405);
    let r = h.req("GET", "/api/currentUser", None, &[]).await;
    assert_eq!(r.json()["message"], "The GET method is not supported for route api/currentUser. Supported methods: POST.");
    // the oidc auth throttle: 20 a minute per address
    for i in 0..20 {
        assert_eq!(h.req("POST", "/api/oidc/auth", Some(json!({"id": format!("99000{:04}", 3000 + i)})), &[("x-forwarded-for", "198.18.9.77")]).await.status, 200);
    }
    let r = h.req("POST", "/api/oidc/auth", Some(json!({"id": "990003999"})), &[("x-forwarded-for", "198.18.9.77")]).await;
    assert_eq!((r.status, r.headers["x-ratelimit-limit"].to_str().unwrap()), (429, "20"));
    assert!(r.headers.contains_key("retry-after"));
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_input_never_panics() {
    let h = harness().await;
    let mut seed: u64 = 0x5eed;
    let mut rnd = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let atoms = [r#""""#, "null", "0", "-1", "1e999", "[]", "{}", r#"["a"]"#, r#"{"a":1}"#, r#""tfa_code""#, r#""\u0000""#, "true", r#""user-5eed0002""#, r#""tok-5eed00000000b002""#];
    let keys = ["username", "password", "id", "uuid", "type", "secret", "tfaCode", "verificationCode", "deviceInfo", "op"];
    for i in 0..300 {
        let mut fields = vec![];
        for k in keys {
            if rnd() % 3 == 0 {
                fields.push(format!(r#""{k}":{}"#, atoms[(rnd() % atoms.len() as u64) as usize]));
            }
        }
        let body = format!("{{{}}}", fields.join(","));
        let path = ["/api/login", "/api/oidc/auth", "/api/currentUser", "/api/logout"][i % 4];
        let r = h.client.post(format!("{}{}", h.url, path)).header("content-type", "application/json").header("x-forwarded-for", format!("198.18.{}.{}", i / 250, i % 250)).body(body.clone()).send().await;
        let r = r.unwrap_or_else(|e| panic!("{path} {body}: {e}"));
        assert!([200, 401, 404, 413, 429, 500].contains(&r.status().as_u16()), "{path} {body}: {}", r.status());
    }
    for q in ["code[]=1", "code=%00", "code=x&id[]=1", "id=1&uuid=2", "", "code=" ] {
        let r = h.req("GET", &format!("/api/oidc/auth-query?{q}"), None, &[]).await;
        assert!([200, 500].contains(&r.status), "{q}");
    }
    for q in ["state[]=1", "state=%00&code=1", "error=1&state=x", "state=" ] {
        let r = h.req("GET", &format!("/login/oidc/client-callback?{q}"), None, &[]).await;
        assert!([400, 403, 500].contains(&r.status), "{q}");
    }
    // still serving
    assert_eq!(h.req("GET", "/api/login-options", None, &[]).await.status, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_replay_notices_a_changed_sign_in_page() {
    // a replay that cannot see a difference is worthless: one expected page text changed must be reported
    let h = harness_with(Opts { real_time: true, ..Default::default() }).await;
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/signin");
    let tmp = tempfile::tempdir().unwrap();
    for f in std::fs::read_dir(&src).unwrap().map(|e| e.unwrap().path()) {
        let name = f.file_name().unwrap().to_string_lossy().into_owned();
        if name.contains("-oidc-auth-c1.json") || name.contains("-oidc-callback-ok.json") || name.contains("-oidc-poll-ok.json") {
            let text = std::fs::read_to_string(&f).unwrap().replace("You are signed in as text-5eed0a01.", "You are signed in as text-5eed0a02.");
            std::fs::write(tmp.path().join(&name), text).unwrap();
        }
    }
    let s = hte_console::sanitise::Sanitiser::new(Some("test"), &[]);
    let r = hte_console::replay::run(tmp.path(), &h.url, &s).await.unwrap();
    assert_eq!(r.total, 3);
    assert_eq!(r.differences.len(), 1, "{:?}", r.differences);
    assert!(r.differences[0].contains("page does not contain"), "{:?}", r.differences);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_browser_that_goes_away_mid_exchange_releases_the_state() {
    let h = harness().await;
    // the browser gives up while the token endpoint is slow: the sign-in still completes, the state is released
    let (code, url) = h.oidc_start("990000280").await;
    let cb = h.authorize(&url, "slow-token", "anna").await;
    let impatient = reqwest::Client::builder().timeout(std::time::Duration::from_millis(300)).build().unwrap();
    assert!(impatient.get(format!("{}{cb}", h.url)).header("x-forwarded-for", "198.18.9.1").send().await.is_err());
    // the slow token endpoint, then provisioning (a bcrypt hash, slow in a debug build)
    let t = std::time::Instant::now();
    while !h.native.signin.inflight.lock().unwrap().is_empty() && t.elapsed() < std::time::Duration::from_secs(15) {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(h.native.signin.inflight.lock().unwrap().is_empty());
    assert_eq!(h.poll(&code, "990000280").await.json()["user"]["name"], "990005001");
    // two callbacks for one state at once: one completes, the other reads as expired
    let (code, url) = h.oidc_start("990000281").await;
    let cb = h.authorize(&url, "slow-token", "anna").await;
    let (a, b) = tokio::join!(h.callback(&cb), async {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        h.callback(&cb).await
    });
    assert_eq!((a.status, b.status), (200, 400));
    assert!(h.poll(&code, "990000281").await.json()["access_token"].is_string());
    assert!(h.native.signin.inflight.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn more_rules_iat_global_2fa_forwarded_root() {
    let h = harness().await;
    let (_, poll) = h.sso("990000290", "iat-future", "anna").await;
    assert!(poll.json()["error"].as_str().unwrap().starts_with("The ID token failed verification: Cannot handle token with iat prior to 2027-01-15T08:10:00+00:00"));
    h.sql("insert into settings (key, value) values ('two_factor_required', '1')");
    assert_eq!(h.login("user-5eed0008", PW, "990000201").await.json()["error"], "Two-factor authentication is required. Set it up in the web console, then sign in again.");
    // from a trusted proxy: X-Forwarded-Port and -Prefix count; a bracketed IPv6 Host keeps its port
    let r = h.req("POST", "/api/oidc/auth", Some(json!({"id": "990000291"})), &[("host", "remote.example.test"), ("x-forwarded-proto", "https"), ("x-forwarded-port", "8443"), ("x-forwarded-prefix", "/c/")]).await;
    assert!(r.json()["url"].as_str().unwrap().contains("redirect_uri=https%3A%2F%2Fremote.example.test%3A8443%2Fc%2Flogin%2Foidc%2Fclient-callback"), "{}", r.body);
    let r = h.req("POST", "/api/oidc/auth", Some(json!({"id": "990000292"})), &[("host", "[::1]:9000")]).await;
    assert!(r.json()["url"].as_str().unwrap().contains("redirect_uri=http%3A%2F%2F%5B%3A%3A1%5D%3A9000%2Flogin"), "{}", r.body);
}
