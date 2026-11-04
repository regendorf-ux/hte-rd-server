//! Phase 7a end to end: the console pages behind the Laravel session (`/logs/*`, `/account*`, `/assets/*`) on a real
//! socket, against a temporary database made from tests/schema_live.sql (the live schema) and a synthetic seed.
//! The session rows are minted here with the crate's own Encrypter, the way the previous console's `SESSION_DRIVER=database` writes
//! them. Expectations come from the previous console's source (v1.15.0-hte.1).

use hte_console::api::{Limiter, Native, Nonces};
use hte_console::laravel::{self, Encrypter};
use hte_console::oidc::Oidc;
use hte_console::pages::{self, session};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const APP_KEY: &str = "base64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
/// 2025-10-25 03:20:00 UTC.
const NOW: i64 = 1_761_362_400;
const TOKEN: &str = "TOKENtokenTOKENtokenTOKENtokenTOKENtoken";

struct H {
    url: String,
    db_path: PathBuf,
    client: reqwest::Client,
    crypt: Encrypter,
    cfg: session::SessionConfig,
    _dir: tempfile::TempDir,
}

struct Resp {
    status: u16,
    headers: reqwest::header::HeaderMap,
    body: String,
}

impl Resp {
    fn location(&self) -> String {
        self.headers.get("location").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default()
    }
    /// The redirect's target without the host (Laravel redirects to absolute URLs).
    fn path(&self) -> String {
        let l = self.location();
        match l.find("://") {
            Some(i) => l[i + 3..].find('/').map(|j| l[i + 3 + j..].to_string()).unwrap_or_default(),
            None => l,
        }
    }
    fn set_cookie(&self) -> Option<String> {
        self.headers.get("set-cookie").map(|v| v.to_str().unwrap().to_string())
    }
}

fn ago(secs: i64) -> String {
    laravel::ts(NOW - secs)
}

const SEED: &str = "
insert into roles (id, name, permissions, require_two_factor) values (1, 'Auditor', '{\"audit\":\"rw\"}', 0);
insert into device_groups (id, name) values (1, 'Front desk');
insert into devices (id, rustdesk_id, uuid, user_id, status) values (1, '1001', 'u1', 2, 'active'), (2, '1002', 'u2', null, 'active'), (3, '1003', 'u3', 2, 'active');
update devices set deleted_at = '2025-10-01 00:00:00' where id = 3;
";

async fn harness() -> H {
    sodiumoxide::init().unwrap();
    std::env::set_var("BCRYPT_ROUNDS", "4");
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cortendesk.sqlite");
    let crypt = Encrypter::from_app_key(APP_KEY).unwrap();
    let c = Connection::open(&db_path).unwrap();
    c.execute_batch(include_str!("schema_live.sql")).unwrap();
    c.execute_batch(hte_console::path::SCHEMA).unwrap(); // the own migration, as the service has run it
    c.execute_batch(SEED).unwrap();
    let hash = laravel::hash_make(b"oldpass123").unwrap();
    for (id, username, name, email, admin, active, role) in [
        (1, "jdoe", "Jane D", "o@example.test", 1, 1, None),
        (2, "dana", "", "dana@example.test", 0, 1, None),
        (3, "erin", "Erin", "erin@example.test", 0, 1, Some(1)),
        (4, "gone", "Gone", "gone@example.test", 0, 0, None),
    ] {
        c.execute(
            "insert into users (id, username, name, email, password, is_admin, is_active, role_id, created_at, updated_at) values (?, ?, ?, ?, ?, ?, ?, ?, '2025-01-01 00:00:00', '2025-01-01 00:00:00')",
            rusqlite::params![id, username, name, email, hash, admin, active, role],
        )
        .unwrap();
    }
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
        clock: Box::new(|| NOW),
    });
    let app = pages::routes(native, None).unwrap().into_make_service_with_connect_info::<std::net::SocketAddr>();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    H { url, db_path, client, crypt, cfg: session::SessionConfig::from_env("HTE Remote"), _dir: dir }
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

    /// A signed-in session row for `uid` (what the previous console's database driver writes) and its cookie.
    fn login(&self, id: &str, uid: i64, extra: Value) -> String {
        let mut data = json!({"_token": TOKEN, session::LOGIN_KEY: uid, "_flash": {"old": [], "new": []}});
        if let Value::Object(m) = extra {
            for (k, v) in m {
                data[k] = v;
            }
        }
        use base64::Engine;
        let payload = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&data).unwrap());
        self.db()
            .execute("insert into sessions (id, user_id, ip_address, user_agent, payload, last_activity) values (?, ?, '198.18.9.1', 'test', ?, ?)", rusqlite::params![id, uid, payload, NOW - 5])
            .unwrap();
        self.cookie(id)
    }

    fn cookie(&self, id: &str) -> String {
        let set = session::set_cookie(&self.cfg, &self.crypt, id, false, NOW);
        set.split(';').next().unwrap().to_string()
    }

    fn payload(&self, id: &str) -> Value {
        use base64::Engine;
        let raw = self.text(&format!("select payload from sessions where id = '{id}'"));
        serde_json::from_slice(&base64::engine::general_purpose::STANDARD.decode(raw).unwrap()).unwrap()
    }

    async fn go(&self, method: &str, path: &str, cookie: Option<&str>, ct: Option<&str>, body: &str, headers: &[(&str, &str)]) -> Resp {
        let mut rq = self.client.request(method.parse().unwrap(), format!("{}{}", self.url, path)).header("x-forwarded-for", "198.18.9.1");
        if let Some(c) = cookie {
            rq = rq.header("cookie", c);
        }
        if let Some(ct) = ct {
            rq = rq.header("content-type", ct);
        }
        for (k, v) in headers {
            rq = rq.header(*k, *v);
        }
        let r = rq.body(body.to_string()).send().await.unwrap();
        let (status, headers) = (r.status().as_u16(), r.headers().clone());
        Resp { status, headers, body: r.text().await.unwrap() }
    }

    async fn theme_post(&self, cookie: &str, token: Option<&str>, header: Option<(&str, String)>, site: Option<&str>) -> Resp {
        let mut headers: Vec<(String, String)> = vec![];
        if let Some((k, v)) = header {
            headers.push((k.to_string(), v));
        }
        if let Some(s) = site {
            headers.push(("sec-fetch-site".into(), s.into()));
        }
        let hs: Vec<(&str, &str)> = headers.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        match token {
            Some(t) => self.go("POST", "/account/theme", Some(cookie), Some("application/x-www-form-urlencoded"), &format!("theme=light&_token={t}"), &hs).await,
            None => self.go("POST", "/account/theme", Some(cookie), Some("application/json"), r#"{"theme":"light"}"#, &hs).await,
        }
    }

    async fn get(&self, path: &str, cookie: &str) -> Resp {
        self.go("GET", path, Some(cookie), None, "", &[]).await
    }

    async fn post_form(&self, path: &str, cookie: &str, form: &[(&str, &str)]) -> Resp {
        let body = laravel::http_build_query(&form.iter().map(|(k, v)| (*k, v.as_bytes())).collect::<Vec<_>>());
        self.go("POST", path, Some(cookie), Some("application/x-www-form-urlencoded"), &body, &[]).await
    }

    fn alarms(&self, n: usize) {
        let c = self.db();
        for i in 0..n {
            c.execute(
                "insert into alarm_logs (rustdesk_id, typ, info, conn_id, created_at, updated_at) values ('1001', 2, ?, 7, ?, ?)",
                rusqlite::params![format!("{{\"ip\":\"10.0.0.{i}\"}}"), ago(330 + i as i64 * 60), ago(330)],
            )
            .unwrap();
        }
    }
}

/// A 40-character session id from a tag.
fn sid(tag: &str) -> String {
    let mut s = tag.repeat(40 / tag.len() + 1);
    s.truncate(40);
    s
}

fn squash(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ------------------------------------------------------------------------------------------------ the gate ---

#[tokio::test(flavor = "multi_thread")]
async fn a_request_without_a_session_goes_to_the_sign_in_page() {
    let h = harness().await;
    let r = h.go("GET", "/logs/alarms", None, None, "", &[]).await;
    assert_eq!((r.status, r.path().as_str()), (302, "/login"));
    // a cookie that is not ours, a forged one, an unknown session id
    let r = h.go("GET", "/logs/alarms", Some("hte-remote-session=nonsense"), None, "", &[]).await;
    assert_eq!(r.status, 302);
    let r = h.go("GET", "/logs/alarms", Some(&h.cookie(&sid("doesnotexist"))), None, "", &[]).await;
    assert_eq!(r.status, 302);
    // nothing is served unauthenticated, not even to a POST
    let r = h.go("POST", "/account/theme", None, Some("application/json"), r#"{"theme":"light"}"#, &[]).await;
    assert_eq!(r.status, 302);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_expired_session_a_disabled_person_and_the_middlewares_that_redirect() {
    let h = harness().await;
    // expired: last_activity older than the lifetime
    let cookie = h.login(&sid("expired"), 1, json!({}));
    h.sql(&format!("update sessions set last_activity = {} where id = '{}'", NOW - 121 * 60, sid("expired")));
    assert_eq!(h.get("/logs/alarms", &cookie).await.status, 302);
    // EnsureUserIsActive
    let cookie = h.login(&sid("inactive"), 4, json!({}));
    assert_eq!(h.get("/account", &cookie).await.status, 302);
    // RequireTwoFactor: required for everyone, this person has none set up
    let cookie = h.login(&sid("twofactor"), 2, json!({}));
    assert_eq!(h.get("/account", &cookie).await.status, 200);
    h.sql("insert into settings (key, value) values ('two_factor_required', '1')");
    // phase 8 (0.8.2): answered here, to the enrolment page
    let r = h.get("/account", &cookie).await;
    assert_eq!((r.status, r.path()), (302, "/account/two-factor".to_string()));
    // ... but not for a session signed in through SSO
    let cookie = h.login(&sid("sso"), 2, json!({session::OIDC_KEY: "oidc"}));
    assert_eq!(h.get("/account", &cookie).await.status, 200);
    // RequireMailHealthy: with verification off the mark is simply dropped (the previous console: "fixed")...
    h.sql("delete from settings");
    let cookie = h.login(&sid("mailrepair"), 2, json!({"mail_repair": true}));
    assert_eq!(h.get("/logs/alarms", &cookie).await.status, 200);
    assert!(h.payload(&sid("mailrepair")).get("mail_repair").is_none());
    // ...with it on and the relay failing, to Settings > Email
    h.sql("insert into settings (key, value) values ('email_login_verification', '1'), ('smtp_enabled', '1'), ('smtp_host', 'smtp.example.test'), ('smtp_from_address', 'a@example.test'), ('smtp_failed_at', '2025-10-25 03:00:00')");
    let cookie = h.login(&sid("mailrepai2"), 1, json!({"mail_repair": true}));
    let r = h.get("/logs/alarms", &cookie).await;
    assert_eq!((r.status, r.path()), (302, "/settings?tab=email".to_string()));
    // RequireEmailAddress: a person with no email is sent to /account, whose forms must still work
    h.sql("delete from settings; insert into settings (key, value) values ('email_login_verification', '1'), ('smtp_enabled', '1'), ('smtp_host', 'smtp.example.test'), ('smtp_from_address', 'a@example.test')");
    h.sql("update users set email = null where id = 2");
    let cookie = h.login(&sid("noemail"), 2, json!({}));
    let r = h.get("/logs/alarms", &cookie).await;
    assert_eq!((r.status, r.path()), (302, "/account".to_string()));
    assert_eq!(h.get("/account", &cookie).await.status, 200);
    let r = h.go("POST", "/account/profile", Some(&cookie), Some("application/x-www-form-urlencoded"), "name=Dana&email=dana%40example.test", &[("x-csrf-token", TOKEN)]).await;
    assert_eq!(r.status, 302);
    assert_eq!(h.text("select email from users where id = 2"), "dana@example.test");
}

#[tokio::test(flavor = "multi_thread")]
async fn csrf_is_checked_for_anything_that_writes() {
    let h = harness().await;
    let cookie = h.login(&sid("csrf"), 1, json!({}));
    let theme = |token: Option<&'static str>, header: Option<(&'static str, String)>, site: Option<&'static str>| h.theme_post(&cookie, token, header, site);
    assert_eq!(theme(None, None, None).await.status, 419);
    assert_eq!(theme(None, None, Some("cross-site")).await.status, 419);
    assert_eq!(theme(Some("wrong"), None, None).await.status, 419);
    assert_eq!(theme(None, Some(("x-csrf-token", "wrong".into())), None).await.status, 419);
    assert_eq!(theme(None, Some(("x-csrf-token", TOKEN.into())), None).await.status, 204);
    assert_eq!(theme(Some(TOKEN), None, None).await.status, 204);
    assert_eq!(theme(None, None, Some("same-origin")).await.status, 204);
    // X-XSRF-TOKEN: the encrypted cookie value Laravel hands the browser, prefixed with the HMAC of the cookie name
    let xsrf = h.crypt.encrypt_string(format!("{}|{}", "x".repeat(40), TOKEN).as_bytes());
    assert_eq!(theme(None, Some(("x-xsrf-token", xsrf)), None).await.status, 204);
    let bad = h.crypt.encrypt_string(format!("{}|{}", "x".repeat(40), "other").as_bytes());
    assert_eq!(theme(None, Some(("x-xsrf-token", bad)), None).await.status, 419);
    // a read never needs one
    assert_eq!(h.get("/account", &cookie).await.status, 200);
}

// ---------------------------------------------------------------------------------------------------- logs ---

#[tokio::test(flavor = "multi_thread")]
async fn every_page_renders_for_an_administrator_with_the_console_markup() {
    let h = harness().await;
    h.alarms(3);
    h.sql("insert into audit_connections (rustdesk_id, from_peer, from_name, ip, conn_type, created_at, closed_at, note, note_user_id) values ('1001', '555', 'Front PC', '10.1.1.1', 1, '2025-10-25 03:10:00', '2025-10-25 03:12:05', 'ticket 42', 1), ('1002', '', '', '', 0, '2025-10-25 03:19:00', null, null, null)");
    h.sql("insert into audit_file_transfers (rustdesk_id, from_peer, path, info, direction, file_count, ip, created_at) values ('1001', '555', '/tmp/a.pdf', null, 1, 1, '10.1.1.1', '2025-10-25 03:00:00'), ('1002', '555', '', '{\"files\":[[\"x.txt\",1],[\"y.txt\",2],[\"z.txt\",3]]}', 0, 3, '', '2025-10-25 02:00:00')");
    h.sql("insert into login_logs (username, client, device_id, device_os, ip, successful, note, created_at) values ('jdoe', 'web', '', '', '10.9.9.9', 1, null, '2025-10-25 03:18:00'), ('mallory', 'desktop', '9', 'macOS', '10.9.9.8', 0, 'bad password', '2025-10-25 03:17:00')");
    h.sql("insert into console_audits (user_id, username, action, target_type, target_id, summary, ip, created_at) values (1, 'jdoe', 'device.update', 'device', '1001', 'Updated device 1001', '10.9.9.9', '2025-10-25 03:15:00')");
    let cookie = h.login(&sid("admin"), 1, json!({}));
    for (path, title, needle) in [
        ("/logs/alarms", "Alarm Log", "Rapid access attempts"),
        ("/logs/connections", "Connection Log", "ticket 42"),
        ("/logs/file-transfers", "File Transfer Log", "x.txt, y.txt +1 more"),
        ("/logs/logins", "Login Log", "mallory"),
        ("/logs/console", "Console Audit", "Updated device 1001"),
        ("/account", "My Account", "Change Password"),
    ] {
        let r = h.get(path, &cookie).await;
        assert_eq!(r.status, 200, "{path}");
        assert!(r.body.contains(&format!("<title>{title} | HTE Remote</title>")), "{path}: {}", &r.body[..400.min(r.body.len())]);
        assert!(r.body.contains(needle), "{path} lacks {needle}");
        assert!(r.body.contains(r#"name="csrf-token" content="TOKENtokenTOKENtokenTOKENtokenTOKENtoken""#), "{path}");
        assert!(r.body.contains(concat!("/assets/css/hte-brand.css?v=", env!("CARGO_PKG_VERSION"))), "{path}");
        assert!(r.body.contains("/assets/vendor/htmx/htmx.min.js"), "{path}");
        // the administrator's sidebar: every group
        assert!(r.body.contains("Build Installers") || r.body.contains("Client Downloads"), "{path}");
        assert!(r.body.contains(">Console</a>") && r.body.contains(">Roles </span>") == false || r.body.contains("Roles"), "{path}");
        let cookie_back = r.set_cookie().unwrap();
        assert!(cookie_back.starts_with("hte-remote-session="), "{cookie_back}");
    }
    // the connection log: the file transfer badge, the duration, the active badge, the note's author
    let r = h.get("/logs/connections", &cookie).await;
    let body = squash(&r.body);
    assert!(body.contains("File Transfer</span>"));
    assert!(body.contains(r#"<span title="Closed 2025-10-25 03:12:05"> 2m 5s </span>"#), "{body}");
    assert!(body.contains("Active</span>"));
    assert!(body.contains(r#"<span class="rd-cell-sub">jdoe</span>"#));
    assert!(body.contains(r#"title="2025-10-25 03:10:00">10 minutes ago</span>"#));
    // the alarm log: the three rows, info shown as key: value pairs, the paging line
    let r = h.get("/logs/alarms", &cookie).await;
    let body = squash(&r.body);
    assert!(body.contains("Showing 1–3 of 3"));
    assert!(body.contains(r#"<span class="text-muted">ip:</span> 10.0.0.0"#));
    assert!(body.contains("5 minutes ago"));
    assert!(body.contains("conn 7 · 5m ago"));
}

#[tokio::test(flavor = "multi_thread")]
async fn filters_dates_and_paging() {
    let h = harness().await;
    h.alarms(45);
    h.sql("insert into alarm_logs (rustdesk_id, typ, info, created_at) values ('1002', 0, 'blocked 1.2.3.4', '2025-09-01 12:00:00'), ('console', 100, 'brute force', '2025-09-02 12:00:00')");
    let cookie = h.login(&sid("filters"), 1, json!({}));
    let body = |r: &Resp| squash(&r.body);
    let r = h.get("/logs/alarms", &cookie).await;
    assert!(body(&r).contains("Showing 1–20 of 47"), "{}", body(&r));
    assert!(body(&r).contains(r#"href="/logs/alarms?page=2""#));
    let r = h.get("/logs/alarms?page=3", &cookie).await;
    assert!(body(&r).contains("Showing 41–47 of 47"));
    // a page past the end is empty, not clamped
    let r = h.get("/logs/alarms?page=9", &cookie).await;
    assert!(body(&r).contains("Showing 0–0 of 47") && body(&r).contains("No alarms match your filters."));
    let r = h.get("/logs/alarms?perPage=50&search=blocked", &cookie).await;
    assert!(body(&r).contains("Showing 1–1 of 1") && body(&r).contains("blocked 1.2.3.4"));
    let r = h.get("/logs/alarms?type=100", &cookie).await;
    assert!(body(&r).contains("Showing 1–1 of 1") && body(&r).contains("Console</span>"));
    // whereDate: both ends are inclusive days
    let r = h.get("/logs/alarms?dateFrom=2025-09-01&dateTo=2025-09-01", &cookie).await;
    assert!(body(&r).contains("Showing 1–1 of 1") && body(&r).contains("blocked 1.2.3.4"));
    let r = h.get("/logs/alarms?dateFrom=2025-09-01&dateTo=2025-09-02", &cookie).await;
    assert!(body(&r).contains("of 2"), "{}", body(&r));
    // the pager's links keep the filters
    let r = h.get("/logs/alarms?perPage=20&search=10.0.0&type=2", &cookie).await;
    assert!(body(&r).contains(r#"href="/logs/alarms?search=10.0.0&amp;type=2&amp;page=2""#), "{}", body(&r));
    // an unknown perPage is the default
    let r = h.get("/logs/alarms?perPage=7", &cookie).await;
    assert!(body(&r).contains("Showing 1–20 of 47"));
    // LIKE is not escaped: a % matches everything, as in the previous console
    let r = h.get("/logs/alarms?search=%25", &cookie).await;
    assert!(body(&r).contains("of 47"));
}

#[tokio::test(flavor = "multi_thread")]
async fn who_sees_what() {
    let h = harness().await;
    h.sql("insert into alarm_logs (rustdesk_id, typ, info, created_at) values ('1001', 0, 'own device alarm', '2025-10-25 03:00:00'), ('1002', 0, 'someone elses alarm', '2025-10-25 03:00:00'), ('1003', 0, 'recycled device alarm', '2025-10-25 03:00:00'), ('console', 100, 'console alarm', '2025-10-25 03:00:00'), ('9999', 0, 'unknown device alarm', '2025-10-25 03:00:00')");
    let admin = h.login(&sid("admin"), 1, json!({}));
    let dana = h.login(&sid("dana"), 2, json!({}));
    let erin = h.login(&sid("erin"), 3, json!({}));
    let r = h.get("/logs/alarms", &admin).await;
    assert!(r.body.contains("of 5"), "{}", squash(&r.body));
    // a person with no role: devices and address books, and the logs at read level; their own devices only
    let r = h.get("/logs/alarms", &dana).await;
    let b = squash(&r.body);
    assert!(b.contains("own device alarm") && b.contains("Showing 1–1 of 1"), "{b}");
    assert!(!b.contains("someone elses") && !b.contains("console alarm") && !b.contains("recycled") && !b.contains("unknown device"));
    // ... who sees no Logins and Console entries in the sidebar, and is turned away from those pages
    assert!(!b.contains(r#"href="/logs/logins""#) && !b.contains(r#"href="/settings""#) && !b.contains(r#"href="/users""#));
    let r = h.get("/logs/logins", &dana).await;
    assert_eq!((r.status, r.path().as_str()), (302, "/"), "{}", r.location());
    let r = h.get("/logs/console/export", &dana).await;
    assert_eq!(r.status, 302);
    let flash = h.payload(&sid("dana"));
    assert_eq!(flash["_flash"], json!({"old": ["denied"], "new": []}));
    assert_eq!(flash["denied"], "That section is restricted.");
    // a role with audit rw and no devices: the logs page opens, the device-scoped lists are empty
    let r = h.get("/logs/alarms", &erin).await;
    assert!(squash(&r.body).contains("Showing 0–0 of 0"));
    assert_eq!(h.get("/logs/logins", &erin).await.status, 200);
    assert_eq!(h.get("/logs/console", &erin).await.status, 200);
    // the flash is there for the next request and gone after it
    assert_eq!(h.get("/account", &dana).await.status, 200);
    let after = h.payload(&sid("dana"));
    assert_eq!(after["_flash"], json!({"old": [], "new": []}));
    assert!(after.get("denied").is_none());
}

/// HTE: the connection log's Path column and filter, the CSV's Path and size, and the dashboard's bar of how sessions connected.
#[tokio::test(flavor = "multi_thread")]
async fn connection_paths_show_in_the_log_the_export_and_the_dashboard() {
    let h = harness().await;
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    h.sql(&format!("insert into relay_sessions (uuid, rustdesk_id, started_at, ended_at, bytes, created_at) values ('r1', '2002', '{now}', '{now}', 12345678, '{now}')"));
    h.sql(&format!(
        "insert into audit_connections (rustdesk_id, from_peer, from_name, ip, conn_type, path, relay_session_id, created_at) values
           ('2001', '555', 'Lan PC', '10.1.1.1', 0, 'lan', null, '{now}'),
           ('2002', '555', 'Relay PC', '10.1.1.2', 0, 'punch', 1, '{now}'),
           ('2003', '555', 'Direct PC', '10.1.1.3', 0, 'punch-webrtc', null, '{now}'),
           ('2004', '555', 'Old PC', '10.1.1.4', 0, null, null, '{now}'),
           ('2005', '555', 'Punch PC', '10.1.1.5', 0, 'punch', null, '{now}')"
    ));
    let cookie = h.login(&sid("paths"), 1, json!({}));
    let all = h.get("/logs/connections", &cookie).await.body;
    for needle in ["<th>Path</th>", "LAN", "Hole punch", "WebRTC", "12.3 MB"] {
        assert!(all.contains(needle), "{needle}");
    }
    // a punch that ended on the relay is counted as relay, not direct
    let only = |f: &str| {
        let h = &h;
        let cookie = cookie.clone();
        let f = f.to_string();
        async move { h.get(&format!("/logs/connections?path={f}"), &cookie).await.body }
    };
    let relay = only("relay").await;
    assert!(relay.contains("Relay PC") && !relay.contains("Direct PC") && !relay.contains("Lan PC") && !relay.contains("Old PC"));
    let direct = only("direct").await;
    assert!(direct.contains("Direct PC") && direct.contains("Punch PC") && !direct.contains("Relay PC"));
    assert!(only("lan").await.contains("Lan PC"));
    let unknown = only("unknown").await;
    assert!(unknown.contains("Old PC") && !unknown.contains("Lan PC"));
    // the pager keeps the filter; an unknown value is no filter
    assert!(only("relay").await.contains("value=\"relay\" selected"));
    assert!(only("nonsense").await.contains("Lan PC"));
    let csv = h.get("/logs/connections/export?path=relay", &cookie).await.body;
    assert!(csv.contains(",Relay,12345678,"), "{csv}");
    assert!(!csv.contains("Lan PC"), "{csv}");
    // the dashboard: the five sessions (one of them relayed)
    let dash = h.get("/", &cookie).await.body;
    assert!(dash.contains("How sessions connected") && dash.contains("5 sessions"), "{dash}");
}

#[tokio::test(flavor = "multi_thread")]
async fn csv_exports() {
    let h = harness().await;
    h.sql("insert into alarm_logs (rustdesk_id, typ, info, conn_id, created_at) values ('1001', 1, '=HYPERLINK(\"x\")', 9, '2025-10-25 03:00:00'), ('1002', 55, 'plain, with comma', null, '2025-10-25 02:00:00')");
    h.sql("insert into audit_connections (rustdesk_id, from_peer, from_name, ip, conn_type, created_at, closed_at, note, note_user_id) values ('1001', '555', 'Front PC', '10.1.1.1', 4, '2025-10-25 03:10:00', '2025-10-25 03:12:05', 'ticket 42', 1), ('1002', '', '', '', 9, '2025-10-25 03:19:00', null, null, null)");
    let cookie = h.login(&sid("export"), 1, json!({}));
    let r = h.get("/logs/alarms/export", &cookie).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.headers.get("content-type").unwrap(), "text/html; charset=UTF-8");
    assert_eq!(r.headers.get("content-disposition").unwrap(), "attachment; filename=alarm-log.csv");
    assert_eq!(
        r.body,
        "When,Device,Type,Info,\"Conn ID\"\n\"2025-10-25 03:00:00\",1001,\"Many failed attempts (>30)\",\"'=HYPERLINK(\"\"x\"\")\",9\n\"2025-10-25 02:00:00\",1002,\"Type 55\",\"plain, with comma\",\n"
    );
    let r = h.get("/logs/connections/export?search=1001", &cookie).await;
    assert_eq!(
        r.body,
        "When,\"Controlled Device\",\"From ID\",\"From Name\",Type,IP,Path,\"Relayed (bytes)\",\"Closed At\",\"Duration (s)\",Note,\"Note By\"\n\"2025-10-25 03:10:00\",1001,555,\"Front PC\",Terminal,10.1.1.1,,,\"2025-10-25 03:12:05\",125,\"ticket 42\",jdoe\n"
    );
    let r = h.get("/logs/connections/export", &cookie).await;
    assert!(r.body.contains("\"Type 9\",,,,active,,,"), "{}", r.body);
    // a person with no role gets the export of what they see
    let dana = h.login(&sid("danaexport"), 2, json!({}));
    let r = h.get("/logs/alarms/export", &dana).await;
    assert!(r.body.contains("1001") && !r.body.contains("1002"), "{}", r.body);
}

// -------------------------------------------------------------------------------------------------- account ---

#[tokio::test(flavor = "multi_thread")]
async fn saving_the_profile_writes_what_php_writes() {
    let h = harness().await;
    let cookie = h.login(&sid("profile"), 2, json!({}));
    let r = h.get("/account", &cookie).await;
    let b = squash(&r.body);
    assert!(b.contains(r#"<span class="rd-cell-title">dana</span>"#) && b.contains("dana@example.test"), "{b}");
    assert!(b.contains(r#"value="dana@example.test""#));
    // an email that is taken, then a malformed one: 422 with the messages, nothing written
    let r = h.post_form("/account/profile", &cookie, &[("_token", TOKEN), ("name", "Dana S"), ("email", "o@example.test")]).await;
    assert_eq!(r.status, 422);
    assert!(r.body.contains("The email has already been taken.") && r.body.contains(r#"value="Dana S""#), "{}", squash(&r.body));
    let r = h.post_form("/account/profile", &cookie, &[("_token", TOKEN), ("name", "Dana S"), ("email", "not-an-email")]).await;
    assert_eq!(r.status, 422);
    assert!(r.body.contains("The email field must be a valid email address."));
    assert_eq!(h.text("select name from users where id = 2"), "");
    assert_eq!(h.count("console_audits"), 0);
    // the saved profile: redirect, the rows, the audit entry, the flash
    let r = h.post_form("/account/profile", &cookie, &[("_token", TOKEN), ("name", "Dana S"), ("email", "dana2@example.test")]).await;
    assert_eq!((r.status, r.path().as_str()), (302, "/account"), "{}", r.location());
    assert_eq!(h.text("select name from users where id = 2"), "Dana S");
    assert_eq!(h.text("select email from users where id = 2"), "dana2@example.test");
    assert_eq!(h.text("select updated_at from users where id = 2"), laravel::ts(NOW));
    assert_eq!(h.text("select action || '|' || username || '|' || target_type || '|' || target_id || '|' || summary || '|' || ip || '|' || created_at from console_audits"), format!("account.update|dana|user|2|Updated own profile|198.18.9.1|{}", laravel::ts(NOW)));
    let r = h.get("/account", &cookie).await;
    assert!(r.body.contains("Profile saved."));
    assert!(!h.get("/account", &cookie).await.body.contains("Profile saved."));
    // saving nothing new writes no row (Eloquent's dirty check) but is still audited, like the previous console
    let before = h.text("select updated_at from users where id = 2");
    h.post_form("/account/profile", &cookie, &[("_token", TOKEN), ("name", "Dana S"), ("email", "dana2@example.test")]).await;
    assert_eq!(h.text("select updated_at from users where id = 2"), before);
    assert_eq!(h.count("console_audits"), 2);
    // blank fields clear the columns to NULL
    h.post_form("/account/profile", &cookie, &[("_token", TOKEN), ("name", ""), ("email", "")]).await;
    assert_eq!(h.text("select typeof(name) || typeof(email) from users where id = 2"), "nulln".to_string() + "ull");
}

#[tokio::test(flavor = "multi_thread")]
async fn changing_the_password() {
    let h = harness().await;
    h.sql("insert into trusted_devices (user_id, token_hash, expires_at) values (2, 'a', '2030-01-01 00:00:00'), (2, 'b', '2030-01-01 00:00:00'), (1, 'c', '2030-01-01 00:00:00')");
    let old = sid("passwd");
    let cookie = h.login(&old, 2, json!({}));
    let before = h.text("select password from users where id = 2");
    let post = |current: &'static str, new: &'static str, confirm: &'static str| {
        let h = &h;
        let cookie = cookie.clone();
        async move { h.post_form("/account/password", &cookie, &[("_token", TOKEN), ("current_password", current), ("password", new), ("password_confirmation", confirm)]).await }
    };
    let r = post("", "", "").await;
    assert_eq!(r.status, 422);
    for m in ["The current password field is required.", "The password field is required.", "Please confirm the new password."] {
        assert!(r.body.contains(m), "{m}");
    }
    let r = post("oldpass123", "short", "short").await;
    assert!(r.body.contains("The password field must be at least 8 characters."));
    let r = post("oldpass123", "longenough1", "different1").await;
    assert!(r.body.contains("The new passwords do not match."));
    let r = post("not the password", "longenough1", "longenough1").await;
    assert_eq!(r.status, 422);
    assert!(r.body.contains("That is not your current password."));
    assert_eq!(h.text("select password from users where id = 2"), before);
    assert_eq!(h.count("trusted_devices"), 3);
    // the change: a $2y$ hash that verifies, the person's trusted browsers gone, a new session id, the audit row
    let r = post("oldpass123", "  new pass 456 ", "  new pass 456 ").await;
    assert_eq!((r.status, r.path().as_str()), (302, "/account"));
    let hash = h.text("select password from users where id = 2");
    assert!(hash.starts_with("$2y$"));
    assert!(laravel::hash_check(b"  new pass 456 ", &hint(&hash)).unwrap(), "the password is kept exactly as typed");
    assert_eq!(h.count("trusted_devices"), 1);
    assert_eq!(h.text("select action || '|' || summary from console_audits"), "account.password|Changed own password");
    let set = r.set_cookie().unwrap();
    assert!(set.starts_with("hte-remote-session="));
    let new_cookie = set.split(';').next().unwrap().to_string();
    assert_ne!(new_cookie, cookie);
    // the old row is gone: a copy of the old cookie is nobody's session any more
    assert_eq!(h.count("sessions where user_id = 2"), 1);
    let r = h.get("/account", &cookie).await;
    assert_eq!(r.status, 302, "the old cookie no longer opens the page");
    // the new session carries the flash for the page the redirect lands on, and works on its own
    let r = h.get("/account", &new_cookie).await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("Password changed."));
}

fn hint(s: &str) -> hte_console::php::Val {
    hte_console::php::Val::str(s)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_theme_is_saved_and_validated() {
    let h = harness().await;
    let cookie = h.login(&sid("theme"), 1, json!({}));
    let post = |body: &'static str| {
        let (h, cookie) = (&h, cookie.clone());
        async move { h.go("POST", "/account/theme", Some(&cookie), Some("application/json"), body, &[("x-csrf-token", TOKEN)]).await }
    };
    let r = post(r#"{"theme":"light"}"#).await;
    assert_eq!(r.status, 204);
    assert_eq!(h.text("select theme from users where id = 1"), "light");
    let r = post(r#"{"theme":"purple"}"#).await;
    // deliberate: the previous console redirects back here; this answers 422 with the messages
    assert_eq!(r.status, 422);
    assert!(r.body.contains("The selected theme is invalid."));
    let r = post("{}").await;
    assert_eq!(r.status, 422);
    assert_eq!(h.text("select theme from users where id = 1"), "light");
    // the page follows the saved choice
    let r = h.get("/account", &cookie).await;
    assert!(r.body.contains(r#"data-bs-theme="light" data-rd-theme-pref="light""#));
    assert!(r.body.contains(r#"value="light" data-rd-theme-radio checked"#), "{}", squash(&r.body));
}

#[tokio::test(flavor = "multi_thread")]
async fn assets_are_served_and_the_server_refuses_anything_else() {
    let h = harness().await;
    let r = h.go("GET", "/assets/css/hte-remote.css", None, None, "", &[]).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.headers.get("content-type").unwrap(), "text/css; charset=utf-8");
    assert!(r.body.contains(".rd-toolbar"));
    let r = h.go("GET", "/assets/vendor/htmx/htmx.min.js", None, None, "", &[]).await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("htmx"));
    assert_eq!(h.go("GET", "/assets/nope.css", None, None, "", &[]).await.status, 404);
    assert_eq!(h.go("GET", "/assets/%2e%2e/Cargo.toml", None, None, "", &[]).await.status, 404);
    assert_eq!(h.go("POST", "/assets/css/hte-remote.css", None, None, "", &[]).await.status, 405);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_method_is_php_s_business_for_everyone() {
    let h = harness().await;
    let cookie = h.login(&sid("method"), 1, json!({}));
    // nothing is answered before the session is checked: even a wrong method goes to the previous console (here: the sign-in redirect)
    assert_eq!(h.go("DELETE", "/logs/alarms", Some(&cookie), None, "", &[]).await.status, 302);
    assert_eq!(h.go("POST", "/logs/alarms", None, None, "", &[]).await.status, 302);
    let big = "x".repeat(70 * 1024);
    assert_eq!(h.go("POST", "/account/profile", Some(&cookie), Some("application/x-www-form-urlencoded"), &big, &[]).await.status, 413);
}

// ------------------------------------------------------------------------------------- the replay tool itself ---

/// `hte-console page-replay` against hte-console on both sides must find nothing (it is how the tool is checked here:
/// The previous console is not available on this machine), and must see a difference when one exists.
#[tokio::test(flavor = "multi_thread")]
async fn the_page_replay_finds_no_difference_between_two_identical_consoles_and_sees_a_real_one() {
    use hte_console::pagereplay;
    let (a, b) = (harness().await, harness().await);
    let seed = pagereplay::seed_sql(NOW).unwrap();
    for h in [&a, &b] {
        h.sql(&seed);
    }
    let r = pagereplay::run_with(&a.url, &b.url, APP_KEY, "hte-remote-session", NOW, false).await.unwrap();
    assert!(r.total > 45, "{} requests", r.total);
    assert!(r.differences.is_empty(), "{}", r.differences.join("\n"));
    // one text changed on one side
    b.sql("update alarm_logs set info = 'tampered' where id = 3");
    let r = pagereplay::run_with(&a.url, &b.url, APP_KEY, "hte-remote-session", NOW, false).await.unwrap();
    assert!(r.differences.iter().any(|d| d.contains("GET /logs/alarms") && d.contains("tampered")), "{:?}", r.differences);
    // and a different class (a badge) on one side
    b.sql("update alarm_logs set info = (select info from alarm_logs where id = 2) where id = 3; update alarm_logs set typ = 9 where id = 5");
    let r = pagereplay::run_with(&a.url, &b.url, APP_KEY, "hte-remote-session", NOW, false).await.unwrap();
    assert!(r.differences.iter().any(|d| d.contains("classes") || d.contains("text")), "{:?}", r.differences);
}
