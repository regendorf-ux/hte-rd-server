//! Phase 7b end to end: the devices, users, groups, address-book, strategy, dashboard and settings pages on a real
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
insert into device_groups (id, name) values (1, 'Front desk'), (2, 'Back office');
insert into user_groups (id, name) values (1, 'Techs');
insert into devices (id, rustdesk_id, uuid, hostname, username, os, version, alias, user_id, device_group_id, status, last_online_at, last_online_ip, created_at, updated_at) values
 (1, '1001', 'u1', 'FRONT-PC', 'dana', 'windows / Windows 11', '1.4.0', 'Front PC', 2, 1, 'active', '2025-10-25 03:19:30', '10.0.0.1', '2025-09-01 10:00:00', '2025-10-25 03:19:30'),
 (2, '1002', 'u2', 'BACK-PC', 'erin', 'macos / macOS 14', '1.3.9', null, null, 2, 'active', '2025-10-20 08:00:00', '10.0.0.2', '2025-09-02 10:00:00', '2025-10-20 08:00:00'),
 (3, '1003', 'u3', 'OLD-PC', 'dana', 'linux / Ubuntu', '1.3.0', null, 2, null, 'active', null, null, '2025-09-03 10:00:00', '2025-09-03 10:00:00'),
 (4, '1004', 'u4', 'NEW-PC', 'dana', 'windows / Windows 10', '1.4.0', null, null, null, 'pending', '2025-10-25 03:00:00', '10.0.0.4', '2025-10-24 10:00:00', '2025-10-24 10:00:00');
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

    /// A multipart form with one file (the backup upload).
    async fn post_file(&self, path: &str, cookie: &str, field: &str, filename: &str, data: &[u8]) -> Resp {
        let mut body = format!("--XyZ\r\nContent-Disposition: form-data; name=\"_token\"\r\n\r\n{TOKEN}\r\n--XyZ\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\nContent-Type: application/x-tar\r\n\r\n").into_bytes();
        body.extend_from_slice(data);
        body.extend_from_slice(b"\r\n--XyZ--\r\n");
        let r = self
            .client
            .post(format!("{}{}", self.url, path))
            .header("x-forwarded-for", "198.18.9.1")
            .header("cookie", cookie)
            .header("content-type", "multipart/form-data; boundary=XyZ")
            .body(body)
            .send()
            .await
            .unwrap();
        let (status, headers) = (r.status().as_u16(), r.headers().clone());
        Resp { status, headers, body: r.text().await.unwrap() }
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

// ------------------------------------------------------------------------------------------------ devices ---

fn tok() -> (&'static str, &'static str) {
    ("_token", TOKEN)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_device_list_and_its_filters() {
    let h = harness().await;
    let cookie = h.login(&sid("devlist"), 1, json!({}));
    let r = h.get("/devices", &cookie).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let body = squash(&r.body);
    let r_body = r.body.clone();
    assert!(body.contains("<title>Devices | HTE Remote</title>"));
    // chips: 3 live devices (1,2,4 is pending so not counted; 3 is trashed): total 2, online 1
    assert!(body.contains(r#"<span class="rd-chip-value">2</span> <span class="rd-chip-label">Devices</span>"#), "{body}");
    assert!(body.contains(r#"<span class="rd-chip-value">1</span> <span class="rd-chip-label">Online</span>"#));
    assert!(body.contains(r#"<span class="rd-chip-value">1</span> <span class="rd-chip-label">Pending</span>"#));
    assert!(body.contains("Recycle Bin (1)"));
    assert!(body.contains("FRONT-PC") && body.contains("BACK-PC") && !body.contains("OLD-PC"));
    // default order: last seen, newest first
    assert!(body.find("FRONT-PC").unwrap() < body.find("BACK-PC").unwrap());
    // the Terminal action sits beside Connect (twice: the table and the compact list) for a desktop computer, with the same
    // address as Connect plus the terminal mode, and never for a phone
    let terminal = |b: &str, id: &str| b.matches(&format!(r#"href="/webclient?id={id}&amp;mode=terminal""#)).count();
    let connect = |b: &str, id: &str| b.matches(&format!(r#"href="/webclient?id={id}""#)).count();
    for id in ["1001", "1002"] {
        assert_eq!((connect(&r_body, id), terminal(&r_body, id)), (2, 2), "{id}");
    }
    h.sql("update devices set os = 'android / Android 14' where rustdesk_id = '1002'");
    let r = h.get("/devices", &cookie).await;
    assert_eq!((connect(&r.body, "1002"), terminal(&r.body, "1002")), (2, 0), "no terminal on Android");
    assert_eq!(terminal(&r.body, "1001"), 2);
    h.sql("update devices set os = 'ios / iOS 17' where rustdesk_id = '1002'");
    assert_eq!(terminal(&h.get("/devices", &cookie).await.body, "1002"), 0);
    h.sql("update devices set os = 'macos / macOS 14' where rustdesk_id = '1002'");
    // search, status, group, owner
    let r = h.get("/devices?search=erin", &cookie).await;
    assert!(r.body.contains("BACK-PC") && !r.body.contains("FRONT-PC"));
    let r = h.get("/devices?status=offline", &cookie).await;
    assert!(r.body.contains("BACK-PC") && !r.body.contains("FRONT-PC"));
    let r = h.get("/devices?group=1", &cookie).await;
    assert!(r.body.contains("FRONT-PC") && !r.body.contains("BACK-PC"));
    let r = h.get("/devices?owner=-1", &cookie).await;
    assert!(r.body.contains("BACK-PC") && !r.body.contains("FRONT-PC"));
    let r = h.get("/devices?trashed=1", &cookie).await;
    assert!(r.body.contains("OLD-PC") && r.body.contains("Recycle bin"));
    let r = h.get("/devices?pending=1", &cookie).await;
    assert!(squash(&r.body).contains("Pending approval") && r.body.contains("1004") && r.body.contains("Approve"));
    // the person without admin sees only theirs
    let dana = h.login(&sid("devdana"), 2, json!({}));
    let r = h.get("/devices", &dana).await;
    assert!(r.body.contains("FRONT-PC") && !r.body.contains("BACK-PC"), "{}", r.body);
    assert!(!r.body.contains("All owners"));
    let r = h.get("/devices/2", &dana).await;
    assert_eq!(r.status, 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn sorting_and_columns_are_saved_on_the_person() {
    let h = harness().await;
    let cookie = h.login(&sid("devsort"), 1, json!({}));
    let r = h.post_form("/devices/sort", &cookie, &[tok(), ("field", "id"), ("back", "")]).await;
    assert_eq!(r.status, 302, "{}", r.body);
    assert_eq!(h.text("select devices_sort from users where id = 1"), "id");
    assert_eq!(h.text("select devices_sort_direction from users where id = 1"), "asc");
    let r = h.post_form("/devices/sort", &cookie, &[tok(), ("field", "id"), ("back", "")]).await;
    assert_eq!(r.status, 302);
    assert_eq!(h.text("select devices_sort_direction from users where id = 1"), "desc");
    let body = h.get("/devices", &cookie).await.body;
    assert!(body.find("BACK-PC").unwrap() < body.find("FRONT-PC").unwrap());
    // columns
    let r = h.post_form("/devices/columns", &cookie, &[tok(), ("columns[]", "device"), ("columns[]", "cpu"), ("back", ""), ("done", "1")]).await;
    assert_eq!(r.status, 302);
    assert_eq!(h.text("select devices_columns from users where id = 1"), r#"["device","cpu"]"#);
    let body = h.get("/devices", &cookie).await.body;
    assert!(body.contains(">CPU</th>") && !body.contains(">Version"));
    h.post_form("/devices/columns", &cookie, &[tok(), ("reset", "1"), ("back", "")]).await;
    assert_eq!(h.text("select coalesce(devices_columns, 'NULL') from users where id = 1"), "NULL");
}

#[tokio::test(flavor = "multi_thread")]
async fn device_writes() {
    let h = harness().await;
    let cookie = h.login(&sid("devwrite"), 1, json!({}));
    // bulk: incoming only, then a group move
    let r = h.post_form("/devices/bulk", &cookie, &[tok(), ("do", "incoming"), ("selected[]", "1"), ("selected[]", "2"), ("back", "")]).await;
    assert_eq!(r.status, 302, "{}", r.body);
    assert_eq!(h.count("devices where can_initiate = 0"), 2);
    assert_eq!(h.text("select summary from console_audits where action = 'device.initiate'"), "Set 2 devices incoming only");
    let body = h.get("/devices", &cookie).await.body;
    assert!(squash(&body).contains("2 devices set incoming only."));
    let r = h.post_form("/devices/bulk", &cookie, &[tok(), ("do", "move-group"), ("selected[]", "1"), ("selected[]", "2"), ("group_id", "2"), ("back", "")]).await;
    assert_eq!(r.status, 302);
    assert_eq!(h.text("select cast(device_group_id as text) from devices where id = 1"), "2");
    assert_eq!(h.text("select summary from console_audits where action = 'device.group-move'"), "Moved 1 device to Back office; 1 unchanged.");
    // a group move without a choice shows the picker with its message
    let r = h.post_form("/devices/bulk", &cookie, &[tok(), ("do", "move-group"), ("selected[]", "1"), ("back", "")]).await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("Pick a device group."));
    // edit
    let r = h.post_form("/devices/save", &cookie, &[tok(), ("id", "1"), ("alias", "Desk"), ("note", "n"), ("group_id", "1"), ("user_id", "0"), ("can_initiate", "1"), ("strategy_id", "0"), ("return", "/devices")]).await;
    assert_eq!(r.status, 302, "{}", r.body);
    assert_eq!(h.text("select alias from devices where id = 1"), "Desk");
    assert_eq!(h.text("select coalesce(cast(user_id as text), 'NULL') from devices where id = 1"), "NULL");
    assert_eq!(h.count("console_audits where action = 'device.update'"), 1);
    assert_eq!(h.count("console_audits where action = 'device.initiate' and summary like 'Device 1001%'"), 1);
    // create, with a duplicate id refused
    let r = h.post_form("/devices/save", &cookie, &[tok(), ("id", "0"), ("rustdesk_id", "2001"), ("alias", ""), ("note", ""), ("group_id", "0"), ("user_id", "0"), ("can_initiate", "1"), ("return", "/devices")]).await;
    assert_eq!(r.status, 302);
    assert_eq!(h.count("devices where rustdesk_id = '2001'"), 1);
    let r = h.post_form("/devices/save", &cookie, &[tok(), ("id", "0"), ("rustdesk_id", "2001"), ("return", "/devices")]).await;
    assert_eq!(r.status, 422);
    assert!(r.body.contains("The form rustdesk id has already been taken."), "{}", r.body);
    // delete, restore, destroy
    let r = h.post_form("/devices/bulk", &cookie, &[tok(), ("do", "delete"), ("selected[]", "2"), ("back", "")]).await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("Delete device 1002?"));
    let r = h.post_form("/devices/delete", &cookie, &[tok(), ("ids[]", "2"), ("return", "/devices")]).await;
    assert_eq!(r.status, 302);
    assert!(h.text("select deleted_at from devices where id = 2").starts_with("2025-10-25"));
    h.post_form("/devices/act", &cookie, &[tok(), ("do", "restore"), ("id", "2"), ("back", "trashed=1")]).await;
    assert_eq!(h.text("select coalesce(deleted_at, 'NULL') from devices where id = 2"), "NULL");
    h.post_form("/devices/act", &cookie, &[tok(), ("do", "destroy"), ("id", "3"), ("back", "trashed=1")]).await;
    assert_eq!(h.count("devices where id = 3"), 0);
    // approve
    h.post_form("/devices/act", &cookie, &[tok(), ("do", "approve"), ("id", "4"), ("back", "pending=1")]).await;
    assert_eq!(h.text("select status from devices where id = 4"), "active");
    assert_eq!(h.text("select summary from console_audits where action = 'device.approve'"), "Approved device 1004");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_device_page() {
    let h = harness().await;
    h.sql("insert into audit_connections (rustdesk_id, from_peer, from_name, ip, conn_type, created_at, closed_at) values ('1001', '555', 'Front PC', '10.1.1.1', 0, '2025-10-25 03:10:00', '2025-10-25 03:12:05')");
    let cookie = h.login(&sid("devpage"), 1, json!({}));
    let r = h.get("/devices/1", &cookie).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let body = squash(&r.body);
    assert!(body.contains("Front PC") && body.contains("Windows 11"));
    assert!(body.contains("Who can reach this device"));
    assert!(body.contains("Set on the computer itself") || body.contains("Not managed by the console"));
    assert!(body.contains("Recent connections") && body.contains("2m 5s"));
    // the note
    let r = h.post_form("/devices/1/do", &cookie, &[tok(), ("do", "note"), ("note", "  hello  ")]).await;
    assert_eq!(r.status, 302, "{}", r.body);
    assert_eq!(h.text("select note from devices where id = 1"), "hello");
    // the address book
    h.sql("insert into address_books (id, guid, name, is_personal, owner_user_id, created_at, updated_at) values (1, 'g1', 'Shared', 0, 1, '2025-01-01 00:00:00', '2025-01-01 00:00:00')");
    h.post_form("/devices/1/do", &cookie, &[tok(), ("do", "add-book"), ("book_id", "1")]).await;
    assert_eq!(h.count("address_book_entries where address_book_id = 1 and rustdesk_id = '1001'"), 1);
    h.post_form("/devices/1/do", &cookie, &[tok(), ("do", "remove-book"), ("book_id", "1")]).await;
    assert_eq!(h.count("address_book_entries"), 0);
    // the password: not enabled, so there is nothing to change; an administrator's request is accepted anyway
    let r = h.post_form("/devices/1/do", &cookie, &[tok(), ("do", "rotate-password")]).await;
    assert_eq!(r.status, 302);
    assert_eq!(h.count("hte_device_passwords where rustdesk_id = '1001'"), 1);
    // Release ID: refused with nothing listening, audited either way; the button is on the page
    std::env::set_var("HTE_CONSOLE_HBBS_ADMIN", "127.0.0.1:1");
    assert!(squash(&h.get("/devices/1", &cookie).await.body).contains("Release ID"));
    let r = h.post_form("/devices/1/do", &cookie, &[tok(), ("do", "release-id")]).await;
    assert_eq!(r.status, 302, "{}", r.body);
    assert_eq!(h.count("console_audits where action = 'hte.release_id' and summary = 'Release ID 1001: refused'"), 1);
    // a person who may not write cannot
    let erin = h.login(&sid("deverin"), 3, json!({}));
    assert_eq!(h.get("/devices", &erin).await.status, 302);
}

#[tokio::test]
async fn the_users_pages() {
    let h = harness().await;
    let cookie = h.login(&sid("users1"), 1, json!({}));
    let r = h.get("/users", &cookie).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let body = squash(&r.body);
    assert!(body.contains("dana") && body.contains("Showing 1–4 of 4"), "{body}");
    let r = h.get("/users?search=gone&status=disabled", &cookie).await;
    assert!(squash(&r.body).contains("Showing 1–1 of 1"));
    // the editor opens, validates (422), then saves
    let r = h.get("/users?create=1", &cookie).await;
    assert!(squash(&r.body).contains("Add User"));
    let r = h.post_form("/users/save", &cookie, &[tok(), ("id", "0"), ("return", "/users"), ("username", "dana"), ("password", "short")]).await;
    assert_eq!(r.status, 422, "{}", r.body);
    assert!(r.body.contains("The username has already been taken.") && r.body.contains("The password field must be at least 8 characters."), "{}", r.body);
    let r = h.post_form("/users/save", &cookie, &[tok(), ("id", "0"), ("return", "/users"), ("username", "newbie"), ("name", "New B"), ("email", "n@example.test"), ("password", "longenough1"), ("is_active", "1"), ("user_group_ids[]", "1"), ("device_group_ids[]", "2")]).await;
    assert_eq!(r.status, 302, "{}", r.body);
    assert_eq!(h.count("users where username = 'newbie' and is_active = 1 and is_admin = 0"), 1);
    assert_eq!(h.count("user_group_user where user_id = 5"), 1);
    assert_eq!(h.count("device_group_user where user_id = 5 and device_group_id = 2"), 1);
    assert_eq!(h.count("console_audits where action = 'user.create'"), 1);
    // edit: role, blank password keeps the hash
    let before = h.text("select password from users where id = 5");
    h.post_form("/users/save", &cookie, &[tok(), ("id", "5"), ("return", "/users"), ("username", "newbie"), ("name", "New C"), ("password", ""), ("role_id", "1"), ("is_active", "1")]).await;
    assert_eq!(h.text("select password from users where id = 5"), before);
    assert_eq!(h.text("select cast(role_id as text) from users where id = 5"), "1");
    assert_eq!(h.count("device_group_user where user_id = 5"), 0);
    // actions
    h.post_form("/users/act", &cookie, &[tok(), ("id", "2"), ("do", "toggle"), ("back", "")]).await;
    assert_eq!(h.text("select cast(is_active as text) from users where id = 2"), "0");
    h.post_form("/users/act", &cookie, &[tok(), ("id", "1"), ("do", "toggle"), ("back", "")]).await;
    assert_eq!(h.text("select cast(is_active as text) from users where id = 1"), "1");
    h.sql("update users set totp_enabled = 1, totp_secret = 'x' where id = 4; insert into two_factor_recovery_codes (user_id, code_hash, created_at) values (4, 'c', '2025-01-01 00:00:00')");
    h.post_form("/users/act", &cookie, &[tok(), ("id", "4"), ("do", "reset2fa"), ("back", "")]).await;
    assert_eq!(h.count("users where id = 4 and totp_enabled = 0 and totp_secret is null"), 1);
    assert_eq!(h.count("two_factor_recovery_codes"), 0);
    // assign devices
    let r = h.get("/users?assign=2", &cookie).await;
    assert!(squash(&r.body).contains("Assign Devices"));
    h.post_form("/users/assign", &cookie, &[tok(), ("id", "2"), ("ids[]", "2"), ("back", "")]).await;
    assert_eq!(h.text("select cast(user_id as text) from devices where id = 2"), "2");
    assert_eq!(h.count("devices where id = 1 and user_id is null"), 1);
    // the person page
    let r = h.get("/users/2", &cookie).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(squash(&r.body).contains("Recent sign-ins") && squash(&r.body).contains("BACK-PC"));
    assert_eq!(h.get("/users/99", &cookie).await.status, 404);
    // delete
    h.post_form("/users/act", &cookie, &[tok(), ("id", "5"), ("do", "delete"), ("back", "")]).await;
    assert_eq!(h.count("users where id = 5"), 0);
    // the self guard and a person without the role
    h.post_form("/users/act", &cookie, &[tok(), ("id", "1"), ("do", "delete"), ("back", "")]).await;
    assert_eq!(h.count("users where id = 1"), 1);
    let erin = h.login(&sid("userserin"), 3, json!({}));
    assert_eq!(h.get("/users", &erin).await.status, 302);
}

#[tokio::test]
async fn the_groups_page() {
    let h = harness().await;
    let cookie = h.login(&sid("groups1"), 1, json!({}));
    let r = h.get("/groups", &cookie).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(squash(&r.body).contains("Front desk") && squash(&r.body).contains("Back office"));
    assert!(squash(&h.get("/groups?tab=users", &cookie).await.body).contains("Techs"));
    assert!(squash(&h.get("/groups?tab=users&create=1", &cookie).await.body).contains("Add User Group"));
    assert!(squash(&h.get("/groups?edit=1", &cookie).await.body).contains("Edit Device Group"));
    let r = h.post_form("/groups/save", &cookie, &[tok(), ("type", "users"), ("id", "0"), ("name", "")]).await;
    assert_eq!(r.status, 422, "{}", r.body);
    assert!(r.body.contains("The name field is required."));
    let r = h.post_form("/groups/save", &cookie, &[tok(), ("type", "users"), ("id", "0"), ("name", "Ops"), ("note", "n"), ("device_group_ids[]", "1"), ("device_group_ids[]", "2"), ("accessor_group_ids[]", "1")]).await;
    assert_eq!(r.status, 302, "{}", r.body);
    assert_eq!(h.count("device_group_user_group where user_group_id = 2"), 2);
    assert_eq!(h.count("group_accesses where target_type = 'user_group' and target_id = 2 and accessor_id = 1"), 1);
    assert_eq!(h.count("console_audits where action = 'group.create'"), 1);
    h.post_form("/groups/save", &cookie, &[tok(), ("type", "devices"), ("id", "1"), ("name", "Front"), ("accessor_group_ids[]", "2")]).await;
    assert_eq!(h.text("select name from device_groups where id = 1"), "Front");
    assert_eq!(h.count("group_accesses where target_type = 'device_group' and target_id = 1 and accessor_id = 2"), 1);
    h.post_form("/groups/act", &cookie, &[tok(), ("type", "devices"), ("id", "1"), ("do", "delete")]).await;
    assert_eq!(h.count("device_groups"), 1);
    assert_eq!(h.count("devices where device_group_id = 1"), 0);
    assert_eq!(h.count("group_accesses where target_type = 'device_group'"), 0);
    h.post_form("/groups/act", &cookie, &[tok(), ("type", "users"), ("id", "2"), ("do", "delete")]).await;
    assert_eq!(h.count("user_groups"), 1);
    assert_eq!(h.count("group_accesses"), 0);
    assert_eq!(h.count("device_group_user_group where user_group_id = 2"), 0);
    let erin = h.login(&sid("groupserin"), 3, json!({}));
    assert_eq!(h.get("/groups", &erin).await.status, 302);
}

#[tokio::test]
async fn the_address_book_page() {
    let h = harness().await;
    let cookie = h.login(&sid("ab1"), 1, json!({}));
    // opening the page makes the person's own book
    let r = h.get("/address-books", &cookie).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(h.count("address_books where owner_user_id = 1 and is_personal = 1"), 1);
    assert!(squash(&r.body).contains("No shared address books yet") || squash(&r.body).contains("Select an address book") || squash(&r.body).contains("My address book"));
    // a shared book
    assert!(squash(&h.get("/address-books?modal=newBook", &cookie).await.body).contains("New shared address book"));
    let r = h.post_form("/address-books/act", &cookie, &[tok(), ("do", "create-book"), ("back", ""), ("book_name", "")]).await;
    assert_eq!(r.status, 422, "{}", r.body);
    assert!(r.body.contains("The name field is required."));
    let r = h.post_form("/address-books/act", &cookie, &[tok(), ("do", "create-book"), ("back", ""), ("book_name", "  Clinic  "), ("book_note", "n")]).await;
    assert_eq!(r.status, 302, "{}", r.body);
    assert_eq!(h.count("address_books where name = 'Clinic' and is_personal = 0"), 1);
    let id = h.text("select cast(id as text) from address_books where name = 'Clinic'");
    let back = format!("tab=shared&selectedBookId={id}");
    assert!(r.location().ends_with(&format!("/address-books?selectedBookId={id}&tab=shared")));
    // tags
    let r = h.post_form("/address-books/act", &cookie, &[tok(), ("do", "add-tag"), ("back", &back), ("tag_name", "Red"), ("tag_color", "bad")]).await;
    assert_eq!(r.status, 422);
    assert!(r.body.contains("The color field format is invalid."));
    h.post_form("/address-books/act", &cookie, &[tok(), ("do", "add-tag"), ("back", &back), ("tag_name", "Red"), ("tag_color", "#FF0000")]).await;
    assert_eq!(h.text("select cast(color as text) from tags where name = 'Red'"), "4294901760");
    let r = h.post_form("/address-books/act", &cookie, &[tok(), ("do", "add-tag"), ("back", &back), ("tag_name", "Red"), ("tag_color", "#FF0000")]).await;
    assert!(r.body.contains("The tag name has already been taken."));
    let tag = h.text("select cast(id as text) from tags where name = 'Red'");
    // entries
    let r = h.post_form("/address-books/act", &cookie, &[tok(), ("do", "save-entry"), ("back", &back), ("entry_id", "0"), ("rustdesk_id", "555"), ("alias", "Desk"), ("tag_ids[]", &tag), ("tag_ids[]", "999")]).await;
    assert_eq!(r.status, 302, "{}", r.body);
    assert_eq!(h.text("select tag_ids from address_book_entries where rustdesk_id = '555'"), format!("[{tag}]"));
    let r = h.post_form("/address-books/act", &cookie, &[tok(), ("do", "save-entry"), ("back", &back), ("entry_id", "0"), ("rustdesk_id", "555")]).await;
    assert_eq!(r.status, 422);
    assert!(r.body.contains("The RustDesk ID has already been taken."));
    let page = squash(&h.get(&format!("/address-books?{back}"), &cookie).await.body);
    assert!(page.contains("Desk") && page.contains("Red") && page.contains("Sharing rules"), "{page}");
    let eid = h.text("select cast(id as text) from address_book_entries where rustdesk_id = '555'");
    h.post_form("/address-books/act", &cookie, &[tok(), ("do", "save-entry"), ("back", &back), ("entry_id", &eid), ("alias", "Desk 2")]).await;
    assert_eq!(h.text("select alias from address_book_entries where rustdesk_id = '555'"), "Desk 2");
    assert_eq!(h.text("select tag_ids from address_book_entries where rustdesk_id = '555'"), "[]");
    // rules
    let r = h.post_form("/address-books/act", &cookie, &[tok(), ("do", "add-rule"), ("back", &back), ("rule_type", "user"), ("rule_subject", ""), ("rule_permission", "1")]).await;
    assert_eq!(r.status, 422);
    assert!(r.body.contains("The subject field is required."));
    h.post_form("/address-books/act", &cookie, &[tok(), ("do", "add-rule"), ("back", &back), ("rule_type", "everyone"), ("rule_permission", "1")]).await;
    assert_eq!(h.count("address_book_rules where subject_type = 'everyone' and subject_id is null and permission = 1"), 1);
    let rid = h.text("select cast(id as text) from address_book_rules");
    h.post_form("/address-books/act", &cookie, &[tok(), ("do", "rule-perm"), ("back", &back), ("id", &rid), ("permission", "2")]).await;
    assert_eq!(h.text("select cast(permission as text) from address_book_rules"), "2");
    // a plain user now sees the book, with read/write, and cannot manage it
    let dana = h.login(&sid("abdana"), 2, json!({}));
    let page = squash(&h.get(&format!("/address-books?{back}"), &dana).await.body);
    assert!(page.contains("Clinic") && page.contains("Read/Write") && !page.contains("Sharing rules"), "{page}");
    let r = h.post_form("/address-books/act", &dana, &[tok(), ("do", "delete-book"), ("back", &back)]).await;
    assert_eq!(r.status, 302);
    assert_eq!(h.count("address_books where name = 'Clinic'"), 1);
    h.post_form("/address-books/act", &dana, &[tok(), ("do", "delete-entry"), ("back", &back), ("id", &eid)]).await;
    assert_eq!(h.count("address_book_entries"), 0);
    // deleting a tag strips it from entries; deleting the book takes the rest
    h.post_form("/address-books/act", &cookie, &[tok(), ("do", "delete-tag"), ("back", &back), ("id", &tag)]).await;
    assert_eq!(h.count("tags"), 0);
    h.post_form("/address-books/act", &cookie, &[tok(), ("do", "delete-rule"), ("back", &back), ("id", &rid)]).await;
    assert_eq!(h.count("address_book_rules"), 0);
    h.post_form("/address-books/act", &cookie, &[tok(), ("do", "delete-book"), ("back", &back)]).await;
    assert_eq!(h.count("address_books where name = 'Clinic'"), 0);
    assert!(h.count("console_audits where action like 'address-book.%'") >= 8);
    // a personal book is not removable while its owner lives
    let pb = h.text("select cast(id as text) from address_books where is_personal = 1 and owner_user_id = 1");
    h.post_form("/address-books/act", &cookie, &[tok(), ("do", "delete-book"), ("back", &format!("tab=personal&selectedBookId={pb}"))]).await;
    assert_eq!(h.count(&format!("address_books where id = {pb}")), 1);
}

#[tokio::test]
async fn the_strategies_page() {
    let h = harness().await;
    let cookie = h.login(&sid("st1"), 1, json!({}));
    let r = h.get("/strategies", &cookie).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(squash(&r.body).contains("No strategies yet"));
    let r = h.get("/strategies?create=1", &cookie).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(squash(&r.body).contains("Add Strategy") && r.body.contains("opt_access-mode"));
    // validation
    let r = h.post_form("/strategies/preview", &cookie, &[tok(), ("id", "0"), ("name", ""), ("timeout", "15"), ("opt_auto-disconnect-timeout", "")]).await;
    assert_eq!(r.status, 422, "{}", r.body);
    assert!(r.body.contains("The name field is required."));
    // the Network group and its ice-servers option: a list the client would skip is refused, a good one is kept canonical
    let r = h.get("/strategies?create=1", &cookie).await;
    assert!(squash(&r.body).contains("Network") && r.body.contains("opt_ice-servers"));
    let r = h.post_form("/strategies/preview", &cookie, &[tok(), ("id", "0"), ("name", "Net"), ("timeout", "15"), ("opt_ice-servers", "turn://turn.example.test:3478")]).await;
    assert_eq!(r.status, 422, "{}", r.body);
    assert!(squash(&r.body).contains("turn://turn.example.test:3478 is not a STUN or TURN server the client will use"));
    let r = h.post_form("/strategies/preview", &cookie, &[tok(), ("id", "0"), ("name", "Net"), ("timeout", "15"), ("opt_ice-servers", " STUN:stun.example.test ")]).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let r = h.post_form("/strategies/preview", &cookie, &[tok(), ("id", "0"), ("name", "Lock"), ("timeout", "15"), ("opt_auto-disconnect-timeout", "5000")]).await;
    assert_eq!(r.status, 422, "{}", r.body);
    assert!(r.body.contains("Enter a whole number between 1 and 1440."));
    // review, then apply
    let fields = [tok(), ("id", "0"), ("name", "Lock"), ("enabled", "1"), ("is_default", "1"), ("timeout", "15"), ("opt_access-mode", "view"), ("opt_enable-keyboard", "N")];
    let r = h.post_form("/strategies/preview", &cookie, &fields).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(squash(&r.body).contains("Review strategy impact") && squash(&r.body).contains("High-impact controls"));
    let fp = r.body.split("name=\"fingerprint\" value=\"").nth(1).unwrap().split('"').next().unwrap().to_string();
    let mut bad = fields.to_vec();
    bad.push(("fingerprint", "deadbeef"));
    let r = h.post_form("/strategies/confirm", &cookie, &bad).await;
    assert_eq!(r.status, 422);
    assert!(r.body.contains("changed after the preview"));
    assert_eq!(h.count("strategies"), 0);
    let mut good = fields.to_vec();
    good.push(("fingerprint", &fp));
    let r = h.post_form("/strategies/confirm", &cookie, &good).await;
    assert_eq!(r.status, 302, "{}", r.body);
    assert_eq!(h.count("strategies where name = 'Lock' and is_default = 1 and enabled = 1"), 1);
    assert_eq!(h.count("strategy_revisions where change_note = 'Initial revision'"), 1);
    assert_eq!(h.count("console_audits where action = 'strategy.create'"), 1);
    assert_eq!(h.count("devices where strategy_id_resolved is not null and deleted_at is null and status = 'active'"), h.count("devices where deleted_at is null and status = 'active'"));
    let id = h.text("select cast(id as text) from strategies where name = 'Lock'");
    // toggle
    h.post_form("/strategies/toggle", &cookie, &[tok(), ("id", &id)]).await;
    assert_eq!(h.count("strategies where enabled = 0"), 1);
    assert_eq!(h.count("strategy_revisions where change_note = 'Toggled enabled state'"), 1);
    // assign
    let dev = h.text("select cast(id as text) from devices where rustdesk_id = '1001'");
    let r = h.post_form("/strategies/assign", &cookie, &[tok(), ("id", &id), ("device_ids[]", &dev), ("user_ids[]", "2")]).await;
    assert_eq!(r.status, 302, "{}", r.body);
    assert_eq!(h.count(&format!("device_strategy where strategy_id = {id}")), 1);
    assert_eq!(h.count(&format!("strategy_user where strategy_id = {id}")), 1);
    // pages
    for q in ["history", "assign", "compliance"] {
        let r = h.get(&format!("/strategies?{q}={id}"), &cookie).await;
        assert_eq!(r.status, 200, "{q}: {}", r.body);
    }
    // restore review, then delete
    let rev = h.text(&format!("select cast(id as text) from strategy_revisions where strategy_id = {id} order by revision limit 1"));
    let r = h.post_form("/strategies/restore", &cookie, &[tok(), ("id", &rev)]).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(squash(&r.body).contains("Review revision restore"));
    let r = h.get(&format!("/strategies?delete={id}"), &cookie).await;
    assert!(squash(&r.body).contains("Review strategy deletion"));
    let fp = r.body.split("name=\"fingerprint\" value=\"").nth(1).unwrap().split('"').next().unwrap().to_string();
    let r = h.post_form("/strategies/confirm", &cookie, &[tok(), ("id", &id), ("delete_id", &id), ("fingerprint", &fp)]).await;
    assert_eq!(r.status, 302, "{}", r.body);
    assert_eq!(h.count("strategies where deleted_at is not null and name like 'Lock (deleted %'"), 1);
    assert_eq!(h.count("device_strategy"), 0);
    // a person without the strategy permission is turned away
    let viewer = h.login(&sid("st2"), 3, json!({}));
    assert_ne!(h.get("/strategies?create=1", &viewer).await.status, 200);
}

#[tokio::test]
async fn the_settings_page() {
    let h = harness().await;
    let cookie = h.login(&sid("se1"), 1, json!({}));
    let r = h.get("/settings", &cookie).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let page = squash(&r.body);
    assert!(page.contains("RustDesk Server") && page.contains("Per-person reach: Off"));
    for tab in ["Client Setup", "Security", "SSO", "Email", "Notifications", "Maintenance", "Backups"] {
        assert!(page.contains(tab), "{tab}");
    }
    // validation: nothing is written, the failing tab opens, no secret comes back
    let base = |extra: &[(&'static str, &'static str)]| {
        let mut f = vec![tok(), ("tab", "server"), ("online_window", "60"), ("log_retention_days", "365"), ("default_device_group_id", "0"), ("server_access_mode", "open"), ("oidc_new_user_policy", "deny"),
            ("oidc_default_group_id", "0"), ("smtp_port", "587"), ("smtp_encryption", "starttls"), ("apprise_mode", "config"), ("apprise_cooldown_minutes", "15"), ("apprise_offline_grace_minutes", "0"),
            ("email_trusted_device_days", "30"), ("hte_password_days", "30")];
        f.extend_from_slice(extra);
        f
    };
    let r = h.post_form("/settings/save", &cookie, &base(&[("online_window", "5"), ("oidc_client_secret", "topsecret-value")])).await;
    assert_eq!(r.status, 422, "{}", r.body);
    assert!(r.body.contains("The online window field must be at least 20."));
    assert!(!r.body.contains("topsecret-value"));
    assert_eq!(h.count("settings"), 0);
    let r = h.post_form("/settings/save", &cookie, &base(&[("smtp_from_address", "nope"), ("smtp_host", "")])).await;
    assert_eq!(r.status, 422);
    assert!(r.body.contains("The smtp from address field must be a valid email address."));
    assert!(r.body.contains(r#"data-rd-pane="email""#) && squash(&r.body).contains("nav-link active"));
    // the web client's WebRTC rows: off until turned on; a list the client would skip is refused and opens the Server tab
    assert!(page.contains("Web client uses WebRTC") && page.contains("Web client ICE servers"));
    assert!(!page.contains(r#"name="web_client_webrtc" value="1" checked"#), "WebRTC is off until someone turns it on");
    let r = h.post_form("/settings/save", &cookie, &base(&[("web_client_webrtc", "1"), ("web_client_ice_servers", "stun:ok.example.test, turn://no-credentials.example.test")])).await;
    assert_eq!(r.status, 422, "{}", r.body);
    assert!(squash(&r.body).contains("turn://no-credentials.example.test is not a STUN or TURN server the client will use"));
    assert!(r.body.contains(r#"data-rd-pane="server""#));
    assert_eq!(h.count("settings"), 0);
    let r = h.post_form("/settings/save", &cookie, &base(&[("rdgen_url", "not a url")])).await;
    assert!(r.body.contains("The rdgen url field must be a valid URL."));
    let r = h.post_form("/settings/save", &cookie, &base(&[("oidc_enabled", "1"), ("oidc_discovery_url", "https://idp.example.test"), ("oidc_client_id", "cid")])).await;
    assert!(r.body.contains("Provider URL, client ID and client secret are all required to enable SSO."));
    // a save, with the secrets
    let fields = base(&[
        ("id_server", " hbbs.example.test:21116 "), ("rdgen_url", "https://rdgen.example.test/"), ("client_url_scheme", "Level1:"), ("downloads_on_login", "1"), ("server_ip_match", "1"), ("hte_scope_enforce", "1"), ("web_client_webrtc", "1"), ("web_client_ice_servers", " STUN:stun.example.test:3478 , turn://u:p@turn.example.test "),
        ("relay_address[]", "r1.example.test:21117"), ("relay_geo[]", "eu"), ("relay_address[]", ""), ("relay_geo[]", ""),
        ("oidc_enabled", "1"), ("oidc_discovery_url", "https://idp.example.test/"), ("oidc_client_id", "cid"), ("oidc_client_secret", "topsecret-value"),
        ("smtp_host", "smtp.example.test"), ("smtp_from_address", "c@example.test"), ("smtp_enabled", "1"), ("smtp_password", "smtp-pass-123"), ("email_login_verification", "1"),
        ("apprise_enabled", "1"), ("apprise_endpoint", "https://apprise.example.test"), ("apprise_mode", "urls"), ("apprise_urls", "slack://a/b\r\n\r\n0\r\ndiscord://c"),
        ("apprise_event_device_offline", "1"), ("apprise_scope_device_offline", "selected"), ("apprise_scope_groups_device_offline[]", "1"), ("apprise_scope_groups_device_offline[]", "1"), ("apprise_scope_devices_device_offline[]", "2"),
    ]);
    let r = h.post_form("/settings/save", &cookie, &fields).await;
    assert_eq!(r.status, 302, "{}", r.body);
    assert!(r.location().ends_with("/settings?tab=server"));
    assert_eq!(h.text("select value from settings where key = 'id_server'"), "hbbs.example.test:21116");
    assert_eq!(h.text("select value from settings where key = 'rdgen_url'"), "https://rdgen.example.test");
    assert_eq!(h.text("select value from settings where key = 'client_url_scheme'"), "level1");
    assert_eq!(h.text("select value from settings where key = 'relay_servers'"), r#"[{"address":"r1.example.test:21117","geo":"eu"}]"#);
    assert_eq!(h.text("select value from settings where key = 'oidc_discovery_url'"), "https://idp.example.test");
    assert_eq!(h.text("select value from settings where key = 'server_ip_match'"), "1");
    assert_eq!(h.text("select value from settings where key = 'hte_scope_enforce'"), "1");
    assert_eq!(h.text("select value from settings where key = 'email_login_verification'"), "1");
    assert_eq!(h.text("select value from settings where key = 'webclient_webrtc'"), "1");
    assert_eq!(h.text("select value from settings where key = 'webclient_ice_servers'"), "stun:stun.example.test:3478,turn://u:p@turn.example.test");
    assert_eq!(h.count("console_audits where action = 'settings.webclient-webrtc'"), 1);
    assert_eq!(h.count("console_audits where action = 'settings.webclient-ice'"), 1);
    assert_eq!(h.count("console_audits where summary like '%u:p%'"), 0, "the TURN password is never written to the log");
    assert_eq!(h.text("select value from settings where key = 'apprise_scope_groups_device_offline'"), "[1]");
    assert_eq!(h.text("select value from settings where key = 'apprise_scope_devices_device_offline'"), "[2]");
    let plain = |key: &str| -> String {
        let enc = h.text(&format!("select value from settings where key = '{key}'"));
        assert!(!enc.contains("topsecret") && !enc.contains("smtp-pass") && !enc.contains("apprise.example"), "{key} is stored in the clear");
        String::from_utf8(h.crypt.decrypt_string(enc.as_bytes()).unwrap()).unwrap()
    };
    assert_eq!(plain("oidc_client_secret"), "topsecret-value");
    assert_eq!(plain("smtp_password"), "smtp-pass-123");
    assert_eq!(plain("apprise_endpoint"), "https://apprise.example.test");
    assert_eq!(plain("apprise_urls"), r#"["slack:\/\/a\/b","discord:\/\/c"]"#);
    assert_eq!(h.count("console_audits where action = 'settings.update'"), 1);
    assert_eq!(h.count("console_audits where action = 'settings.hte-scope'"), 1);
    assert_eq!(h.count("console_audits where action = 'settings.server-ip-match'"), 1);
    // the page now says a secret is stored, and never says which
    let r = h.get("/settings?tab=sso", &cookie).await;
    let body = &r.body;
    assert!(body.contains("Stored — leave blank to keep") && !body.contains("topsecret") && !body.contains("smtp-pass"));
    assert!(body.contains(r#"value="cid""#));
    let before = h.text("select value from settings where key = 'oidc_client_secret'");
    // a blank secret keeps the stored one
    let r = h.post_form("/settings/save", &cookie, &[&fields[..], &[("oidc_client_secret", "")]].concat().iter().filter(|(k, v)| !(*k == "oidc_client_secret" && *v == "topsecret-value")).cloned().collect::<Vec<_>>()).await;
    assert_eq!(r.status, 302, "{}", r.body);
    assert_eq!(h.text("select value from settings where key = 'oidc_client_secret'"), before);
    // relay rows: add, remove
    let r = h.post_form("/settings/relay", &cookie, &[tok(), ("do", "add"), ("relay_address[]", "x:1"), ("relay_geo[]", "g")]).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body.matches(r#"name="relay_address[]""#).count(), 2);
    let r = h.post_form("/settings/relay", &cookie, &[tok(), ("do", "remove:0"), ("relay_address[]", "x:1"), ("relay_geo[]", "g")]).await;
    assert_eq!(r.body.matches(r#"name="relay_address[]""#).count(), 0);
    // presence snoozes
    let r = h.post_form("/settings/snooze", &cookie, &[tok(), ("do", "create"), ("snooze_type", "group"), ("snooze_target", "1"), ("snooze_minutes", "5")]).await;
    assert_eq!(r.status, 422);
    assert!(r.body.contains("The presence snooze minutes field must be at least 15."));
    let r = h.post_form("/settings/snooze", &cookie, &[tok(), ("do", "create"), ("snooze_type", "group"), ("snooze_target", "1"), ("snooze_minutes", "60")]).await;
    assert_eq!(r.status, 302, "{}", r.body);
    assert_eq!(h.count("device_presence_snoozes where target_type = 'group' and target_id = 1"), 1);
    assert!(squash(&h.get("/settings?tab=notifications", &cookie).await.body).contains("Group: Front desk"));
    let sid_ = h.text("select cast(id as text) from device_presence_snoozes");
    h.post_form("/settings/snooze", &cookie, &[tok(), ("do", &format!("clear:{sid_}"))]).await;
    assert_eq!(h.count("device_presence_snoozes"), 0);
    // a person without the setting permission is turned away
    let viewer = h.login(&sid("se2"), 3, json!({}));
    assert_ne!(h.get("/settings", &viewer).await.status, 200);
    let before = h.count("console_audits where action = 'settings.update'");
    let r = h.post_form("/settings/save", &viewer, &[tok()]).await;
    assert!(!r.location().contains("/settings"), "{}", r.location());
    assert_eq!(h.count("console_audits where action = 'settings.update'"), before);
}

#[tokio::test]
async fn the_overview_page() {
    let h = harness().await;
    h.sql("insert into audit_connections (rustdesk_id, from_peer, from_name, ip, conn_type, created_at) values ('1001', '555', 'Front PC', '10.1.1.1', 0, datetime('now'))");
    let cookie = h.login(&sid("ov1"), 1, json!({}));
    let r = h.get("/", &cookie).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let page = squash(&r.body);
    assert!(page.contains("Online now") && page.contains("Active Sessions") && page.contains("Client Versions"), "{page}");
    assert!(page.contains(r#"id="chart-connections""#) && page.contains("chart-platforms"));
    let r = h.get("/dashboard/stats", &cookie).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.body.contains("rd-stat-grid") && !r.body.contains("<html"));
    let r = h.get("/dashboard/sessions", &cookie).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.body.contains("Active Sessions") && !r.body.contains("<html"));
    assert!(r.body.contains("Disconnect"));
    let r = h.post_form("/dashboard/disconnect", &cookie, &[tok(), ("id", "1")]).await;
    assert_eq!(r.status, 302, "{}", r.body);
    assert_eq!(h.count("audit_connections where disconnect_requested_at is not null and disconnect_requested_by = 1"), 1);
    assert_eq!(h.count("console_audits where action = 'session.disconnect'"), 1);
    // a view-only person (no audit area) gets the device cards but no session panel
    let cookie = h.login(&sid("ov2"), 3, json!({}));
    let r = h.get("/", &cookie).await;
    assert_eq!(r.status, 200, "{}", r.body);
}

#[tokio::test]
async fn the_web_client() {
    let h = harness().await;
    std::env::set_var("APP_URL", "https://remote.example.test");
    // computers' confirmed passwords: 1001 (dana's), 1002 (not hers), 1004 (pending), 1005 (hers, no confirmed password yet)
    let pw = h.crypt.encrypt_string(b"Zq7-managed-PASSWORD");
    h.sql("insert into devices (id, rustdesk_id, uuid, hostname, user_id, status, created_at, updated_at) values (5, '1005', 'u5', 'SPARE-PC', 2, 'active', '2025-09-05 10:00:00', '2025-09-05 10:00:00')");
    h.sql(&format!("insert into hte_device_passwords (rustdesk_id, capable_at, current_version, confirmed_version, confirmed_enc, created_at, updated_at) values ('1001', '2025-01-01 00:00:00', 1, 1, '{pw}', '2025-01-01 00:00:00', '2025-01-01 00:00:00'), ('1002', '2025-01-01 00:00:00', 1, 1, '{pw}', '2025-01-01 00:00:00', '2025-01-01 00:00:00'), ('1004', '2025-01-01 00:00:00', 1, 1, '{pw}', '2025-01-01 00:00:00', '2025-01-01 00:00:00'), ('1005', '2025-01-01 00:00:00', 0, 0, null, '2025-01-01 00:00:00', '2025-01-01 00:00:00')"));
    h.sql("insert into settings (key, value, created_at, updated_at) values ('hte_scope_enforce', '1', '2025-01-01 00:00:00', '2025-01-01 00:00:00'), ('public_key', 'SERVERKEYb64=', '2025-01-01 00:00:00', '2025-01-01 00:00:00')");
    let dana = h.login(&sid("wc2"), 2, json!({}));
    let erin = h.login(&sid("wc3"), 3, json!({}));

    // the page: HTE Remote's title and icon, the bundle's configuration in a data attribute, never a password
    let r = h.get("/webclient?id=1001", &dana).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.body.contains("<title>1001 — HTE Remote Web Client</title>") && r.body.contains("hte-remote.png"), "{}", r.body);
    assert!(!r.body.contains("CortenDesk") && !r.body.contains("cortendesk-sm"));
    assert!(r.body.contains("/rdclient/app.js?v=") && r.body.contains("hte-brand.css") && r.body.contains("hte-webclient.js"));
    assert!(!r.body.contains("Zq7-managed-PASSWORD"));
    let cfg = r.body.split("data-config=\"").nth(1).unwrap().split('"').next().unwrap().replace("&quot;", "\"").replace("&#039;", "'").replace("&amp;", "&");
    let cfg: serde_json::Value = serde_json::from_str(&cfg).unwrap();
    assert_eq!(cfg["peerId"], "1001");
    assert_eq!(cfg["myId"], "web-2");
    assert_eq!(cfg["myName"], "dana");
    assert_eq!(cfg["serverKeyB64"], "SERVERKEYb64=");
    assert_eq!(cfg["wsIdUrl"], "wss://remote.example.test/ws/id");
    assert_eq!(cfg["wsRelayUrl"], "wss://remote.example.test/ws/relay");
    assert_eq!(cfg["version"], "1.15.0-hte.1");
    assert!(cfg["workerUrl"].as_str().unwrap().starts_with("/rdclient/session.worker.js?v="));
    let r = h.get("/webclient", &dana).await;
    assert!(r.body.contains("<title>HTE Remote Web Client</title>"));
    // WebRTC is off until someone turns it on: the page carries null, so the bundle never offers it
    assert!(cfg["webrtc"].is_null(), "{cfg}");
    let config_of = |body: &str| -> serde_json::Value {
        let c = body.split("data-config=\"").nth(1).unwrap().split('"').next().unwrap().replace("&quot;", "\"").replace("&#039;", "'").replace("&amp;", "&");
        serde_json::from_str(&c).unwrap()
    };
    h.sql("insert into settings (key, value, created_at, updated_at) values ('webclient_webrtc', '1', '2025-01-01 00:00:00', '2025-01-01 00:00:00')");
    assert_eq!(config_of(&h.get("/webclient?id=1001", &dana).await.body)["webrtc"], json!({"iceServers": ""}));
    h.sql("insert into settings (key, value, created_at, updated_at) values ('webclient_ice_servers', 'stun:stun.example.test:3478,turn://u:p@turn.example.test', '2025-01-01 00:00:00', '2025-01-01 00:00:00')");
    assert_eq!(config_of(&h.get("/webclient?id=1001", &dana).await.body)["webrtc"], json!({"iceServers": "stun:stun.example.test:3478,turn://u:p@turn.example.test"}));
    // a list that no longer parses (edited in the database) is not handed on half-trusted
    h.sql("update settings set value = 'turn://no-credentials' where key = 'webclient_ice_servers'");
    assert_eq!(config_of(&h.get("/webclient?id=1001", &dana).await.body)["webrtc"], json!({"iceServers": ""}));
    h.sql("delete from settings where key in ('webclient_webrtc', 'webclient_ice_servers')");
    // the terminal page is the same page: same sign-in, same title scheme, and no person without a session gets it
    let r = h.get("/webclient?id=1001&mode=terminal", &dana).await;
    assert!(r.body.contains("<title>1001 — HTE Remote Terminal</title>"), "{}", r.body);
    assert!(h.client.get(format!("{}/webclient?id=1001&mode=terminal", h.url)).send().await.unwrap().status().is_redirection());

    // the list: exactly the computers the person may reach now, in /api/peers' order; never another person's
    let ids = |body: &str| -> Vec<String> { serde_json::from_str::<serde_json::Value>(body).unwrap()["devices"].as_array().unwrap().iter().map(|d| d["id"].as_str().unwrap().to_string()).collect() };
    let r = h.get("/webclient/devices", &dana).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.headers.get("cache-control").unwrap().to_str().unwrap().contains("no-store"));
    assert_eq!(ids(&r.body), vec!["1001", "1005"]);
    assert!(!r.body.contains("Zq7-managed-PASSWORD"));
    assert!(ids(&h.get("/webclient/devices", &erin).await.body).is_empty());
    assert!(h.client.get(format!("{}/webclient/devices", h.url)).send().await.unwrap().status().is_redirection());

    // the credential: any computer she may reach now with a confirmed password gives it (no address book needed); another
    // person's computer, a pending one, one in the recycle bin, one with no confirmed password, an unknown one give nothing
    let r = h.post_form("/webclient/credential", &dana, &[tok(), ("id", "1001")]).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(serde_json::from_str::<serde_json::Value>(&r.body).unwrap()["password"], "Zq7-managed-PASSWORD");
    assert!(r.headers.get("cache-control").unwrap().to_str().unwrap().contains("no-store"));
    for id in ["1002", "1004", "1003", "1005", "9999", ""] {
        let r = h.post_form("/webclient/credential", &dana, &[tok(), ("id", id)]).await;
        assert_eq!(r.status, 404, "{id}: {}", r.body);
        assert_eq!(r.body, "{}");
    }
    let r = h.post_form("/webclient/credential", &erin, &[tok(), ("id", "1001")]).await;
    assert_eq!(r.status, 404);
    // access revoked: the computer moves to someone else and is refused at once, and leaves her list
    h.sql("update devices set user_id = 3 where id = 1");
    assert_eq!(h.post_form("/webclient/credential", &dana, &[tok(), ("id", "1001")]).await.status, 404);
    assert_eq!(ids(&h.get("/webclient/devices", &dana).await.body), vec!["1005"]);
    assert_eq!(h.post_form("/webclient/credential", &erin, &[tok(), ("id", "1001")]).await.status, 200);
    // a form post without the token is refused before the handler
    let r = h.post_form("/webclient/credential", &dana, &[("id", "1001")]).await;
    assert_eq!(r.status, 419);

    // the static files: branded copies with types, ETag and cache rules; the maps are gone
    let c = reqwest::Client::new();
    let get = |p: &str| c.get(format!("{}{p}", h.url)).send();
    let js = get("/rdclient/app.js?v=x").await.unwrap();
    assert_eq!(js.status(), 200);
    assert_eq!(js.headers()["content-type"], "text/javascript; charset=utf-8");
    assert_eq!(js.headers()["cache-control"], "public, max-age=31536000, immutable");
    let etag = js.headers()["etag"].to_str().unwrap().to_string();
    let text = js.text().await.unwrap();
    assert!(text.contains("HTE <span>Remote</span>") && !text.contains("CortenDesk") && !text.contains("sourceMappingURL"));
    let r = c.get(format!("{}/rdclient/app.js", h.url)).header("if-none-match", &etag).send().await.unwrap();
    assert_eq!(r.status(), 304);
    assert_eq!(get("/rdclient/logo.png").await.unwrap().headers()["content-type"], "image/png");
    assert_eq!(get("/rdclient/app.css").await.unwrap().headers()["content-type"], "text/css; charset=utf-8");
    assert_eq!(get("/rdclient/session.worker.js").await.unwrap().status(), 200);
    assert_eq!(get("/rdclient/app.js.map").await.unwrap().status(), 404);
    // code that loads on demand (the terminal's xterm.js, the video muxer): the chunks the bundle names are served, cached for good, with
    // their licence notice beside them; the manifest carries the product's name; nothing else under chunks/ exists
    let chunks: Vec<&str> = text.match_indices("./chunks/").map(|(i, _)| &text[i + 2..i + text[i..].find('"').unwrap()]).collect();
    assert!(chunks.iter().any(|c| c.starts_with("chunks/xterm-")), "the terminal's xterm chunk is named by the bundle: {chunks:?}");
    for ch in &chunks {
        let r = get(&format!("/rdclient/{ch}")).await.unwrap();
        assert_eq!(r.status(), 200, "{ch}");
        assert_eq!(r.headers()["content-type"], "text/javascript; charset=utf-8");
        assert_eq!(r.headers()["cache-control"], "public, max-age=31536000, immutable");
        assert!(!r.text().await.unwrap().contains("sourceMappingURL"), "{ch}");
    }
    let xterm = chunks.iter().find(|c| c.starts_with("chunks/xterm-")).unwrap();
    let notice = get(&format!("/rdclient/{xterm}.LEGAL.txt")).await.unwrap();
    assert_eq!(notice.status(), 200);
    assert!(notice.text().await.unwrap().contains("xterm.js authors"));
    assert_eq!(get("/rdclient/chunks/not-there.js").await.unwrap().status(), 404);
    assert_eq!(get("/rdclient/chunks/xterm-AAAA.js.map").await.unwrap().status(), 404);
    let manifest = get("/rdclient/manifest.webmanifest").await.unwrap();
    assert_eq!(manifest.status(), 200);
    let manifest = manifest.text().await.unwrap();
    assert!(manifest.contains("HTE Remote Web Client") && !manifest.contains("CortenDesk"), "{manifest}");
    // without a session the page is not shown
    let r = h.client.get(format!("{}/webclient?id=1001", h.url)).send().await.unwrap();
    assert!(r.status().is_redirection(), "{}", r.status());
    std::env::remove_var("APP_URL");
}

/// The backup and prune code reads the environment as the CLI does: the tests that set it take turns.
static ENV: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Backups, Prune now and the API tokens page. The backup code reads the environment as the CLI does, so this one test
/// owns HTE_CONSOLE_DATABASE and friends for the whole process.
#[tokio::test]
async fn backups_prune_and_api_tokens() {
    let _env = ENV.lock().await;
    let h = harness().await;
    let keep = tempfile::tempdir().unwrap();
    let backups = keep.path().join("backups");
    std::env::set_var("HTE_CONSOLE_DATABASE", &h.db_path);
    std::env::set_var("APP_KEY", APP_KEY);
    std::env::set_var("HTE_CONSOLE_BACKUPS_DIR", &backups);
    std::env::set_var("HTE_CONSOLE_RUSTDESK_DIR", keep.path().join("rustdesk"));
    std::env::set_var("HTE_CONSOLE_SERVER_SECRET_FILE", keep.path().join("none"));
    let admin = h.login(&sid("bk1"), 1, json!({}));
    let erin = h.login(&sid("bk2"), 3, json!({}));

    let r = h.get("/settings?tab=backups", &admin).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.body.contains("No backups yet.") && r.body.contains("Back up now"));

    // a person without the setting area gets nothing, and nothing is written
    for p in ["/settings/backups/run", "/settings/prune", "/settings/backups/save"] {
        let r = h.post_form(p, &erin, &[tok()]).await;
        assert_eq!(r.status, 302, "{p}");
    }
    assert_eq!(h.count("console_audits"), 0);

    // Back up now: the archive, the "system" log line, the flash
    let r = h.post_form("/settings/backups/run", &admin, &[tok()]).await;
    assert_eq!(r.status, 302);
    assert_eq!(r.path(), "/settings?tab=backups");
    let names: Vec<String> = std::fs::read_dir(&backups).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| n.ends_with(".tar")).collect();
    assert_eq!(names.len(), 1, "{names:?}");
    let name = names[0].clone();
    assert_eq!(h.count("console_audits where action = 'backup.create' and username = 'system'"), 1);
    assert!(h.text("select value from settings where key = 'backup_last_result'").contains("Wrote hte-remote-backup-"));
    let r = h.get("/settings?tab=backups", &admin).await;
    assert!(r.body.contains(&name) && r.body.contains("Wrote hte-remote-backup-"));

    // schedule and retention
    let r = h.post_form("/settings/backups/save", &admin, &[tok(), ("keep_daily", "3"), ("keep_weekly", "2"), ("keep_monthly", "1")]).await;
    assert_eq!(r.status, 302);
    assert_eq!(h.text("select value from settings where key = 'backup_enabled'"), "0");
    assert_eq!(h.text("select value from settings where key = 'backup_keep_daily'"), "3");
    assert_eq!(h.text("select value from settings where key = 'backup_keep_monthly'"), "1");
    assert_eq!(h.text("select summary from console_audits where action = 'backup.settings'"), "Updated backup settings (off, keep 3/2/1, copy: none)");
    let before = h.count("settings");
    h.post_form("/settings/backups/save", &admin, &[tok(), ("enabled", "1"), ("keep_daily", "999"), ("keep_weekly", "2"), ("keep_monthly", "1")]).await;
    assert_eq!(h.count("settings"), before);
    assert_eq!(h.text("select value from settings where key = 'backup_enabled'"), "0");

    // download: the archive as stored, and only a real backup name
    let r = h.get(&format!("/settings/backups/download?name={name}"), &admin).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.headers.get("content-type").unwrap(), "application/x-tar");
    assert_eq!(r.headers.get("cache-control").unwrap(), "no-store, private");
    assert_eq!(h.get("/settings/backups/download?name=../../etc/passwd", &admin).await.status, 404);
    // 7c: the previous console's audit row for it, and the previous console's own URL for the same file
    assert_eq!(h.text("select summary from console_audits where action = 'backup.download' order by id desc limit 1"), format!("Downloaded backup {name}"));
    let r = h.get(&format!("/settings/backups/{name}"), &admin).await;
    assert_eq!((r.status, r.path()), (302, format!("/settings/backups/download?name={name}")));

    // restore: what changed since is undone, and the log says so
    h.sql("insert into settings (key, value) values ('marker', 'after the backup')");
    let r = h.post_form("/settings/backups/restore", &admin, &[tok(), ("name", &name)]).await;
    assert_eq!(r.status, 302);
    assert_eq!(h.count("settings where key = 'marker'"), 0);
    assert_eq!(h.count("console_audits where action = 'backup.restore' and summary = 'Restored backup ' || target_id"), 1);
    let r = h.post_form("/settings/backups/restore", &admin, &[tok(), ("name", "cortendesk-backup-20250101-000000.tar")]).await;
    assert_eq!(r.status, 302);

    // delete
    let r = h.post_form("/settings/backups/delete", &admin, &[tok(), ("name", &name)]).await;
    assert_eq!(r.status, 302);
    assert!(!backups.join(&name).exists());
    assert_eq!(h.count("console_audits where action = 'backup.delete'"), 1);
    h.post_form("/settings/backups/delete", &admin, &[tok(), ("name", "../x")]).await;
    assert_eq!(h.count("console_audits where action = 'backup.delete'"), 1);

    // Prune now: rows older than the saved window go, newer stay
    h.sql("insert into settings (key, value) values ('log_retention_days', '30')");
    h.sql(&format!("insert into login_logs (username, created_at) values ('old', '{}'), ('new', '{}')", ago(40 * 86_400), ago(86_400)));
    let r = h.post_form("/settings/prune", &admin, &[tok()]).await;
    assert_eq!(r.status, 302);
    assert_eq!(h.count("login_logs where username = 'old'"), 0);
    assert_eq!(h.count("login_logs where username = 'new'"), 1);
    assert_eq!(h.text("select summary from console_audits where action = 'logs.prune'"), "Pruned logs older than 30 days");

    // API tokens: shown once, stored as a hash, clamped to what the creator holds, revoked
    let r = h.get("/api-tokens", &admin).await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("No API tokens yet."));
    let r = h.post_form("/api-tokens", &admin, &[tok(), ("name", "ci"), ("expires_days", "30"), ("perm_device", "rw"), ("perm_audit", "r")]).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let plain = r.body.split("value=\"cdk_").nth(1).and_then(|t| t.split('"').next()).map(|t| format!("cdk_{t}")).expect("plaintext shown");
    assert_eq!(plain.len(), 44);
    use sha2::{Digest, Sha256};
    assert_eq!(h.text("select token_hash from api_tokens"), hex::encode(Sha256::digest(plain.as_bytes())));
    assert_eq!(h.text("select token_prefix from api_tokens"), &plain[..12]);
    assert_eq!(h.text("select permissions from api_tokens"), r#"{"device":"rw","user":"none","group":"none","strategy":"none","address_book":"none","audit":"r"}"#);
    assert_eq!(h.text("select expires_at from api_tokens"), laravel::ts(NOW + 30 * 86_400));
    assert_eq!(h.text("select summary from console_audits where action = 'api-token.create'"), "Created API token ci");
    let r = h.get("/api-tokens", &admin).await;
    assert!(!r.body.contains(&plain) && r.body.contains(&plain[..12]));
    let r = h.post_form("/api-tokens", &admin, &[tok(), ("name", "empty")]).await;
    assert_eq!(r.status, 422);
    assert!(r.body.contains("Grant at least one resource permission."));
    assert_eq!(h.count("api_tokens"), 1);
    let id = h.text("select cast(id as text) from api_tokens");
    let r = h.post_form("/api-tokens/revoke", &admin, &[tok(), ("id", &id)]).await;
    assert_eq!(r.status, 302);
    assert_eq!(h.count("api_tokens"), 0);
    assert_eq!(h.text("select summary from console_audits where action = 'api-token.revoke'"), "Revoked API token ci");
    assert_eq!(h.post_form("/api-tokens", &erin, &[tok(), ("name", "x"), ("perm_device", "rw")]).await.status, 302);
    assert_eq!(h.count("api_tokens"), 0);
}

/// The Rust half of the page replay's writes (the replay against the previous console paired each with the previous console's page components call and compares the
/// two databases): every form post must be taken, the reads equal themselves, and the writes must leave their rows.
#[tokio::test(flavor = "multi_thread")]
async fn the_replay_writes_run_on_hte_console() {
    let _env = ENV.lock().await;
    let h = harness().await;
    let keep = tempfile::tempdir().unwrap();
    std::env::set_var("HTE_CONSOLE_DATABASE", &h.db_path);
    std::env::set_var("APP_KEY", APP_KEY);
    std::env::set_var("HTE_CONSOLE_BACKUPS_DIR", keep.path().join("backups"));
    std::env::set_var("HTE_CONSOLE_RUSTDESK_DIR", keep.path().join("rustdesk"));
    h.sql(&hte_console::pagereplay::seed_sql(NOW).unwrap());
    let r = hte_console::pagereplay::run_with(&h.url, &h.url, APP_KEY, "hte-remote-session", NOW, true).await.unwrap();
    assert!(r.differences.is_empty(), "{}", r.differences.join("\n"));
    assert_eq!(h.count("devices where id = 4 and status = 'active'"), 1);
    assert_eq!(h.count("device_groups where name = 'Lab'"), 1);
    assert_eq!(h.count("device_groups where id = 2"), 0);
    assert_eq!(h.count("address_books where name = 'Field techs'"), 1);
    assert_eq!(h.count("api_tokens where name = 'ci'"), 1);
    assert_eq!(h.text("select value from settings where key = 'online_window'"), "45");
    assert_eq!(h.text("select value from settings where key = 'backup_keep_daily'"), "3");
    assert_eq!(h.text("select value from settings where key = 'log_retention_days'"), "30");
    assert_eq!(h.text("select note from devices where id = 1"), "Reception desk, left monitor");
    // 7c: roles
    assert_eq!(h.text("select permissions from roles where name = 'Helpdesk'"), r#"{"device":"r","user":"none","group":"none","address_book":"rw","audit":"r","strategy":"none","setting":"rw","token":"none"}"#);
    assert_eq!(h.count("roles where id = 1"), 0);
    assert_eq!(h.count("users where id = 3 and role_id is null"), 1);
    assert_eq!(h.count("console_audits where action like 'role.%'"), 3);
}

/// Every dialog the replay opens (`pagereplay::dialogs`) answers 200 and shows its dialog.
#[tokio::test]
async fn the_dialogs_the_replay_opens() {
    let h = harness().await;
    let cookie = h.login(&sid("dialogs"), 1, json!({}));
    let fields = [tok(), ("id", "0"), ("name", "Lock"), ("enabled", "1"), ("is_default", "1"), ("timeout", "15"), ("opt_access-mode", "view")];
    let r = h.post_form("/strategies/preview", &cookie, &fields).await;
    let fp = r.body.split("name=\"fingerprint\" value=\"").nth(1).unwrap().split('"').next().unwrap().to_string();
    let mut good = fields.to_vec();
    good.push(("fingerprint", &fp));
    assert_eq!(h.post_form("/strategies/confirm", &cookie, &good).await.status, 302);
    for q in [
        "/strategies?create=1", "/strategies?edit=1", "/strategies?assign=1", "/strategies?history=1", "/strategies?compliance=1", "/strategies?delete=1",
        "/users?create=1", "/users?edit=2", "/users?assign=2", "/groups?tab=devices&create=1", "/groups?tab=users&create=1", "/groups?tab=devices&edit=2",
        "/devices?create=1", "/devices?delete=1", "/devices/1?edit=1", "/devices/1?delete=1", "/roles?create=1", "/roles?edit=1",
    ] {
        let r = h.get(q, &cookie).await;
        assert_eq!(r.status, 200, "{q}: {}", &r.body[..r.body.len().min(400)]);
        assert!(r.body.contains("modal fade show"), "{q} shows no dialog");
    }
}

/// An S3 that answers every request: an empty list, 200 for the rest; records what it was asked.
fn fake_s3() -> (String, Arc<Mutex<Vec<String>>>) {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(vec![]));
    let log = seen.clone();
    std::thread::spawn(move || {
        for conn in l.incoming().flatten() {
            let mut c = conn;
            let mut buf = vec![0u8; 65536];
            let mut head = String::new();
            let mut got = 0;
            // read the head, then drain the declared body
            loop {
                let n = c.read(&mut buf[got..]).unwrap_or(0);
                if n == 0 {
                    break;
                }
                got += n;
                head = String::from_utf8_lossy(&buf[..got]).into_owned();
                if let Some(end) = head.find("\r\n\r\n") {
                    let len = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0))).unwrap_or(0);
                    if got >= end + 4 + len {
                        break;
                    }
                    if got == buf.len() {
                        got = end + 4;
                    }
                }
            }
            log.lock().unwrap().push(head.lines().next().unwrap_or("").to_string());
            let body = "<?xml version=\"1.0\"?><ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>";
            let _ = write!(c, "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        }
    });
    (url, seen)
}

#[tokio::test(flavor = "multi_thread")]
async fn backups_off_site_copy_and_upload() {
    let _env = ENV.lock().await;
    let h = harness().await;
    let keep = tempfile::tempdir().unwrap();
    let backups = keep.path().join("backups");
    std::env::set_var("HTE_CONSOLE_DATABASE", &h.db_path);
    std::env::set_var("APP_KEY", APP_KEY);
    std::env::set_var("HTE_CONSOLE_BACKUPS_DIR", &backups);
    std::env::set_var("HTE_CONSOLE_RUSTDESK_DIR", keep.path().join("rustdesk"));
    std::env::set_var("HTE_CONSOLE_SERVER_SECRET_FILE", keep.path().join("none"));
    let admin = h.login(&sid("os1"), 1, json!({}));

    // the page offers both
    let r = h.get("/settings?tab=backups", &admin).await;
    assert!(r.body.contains("Off-site copy") && r.body.contains("Restore from a file") && !r.body.contains("Test connection"));

    // a target without what it needs is refused, nothing written
    let r = h.post_form("/settings/backups/save", &admin, &[tok(), ("keep_daily", "7"), ("keep_weekly", "8"), ("keep_monthly", "6"), ("target", "s3"), ("s3_bucket", "")]).await;
    assert_eq!(r.status, 302);
    let r = h.get("/settings?tab=backups", &admin).await;
    assert!(r.body.contains("A bucket name is needed to copy backups there."), "{}", r.body);
    assert_eq!(h.count("settings where key = 'backup_target'"), 0);
    let r = h.post_form("/settings/backups/save", &admin, &[tok(), ("keep_daily", "7"), ("keep_weekly", "8"), ("keep_monthly", "6"), ("target", "s3"), ("s3_bucket", "bk"), ("s3_endpoint", "ftp://nope")]).await;
    assert_eq!(r.status, 302);
    assert!(h.get("/settings?tab=backups", &admin).await.body.contains("The s3 endpoint field must be a valid URL."));

    // saved: the secret is stored encrypted and not shown again; Test connection saves, then asks the (fake) S3
    let (url, seen) = fake_s3();
    let form = [tok(), ("enabled", "1"), ("keep_daily", "7"), ("keep_weekly", "8"), ("keep_monthly", "6"), ("target", "s3"), ("s3_bucket", "bk"), ("s3_endpoint", url.as_str()), ("s3_path_style", "1"), ("s3_access_key", "AKIA"), ("s3_secret_key", "hunter2-secret")];
    let r = h.post_form("/settings/backups/test", &admin, &form).await;
    assert_eq!(r.status, 302);
    let stored = h.text("select value from settings where key = 'backup_s3_secret_key'");
    assert!(!stored.is_empty() && !stored.contains("hunter2"));
    let page = h.get("/settings?tab=backups", &admin).await.body;
    assert!(page.contains("Connected to S3 bucket bk"), "{page}");
    assert!(page.contains("stored, blank keeps it") && !page.contains("hunter2"));
    assert!(seen.lock().unwrap().iter().any(|l| l.starts_with("PUT ") || l.starts_with("GET ")), "{:?}", seen.lock().unwrap());

    // Back up now copies the new archive to the target
    let r = h.post_form("/settings/backups/run", &admin, &[tok()]).await;
    assert_eq!(r.status, 302);
    let page = h.get("/settings?tab=backups", &admin).await.body;
    assert!(page.contains("copied to S3 bucket bk"), "{page}");
    assert!(seen.lock().unwrap().iter().any(|l| l.starts_with("PUT /bk/hte-remote-backup-")), "{:?}", seen.lock().unwrap());

    // restore from a file: the archive of another moment, checked, stored under its name, restored
    let name = std::fs::read_dir(&backups).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).find(|n| n.ends_with(".tar")).unwrap();
    let bytes = std::fs::read(backups.join(&name)).unwrap();
    h.sql("insert into settings (key, value) values ('marker', 'after the backup')");
    let r = h.post_file("/settings/backups/upload", &admin, "upload", "mine.tar", &bytes).await;
    assert_eq!(r.status, 302, "{}", r.body);
    assert_eq!(h.count("settings where key = 'marker'"), 0);
    assert_eq!(h.count("console_audits where action = 'backup.restore'"), 1);
    let uploaded: Vec<String> = std::fs::read_dir(&backups).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| n.ends_with("-upload.tar")).collect();
    assert_eq!(uploaded.len(), 1, "{uploaded:?}");
    assert!(backups.join(format!("{}.json", uploaded[0])).is_file());
    // nothing picked, and a file that is not ours
    let r = h.post_file("/settings/backups/upload", &admin, "upload", "", b"").await;
    assert_eq!(r.status, 302);
    assert!(h.get("/settings?tab=backups", &admin).await.body.contains("Pick a backup archive first."));
    let r = h.post_file("/settings/backups/upload", &admin, "upload", "x.tar", b"not a tar").await;
    assert_eq!(r.status, 302);
    assert!(h.get("/settings?tab=backups", &admin).await.body.contains("That file is not an HTE Remote backup."));
}
