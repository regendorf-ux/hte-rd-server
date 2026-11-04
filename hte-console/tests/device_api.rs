//! Phase 1 end to end: the native device endpoints on a real socket, against a temporary database made from
//! tests/schema.sql, a stand-in hbbs peer table with a known key pair, and a clock the tests move.
//! Expectations come from the previous console's source (v1.15.0-hte.1); each test names the previous console behaviour it pins.

use base64::Engine;
use hte_console::api::{router, Limiter, Native, Nonces};
use hte_console::laravel::{self, Encrypter};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use sodiumoxide::crypto::{sealedbox, sign};
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

const T0: i64 = 1_800_000_000; // 2027-01-15 08:00:00 UTC
const APP_KEY: &str = "base64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const UUID: &str = "UExBQ0VIT0xERVIhAAAAAA==";

struct H {
    url: String,
    db_path: PathBuf,
    clock: Arc<AtomicI64>,
    client: reqwest::Client,
    native: Arc<Native>,
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

fn keypair() -> (sign::PublicKey, sign::SecretKey) {
    sign::keypair_from_seed(&sign::Seed([7u8; 32]))
}

async fn harness() -> H {
    harness_with(laravel::DEFAULT_TRUSTED).await
}

async fn harness_with(trusted: &str) -> H {
    sodiumoxide::init().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cortendesk.sqlite");
    let c = Connection::open(&db_path).unwrap();
    c.execute_batch(include_str!("schema.sql")).unwrap();
    c.execute_batch(hte_console::path::SCHEMA).unwrap(); // the own migration, as the service has run it
    drop(c);
    let hbbs = dir.path().join("db_v2.sqlite3");
    let h = Connection::open(&hbbs).unwrap();
    h.execute_batch("create table peer (guid blob, id varchar(100) not null, uuid blob, pk blob not null, info text)").unwrap();
    h.execute("insert into peer (id, pk) values ('990000777', ?)", params![keypair().0 .0.to_vec()]).unwrap();
    h.execute("insert into peer (id, pk) values ('990000666', ?)", params![vec![0u8; 32]]).unwrap(); // not a usable point
    drop(h);
    let clock = Arc::new(AtomicI64::new(T0));
    let ck = clock.clone();
    let native = Arc::new(Native {
        db: Mutex::new(hte_console::sqlite::open(&db_path, std::time::Duration::from_secs(5), true).unwrap()),
        crypt: Encrypter::from_app_key(APP_KEY).unwrap(),
        hbbs_db: hbbs,
        trusted: laravel::parse_trusted(trusted),
        api_version: "1.15.0-hte.1".into(),
        max_body: 1 << 20,
        limiter: Mutex::new(Limiter::default()),
        nonces: Mutex::new(Nonces::default()),
        signin: hte_console::signin::State::new(hte_console::oidc::Oidc::new(false, false), None, "CortenDesk".into()),
        clock: Box::new(move || ck.load(Ordering::SeqCst)),
    });
    let app = router(native.clone(), None).into_make_service_with_connect_info::<std::net::SocketAddr>();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    H { url, db_path, clock, client: reqwest::Client::new(), native, _dir: dir }
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
    fn ts(&self) -> String {
        laravel::ts(self.clock.load(Ordering::SeqCst))
    }
    async fn send(&self, method: &str, path: &str, ct: Option<&str>, body: Vec<u8>, xff: &str) -> Resp {
        let mut rq = self.client.request(method.parse().unwrap(), format!("{}{}", self.url, path)).header("x-forwarded-for", xff);
        if let Some(ct) = ct {
            rq = rq.header("content-type", ct);
        }
        let r = rq.body(body).send().await.unwrap();
        let status = r.status().as_u16();
        let headers = r.headers().clone();
        let ct = headers.get("content-type").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
        Resp { status, ct, headers, body: r.text().await.unwrap() }
    }
    async fn post(&self, path: &str, body: Value) -> Resp {
        self.send("POST", path, Some("application/json"), serde_json::to_vec(&body).unwrap(), "203.0.113.9").await
    }
    async fn post_raw(&self, path: &str, body: &str) -> Resp {
        self.send("POST", path, Some("application/json"), body.as_bytes().to_vec(), "203.0.113.9").await
    }
    fn device(&self, id: &str, uuid: &str, hostname: Option<&str>) {
        self.db()
            .execute(
                "insert into devices (rustdesk_id, uuid, hostname, status, created_at, updated_at) values (?, ?, ?, 'active', '2026-01-01 00:00:00', '2026-01-01 00:00:00')",
                params![id, uuid, hostname],
            )
            .unwrap();
    }
}

// ------------------------------------------------------------------------------------------- heartbeat ---

#[tokio::test]
async fn heartbeat_without_id_unknown_and_known() {
    let h = harness().await;
    let r = h.post("/api/heartbeat", json!({})).await;
    assert_eq!((r.status, r.body.as_str()), (200, "{}"));
    assert_eq!(r.ct, "application/json");
    let r = h.post("/api/heartbeat", json!({"id": "990000001", "uuid": UUID})).await;
    assert_eq!(r.body, r#"{"sysinfo":1}"#);
    assert_eq!(h.count("devices"), 0, "an unknown device is not created by a heartbeat");

    h.device("990000001", UUID, Some("host-a"));
    let r = h.post("/api/heartbeat", json!({"id": "990000001", "uuid": UUID, "ver": 1005000})).await;
    assert_eq!(r.body, "{}");
    assert_eq!(h.one::<String>("select last_online_at from devices"), h.ts());
    assert_eq!(h.one::<String>("select last_online_ip from devices"), "203.0.113.9");
    assert_eq!(h.one::<String>("select updated_at from devices"), h.ts());
    // rate-limit headers as Laravel adds them (device limit: fewer attempts left)
    assert_eq!(r.headers["x-ratelimit-limit"], "120");
    assert_eq!(r.headers["x-ratelimit-remaining"], "118");
    assert_eq!(r.headers["cache-control"], "no-cache, private");
}

#[tokio::test]
async fn heartbeat_known_device_without_inventory_asks_for_sysinfo() {
    let h = harness().await;
    h.device("990000001", UUID, None);
    assert_eq!(h.post("/api/heartbeat", json!({"id": "990000001", "uuid": UUID})).await.body, r#"{"sysinfo":1}"#);
    h.sql("update devices set hostname = ''");
    assert_eq!(h.post("/api/heartbeat", json!({"id": "990000001", "uuid": UUID})).await.body, r#"{"sysinfo":1}"#);
}

#[tokio::test]
async fn heartbeat_uuid_pinning_and_trash() {
    let h = harness().await;
    h.device("990000001", "plain-uuid", Some("host-a"));
    // a different machine with the same id: answered {} and nothing written
    let r = h.post("/api/heartbeat", json!({"id": "990000001", "uuid": "b3RoZXI="})).await;
    assert_eq!(r.body, "{}");
    assert!(h.one::<Option<String>>("select last_online_at from devices").is_none());
    // base64 of the stored plain uuid matches, and the uuid is re-pinned in the client's form
    let sent = base64::engine::general_purpose::STANDARD.encode("plain-uuid");
    h.post("/api/heartbeat", json!({"id": "990000001", "uuid": sent})).await;
    assert_eq!(h.one::<String>("select uuid from devices"), sent);
    // recycled devices stay invisible
    h.sql("update devices set deleted_at = '2026-01-02 00:00:00', last_online_at = null");
    assert_eq!(h.post("/api/heartbeat", json!({"id": "990000001", "uuid": sent})).await.body, "{}");
    assert!(h.one::<Option<String>>("select last_online_at from devices").is_none());
}

#[tokio::test]
async fn heartbeat_reconciles_sessions_and_delivers_disconnects() {
    let h = harness().await;
    h.device("990000001", UUID, Some("host-a"));
    let old = laravel::ts(T0 - 600);
    h.sql(&format!(
        "insert into audit_connections (action, conn_id, rustdesk_id, created_at, updated_at) values ('authorized', 11, '990000001', '{old}', '{old}');
         insert into audit_connections (action, conn_id, rustdesk_id, created_at, updated_at) values ('authorized', 12, '990000001', '{old}', '{old}');
         insert into audit_connections (action, conn_id, rustdesk_id, disconnect_requested_at, created_at, updated_at) values ('authorized', 13, '990000001', '{old}', '{old}', '{old}');"
    ));
    let r = h.post("/api/heartbeat", json!({"id": "990000001", "uuid": UUID, "conns": [12, 13]})).await;
    assert_eq!(r.json(), json!({"disconnect": [13]}));
    assert_eq!(h.one::<String>("select action from audit_connections where conn_id = 11"), "close");
    assert!(h.one::<Option<String>>("select closed_at from audit_connections where conn_id = 12").is_none());
    assert_eq!(h.one::<String>("select disconnect_sent_at from audit_connections where conn_id = 13"), h.ts());
    // asked again within a minute: not repeated; after a minute: repeated
    assert_eq!(h.post("/api/heartbeat", json!({"id": "990000001", "uuid": UUID, "conns": [12, 13]})).await.body, "{}");
    h.advance(61);
    assert_eq!(h.post("/api/heartbeat", json!({"id": "990000001", "uuid": UUID, "conns": [12, 13]})).await.json(), json!({"disconnect": [13]}));
    // no conns at all = nothing is live: everything open and older than the grace period closes
    h.post("/api/heartbeat", json!({"id": "990000001", "uuid": UUID})).await;
    assert_eq!(h.count("audit_connections where closed_at is null"), 0);
}

#[tokio::test]
async fn heartbeat_consumes_a_presence_recovery_marker() {
    let h = harness().await;
    h.device("990000001", UUID, Some("host-a"));
    h.sql("insert into device_presence_notification_states (device_id, offline_notified_at) values (1, '2026-01-01 00:00:00')");
    h.post("/api/heartbeat", json!({"id": "990000001", "uuid": UUID})).await;
    assert_eq!(h.count("device_presence_notification_states"), 0);
}

// -------------------------------------------------------------------------------------------- strategy ---

fn strategy(h: &H, enforce: bool, options: &str) {
    h.db()
        .execute(
            "insert into strategies (name, enabled, is_default, enforce, options, created_at, updated_at) values ('s', 1, 1, ?, ?, '2026-01-01 00:00:00', '2026-01-01 00:00:00')",
            params![enforce as i64, options],
        )
        .unwrap();
    h.sql("update devices set strategy_id_resolved = (select id from strategies)");
}

#[tokio::test]
async fn strategy_is_pushed_acked_and_not_repeated() {
    let h = harness().await;
    h.device("990000001", UUID, Some("host-a"));
    strategy(&h, false, r#"{"direct-server":"N","enable-audio":true,"2fa":"secret","whitelist":"10.0.0.0/8"}"#);
    let r = h.post("/api/heartbeat", json!({"id": "990000001", "uuid": UUID, "modified_at": 0})).await;
    let v = r.json();
    assert_eq!(v["modified_at"], json!(T0));
    assert_eq!(v["strategy"], json!({"config_options": {"direct-server": "N", "enable-audio": "Y", "whitelist": "10.0.0.0/8"}}));
    assert!(r.body.contains(r#""10.0.0.0\/8""#), "slashes escaped as the previous console's json_encode does: {}", r.body);
    assert_eq!(h.one::<i64>("select strategy_version from devices"), T0);
    assert_eq!(h.one::<String>("select strategy_options from devices"), r#"{"direct-server":"N","enable-audio":"Y","whitelist":"10.0.0.0\/8"}"#);
    assert_eq!(h.one::<String>("select strategy_sent_at from devices"), h.ts());
    // the device echoes the token: acknowledged, nothing more to say (not enforced)
    h.advance(15);
    let r = h.post("/api/heartbeat", json!({"id": "990000001", "uuid": UUID, "modified_at": T0})).await;
    assert_eq!(r.body, "{}");
    assert_eq!(h.one::<String>("select strategy_acked_options from devices"), h.one::<String>("select strategy_options from devices"));
    assert_eq!(h.one::<String>("select strategy_acked_at from devices"), h.ts());
    // within a minute the ack is not rewritten
    let acked_at = h.one::<String>("select strategy_acked_at from devices");
    h.advance(15);
    h.post("/api/heartbeat", json!({"id": "990000001", "uuid": UUID, "modified_at": T0})).await;
    assert_eq!(h.one::<String>("select strategy_acked_at from devices"), acked_at);
    // the option is dropped from the strategy: the device is told to reset it with ""
    h.advance(60);
    h.sql(r#"update strategies set options = '{"direct-server":"N","enable-audio":true}'"#);
    let v = h.post("/api/heartbeat", json!({"id": "990000001", "uuid": UUID, "modified_at": T0})).await.json();
    assert_eq!(v["strategy"]["config_options"], json!({"direct-server": "N", "enable-audio": "Y", "whitelist": ""}));
    assert_eq!(v["modified_at"], json!(T0 + 90));
}

#[tokio::test]
async fn strategy_enforce_repeats_and_pending_devices_get_none() {
    let h = harness().await;
    h.device("990000001", UUID, Some("host-a"));
    strategy(&h, true, r#"{"direct-server":"N"}"#);
    let v = h.post("/api/heartbeat", json!({"id": "990000001", "uuid": UUID})).await.json();
    let token = v["modified_at"].as_i64().unwrap();
    let v = h.post("/api/heartbeat", json!({"id": "990000001", "uuid": UUID, "modified_at": token})).await.json();
    assert_eq!(v, json!({"modified_at": token, "strategy": {"config_options": {"direct-server": "N"}}}));
    h.sql("update devices set status = 'pending'");
    assert_eq!(h.post("/api/heartbeat", json!({"id": "990000001", "uuid": UUID, "modified_at": token})).await.body, "{}");
}

// --------------------------------------------------------------------------------------------- sysinfo ---

#[tokio::test]
async fn sysinfo_creates_updates_and_answers_in_plain_text() {
    let h = harness().await;
    let r = h.post("/api/sysinfo", json!({"uuid": UUID})).await;
    assert_eq!((r.status, r.body.as_str(), r.ct.as_str()), (200, "ID_NOT_FOUND", "text/html; charset=UTF-8"));
    let info = json!({"id": "990000001", "uuid": UUID, "cpu": " cpu-x ", "memory": "16GB", "os": "windows / Windows 11", "hostname": "host-a", "username": "", "version": "1.5.0"});
    assert_eq!(h.post("/api/sysinfo", info.clone()).await.body, "SYSINFO_UPDATED");
    let row: (String, String, String, String, String, String) = h
        .db()
        .query_row("select cpu, username, status, registered_ip, last_online_ip, created_at from devices", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
        .unwrap();
    assert_eq!(row, ("cpu-x".into(), "".into(), "active".into(), "203.0.113.9".into(), "203.0.113.9".into(), h.ts()));
    // an update changes only what changed; registered_ip stays where the device first appeared
    h.advance(30);
    let mut later = info.clone();
    later["hostname"] = json!("host-b");
    h.send("POST", "/api/sysinfo", Some("application/json"), serde_json::to_vec(&later).unwrap(), "198.51.100.4").await;
    assert_eq!(h.one::<String>("select hostname from devices"), "host-b");
    assert_eq!(h.one::<String>("select registered_ip from devices"), "203.0.113.9");
    assert_eq!(h.one::<String>("select last_online_ip from devices"), "198.51.100.4");
    // another machine with the same id: acknowledged, ignored
    let mut other = info.clone();
    other["uuid"] = json!("b3RoZXI=");
    other["hostname"] = json!("intruder");
    assert_eq!(h.post("/api/sysinfo", other).await.body, "SYSINFO_UPDATED");
    assert_eq!(h.one::<String>("select hostname from devices"), "host-b");
}

#[tokio::test]
async fn sysinfo_new_device_approval_gate_group_and_strategy() {
    let h = harness().await;
    h.sql(
        "insert into settings (key, value) values ('require_device_approval', '1'), ('default_device_group_id', '1'), ('auto_approve_signed_in', '1');
         insert into device_groups (id, name) values (1, 'g');
         insert into users (id, username, password, is_active) values (5, 'u', 'x', 1);
         insert into strategies (name, enabled, is_default, options) values ('d', 1, 1, '{}');
         insert into strategies (name, enabled, is_default, options) values ('mine', 1, 0, '{}');
         insert into strategy_user (user_id, strategy_id) values (5, 2);",
    );
    // pending, in the default group, resolved to the default strategy
    h.post("/api/sysinfo", json!({"id": "990000001", "uuid": UUID, "hostname": "a"})).await;
    let row: (String, i64, i64, Option<i64>) =
        h.db().query_row("select status, device_group_id, strategy_id_resolved, user_id from devices", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).unwrap();
    assert_eq!(row, ("pending".into(), 1, 1, None));
    // a client already signed in from that device approves it on first sight and owns it
    h.sql("insert into client_tokens (user_id, token, device_id) values (5, 'tok', '990000002')");
    h.post("/api/sysinfo", json!({"id": "990000002", "uuid": UUID, "hostname": "b"})).await;
    let row: (String, i64, i64) =
        h.db().query_row("select status, user_id, strategy_id_resolved from devices where rustdesk_id = '990000002'", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
    assert_eq!(row, ("active".into(), 5, 2));
}

#[tokio::test]
async fn sysinfo_new_devices_incoming_only_leaves_known_devices_alone() {
    let h = harness().await;
    h.post("/api/sysinfo", json!({"id": "990000001", "uuid": UUID, "hostname": "old"})).await;
    h.sql("insert into settings (key, value) values ('new_devices_incoming_only', '1')");
    h.post("/api/sysinfo", json!({"id": "990000002", "uuid": UUID, "hostname": "new"})).await;
    h.post("/api/sysinfo", json!({"id": "990000001", "uuid": UUID, "hostname": "old2"})).await;
    assert_eq!(h.one::<i64>("select can_initiate from devices where rustdesk_id = '990000001'"), 1);
    assert_eq!(h.one::<i64>("select can_initiate from devices where rustdesk_id = '990000002'"), 0);
}

// ------------------------------------------------------------------------------------------------ audit ---

#[tokio::test]
async fn audit_conn_new_authorized_close_and_retries() {
    let h = harness().await;
    let new = json!({"action": "new", "id": "990000001", "conn_id": 7001, "ip": "198.18.0.9", "session_id": 0, "uuid": UUID, "nonce": "n1"});
    let r = h.post("/api/audit/conn", new.clone()).await;
    assert_eq!((r.status, r.body.as_str()), (200, ""));
    // the same nonce again: answered as stored, not written again
    h.post("/api/audit/conn", new.clone()).await;
    // no nonce, same connection, inside the retry window: still one row
    let mut no_nonce = new.clone();
    no_nonce.as_object_mut().unwrap().remove("nonce");
    h.post("/api/audit/conn", no_nonce).await;
    assert_eq!(h.count("audit_connections"), 1);
    let guid: String = h.one("select guid from audit_connections");
    assert_eq!(guid.len(), 36);
    // authorized: the row is updated with the peer and the real session id (a u64 kept exact)
    h.advance(2);
    let auth = json!({"id": "990000001", "conn_id": 7001, "peer": ["990000002", "Alice"], "type": 0, "session_id": 18446744073709551615u64, "nonce": "n2"});
    h.post("/api/audit/conn", auth).await;
    let row: (String, String, String, String, i64) = h
        .db()
        .query_row("select action, from_peer, from_name, session_id, conn_type from audit_connections", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
        .unwrap();
    assert_eq!(row, ("authorized".into(), "990000002".into(), "Alice".into(), "18446744073709551615".into(), 0));
    // legacy note from the controlling side (tokenless, no conn_id)
    h.post("/api/audit/conn", json!({"id": "990000001", "session_id": 18446744073709551615u64, "note": "  checked  "})).await;
    assert_eq!(h.one::<String>("select note from audit_connections"), "checked");
    // close
    h.advance(2);
    h.post("/api/audit/conn", json!({"action": "close", "id": "990000001", "conn_id": 7001, "nonce": "n3"})).await;
    assert_eq!(h.one::<String>("select closed_at from audit_connections"), h.ts());
    // conn_id 0 or no id: stored, nothing written
    h.post("/api/audit/conn", json!({"action": "new", "id": "990000001", "conn_id": 0})).await;
    h.post("/api/audit/conn", json!({"action": "new", "conn_id": 5})).await;
    assert_eq!(h.count("audit_connections"), 1);
}

#[tokio::test]
async fn audit_conn_authorized_without_new_creates_a_row() {
    let h = harness().await;
    h.post("/api/audit/conn", json!({"id": "990000001", "conn_id": 9, "peer": "990000002", "type": "1"})).await;
    let row: (String, String, String, i64, String) =
        h.db().query_row("select action, from_peer, from_name, conn_type, ip from audit_connections", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).unwrap();
    assert_eq!(row, ("authorized".into(), "990000002".into(), "".into(), 1, "203.0.113.9".into()));
}

#[tokio::test]
async fn audit_write_failure_answers_500_and_forgets_the_nonce() {
    let h = harness().await;
    // an array where the previous console casts to string inside the write: "Audit record not stored", and the retry may store it
    let bad = json!({"action": "new", "id": "990000001", "conn_id": 1, "ip": ["x"], "nonce": "n"});
    let r = h.post("/api/audit/conn", bad).await;
    assert_eq!((r.status, r.json()), (500, json!({"error": "Audit record not stored"})));
    let good = json!({"action": "new", "id": "990000001", "conn_id": 1, "ip": "198.18.0.9", "nonce": "n"});
    assert_eq!(h.post("/api/audit/conn", good).await.status, 200);
    assert_eq!(h.count("audit_connections"), 1);
}

#[tokio::test]
async fn audit_file_and_alarm() {
    let h = harness().await;
    let info = r#"{"ip":"198.18.0.9","name":"Bob","num":3,"files":[["a.txt",10]]}"#;
    let r = h.post("/api/audit/file", json!({"id": "990000001", "peer_id": "990000002", "path": "C:\\x", "info": info, "is_file": true, "type": 1, "uuid": UUID, "nonce": "f"})).await;
    assert_eq!((r.status, r.body.as_str()), (200, ""));
    let row: (String, String, i64, i64, i64, String) = h
        .db()
        .query_row("select from_peer, from_name, is_file, direction, file_count, ip from audit_file_transfers", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
        .unwrap();
    assert_eq!(row, ("990000002".into(), "Bob".into(), 1, 1, 3, "198.18.0.9".into()));
    // info that is not JSON: stored as given, the client address used
    h.post("/api/audit/file", json!({"id": "990000001", "info": "not json"})).await;
    assert_eq!(h.one::<String>("select ip from audit_file_transfers where id = 2"), "203.0.113.9");
    assert_eq!(h.one::<i64>("select is_file from audit_file_transfers where id = 2"), 0);

    let r = h.post("/api/audit/alarm", json!({"id": "990000001", "uuid": UUID, "typ": 1, "info": "{\"ip\":\"198.18.0.9\"}", "nonce": "a"})).await;
    assert_eq!((r.status, r.body.as_str()), (200, ""));
    h.post("/api/audit/alarm", json!({"id": "990000001", "typ": 9, "conn_id": 4})).await;
    let rows: Vec<(i64, Option<i64>)> = h.db().prepare("select typ, conn_id from alarm_logs order by id").unwrap().query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(Result::unwrap).collect();
    assert_eq!(rows, vec![(1, None), (9, Some(4))]);
    assert_eq!(h.post("/api/audit/alarm", json!({"typ": 1})).await.body, "");
    assert_eq!(h.count("alarm_logs"), 2);
}

// ------------------------------------------------------------------------------------------- bad input ---

#[tokio::test]
async fn form_and_charset_bodies_are_read_as_php_reads_them() {
    let h = harness().await;
    h.device("990000001", UUID, Some("host-a"));
    // a form body (what parse_str reads), with the uuid's padding percent-encoded
    let form = b"id=990000001&uuid=UExBQ0VIT0xERVIhAAAAAA%3D%3D".to_vec();
    let r = h.send("POST", "/api/heartbeat", Some("application/x-www-form-urlencoded"), form, "203.0.113.9").await;
    assert_eq!((r.status, r.body.as_str()), (200, "{}"));
    assert_eq!(h.one::<String>("select last_online_at from devices"), h.ts());
    // sysinfo from a form: trimmed like any input, the empty string becomes null
    let form = b"id=990000001&uuid=UExBQ0VIT0xERVIhAAAAAA%3D%3D&hostname=+host-f+&cpu=".to_vec();
    let r = h.send("POST", "/api/sysinfo", Some("application/x-www-form-urlencoded; charset=UTF-8"), form, "203.0.113.9").await;
    assert_eq!(r.body, "SYSINFO_UPDATED");
    assert_eq!(h.one::<String>("select hostname from devices"), "host-f");
    assert_eq!(h.one::<String>("select cpu from devices"), "");
    // JSON with a charset parameter is still JSON
    h.advance(10);
    let body = serde_json::to_vec(&json!({"id": "990000001", "uuid": UUID})).unwrap();
    let r = h.send("POST", "/api/heartbeat", Some("application/json; charset=utf-8"), body, "198.51.100.7").await;
    assert_eq!(r.body, "{}");
    assert_eq!(h.one::<String>("select last_online_ip from devices"), "198.51.100.7");
}

#[tokio::test]
async fn client_address_follows_the_trusted_proxies() {
    let body = || serde_json::to_vec(&json!({"id": "990000001", "uuid": UUID})).unwrap();
    // the test client is 127.0.0.1: trusted by default, by `*` and as REMOTE_ADDR
    for trusted in [laravel::DEFAULT_TRUSTED, "*", "REMOTE_ADDR"] {
        let h = harness_with(trusted).await;
        h.device("990000001", UUID, None);
        // two X-Forwarded-For headers are one list; the right-most untrusted address is the client
        let r = h
            .client
            .post(format!("{}/api/heartbeat", h.url))
            .header("content-type", "application/json")
            .header("x-forwarded-for", "192.0.2.1")
            .header("x-forwarded-for", "203.0.113.9, 10.1.2.3")
            .body(body())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
        // `*`: every hop is trusted, so the left-most; REMOTE_ADDR trusts only the peer, so 10.1.2.3 is the client
        let want = match trusted {
            "*" => "192.0.2.1",
            "REMOTE_ADDR" => "10.1.2.3",
            _ => "203.0.113.9",
        };
        assert_eq!(h.one::<String>("select last_online_ip from devices"), want, "{trusted}");
    }
    // trusting nobody (or only a name, which the previous console cannot match either): the peer is the client
    for trusted in ["", "proxy.example"] {
        let h = harness_with(trusted).await;
        h.device("990000001", UUID, None);
        h.send("POST", "/api/heartbeat", Some("application/json"), body(), "203.0.113.9").await;
        assert_eq!(h.one::<String>("select last_online_ip from devices"), "127.0.0.1", "{trusted:?}");
    }
}

#[tokio::test]
async fn unreadable_stored_timestamps_answer_500_as_carbon_throws() {
    let h = harness().await;
    h.device("990000001", UUID, Some("host-a"));
    strategy(&h, false, r#"{"direct-server":"N"}"#);
    let token = h.post("/api/heartbeat", json!({"id": "990000001", "uuid": UUID})).await.json()["modified_at"].as_i64().unwrap();
    h.sql("update devices set strategy_acked_at = 'not a date'");
    let r = h.post("/api/heartbeat", json!({"id": "990000001", "uuid": UUID, "modified_at": token})).await;
    assert_eq!((r.status, r.json()), (500, json!({"message": "Server Error"})));
    // a client token that expires at nonsense: the new device is stored (no transaction), then the 500
    h.sql(
        "insert into settings (key, value) values ('require_device_approval', '1'), ('auto_approve_signed_in', '1');
         insert into users (id, username, password, is_active) values (5, 'u', 'x', 1);
         insert into client_tokens (user_id, token, device_id, expires_at) values (5, 'tok', '990000002', 'soon');",
    );
    let r = h.post("/api/sysinfo", json!({"id": "990000002", "uuid": UUID, "hostname": "b"})).await;
    assert_eq!((r.status, r.json()), (500, json!({"message": "Server Error"})));
    assert_eq!(h.one::<String>("select status from devices where rustdesk_id = '990000002'"), "pending");
}

#[tokio::test]
async fn a_soft_deleted_strategy_still_resolves_through_a_link_but_delivers_nothing() {
    // Strategy::resolve joins the link tables without the soft-delete scope; deliveryFor's find() has it
    let h = harness().await;
    h.sql(
        "insert into settings (key, value) values ('require_device_approval', '1'), ('auto_approve_signed_in', '1');
         insert into users (id, username, password, is_active) values (5, 'u', 'x', 1);
         insert into strategies (name, enabled, is_default, options) values ('d', 1, 1, '{\"direct-server\":\"Y\"}');
         insert into strategies (name, enabled, is_default, options, deleted_at) values ('gone', 1, 0, '{\"direct-server\":\"N\"}', '2026-01-01 00:00:00');
         insert into strategy_user (user_id, strategy_id) values (5, 2);
         insert into client_tokens (user_id, token, device_id) values (5, 'tok', '990000001');",
    );
    h.post("/api/sysinfo", json!({"id": "990000001", "uuid": UUID, "hostname": "a"})).await;
    assert_eq!(h.one::<i64>("select strategy_id_resolved from devices"), 2);
    assert_eq!(h.post("/api/heartbeat", json!({"id": "990000001", "uuid": UUID})).await.body, "{}");
}

#[tokio::test]
async fn bad_input_gets_what_php_gives() {
    let h = harness().await;
    h.device("990000001", UUID, Some("host-a"));
    // invalid JSON is an empty input bag: no id
    assert_eq!(h.post_raw("/api/heartbeat", "{\"id\":").await.body, "{}");
    assert_eq!(h.post_raw("/api/sysinfo", "garbage").await.body, "ID_NOT_FOUND");
    // nesting beyond the previous console's 512 levels is invalid JSON too
    let deep = format!("{{\"id\":\"990000001\",\"x\":{}{}}}", "[".repeat(600), "]".repeat(600));
    assert_eq!(h.post_raw("/api/heartbeat", &deep).await.body, "{}");
    // Laravel only reads JSON when the Content-Type says so (case-sensitively)
    let r = h.send("POST", "/api/heartbeat", Some("text/plain"), br#"{"id":"990000001"}"#.to_vec(), "203.0.113.9").await;
    assert_eq!(r.body, "{}");
    // an array where the previous console casts to string: the limiter's (string) cast throws, Laravel answers 500
    let r = h.post("/api/heartbeat", json!({"id": ["990000001"]})).await;
    assert_eq!((r.status, r.json()), (500, json!({"message": "Server Error"})));
    assert!(r.headers.get("x-ratelimit-limit").is_none());
    let r = h.post("/api/sysinfo", json!({"id": "990000009", "hostname": {"a": 1}})).await;
    assert_eq!(r.status, 500);
    assert_eq!(h.count("devices where rustdesk_id = '990000009'"), 0);
    let r = h.post("/api/audit/file", json!({"id": "990000001", "info": ["x"]})).await;
    assert_eq!((r.status, r.json()), (500, json!({"message": "Server Error"})));
    // numbers and booleans are cast as the previous console casts them
    h.post("/api/sysinfo", json!({"id": 990000005, "uuid": UUID, "hostname": 1.0, "cpu": true, "memory": false})).await;
    let row: (String, String, String) = h.db().query_row("select hostname, cpu, memory from devices where rustdesk_id = '990000005'", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
    assert_eq!(row, ("1".into(), "1".into(), "".into()));
    // query parameters are input too (the previous console merges them under the body)
    let r = h.send("POST", "/api/heartbeat?id=990000001&uuid=UExBQ0VIT0xERVIhAAAAAA%3D%3D", None, vec![], "203.0.113.9").await;
    assert_eq!(r.body, "{}");
    assert_eq!(h.one::<String>("select last_online_at from devices where rustdesk_id = '990000001'"), h.ts());
}

#[tokio::test]
async fn methods_bodies_and_rate_limits() {
    let h = harness().await;
    let r = h.send("GET", "/api/heartbeat", None, vec![], "203.0.113.9").await;
    assert_eq!(r.status, 405);
    assert_eq!(r.json(), json!({"message": "The GET method is not supported for route api/heartbeat. Supported methods: POST."}));
    assert_eq!(r.headers["allow"], "POST");
    // the exception is rendered inside the pipeline, so HandleCors still adds its header (as on 404 and 413)
    assert_eq!(r.headers["access-control-allow-origin"], "*");
    let r = h.send("OPTIONS", "/api/heartbeat", None, vec![], "203.0.113.9").await;
    assert_eq!((r.status, r.headers["allow"].to_str().unwrap()), (200, "POST"));
    // a CORS preflight is answered by HandleCors before routing
    let r = h
        .client
        .request(reqwest::Method::OPTIONS, format!("{}/api/heartbeat", h.url))
        .header("access-control-request-method", "post")
        .header("access-control-request-headers", "content-type")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 204);
    assert_eq!(r.headers()["access-control-allow-methods"], "POST");
    assert_eq!(r.headers()["access-control-allow-headers"], "content-type");
    assert_eq!(r.headers()["access-control-allow-origin"], "*");
    let r = h.send("GET", "/api/version", None, vec![], "203.0.113.9").await;
    assert_eq!((r.status, r.body.as_str(), r.ct.as_str()), (200, "1.15.0-hte.1", "text/html; charset=UTF-8"));
    assert_eq!(h.send("POST", "/api/version", None, vec![], "203.0.113.9").await.status, 405);
    // bodies are bounded: answered from the declared length, before any of the body is read (raw socket: a client
    // still uploading 2 MiB may see the connection close under it, which would make this test racy)
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(h.url.trim_start_matches("http://")).await.unwrap();
        s.write_all(b"POST /api/heartbeat HTTP/1.1\r\nhost: x\r\ncontent-type: application/json\r\ncontent-length: 2097152\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = s.read(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf[..n]);
        assert!(text.starts_with("HTTP/1.1 413"), "{text}");
        assert!(text.contains(r#"{"message":"The POST data is too large."}"#), "{text}");
        assert!(text.contains("access-control-allow-origin: *"), "{text}");
    }
    // 120 a minute per device and address, then 429 until the window ends
    for _ in 0..120 {
        assert_eq!(h.post("/api/heartbeat", json!({"id": "990000001"})).await.status, 200);
    }
    let r = h.post("/api/heartbeat", json!({"id": "990000001"})).await;
    assert_eq!((r.status, r.json()), (429, json!({"message": "Too Many Attempts."})));
    assert_eq!(r.headers["retry-after"], "60");
    assert_eq!(r.headers["x-ratelimit-remaining"], "0");
    // another device behind the same address is not affected; the window ends after a minute
    assert_eq!(h.post("/api/heartbeat", json!({"id": "990000002"})).await.status, 200);
    h.advance(60);
    assert_eq!(h.post("/api/heartbeat", json!({"id": "990000001"})).await.status, 200);
}

// -------------------------------------------------------------------------------- the sealed password ---

#[tokio::test]
async fn sealed_password_is_issued_opened_and_confirmed() {
    let h = harness().await;
    h.device("990000777", UUID, Some("host-a"));
    h.sql(
        "insert into settings (key, value) values ('hte_pw_enabled', '1');
         insert into hte_auto_books (user_id, address_book_id) values (5, 40);
         insert into address_book_entries (address_book_id, rustdesk_id) values (40, '990000777'), (41, '990000777');",
    );
    // a client that does not send hte_pw is left alone
    assert_eq!(h.post("/api/heartbeat", json!({"id": "990000777", "uuid": UUID})).await.body, "{}");
    assert_eq!(h.count("hte_device_passwords"), 0);

    let r = h.post("/api/heartbeat", json!({"id": "990000777", "uuid": UUID, "hte_pw": 0})).await;
    let v = r.json();
    assert_eq!(v["hte_password"]["v"], json!(1));
    // open the box with the device's own key, as HTE Remote does
    let (pk, sk) = keypair();
    let cpk = sign::to_curve25519_pk(&pk).unwrap();
    let csk = sign::to_curve25519_sk(&sk).unwrap();
    let sealed = base64::engine::general_purpose::STANDARD.decode(v["hte_password"]["box"].as_str().unwrap()).unwrap();
    let plain: Value = serde_json::from_slice(&sealedbox::open(&sealed, &cpk, &csk).unwrap()).unwrap();
    assert_eq!(plain["v"], json!(1));
    let pw = plain["pw"].as_str().unwrap().to_string();
    assert_eq!(pw.len(), 20);
    // the database holds it encrypted with the app key, never in clear
    let enc: String = h.one("select current_enc from hte_device_passwords");
    assert!(!enc.contains(&pw));
    assert_eq!(h.native.crypt.decrypt_string(enc.as_bytes()).unwrap(), pw.as_bytes());
    assert_eq!(h.one::<String>("select issued_reason from hte_device_passwords"), "first check-in");

    // still holding the old one: offered again
    h.advance(15);
    assert_eq!(h.post("/api/heartbeat", json!({"id": "990000777", "uuid": UUID, "hte_pw": 0})).await.json()["hte_password"]["v"], json!(1));
    // reports the new one: confirmed, into the automatic book (not the other one), nothing more offered
    h.advance(15);
    let r = h.post("/api/heartbeat", json!({"id": "990000777", "uuid": UUID, "hte_pw": 1})).await;
    assert_eq!(r.body, "{}");
    assert_eq!(h.one::<i64>("select confirmed_version from hte_device_passwords"), 1);
    assert_eq!(h.one::<String>("select confirmed_at from hte_device_passwords"), h.ts());
    let book: String = h.one("select password_enc from address_book_entries where address_book_id = 40");
    assert_eq!(h.native.crypt.decrypt_string(book.as_bytes()).unwrap(), pw.as_bytes());
    assert!(h.one::<Option<String>>("select password_enc from address_book_entries where address_book_id = 41").is_none());
}

#[tokio::test]
async fn sealed_password_needs_a_known_usable_key() {
    let h = harness().await;
    h.device("990000888", UUID, Some("no-key"));
    h.device("990000666", UUID, Some("bad-key"));
    h.sql("insert into settings (key, value) values ('hte_pw_enabled', '1')");
    // no key registered with hbbs: a password is issued but nothing can be sent
    assert_eq!(h.post("/api/heartbeat", json!({"id": "990000888", "uuid": UUID, "hte_pw": 0})).await.body, "{}");
    assert_eq!(h.one::<i64>("select current_version from hte_device_passwords"), 1);
    // a key libsodium cannot convert: the previous console's SodiumException, a 500
    let r = h.post("/api/heartbeat", json!({"id": "990000666", "uuid": UUID, "hte_pw": 0})).await;
    assert_eq!((r.status, r.json()), (500, json!({"message": "Server Error"})));
    // switched off: the device is still recorded as capable, but nothing is issued
    h.sql("update settings set value = '0'; delete from hte_device_passwords");
    assert_eq!(h.post("/api/heartbeat", json!({"id": "990000888", "uuid": UUID, "hte_pw": 0})).await.body, "{}");
    assert_eq!(h.one::<i64>("select current_version from hte_device_passwords"), 0);
}

#[tokio::test]
async fn sealed_password_pending_devices_and_missing_ciphertext() {
    let h = harness().await;
    h.device("990000777", UUID, Some("host-a"));
    h.sql("insert into settings (key, value) values ('hte_pw_enabled', '1'); update devices set status = 'pending'");
    // pending: recorded as capable, nothing issued or sent
    assert_eq!(h.post("/api/heartbeat", json!({"id": "990000777", "uuid": UUID, "hte_pw": 0})).await.body, "{}");
    assert_eq!(h.one::<i64>("select current_version from hte_device_passwords"), 0);
    assert_eq!(h.one::<String>("select capable_at from hte_device_passwords"), h.ts());
    // a version without its ciphertext: nothing to seal, nothing sent, nothing reissued
    h.sql("update devices set status = 'active'; update hte_device_passwords set current_version = 1, current_enc = null");
    h.advance(15);
    assert_eq!(h.post("/api/heartbeat", json!({"id": "990000777", "uuid": UUID, "hte_pw": 0})).await.body, "{}");
    assert_eq!(h.one::<i64>("select current_version from hte_device_passwords"), 1);
    // a ciphertext the app key cannot open: Crypt's DecryptException, a 500
    h.sql("update hte_device_passwords set current_enc = 'eyJpdiI6IiJ9'");
    let r = h.post("/api/heartbeat", json!({"id": "990000777", "uuid": UUID, "hte_pw": 0})).await;
    assert_eq!((r.status, r.json()), (500, json!({"message": "Server Error"})));
}

// --------------------------------------------------------------------------------------------- no panic ---

/// Random bytes and randomly typed fields straight into every handler (not through HTTP, where a panic would
/// only become a 500): nothing may panic, and every answer is one the previous console can give.
#[tokio::test]
async fn random_input_never_panics() {
    use hte_console::laravel::Input;
    use rand::{Rng, SeedableRng};
    let h = harness().await;
    h.device("990000001", UUID, None);
    h.device("990000777", UUID, Some("host"));
    h.sql("insert into settings (key, value) values ('hte_pw_enabled', '1')");
    strategy(&h, true, r#"{"direct-server":"N"}"#);
    let mut rng = rand::rngs::StdRng::seed_from_u64(20261024);
    let fields = ["id", "uuid", "conns", "modified_at", "hte_pw", "action", "conn_id", "session_id", "peer", "type", "note", "nonce", "info", "is_file", "typ", "ip", "hostname", "cpu", "path", "num"];
    let leaf = |rng: &mut rand::rngs::StdRng| -> Value {
        match rng.gen_range(0..9) {
            0 => Value::Null,
            1 => json!(rng.gen::<bool>()),
            2 => json!(rng.gen::<i64>()),
            3 => json!(rng.gen::<f64>() * 1e20),
            4 => json!(["990000001", 1, null]),
            5 => json!({"a": [1, {"b": "c"}]}),
            6 => json!(if rng.gen() { "990000001" } else { "990000777" }),
            7 => json!(" \u{200B}\u{0} new close "),
            _ => json!(u64::MAX),
        }
    };
    for round in 0..1500 {
        let body: Vec<u8> = if round % 3 == 0 {
            (0..rng.gen_range(0..64)).map(|_| rng.gen::<u8>()).collect()
        } else {
            let mut m = serde_json::Map::new();
            for f in fields {
                if rng.gen_bool(0.4) {
                    m.insert(f.into(), leaf(&mut rng));
                }
            }
            serde_json::to_vec(&Value::Object(m)).unwrap()
        };
        let ct = ["application/json", "application/x-www-form-urlencoded", "text/plain"][rng.gen_range(0..3)];
        let q = if rng.gen_bool(0.2) { Some("id[]=1&id[x]=2&conn_id=%FF&a.b=1") } else { None };
        let input = Input::new("POST", Some(ct), q, &body);
        let now = T0 + round;
        let conn = h.native.db.lock().unwrap();
        let replies = [
            hte_console::sync::heartbeat(&h.native, &conn, &input, "203.0.113.9", now),
            hte_console::sync::sysinfo(&h.native, &conn, &input, "203.0.113.9", now),
            hte_console::audit::connection(&h.native, &conn, &input, "203.0.113.9", now),
            hte_console::audit::file(&h.native, &conn, &input, "203.0.113.9", now),
            hte_console::audit::alarm(&h.native, &conn, &input, now),
        ];
        for r in replies {
            let status = match r {
                hte_console::api::Reply::Json(s, _) | hte_console::api::Reply::Text(s, _) => s,
            };
            assert!(status == 200 || status == 500, "round {round}: status {status}");
        }
    }
}

// ----------------------------------------------------------------------------------------------- replay ---

/// The replay runner against this service, with the synthetic fixtures (the previous console half of the comparison runs in
/// replay/replay.sh against a throwaway previous console).
#[tokio::test]
async fn synthetic_fixtures_replay_clean_against_the_native_service() {
    let h = harness().await;
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/synthetic");
    let s = hte_console::sanitise::Sanitiser::new(Some("any salt"), &[]);
    let report = hte_console::replay::run(&dir, &h.url, &s).await.unwrap();
    assert_eq!(report.skipped, 0);
    assert!(report.total >= 24, "{} fixtures", report.total);
    assert!(report.differences.is_empty(), "{:#?}", report.differences);
    // and the writes the fixtures imply
    assert_eq!(h.one::<String>("select hostname from devices where rustdesk_id = '990000001'"), "host-00000002");
    assert_eq!(h.count("devices where rustdesk_id = '990000005'"), 0);
    let row: (String, String, String) =
        h.db().query_row("select action, session_id, note from audit_connections where conn_id = 7001", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
    assert_eq!(row, ("close".into(), "18446744073709551615".into(), "text-00000008".into()));
    assert_eq!(h.count("audit_connections where conn_id = 7002"), 0, "the reused nonce wrote nothing");
    assert_eq!(h.count("audit_connections where conn_id = 7003"), 1, "the retry after the failed write did");
}
