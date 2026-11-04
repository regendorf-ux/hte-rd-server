//! Phase 3 end to end: the server link (policy with HTE Remote's scope, local addresses, refusals) on a real socket, and
//! the scheduled jobs (reach sweep, computer passwords and their books, stale sessions, the diagnostics heartbeat),
//! against a temporary database made from tests/schema.sql, tests/schema_phase3.sql and the replay's own seed
//! (fixtures/serverlink/*.sql: the world of tests/Hte/ReachTest's hteFixture()). Tests named like a Pest test in
//! tests/Hte/{ReachTest,PasswordsTest} carry its assertions (the console-page parts are phase 7's); the others pin
//! The previous console behaviour read from the source (v1.15.0-hte.1, Laravel 13.35), each named for what it pins.

use base64::Engine;
use hte_console::api::{router, Limiter, Native, Nonces};
use hte_console::cache::Store;
use hte_console::laravel::{self, Encrypter};
use hte_console::link::{self, Link};
use hte_console::sweeps::{self, Job, Scheduler};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sodiumoxide::crypto::{sealedbox, sign};
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

const APP_KEY: &str = "base64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const SECRET: &str = "tok-5eed00000003c0de";
const PREFIX: &str = "hte-remote-cache-";
const SEED: &str = include_str!("../fixtures/serverlink/0000000000003-serverlink-seed.sql");
const UUID_SERVER: &str = "UExBQ0VIT0xERVIhAAAD6g==";
const UUID_FRONT: &str = "UExBQ0VIT0xERVIhAAAD6Q==";

struct H {
    url: String,
    db_path: PathBuf,
    clock: Arc<AtomicI64>,
    client: reqwest::Client,
    native: Arc<Native>,
    store: Store,
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
    fn header(&self, h: &str) -> String {
        self.headers.get(h).map(|v| v.to_str().unwrap().to_string()).unwrap_or_default()
    }
}

/// The key pair hbbs holds for the server (990003002) and the front desk (990003001).
fn keypair(seed: u8) -> (sign::PublicKey, sign::SecretKey) {
    sign::keypair_from_seed(&sign::Seed([seed; 32]))
}

fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

async fn harness() -> H {
    harness_with(SECRET).await
}

async fn harness_with(secret: &str) -> H {
    sodiumoxide::init().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cortendesk.sqlite");
    let c = Connection::open(&db_path).unwrap();
    c.execute_batch(include_str!("schema.sql")).unwrap();
    c.execute_batch(include_str!("schema_phase3.sql")).unwrap();
    c.execute_batch(hte_console::path::SCHEMA).unwrap(); // the own migration, as the service has run it
    c.execute_batch(SEED).unwrap();
    drop(c);
    let hbbs = dir.path().join("db_v2.sqlite3");
    let h = Connection::open(&hbbs).unwrap();
    h.execute_batch("create table peer (guid blob, id varchar(100) not null, uuid blob, pk blob not null, info text)").unwrap();
    h.execute("insert into peer (id, pk) values ('990003002', ?)", params![keypair(2).0 .0.to_vec()]).unwrap();
    h.execute("insert into peer (id, pk) values ('990003001', ?)", params![keypair(1).0 .0.to_vec()]).unwrap();
    drop(h);
    // the seed writes datetime('now'): the clock starts at the real time
    let clock = Arc::new(AtomicI64::new(now_secs()));
    let ck = clock.clone();
    let native = Arc::new(Native {
        db: Mutex::new(hte_console::sqlite::open(&db_path, std::time::Duration::from_secs(5), true).unwrap()),
        crypt: Encrypter::from_app_key(APP_KEY).unwrap(),
        hbbs_db: hbbs,
        trusted: laravel::parse_trusted(laravel::DEFAULT_TRUSTED),
        api_version: "1.15.0-hte.1".into(),
        max_body: 1 << 20,
        limiter: Mutex::new(Limiter::default()),
        nonces: Mutex::new(Nonces::default()),
        signin: hte_console::signin::State::new(hte_console::oidc::Oidc::new(false, false), None, "HTE Remote".into()),
        clock: Box::new(move || ck.load(Ordering::SeqCst)),
    });
    let store = Store { prefix: PREFIX.into() };
    let l = Arc::new(Link::new(secret, store.clone()));
    let app = link::routes(native.clone(), l).merge(router(native.clone(), None)).into_make_service_with_connect_info::<std::net::SocketAddr>();
    let lis = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", lis.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(lis, app).await.unwrap() });
    H { url, db_path, clock, client: reqwest::Client::new(), native, store, _dir: dir }
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
    fn now(&self) -> i64 {
        self.clock.load(Ordering::SeqCst)
    }
    fn advance(&self, s: i64) {
        self.clock.fetch_add(s, Ordering::SeqCst);
    }
    async fn send(&self, method: &str, path: &str, auth: Option<&str>, headers: &[(&str, &str)], body: Option<Value>) -> Resp {
        let mut rq = self.client.request(method.parse().unwrap(), format!("{}{}", self.url, path)).header("x-forwarded-for", "198.18.3.1");
        if let Some(a) = auth {
            rq = rq.header("authorization", format!("Bearer {a}"));
        }
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
    async fn policy(&self) -> Resp {
        self.send("GET", "/api/server/policy", Some(SECRET), &[("user-agent", "cortendesk-server/1.1.1-hte.2")], None).await
    }
    async fn post(&self, path: &str, body: Value) -> Resp {
        self.send("POST", path, Some(SECRET), &[], Some(body)).await
    }
    async fn beat(&self, id: &str, uuid: &str, held: Option<i64>) -> Value {
        let mut b = json!({"id": id, "uuid": uuid});
        if let Some(h) = held {
            b["hte_pw"] = json!(h);
        }
        let r = self.send("POST", "/api/heartbeat", None, &[], Some(b)).await;
        assert_eq!(r.status, 200, "{}", r.body);
        r.json()
    }
    fn sweep(&self, jobs: &[Job]) -> Vec<String> {
        sweeps::once(&self.native, &self.store, jobs).unwrap()
    }
    fn session(&self, from: &str, to: &str, conn: i64) {
        self.db()
            .execute(
                "insert into audit_connections (action, conn_id, rustdesk_id, from_peer, from_name, conn_type, session_id, uuid, ip, guid, created_at, updated_at)
                 values ('authorized', ?, ?, ?, 'test', 0, 'sess', 'u', '198.18.3.5', ?, ?, ?)",
                params![conn, to, from, format!("00000000-0000-4000-8000-{:012}", conn), laravel::ts(self.now()), laravel::ts(self.now())],
            )
            .unwrap();
    }
    fn disconnect_requested(&self, conn: i64) -> bool {
        self.one::<Option<String>>(&format!("select disconnect_requested_at from audit_connections where conn_id = {conn}")).is_some()
    }
    fn enc(&self, plain: &str) -> String {
        self.native.crypt.encrypt_string(plain.as_bytes())
    }
    fn dec(&self, enc: &str) -> String {
        String::from_utf8(self.native.crypt.decrypt_string(enc.as_bytes()).unwrap()).unwrap()
    }
    fn book_of(&self, user: i64) -> i64 {
        self.one(&format!("select address_book_id from hte_auto_books where user_id = {user}"))
    }
    fn book_ids(&self, user: i64) -> Vec<String> {
        let c = self.db();
        let mut st = c.prepare(&format!("select rustdesk_id from address_book_entries where address_book_id = {} order by rustdesk_id", self.book_of(user))).unwrap();
        let rows = st.query_map([], |r| r.get::<_, String>(0)).unwrap();
        rows.map(Result::unwrap).collect()
    }
}

fn sha256(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

fn open_box(b64: &str, seed: u8) -> Value {
    let (pk, sk) = keypair(seed);
    let sealed = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
    serde_json::from_slice(&sealedbox::open(&sealed, &sign::to_curve25519_pk(&pk).unwrap(), &sign::to_curve25519_sk(&sk).unwrap()).unwrap()).unwrap()
}

// ------------------------------------------------------------------------------------ ReachTest: policy ---

#[tokio::test]
async fn the_policy_carries_no_scope_while_the_setting_is_off() {
    let h = harness().await;
    h.sql("update settings set value = '0' where key = 'hte_scope_enforce'");
    let r = h.policy().await;
    assert_eq!(r.status, 200);
    assert!(r.body.ends_with(r#","scope":{"enforce":false,"users":{},"token_users":{}}}"#), "{}", r.body);
}

#[tokio::test]
async fn the_policy_maps_every_active_person_to_the_devices_they_see() {
    let h = harness().await;
    let r = h.policy().await;
    let p = r.json();
    let users = &p["scope"]["users"];
    assert_eq!(p["scope"]["enforce"], json!(true));
    assert_eq!(users["930001"], json!({"name": "user-5eed3001", "all": true, "devices": []}));
    // owner of the front desk, nothing else
    assert_eq!(users["930002"], json!({"name": "user-5eed3002", "all": false, "devices": ["990003001"]}));
    // the user group holds the device group: the front desk and the server, not the pending laptop
    assert_eq!(users["930003"]["devices"], json!(["990003001", "990003002"]));
    assert_eq!(users["930004"]["devices"], json!([]));
    assert_eq!(p["scope"]["token_users"][sha256("tok-5eed00000003a002")], json!("930002"));
    assert_eq!(p["scope"]["token_users"][sha256("tok-5eed00000003a001")], json!("930001"));
    // the whole answer, as the previous console encodes it: approved devices by id, tokens by hash (ksort), each live once
    let mut tokens: Vec<(String, &str)> = ["a001", "a002", "a003", "a004"].iter().map(|t| (sha256(&format!("tok-5eed00000003{t}")), "990003004")).collect();
    tokens.sort();
    let tok_json: Vec<String> = tokens.iter().map(|(k, v)| format!(r#""{k}":"{v}""#)).collect();
    let mut tu: Vec<(String, String)> = (1..=4).map(|i| (sha256(&format!("tok-5eed00000003a00{i}")), format!("93000{i}"))).collect();
    tu.sort();
    let tu_json: Vec<String> = tu.iter().map(|(k, v)| format!(r#""{k}":"{v}""#)).collect();
    let want = format!(
        concat!(
            r#"{{"mode":"open","allow":["990003002","990003004"],"incoming_only":["990003001"],"tokens":{{{}}},"ip_match":false,"#,
            r#""scope":{{"enforce":true,"users":{{"930001":{{"name":"user-5eed3001","all":true,"devices":[]}},"#,
            r#""930002":{{"name":"user-5eed3002","all":false,"devices":["990003001"]}},"#,
            r#""930003":{{"name":"user-5eed3003","all":false,"devices":["990003001","990003002"]}},"#,
            r#""930004":{{"name":"user-5eed3004","all":false,"devices":[]}}}},"token_users":{{{}}}}}}}"#
        ),
        tok_json.join(","),
        tu_json.join(",")
    );
    assert_eq!(r.body, want);
    assert_eq!(r.ct, "application/json");
}

#[tokio::test]
async fn a_disabled_person_and_an_expired_token_drop_out_of_the_scope() {
    let h = harness().await;
    h.sql("update users set is_active = 0 where id = 930004");
    h.sql(&format!("update client_tokens set expires_at = '{}' where token = 'tok-5eed00000003a003'", laravel::ts(h.now() - 60)));
    let p = h.policy().await.json();
    assert!(p["scope"]["users"].get("930004").is_none());
    let tu = &p["scope"]["token_users"];
    assert!(tu.get(sha256("tok-5eed00000003a004")).is_none());
    assert!(tu.get(sha256("tok-5eed00000003a003")).is_none());
    assert!(tu.get(sha256("tok-5eed00000003a002")).is_some());
    // the device half of the policy keeps every live token, a disabled person's included
    assert!(p["tokens"].get(sha256("tok-5eed00000003a004")).is_some());
    assert!(p["tokens"].get(sha256("tok-5eed00000003a0e0")).is_none(), "an expired token");
}

#[tokio::test]
async fn the_device_page_lists_who_can_reach_it_and_how() {
    // The page's sections are phase 7's; the people in them are what the sweep uses (Passwords::reachIds).
    let h = harness().await;
    let device = |id: &str| hte_console::sqlite::first(&h.native.db.lock().unwrap(), "select * from devices where rustdesk_id = ?", &[hte_console::sqlite::P(hte_console::php::Val::str(id))]).unwrap().unwrap();
    let ids = |id: &str| {
        let d = device(id);
        hte_console::reach::reach_ids(&h.native.db.lock().unwrap(), &d).unwrap()
    };
    assert_eq!(ids("990003001"), vec![930001, 930002, 930003]);
    assert_eq!(ids("990003002"), vec![930001, 930003]);
    // a person is counted once: the owner granted the group directly too
    h.sql("insert into device_group_user (device_group_id, user_id) values (930101, 930002)");
    assert_eq!(ids("990003001"), vec![930001, 930002, 930003]);
    assert_eq!(ids("990003002"), vec![930001, 930002, 930003]);
    // a disabled administrator is not listed; group access through a user group is
    h.sql("update users set is_active = 0 where id = 930001; insert into user_groups (id, name) values (930299, 'g'); insert into user_group_user (user_group_id, user_id) values (930299, 930004); insert into group_accesses (accessor_type, accessor_id, target_type, target_id) values ('user_group', 930299, 'device_group', 930101)");
    assert_eq!(ids("990003002"), vec![930002, 930003, 930004]);
}

#[tokio::test]
async fn hbbs_reports_a_refusal_and_the_console_keeps_it_as_an_admin_only_alarm() {
    let h = harness().await;
    let r = h
        .post(
            "/api/server/refusals",
            json!({"refusals": [{"user_id": "930004", "user_name": "user-5eed3004", "from": "990003004", "to": "990003001", "ip": "198.18.3.9", "reason": "outside scope", "at": h.now()}]}),
        )
        .await;
    assert_eq!((r.status, r.body.as_str()), (200, r#"{"recorded":1}"#));
    let (rid, typ, info): (String, i64, String) = h.db().query_row("select rustdesk_id, typ, info from alarm_logs order by id desc limit 1", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
    assert_eq!((rid.as_str(), typ), ("console", 102));
    assert_eq!(
        info,
        r#"{"user":"user-5eed3004","user_id":"930004","from":"990003004","from_name":"host-5eed3004","to":"990003001","to_name":"host-5eed3001","ip":"198.18.3.9","reason":"outside scope"}"#
    );
    let r = h.send("POST", "/api/server/refusals", Some("wrong"), &[], Some(json!({"refusals": []}))).await;
    assert_eq!((r.status, r.json()), (401, json!({"error": "Invalid server secret."})));
}

#[tokio::test]
async fn a_regular_person_does_not_get_the_card_and_cannot_post_refusals() {
    // the card is phase 7's; a client token is no server secret
    let h = harness().await;
    let r = h.send("POST", "/api/server/refusals", Some("tok-5eed00000003a002"), &[], Some(json!({"refusals": [{"to": "990003001"}]}))).await;
    assert_eq!(r.status, 401);
    assert_eq!(h.count("alarm_logs"), 0);
}

// ------------------------------------------------------------------------------------- ReachTest: sweep ---

#[tokio::test]
async fn the_sweep_does_nothing_while_enforcement_is_off() {
    let h = harness().await;
    h.sql("update settings set value = '0' where key = 'hte_scope_enforce'");
    h.session("990003004", "990003002", 1);
    // only 930004 is signed in on the Mac and may not reach the server
    h.sql("delete from client_tokens where user_id <> 930004");
    assert_eq!(h.sweep(&[Job::Reach]), vec!["reach: closed 0"]);
    assert!(!h.disconnect_requested(1));
}

#[tokio::test]
async fn a_session_stays_while_someone_signed_in_there_may_reach_the_device() {
    let h = harness().await;
    // every person is signed in on the Mac, the administrator among them
    h.session("990003004", "990003002", 1);
    h.sweep(&[Job::Reach]);
    assert!(!h.disconnect_requested(1));
    // only the group member left there: their user group still holds the device group
    h.sql("delete from client_tokens where user_id <> 930003");
    h.sweep(&[Job::Reach]);
    assert!(!h.disconnect_requested(1));
}

#[tokio::test]
async fn a_removed_grant_closes_the_session_and_leaves_an_alarm() {
    let h = harness().await;
    h.sql("delete from client_tokens where user_id <> 930003");
    h.session("990003004", "990003002", 7);
    h.sql("delete from user_group_user where user_id = 930003");
    assert_eq!(h.sweep(&[Job::Reach]), vec!["reach: closed 1"]);
    assert!(h.disconnect_requested(7));
    assert!(h.one::<Option<i64>>("select disconnect_requested_by from audit_connections where conn_id = 7").is_none());
    // the console's own disconnect: the server is told at its next check-in (AuditConnection::pendingDisconnectsFor)
    assert_eq!(h.beat("990003002", UUID_SERVER, None).await, json!({"disconnect": [7]}));
    let (typ, conn, info): (i64, i64, String) = h.db().query_row("select typ, conn_id, info from alarm_logs where typ = 103", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
    assert_eq!((typ, conn), (103, 7));
    assert_eq!(info, r#"{"from":"990003004","to":"990003002","reason":"user-5eed3003 may no longer reach 990003002"}"#);
    let (who, action, summary, tt, tid): (String, String, String, String, String) = h
        .db()
        .query_row("select username, action, summary, target_type, target_id from console_audits", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
        .unwrap();
    assert_eq!((who.as_str(), action.as_str(), tt.as_str(), tid.as_str()), ("system", "session.disconnect", "device", "990003002"));
    assert_eq!(summary, "Closed session 7 from 990003004 on 990003002: user-5eed3003 may no longer reach 990003002");
    // asked once: a second sweep does not ask again
    h.sweep(&[Job::Reach]);
    assert_eq!(h.count("alarm_logs where typ = 103"), 1);
}

#[tokio::test]
async fn a_disabled_or_signed_out_person_loses_the_session_the_web_client_is_left_alone() {
    let h = harness().await;
    h.sql("delete from client_tokens where user_id <> 930002");
    h.session("990003004", "990003001", 1);
    h.session("web-8f3a", "990003001", 2);
    h.sweep(&[Job::Reach]);
    assert!(!h.disconnect_requested(1));
    h.sql("update users set is_active = 0 where id = 930002");
    h.sweep(&[Job::Reach]);
    assert!(h.disconnect_requested(1));
    assert!(!h.disconnect_requested(2));
    let verdict = |conn: i64| {
        h.session("990003004", "990003001", conn);
        let c = h.native.db.lock().unwrap();
        let s = hte_console::sqlite::first(&c, "select * from audit_connections where conn_id = ?", &[hte_console::sqlite::P(hte_console::php::Val::Int(conn))]).unwrap().unwrap();
        hte_console::reach::verdict(&c, &s, h.now()).unwrap()
    };
    assert_eq!(verdict(3).as_deref(), Some("the person signed in on 990003004 is disabled"));
    h.sql("delete from client_tokens");
    assert_eq!(verdict(4).as_deref(), Some("nobody is signed in on 990003004"));
}

#[tokio::test]
async fn the_sweep_is_scheduled() {
    // every 15 s under the previous console's own lock: the previous console's scheduler skips the task while hte-console holds it
    let h = harness().await;
    std::env::set_var("HTE_CONSOLE_SWEEPS", "reach, stale");
    assert_eq!(sweeps::from_env().unwrap(), vec![Job::Reach, Job::Stale]);
    std::env::set_var("HTE_CONSOLE_SWEEPS", "all");
    assert_eq!(sweeps::from_env().unwrap().len(), 4);
    std::env::set_var("HTE_CONSOLE_SWEEPS", "reach,nope");
    assert!(sweeps::from_env().is_err());
    std::env::remove_var("HTE_CONSOLE_SWEEPS");
    assert!(sweeps::from_env().unwrap().is_empty(), "none unless asked");

    // the lock name the previous console's scheduler uses for `Schedule::command(ReachSweep::class)->everyFifteenSeconds()`
    let key = format!("{PREFIX}framework/schedule-{}", hex::encode(<sha1::Sha1 as sha1::Digest>::digest(b"* * * * *php artisan hte:reach-sweep")));
    assert_eq!(format!("{PREFIX}{}", Job::Reach.mutex_name()), key);

    h.sql("delete from client_tokens where user_id <> 930004");
    h.session("990003004", "990003002", 1);
    // The previous console's scheduler is mid-run: hte-console skips this tick
    h.sql(&format!("insert into cache_locks (key, owner, expiration) values ('{key}', 'PhPsCheDuLeR0001', {})", h.now() + 60));
    let s = Scheduler::new(h.native.clone(), h.store.clone(), vec![Job::Reach]);
    s.tick(Job::Reach);
    assert!(!h.disconnect_requested(1));
    // The previous console finished (forceRelease): the next tick takes the lock, runs, and keeps it
    h.sql("delete from cache_locks");
    s.tick(Job::Reach);
    assert!(h.disconnect_requested(1));
    let (owner, exp): (String, i64) = h.db().query_row("select owner, expiration from cache_locks where key = ?", [&key], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    assert!(owner.starts_with("hte-console-"));
    assert_eq!(exp, h.now() + 60, "the scheduler's withoutOverlapping(1)");
    // what the previous console's scheduler would try now: the insert fails, the take-over matches nothing (not its owner, not expired)
    let taken = h.db().execute("update cache_locks set owner = 'x', expiration = 0 where key = ?1 and (owner = 'x' or expiration <= ?2)", params![key, h.now()]).unwrap();
    assert_eq!(taken, 0);
    // a clean stop gives it back
    s.release_all();
    assert_eq!(h.count("cache_locks"), 0);
}

// ---------------------------------------------------------------------------------------- PasswordsTest ---

fn confirmed(h: &H, id: &str, pw: &str) {
    let e = h.enc(pw);
    h.sql(&format!(
        "insert into hte_device_passwords (rustdesk_id, capable_at, current_version, current_enc, confirmed_version, confirmed_enc, confirmed_at, created_at, updated_at)
         values ('{id}', '{t}', 1, '{e}', 1, '{e}', '{t}', '{t}', '{t}')",
        t = laravel::ts(h.now())
    ));
}

#[tokio::test]
async fn each_person_gets_one_hte_remote_book_with_exactly_the_computers_they_may_reach() {
    let h = harness().await;
    h.sql("insert into settings (key, value) values ('hte_pw_enabled', '1')");
    confirmed(&h, "990003001", "tok-5eed00000003f001");
    confirmed(&h, "990003002", "tok-5eed00000003f002");
    h.sweep(&[Job::Passwords]);
    assert_eq!(h.book_ids(930002), vec!["990003001"]);
    assert_eq!(h.book_ids(930003), vec!["990003001", "990003002"]);
    assert!(h.book_ids(930004).is_empty());
    assert_eq!(h.book_ids(930001), vec!["990003001", "990003002", "990003004"]);
    let front: String = h.one(&format!("select password_enc from address_book_entries where address_book_id = {} and rustdesk_id = '990003001'", h.book_of(930002)));
    assert_eq!(h.dec(&front), "tok-5eed00000003f001");
    // the Mac never checked in as able: listed, without a password
    assert!(h.one::<Option<String>>(&format!("select password_enc from address_book_entries where address_book_id = {} and rustdesk_id = '990003004'", h.book_of(930001))).is_none());
    // one book per person, named and owned as the previous console makes it, readable by that person alone
    let (name, owner, personal, note): (String, i64, i64, String) =
        h.db().query_row(&format!("select name, owner_user_id, is_personal, note from address_books where id = {}", h.book_of(930003)), [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).unwrap();
    assert_eq!((name.as_str(), owner, personal), ("HTE Remote", 930001, 0));
    assert!(note.starts_with("Automatic (HTE)"));
    assert_eq!(h.count("address_books"), 4);
    let rule: (String, i64, i64) = h.db().query_row(&format!("select subject_type, subject_id, permission from address_book_rules where address_book_id = {}", h.book_of(930003)), [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
    assert_eq!(rule, ("user".into(), 930003, 1));
    let entry: (String, String, String, String) = h
        .db()
        .query_row(&format!("select alias, hostname, platform, coalesce(username, '') from address_book_entries where address_book_id = {} and rustdesk_id = '990003004'", h.book_of(930001)), [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap();
    assert_eq!(entry, ("host-5eed3004".into(), "host-5eed3004".into(), "Mac OS".into(), "".into()));
    // a second sweep writes nothing; a disabled person's book is emptied
    assert_eq!(h.sweep(&[Job::Passwords]), vec!["passwords: issued 0, book entries written 0"]);
    h.sql("update users set is_active = 0 where id = 930003");
    h.sweep(&[Job::Passwords]);
    assert_eq!(h.count(&format!("address_book_entries where address_book_id = {}", h.book_of(930003))), 0);
    assert_eq!(h.count(&format!("address_book_rules where address_book_id = {}", h.book_of(930003))), 0);
}

#[tokio::test]
async fn losing_access_changes_the_password_the_book_follows_once_the_computer_confirms() {
    let h = harness().await;
    h.sql("insert into settings (key, value) values ('hte_pw_enabled', '1')");
    let r = h.beat("990003002", UUID_SERVER, Some(0)).await;
    assert_eq!(r["hte_password"]["v"], json!(1));
    h.advance(15);
    h.beat("990003002", UUID_SERVER, Some(1)).await;
    h.sweep(&[Job::Passwords]);
    let first = h.dec(&h.one::<String>("select confirmed_enc from hte_device_passwords where rustdesk_id = '990003002'"));

    // the group member leaves the user group: they lose the server, and its password changes
    h.sql("delete from user_group_user where user_id = 930003");
    h.advance(60);
    assert_eq!(h.sweep(&[Job::Passwords]), vec!["passwords: issued 1, book entries written 0"]);
    assert_eq!(h.one::<i64>("select current_version from hte_device_passwords where rustdesk_id = '990003002'"), 2);
    assert_eq!(h.one::<String>("select issued_reason from hte_device_passwords where rustdesk_id = '990003002'"), "access removed (user-5eed3003)");
    let summary: String = h.one("select summary from console_audits where action = 'hte.password'");
    assert_eq!(summary, "New password for 990003002: access removed (user-5eed3003)");

    // until the computer confirms, the books keep the old one (it still works there)
    let entry = || h.dec(&h.one::<String>(&format!("select password_enc from address_book_entries where address_book_id = {} and rustdesk_id = '990003002'", h.book_of(930001))));
    assert_eq!(entry(), first);
    h.advance(15);
    let r = h.beat("990003002", UUID_SERVER, Some(1)).await;
    let second = open_box(r["hte_password"]["box"].as_str().unwrap(), 2)["pw"].as_str().unwrap().to_string();
    h.advance(15);
    h.beat("990003002", UUID_SERVER, Some(2)).await;
    assert_eq!(entry(), second);
    assert_ne!(second, first);
    // nothing else lost: no new password on the next sweep
    h.advance(60);
    assert_eq!(h.sweep(&[Job::Passwords]), vec!["passwords: issued 0, book entries written 0"]);
}

#[tokio::test]
async fn a_password_older_than_the_schedule_is_changed() {
    let h = harness().await;
    h.sql("insert into settings (key, value) values ('hte_pw_enabled', '1'), ('hte_pw_days', '7')");
    h.beat("990003002", UUID_SERVER, Some(0)).await;
    h.beat("990003002", UUID_SERVER, Some(1)).await;
    h.sweep(&[Job::Passwords]);
    h.sql(&format!("update hte_device_passwords set confirmed_at = '{}'", laravel::ts(h.now() - 8 * 86_400)));
    assert_eq!(h.sweep(&[Job::Passwords])[0], "passwords: issued 1, book entries written 0");
    assert_eq!(h.one::<String>("select issued_reason from hte_device_passwords"), "every 7 days");
    h.sql("update settings set value = '0' where key = 'hte_pw_days'");
    h.sql(&format!("update hte_device_passwords set confirmed_version = 2, confirmed_at = '{}'", laravel::ts(h.now() - 400 * 86_400)));
    assert!(h.sweep(&[Job::Passwords])[0].starts_with("passwords: issued 0"));
    // a pending one is never replaced, and the switch off stops everything
    h.sql("update settings set value = '0' where key = 'hte_pw_enabled'; update hte_device_passwords set reach_user_ids = '[930001,930002,930003,930004]'");
    assert_eq!(h.sweep(&[Job::Passwords])[0], "passwords: issued 0, book entries written 0");
}

#[tokio::test]
async fn a_long_access_removed_reason_is_cut_like_str_limit() {
    // issued_reason is Str::limit($reason, 60, ''): every name of a long list does not fit
    let h = harness().await;
    h.sql("insert into settings (key, value) values ('hte_pw_enabled', '1')");
    confirmed(&h, "990003002", "tok-5eed00000003f002");
    h.sql("insert into users (id, username, password, is_admin, is_active) values (930005, 'user-5eed3005', 'x', 0, 1)");
    h.sql("insert into user_group_user (user_group_id, user_id) values (930201, 930002), (930201, 930004), (930201, 930005)");
    h.sweep(&[Job::Passwords]);
    h.sql("delete from user_group_user");
    h.sweep(&[Job::Passwords]);
    let reason: String = h.one("select issued_reason from hte_device_passwords where rustdesk_id = '990003002'");
    // the first 60 characters end on ", " before the fourth name: rtrim takes the space
    assert_eq!(reason, "access removed (user-5eed3002, user-5eed3003, user-5eed3004,");
    // the log line keeps all of it (Str::limit 250)
    let summary: String = h.one("select summary from console_audits where action = 'hte.password'");
    assert!(summary.ends_with("access removed (user-5eed3002, user-5eed3003, user-5eed3004, user-5eed3005)"), "{summary}");
}

// --------------------------------------------------------------------------------------------- server link ---

#[tokio::test]
async fn the_server_link_is_404_while_unlinked_and_401_for_a_wrong_secret() {
    let h = harness_with("").await;
    for (m, p) in [("GET", "/api/server/policy"), ("POST", "/api/server/local-addrs"), ("POST", "/api/server/refusals")] {
        let r = h.send(m, p, Some(SECRET), &[], None).await;
        assert_eq!((r.status, r.json()), (404, json!({"error": "Server link is not configured."})), "{p}");
        assert_eq!(r.header("access-control-allow-origin"), "*");
    }
    let h = harness().await;
    for auth in [None, Some("tok-5eed00000003c0dd"), Some("")] {
        let r = h.send("GET", "/api/server/policy", auth, &[], None).await;
        assert_eq!((r.status, r.json()), (401, json!({"error": "Invalid server secret."})));
        assert_eq!(r.header("x-ratelimit-limit"), "", "the secret is checked before the limiter");
    }
}

#[tokio::test]
async fn the_policy_is_etagged_and_every_pull_is_recorded() {
    let h = harness().await;
    let r = h.policy().await;
    let etag = r.header("etag");
    assert_eq!(etag, format!("\"{}\"", sha256(&r.body)));
    assert_eq!((r.header("x-ratelimit-limit").as_str(), r.header("x-ratelimit-remaining").as_str()), ("600", "599"));
    assert_eq!(r.header("cache-control"), "no-cache, private");
    // the pull, in Laravel's database cache as Cache::forever writes it
    let (value, exp): (String, i64) = h
        .db()
        .query_row(&format!("select value, expiration from cache where key = '{PREFIX}cortendesk:server-link:last-pull'"), [], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap();
    let at = chrono::DateTime::from_timestamp(h.now(), 0).unwrap().format("%Y-%m-%dT%H:%M:%S+00:00").to_string();
    assert_eq!(value, format!(r#"a:2:{{s:2:"at";s:25:"{at}";s:5:"agent";s:29:"cortendesk-server/1.1.1-hte.2";}}"#));
    assert_eq!(exp, h.now() + 315_360_000);
    // unchanged: 304, no body, no type; the pull is still recorded
    h.advance(5);
    let r = h.send("GET", "/api/server/policy", Some(SECRET), &[("if-none-match", &etag), ("user-agent", "x")], None).await;
    assert_eq!((r.status, r.body.as_str(), r.ct.as_str()), (304, "", ""));
    assert_eq!(r.header("etag"), etag);
    assert_eq!(r.header("x-ratelimit-remaining"), "598");
    assert!(h.one::<String>(&format!("select value from cache where key = '{PREFIX}cortendesk:server-link:last-pull'")).ends_with(r#"s:5:"agent";s:1:"x";}"#));
    // changed: the full policy and a new tag
    h.sql("update devices set can_initiate = 1 where rustdesk_id = '990003001'");
    let r = h.send("GET", "/api/server/policy", Some(SECRET), &[("if-none-match", &etag)], None).await;
    assert_eq!(r.status, 200);
    assert_ne!(r.header("etag"), etag);
    assert!(r.body.contains(r#""allow":["990003001","990003002","990003004"],"incoming_only":[]"#));
    // HEAD: headers only; POST: 405 (the router, before the secret)
    let r = h.send("HEAD", "/api/server/policy", Some(SECRET), &[], None).await;
    assert_eq!((r.status, r.body.as_str(), r.ct.as_str()), (200, "", "application/json"));
    let r = h.send("POST", "/api/server/policy", None, &[], None).await;
    assert_eq!(r.status, 405);
    assert_eq!(r.header("allow"), "GET, HEAD");
    // approved-only mode and ip matching come from the settings
    h.sql("insert into settings (key, value) values ('server_access_mode', 'approved'), ('server_ip_match', '1')");
    let p = h.policy().await.json();
    assert_eq!((p["mode"].clone(), p["ip_match"].clone()), (json!("approved"), json!(true)));
}

#[tokio::test]
async fn local_addresses_are_kept_newest_first_and_never_rolled_back() {
    let h = harness().await;
    let lan = |id: &str| h.one::<Option<String>>(&format!("select lan_ip from devices where rustdesk_id = '{id}'"));
    let seen = |id: &str| h.one::<Option<String>>(&format!("select lan_ip_seen_at from devices where rustdesk_id = '{id}'"));
    let r = h.post("/api/server/local-addrs", json!({"addrs": [{"id": "990003001", "ip": "198.18.3.21", "seen_at": 1_700_000_000}]})).await;
    assert_eq!(r.body, r#"{"updated":1}"#);
    assert_eq!((lan("990003001").as_deref(), seen("990003001").as_deref()), (Some("198.18.3.21"), Some("2023-11-14 22:13:20")));
    let r = h.post("/api/server/local-addrs", json!({"addrs": [{"id": "990003001", "ip": "198.18.3.22", "seen_at": 1_690_000_000}]})).await;
    assert_eq!(r.body, r#"{"updated":0}"#);
    assert_eq!(lan("990003001").as_deref(), Some("198.18.3.21"));
    // unknown and trashed devices are skipped, a pending one is not; the future is now
    h.sql("update devices set deleted_at = '2026-01-01 00:00:00' where rustdesk_id = '990003004'");
    let r = h
        .post(
            "/api/server/local-addrs",
            json!({"addrs": [{"id": "990003999", "ip": "198.18.3.30"}, {"id": "990003004", "ip": "198.18.3.31"}, {"id": "990003003", "ip": "2001:db8::3:31", "seen_at": 4_102_444_800i64}]}),
        )
        .await;
    assert_eq!(r.body, r#"{"updated":1}"#);
    assert_eq!(seen("990003003"), Some(laravel::ts(h.now())));
    assert!(lan("990003004").is_none());
    // an unchanged address costs no write (Eloquent saves only what changed)
    let before: String = h.one("select updated_at from devices where rustdesk_id = '990003001'");
    h.advance(10);
    let r = h.post("/api/server/local-addrs", json!({"addrs": [{"id": "990003001", "ip": "198.18.3.21", "seen_at": 1_700_000_000}]})).await;
    assert_eq!(r.body, r#"{"updated":1}"#, "counted all the same");
    assert_eq!(h.one::<String>("select updated_at from devices where rustdesk_id = '990003001'"), before);
    // an entry that escapes the wildcard rules (a key with a dot) reaches the controller: the previous console's warning, a 500
    let r = h.post("/api/server/local-addrs", json!({"addrs": {"a.b": {"ip": "198.18.3.1"}}})).await;
    assert_eq!((r.status, r.json()), (500, json!({"message": "Server Error"})));
}

/// HTE: connection paths. A device echoes hbbs's tag in its audit; hbbr reports the sessions it carried; the one it carried is linked.
#[tokio::test]
async fn a_session_is_told_apart_by_its_tag_and_by_the_relay_s_report() {
    let h = harness().await;
    let path = |conn: i64| h.one::<Option<String>>(&format!("select path from audit_connections where conn_id = {conn}"));
    let relay = |conn: i64| h.one::<Option<i64>>(&format!("select relay_session_id from audit_connections where conn_id = {conn}"));
    let audit = |body: Value| {
        let h = &h;
        async move {
            let r = h.send("POST", "/api/audit/conn", None, &[], Some(body)).await;
            assert_eq!(r.status, 200, "{}", r.body);
        }
    };
    // the tag of a 1.5 device is kept; a tag that is not ours, or none, leaves the path empty
    audit(json!({"action": "new", "id": "990003001", "conn_id": 801, "ip": "198.18.3.5", "session_id": 0, "uuid": "u", "conn_audit_ref": "cd1/punch"})).await;
    audit(json!({"action": "new", "id": "990003001", "conn_id": 802, "ip": "198.18.3.5", "session_id": 0, "uuid": "u", "conn_audit_ref": "elsewhere/punch"})).await;
    audit(json!({"action": "new", "id": "990003001", "conn_id": 803, "ip": "198.18.3.5", "session_id": 0, "uuid": "u"})).await;
    assert_eq!((path(801).as_deref(), path(802), path(803)), (Some("punch"), None, None));
    // the attempt that logs in; the relay reports a session for that device while it is open
    audit(json!({"id": "990003001", "conn_id": 801, "type": 0, "peer": ["990003002", "Front"], "session_id": 0, "uuid": "u"})).await;
    let started = h.now();
    let r = h.post("/api/server/relay-sessions", json!({"sessions": [{"uuid": "r-1", "id": "990003001", "conn_type": 0, "controller_ip": "198.18.3.7", "device_ip": "198.18.3.5", "started_at": started}]})).await;
    assert_eq!((r.status, r.body.as_str()), (200, r#"{"stored":1}"#));
    assert_eq!(relay(801), Some(1), "the row that logged in, though the tag said punch: the relay report wins");
    assert_eq!((relay(802), relay(803)), (None, None));
    // closed, with its size; a late copy of the open does not undo the close
    h.advance(60);
    h.post("/api/server/relay-sessions", json!({"sessions": [{"uuid": "r-1", "id": "990003001", "ended_at": h.now(), "bytes": 5_000_000}]})).await;
    h.post("/api/server/relay-sessions", json!({"sessions": [{"uuid": "r-1", "id": "990003001", "started_at": started}]})).await;
    let (ended, bytes): (Option<String>, i64) = h.db().query_row("select ended_at, bytes from relay_sessions where uuid = 'r-1'", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    assert_eq!((ended.is_some(), bytes), (true, 5_000_000));
    assert_eq!(h.count("relay_sessions"), 1);
    assert_eq!(relay(801), Some(1));
    // a malformed report is a 422 and stores nothing
    let r = h.post("/api/server/relay-sessions", json!({"sessions": [{"id": "990003001"}, {"uuid": "r-2", "id": "x", "device_ip": "not an address"}]})).await;
    assert_eq!(r.status, 422);
    assert_eq!(h.count("relay_sessions"), 1);
}

#[tokio::test]
async fn the_server_link_limit_is_600_a_minute_shared_by_its_routes() {
    let h = harness().await;
    for i in 0..600 {
        let r = if i % 2 == 0 { h.policy().await } else { h.post("/api/server/refusals", json!({})).await };
        assert!(r.status == 200 || r.status == 422, "{}", r.status);
    }
    let r = h.post("/api/server/local-addrs", json!({})).await;
    assert_eq!((r.status, r.json()), (429, json!({"message": "Too Many Attempts."})));
    assert_eq!((r.header("x-ratelimit-remaining").as_str(), r.header("retry-after").is_empty()), ("0", false));
    h.advance(61);
    assert_eq!(h.policy().await.status, 200);
}

#[tokio::test]
async fn bad_bodies_get_laravels_422_and_never_a_panic() {
    let h = harness().await;
    let r = h.post("/api/server/refusals", json!({"refusals": [{"user_name": "x"}, {"to": ["990003001"]}]})).await;
    assert_eq!(r.status, 422);
    assert_eq!(
        r.json(),
        json!({"message": "The refusals.0.to field is required. (and 1 more error)", "errors": {"refusals.0.to": ["The refusals.0.to field is required."], "refusals.1.to": ["The refusals.1.to field must be a string."]}})
    );
    let r = h.send("POST", "/api/server/local-addrs", Some(SECRET), &[("content-type", "text/plain")], None).await;
    assert_eq!(r.json()["errors"], json!({"addrs": ["The addrs field is required."]}));
    // seeded random shapes
    let mut x: u64 = 0x5eed_0003;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let atoms = [json!(null), json!(""), json!("990003001"), json!(-1), json!(1.5), json!(true), json!([]), json!({}), json!("198.18.3.1"), json!("a.b"), json!({"a.b": 1})];
    for _ in 0..300 {
        let mut entry = serde_json::Map::new();
        for k in ["id", "ip", "seen_at", "to", "from", "user_name", "at", "x.y"] {
            if next() % 2 == 0 {
                entry.insert(k.into(), atoms[(next() % atoms.len() as u64) as usize].clone());
            }
        }
        let list = if next() % 5 == 0 { json!({"k": Value::Object(entry)}) } else { json!([Value::Object(entry)]) };
        for (path, key) in [("/api/server/local-addrs", "addrs"), ("/api/server/refusals", "refusals")] {
            let r = h.send("POST", path, Some(SECRET), &[("x-forwarded-for", &format!("198.18.{}.{}", next() % 200, next() % 200))], Some(json!({ key: list.clone() }))).await;
            assert!([200, 422, 500].contains(&r.status), "{path}: {} {}", r.status, r.body);
        }
    }
    assert_eq!(h.policy().await.status, 200, "still answering");
}

// ------------------------------------------------------------------------------------- stale, diagnostics ---

#[tokio::test]
async fn stale_sessions_close_on_silent_devices_only() {
    let h = harness().await;
    h.session("990003004", "990003002", 1); // the server never checked in
    h.session("990003004", "990003001", 2); // the front desk is checking in
    h.session("990003004", "990009999", 3); // no such device (hard-deleted): closes too
    h.advance(6 * 60);
    h.sql(&format!("update devices set last_online_at = '{}' where rustdesk_id = '990003001'", laravel::ts(h.now() - 60)));
    h.session("990003004", "990003002", 4); // too young
    assert_eq!(h.sweep(&[Job::Stale]), vec!["stale: closed 2"]);
    let state = |c: i64| h.one::<Option<String>>(&format!("select action from audit_connections where conn_id = {c} and closed_at is not null"));
    assert_eq!((state(1).as_deref(), state(3).as_deref()), (Some("close"), Some("close")));
    assert_eq!(h.count("audit_connections where closed_at is null"), 2);
    // no device checking in at all: every stale session closes
    h.advance(6 * 60);
    assert_eq!(h.sweep(&[Job::Stale]), vec!["stale: closed 2"]);
}

#[tokio::test]
async fn the_diagnostics_heartbeat_is_what_fleet_diagnostics_reads() {
    let h = harness().await;
    assert_eq!(h.sweep(&[Job::Diagnostics]), vec!["diagnostics: recorded"]);
    let (value, exp): (String, i64) =
        h.db().query_row(&format!("select value, expiration from cache where key = '{PREFIX}cortendesk:diagnostics:scheduler-heartbeat'"), [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    let at = chrono::DateTime::from_timestamp(h.now(), 0).unwrap().format("%Y-%m-%dT%H:%M:%S+00:00").to_string();
    assert_eq!(value, format!(r#"s:25:"{at}";"#));
    assert_eq!(exp, h.now() + 315_360_000);
    h.advance(60);
    h.sweep(&[Job::Diagnostics]);
    assert_eq!(h.count("cache"), 1, "upserted, not added");
    assert_eq!(h.count("cache_locks"), 0, "the one-off run gives its lock back");
}

// ---------------------------------------------------------------------------------------------- fixtures ---

#[tokio::test]
async fn synthetic_server_link_fixtures_replay_clean_against_the_native_service() {
    let h = harness().await;
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/serverlink");
    let s = hte_console::sanitise::Sanitiser::new(Some("any salt"), &[]);
    let report = hte_console::replay::run(&dir, &h.url, &s).await.unwrap();
    assert_eq!(report.skipped, 0);
    assert!(report.total >= 31, "{} fixtures", report.total);
    assert!(report.differences.is_empty(), "{:#?}", report.differences);
    // the writes they imply
    assert_eq!(h.one::<String>("select lan_ip from devices where rustdesk_id = '990003001'"), "198.18.3.25");
    assert_eq!(h.one::<String>("select lan_ip from devices where rustdesk_id = '990003002'"), "198.18.3.23");
    assert_eq!(h.one::<String>("select lan_ip from devices where rustdesk_id = '990003003'"), "198.18.3.31");
    assert_eq!(h.count("alarm_logs where typ = 102"), 4);
    assert_eq!(
        h.one::<String>("select info from alarm_logs where typ = 102 order by id limit 1 offset 1"),
        r#"{"user":"nobody signed in","user_id":"","from":"990003999","from_name":"","to":"990003002","to_name":"host-5eed3002","ip":"198.18.3.10","reason":"not signed in"}"#
    );
    assert!(h.one::<String>(&format!("select value from cache where key = '{PREFIX}cortendesk:server-link:last-pull'")).contains("cortendesk-server/1.1.1-hte.2"));
}

#[test]
fn every_phase_3_fixture_and_seed_passes_the_leftover_scan() {
    let s = hte_console::sanitise::Sanitiser::new(Some("any salt"), &[]);
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    let found = hte_console::fixture::scan(&s, &root.join("serverlink")).unwrap();
    assert!(found.is_empty(), "{found:#?}");
    for d in ["serverlink", "sweeps"] {
        for e in std::fs::read_dir(root.join(d)).unwrap() {
            let p = e.unwrap().path();
            if p.extension().map_or(false, |x| x == "sql") {
                let text = std::fs::read_to_string(&p).unwrap();
                let left: Vec<(usize, Vec<String>)> =
                    text.lines().enumerate().map(|(i, l)| (i + 1, s.leftovers(&json!({ "sql": l.replace('\'', " ") })))).filter(|(_, v)| !v.is_empty()).collect();
                assert!(left.is_empty(), "{}: {left:#?}", p.display());
                assert!(text.contains("SYNTHETIC"), "{} is marked synthetic", p.display());
            }
        }
    }
}

/// The sweeps scenario of the replay (fixtures/sweeps/sweeps.plan), on hte-console's side, with the previous console's expected end
/// state written out (on the server the replay compares it with the previous console's own run).
#[tokio::test]
async fn the_sweeps_scenario_ends_as_the_php_source_says() {
    let h = harness().await;
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/sweeps");
    let plan = std::fs::read_to_string(dir.join("sweeps.plan")).unwrap();
    for line in plan.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let (verb, rest) = line.split_once(' ').unwrap();
        match verb {
            "sql" => {
                let sql = hte_console::seed::expand(&std::fs::read_to_string(dir.join(rest)).unwrap(), "http://unused", &h.native.crypt).unwrap();
                h.sql(&sql);
            }
            "sweep" => {
                let jobs: Vec<Job> = rest.split_whitespace().map(|j| Job::parse(j).unwrap()).collect();
                h.sweep(&jobs);
                h.advance(1);
            }
            other => panic!("unknown step {other}"),
        }
    }
    let closed = |c: i64| h.disconnect_requested(c);
    assert!(closed(93001) && closed(93003) && closed(93005));
    // 93003 nobody on the front desk, 93001 the member left the group, 93005 the owner disabled; 93002 web, 93006 off
    let reasons: Vec<String> = {
        let c = h.db();
        let mut st = c.prepare("select conn_id || ': ' || json_extract(info, '$.reason') from alarm_logs where typ = 103 order by id").unwrap();
        let r = st.query_map([], |r| r.get::<_, String>(0)).unwrap();
        r.map(Result::unwrap).collect()
    };
    assert_eq!(
        reasons,
        vec![
            "93003: nobody is signed in on 990003001",
            "93001: user-5eed3003 may no longer reach 990003002",
            "93005: the person signed in on 990003001 is disabled",
        ]
    );
    assert!(!closed(93002) && !closed(93006) && !closed(93004));
    assert_eq!(h.one::<String>("select action from audit_connections where conn_id = 93004"), "close", "the stale sweep");
    let pw = |id: &str| -> (i64, i64, Option<String>) {
        h.db().query_row(&format!("select current_version, confirmed_version, issued_reason from hte_device_passwords where rustdesk_id = '{id}'"), [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap()
    };
    assert_eq!(pw("990003001"), (2, 2, Some("access removed (user-5eed3003)".into())));
    assert_eq!(pw("990003002"), (2, 2, Some("access removed (user-5eed3004)".into())));
    assert_eq!(pw("990003003"), (0, 0, None), "a pending computer gets none");
    assert_eq!(pw("990003004"), (2, 2, Some("every 7 days".into())));
    assert_eq!(h.count("console_audits where action = 'hte.password'"), 4);
    // books: the disabled owner's emptied, 930004 reaches the front desk through group access, the server left
    assert!(h.book_ids(930002).is_empty());
    assert_eq!(h.book_ids(930004), vec!["990003001"]);
    assert_eq!(h.book_ids(930003), Vec::<String>::new());
    assert_eq!(h.book_ids(930001), vec!["990003001", "990003002", "990003004"]);
    assert_eq!(h.count(&format!("cache where key = '{PREFIX}cortendesk:diagnostics:scheduler-heartbeat'")), 1);
    assert_eq!(h.count("cache_locks"), 0);
}

/// `hte-console schedule-locks` names the same keys the scheduler takes.
#[test]
fn schedule_lock_names_follow_laravels_mutex_names() {
    use sha1::Digest;
    for (job, expr, cmd) in [
        (Job::Reach, "* * * * *", "hte:reach-sweep"),
        (Job::Passwords, "* * * * *", "hte:passwords"),
        (Job::Stale, "*/5 * * * *", "cortendesk:close-stale-sessions"),
        (Job::Diagnostics, "* * * * *", "cortendesk:diagnostics-heartbeat"),
    ] {
        assert_eq!(job.mutex_name(), format!("framework/schedule-{}", hex::encode(sha1::Sha1::digest(format!("{expr}php artisan {cmd}").as_bytes()))));
        assert_eq!(job.command(), cmd);
    }
}

// ------------------------------------------------------------------------------- from the independent review ---

#[tokio::test]
async fn a_full_batch_of_the_longest_refusals_is_taken_and_a_larger_body_is_413() {
    let h = harness().await;
    let long = |c: char, n: usize| c.to_string().repeat(n);
    let one = json!({"user_id": long('7', 40), "user_name": long('n', 255), "from": "990003004", "to": "990003001", "ip": long('1', 64), "reason": long('r', 100), "at": 1_700_000_000});
    let batch = json!({"refusals": vec![one; 500]});
    let t = std::time::Instant::now();
    let r = h.post("/api/server/refusals", batch).await;
    assert_eq!((r.status, r.body.as_str()), (200, r#"{"recorded":500}"#));
    assert!(t.elapsed() < std::time::Duration::from_secs(5), "validated in {:?}", t.elapsed());
    // 501 entries: Laravel's max:500
    let r = h.post("/api/server/refusals", json!({"refusals": vec![json!({"to": "990003001"}); 501]})).await;
    assert_eq!(r.json()["errors"]["refusals"], json!(["The refusals field must not have more than 500 items."]));
    // a declared length over 4 MiB is answered before the body is read (a client still writing it would see the
    // connection close): headers only, over a raw socket
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut sock = tokio::net::TcpStream::connect(h.url.trim_start_matches("http://")).await.unwrap();
    let head = format!("POST /api/server/refusals HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {SECRET}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", 4 * 1024 * 1024 + 1);
    sock.write_all(head.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 512];
    let n = sock.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 413"), "{}", String::from_utf8_lossy(&buf[..n]));
}

#[tokio::test]
async fn a_restarted_service_takes_back_its_own_locks_at_once() {
    let h = harness().await;
    let key = |j: Job| format!("{PREFIX}{}", j.mutex_name());
    h.sql(&format!(
        "insert into cache_locks (key, owner, expiration) values ('{}', 'hte-console-svc-killed00000', {e}), ('{}', 'hte-console-cli-running0000', {e}), ('{}', 'PhPsCheDuLeR0001', {e})",
        key(Job::Reach),
        key(Job::Stale),
        key(Job::Diagnostics),
        e = h.now() + 600
    ));
    h.sql("delete from client_tokens where user_id <> 930004");
    h.session("990003004", "990003002", 1);
    let s = Scheduler::new(h.native.clone(), h.store.clone(), vec![Job::Reach, Job::Stale, Job::Diagnostics]);
    s.start();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(h.disconnect_requested(1), "the reach sweep ran at once with the lock taken back");
    let owner = |j: Job| h.one::<String>(&format!("select owner from cache_locks where key = '{}'", key(j)));
    assert!(owner(Job::Reach).starts_with("hte-console-svc-") && owner(Job::Reach) != "hte-console-svc-killed00000");
    assert_eq!(owner(Job::Stale), "hte-console-cli-running0000", "a sweep run's lock is not taken");
    assert_eq!(owner(Job::Diagnostics), "PhPsCheDuLeR0001", "nor the previous console's");
    s.release_all();
}

#[tokio::test]
async fn a_held_lock_is_refreshed_and_none_is_taken_after_the_stop() {
    let h = harness().await;
    let key = format!("{PREFIX}{}", Job::Reach.mutex_name());
    let s = Scheduler::new(h.native.clone(), h.store.clone(), vec![Job::Reach]);
    s.tick(Job::Reach);
    let first: (String, i64) = h.db().query_row("select owner, expiration from cache_locks where key = ?", [&key], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    h.advance(15);
    s.tick(Job::Reach);
    let second: (String, i64) = h.db().query_row("select owner, expiration from cache_locks where key = ?", [&key], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    assert_eq!((second.0.as_str(), second.1), (first.0.as_str(), first.1 + 15));
    s.release_all();
    s.tick(Job::Reach); // a tick that was waiting for the database when the stop came
    assert_eq!(h.count("cache_locks"), 0);
}

#[tokio::test]
async fn a_write_failing_half_way_leaves_the_row_for_the_next_run() {
    let h = harness().await;
    h.sql("delete from client_tokens where user_id <> 930003");
    h.session("990003004", "990003002", 1);
    h.sql("insert into settings (key, value) values ('hte_pw_enabled', '1')");
    confirmed(&h, "990003002", "tok-5eed00000003f002");
    h.sweep(&[Job::Passwords]);
    // the log table is gone for a moment: both sweeps fail on their last write
    h.sql("delete from user_group_user where user_id = 930003; alter table console_audits rename to console_audits_away");
    {
        let c = h.native.db.lock().unwrap();
        assert!(hte_console::reach::sweep(&c, h.now()).is_err());
        assert!(hte_console::passwords_sweep::sweep(&c, &h.native.crypt, h.now()).is_err());
    }
    assert!(!h.disconnect_requested(1));
    assert_eq!(h.count("alarm_logs"), 0);
    assert_eq!(h.one::<i64>("select current_version from hte_device_passwords"), 1);
    assert_eq!(h.one::<String>("select reach_user_ids from hte_device_passwords"), "[930001,930003]", "the lost person is still there");
    h.sql("alter table console_audits_away rename to console_audits");
    h.sweep(&[Job::Reach, Job::Passwords]);
    assert!(h.disconnect_requested(1));
    assert_eq!(h.one::<String>("select issued_reason from hte_device_passwords"), "access removed (user-5eed3003)");
}
