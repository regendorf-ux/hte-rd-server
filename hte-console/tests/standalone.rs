//! Phase 9 end to end: the console as the all-in-one image runs it. No upstream (nothing to forward to), the previous console's session
//! bridge and the previous console session reading off, the schema checked by `migrate::run`, and everything the CortenDesk container used to
//! answer by itself (static files, health, the web client's bundle) answered here. On a real socket, against a temporary
//! database made from tests/schema_live.sql with the previous console's 41 migrations recorded.

use hte_console::api::{Limiter, Native, Nonces};
use hte_console::laravel::{self, Encrypter};
use hte_console::oidc::Oidc;
use hte_console::pages::{self, websession::OwnConfig};
use rusqlite::{params, Connection};
use std::sync::{Arc, Mutex};

const APP_KEY: &str = "base64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

struct H {
    url: String,
    client: reqwest::Client,
    db_path: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

fn live_db(path: &std::path::Path) {
    let c = Connection::open(path).unwrap();
    c.execute_batch(include_str!("schema_live.sql")).unwrap();
    // the live file records the 41 migrations the previous console ran; the fixture schema does not carry the rows
    for m in hte_console::migrate::PHP_MIGRATIONS {
        c.execute(r#"insert into "migrations" ("migration", "batch") values (?, 1)"#, params![m]).unwrap();
    }
}

async fn harness() -> H {
    sodiumoxide::init().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cortendesk.sqlite");
    live_db(&db_path);
    let conn = hte_console::sqlite::open(&db_path, std::time::Duration::from_secs(5), true).unwrap();
    let report = hte_console::migrate::run(&conn).unwrap();
    assert!(report.own_pending.is_empty());
    let native = Arc::new(Native {
        db: Mutex::new(conn),
        crypt: Encrypter::from_app_key(APP_KEY).unwrap(),
        hbbs_db: dir.path().join("none.sqlite3"),
        trusted: laravel::parse_trusted(laravel::DEFAULT_TRUSTED),
        api_version: "1.15.0-hte.1".into(),
        max_body: 1 << 20,
        limiter: Mutex::new(Limiter::default()),
        nonces: Mutex::new(Nonces::default()),
        signin: hte_console::signin::State::new(Oidc::new(true, false), None, "HTE Remote".into()),
        clock: Box::new(|| 1_800_000_000),
    });
    // as the previous-console-free service: no upstream, the sign-in on, the previous console's sessions neither read nor minted
    let own = OwnConfig { signin: true, idle_s: 3600, absolute_s: 12 * 3600, bridge: false, laravel_read: false };
    let app = pages::routes_with(native.clone(), None, own).unwrap().merge(hte_console::api::router(native, None)).into_make_service_with_connect_info::<std::net::SocketAddr>();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    H { url, client, db_path, _dir: dir }
}

impl H {
    async fn req(&self, method: &str, path: &str) -> (u16, reqwest::header::HeaderMap, Vec<u8>) {
        let r = self.client.request(method.parse().unwrap(), format!("{}{}", self.url, path)).header("x-forwarded-for", "198.18.9.1").send().await.unwrap();
        let (s, h) = (r.status().as_u16(), r.headers().clone());
        (s, h, r.bytes().await.unwrap().to_vec())
    }
}

#[tokio::test]
async fn the_static_files_are_served_here() {
    let h = harness().await;
    for (path, ctype) in [
        ("/assets/css/hte-remote.css", "text/css"),
        ("/assets/css/hte-brand.css", "text/css"),
        ("/assets/js/shell.js", "text/javascript"),
        ("/assets/vendor/bootstrap/bootstrap.min.css", "text/css"),
        ("/assets/vendor/htmx/htmx.min.js", "text/javascript"),
        ("/assets/images/hte-remote.png", "image/png"),
        ("/rdclient/app.js", "text/javascript"),
        ("/rdclient/app.css", "text/css"),
        ("/robots.txt", "text/plain"),
        ("/favicon.ico", "image/x-icon"),
    ] {
        let (s, hd, body) = h.req("GET", path).await;
        assert_eq!(s, 200, "{path}");
        assert!(hd["content-type"].to_str().unwrap().starts_with(ctype), "{path}: {:?}", hd["content-type"]);
        assert_eq!(path == "/favicon.ico", body.is_empty(), "{path}: the previous console's favicon.ico is empty, nothing else is");
    }
    let (_, _, robots) = h.req("GET", "/robots.txt").await;
    assert_eq!(robots, b"User-agent: *\nDisallow:\n");
    // every embedded asset answers 200 with a body
    for name in pages::assets::names() {
        let (s, _, body) = h.req("GET", &format!("/assets/{name}")).await;
        assert!(s == 200 && !body.is_empty(), "/assets/{name}: {s}");
    }
    let (s, _, _) = h.req("GET", "/assets/css/nope.css").await;
    assert_eq!(s, 404);
    let (s, _, _) = h.req("GET", "/assets/../Cargo.toml").await;
    assert_eq!(s, 404);
    let (s, _, _) = h.req("POST", "/robots.txt").await;
    assert_eq!(s, 405);
}

#[tokio::test]
async fn health_and_the_sign_in_work_with_nothing_behind_them() {
    let h = harness().await;
    let (s, _, body) = h.req("GET", "/health/live").await;
    assert_eq!((s, body), (200, br#"{"live":true}"#.to_vec()));
    let (s, hd, _) = h.req("GET", "/up").await;
    assert_eq!(s, 200, "{hd:?}");
    let (s, hd, _) = h.req("GET", "/login").await;
    assert_eq!(s, 200);
    assert!(hd.get_all("set-cookie").iter().any(|c| c.to_str().unwrap().starts_with("hte-remote-console=")), "our cookie, none of the previous console's");
    assert!(!hd.get_all("set-cookie").iter().any(|c| c.to_str().unwrap().contains("hte-remote-session") || c.to_str().unwrap().contains("XSRF")));
    // a page without a session goes to the sign-in, not to a previous-console that is not there
    for path in ["/", "/devices", "/diagnostics", "/roles", "/settings", "/logs/alarms", "/webclient"] {
        let (s, hd, _) = h.req("GET", path).await;
        assert_eq!(s, 302, "{path}");
        assert!(hd["location"].to_str().unwrap().ends_with("/login"), "{path}: {:?}", hd["location"]);
    }
}

#[tokio::test]
async fn what_the_previous_console_served_answers_404_and_never_hangs() {
    let h = harness().await;
    // The previous console's endpoints, the downloads, the previous console's storage: gone with the previous console; /ws/* is Caddy's (to hbbs/hbbr), never this port
    for path in ["/livewire-abc123/update", "/livewire/livewire.js", "/downloads", "/downloads/x.exe", "/storage/x", "/ws/id", "/ws/relay"] {
        let (s, _, _) = h.req("GET", path).await;
        assert_eq!(s, 404, "{path}");
    }
    // served here since 0.8.2 (two-factor, invitations): without a session the account page sends to the sign-in, an unknown
    // invitation is refused; neither is a 5xx or a hang
    let (s, _, _) = h.req("GET", "/account/two-factor").await;
    assert_eq!(s, 302, "/account/two-factor");
    let (s, _, _) = h.req("GET", "/invite/abc").await;
    assert!(s < 500, "/invite/abc: {s}");
    let (s, _, body) = h.req("GET", "/api/nothing-here").await;
    assert_eq!(s, 404);
    assert!(String::from_utf8_lossy(&body).contains("Not Found"));
}

#[tokio::test]
async fn the_schema_check_is_what_start_up_runs() {
    let h = harness().await;
    let c = Connection::open(&h.db_path).unwrap();
    let n: i64 = c.query_row(r#"select count(*) from "migrations""#, [], |r| r.get(0)).unwrap();
    assert_eq!(n, 44, "the previous console's 41 rows and ours");
    let out = hte_console::maintenance::status(&c, "hte-remote-cache-", 1_800_000_000).unwrap();
    assert!(out.contains("migrations_php=41/41") && out.contains("migrations_own_pending=0") && out.contains("migrations_unknown=0"), "{out}");
    assert!(out.contains("devices=0") && out.contains("scheduler_heartbeat_age_s=?"), "{out}");
    // the file is in WAL mode, as the previous console and every earlier phase need it
    let mode: String = c.query_row("pragma journal_mode", [], |r| r.get(0)).unwrap();
    assert_eq!(mode, "wal");
}
