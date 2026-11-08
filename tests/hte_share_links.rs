//! HTE (2.4.0): share links against a real hbbs and a fake console. A link's ticket admits its one device while the
//! console lists the link as live, and nothing else: not a second device, not an expired or ended link, not open mode,
//! not a device the server has not approved. Ending a link at the console closes it at hbbs within one policy pull,
//! with the ticket still unexpired. The helpers mirror hte_scope.rs.

#![allow(dead_code)]
use axum::{
    extract::Extension,
    http::{HeaderMap, HeaderValue, StatusCode},
    routing::{get, post},
    Router,
};
use hbb_common::{
    bytes::Bytes,
    bytes_codec::BytesCodec,
    futures_util::{sink::SinkExt, stream::StreamExt},
    protobuf::Message as _,
    rendezvous_proto::*,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpStream, UdpSocket},
        time::{sleep, timeout},
    },
    tokio_util::codec::Framed,
};
use sodiumoxide::crypto::{auth::hmacsha256, hash::sha256};
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// Clear of every other test file's ports (each hbbs takes port-1 and port+2).
const PORT_SHARE: i32 = 31276;
const PORT_SHARE_OPEN: i32 = 31286;

const SECRET: &str = "test-link-secret";
const DENY_SCOPE: &str = "You are not given access to this device";
const DENY_NOBODY: &str = "Only signed-in people may reach devices";
const DENY_UNAPPROVED: &str = "This device is not approved on this server";

#[derive(Default)]
struct Console {
    body: String,
    version: u32,
    fail: bool,
    refusals: Vec<serde_json::Value>,
}
type Shared = Arc<Mutex<Console>>;

fn authorized(headers: &HeaderMap) -> bool {
    headers.get("authorization").and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {SECRET}"))
}

async fn policy(Extension(st): Extension<Shared>, headers: HeaderMap) -> (StatusCode, HeaderMap, String) {
    let c = st.lock().unwrap();
    let mut out = HeaderMap::new();
    if !authorized(&headers) {
        return (StatusCode::UNAUTHORIZED, out, String::new());
    }
    if c.fail {
        return (StatusCode::INTERNAL_SERVER_ERROR, out, String::new());
    }
    let etag = format!("\"v{}\"", c.version);
    out.insert("etag", HeaderValue::from_str(&etag).unwrap());
    if headers.get("if-none-match").and_then(|v| v.to_str().ok()) == Some(etag.as_str()) {
        return (StatusCode::NOT_MODIFIED, out, String::new());
    }
    (StatusCode::OK, out, c.body.clone())
}

async fn refusals(Extension(st): Extension<Shared>, headers: HeaderMap, body: String) -> StatusCode {
    if !authorized(&headers) {
        return StatusCode::UNAUTHORIZED;
    }
    let mut c = st.lock().unwrap();
    if c.fail {
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    if let Some(items) = v.get("refusals").and_then(|r| r.as_array()) {
        c.refusals.extend(items.iter().cloned());
    }
    StatusCode::OK
}

async fn ignore_addrs() -> StatusCode {
    StatusCode::OK
}

fn set_policy(st: &Shared, body: serde_json::Value) {
    let mut c = st.lock().unwrap();
    c.body = body.to_string();
    c.version += 1;
}

fn start_console(body: serde_json::Value) -> (String, Shared) {
    let st: Shared = Default::default();
    set_policy(&st, body);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route("/api/server/policy", get(policy))
        .route("/api/server/refusals", post(refusals))
        .route("/api/server/local-addrs", post(ignore_addrs))
        .layer(Extension(st.clone()));
    tokio::spawn(async move {
        axum::Server::from_tcp(listener).unwrap().serve(app.into_make_service()).await.ok();
    });
    (url, st)
}

struct Hbbs(Child);
impl Drop for Hbbs {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_hbbs(dir: &std::path::Path, port: i32, console: &str) -> (Hbbs, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hbbs"));
    cmd.current_dir(dir)
        .args(["-p", &port.to_string(), "-k", "_"])
        .env("TEST_HBBS", "no")
        .env("CORTENDESK_CONSOLE_URL", console)
        .env("CORTENDESK_SERVER_SECRET", SECRET)
        .env("CORTENDESK_POLICY_INTERVAL", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().expect("hbbs starts");
    let stdout = child.stdout.take().expect("stdout piped");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut tx = Some(tx);
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Some(k) = line.split("Key: ").nth(1) {
                if let Some(tx) = tx.take() {
                    tx.send(k.trim().to_owned()).ok();
                }
            }
        }
    });
    let key = rx.recv_timeout(Duration::from_secs(20)).expect("hbbs logs its key");
    (Hbbs(child), key)
}

async fn admin(port: i32, cmd: &str) -> String {
    let Ok(mut s) = TcpStream::connect(format!("127.0.0.1:{}", port - 1)).await else {
        return String::new();
    };
    s.write_all(cmd.as_bytes()).await.ok();
    let mut out = String::new();
    timeout(Duration::from_secs(2), s.read_to_string(&mut out)).await.ok();
    out
}

async fn wait_policy(port: i32, needle: &str) {
    let mut last = String::new();
    for _ in 0..100 {
        last = admin(port, "pol").await;
        if last.contains(needle) {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("policy never showed {needle:?}, last: {last:?}");
}

struct Peer {
    sock: UdpSocket,
    id: String,
}

impl Peer {
    async fn register(port: i32, id: &str) -> Peer {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut msg = RendezvousMessage::new();
        msg.set_register_pk(RegisterPk {
            id: id.to_owned(),
            uuid: format!("uuid-{id}").into_bytes().into(),
            pk: vec![7u8; 32].into(),
            ..Default::default()
        });
        let bytes = msg.write_to_bytes().unwrap();
        let mut buf = [0u8; 1024];
        for _ in 0..50 {
            sock.send_to(&bytes, format!("127.0.0.1:{port}")).await.ok();
            if let Ok(Ok((n, _))) = timeout(Duration::from_millis(200), sock.recv_from(&mut buf)).await {
                let res = RendezvousMessage::parse_from_bytes(&buf[..n]).unwrap();
                match res.union {
                    Some(rendezvous_message::Union::RegisterPkResponse(r)) => {
                        assert_eq!(r.result.enum_value(), Ok(register_pk_response::Result::OK), "{id} registers");
                        return Peer { sock, id: id.to_owned() };
                    }
                    other => panic!("unexpected reply to RegisterPk: {other:?}"),
                }
            }
        }
        panic!("hbbs never answered RegisterPk for {id}");
    }

    async fn forwarded(&self, ms: u64) -> Option<RendezvousMessage> {
        let mut buf = [0u8; 1024];
        let deadline = hbb_common::tokio::time::Instant::now() + Duration::from_millis(ms);
        loop {
            let left = deadline.saturating_duration_since(hbb_common::tokio::time::Instant::now());
            let (n, _) = timeout(left, self.sock.recv_from(&mut buf)).await.ok()?.ok()?;
            let msg = RendezvousMessage::parse_from_bytes(&buf[..n]).ok()?;
            if !matches!(msg.union, Some(rendezvous_message::Union::RegisterPkResponse(_))) {
                return Some(msg);
            }
        }
    }
}

type Conn = Framed<TcpStream, BytesCodec>;

async fn connect(port: i32) -> Conn {
    for _ in 0..100 {
        if let Ok(s) = TcpStream::connect(format!("127.0.0.1:{port}")).await {
            return Framed::new(s, BytesCodec::new());
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("hbbs never accepted a connection on {port}");
}

async fn send(conn: &mut Conn, msg: RendezvousMessage) {
    conn.send(Bytes::from(msg.write_to_bytes().unwrap())).await.expect("request sent");
}

async fn reply(conn: &mut Conn, ms: u64) -> Option<RendezvousMessage> {
    loop {
        let bytes = match timeout(Duration::from_millis(ms), conn.next()).await {
            Ok(Some(Ok(b))) => b,
            _ => return None,
        };
        let msg = RendezvousMessage::parse_from_bytes(&bytes).expect("reply parses");
        if !matches!(msg.union, Some(rendezvous_message::Union::KeyExchange(_))) {
            return Some(msg);
        }
    }
}

async fn punch(port: i32, key: &str, target: &str, token: &str) -> Conn {
    let mut conn = connect(port).await;
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_request(PunchHoleRequest {
        id: target.to_owned(),
        token: token.to_owned(),
        licence_key: key.to_owned(),
        version: "1.5.0".to_owned(),
        ..Default::default()
    });
    send(&mut conn, msg).await;
    conn
}

async fn request_relay(port: i32, target: &str, token: &str) -> Conn {
    let mut conn = connect(port).await;
    let mut msg = RendezvousMessage::new();
    msg.set_request_relay(RequestRelay {
        id: target.to_owned(),
        uuid: "5c8a1d9e-relay-test".to_owned(),
        token: token.to_owned(),
        ..Default::default()
    });
    send(&mut conn, msg).await;
    conn
}

async fn assert_refused(conn: &mut Conn, text: &str) {
    match reply(conn, 3000).await.map(|m| m.union) {
        Some(Some(rendezvous_message::Union::PunchHoleResponse(ph))) => {
            assert!(ph.socket_addr.is_empty(), "a refusal carries no address");
            assert!(ph.other_failure.contains(text), "expected {text:?}, got {:?}", ph.other_failure);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

async fn assert_relay_refused(conn: &mut Conn, text: &str) {
    match reply(conn, 3000).await.map(|m| m.union) {
        Some(Some(rendezvous_message::Union::RelayResponse(rr))) => {
            assert!(rr.refuse_reason.contains(text), "expected {text:?}, got {:?}", rr.refuse_reason)
        }
        other => panic!("expected a relay refusal, got {other:?}"),
    }
}

async fn assert_forwarded(conn: &mut Conn, target: &Peer) {
    let msg = target.forwarded(3000).await;
    match msg.map(|m| m.union) {
        Some(Some(rendezvous_message::Union::FetchLocalAddr(_))) => {}
        other => panic!("{} should have been asked for its local address, got {other:?}", target.id),
    }
    assert!(reply(conn, 300).await.is_none(), "the initiator must not be refused");
}

fn sha256_hex(s: &str) -> String {
    sha256::hash(s.as_bytes()).0.iter().map(|b| format!("{b:02x}")).collect()
}

fn _unused_ticket(user: &str) -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let signed = format!("cdw1.{}.web-{user}", now + 600);
    let mut st = hmacsha256::State::init(SECRET.as_bytes());
    st.update(signed.as_bytes());
    let sig: String = st.finalize().0.iter().map(|b| format!("{b:02x}")).collect();
    format!("{signed}.{sig}")
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// What the console's `ServerLink::shareTicket` signs: bound to one device, subject `share-<link id>`.
fn share_ticket(link: &str, device: &str, ttl: i64) -> String {
    let signed = format!("cdw2.{}.{device}.share-{link}", (now() as i64 + ttl) as u64);
    let mut st = hmacsha256::State::init(SECRET.as_bytes());
    st.update(signed.as_bytes());
    let sig: String = st.finalize().0.iter().map(|b| format!("{b:02x}")).collect();
    format!("{signed}.{sig}")
}

fn share_policy(mode: &str, shares: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "mode": mode,
        "allow": ["sh-desk", "sh-other"],
        "incoming_only": [],
        "tokens": {},
        "ip_match": false,
        "scope": {"enforce": true, "users": {}, "token_users": {}, "shares": shares}
    })
}

const DENY_ENDED: &str = "This share link has ended";
const DENY_MODE: &str = "Share links work only while this server admits approved devices only";

#[tokio::test]
async fn a_share_link_reaches_its_device_only_while_it_is_live() {
    let live = serde_json::json!({
        "7": {"device": "sh-desk", "expires": now() + 600},
        "8": {"device": "sh-desk", "expires": now() - 5},
    });
    let (url, console) = start_console(share_policy("approved", live));
    let dir = tempfile::tempdir().unwrap();
    let (_hbbs, key) = spawn_hbbs(dir.path(), PORT_SHARE, &url);
    wait_policy(PORT_SHARE, "scope=on").await;

    let desk = Peer::register(PORT_SHARE, "sh-desk").await;
    let other = Peer::register(PORT_SHARE, "sh-other").await;

    // The link reaches its device, by punch and by relay.
    let mut conn = punch(PORT_SHARE, &key, &desk.id, &share_ticket("7", "sh-desk", 600)).await;
    assert_forwarded(&mut conn, &desk).await;

    // By relay it is admitted exactly like any other session: the target is asked to answer on the relay (the same
    // path that hands the relay its `hte1 <uuid>` admission, see hte_relay_gate.rs).
    let _conn = request_relay(PORT_SHARE, &desk.id, &share_ticket("7", "sh-desk", 600)).await;
    match desk.forwarded(3000).await.map(|m| m.union) {
        Some(Some(rendezvous_message::Union::RequestRelay(_))) => {}
        other => panic!("the device should have been asked to relay, got {other:?}"),
    }

    // It cannot reach a second device: a ticket cut for another device is refused, and so is this one pointed at it.
    let mut conn = punch(PORT_SHARE, &key, &other.id, &share_ticket("7", "sh-desk", 600)).await;
    assert_refused(&mut conn, DENY_UNAPPROVED).await;
    let mut conn = punch(PORT_SHARE, &key, &other.id, &share_ticket("7", "sh-other", 600)).await;
    assert_refused(&mut conn, DENY_ENDED).await;
    let mut conn = request_relay(PORT_SHARE, &other.id, &share_ticket("7", "sh-other", 600)).await;
    assert_relay_refused(&mut conn, DENY_ENDED).await;
    assert!(other.forwarded(300).await.is_none(), "nothing reaches the second device");

    // An expired link (the console's list says so, the ticket still has time) and an unknown one are refused.
    let mut conn = punch(PORT_SHARE, &key, &desk.id, &share_ticket("8", "sh-desk", 600)).await;
    assert_refused(&mut conn, DENY_ENDED).await;
    let mut conn = punch(PORT_SHARE, &key, &desk.id, &share_ticket("9", "sh-desk", 600)).await;
    assert_refused(&mut conn, DENY_ENDED).await;
    // A ticket past its own expiry is no ticket at all.
    let mut conn = punch(PORT_SHARE, &key, &desk.id, &share_ticket("7", "sh-desk", -5)).await;
    assert_refused(&mut conn, DENY_UNAPPROVED).await;

    // The creator ends link 7 at the console: gone from the list, so refused at once on the next pull although its
    // ticket has ten minutes left.
    set_policy(&console, share_policy("approved", serde_json::json!({})));
    sleep(Duration::from_millis(2500)).await;
    let mut conn = punch(PORT_SHARE, &key, &desk.id, &share_ticket("7", "sh-desk", 600)).await;
    assert_refused(&mut conn, DENY_ENDED).await;
}

/// Open mode never admits a share link, whatever the console lists.
#[tokio::test]
async fn a_share_link_is_refused_in_open_mode() {
    let live = serde_json::json!({"7": {"device": "sh-desk", "expires": now() + 600}});
    let (url, _console) = start_console(share_policy("open", live));
    let dir = tempfile::tempdir().unwrap();
    let (_hbbs, key) = spawn_hbbs(dir.path(), PORT_SHARE_OPEN, &url);
    wait_policy(PORT_SHARE_OPEN, "mode=open").await;
    let desk = Peer::register(PORT_SHARE_OPEN, "sh-desk").await;
    let mut conn = punch(PORT_SHARE_OPEN, &key, &desk.id, &share_ticket("7", "sh-desk", 600)).await;
    assert_refused(&mut conn, DENY_MODE).await;
}
