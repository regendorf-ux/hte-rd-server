//! HTE (2026-10-16): with the relay gate on, hbbr pairs a uuid only after hbbs
//! admitted a session with it. Real hbbs and hbbr, a fake console.

use axum::{extract::Extension, http::{HeaderMap, StatusCode}, routing::{get, post}, Router};
use hbb_common::{
    bytes::Bytes,
    bytes_codec::BytesCodec,
    futures_util::{sink::SinkExt, stream::StreamExt},
    protobuf::Message as _,
    rendezvous_proto::*,
    tokio::{self, io::{AsyncReadExt, AsyncWriteExt}, net::{TcpStream, UdpSocket}, time::{sleep, timeout}},
    tokio_util::codec::Framed,
};
use sodiumoxide::crypto::hash::sha256;
use std::{process::{Child, Command, Stdio}, sync::Arc, time::Duration};
use tokio_tungstenite::{connect_async, tungstenite::Message};

const HBBS: i32 = 31276;
const HBBR: i32 = 31286; // websocket on +2
const GATE: &str = "31296";
const SECRET: &str = "test-link-secret";
const KEY: &str = "gate-test-key";

struct Proc(Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn sha256_hex(s: &str) -> String {
    sha256::hash(s.as_bytes()).0.iter().map(|b| format!("{b:02x}")).collect()
}

async fn policy(Extension(body): Extension<Arc<String>>, headers: HeaderMap) -> (StatusCode, String) {
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(&format!("Bearer {SECRET}")) {
        return (StatusCode::UNAUTHORIZED, String::new());
    }
    (StatusCode::OK, (*body).clone())
}

async fn ok() -> StatusCode {
    StatusCode::OK
}

fn start_console() -> String {
    let body = serde_json::json!({
        "mode": "approved", "allow": ["gate-a", "gate-b"], "incoming_only": [],
        "tokens": { sha256_hex("token-a"): "gate-a" }, "ip_match": false
    })
    .to_string();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route("/api/server/policy", get(policy))
        .route("/api/server/local-addrs", post(ok))
        .route("/api/server/refusals", post(ok))
        .layer(Extension(Arc::new(body)));
    tokio::spawn(async move {
        axum::Server::from_tcp(listener).unwrap().serve(app.into_make_service()).await.ok();
    });
    url
}

async fn admin(port: i32, cmd: &str) -> String {
    let Ok(mut s) = TcpStream::connect(format!("127.0.0.1:{}", port - 1)).await else { return String::new() };
    s.write_all(cmd.as_bytes()).await.ok();
    let mut out = String::new();
    timeout(Duration::from_secs(2), s.read_to_string(&mut out)).await.ok();
    out
}

async fn spawn(dir: &std::path::Path, console: &str) -> (Proc, Proc) {
    let hbbs = Command::new(env!("CARGO_BIN_EXE_hbbs"))
        .current_dir(dir)
        .args(["-p", &HBBS.to_string(), "-k", "_"])
        .env("TEST_HBBS", "no")
        .env("CORTENDESK_CONSOLE_URL", console)
        .env("CORTENDESK_SERVER_SECRET", SECRET)
        .env("CORTENDESK_POLICY_INTERVAL", "1")
        .env("HTE_RELAY_GATE_PORT", GATE)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("hbbs starts");
    let hbbr = Command::new(env!("CARGO_BIN_EXE_hbbr"))
        .current_dir(dir)
        .args(["-p", &HBBR.to_string(), "-k", KEY])
        .env("HTE_RELAY_GATE_PORT", GATE)
        .env_remove("KEY")
        .env_remove("PORT")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("hbbr starts");
    for _ in 0..100 {
        if TcpStream::connect(format!("127.0.0.1:{}", HBBR + 2)).await.is_ok()
            && admin(HBBS, "pol").await.contains("mode=approved")
        {
            return (Proc(hbbs), Proc(hbbr));
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("hbbs/hbbr never came up");
}

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

async fn ws_join(uuid: &str) -> Ws {
    let (mut ws, _) = connect_async(format!("ws://127.0.0.1:{}", HBBR + 2)).await.expect("ws connects");
    let mut msg = RendezvousMessage::new();
    msg.set_request_relay(RequestRelay { uuid: uuid.to_owned(), licence_key: KEY.to_owned(), ..Default::default() });
    ws.send(Message::Binary(msg.write_to_bytes().unwrap().into())).await.unwrap();
    ws
}

async fn ws_recv(ws: &mut Ws, ms: u64) -> Option<Vec<u8>> {
    loop {
        match timeout(Duration::from_millis(ms), ws.next()).await {
            Ok(Some(Ok(Message::Binary(b)))) => return Some(b.to_vec()),
            Ok(Some(Ok(_))) => continue,
            _ => return None,
        }
    }
}

async fn pairs(uuid: &str) -> bool {
    let mut a = ws_join(uuid).await;
    sleep(Duration::from_millis(300)).await;
    let mut b = ws_join(uuid).await;
    sleep(Duration::from_millis(300)).await;
    a.send(Message::Binary(b"hello".to_vec().into())).await.ok();
    ws_recv(&mut b, 5000).await.as_deref() == Some(&b"hello"[..])
}

async fn register(id: &str) -> UdpSocket {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut msg = RendezvousMessage::new();
    msg.set_register_pk(RegisterPk {
        id: id.to_owned(), uuid: format!("uuid-{id}").into_bytes().into(), pk: vec![7u8; 32].into(), ..Default::default()
    });
    let bytes = msg.write_to_bytes().unwrap();
    let mut buf = [0u8; 1024];
    for _ in 0..50 {
        sock.send_to(&bytes, format!("127.0.0.1:{HBBS}")).await.ok();
        if timeout(Duration::from_millis(200), sock.recv_from(&mut buf)).await.is_ok() {
            return sock;
        }
    }
    panic!("{id} never registered");
}

async fn request_relay_via_hbbs(target: &str, uuid: &str, token: &str) -> Framed<TcpStream, BytesCodec> {
    let s = TcpStream::connect(format!("127.0.0.1:{HBBS}")).await.unwrap();
    let mut conn = Framed::new(s, BytesCodec::new());
    let mut msg = RendezvousMessage::new();
    msg.set_request_relay(RequestRelay { id: target.to_owned(), uuid: uuid.to_owned(), token: token.to_owned(), ..Default::default() });
    conn.send(Bytes::from(msg.write_to_bytes().unwrap())).await.unwrap();
    conn
}

#[tokio::test]
async fn hbbr_pairs_only_what_hbbs_admitted() {
    let url = start_console();
    let dir = tempfile::tempdir().unwrap();
    let (_hbbs, _hbbr) = spawn(dir.path(), &url).await;
    let _b = register("gate-b").await;

    // Nobody asked hbbs: the relay refuses to pair.
    assert!(!pairs("gate-unknown").await, "an unknown uuid must not pair");

    // Refused by hbbs (no sign-in): still not paired.
    let _c = request_relay_via_hbbs("gate-b", "gate-refused", "").await;
    sleep(Duration::from_millis(300)).await;
    assert!(!pairs("gate-refused").await, "a uuid hbbs refused must not pair");

    // Admitted by hbbs: paired.
    let _c = request_relay_via_hbbs("gate-b", "gate-admitted", "token-a").await;
    sleep(Duration::from_millis(300)).await;
    assert!(pairs("gate-admitted").await, "an admitted uuid pairs");
}

/// Upstream 1.5.1 drops a request whose uuid is empty, over 128 bytes or has
/// anything but ASCII letters, digits, `-` and `_`. The drop comes before the
/// per-person check and the gate: a person who may reach the device, with a
/// malformed uuid, still gets no pairing, and a normal uuid still pairs.
#[tokio::test]
async fn a_malformed_relay_uuid_is_dropped_before_the_gate() {
    let url = start_console();
    let dir = tempfile::tempdir().unwrap();
    let (_hbbs, _hbbr) = spawn(dir.path(), &url).await;
    let _b = register("gate-b").await;

    // A normal (v4-shaped) uuid from an allowed person pairs.
    let normal = "e4c181d0-41c7-4ae6-8ef0-36581b6b2b12";
    let _c = request_relay_via_hbbs("gate-b", normal, "token-a").await;
    sleep(Duration::from_millis(300)).await;
    assert!(pairs(normal).await, "a normal uuid still pairs");

    let too_long = "a".repeat(129);
    for bad in ["bad uuid", "e4c181d0\u{e9}", "{e4c181d0}", "id.with.dots", too_long.as_str()] {
        let _c = request_relay_via_hbbs("gate-b", bad, "token-a").await;
        sleep(Duration::from_millis(300)).await;
        assert!(!pairs(bad).await, "a malformed uuid must not pair: {bad:?}");
    }
}
