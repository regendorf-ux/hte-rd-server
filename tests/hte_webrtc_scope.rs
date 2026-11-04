//! HTE (2026-11-02): WebRTC signalling (RustDesk 1.5, upstream 1.2.0) against a
//! real hbbs and a fake console. The offer rides in the punch hole request, so
//! per-person reach judges it first: a person outside a device's scope gets a
//! refusal, the device hears nothing, and the connection that was refused
//! cannot trickle candidates to anyone; a route opens only for an admitted
//! offer and reaches only the device offered to; signalling is off unless
//! `HTE_REMOTE_WEBRTC` says on; and behind a proxy (X-Forwarded-For from a trusted proxy) every
//! connection keeps its own reply route. Controllers connect over WebSocket,
//! as the console's web client does, so the tests need no second loopback
//! address. The helpers mirror hte_scope.rs.

use axum::{
    extract::Extension,
    http::{HeaderMap, HeaderValue, StatusCode},
    routing::{get, post},
    Router,
};
use hbb_common::{
    bytes::Bytes,
    futures_util::{sink::SinkExt, stream::StreamExt},
    protobuf::Message as _,
    rendezvous_proto::*,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpStream, UdpSocket},
        time::{sleep, timeout},
    },
    AddrMangle,
};
use sodiumoxide::crypto::{auth::hmacsha256, hash::sha256};
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// Clear of every other test file's ports (each hbbs takes port-1 and port+2).
const PORT_ON: i32 = 31306;
const PORT_OFF: i32 = 31316;
const PORT_KEYS: i32 = 31326;

const SECRET: &str = "test-link-secret";
const DENY_SCOPE: &str = "You are not given access to this device";
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

fn spawn_hbbs(dir: &std::path::Path, port: i32, console: &str, webrtc: bool) -> (Hbbs, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hbbs"));
    cmd.current_dir(dir)
        .args(["-p", &port.to_string(), "-k", "_"])
        .env("TEST_HBBS", "no")
        .env("TRUSTED_PROXIES", "127.0.0.1/32")
        .env("CORTENDESK_CONSOLE_URL", console)
        .env("CORTENDESK_SERVER_SECRET", SECRET)
        .env("CORTENDESK_POLICY_INTERVAL", "1")
        .env_remove("HTE_REMOTE_WEBRTC")
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if webrtc {
        cmd.env("HTE_REMOTE_WEBRTC", "1");
    }
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
        let mut buf = [0u8; 65536];
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

fn sha256_hex(s: &str) -> String {
    sha256::hash(s.as_bytes()).0.iter().map(|b| format!("{b:02x}")).collect()
}

fn ticket(user: &str) -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let signed = format!("cdw1.{}.web-{user}", now + 600);
    let mut st = hmacsha256::State::init(SECRET.as_bytes());
    st.update(signed.as_bytes());
    let sig: String = st.finalize().0.iter().map(|b| format!("{b:02x}")).collect();
    format!("{signed}.{sig}")
}

/// HTE Remote's set-up: approved devices only, nobody found by IP, two people.
fn hte_policy(enforce: bool) -> serde_json::Value {
    serde_json::json!({
        "mode": "approved",
        "allow": ["sc-maria", "sc-jdoe", "sc-front", "sc-server"],
        "incoming_only": [],
        "tokens": {
            sha256_hex("token-maria"): "sc-maria",
            sha256_hex("token-jdoe"): "sc-jdoe",
        },
        "ip_match": false,
        "scope": {
            "enforce": enforce,
            "users": {
                "7": {"name": "mperez", "all": false, "devices": ["sc-front"]},
                "8": {"name": "jdoe", "all": true, "devices": []},
            },
            "token_users": {
                sha256_hex("token-maria"): "7",
                sha256_hex("token-jdoe"): "8",
            }
        }
    })
}


use tokio_tungstenite::{
    client_async,
    tungstenite::{client::IntoClientRequest, Message},
    WebSocketStream,
};

type Ws = WebSocketStream<TcpStream>;

/// A browser's connection through a proxy: the TCP peer is loopback, the
/// address hbbs works with comes from X-Forwarded-For (127.0.0.1 is the trusted proxy) plus this connection's port.
struct Web {
    ws: Ws,
    /// The address hbbs keys this connection by (what the device sees).
    keyed_as: String,
}

impl Web {
    async fn open(port: i32, real_ip: &str) -> Web {
        let mut last = None;
        for _ in 0..100 {
            match TcpStream::connect(format!("127.0.0.1:{}", port + 2)).await {
                Ok(tcp) => {
                    let local = tcp.local_addr().unwrap();
                    let mut req = format!("ws://127.0.0.1:{}", port + 2).into_client_request().unwrap();
                    req.headers_mut().insert("X-Forwarded-For", real_ip.parse().unwrap());
                    let (ws, _) = client_async(req, tcp).await.expect("websocket upgrade");
                    return Web { ws, keyed_as: format!("{real_ip}:{}", local.port()) };
                }
                Err(e) => last = Some(e),
            }
            sleep(Duration::from_millis(100)).await;
        }
        panic!("hbbs never accepted a websocket on {}: {last:?}", port + 2);
    }

    async fn send(&mut self, msg: RendezvousMessage) {
        self.ws.send(Message::Binary(msg.write_to_bytes().unwrap().into())).await.expect("sent");
    }

    async fn recv(&mut self, ms: u64) -> Option<RendezvousMessage> {
        loop {
            match timeout(Duration::from_millis(ms), self.ws.next()).await {
                Ok(Some(Ok(Message::Binary(b)))) => return Some(RendezvousMessage::parse_from_bytes(&b).expect("parses")),
                Ok(Some(Ok(_))) => continue,
                _ => return None,
            }
        }
    }
}

const OFFER: &str = "webrtc://b2ZmZXI=";
const ANSWER: &str = "webrtc://YW5zd2Vy";

fn offer_to(target: &str, token: &str, key: &str) -> RendezvousMessage {
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_request(PunchHoleRequest {
        id: target.to_owned(),
        token: token.to_owned(),
        licence_key: key.to_owned(),
        version: "1.5.0".to_owned(),
        webrtc_sdp_offer: OFFER.to_owned(),
        ..Default::default()
    });
    msg
}

fn candidate(id: &str, socket_addr: &[u8], text: &str) -> RendezvousMessage {
    let mut msg = RendezvousMessage::new();
    msg.set_ice_candidate(IceCandidate {
        id: id.to_owned(),
        socket_addr: socket_addr.to_vec().into(),
        session_key: "sha-256 AA:BB".to_owned(),
        candidate: text.to_owned(),
        ..Default::default()
    });
    msg
}

async fn expect_punch(device: &Peer, offer: &str) -> PunchHole {
    match device.forwarded(3000).await.map(|m| m.union) {
        Some(Some(rendezvous_message::Union::PunchHole(ph))) => {
            assert_eq!(ph.webrtc_sdp_offer, offer, "the offer reaches {} as sent", device.id);
            ph
        }
        other => panic!("{} should have been punched, got {other:?}", device.id),
    }
}

async fn expect_refusal(web: &mut Web, text: &str) {
    match web.recv(3000).await.map(|m| m.union) {
        Some(Some(rendezvous_message::Union::PunchHoleResponse(r))) => {
            assert!(r.socket_addr.is_empty(), "a refusal carries no address");
            assert!(r.webrtc_sdp_answer.is_empty());
            assert!(r.other_failure.contains(text), "expected {text:?}, got {:?}", r.other_failure);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn expect_candidate(msg: Option<RendezvousMessage>, text: &str) {
    match msg.map(|m| m.union) {
        Some(Some(rendezvous_message::Union::IceCandidate(ice))) => assert_eq!(ice.candidate, text),
        other => panic!("expected candidate {text}, got {other:?}"),
    }
}

/// A device's own connection to hbbs, for what it sends over TCP.
async fn device_conn(port: i32) -> TcpStream {
    for _ in 0..100 {
        if let Ok(s) = TcpStream::connect(format!("127.0.0.1:{port}")).await {
            return s;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("hbbs never accepted a connection on {port}");
}

async fn device_sends(port: i32, msg: RendezvousMessage) -> TcpStream {
    use hbb_common::{bytes_codec::BytesCodec, tokio_util::codec::Framed};
    let mut framed = Framed::new(device_conn(port).await, BytesCodec::new());
    // hbbs opens a plain TCP connection with its key exchange offer; ignoring
    // it leaves the connection plain, which is all a device's candidate needs.
    let _ = timeout(Duration::from_millis(500), framed.next()).await;
    framed.send(Bytes::from(msg.write_to_bytes().unwrap())).await.expect("sent");
    framed.into_inner()
}

#[tokio::test]
async fn an_offer_is_judged_by_reach_like_any_request() {
    let (url, console) = start_console(hte_policy(true));
    let dir = tempfile::tempdir().unwrap();
    let (_hbbs, key) = spawn_hbbs(dir.path(), PORT_ON, &url, true);
    wait_policy(PORT_ON, "scope=on people=2").await;
    let front = Peer::register(PORT_ON, "sc-front").await;
    let server = Peer::register(PORT_ON, "sc-server").await;

    // María (scope: the front desk) offers to the front desk: it goes through,
    // and the connection that carried it may trickle candidates to that device.
    let mut maria = Web::open(PORT_ON, "203.0.113.7").await;
    maria.send(offer_to(&front.id, &ticket("7"), &key)).await;
    let ph = expect_punch(&front, OFFER).await;
    let seen = AddrMangle::decode(&ph.socket_addr).to_string();
    assert_eq!(seen, maria.keyed_as, "the device is told the proxy-forwarded IP and this connection's own port");
    assert!(!seen.ends_with(":0"));
    maria.send(candidate(&front.id, &[], "maria-1")).await;
    expect_candidate(front.forwarded(3000).await, "maria-1");

    // ... and to no other device, though the person is signed in.
    maria.send(candidate(&server.id, &[], "stray")).await;
    assert!(server.forwarded(800).await.is_none(), "a route reaches only the device offered to");

    // The device's candidates reach the controller whose address they name.
    let _t = device_sends(PORT_ON, candidate("", &ph.socket_addr, "front-1")).await;
    expect_candidate(maria.recv(3000).await, "front-1");

    // María offers to the server, outside her scope: refused, the server hears
    // nothing, and that connection has no route even to a device she may reach.
    let mut refused = Web::open(PORT_ON, "203.0.113.8").await;
    refused.send(offer_to(&server.id, &ticket("7"), &key)).await;
    expect_refusal(&mut refused, DENY_SCOPE).await;
    assert!(server.forwarded(500).await.is_none(), "nothing reaches the server");
    refused.send(candidate(&server.id, &[], "stray-2")).await;
    refused.send(candidate(&front.id, &[], "stray-3")).await;
    assert!(server.forwarded(500).await.is_none() && front.forwarded(500).await.is_none(), "a refused offer opens no route");
    let _t = device_sends(PORT_ON, candidate("", &AddrMangle::encode(refused.keyed_as.parse().unwrap()), "to-refused")).await;
    assert!(refused.recv(800).await.is_none(), "nothing is delivered to a connection without a route");

    // Nobody signed in (approved mode, no IP match): refused, nothing sent.
    let mut anon = Web::open(PORT_ON, "203.0.113.9").await;
    anon.send(offer_to(&front.id, "", &key)).await;
    expect_refusal(&mut anon, DENY_UNAPPROVED).await;
    assert!(front.forwarded(500).await.is_none());

    // The administrator reaches the server by offer.
    let mut admin_web = Web::open(PORT_ON, "203.0.113.10").await;
    admin_web.send(offer_to(&server.id, &ticket("8"), &key)).await;
    expect_punch(&server, OFFER).await;

    // The refusal reached the alarm log's feed (type 102 on the console side).
    sleep(Duration::from_millis(2500)).await;
    let reports = console.lock().unwrap().refusals.clone();
    assert!(
        reports.iter().any(|r| r["to"] == "sc-server" && r["from"] == "web" && r["reason"] == "outside scope" && r["user_name"] == "mperez"),
        "the out-of-scope offer is reported, got {reports:?}"
    );
}

#[tokio::test]
async fn signalling_is_off_unless_switched_on() {
    let (url, _console) = start_console(hte_policy(true));
    let dir = tempfile::tempdir().unwrap();
    let (_hbbs, key) = spawn_hbbs(dir.path(), PORT_OFF, &url, false);
    wait_policy(PORT_OFF, "scope=on people=2").await;
    let front = Peer::register(PORT_OFF, "sc-front").await;

    // The request still goes through; the offer does not travel.
    let mut maria = Web::open(PORT_OFF, "203.0.113.7").await;
    maria.send(offer_to(&front.id, &ticket("7"), &key)).await;
    let ph = expect_punch(&front, "").await;
    maria.send(candidate(&front.id, &[], "maria-1")).await;
    assert!(front.forwarded(800).await.is_none(), "no candidates to the device");

    // An answer and candidates from the device are not passed on either.
    let mut sent = RendezvousMessage::new();
    sent.set_punch_hole_sent(PunchHoleSent {
        socket_addr: ph.socket_addr.clone(),
        id: front.id.clone(),
        version: "1.5.0".to_owned(),
        webrtc_sdp_answer: ANSWER.to_owned(),
        ..Default::default()
    });
    let _t = device_sends(PORT_OFF, sent).await;
    match maria.recv(3000).await.map(|m| m.union) {
        Some(Some(rendezvous_message::Union::PunchHoleResponse(r))) => assert!(r.webrtc_sdp_answer.is_empty(), "no answer passed on"),
        other => panic!("expected the plain punch hole response, got {other:?}"),
    }
    let _t = device_sends(PORT_OFF, candidate("", &ph.socket_addr, "front-1")).await;
    assert!(maria.recv(800).await.is_none(), "no candidates to the controller");
}

/// Behind a proxy every browser arrives from one IP. Each connection must keep
/// its own reply route: a refusal, a relay response and a punch go to the
/// connection that asked.
#[tokio::test]
async fn clients_behind_one_proxy_ip_keep_their_own_replies() {
    let (url, _console) = start_console(hte_policy(true));
    let dir = tempfile::tempdir().unwrap();
    let (_hbbs, key) = spawn_hbbs(dir.path(), PORT_KEYS, &url, true);
    wait_policy(PORT_KEYS, "scope=on people=2").await;
    let front = Peer::register(PORT_KEYS, "sc-front").await;
    let server = Peer::register(PORT_KEYS, "sc-server").await;

    let mut maria = Web::open(PORT_KEYS, "198.51.100.4").await;
    let mut boss = Web::open(PORT_KEYS, "198.51.100.4").await;
    assert_ne!(maria.keyed_as, boss.keyed_as, "same IP, own ports");

    // Both ask at once; each is answered on its own connection.
    maria.send(offer_to(&server.id, &ticket("7"), &key)).await;
    boss.send(offer_to(&server.id, &ticket("8"), &key)).await;
    expect_refusal(&mut maria, DENY_SCOPE).await;
    let ph = expect_punch(&server, OFFER).await;
    assert_eq!(AddrMangle::decode(&ph.socket_addr).to_string(), boss.keyed_as);
    assert!(boss.recv(500).await.is_none(), "the administrator is not refused with María's answer");

    // The device answers the administrator's offer; only that connection hears.
    let mut sent = RendezvousMessage::new();
    sent.set_punch_hole_sent(PunchHoleSent {
        socket_addr: ph.socket_addr.clone(),
        id: server.id.clone(),
        version: "1.5.0".to_owned(),
        webrtc_sdp_answer: ANSWER.to_owned(),
        ..Default::default()
    });
    let _t = device_sends(PORT_KEYS, sent).await;
    match boss.recv(3000).await.map(|m| m.union) {
        Some(Some(rendezvous_message::Union::PunchHoleResponse(r))) => assert_eq!(r.webrtc_sdp_answer, ANSWER),
        other => panic!("expected the answer, got {other:?}"),
    }
    assert!(maria.recv(500).await.is_none(), "María does not receive the administrator's answer");

    // Relay by the web client: the response finds the asking connection.
    let mut rq = RendezvousMessage::new();
    rq.set_request_relay(RequestRelay {
        id: front.id.clone(),
        uuid: "web-relay-1".to_owned(),
        token: ticket("7"),
        ..Default::default()
    });
    // (A connection's first request takes its reply route; María's refusal above used hers.)
    let mut maria = Web::open(PORT_KEYS, "198.51.100.4").await;
    maria.send(rq).await;
    let asked = match front.forwarded(3000).await.map(|m| m.union) {
        Some(Some(rendezvous_message::Union::RequestRelay(rf))) => rf,
        other => panic!("the front desk should be asked for a relay, got {other:?}"),
    };
    assert_eq!(AddrMangle::decode(&asked.socket_addr).to_string(), maria.keyed_as);
    let mut rr = RendezvousMessage::new();
    rr.set_relay_response(RelayResponse {
        socket_addr: asked.socket_addr.clone(),
        uuid: asked.uuid.clone(),
        union: Some(relay_response::Union::Id(front.id.clone())),
        ..Default::default()
    });
    let _t = device_sends(PORT_KEYS, rr).await;
    match maria.recv(3000).await.map(|m| m.union) {
        Some(Some(rendezvous_message::Union::RelayResponse(r))) => assert_eq!(r.uuid, "web-relay-1"),
        other => panic!("expected the relay response, got {other:?}"),
    }
    assert!(boss.recv(500).await.is_none(), "the other connection behind the same IP hears nothing");
}
