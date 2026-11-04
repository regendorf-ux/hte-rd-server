//! HTE (2026-11-04): per-person reach comes before UDP and IPv6 hole punching (upstream 1.4.0). Against a real hbbs and a fake
//! console: a request outside the person's scope is refused before any UDP port or IPv6 address of the controller is passed to the
//! device, over TCP and over UDP; nothing a refused controller or anyone else sends afterwards opens a route that carries the device's
//! addresses back; an in-scope request still gets the full UDP and IPv6 punch. The controller is on a non-loopback address and the
//! device on 127.0.0.1, so the two are not taken for one LAN (as in udp_punch.rs).

use axum::{
    extract::Extension,
    http::{HeaderMap, HeaderValue, StatusCode},
    routing::{get, post},
    Router,
};
use hbb_common::{
    bytes::Bytes,
    bytes_codec::BytesCodec,
    futures_util::{SinkExt, StreamExt},
    protobuf::Message as _,
    rendezvous_proto::*,
    tokio::{
        self,
        net::{TcpStream, UdpSocket},
        time::{sleep, timeout},
    },
    tokio_util::codec::Framed,
    AddrMangle,
};
use sodiumoxide::crypto::{auth::hmacsha256, hash::sha256};
use std::{
    io::{BufRead, BufReader},
    net::{IpAddr, SocketAddr, UdpSocket as StdUdp},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// Clear of every other test file's ports (each hbbs takes port-1 and port+2).
const PORT_TCP: i32 = 31346;
const PORT_UDP: i32 = 31356;
const PORT_OFF: i32 = 31366;

const SECRET: &str = "test-link-secret";
const DENY_SCOPE: &str = "You are not given access to this device";
const DENY_UNAPPROVED: &str = "This device is not approved on this server";

type Shared = Arc<Mutex<String>>;

async fn policy(Extension(st): Extension<Shared>, headers: HeaderMap) -> (StatusCode, HeaderMap, String) {
    let mut out = HeaderMap::new();
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(&format!("Bearer {SECRET}")) {
        return (StatusCode::UNAUTHORIZED, out, String::new());
    }
    out.insert("etag", HeaderValue::from_static("\"v1\""));
    (StatusCode::OK, out, st.lock().unwrap().clone())
}

async fn ok() -> StatusCode {
    StatusCode::OK
}

fn start_console(body: serde_json::Value) -> String {
    let st: Shared = Arc::new(Mutex::new(body.to_string()));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route("/api/server/policy", get(policy))
        .route("/api/server/refusals", post(ok))
        .route("/api/server/local-addrs", post(ok))
        .layer(Extension(st));
    tokio::spawn(async move {
        axum::Server::from_tcp(listener).unwrap().serve(app.into_make_service()).await.ok();
    });
    url
}

struct Hbbs(Child);
impl Drop for Hbbs {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_hbbs(dir: &std::path::Path, port: i32, console: &str, envs: &[(&str, &str)]) -> (Hbbs, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hbbs"));
    cmd.current_dir(dir)
        .args(["-p", &port.to_string(), "-k", "_"])
        .env("TEST_HBBS", "no")
        .env_remove("ALWAYS_USE_RELAY")
        .env_remove("UDP_PUNCH")
        .env_remove("IPV6_PUNCH")
        .env("CORTENDESK_CONSOLE_URL", console)
        .env("CORTENDESK_SERVER_SECRET", SECRET)
        .env("CORTENDESK_POLICY_INTERVAL", "1")
        .envs(envs.iter().copied())
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
    use hbb_common::tokio::io::{AsyncReadExt, AsyncWriteExt};
    let Ok(mut s) = TcpStream::connect(format!("127.0.0.1:{}", port - 1)).await else {
        return String::new();
    };
    s.write_all(cmd.as_bytes()).await.ok();
    let mut out = String::new();
    timeout(Duration::from_secs(2), s.read_to_string(&mut out)).await.ok();
    out
}

async fn wait_policy(port: i32, needle: &str) {
    for _ in 0..100 {
        if admin(port, "pol").await.contains(needle) {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("policy never showed {needle:?}");
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

/// Two people: María (user 7) reaches only `sp-front`, the administrator (user 8) everything.
fn policy_body(enforce: bool) -> serde_json::Value {
    serde_json::json!({
        "mode": "approved",
        "allow": ["sp-front", "sp-server", "sp-maria", "sp-jdoe"],
        "incoming_only": [],
        "tokens": {sha256_hex("token-maria"): "sp-maria", sha256_hex("token-jdoe"): "sp-jdoe"},
        "ip_match": false,
        "scope": {
            "enforce": enforce,
            "users": {
                "7": {"name": "mperez", "all": false, "devices": ["sp-front"]},
                "8": {"name": "jdoe", "all": true, "devices": []},
            },
            "token_users": {sha256_hex("token-maria"): "7", sha256_hex("token-jdoe"): "8"}
        }
    })
}

/// An address of this machine other than loopback.
fn non_loopback_ip() -> IpAddr {
    let socket = StdUdp::bind("0.0.0.0:0").unwrap();
    socket.connect("192.0.2.1:9").unwrap();
    let ip = socket.local_addr().unwrap().ip();
    assert!(!ip.is_loopback() && !ip.is_unspecified(), "need a non-loopback address");
    ip
}

fn v6(s: &str) -> Bytes {
    AddrMangle::encode(s.parse::<SocketAddr>().unwrap()).into()
}

async fn udp_send(socket: &UdpSocket, port: i32, msg: &RendezvousMessage) {
    socket.send_to(&msg.write_to_bytes().unwrap(), ("127.0.0.1", port as u16)).await.unwrap();
}

/// The next message on `socket` other than a registration reply.
async fn udp_recv(socket: &UdpSocket, ms: u64) -> Option<RendezvousMessage> {
    let mut buf = [0u8; 2048];
    loop {
        let (n, _) = timeout(Duration::from_millis(ms), socket.recv_from(&mut buf)).await.ok()?.ok()?;
        let msg = RendezvousMessage::parse_from_bytes(&buf[..n]).ok()?;
        if !msg.has_register_pk_response() && !msg.has_register_peer_response() {
            return Some(msg);
        }
    }
}

/// A device registered over UDP from 127.0.0.1.
async fn device(port: i32, id: &str) -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut msg = RendezvousMessage::new();
    msg.set_register_pk(RegisterPk {
        id: id.to_owned(),
        uuid: id.as_bytes().to_vec().into(),
        pk: vec![7; 32].into(),
        ..Default::default()
    });
    udp_send(&socket, port, &msg).await;
    let mut buf = [0u8; 256];
    let (n, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await.unwrap().unwrap();
    let reply = RendezvousMessage::parse_from_bytes(&buf[..n]).unwrap();
    assert_eq!(reply.register_pk_response().result.enum_value(), Ok(register_pk_response::Result::OK));
    socket
}

type Tcp = Framed<TcpStream, BytesCodec>;

async fn controller(port: i32) -> Tcp {
    let stream = TcpStream::connect((non_loopback_ip(), port as u16)).await.unwrap();
    Framed::new(stream, BytesCodec::new())
}

async fn tcp_send(tcp: &mut Tcp, msg: &RendezvousMessage) {
    tcp.send(Bytes::from(msg.write_to_bytes().unwrap())).await.unwrap();
}

/// The next message on `tcp`, skipping the server's key exchange offer.
async fn tcp_recv(tcp: &mut Tcp, ms: u64) -> Option<RendezvousMessage> {
    loop {
        let bytes = timeout(Duration::from_millis(ms), tcp.next()).await.ok()??.ok()?;
        let msg = RendezvousMessage::parse_from_bytes(&bytes).ok()?;
        if !msg.has_key_exchange() {
            return Some(msg);
        }
    }
}

/// A 1.5 controller's request, offering UDP port 40000 and a global IPv6 address.
fn request(key: &str, id: &str, token: &str) -> RendezvousMessage {
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_request(PunchHoleRequest {
        id: id.to_owned(),
        token: token.to_owned(),
        licence_key: key.to_owned(),
        version: "1.5.0".to_owned(),
        udp_port: 40000,
        socket_addr_v6: v6("[2001:db8::5]:5000"),
        ..Default::default()
    });
    msg
}

fn hole_sent(socket_addr: Bytes, id: &str, socket_addr_v6: Bytes) -> RendezvousMessage {
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_sent(PunchHoleSent {
        socket_addr,
        id: id.to_owned(),
        version: "1.5.0".to_owned(),
        socket_addr_v6,
        ..Default::default()
    });
    msg
}

fn refusal_text(msg: &RendezvousMessage) -> String {
    let r = msg.punch_hole_response();
    assert!(r.socket_addr.is_empty() && r.socket_addr_v6.is_empty(), "a refusal carries no address");
    r.other_failure.clone()
}

/// Over TCP. Out of scope, signed out and stranger: refused, the device hears nothing (no UDP port, no IPv6 address of the
/// controller), and a `PunchHoleSent` made up for the refused request returns no address to the controller. In scope: the full
/// punch, to the device and back.
#[tokio::test]
async fn a_refused_request_passes_no_udp_port_or_ipv6_address() {
    let url = start_console(policy_body(true));
    let dir = tempfile::tempdir().unwrap();
    let (_hbbs, key) = spawn_hbbs(dir.path(), PORT_TCP, &url, &[]);
    wait_policy(PORT_TCP, "scope=on people=2").await;
    let server = device(PORT_TCP, "sp-server").await;
    let front = device(PORT_TCP, "sp-front").await;

    for (who, token) in [("María's token", "token-maria".to_string()), ("María's web client", ticket("7"))] {
        let mut a = controller(PORT_TCP).await;
        tcp_send(&mut a, &request(&key, "sp-server", &token)).await;
        let text = refusal_text(&tcp_recv(&mut a, 3000).await.unwrap_or_else(|| panic!("{who}: no answer")));
        assert!(text.contains(DENY_SCOPE), "{who}: {text}");
        assert!(udp_recv(&server, 500).await.is_none(), "{who}: the device was told something");
        // A forger answers as the device with an IPv6 address, from a socket the device does not own: no route exists, so
        // nothing goes back to the controller.
        let forger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let aimed = AddrMangle::encode(SocketAddr::new(non_loopback_ip(), 1)).into();
        udp_send(&forger, PORT_TCP, &hole_sent(aimed, "sp-server", v6("[2001:db8::6]:6000"))).await;
        assert!(tcp_recv(&mut a, 500).await.is_none(), "{who}: an address came back");
    }

    // Nobody signed in (approved mode, no IP match).
    let mut a = controller(PORT_TCP).await;
    tcp_send(&mut a, &request(&key, "sp-front", "")).await;
    let text = refusal_text(&tcp_recv(&mut a, 3000).await.expect("answer"));
    assert!(text.contains(DENY_UNAPPROVED), "{text}");
    assert!(udp_recv(&front, 500).await.is_none());

    // In scope: María to the front desk, and the administrator to the server, get the whole punch.
    for (token, id, dev) in [("token-maria", "sp-front", &front), ("token-jdoe", "sp-server", &server)] {
        let mut a = controller(PORT_TCP).await;
        tcp_send(&mut a, &request(&key, id, token)).await;
        let ph = udp_recv(dev, 3000).await.expect("punch hole").punch_hole().clone();
        assert_eq!(ph.udp_port, 40000, "{id}");
        assert_eq!(AddrMangle::decode(&ph.socket_addr_v6), "[2001:db8::5]:5000".parse().unwrap(), "{id}");
        let punch = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp_send(&punch, PORT_TCP, &hole_sent(ph.socket_addr.clone(), id, v6("[2001:db8::6]:6000"))).await;
        let resp = tcp_recv(&mut a, 3000).await.expect("response").punch_hole_response().clone();
        assert!(resp.is_udp, "{id}");
        assert_eq!(AddrMangle::decode(&resp.socket_addr_v6), "[2001:db8::6]:6000".parse().unwrap(), "{id}");
    }
}

/// Upstream 1.4.0 does not take a punch request over UDP at all (`handle_udp` drops it): not from a person in scope, not from one
/// outside it, not from nobody. Nothing reaches the device and nothing is answered, so the UDP port and IPv6 address that a request
/// carries have no way past the reach rule on that path. This test fails if a later upstream accepts one: it would then need the
/// same judgement as the TCP path.
#[tokio::test]
async fn a_udp_request_reaches_no_device() {
    let url = start_console(policy_body(true));
    let dir = tempfile::tempdir().unwrap();
    let (_hbbs, key) = spawn_hbbs(dir.path(), PORT_UDP, &url, &[]);
    wait_policy(PORT_UDP, "scope=on people=2").await;
    let server = device(PORT_UDP, "sp-server").await;
    let front = device(PORT_UDP, "sp-front").await;
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    for (token, id) in [("", "sp-server"), ("token-maria", "sp-server"), ("token-maria", "sp-front"), ("token-jdoe", "sp-server")] {
        udp_send(&a, PORT_UDP, &request(&key, id, token)).await;
        assert!(udp_recv(&server, 400).await.is_none(), "{token:?} -> {id}: the server was told something");
        assert!(udp_recv(&front, 100).await.is_none(), "{token:?} -> {id}: the front desk was told something");
        assert!(udp_recv(&a, 100).await.is_none(), "{token:?} -> {id}: something was answered");
    }
}

/// Enforcement off is today's behaviour: the person's token is no longer judged by scope, and the punch goes through.
#[tokio::test]
async fn without_enforcement_the_punch_is_not_judged_by_scope() {
    let url = start_console(policy_body(false));
    let dir = tempfile::tempdir().unwrap();
    let (_hbbs, key) = spawn_hbbs(dir.path(), PORT_OFF, &url, &[]);
    wait_policy(PORT_OFF, "scope=off").await;
    let server = device(PORT_OFF, "sp-server").await;
    let mut a = controller(PORT_OFF).await;
    tcp_send(&mut a, &request(&key, "sp-server", "token-maria")).await;
    let ph = udp_recv(&server, 3000).await.expect("punch hole").punch_hole().clone();
    assert_eq!(ph.udp_port, 40000);
}
