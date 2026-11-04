//! HTE (2026-11-04): a `db_v2.sqlite3` written before sqlx 0.8 (the fixture is a copy made by sqlx 0.6, the engine of hbbs up to 1.3.0)
//! is read by the new hbbs as before: its devices keep their ID, uuid and key, a device with another uuid is still refused its ID, a
//! new device is added, and all of it is still there after a restart. Works on a copy; never a live database.

use hbb_common::{
    protobuf::Message as _,
    rendezvous_proto::*,
    tokio::{
        self,
        net::UdpSocket,
        time::{sleep, timeout},
    },
};
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

const PORT: u16 = 31396;

struct Hbbs(Child);
impl Drop for Hbbs {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(dir: &Path) -> Hbbs {
    Hbbs(
        Command::new(env!("CARGO_BIN_EXE_hbbs"))
            .current_dir(dir)
            .args(["-p", &PORT.to_string(), "-k", "_"])
            .env("TEST_HBBS", "no")
            .env("DB_URL", "./db_v2.sqlite3")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}

/// RegisterPk for `id` with `uuid` and a 32-byte key of `pk_byte`s, until hbbs answers.
async fn register(id: &str, uuid: &str, pk_byte: u8) -> register_pk_response::Result {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut msg = RendezvousMessage::new();
    msg.set_register_pk(RegisterPk {
        id: id.to_owned(),
        uuid: uuid.as_bytes().to_vec().into(),
        pk: vec![pk_byte; 32].into(),
        ..Default::default()
    });
    let bytes = msg.write_to_bytes().unwrap();
    let mut buf = [0u8; 1024];
    for _ in 0..60 {
        sock.send_to(&bytes, ("127.0.0.1", PORT)).await.ok();
        if let Ok(Ok((n, _))) = timeout(Duration::from_millis(250), sock.recv_from(&mut buf)).await {
            let reply = RendezvousMessage::parse_from_bytes(&buf[..n]).unwrap();
            if reply.has_register_pk_response() {
                return reply.register_pk_response().result.enum_value().unwrap();
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("hbbs never answered");
}

#[tokio::test]
async fn a_database_from_before_sqlx_0_8_reads_as_before() {
    use register_pk_response::Result::*;
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/peers-1.3.0.sqlite3"),
        dir.path().join("db_v2.sqlite3"),
    )
    .unwrap();
    {
        let _hbbs = start(dir.path());
        // The devices of the old file, with the uuid and key they registered with.
        assert_eq!(register("123456781", "machine-one", 7).await, OK);
        assert_eq!(register("123456782", "machine-two", 7).await, OK);
        // Another machine claiming a known ID is refused.
        assert_eq!(register("123456781", "someone-else", 7).await, UUID_MISMATCH);
        // A new device is stored.
        assert_eq!(register("123456783", "machine-three", 9).await, OK);
    }
    // After a restart (the first hbbs is gone): the old devices and the new one are still known by their uuid.
    let _hbbs = start(dir.path());
    assert_eq!(register("123456781", "someone-else", 7).await, UUID_MISMATCH);
    assert_eq!(register("123456783", "machine-three", 9).await, OK);
    assert_eq!(register("123456783", "other", 9).await, UUID_MISMATCH);
}
