//! HTE (2026-11-04): the key files of a deployed server still start hbbs and hbbr cleanly under 1.4.0's rules (an `id_ed25519` that
//! cannot be read or is not a key stops the server; a `.pub` that does not match is rewritten; a loose mode is set to 0600). The
//! layout is the one `docker/hte/entrypoint.sh` writes into the mounted directory: base64, no trailing newline, secret 0600,
//! public 0644, owned by the container's uid. Only keys made here; never a live key.

use hbb_common::{base64, sodiumoxide::crypto::sign};
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::Duration,
};

const PORT_HBBS: u16 = 31376;
const PORT_HBBR: u16 = 31386;

fn pair() -> (String, String) {
    let (pk, sk) = sign::gen_keypair();
    (base64::encode(&pk), base64::encode(&sk))
}

fn lay_out(dir: &Path, public: &str, secret: &str, secret_mode: u32) {
    fs::write(dir.join("id_ed25519"), secret).unwrap();
    fs::set_permissions(dir.join("id_ed25519"), fs::Permissions::from_mode(secret_mode)).unwrap();
    fs::write(dir.join("id_ed25519.pub"), public).unwrap();
    fs::set_permissions(dir.join("id_ed25519.pub"), fs::Permissions::from_mode(0o644)).unwrap();
}

struct Run {
    child: Child,
    lines: mpsc::Receiver<String>,
}
impl Drop for Run {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// hbbs or hbbr as the image starts them: `-k _` in the key directory.
fn run(bin: &str, dir: &Path, port: u16) -> Run {
    let mut child = Command::new(bin)
        .current_dir(dir)
        .args(["-p", &port.to_string(), "-k", "_"])
        .env("TEST_HBBS", "no")
        .env("DB_URL", "./db_v2.sqlite3")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (tx, rx) = mpsc::channel();
    for out in [child.stdout.take().map(|s| Box::new(s) as Box<dyn std::io::Read + Send>), child.stderr.take().map(|s| Box::new(s) as Box<dyn std::io::Read + Send>)]
        .into_iter()
        .flatten()
    {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                tx.send(line).ok();
            }
        });
    }
    Run { child, lines: rx }
}

/// The key the server logs once it is up, or None when it exited first.
fn started_with(r: &mut Run) -> Option<String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        if let Ok(line) = r.lines.recv_timeout(Duration::from_millis(100)) {
            if let Some(k) = line.split("Key: ").nth(1) {
                return Some(k.trim().to_owned());
            }
        }
        if r.child.try_wait().unwrap().is_some() {
            return None;
        }
    }
    panic!("neither a key nor an exit in 20 s");
}

fn exited(r: &mut Run) -> bool {
    for _ in 0..100 {
        if r.child.try_wait().unwrap().is_some() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

#[test]
fn the_entrypoints_key_layout_starts_both_servers_and_is_left_alone() {
    let (public, secret) = pair();
    for (bin, port) in [(env!("CARGO_BIN_EXE_hbbs"), PORT_HBBS), (env!("CARGO_BIN_EXE_hbbr"), PORT_HBBR)] {
        let dir = tempfile::tempdir().unwrap();
        lay_out(dir.path(), &public, &secret, 0o600);
        let mut r = run(bin, dir.path(), port);
        assert_eq!(started_with(&mut r).as_deref(), Some(public.as_str()), "{bin}");
        assert_eq!(fs::read_to_string(dir.path().join("id_ed25519")).unwrap(), secret);
        assert_eq!(fs::read_to_string(dir.path().join("id_ed25519.pub")).unwrap(), public, "the public file is not rewritten");
        assert_eq!(fs::metadata(dir.path().join("id_ed25519")).unwrap().permissions().mode() & 0o777, 0o600);
        drop(r);
    }
}

#[test]
fn a_loose_secret_a_newline_and_a_stale_public_file_are_put_right() {
    let (public, secret) = pair();
    let (other_public, _) = pair();
    let dir = tempfile::tempdir().unwrap();
    // A hand-copied key: a trailing newline on both files, group-readable, and a .pub of another key.
    lay_out(dir.path(), &other_public, &format!("{secret}\n"), 0o640);
    let mut r = run(env!("CARGO_BIN_EXE_hbbs"), dir.path(), PORT_HBBS + 20);
    assert_eq!(started_with(&mut r).as_deref(), Some(public.as_str()), "the private key decides");
    assert_eq!(fs::read_to_string(dir.path().join("id_ed25519.pub")).unwrap(), public, "the stale .pub is rewritten");
    assert_eq!(fs::metadata(dir.path().join("id_ed25519")).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(fs::read_to_string(dir.path().join("id_ed25519")).unwrap(), format!("{secret}\n"), "the secret is never rewritten");
    drop(r);

    // A trailing newline alone does not make the .pub stale.
    let dir = tempfile::tempdir().unwrap();
    lay_out(dir.path(), &format!("{public}\n"), &secret, 0o600);
    let mut r = run(env!("CARGO_BIN_EXE_hbbs"), dir.path(), PORT_HBBS + 40);
    assert_eq!(started_with(&mut r).as_deref(), Some(public.as_str()));
    assert_eq!(fs::read_to_string(dir.path().join("id_ed25519.pub")).unwrap(), format!("{public}\n"));
}

#[test]
fn a_secret_that_is_not_a_key_stops_the_servers_and_nothing_is_written() {
    let (public, _) = pair();
    for (bin, port) in [(env!("CARGO_BIN_EXE_hbbs"), PORT_HBBS + 60), (env!("CARGO_BIN_EXE_hbbr"), PORT_HBBR + 20)] {
        let dir = tempfile::tempdir().unwrap();
        lay_out(dir.path(), &public, "this is not base64 key material", 0o600);
        let mut r = run(bin, dir.path(), port);
        assert_eq!(started_with(&mut r), None, "{bin} must not start on a bad key");
        assert!(exited(&mut r));
        assert_eq!(fs::read_to_string(dir.path().join("id_ed25519.pub")).unwrap(), public, "the public file is left as it was");
        assert_eq!(fs::read_to_string(dir.path().join("id_ed25519")).unwrap(), "this is not base64 key material");
    }
}
