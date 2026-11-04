//! The device page's "Release ID" button: asks hbbs, over its loopback admin port, to forget a device so another
//! machine can register under that ID (`release-id <id>`, hbbs 1.4.0).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// `HTE_CONSOLE_HBBS_ADMIN` (default `127.0.0.1:21115`): hbbs's admin port, one below the ID server's.
pub fn address() -> String {
    crate::envvar::var("HTE_CONSOLE_HBBS_ADMIN").ok().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| "127.0.0.1:21115".into())
}

/// What hbbs answered, as a sentence for the person who pressed the button.
pub fn release(addr: &str, id: &str) -> Result<String, String> {
    // The id goes into a command line: only what an ID can be.
    if id.is_empty() || id.len() > 64 || !id.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-') {
        return Err("This ID cannot be released.".into());
    }
    let sa: SocketAddr = addr.parse().map_err(|_| "The ID server's admin address is not valid.".to_string())?;
    let unreachable = || "The ID server did not answer; nothing was changed.".to_string();
    let mut s = TcpStream::connect_timeout(&sa, Duration::from_secs(5)).map_err(|_| unreachable())?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    s.set_write_timeout(Some(Duration::from_secs(5))).ok();
    s.write_all(format!("release-id {id}\n").as_bytes()).map_err(|_| unreachable())?;
    let mut buf = Vec::new();
    s.take(4096).read_to_end(&mut buf).map_err(|_| unreachable())?;
    parse(id, &String::from_utf8_lossy(&buf))
}

fn parse(id: &str, reply: &str) -> Result<String, String> {
    let line = reply.lines().next().unwrap_or("").trim();
    if line == format!("OK {id}") {
        Ok(format!("ID {id} was released; another machine can take it now."))
    } else if line == format!("OK {id} online") {
        Ok(format!("ID {id} was released, but the machine was online and may register again at once if it is still running."))
    } else if line == format!("NOT_FOUND {id}") {
        Err(format!("The ID server does not know {id}."))
    } else if line.starts_with("ERROR") {
        Err("The ID server could not release it; see its log.".into())
    } else {
        Err("The ID server gave no usable answer; nothing was changed.".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn fake(reply: &'static str) -> (String, std::thread::JoinHandle<String>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut b = [0u8; 256];
            let n = s.read(&mut b).unwrap();
            s.write_all(reply.as_bytes()).unwrap();
            String::from_utf8_lossy(&b[..n]).into_owned()
        });
        (addr, h)
    }

    #[test]
    fn sends_the_command_and_reads_the_answers() {
        let (a, h) = fake("OK 1001\n");
        assert!(release(&a, "1001").unwrap().contains("released"));
        assert_eq!(h.join().unwrap(), "release-id 1001\n");
        let (a, _) = fake("OK 1001 online\n");
        assert!(release(&a, "1001").unwrap().contains("online"));
        let (a, _) = fake("NOT_FOUND 1001\n");
        assert!(release(&a, "1001").unwrap_err().contains("does not know"));
        let (a, _) = fake("ERROR disk\n");
        assert!(release(&a, "1001").is_err());
    }

    #[test]
    fn refuses_what_is_not_an_id_and_reports_a_dead_port() {
        assert!(release("127.0.0.1:1", "1001 h").is_err());
        assert!(release("127.0.0.1:1", "").is_err());
        assert!(release("127.0.0.1:1", "1001").unwrap_err().contains("did not answer"));
    }
}
