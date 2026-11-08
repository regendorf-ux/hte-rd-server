//! `App\Services\MailSettings` (v1.15.0-hte.1) and the SMTP transport the previous console borrows from Symfony Mailer: the relay in
//! the settings table (`smtp_*`, the password `Crypt`-encrypted), one synchronous send with a 10-second socket timeout,
//! and the health record (`smtp_ok_at`, `smtp_failed_at`, `smtp_last_error`) that `RequireMailHealthy` reads.
//!
//! The transport, as Symfony's `EsmtpTransport` does it: `ssl` = TLS from the first byte (smtps); otherwise plain TCP
//! and STARTTLS whenever the server offers it (Symfony's auto-TLS, so "none" is not plaintext against a relay that
//! offers TLS), the certificate verified against the public roots (Symfony verifies by default); then AUTH when a
//! username is set (LOGIN, else PLAIN: Symfony also knows CRAM-MD5 and XOAUTH2, which no relay at HTE needs), MAIL
//! FROM, RCPT TO, DATA, QUIT. The message is `text/html; charset=utf-8`, quoted-printable, as a the previous console's template mailable sends it.
//!
//! A send happens on the caller's thread. Where the caller holds the database lock (a page handler) the device API
//! waits for it: at most the 10-second timeout per step, and only when the relay is slow. Nothing here logs the
//! password, a token or a message body.

use crate::laravel::Encrypter;
use crate::php::{self, Fault};
use crate::sqlite as db;
use base64::Engine;
use rusqlite::Connection;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(10);

/// The relay as the settings table describes it.
#[derive(Clone, Default)]
pub struct MailConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub username: String,
    /// Decrypted; never logged.
    pub password: String,
    /// starttls | ssl | none
    pub encryption: String,
    pub from_address: String,
    pub from_name: String,
    /// The line at the bottom of every message (CortenDesk 1.22.0); empty keeps "Sent by <app> at <address>".
    pub footer: String,
}

impl std::fmt::Debug for MailConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailConfig").field("host", &self.host).field("port", &self.port).field("encryption", &self.encryption).finish_non_exhaustive()
    }
}

fn setting(c: &Connection, key: &str) -> Result<String, Fault> {
    Ok(String::from_utf8_lossy(php::trim(&db::setting(c, key, "")?)).into_owned())
}

impl MailConfig {
    pub fn load(c: &Connection, crypt: &Encrypter) -> Result<MailConfig, Fault> {
        let stored = setting(c, "smtp_password")?;
        let password = if stored.is_empty() {
            String::new()
        } else {
            match crypt.decrypt_string(stored.as_bytes()) {
                Ok(p) => String::from_utf8_lossy(&p).into_owned(),
                Err(_) => stored,
            }
        };
        let port = setting(c, "smtp_port")?.parse::<i64>().ok().filter(|p| *p > 0 && *p < 65536).unwrap_or(587) as u16;
        let enc = setting(c, "smtp_encryption")?;
        Ok(MailConfig {
            enabled: setting(c, "smtp_enabled")? == "1",
            host: setting(c, "smtp_host")?,
            port,
            username: setting(c, "smtp_username")?,
            password,
            encryption: if ["starttls", "ssl", "none"].contains(&enc.as_str()) { enc } else { "starttls".into() },
            from_address: setting(c, "smtp_from_address")?,
            from_name: setting(c, "smtp_from_name")?,
            footer: setting(c, "smtp_footer")?,
        })
    }

    /// `isConfigured()`: a host and a From address.
    pub fn is_configured(&self) -> bool {
        !self.host.is_empty() && !self.from_address.is_empty()
    }

    /// `isEnabled()`
    pub fn is_enabled(&self) -> bool {
        self.enabled && self.is_configured()
    }
}

/// `MailSettings::isEnabled()` straight from the settings.
pub fn enabled(c: &Connection) -> Result<bool, Fault> {
    Ok(setting(c, "smtp_enabled")? == "1" && !setting(c, "smtp_host")?.is_empty() && !setting(c, "smtp_from_address")?.is_empty())
}

/// `isHealthy()`: no failure recorded, or a success since the last one.
pub fn is_healthy(c: &Connection) -> Result<bool, Fault> {
    let failed = setting(c, "smtp_failed_at")?;
    if failed.is_empty() {
        return Ok(true);
    }
    let ok = setting(c, "smtp_ok_at")?;
    Ok(!ok.is_empty() && ok >= failed)
}

pub fn record_success(c: &Connection, now: i64) -> Result<(), Fault> {
    crate::backup::put_setting(c, "smtp_ok_at", &crate::laravel::ts(now), now).map_err(Fault::Other)
}

pub fn record_failure(c: &Connection, error: &str, now: i64) -> Result<(), Fault> {
    crate::backup::put_setting(c, "smtp_failed_at", &crate::laravel::ts(now), now).map_err(Fault::Other)?;
    let e: String = error.chars().take(300).collect();
    crate::backup::put_setting(c, "smtp_last_error", &e, now).map_err(Fault::Other)
}

/// One message.
pub struct Message {
    pub to: String,
    pub subject: String,
    pub html: String,
}

/// `MailSettings::send()`: only when enabled; a failure is recorded and answered false, never raised.
pub fn send(c: &Connection, crypt: &Encrypter, app_name: &str, local_domain: &str, msg: &Message, now: i64) -> Result<bool, Fault> {
    let cfg = MailConfig::load(c, crypt)?;
    if !cfg.is_enabled() {
        return Ok(false);
    }
    match deliver(&cfg, app_name, local_domain, msg, now) {
        Ok(()) => {
            record_success(c, now)?;
            Ok(true)
        }
        Err(e) => {
            tracing::warn!(host = %cfg.host, "email send failed: {e}");
            record_failure(c, &e, now)?;
            Ok(false)
        }
    }
}

/// `MailSettings::test($to)`: ignores the on/off switch (an operator proves the relay before turning it on).
pub fn test(c: &Connection, crypt: &Encrypter, app_name: &str, local_domain: &str, msg: &Message, now: i64) -> Result<(bool, String), Fault> {
    let cfg = MailConfig::load(c, crypt)?;
    if !cfg.is_configured() {
        return Ok((false, "Set the SMTP host and From address first.".into()));
    }
    match deliver(&cfg, app_name, local_domain, msg, now) {
        Ok(()) => {
            record_success(c, now)?;
            Ok((true, format!("Test message sent to {}. Check the inbox (and the spam folder).", msg.to)))
        }
        Err(e) => {
            record_failure(c, &e, now)?;
            Ok((false, format!("Send failed: {e}")))
        }
    }
}

// ------------------------------------------------------------------------------------------- the message ---

fn no_breaks(s: &str) -> bool {
    !s.contains('\r') && !s.contains('\n')
}

/// RFC 2047 `=?utf-8?Q?...?=` for a header text that is not plain printable ASCII.
fn header_text(s: &str) -> String {
    if s.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return s.to_string();
    }
    let mut out = String::from("=?utf-8?Q?");
    for b in s.bytes() {
        match b {
            b' ' => out.push('_'),
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'!' | b'*' | b'+' | b'-' | b'/' => out.push(b as char),
            _ => out.push_str(&format!("={b:02X}")),
        }
    }
    out.push_str("?=");
    out
}

/// Quoted-printable (RFC 2045), lines of at most 76 characters, CRLF line ends.
pub fn quoted_printable(body: &str) -> String {
    let mut out = String::new();
    for (i, line) in body.split('\n').enumerate() {
        if i > 0 {
            out.push_str("\r\n");
        }
        let line = line.strip_suffix('\r').unwrap_or(line);
        let bytes = line.as_bytes();
        let mut col = 0;
        for (j, &b) in bytes.iter().enumerate() {
            let last = j + 1 == bytes.len();
            let enc = match b {
                b'=' => format!("={b:02X}"),
                b' ' | b'\t' if last => format!("={b:02X}"),
                0x21..=0x7e | b' ' | b'\t' => (b as char).to_string(),
                _ => format!("={b:02X}"),
            };
            if col + enc.len() > 75 {
                out.push_str("=\r\n");
                col = 0;
            }
            out.push_str(&enc);
            col += enc.len();
        }
    }
    out
}

/// The footer line of a rendered message: the layout marks its default ("Sent by ...") between two comments, and a footer set
/// in Settings > Email takes its place, HTML-escaped, a line break kept (`nl2br(e($footer))`).
pub fn with_footer(html: &str, footer: &str) -> String {
    const OPEN: &str = "<!--rd-footer-->";
    const CLOSE: &str = "<!--/rd-footer-->";
    let footer = footer.trim();
    let (Some(a), Some(b)) = (html.find(OPEN), html.find(CLOSE)) else { return html.to_string() };
    if footer.is_empty() || b < a {
        return html.to_string();
    }
    let text = crate::laravel::e(footer).replace("\r\n", "<br>\n").replace('\n', "<br>\n");
    format!("{}{text}{}", &html[..a], &html[b + CLOSE.len()..])
}

/// The whole message as it goes after DATA (before dot-stuffing).
pub fn build(cfg: &MailConfig, app_name: &str, local_domain: &str, msg: &Message, now: i64) -> Result<String, String> {
    if !no_breaks(&msg.to) || !no_breaks(&msg.subject) || !no_breaks(&cfg.from_address) || !no_breaks(&cfg.from_name) {
        return Err("a header carries a line break".into());
    }
    let name = if cfg.from_name.is_empty() { app_name } else { &cfg.from_name };
    let from_name = if name.bytes().all(|b| b.is_ascii_alphanumeric() || b" .-_".contains(&b)) { format!("\"{name}\"") } else { header_text(name) };
    let date = chrono::DateTime::<chrono::Utc>::from_timestamp(now, 0).unwrap_or_default().format("%a, %d %b %Y %H:%M:%S +0000");
    let id = crate::laravel::str_random(32);
    Ok(format!(
        "From: {from_name} <{from}>\r\nTo: {to}\r\nSubject: {subject}\r\nMessage-ID: <{id}@{domain}>\r\nMIME-Version: 1.0\r\nDate: {date}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n{body}\r\n",
        from = cfg.from_address,
        to = msg.to,
        subject = header_text(&msg.subject),
        domain = if local_domain.is_empty() { "localhost" } else { local_domain },
        body = quoted_printable(&with_footer(&msg.html, &cfg.footer)),
    ))
}

// ------------------------------------------------------------------------------------------ the transport ---

enum Stream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
    Gone,
}

impl Read for Stream {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(b),
            Stream::Tls(s) => s.read(b),
            Stream::Gone => Err(std::io::ErrorKind::NotConnected.into()),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(b),
            Stream::Tls(s) => s.write(b),
            Stream::Gone => Err(std::io::ErrorKind::NotConnected.into()),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            Stream::Tls(s) => s.flush(),
            Stream::Gone => Ok(()),
        }
    }
}

fn tls_config() -> Arc<ClientConfig> {
    static CFG: once_cell::sync::Lazy<Arc<ClientConfig>> = once_cell::sync::Lazy::new(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
            .expect("TLS 1.2 and 1.3 are available")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(cfg)
    });
    CFG.clone()
}

struct Smtp {
    r: BufReader<Stream>,
    host: String,
}

struct Reply {
    code: u32,
    text: String,
}

impl Smtp {
    fn reply(&mut self) -> Result<Reply, String> {
        let mut lines = vec![];
        loop {
            let mut l = String::new();
            // a reply line is short; a relay that streams without a newline is cut off at 4 KiB
            let n = (&mut self.r).take(4096).read_line(&mut l).map_err(|e| format!("Connection to \"{}\" has been closed unexpectedly ({e}).", self.host))?;
            if n == 0 {
                return Err(format!("Connection to \"{}\" has been closed unexpectedly.", self.host));
            }
            let l = l.trim_end().to_string();
            let more = l.len() > 3 && l.as_bytes()[3] == b'-';
            lines.push(l);
            if !more || lines.len() > 200 {
                break;
            }
        }
        let code = lines.last().and_then(|l| l.get(..3)).and_then(|c| c.parse().ok()).unwrap_or(0);
        Ok(Reply { code, text: lines.join("\n") })
    }

    fn send(&mut self, line: &str) -> Result<(), String> {
        let w = self.r.get_mut();
        w.write_all(line.as_bytes()).and_then(|_| w.write_all(b"\r\n")).and_then(|_| w.flush()).map_err(|e| format!("Unable to write to \"{}\" ({e}).", self.host))
    }

    /// A command and the codes it may answer, as Symfony's `executeCommand($command, $codes)`.
    fn cmd(&mut self, line: &str, codes: &[u32]) -> Result<Reply, String> {
        self.send(line)?;
        self.expect(codes)
    }

    fn expect(&mut self, codes: &[u32]) -> Result<Reply, String> {
        let r = self.reply()?;
        if !codes.contains(&r.code) {
            let want = codes.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("\", \"");
            return Err(format!("Expected response code \"{want}\" but got code \"{}\", with message \"{}\".", r.code, r.text));
        }
        Ok(r)
    }

    fn upgrade(&mut self) -> Result<(), String> {
        let name = ServerName::try_from(self.host.clone()).map_err(|_| format!("The SMTP host {} is not a valid name for TLS.", self.host))?;
        let old = std::mem::replace(self.r.get_mut(), Stream::Gone);
        let Stream::Plain(sock) = old else { return Err("already encrypted".into()) };
        let conn = ClientConnection::new(tls_config(), name).map_err(|e| format!("Unable to connect with STARTTLS: {e}"))?;
        let mut tls = Box::new(StreamOwned::new(conn, sock));
        while tls.conn.is_handshaking() {
            tls.conn.complete_io(&mut tls.sock).map_err(|e| format!("Unable to connect with TLS: {e}"))?;
        }
        *self.r.get_mut() = Stream::Tls(tls);
        Ok(())
    }
}

fn connect(host: &str, port: u16) -> Result<TcpStream, String> {
    let addrs: Vec<_> = (host, port).to_socket_addrs().map_err(|e| format!("Connection could not be established with host \"{host}:{port}\": {e}"))?.collect();
    let mut last = String::from("no address");
    for a in addrs {
        match TcpStream::connect_timeout(&a, TIMEOUT) {
            Ok(s) => {
                let _ = s.set_read_timeout(Some(TIMEOUT));
                let _ = s.set_write_timeout(Some(TIMEOUT));
                return Ok(s);
            }
            Err(e) => last = e.to_string(),
        }
    }
    Err(format!("Connection could not be established with host \"{host}:{port}\": {last}"))
}

fn has_ext(ehlo: &str, ext: &str) -> Option<String> {
    ehlo.lines().skip(1).map(|l| l.get(4..).unwrap_or("").trim()).find(|l| l.to_ascii_uppercase().split_whitespace().next() == Some(ext)).map(str::to_string)
}

/// One message to one recipient over a fresh connection.
pub fn deliver(cfg: &MailConfig, app_name: &str, local_domain: &str, msg: &Message, now: i64) -> Result<(), String> {
    if !crate::email::is_valid(msg.to.as_bytes()) {
        return Err(format!("Email \"{}\" does not comply with addr-spec of RFC 2822.", msg.to));
    }
    let data = build(cfg, app_name, local_domain, msg, now)?;
    let sock = connect(&cfg.host, cfg.port)?;
    let mut s = Smtp { r: BufReader::new(Stream::Plain(sock)), host: cfg.host.clone() };
    if cfg.encryption == "ssl" {
        s.upgrade()?;
    }
    s.expect(&[220])?;
    let helo = if local_domain.is_empty() { "[127.0.0.1]".to_string() } else { local_domain.to_string() };
    let mut ehlo = s.cmd(&format!("EHLO {helo}"), &[250])?.text;
    if cfg.encryption != "ssl" {
        if has_ext(&ehlo, "STARTTLS").is_some() {
            s.cmd("STARTTLS", &[220])?;
            s.upgrade()?;
            ehlo = s.cmd(&format!("EHLO {helo}"), &[250])?.text;
        } else if cfg.encryption == "starttls" {
            // Hardened (Symfony goes on in plain text): "starttls" means TLS, so a relay, or someone in the path who
            // strips the offer, never gets the password or a sign-in code in the clear. "none" stays opportunistic.
            return Err(format!("The SMTP server \"{}\" did not offer STARTTLS; set the encryption to \"none\" to send without it.", cfg.host));
        }
    }
    if !cfg.username.is_empty() {
        let mechs = has_ext(&ehlo, "AUTH").unwrap_or_default().to_ascii_uppercase();
        let b64 = |v: &str| base64::engine::general_purpose::STANDARD.encode(v.as_bytes());
        if mechs.split_whitespace().any(|m| m == "LOGIN") {
            s.cmd("AUTH LOGIN", &[334])?;
            s.cmd(&b64(&cfg.username), &[334])?;
            s.cmd(&b64(&cfg.password), &[235]).map_err(|_| format!("Failed to authenticate on the SMTP server using the LOGIN authenticator."))?;
        } else if mechs.split_whitespace().any(|m| m == "PLAIN") {
            let token = base64::engine::general_purpose::STANDARD.encode(format!("\0{}\0{}", cfg.username, cfg.password));
            s.cmd(&format!("AUTH PLAIN {token}"), &[235]).map_err(|_| format!("Failed to authenticate on the SMTP server using the PLAIN authenticator."))?;
        } else {
            return Err(format!("Failed to find an authenticator supported by the SMTP server, which currently supports: \"{}\".", mechs.to_ascii_lowercase()));
        }
    }
    s.cmd(&format!("MAIL FROM:<{}>", cfg.from_address), &[250])?;
    s.cmd(&format!("RCPT TO:<{}>", msg.to), &[250, 251, 252])?;
    s.cmd("DATA", &[354])?;
    let mut body = String::with_capacity(data.len() + 16);
    for line in data.split("\r\n") {
        if line.starts_with('.') {
            body.push('.');
        }
        body.push_str(line);
        body.push_str("\r\n");
    }
    // `data` ends with CRLF, so the split left one empty line: the terminator follows it
    let body = body.strip_suffix("\r\n").unwrap_or(&body).to_string();
    s.send(&format!("{body}."))?;
    s.expect(&[250])?;
    let _ = s.cmd("QUIT", &[221]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_footer_replaces_the_default_line() {
        let html = "<td><!--rd-footer-->Sent by HTE Remote at https://x.example.<!--/rd-footer--></td>";
        assert_eq!(with_footer(html, ""), html);
        assert_eq!(with_footer(html, "  \n "), html);
        assert_eq!(with_footer(html, "Support: <b>help</b>\nCall 555"), "<td>Support: &lt;b&gt;help&lt;/b&gt;<br>\nCall 555</td>");
        assert_eq!(with_footer("<td>no marks</td>", "x"), "<td>no marks</td>");
    }

    #[test]
    fn quoted_printable_and_headers() {
        assert_eq!(quoted_printable("a=b é\nend "), "a=3Db =C3=A9\r\nend=20");
        let long = "x".repeat(100);
        assert!(quoted_printable(&long).split("\r\n").all(|l| l.len() <= 76));
        assert_eq!(header_text("Reset your HTE Remote password"), "Reset your HTE Remote password");
        assert_eq!(header_text("é"), "=?utf-8?Q?=C3=A9?=");
        let cfg = MailConfig { from_address: "a@b.co".into(), from_name: "HTE Remote".into(), ..Default::default() };
        let m = Message { to: "x@y.co".into(), subject: "S".into(), html: "<p>hi</p>".into() };
        let b = build(&cfg, "HTE Remote", "console.example", &m, 0).unwrap();
        assert!(b.starts_with("From: \"HTE Remote\" <a@b.co>\r\nTo: x@y.co\r\nSubject: S\r\n"));
        assert!(b.contains("Content-Type: text/html; charset=utf-8"));
        let bad = Message { to: "x@y.co\r\nBcc: z@z.co".into(), subject: "S".into(), html: String::new() };
        assert!(build(&cfg, "HTE Remote", "", &bad, 0).is_err());
    }

    /// A fake relay on a socket: EHLO without STARTTLS, AUTH LOGIN, the message kept for the test.
    #[test]
    fn a_message_reaches_a_plain_relay_with_login() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut w = s;
            let mut said = vec![];
            w.write_all(b"220 fake ESMTP\r\n").unwrap();
            let mut in_data = false;
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                let t = line.trim_end().to_string();
                if in_data {
                    if t == "." {
                        in_data = false;
                        w.write_all(b"250 queued\r\n").unwrap();
                    } else {
                        said.push(t);
                    }
                    continue;
                }
                said.push(t.clone());
                let up = t.to_ascii_uppercase();
                let out: &[u8] = if up.starts_with("EHLO") {
                    b"250-fake\r\n250 AUTH PLAIN LOGIN\r\n"
                } else if up == "AUTH LOGIN" || said.len() == 3 {
                    b"334 x\r\n"
                } else if said.len() == 4 {
                    b"235 ok\r\n"
                } else if up == "DATA" {
                    in_data = true;
                    b"354 go\r\n"
                } else if up == "QUIT" {
                    w.write_all(b"221 bye\r\n").unwrap();
                    break;
                } else {
                    b"250 ok\r\n"
                };
                w.write_all(out).unwrap();
            }
            said
        });
        let cfg = MailConfig { enabled: true, host: "127.0.0.1".into(), port, username: "u".into(), password: "tok-5eed0000mailpw01".into(), encryption: "none".into(), from_address: "from@example.invalid".into(), from_name: String::new(), footer: String::new() };
        let m = Message { to: "to@example.invalid".into(), subject: "Hello".into(), html: ".dot line\n<p>hi</p>".into() };
        deliver(&cfg, "HTE Remote", "console.example.invalid", &m, 1_800_000_000).unwrap();
        let said = h.join().unwrap();
        assert_eq!(said[0], "EHLO console.example.invalid");
        assert_eq!(said[1], "AUTH LOGIN");
        assert_eq!(said[2], base64::engine::general_purpose::STANDARD.encode("u"));
        assert!(said.contains(&"MAIL FROM:<from@example.invalid>".to_string()));
        assert!(said.contains(&"RCPT TO:<to@example.invalid>".to_string()));
        assert!(said.contains(&"..dot line".to_string()), "dot-stuffed: {said:?}");
        assert!(said.contains(&"Subject: Hello".to_string()));
    }
}
