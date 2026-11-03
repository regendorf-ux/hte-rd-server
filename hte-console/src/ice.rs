//! The `ice-servers` list: the STUN and TURN servers a RustDesk 1.5 client (and the browser client) uses for WebRTC. Ported
//! from CortenDesk 1.17's `App\Support\IceServers`, so a list means the same thing here.
//!
//! A comma-separated list of `stun:host[:port]`, `stuns:host[:port]`, `stun://host[:port]`, `stuns://host[:port]`,
//! `turn://user:pass@host[:port]` and `turns://user:pass@host[:port]`. The port defaults to 3478; an IPv6 address goes in
//! brackets; a TURN entry needs a user name and a password (percent-encoded where they hold anything but letters, digits
//! and `-._~`, because a comma would split the list). The client skips an entry it cannot use without saying so, which would
//! leave an operator believing a server is configured when it is not; so a list is accepted only when every entry is one the
//! client will use.

use regex::Regex;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

pub const MAX_ENTRIES: usize = 16;
pub const MAX_LENGTH: usize = 4096;

fn entry_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?is)^(stuns?|turns?):(//)?(.+)$").unwrap())
}

fn userinfo_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[A-Za-z0-9\-._~%!$&'()*+;=]+:[A-Za-z0-9\-._~%!$&'()*+;=]+$").unwrap())
}

fn host_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$").unwrap())
}

/// The non-empty, trimmed entries of a list.
pub fn entries(value: &str) -> Vec<&str> {
    value.split(',').map(str::trim).filter(|e| !e.is_empty()).collect()
}

/// The list in canonical form (`""` for an empty one), or `None` when it is too long or any entry is unusable.
pub fn normalize(value: &str) -> Option<String> {
    let list = entries(value);
    if list.is_empty() {
        return Some(String::new());
    }
    if list.len() > MAX_ENTRIES || value.len() > MAX_LENGTH {
        return None;
    }
    let clean: Option<Vec<String>> = list.iter().map(|e| parse(e)).collect();
    clean.map(|c| c.join(","))
}

/// The first entry the client would skip, or `None` when all are usable.
pub fn first_invalid(value: &str) -> Option<&str> {
    entries(value).into_iter().find(|e| parse(e).is_none())
}

/// One entry with its scheme lower-cased, or `None` when unusable.
fn parse(entry: &str) -> Option<String> {
    let m = entry_re().captures(entry)?;
    let scheme = m[1].to_ascii_lowercase();
    let slashes = m.get(2).is_some();
    let mut rest = m[3].to_string();
    let mut userinfo: Option<String> = None;
    if slashes && rest.contains('@') {
        let (u, h) = rest.split_once('@')?;
        // `%` must start a two-digit escape
        let bytes = u.as_bytes();
        let hex_at = |i: usize| bytes.get(i).map_or(false, u8::is_ascii_hexdigit);
        let bad_escape = bytes.iter().enumerate().any(|(i, b)| *b == b'%' && !(hex_at(i + 1) && hex_at(i + 2)));
        if !userinfo_re().is_match(u) || bad_escape || !decodes_to_utf8(u) {
            return None;
        }
        userinfo = Some(u.to_string());
        rest = h.to_string();
    }
    // TURN authenticates every allocation, and only the // form carries credentials: the client drops a TURN entry without them
    if scheme.starts_with("turn") && userinfo.is_none() {
        return None;
    }
    if scheme.starts_with("stun") && userinfo.is_some() {
        return None;
    }
    if !valid_host_port(&rest) {
        return None;
    }
    Some(format!("{scheme}:{}{}{rest}", if slashes { "//" } else { "" }, userinfo.map(|u| format!("{u}@")).unwrap_or_default()))
}

/// The browser client percent-decodes the user name and password and drops the entry when that fails: so must we.
fn decodes_to_utf8(u: &str) -> bool {
    let b = u.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() + 1 {
            match u.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok()) {
                Some(v) => out.push(v),
                None => return false,
            }
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).is_ok()
}

fn valid_host_port(hp: &str) -> bool {
    if let Some(inner) = hp.strip_prefix('[') {
        let Some((addr, tail)) = inner.split_once(']') else { return false };
        let port = match tail {
            "" => None,
            t => match t.strip_prefix(':') {
                Some(p) => Some(p),
                None => return false,
            },
        };
        return addr.parse::<Ipv6Addr>().is_ok() && valid_port(port);
    }
    // an IPv6 address without brackets has no unambiguous port
    if hp.matches(':').count() > 1 {
        return false;
    }
    let (host, port) = match hp.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (hp, None),
    };
    valid_host(host) && valid_port(port)
}

fn valid_host(host: &str) -> bool {
    if host.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    // a name needs a letter somewhere (a dotted run of digits that is not an address is not a name)
    host.len() <= 253 && host.bytes().any(|b| b.is_ascii_alphabetic()) && host_re().is_match(host)
}

fn valid_port(port: Option<&str>) -> bool {
    match port {
        None => true,
        Some(p) => !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u32>().map_or(false, |n| (1..=65535).contains(&n)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_good_list_is_kept_in_canonical_form() {
        assert_eq!(normalize("").as_deref(), Some(""));
        assert_eq!(normalize(" , ,").as_deref(), Some(""));
        assert_eq!(normalize("STUN:stun.example.test:3478, turn://user:p%40ss@turn.example.test:3478").as_deref(), Some("stun:stun.example.test:3478,turn://user:p%40ss@turn.example.test:3478"));
        assert_eq!(normalize("stuns://10.0.0.1").as_deref(), Some("stuns://10.0.0.1"));
        assert_eq!(normalize("turns://a:b@[2001:db8::1]:5349").as_deref(), Some("turns://a:b@[2001:db8::1]:5349"));
        assert_eq!(normalize("turn://u:p%C3%A9@h.example.test").as_deref(), Some("turn://u:p%C3%A9@h.example.test"));
        assert_eq!(normalize("stun:[::1]").as_deref(), Some("stun:[::1]"));
    }

    #[test]
    fn what_the_client_would_skip_is_refused() {
        for bad in [
            "turn:turn.example.test",              // no credentials, and no //
            "turn://turn.example.test",            // no credentials
            "turn://user@turn.example.test",       // no password
            "turn://:pw@turn.example.test",        // no user
            "stun://u:p@stun.example.test",        // STUN takes none
            "stun:host:0",                         // port range
            "stun:host:65536",
            "stun:host:",                          // empty port
            "stun:2001:db8::1",                    // IPv6 needs brackets
            "stun:[2001:db8::1",                   // unclosed
            "stun:[nonsense]",
            "stun:",                               // no host
            "stun:1.2.3.4.5",                      // digits only, not an address
            "stun:bad_host.example.test",
            "turn://u:p%zz@h.example.test",        // broken escape
            "turn://u:p%4@h.example.test",
            "turn://u:p%ff@h.example.test",        // not UTF-8 once decoded: the browser drops it
            "turn://u:p%C3@h.example.test",
            "http://example.test",
            "stun.example.test:3478",              // no scheme
        ] {
            assert_eq!(normalize(bad), None, "{bad}");
            assert_eq!(first_invalid(bad), Some(bad), "{bad}");
        }
        assert_eq!(first_invalid("stun:ok.example.test, turn://x"), Some("turn://x"));
        assert_eq!(first_invalid("stun:ok.example.test"), None);
    }

    #[test]
    fn the_list_is_bounded() {
        let many = vec!["stun:h.example.test"; MAX_ENTRIES + 1].join(",");
        assert_eq!(normalize(&many), None);
        assert!(normalize(&vec!["stun:h.example.test"; MAX_ENTRIES].join(",")).is_some());
        let long = format!("stun:{}.example.test", "a".repeat(MAX_LENGTH));
        assert_eq!(normalize(&long), None);
    }
}
