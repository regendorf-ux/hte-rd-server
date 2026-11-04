//! `App\Http\Controllers\Api\AuditController` (v1.15.0-hte.1), the tokenless half: POST /api/audit/conn,
//! /api/audit/file, /api/audit/alarm. (The bearer-token half, PUT /api/audit and GET /api/audit/conn/active,
//! stays in the previous console until phase 4.)
//!
//! Not ported: the Apprise alarm notifications (`security.alarm`, `remote_connection.failure`); Apprise is not ported.

use crate::api::{fail, Native, Reply};
use crate::sqlite::{self as db, P};
use crate::laravel::{self, Cast, Input};
use crate::php::{self, Fault, Key, Val};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

pub const NONCE_TTL_SECONDS: i64 = 300;
pub const RETRY_WINDOW_SECONDS: i64 = 120;
pub const NOTE_MAX_LENGTH: usize = 2000;

/// `AuditController::once()`: run one write at most once per client nonce; a failed write forgets the nonce
/// and answers 500 so the client retries.
fn once(n: &Native, input: &Input, endpoint: &str, id: &[u8], now: i64, write: impl FnOnce() -> Result<(), Fault>) -> Reply {
    let key = match input.get("nonce") {
        Some(Val::Str(s)) if !php::trim(s).is_empty() => {
            let mut h = Sha256::new();
            h.update(endpoint.as_bytes());
            h.update(b"\n");
            h.update(id);
            h.update(b"\n");
            h.update(s);
            Some(<[u8; 32]>::from(h.finalize()))
        }
        _ => None,
    };
    if let Some(k) = key {
        let fresh = n.nonces.lock().unwrap_or_else(|e| e.into_inner()).add(k, NONCE_TTL_SECONDS, now);
        if !fresh {
            return Reply::stored();
        }
    }
    match write() {
        Ok(()) => Reply::stored(),
        Err(f) => {
            let _ = fail(&format!("audit {endpoint}"), &f);
            if let Some(k) = key {
                n.nonces.lock().unwrap_or_else(|e| e.into_inner()).forget(&k);
            }
            Reply::Json(500, r#"{"error":"Audit record not stored"}"#.into())
        }
    }
}

/// `AuditController::sessionId()`: a u64 that the previous console would turn into a float is read again from the raw body
/// with big integers kept as strings.
fn session_id(input: &Input) -> Vec<u8> {
    let mut value = input.get("session_id").cloned().unwrap_or_else(|| Val::str(""));
    if input.is_json {
        let raw = php::json_decode(&input.raw, &php::JsonOpts { bigint_as_string: true, depth: 512 });
        if let Some(Val::Arr(a)) = raw {
            if let Some(v) = a.get(&Key::from_bytes(b"session_id")) {
                value = v.clone();
            }
        }
    }
    match value {
        Val::Int(i) => i.to_string().into_bytes(),
        Val::Str(s) => s,
        _ => vec![],
    }
}

/// `AuditController::cleanNote()`: trimmed, capped at 2000 characters, None when nothing is left.
pub(crate) fn clean_note(note: Option<&Val>) -> Option<Vec<u8>> {
    let Some(Val::Str(s)) = note else { return None };
    let t = php::trim(s);
    if t.is_empty() {
        return None;
    }
    Some(mb_substr(t, NOTE_MAX_LENGTH))
}

/// `mb_substr($s, 0, $n)` in UTF-8: an invalid byte counts as one character.
fn mb_substr(s: &[u8], n: usize) -> Vec<u8> {
    let mut i = 0;
    let mut count = 0;
    while i < s.len() && count < n {
        let len = match s[i] {
            0x00..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => 1,
        };
        let step = if i + len <= s.len() && std::str::from_utf8(&s[i..i + len]).is_ok() { len } else { 1 };
        i += step;
        count += 1;
    }
    s[..i].to_vec()
}

/// POST /api/audit/conn
pub fn connection(n: &Native, c: &Connection, input: &Input, ip: &str, now: i64) -> Reply {
    let action = input.get("action").cloned().unwrap_or(Val::Null);
    let id = match input.string("id") {
        Ok(id) => id,
        Err(f) => return fail("audit conn", &f),
    };
    let conn_id = input.int("conn_id");
    let session = session_id(input);

    if input.has("note") && !input.has("conn_id") {
        let note = input.get("note").cloned();
        return once(n, input, "note", &id, now, || legacy_note(c, &id, &session, note.as_ref(), now));
    }
    if id.is_empty() || conn_id == 0 {
        return Reply::stored();
    }
    once(n, input, "conn", &id, now, || {
        let ts = laravel::ts(now);
        if action == Val::str("new") {
            if !retried_new(c, &id, conn_id, now)? {
                let ip_v = match input.get("ip") {
                    Some(v) => v.to_php_string()?,
                    None => ip.as_bytes().to_vec(),
                };
                let uuid = input.string("uuid")?;
                let mut cols = vec![
                    ("action", Val::str("new")),
                    ("conn_id", Val::Int(conn_id)),
                    ("rustdesk_id", Val::Str(id.clone())),
                    ("ip", Val::Str(ip_v)),
                    ("session_id", Val::Str(session.clone())),
                    ("uuid", Val::Str(uuid)),
                    ("guid", Val::str(&laravel::uuid4())),
                ];
                // HTE: how hbbs set it up, echoed by RustDesk 1.5 devices (path.rs)
                if let Some(path) = input.get("conn_audit_ref").and_then(crate::path::from_tag) {
                    cols.push(("path", Val::str(path)));
                }
                db::insert(c, "audit_connections", cols, &ts)?;
                crate::path::refresh(c, &Val::Str(id.clone()), now)?; // HTE
            }
            return Ok(());
        }

        let open = db::first(
            c,
            r#"select * from "audit_connections" where "rustdesk_id" = ? and "conn_id" = ? and "closed_at" is null order by "id" desc limit 1"#,
            &[P(Val::Str(id.clone())), P(Val::Int(conn_id))],
        )?;

        if action == Val::str("close") {
            if let Some(mut row) = open {
                db::update_dirty(c, "audit_connections", &mut row, vec![("action", Val::str("close"), Cast::Plain), ("closed_at", Val::str(&ts), Cast::Date)], &ts)?;
                crate::path::refresh(c, &row.val("rustdesk_id"), laravel::parse_ts(&row.val("created_at")).unwrap_or(now))?; // HTE
            }
            return Ok(());
        }

        // Authorized: no action key; peer is a 2-element [id, name] array.
        let peer = input.get("peer").map(|v| v.to_array()).unwrap_or_default();
        let part = |i: i64| match peer.get(&Key::Int(i)) {
            None | Some(Val::Null) => Ok(vec![]),
            Some(v) => v.to_php_string(),
        };
        let from_peer = part(0)?;
        let from_name = part(1)?;
        let mut attrs = vec![
            ("action", Val::str("authorized"), Cast::Plain),
            ("from_peer", Val::Str(from_peer), Cast::Plain),
            ("from_name", Val::Str(from_name), Cast::Plain),
            ("conn_type", Val::Int(input.int("type")), Cast::Plain),
        ];
        if !session.is_empty() {
            attrs.push(("session_id", Val::Str(session.clone()), Cast::Plain));
        }
        let opened = match open {
            Some(mut row) => {
                db::update_dirty(c, "audit_connections", &mut row, attrs, &ts)?;
                laravel::parse_ts(&row.val("created_at")).unwrap_or(now)
            }
            None => {
                let uuid = input.string("uuid")?;
                let mut cols: Vec<(&str, Val)> = attrs.into_iter().map(|(k, v, _)| (k, v)).collect();
                if !cols.iter().any(|(k, _)| *k == "session_id") {
                    cols.push(("session_id", Val::Str(session.clone())));
                }
                cols.push(("conn_id", Val::Int(conn_id)));
                cols.push(("rustdesk_id", Val::Str(id.clone())));
                cols.push(("uuid", Val::Str(uuid)));
                cols.push(("ip", Val::str(ip)));
                cols.push(("guid", Val::str(&laravel::uuid4())));
                db::insert(c, "audit_connections", cols, &ts)?;
                now
            }
        };
        crate::path::refresh(c, &Val::Str(id.clone()), opened)?; // HTE
        Ok(())
    })
}

/// `AuditController::isRetriedNew()`
fn retried_new(c: &Connection, id: &[u8], conn_id: i64, now: i64) -> Result<bool, Fault> {
    let r = db::first(
        c,
        r#"select exists(select * from "audit_connections" where "rustdesk_id" = ? and "conn_id" = ? and "action" = ? and "closed_at" is null and "created_at" >= ?) as "exists""#,
        &[P(Val::Str(id.to_vec())), P(Val::Int(conn_id)), P(Val::str("new")), P(Val::str(&laravel::ts(now - RETRY_WINDOW_SECONDS)))],
    )?;
    Ok(r.map_or(false, |r| r.val("exists").to_bool()))
}

/// `AuditController::legacyNote()`: the in-session Note button (controlling side, tokenless).
fn legacy_note(c: &Connection, id: &[u8], session: &[u8], note: Option<&Val>, now: i64) -> Result<(), Fault> {
    if id.is_empty() || session.is_empty() || session == b"0" {
        return Ok(());
    }
    let row = db::first(
        c,
        r#"select * from "audit_connections" where "rustdesk_id" = ? and "session_id" = ? and "conn_type" = ? order by "id" desc limit 1"#,
        &[P(Val::Str(id.to_vec())), P(Val::Str(session.to_vec())), P(Val::Int(0))],
    )?;
    if let Some(mut row) = row {
        if row.is_null("note_user_id") {
            let clean = clean_note(note);
            let ts = laravel::ts(now);
            let noted_at = if clean.is_none() { Val::Null } else { Val::str(&ts) };
            let note_v = clean.map_or(Val::Null, Val::Str);
            db::update_dirty(c, "audit_connections", &mut row, vec![("note", note_v, Cast::Plain), ("noted_at", noted_at, Cast::Date)], &ts)?;
        }
    }
    Ok(())
}

/// POST /api/audit/file (`info` is a JSON-encoded string)
pub fn file(n: &Native, c: &Connection, input: &Input, ip: &str, now: i64) -> Reply {
    let id = match input.string("id") {
        Ok(id) => id,
        Err(f) => return fail("audit file", &f),
    };
    if id.is_empty() {
        return Reply::stored();
    }
    let info = match input.string("info") {
        Ok(i) => i,
        Err(f) => return fail("audit file", &f),
    };
    let decoded = match php::json_decode(&info, &php::JsonOpts::default()) {
        Some(Val::Arr(a)) => a,
        _ => php::Arr::new(),
    };
    once(n, input, "file", &id, now, || {
        let from = |k: &str| match decoded.get_str(k) {
            None | Some(Val::Null) => Ok(None),
            Some(v) => Ok(Some(v.clone())),
        };
        let from_name = from("name")?.map_or(Ok(vec![]), |v: Val| v.to_php_string())?;
        let file_count = from("num")?.map_or(0, |v: Val| v.to_int());
        let ip_v = match from("ip")? {
            Some(v) => v.to_php_string()?,
            None => ip.as_bytes().to_vec(),
        };
        let cols = vec![
            ("rustdesk_id", Val::Str(id.clone())),
            ("from_peer", Val::Str(input.string("peer_id")?)),
            ("from_name", Val::Str(from_name)),
            ("path", Val::Str(input.string("path")?)),
            ("info", Val::Str(info.clone())),
            ("is_file", Val::Bool(input.get("is_file").map_or(false, |v| v.to_bool()))),
            ("direction", Val::Int(input.int("type"))),
            ("file_count", Val::Int(file_count)),
            ("ip", Val::Str(ip_v)),
            ("uuid", Val::Str(input.string("uuid")?)),
        ];
        db::insert(c, "audit_file_transfers", cols, &laravel::ts(now)).map(|_| ())
    })
}

/// POST /api/audit/alarm
pub fn alarm(n: &Native, c: &Connection, input: &Input, now: i64) -> Reply {
    let id = match input.string("id") {
        Ok(id) => id,
        Err(f) => return fail("audit alarm", &f),
    };
    if id.is_empty() {
        return Reply::stored();
    }
    once(n, input, "alarm", &id, now, || {
        let conn_id = input.int("conn_id");
        let cols = vec![
            ("rustdesk_id", Val::Str(id.clone())),
            ("uuid", Val::Str(input.string("uuid")?)),
            ("typ", Val::Int(input.int("typ"))),
            ("info", Val::Str(input.string("info")?)),
            ("conn_id", if conn_id == 0 { Val::Null } else { Val::Int(conn_id) }),
        ];
        db::insert(c, "alarm_logs", cols, &laravel::ts(now)).map(|_| ())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_keeps_big_integers() {
        let i = Input::new("POST", Some("application/json"), None, br#"{"session_id":18446744073709551615}"#);
        assert_eq!(session_id(&i), b"18446744073709551615");
        let i = Input::new("POST", Some("application/json"), None, br#"{"session_id":1.5}"#);
        assert_eq!(session_id(&i), b"");
        let i = Input::new("POST", Some("application/json"), None, br#"{"session_id":" 7 "}"#);
        assert_eq!(session_id(&i), b" 7 "); // read raw, untrimmed, as the previous console does
        let i = Input::new("POST", Some("application/x-www-form-urlencoded"), Some("session_id=%209"), b"");
        assert_eq!(session_id(&i), b"9");
    }

    #[test]
    fn notes() {
        assert_eq!(clean_note(Some(&Val::str("  hi  "))), Some(b"hi".to_vec()));
        assert_eq!(clean_note(Some(&Val::str("   "))), None);
        assert_eq!(clean_note(Some(&Val::Int(5))), None);
        assert_eq!(mb_substr("ééé".as_bytes(), 2), "éé".as_bytes());
        assert_eq!(mb_substr(b"\xff\xfeab", 3), b"\xff\xfea");
    }
}
