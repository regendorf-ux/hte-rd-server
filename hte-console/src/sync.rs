//! `App\Http\Controllers\Api\SyncController` (v1.15.0-hte.1): POST /api/heartbeat and POST /api/sysinfo,
//! with what they call: `AuditConnection::reconcileFor` / `pendingDisconnectsFor`, `Strategy::deliveryFor`,
//! the HTE password hook, `DeviceEnrollment` and the presence half of `CheckDeviceNotifications::reportOnline`.
//!
//! Not ported (and why): Apprise notifications (`device.online`, `device.pending_approval`). Apprise is not ported;
//! the durable recovery marker is still consumed exactly as the previous console does, so the database stays the same.

use crate::api::{fail, Native, Reply};
use crate::sqlite::{self as db, Row, P};
use crate::laravel::{self, Cast, Input};
use crate::php::{self, Fault, Val};
use crate::{passwords, strategy};
use rusqlite::Connection;

pub const RECONCILE_GRACE_SECONDS: i64 = 90;
pub const DISCONNECT_RETRY_SECONDS: i64 = 60;

fn find_device(c: &Connection, id: &[u8]) -> Result<Option<Row>, Fault> {
    // Device::withTrashed()->where('rustdesk_id', $id)->first()
    db::first(c, r#"select * from "devices" where "rustdesk_id" = ? limit 1"#, &[P(Val::Str(id.to_vec()))])
}

/// `SyncController::uuidMatches($stored, $sent)`: equal as sent, or after base64 in either direction.
pub fn uuid_matches(stored: &[u8], sent: &[u8]) -> bool {
    if stored.is_empty() || sent.is_empty() || php::hash_equals(stored, sent) {
        return true;
    }
    let rtrim0 = |v: Vec<u8>| {
        let end = v.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
        v[..end].to_vec()
    };
    if let Some(d) = php::base64_decode_strict(sent) {
        if php::hash_equals(stored, &rtrim0(d)) {
            return true;
        }
    }
    php::base64_decode_strict(stored).map_or(false, |d| php::hash_equals(&rtrim0(d), sent))
}

/// `$device->uuid` handed to `uuidMatches(string ...)`: a null would be a TypeError.
fn stored_uuid(d: &Row) -> Result<Vec<u8>, Fault> {
    match d.val("uuid") {
        Val::Null => Err(Fault::Other("devices.uuid is null".into())),
        v => v.to_php_string(),
    }
}

/// The durable half of `CheckDeviceNotifications::reportOnline`: consume a recovery marker. The notification
/// it would send is not ported (Apprise is not used at HTE).
fn report_online(c: &Connection, device: &Row) -> Result<(), Fault> {
    if device.val("status") != Val::str("active") {
        return Ok(());
    }
    let any = db::first(
        c,
        r#"select exists(select * from "device_presence_notification_states" where "device_id" = ? and "offline_notified_at" is not null) as "exists""#,
        &[P(device.val("id"))],
    )?;
    if any.map_or(false, |r| r.val("exists").to_bool()) {
        db::exec(c, r#"delete from "device_presence_notification_states" where "device_id" = ? and "offline_notified_at" is not null"#, &[P(device.val("id"))])?;
        tracing::info!("device recovered (presence marker consumed; notifications are not sent by hte-console)");
    }
    Ok(())
}

/// `AuditConnection::reconcileFor($id, $live)`: open sessions the device no longer reports are closed.
fn reconcile_for(c: &Connection, id: &[u8], live: &[i64], now: i64) -> Result<(), Fault> {
    let ts = laravel::ts(now);
    let mut sql = String::from(
        r#"update "audit_connections" set "action" = ?, "closed_at" = ?, "updated_at" = ? where "rustdesk_id" = ? and "closed_at" is null and "created_at" < ?"#,
    );
    let mut params = vec![P(Val::str("close")), P(Val::str(&ts)), P(Val::str(&ts)), P(Val::Str(id.to_vec())), P(Val::str(&laravel::ts(now - RECONCILE_GRACE_SECONDS)))];
    if !live.is_empty() {
        sql.push_str(&format!(r#" and "conn_id" not in ({})"#, vec!["?"; live.len()].join(", ")));
        params.extend(live.iter().map(|&i| P(Val::Int(i))));
    }
    db::exec(c, &sql, &params)?;
    Ok(())
}

/// `AuditConnection::pendingDisconnectsFor($id)`: the conn ids an operator asked to close, at most once a minute each.
fn pending_disconnects_for(c: &Connection, id: &[u8], now: i64) -> Result<Vec<i64>, Fault> {
    let rows = db::rows(
        c,
        r#"select * from "audit_connections" where "rustdesk_id" = ? and "closed_at" is null and "disconnect_requested_at" is not null and "conn_id" is not null and ("disconnect_sent_at" is null or "disconnect_sent_at" < ?)"#,
        &[P(Val::Str(id.to_vec())), P(Val::str(&laravel::ts(now - DISCONNECT_RETRY_SECONDS)))],
    )?;
    if rows.is_empty() {
        return Ok(vec![]);
    }
    let ts = laravel::ts(now);
    let sql = format!(r#"update "audit_connections" set "disconnect_sent_at" = ?, "updated_at" = ? where "id" in ({})"#, vec!["?"; rows.len()].join(", "));
    let mut params = vec![P(Val::str(&ts)), P(Val::str(&ts))];
    params.extend(rows.iter().map(|r| P(r.val("id"))));
    db::exec(c, &sql, &params)?;
    Ok(rows.iter().map(|r| r.val("conn_id").to_int()).collect())
}

/// POST /api/heartbeat
pub fn heartbeat(n: &Native, c: &Connection, input: &Input, ip: &str, now: i64) -> Reply {
    match heartbeat_inner(n, c, input, ip, now) {
        Ok(r) => r,
        Err(f) => fail("heartbeat", &f),
    }
}

fn heartbeat_inner(n: &Native, c: &Connection, input: &Input, ip: &str, now: i64) -> Result<Reply, Fault> {
    let empty = || Reply::Json(200, "{}".into());
    let id = input.string("id")?;
    let uuid = input.string("uuid")?;
    if id.is_empty() {
        return Ok(empty());
    }
    let Some(mut device) = find_device(c, &id)? else {
        return Ok(Reply::Json(200, r#"{"sysinfo":1}"#.into()));
    };
    if !device.is_null("deleted_at") {
        return Ok(empty());
    }
    if !uuid_matches(&stored_uuid(&device)?, &uuid) {
        return Ok(empty());
    }
    let ts = laravel::ts(now);
    let mut update = vec![("last_online_at", Val::str(&ts), Cast::Date), ("last_online_ip", Val::str(ip), Cast::Plain)];
    if !uuid.is_empty() && device.val("uuid") != Val::Str(uuid.clone()) {
        update.push(("uuid", Val::Str(uuid.clone()), Cast::Plain));
    }
    db::update_dirty(c, "devices", &mut device, update, &ts)?;
    report_online(c, &device)?;

    let mut response: Vec<(String, Val)> = vec![];
    match device.val("hostname") {
        Val::Null => response.push(("sysinfo".into(), Val::Int(1))),
        Val::Str(s) if s.is_empty() => response.push(("sysinfo".into(), Val::Int(1))),
        _ => {}
    }

    // array_map('intval', (array) $request->input('conns', []))
    let live: Vec<i64> = input.get("conns").map(|v| v.to_array()).unwrap_or_default().iter().map(|(_, v)| v.to_int()).collect();
    reconcile_for(c, &id, &live, now)?;

    let disconnect = pending_disconnects_for(c, &id, now)?;
    if !disconnect.is_empty() {
        let mut a = php::Arr::new();
        for d in disconnect {
            a.push(Val::Int(d));
        }
        response.push(("disconnect".into(), Val::Arr(a)));
    }

    if let Some(d) = strategy::delivery_for(c, &mut device, input.int("modified_at"), now)? {
        response.push(("modified_at".into(), Val::Int(d.modified_at)));
        response.push(("strategy".into(), php::assoc(vec![("config_options".to_string(), strategy::map_val(&d.options))])));
    }

    if input.has("hte_pw") {
        let held = input.int("hte_pw");
        if let Some(o) = passwords::heartbeat(c, &n.crypt, &n.hbbs_db, &device, held, &ts)? {
            response.push(("hte_password".into(), php::assoc(vec![("v".to_string(), Val::Int(o.v)), ("box".to_string(), Val::str(&o.sealed))])));
        }
    }

    if response.is_empty() {
        return Ok(empty());
    }
    let body = php::json_encode(&php::assoc(response)).ok_or_else(|| Fault::Other("json_encode of the heartbeat answer failed".into()))?;
    Ok(Reply::Json(200, body))
}

/// POST /api/sysinfo
pub fn sysinfo(_n: &Native, c: &Connection, input: &Input, ip: &str, now: i64) -> Reply {
    match sysinfo_inner(c, input, ip, now) {
        Ok(r) => r,
        Err(f) => fail("sysinfo", &f),
    }
}

fn sysinfo_inner(c: &Connection, input: &Input, ip: &str, now: i64) -> Result<Reply, Fault> {
    let id = input.string("id")?;
    let uuid = input.string("uuid")?;
    if id.is_empty() {
        return Ok(Reply::text("ID_NOT_FOUND"));
    }
    let device = find_device(c, &id)?;
    if device.as_ref().map_or(false, |d| !d.is_null("deleted_at")) {
        return Ok(Reply::text("SYSINFO_UPDATED"));
    }
    if let Some(d) = &device {
        if !uuid_matches(&stored_uuid(d)?, &uuid) {
            return Ok(Reply::text("SYSINFO_UPDATED"));
        }
    }
    let ts = laravel::ts(now);
    let attrs: Vec<(&str, Val, Cast)> = vec![
        ("uuid", Val::Str(uuid), Cast::Plain),
        ("cpu", Val::Str(input.string("cpu")?), Cast::Plain),
        ("memory", Val::Str(input.string("memory")?), Cast::Plain),
        ("os", Val::Str(input.string("os")?), Cast::Plain),
        ("hostname", Val::Str(input.string("hostname")?), Cast::Plain),
        ("username", Val::Str(input.string("username")?), Cast::Plain),
        ("version", Val::Str(input.string("version")?), Cast::Plain),
        ("last_online_at", Val::str(&ts), Cast::Date),
        ("last_online_ip", Val::str(ip), Cast::Plain),
    ];
    match device {
        None => create_device(c, &id, attrs, ip, now)?,
        Some(mut d) => {
            db::update_dirty(c, "devices", &mut d, attrs, &ts)?;
            report_online(c, &d)?;
        }
    }
    Ok(Reply::text("SYSINFO_UPDATED"))
}

/// The new-device branch of `sysinfo`: approval gate, default group, `Device::create` (its `created` hook
/// resolves the strategy), `DeviceEnrollment::approveIfSignedIn`.
fn create_device(c: &Connection, id: &[u8], attrs: Vec<(&str, Val, Cast)>, ip: &str, now: i64) -> Result<(), Fault> {
    let ts = laravel::ts(now);
    let gate = Val::Str(db::setting(c, "require_device_approval", "0")?).to_bool();
    let mut cols: Vec<(&str, Val)> = vec![("rustdesk_id", Val::Str(id.to_vec()))];
    cols.extend(attrs.into_iter().map(|(k, v, _)| (k, v)));
    cols.push(("status", Val::str(if gate { "pending" } else { "active" })));
    cols.push(("registered_ip", Val::str(ip)));
    if Val::Str(db::setting(c, "new_devices_incoming_only", "0")?).to_bool() {
        cols.push(("can_initiate", Val::Bool(false)));
    }
    // DeviceEnrollment::defaultsForNew
    let group_id = Val::Str(db::setting(c, "default_device_group_id", "0")?).to_int();
    if group_id > 0 {
        if let Some(g) = db::first(c, r#"select * from "device_groups" where "device_groups"."id" = ? limit 1"#, &[P(Val::Int(group_id))])? {
            cols.push(("device_group_id", g.val("id")));
        }
    }
    let mut device = Row(cols.iter().map(|(k, v)| (k.to_string(), v.clone())).collect());
    let new_id = db::insert(c, "devices", cols, &ts)?;
    device.set("id", Val::Int(new_id));
    device.set("updated_at", Val::str(&ts));
    device.set("created_at", Val::str(&ts));
    strategy::sync_resolved_for(c, &mut device, &ts)?;
    approve_if_signed_in(c, &mut device, None, now)?;
    Ok(())
}

/// `DeviceEnrollment::approveIfSignedIn($device, $user)`. Without a user (a new device from sysinfo), the device's
/// newest client token decides; with one (a client that just signed in, phase 2), that user.
pub(crate) fn approve_if_signed_in(c: &Connection, device: &mut Row, signed_in: Option<&Row>, now: i64) -> Result<bool, Fault> {
    if device.val("status") != Val::str("pending") || db::setting(c, "auto_approve_signed_in", "0")? != b"1" {
        return Ok(false);
    }
    let user = match signed_in {
        Some(u) => u.clone(),
        None => {
            let Some(token) = db::first(
                c,
                r#"select * from "client_tokens" where "device_id" = ? and "user_id" is not null order by "id" desc limit 1"#,
                &[P(device.val("rustdesk_id"))],
            )?
            else {
                return Ok(false);
            };
            let valid = match token.val("expires_at") {
                Val::Null => true,
                v => laravel::parse_ts(&v).ok_or_else(|| Fault::Other("unparsable client_tokens.expires_at".into()))? > now,
            };
            if !valid {
                return Ok(false);
            }
            let Some(user) = db::first(c, r#"select * from "users" where "users"."id" = ? limit 1"#, &[P(token.val("user_id"))])? else {
                return Ok(false);
            };
            user
        }
    };
    if !user.val("is_active").to_bool() {
        return Ok(false);
    }
    let ts = laravel::ts(now);
    let mut changes = vec![("status", Val::str("active"), Cast::Plain)];
    let owner_changes = device.is_null("user_id");
    if owner_changes {
        changes.push(("user_id", user.val("id"), Cast::Plain));
    }
    db::update_dirty(c, "devices", device, changes, &ts)?;
    // Device's `updated` hook: a new owner can change the resolved strategy.
    if owner_changes {
        strategy::sync_resolved_for(c, device, &ts)?;
    }
    tracing::info!("device approved on sign-in");
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_rules() {
        assert!(uuid_matches(b"", b"x"));
        assert!(uuid_matches(b"x", b""));
        assert!(uuid_matches(b"abc", b"abc"));
        // stored plain, sent base64 (with trailing NULs trimmed)
        assert!(uuid_matches(b"abc", b"YWJjAAA="));
        // stored base64, sent plain
        assert!(uuid_matches(b"YWJj", b"abc"));
        assert!(!uuid_matches(b"abc", b"abd"));
        assert!(!uuid_matches(b"abc", b"YWJk"));
    }
}
