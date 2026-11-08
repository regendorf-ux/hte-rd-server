//! Phase 3: HTE Remote's per-person reach (v1.15.0-hte.1), a port of `App\Hte\Reach` (`policyBlock`, `sections` as far
//! as `Passwords::reachIds` needs it, `recordRefusals`) and `App\Hte\ReachSweep` (`handle`, `verdict`), with the
//! console's visibility rule they rest on (`Device::scopeVisibleTo`, `User::accessibleDeviceGroupIds`).
//!
//! The rule: administrators reach every approved device; anyone else reaches the approved devices they own plus
//! those in a device group granted to them directly, to one of their user groups, or through a group-access entry
//! (to them or to one of their user groups). Queries are the previous console's, in the previous console's order, so the same rows come back in the
//! same order.

use crate::laravel;
use crate::php::{self, Fault, Val};
use crate::sqlite::{self as db, Row, P};
use crate::validate::str_limit;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

pub const SETTING: &str = "hte_scope_enforce";
/// A session hbbs refused as outside the person's reach.
pub const REFUSAL_ALARM: i64 = 102;
/// A session the console closed because access changed.
pub const SWEEP_ALARM: i64 = 103;
/// `AlarmLog::CONSOLE_SOURCE`
pub const CONSOLE_SOURCE: &str = "console";

pub fn enforced(c: &Connection) -> Result<bool, Fault> {
    Ok(db::setting(c, SETTING, "0")? == b"1")
}

fn ints(rows: Vec<Row>, col: &str) -> Vec<i64> {
    rows.iter().map(|r| r.val(col).to_int()).collect()
}

fn marks(n: usize) -> String {
    vec!["?"; n].join(", ")
}

/// `User::userGroupIds()`: through the belongsToMany join, so only groups that exist.
fn user_group_ids(c: &Connection, user_id: &Val) -> Result<Vec<i64>, Fault> {
    let rows = db::rows(
        c,
        r#"select "user_groups"."id" from "user_groups" inner join "user_group_user" on "user_groups"."id" = "user_group_user"."user_group_id" where "user_group_user"."user_id" = ?"#,
        &[P(user_id.clone())],
    )?;
    Ok(ints(rows, "id"))
}

/// `User::accessibleDeviceGroupIds()`: direct grants, grants to their user groups, group-access entries.
pub fn accessible_device_group_ids(c: &Connection, user: &Row) -> Result<Vec<i64>, Fault> {
    let uid = user.val("id");
    let direct = ints(
        db::rows(
            c,
            r#"select "device_groups"."id" from "device_groups" inner join "device_group_user" on "device_groups"."id" = "device_group_user"."device_group_id" where "device_group_user"."user_id" = ?"#,
            &[P(uid.clone())],
        )?,
        "id",
    );
    let via_groups = ints(
        db::rows(
            c,
            r#"select "device_group_user_group"."device_group_id" from "device_group_user_group" inner join "user_group_user" on "user_group_user"."user_group_id" = "device_group_user_group"."user_group_id" where "user_group_user"."user_id" = ?"#,
            &[P(uid.clone())],
        )?,
        "device_group_id",
    );
    // groupAccessTargetIds(TARGET_DEVICE_GROUP)
    let ugs = user_group_ids(c, &uid)?;
    let mut sql = String::from(r#"select "target_id" from "group_accesses" where "target_type" = ? and (("accessor_type" = ? and "accessor_id" = ?)"#);
    let mut params = vec![P(Val::str("device_group")), P(Val::str("user")), P(uid)];
    if !ugs.is_empty() {
        sql.push_str(&format!(r#" or ("accessor_type" = ? and "accessor_id" in ({})))"#, marks(ugs.len())));
        params.push(P(Val::str("user_group")));
        params.extend(ugs.iter().map(|&i| P(Val::Int(i))));
    } else {
        sql.push(')');
    }
    let via_access = ints(db::rows(c, &sql, &params)?, "target_id");
    let mut out: Vec<i64> = vec![];
    for id in direct.into_iter().chain(via_groups).chain(via_access) {
        if !out.contains(&id) {
            out.push(id);
        }
    }
    Ok(out)
}

/// `Device::query()->visibleTo($user)` (approved, not in the recycle bin), with an extra condition, ordered.
pub fn visible_devices(c: &Connection, user: &Row, extra: Option<(&str, Val)>, order_by: &str) -> Result<Vec<Row>, Fault> {
    let mut sql = String::from(r#"select * from "devices" where "#);
    let mut params = vec![];
    if !user.val("is_admin").to_bool() {
        let groups = accessible_device_group_ids(c, user)?;
        sql.push_str(r#"("user_id" = ?"#);
        params.push(P(user.val("id")));
        if !groups.is_empty() {
            sql.push_str(&format!(r#" or "device_group_id" in ({})"#, marks(groups.len())));
            params.extend(groups.iter().map(|&g| P(Val::Int(g))));
        }
        sql.push_str(") and ");
    }
    sql.push_str(r#""status" = ? and "devices"."deleted_at" is null"#);
    params.push(P(Val::str("active")));
    if let Some((col, v)) = extra {
        // `col` is this crate's constant
        sql.push_str(&format!(r#" and "{col}" = ?"#));
        params.push(P(v));
    }
    if !order_by.is_empty() {
        sql.push_str(&format!(r#" order by "{order_by}" asc"#));
    }
    db::rows(c, &sql, &params)
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// A JSON object as the previous console writes `(object) $array` (`{}` when empty, keys in order), values already encoded.
fn object(pairs: &[(String, String)]) -> Result<String, Fault> {
    let mut out = String::from("{");
    for (n, (k, v)) in pairs.iter().enumerate() {
        if n > 0 {
            out.push(',');
        }
        php::enc_str(k.as_bytes(), &mut out).ok_or_else(|| Fault::Other("json_encode: a key is not UTF-8".into()))?;
        out.push(':');
        out.push_str(v);
    }
    out.push('}');
    Ok(out)
}

fn enc(v: &Val) -> Result<String, Fault> {
    php::json_encode(v).ok_or_else(|| Fault::Other("json_encode of the policy failed".into()))
}

/// `ksort` of the hash map, then `(object)`. The keys are sha256 hex digests, compared as the previous console's runtime (8) compares two
/// non-numeric strings (a digest made only of digits would be an integer key in the previous console: one in 10^13, ignored).
fn ksorted(mut v: Vec<(String, String)>) -> Result<String, Fault> {
    v.sort_by(|a, b| php::smart_strcmp(a.0.as_bytes(), b.0.as_bytes()));
    object(&v)
}

/// The live client tokens as `ServerLink::policy` and `Reach::policyBlock` select them.
fn live_tokens(c: &Connection, extra: &str, now: i64) -> Result<Vec<Row>, Fault> {
    db::rows(
        c,
        &format!(r#"select "id", "token", "device_id", "user_id" from "client_tokens" where {extra} and ("expires_at" is null or "expires_at" > ?) order by "id" asc"#),
        &[P(Val::str(&laravel::ts(now)))],
    )
}

/// `Reach::policyBlock()`, encoded: `{"enforce":..,"users":{..},"token_users":{..}}`; empty when the setting is off.
pub fn policy_block(c: &Connection, now: i64) -> Result<String, Fault> {
    if !enforced(c)? {
        return Ok(r#"{"enforce":false,"users":{},"token_users":{}}"#.to_string());
    }
    let mut users: Vec<(String, String)> = vec![];
    for user in db::rows(c, r#"select * from "users" where "is_active" = ? order by "id" asc"#, &[P(Val::Bool(true))])? {
        let admin = user.val("is_admin").to_bool();
        let mut devices = php::Arr::new();
        if !admin {
            for d in visible_devices(c, &user, None, "rustdesk_id")? {
                devices.push(d.val("rustdesk_id"));
            }
        }
        let entry = php::assoc(vec![
            ("name".to_string(), Val::Str(user.val("username").to_php_string()?)),
            ("all".to_string(), Val::Bool(admin)),
            ("devices".to_string(), Val::Arr(devices)),
        ]);
        users.push((String::from_utf8_lossy(&user.val("id").to_php_string()?).into_owned(), enc(&entry)?));
    }
    // A disabled person's tokens map to nobody: hbbs refuses them.
    let mut token_users: Vec<(String, String)> = vec![];
    for row in live_tokens(c, r#""user_id" is not null"#, now)? {
        let uid = String::from_utf8_lossy(&row.val("user_id").to_php_string()?).into_owned();
        if users.iter().any(|(k, _)| *k == uid) {
            let h = sha256_hex(&row.val("token").to_php_string()?);
            token_users.retain(|(k, _)| *k != h);
            token_users.push((h, enc(&Val::str(&uid))?));
        }
    }
    Ok(format!(r#"{{"enforce":true,"users":{},"token_users":{}}}"#, object(&users)?, ksorted(token_users)?))
}

/// `ServerLink::policy()`, encoded as `response()->json()` writes it: what hbbs enforces, HTE Remote's `scope` included.
pub fn server_policy(c: &Connection, now: i64) -> Result<String, Fault> {
    let mut allow = php::Arr::new();
    let mut incoming_only = php::Arr::new();
    for d in db::rows(c, r#"select "id", "rustdesk_id", "can_initiate" from "devices" where "status" = ? and "devices"."deleted_at" is null order by "id" asc"#, &[P(Val::str("active"))])? {
        if d.val("can_initiate").to_bool() {
            allow.push(d.val("rustdesk_id"));
        } else {
            incoming_only.push(d.val("rustdesk_id"));
        }
    }
    let mut tokens: Vec<(String, String)> = vec![];
    for row in live_tokens(c, r#""device_id" is not null and "device_id" != ''"#, now)? {
        let h = sha256_hex(&row.val("token").to_php_string()?);
        tokens.retain(|(k, _)| *k != h);
        tokens.push((h, enc(&Val::Str(row.val("device_id").to_php_string()?))?));
    }
    let mode = if db::setting(c, "server_access_mode", "open")? == b"approved" { "approved" } else { "open" };
    let ip_match = db::setting(c, "server_ip_match", "0")? == b"1";
    // HTE: the live share links ride in the scope block, only when there are any (the block is unchanged otherwise)
    let mut scope = policy_block(c, now)?;
    if let Some(shares) = crate::pages::share::live_policy(c, now)? {
        scope.pop();
        scope.push_str(&format!(r#","shares":{shares}}}"#));
    }
    Ok(format!(
        r#"{{"mode":{},"allow":{},"incoming_only":{},"tokens":{},"ip_match":{},"scope":{}}}"#,
        enc(&Val::str(mode))?,
        enc(&Val::Arr(allow))?,
        enc(&Val::Arr(incoming_only))?,
        ksorted(tokens)?,
        ip_match,
        scope
    ))
}

fn user_by_id(c: &Connection, id: &Val) -> Result<Option<Row>, Fault> {
    db::first(c, r#"select * from "users" where "users"."id" = ? limit 1"#, &[P(id.clone())])
}

/// `User::query()->whereIn('id', $ids)->get()` (an empty list is `0 = 1`).
fn users_in(c: &Connection, ids: &[Val]) -> Result<Vec<Row>, Fault> {
    if ids.is_empty() {
        return Ok(vec![]);
    }
    db::rows(c, &format!(r#"select * from "users" where "id" in ({})"#, marks(ids.len())), &ids.iter().cloned().map(P).collect::<Vec<_>>())
}

fn members(c: &Connection, user_group_id: &Val) -> Result<Vec<Row>, Fault> {
    let ids: Vec<Val> = db::rows(c, r#"select "user_id" from "user_group_user" where "user_group_id" = ?"#, &[P(user_group_id.clone())])?.iter().map(|r| r.val("user_id")).collect();
    users_in(c, &ids)
}

/// `Passwords::reachIds($device)`: the ids of the active people `Reach::sections` lists for the device
/// (administrators, owner, then each way into its group), sorted, each once.
pub fn reach_ids(c: &Connection, device: &Row) -> Result<Vec<i64>, Fault> {
    let mut seen: Vec<i64> = vec![];
    let mut add = |users: Vec<Row>| {
        for u in users {
            if u.val("is_active").to_bool() && !seen.contains(&u.id()) {
                seen.push(u.id());
            }
        }
    };
    add(db::rows(c, r#"select * from "users" where "is_admin" = ? order by "username" asc"#, &[P(Val::Bool(true))])?);
    if !device.is_null("user_id") {
        if let Some(owner) = user_by_id(c, &device.val("user_id"))? {
            add(vec![owner]);
        }
    }
    let group = match device.val("device_group_id") {
        Val::Null => None,
        g => db::first(c, r#"select * from "device_groups" where "device_groups"."id" = ? limit 1"#, &[P(g)])?,
    };
    if let Some(group) = group {
        let gid = group.val("id");
        let direct: Vec<Val> = db::rows(c, r#"select "user_id" from "device_group_user" where "device_group_id" = ?"#, &[P(gid.clone())])?.iter().map(|r| r.val("user_id")).collect();
        add(users_in(c, &direct)?);
        for ug in db::rows(
            c,
            r#"select "user_groups"."id", "user_groups"."name" from "device_group_user_group" inner join "user_groups" on "user_groups"."id" = "device_group_user_group"."user_group_id" where "device_group_user_group"."device_group_id" = ? order by "user_groups"."name" asc"#,
            &[P(gid.clone())],
        )? {
            add(members(c, &ug.val("id"))?);
        }
        let accesses = db::rows(c, r#"select * from "group_accesses" where "target_type" = ? and "target_id" = ?"#, &[P(Val::str("device_group")), P(gid)])?;
        // Collection::where uses loose comparison: 'user' == 'user'
        let pick = |t: &str| accesses.iter().filter(|a| a.val("accessor_type").to_php_string().ok().as_deref() == Some(t.as_bytes())).map(|a| a.val("accessor_id")).collect::<Vec<Val>>();
        let direct_ids = pick("user");
        if !direct_ids.is_empty() {
            add(users_in(c, &direct_ids)?);
        }
        let group_ids = pick("user_group");
        if !group_ids.is_empty() {
            let sql = format!(r#"select "id", "name" from "user_groups" where "id" in ({}) order by "name" asc"#, marks(group_ids.len()));
            for ug in db::rows(c, &sql, &group_ids.iter().cloned().map(P).collect::<Vec<_>>())? {
                add(members(c, &ug.val("id"))?);
            }
        }
    }
    seen.sort_unstable();
    Ok(seen)
}

/// One row's writes all or none (the previous console's are separate statements; a failure half way, a busy database say, could leave
/// a disconnect without its alarm, or a lost person recorded without the new password: here the row is left as it
/// was and the next run does it again). The end state of a run that succeeds is the previous console's.
pub(crate) fn atomically<T>(c: &Connection, f: impl FnOnce() -> Result<T, Fault>) -> Result<T, Fault> {
    c.execute_batch("SAVEPOINT hte_row").map_err(db::fault)?;
    match f() {
        Ok(v) => {
            c.execute_batch("RELEASE hte_row").map_err(db::fault)?;
            Ok(v)
        }
        Err(e) => {
            let _ = c.execute_batch("ROLLBACK TO hte_row; RELEASE hte_row");
            Err(e)
        }
    }
}

/// `ConsoleAudit::system($action, $summary, $targetType, $targetId)`: a "system" line in the console log
/// (created_at only; no ip).
pub fn console_audit_system(c: &Connection, action: &str, summary: &str, target_type: &str, target_id: &[u8], now: i64) -> Result<(), Fault> {
    db::exec(
        c,
        r#"insert into "console_audits" ("user_id", "username", "action", "target_type", "target_id", "summary", "created_at") values (?, ?, ?, ?, ?, ?, ?)"#,
        &[
            P(Val::Null),
            P(Val::str("system")),
            P(Val::str(action)),
            P(Val::str(target_type)),
            P(Val::Str(target_id.to_vec())),
            P(Val::str(&str_limit(summary, 250, "..."))),
            P(Val::str(&laravel::ts(now))),
        ],
    )?;
    Ok(())
}

/// `AlarmLog::create([...])`: a console-raised alarm.
fn alarm(c: &Connection, typ: i64, conn_id: Option<Val>, info: &Val, now: i64) -> Result<i64, Fault> {
    let info = php::json_encode(info).ok_or_else(|| Fault::Other("json_encode of an alarm's info failed".into()))?;
    let mut cols = vec![("rustdesk_id", Val::str(CONSOLE_SOURCE)), ("typ", Val::Int(typ))];
    if let Some(cid) = conn_id {
        cols.push(("conn_id", cid));
    }
    cols.push(("info", Val::str(&info)));
    db::insert(c, "alarm_logs", cols, &laravel::ts(now))
}

fn device_by_rustdesk_id(c: &Connection, id: &[u8]) -> Result<Option<Row>, Fault> {
    db::first(c, r#"select * from "devices" where "rustdesk_id" = ? and "devices"."deleted_at" is null limit 1"#, &[P(Val::Str(id.to_vec()))])
}

/// `$d?->alias ?: ($d?->hostname ?: '')`
fn name_of(d: &Option<Row>) -> Result<Vec<u8>, Fault> {
    let Some(d) = d else { return Ok(vec![]) };
    for col in ["alias", "hostname"] {
        let v = d.val(col);
        if v.to_bool() {
            return v.to_php_string();
        }
    }
    Ok(vec![])
}

/// `Reach::recordRefusals($refusals)`: one admin-only alarm per refusal hbbs reported. `refusals` is the validated
/// list. Returns how many were recorded.
pub fn record_refusals(c: &Connection, refusals: &php::Arr, now: i64) -> Result<usize, Fault> {
    let mut n = 0;
    for (_, r) in refusals.iter() {
        let r = r.to_array();
        // (string) ($r['x'] ?? '')
        let s = |k: &str| -> Result<Vec<u8>, Fault> {
            match r.get_str(k) {
                None | Some(Val::Null) => Ok(vec![]),
                Some(v) => v.to_php_string(),
            }
        };
        let from = device_by_rustdesk_id(c, &s("from")?)?;
        let to = device_by_rustdesk_id(c, &s("to")?)?;
        let user = s("user_name")?;
        let user = if Val::Str(user.clone()).to_bool() { user } else { b"nobody signed in".to_vec() };
        let info = php::assoc(vec![
            ("user".to_string(), Val::Str(user)),
            ("user_id".to_string(), Val::Str(s("user_id")?)),
            ("from".to_string(), Val::Str(s("from")?)),
            ("from_name".to_string(), Val::Str(name_of(&from)?)),
            ("to".to_string(), Val::Str(s("to")?)),
            ("to_name".to_string(), Val::Str(name_of(&to)?)),
            ("ip".to_string(), Val::Str(s("ip")?)),
            ("reason".to_string(), Val::Str(s("reason")?)),
        ]);
        alarm(c, REFUSAL_ALARM, None, &info, now)?;
        n += 1;
    }
    Ok(n)
}

/// `ReachSweep::verdict($session)`: why this session must close, or None when it may stay.
pub fn verdict(c: &Connection, session: &Row, now: i64) -> Result<Option<String>, Fault> {
    let from = session.val("from_peer").to_php_string()?;
    let known = db::first(
        c,
        r#"select exists(select * from "devices" where "rustdesk_id" = ?) as "exists""#,
        &[P(Val::Str(from.clone()))],
    )?;
    if !known.map_or(false, |r| r.val("exists").to_bool()) {
        return Ok(None); // the web client or something the console does not know
    }
    let holder_ids: Vec<Val> = db::rows(
        c,
        r#"select "user_id" from "client_tokens" where "device_id" = ? and ("expires_at" is null or "expires_at" > ?)"#,
        &[P(Val::Str(from.clone())), P(Val::str(&laravel::ts(now)))],
    )?
    .iter()
    .map(|r| r.val("user_id"))
    .collect();
    let holders = users_in(c, &holder_ids)?;
    let active: Vec<&Row> = holders.iter().filter(|u| u.val("is_active").to_bool()).collect();
    let from_s = String::from_utf8_lossy(&from).into_owned();
    if active.is_empty() {
        return Ok(Some(if holders.is_empty() { format!("nobody is signed in on {from_s}") } else { format!("the person signed in on {from_s} is disabled") }));
    }
    let target = session.val("rustdesk_id");
    for u in &active {
        if u.val("is_admin").to_bool() || !visible_devices(c, u, Some(("rustdesk_id", Val::Str(target.to_php_string()?))), "")?.is_empty() {
            return Ok(None);
        }
    }
    let names: Vec<String> = active.iter().map(|u| String::from_utf8_lossy(&u.val("username").to_php_string().unwrap_or_default()).into_owned()).collect();
    Ok(Some(format!("{} may no longer reach {}", names.join(", "), String::from_utf8_lossy(&target.to_php_string()?))))
}

/// `ReachSweep::handle()`: every open session nobody signed in there may still reach is asked to close (the
/// console's own disconnect, delivered at the target's next check-in), with an alarm 103 and a system log line.
/// Returns how many were closed.
pub fn sweep(c: &Connection, now: i64) -> Result<usize, Fault> {
    if !enforced(c)? {
        return Ok(0);
    }
    let ts = laravel::ts(now);
    let mut closed = 0;
    let sessions = db::rows(
        c,
        r#"select * from "audit_connections" where "closed_at" is null and "disconnect_requested_at" is null and "conn_id" is not null and "from_peer" is not null and "from_peer" != ? order by "id" asc"#,
        &[P(Val::str(""))],
    )?;
    for mut s in sessions {
        let Some(why) = verdict(c, &s, now)? else { continue };
        atomically(c, || {
            db::update_dirty(
                c,
                "audit_connections",
                &mut s,
                vec![
                    ("disconnect_requested_at", Val::str(&ts), laravel::Cast::Date),
                    ("disconnect_sent_at", Val::Null, laravel::Cast::Date),
                    ("disconnect_requested_by", Val::Null, laravel::Cast::Plain),
                ],
                &ts,
            )?;
            let from = s.val("from_peer").to_php_string()?;
            let to = s.val("rustdesk_id").to_php_string()?;
            let info = php::assoc(vec![("from".to_string(), Val::Str(from.clone())), ("to".to_string(), Val::Str(to.clone())), ("reason".to_string(), Val::str(&why))]);
            alarm(c, SWEEP_ALARM, Some(s.val("conn_id")), &info, now)?;
            let summary = format!(
                "Closed session {} from {} on {}: {why}",
                String::from_utf8_lossy(&s.val("conn_id").to_php_string()?),
                String::from_utf8_lossy(&from),
                String::from_utf8_lossy(&to)
            );
            console_audit_system(c, "session.disconnect", &summary, "device", &to, now)
        })?;
        closed += 1;
    }
    if closed > 0 {
        tracing::info!("reach sweep: closed {closed} session(s)");
    }
    Ok(closed)
}
