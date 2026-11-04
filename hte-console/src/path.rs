//! How each session got through (CortenDesk 1.19's connection paths, ported by idea; HTE Remote's own code).
//!
//! Two sources, neither enough alone:
//!
//! - `hbbs` tags the request it sends a device (`cd1/lan`, `cd1/punch`, `cd1/punch-webrtc`, `cd1/relay`) and RustDesk 1.5 devices echo the
//!   tag as `conn_audit_ref` in their connection audit (`audit.rs` stores it in `audit_connections.path`). That says how the attempt
//!   started, not where it ended: one punch hole starts TCP, UDP, IPv6, WebRTC and sometimes relay attempts at once, all with the same tag.
//! - `hbbr` reports every session it carries (`POST /api/server/relay-sessions`, `relay_sessions`): the only proof a session was relayed, and
//!   it works for any client version.
//!
//! Every attempt a device opens posts its own audit row, and the losing attempts close within seconds without logging in. A relay session
//! is therefore linked to one row only, the one it carried: the row that logged in if there is one, and only while the relay lived as long
//! as that row (`link_relay`).

use crate::laravel;
use crate::php::{self, Fault, Val};
use crate::sqlite::{self as db, Row, P};
use rusqlite::Connection;

pub const PATHS: [&str; 4] = ["lan", "punch", "punch-webrtc", "relay"];
const TAG_PREFIX: &str = "cd1/";
/// A relay session and the device's record of it start this close together.
pub const MATCH_WINDOW_SECONDS: i64 = 30;
/// A carried session's relay closes within this of the device's close.
pub const END_SLACK_SECONDS: i64 = 15;
/// More than a losing attempt ever carries before it is dropped.
pub const CARRIED_BYTES: i64 = 1_048_576;

/// `relay_sessions` and the two columns on `audit_connections` (an own migration, `migrate.rs`; runs once, in a transaction).
pub const SCHEMA: &str = r#"
create table "relay_sessions" (
    "id" integer primary key autoincrement not null,
    "uuid" varchar not null,
    "rustdesk_id" varchar not null,
    "conn_type" integer not null default 0,
    "controller_ip" varchar,
    "device_ip" varchar,
    "started_at" datetime,
    "ended_at" datetime,
    "bytes" integer not null default 0,
    "created_at" datetime,
    "updated_at" datetime
);
create unique index "relay_sessions_uuid_unique" on "relay_sessions" ("uuid");
create index "relay_sessions_rustdesk_id_index" on "relay_sessions" ("rustdesk_id");
create index "relay_sessions_started_at_index" on "relay_sessions" ("started_at");
alter table "audit_connections" add column "path" varchar;
alter table "audit_connections" add column "relay_session_id" integer references "relay_sessions" ("id") on delete set null;
create index "audit_connections_relay_session_id_index" on "audit_connections" ("relay_session_id");
"#;

/// The path out of a device's `conn_audit_ref`, or None when it is not ours.
pub fn from_tag(tag: &Val) -> Option<&'static str> {
    let Val::Str(t) = tag else { return None };
    let path = std::str::from_utf8(t).ok()?.strip_prefix(TAG_PREFIX)?;
    PATHS.iter().copied().find(|p| *p == path)
}

/// hbbr's `ConnType` to the console's session type (`logs::CONN_TYPES`).
pub fn session_type(relay_conn_type: i64) -> i64 {
    match relay_conn_type {
        0 => 0,
        1 => 1,
        2 | 3 => 2,
        4 => 3,
        5 => 4,
        _ => 0,
    }
}

/// How a connection got through, folded to what the screens show: `relay`, `lan`, `direct`, `direct-webrtc`, or None when nothing says.
/// Relay is proven by hbbr's own report; the rest is hbbs's tag as the device echoed it.
pub fn transport(path: Option<&str>, relayed: bool) -> Option<&'static str> {
    if relayed {
        return Some("relay");
    }
    match path? {
        "relay" => Some("relay"),
        "lan" => Some("lan"),
        "punch" => Some("direct"),
        "punch-webrtc" => Some("direct-webrtc"),
        _ => None,
    }
}

pub fn transport_label(t: Option<&str>) -> &'static str {
    match t {
        Some("relay") => "Relay",
        Some("lan") => "LAN",
        Some("direct") => "Hole punch",
        Some("direct-webrtc") => "WebRTC",
        _ => "—",
    }
}

/// The four the filter and the dashboard bar count by: `relay`, `direct`, `lan`, `unknown` (WebRTC counts as direct).
pub const FILTERS: [(&str, &str); 4] = [("lan", "LAN"), ("direct", "Direct (hole punch or WebRTC)"), ("relay", "Relay"), ("unknown", "Unknown")];

/// The SQL of `transport()` folded to `FILTERS`.
pub const TRANSPORT_SQL: &str = r#"case when "relay_session_id" is not null or "path" = 'relay' then 'relay' when "path" = 'lan' then 'lan' when "path" in ('punch', 'punch-webrtc') then 'direct' else 'unknown' end"#;

/// A `where` fragment narrowing `audit_connections` to one of `FILTERS`, or None for any other value.
pub fn filter_sql(filter: &str) -> Option<&'static str> {
    match filter {
        "relay" => Some(r#"("relay_session_id" is not null or "path" = 'relay')"#),
        "lan" => Some(r#"("relay_session_id" is null and "path" = 'lan')"#),
        "direct" => Some(r#"("relay_session_id" is null and "path" in ('punch', 'punch-webrtc'))"#),
        "unknown" => Some(r#"("relay_session_id" is null and "path" is null)"#),
        _ => None,
    }
}

fn st(r: &Row, col: &str) -> String {
    String::from_utf8_lossy(&r.val(col).to_php_string().unwrap_or_default()).into_owned()
}

fn at(r: &Row, col: &str) -> Option<i64> {
    laravel::parse_ts(&r.val(col))
}

/// `POST /api/server/relay-sessions`: once when a pair opens and again with `ended_at` and `bytes` when it closes. Upserted on the uuid;
/// batches can arrive late or twice. `reports` is the validated `sessions` array.
pub fn store_relay_sessions(c: &Connection, reports: &php::Arr, now: i64) -> Result<usize, Fault> {
    let ts = laravel::ts(now);
    let mut n = 0;
    for (_, report) in reports.iter() {
        let report = report.to_array();
        let get = |k: &str| match report.get_str(k) {
            None | Some(Val::Null) => None,
            Some(v) => Some(v.clone()),
        };
        let Some(uuid) = get("uuid") else { continue };
        let uuid = uuid.to_php_string()?;
        let id = get("id").map_or(Ok(vec![]), |v| v.to_php_string())?;
        // a skewed clock must not date the future
        let reported = |k: &str| get(k).map(|v| v.to_int()).filter(|t| *t > 0).map(|t| t.min(now));
        let existing = db::first(c, r#"select * from "relay_sessions" where "uuid" = ? limit 1"#, &[P(Val::Str(uuid.clone()))])?;
        let conn_type = session_type(get("conn_type").map_or(0, |v| v.to_int()));
        let ended = reported("ended_at").or(if get("ended_at").is_some() { Some(now) } else { None });
        let relay_id = match existing {
            None => db::insert(
                c,
                "relay_sessions",
                vec![
                    ("uuid", Val::Str(uuid)),
                    ("rustdesk_id", Val::Str(id)),
                    ("conn_type", Val::Int(conn_type)),
                    ("controller_ip", get("controller_ip").unwrap_or(Val::Null)),
                    ("device_ip", get("device_ip").unwrap_or(Val::Null)),
                    ("started_at", Val::str(&laravel::ts(reported("started_at").unwrap_or(now)))),
                    ("ended_at", ended.map_or(Val::Null, |t| Val::str(&laravel::ts(t)))),
                    ("bytes", Val::Int(if ended.is_some() { get("bytes").map_or(0, |v| v.to_int()).max(0) } else { 0 })),
                ],
                &ts,
            )?,
            Some(row) => {
                // a close is never undone by a late copy of the open; the bytes only grow
                let bytes = if ended.is_some() { row.val("bytes").to_int().max(get("bytes").map_or(0, |v| v.to_int())) } else { row.val("bytes").to_int() };
                db::exec(
                    c,
                    r#"update "relay_sessions" set "rustdesk_id" = ?, "conn_type" = ?, "controller_ip" = coalesce(?, "controller_ip"), "device_ip" = coalesce(?, "device_ip"), "ended_at" = coalesce(?, "ended_at"), "bytes" = ?, "updated_at" = ? where "id" = ?"#,
                    &[
                        P(Val::Str(id)),
                        P(Val::Int(conn_type)),
                        P(get("controller_ip").unwrap_or(Val::Null)),
                        P(get("device_ip").unwrap_or(Val::Null)),
                        P(ended.map_or(Val::Null, |t| Val::str(&laravel::ts(t)))),
                        P(Val::Int(bytes)),
                        P(Val::str(&ts)),
                        P(Val::Int(row.id())),
                    ],
                )?;
                row.id()
            }
        };
        if let Some(relay) = db::first(c, r#"select * from "relay_sessions" where "id" = ?"#, &[P(Val::Int(relay_id))])? {
            link_relay(c, &relay)?;
        }
        n += 1;
    }
    Ok(n)
}

/// Re-decide which connection, if any, this relay session carried.
pub fn link_relay(c: &Connection, relay: &Row) -> Result<(), Fault> {
    let start = at(relay, "started_at").or_else(|| at(relay, "created_at")).unwrap_or(0);
    let rows = db::rows(
        c,
        r#"select * from "audit_connections" where "rustdesk_id" = ? and "created_at" between ? and ?"#,
        &[P(relay.val("rustdesk_id")), P(Val::str(&laravel::ts(start - MATCH_WINDOW_SECONDS))), P(Val::str(&laravel::ts(start + MATCH_WINDOW_SECONDS)))],
    )?;
    let relay_type = relay.val("conn_type").to_int();
    let mut candidates: Vec<&Row> = rows
        .iter()
        .filter(|r| st(r, "from_peer").is_empty() || r.val("conn_type").to_int() == relay_type)
        .collect();
    // logged in before not, then closest in time
    candidates.sort_by_key(|r| (if st(r, "from_peer").is_empty() { 1 } else { 0 }, (at(r, "created_at").unwrap_or(0) - start).abs()));
    let best = candidates.into_iter().find(|r| carried(relay, r));
    let relay_id = relay.id();
    match best {
        Some(b) => {
            db::exec(c, r#"update "audit_connections" set "relay_session_id" = null where "relay_session_id" = ? and "id" != ?"#, &[P(Val::Int(relay_id)), P(Val::Int(b.id()))])?;
            if b.val("relay_session_id").to_int() != relay_id || b.is_null("relay_session_id") {
                db::exec(c, r#"update "audit_connections" set "relay_session_id" = ? where "id" = ?"#, &[P(Val::Int(relay_id)), P(Val::Int(b.id()))])?;
            }
        }
        None => {
            db::exec(c, r#"update "audit_connections" set "relay_session_id" = null where "relay_session_id" = ?"#, &[P(Val::Int(relay_id))])?;
        }
    }
    Ok(())
}

/// Did this relay session carry this connection, rather than lose the race to another attempt?
fn carried(relay: &Row, row: &Row) -> bool {
    if relay.val("bytes").to_int() >= CARRIED_BYTES {
        return true;
    }
    // still relaying: the connection's own close may simply not be in yet
    let Some(ended) = at(relay, "ended_at") else { return true };
    // the relay closed and the connection goes on: another attempt won
    let Some(closed) = at(row, "closed_at") else { return false };
    ended >= closed - END_SLACK_SECONDS
}

/// A connection logged in or closed: re-decide the relay sessions around it.
pub fn refresh(c: &Connection, rustdesk_id: &Val, created_at: i64) -> Result<(), Fault> {
    let relays = db::rows(
        c,
        r#"select * from "relay_sessions" where "rustdesk_id" = ? and "started_at" between ? and ?"#,
        &[P(rustdesk_id.clone()), P(Val::str(&laravel::ts(created_at - MATCH_WINDOW_SECONDS))), P(Val::str(&laravel::ts(created_at + MATCH_WINDOW_SECONDS)))],
    )?;
    for relay in &relays {
        link_relay(c, relay)?;
    }
    Ok(())
}

/// The relay session each row points at, by id: for the log's "Relayed" size and the device page.
pub fn relay_bytes(c: &Connection, rows: &[Row]) -> Result<std::collections::HashMap<i64, i64>, Fault> {
    let mut ids: Vec<i64> = rows.iter().filter_map(|r| if let Val::Int(i) = r.val("relay_session_id") { Some(i) } else { None }).collect();
    ids.sort_unstable();
    ids.dedup();
    let mut out = std::collections::HashMap::new();
    if !ids.is_empty() {
        let sql = format!(r#"select "id", "bytes" from "relay_sessions" where "id" in ({})"#, vec!["?"; ids.len()].join(", "));
        for r in db::rows(c, &sql, &ids.iter().map(|i| P(Val::Int(*i))).collect::<Vec<_>>())? {
            out.insert(r.id(), r.val("bytes").to_int());
        }
    }
    Ok(out)
}

/// "12.3 MB" (decimal units, as the relay's limits are set in).
pub fn human_bytes(n: i64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = n.max(0) as f64;
    let mut u = 0;
    while v >= 1000.0 && u < UNITS.len() - 1 {
        v /= 1000.0;
        u += 1;
    }
    if u == 0 {
        format!("{} B", n.max(0))
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            r#"create table "audit_connections" ("id" integer primary key autoincrement not null, "rustdesk_id" varchar, "from_peer" varchar, "conn_type" integer, "created_at" datetime, "closed_at" datetime, "updated_at" datetime)"#,
        )
        .unwrap();
        c.execute_batch(SCHEMA).unwrap();
        c
    }

    fn conn(c: &Connection, id: &str, from: &str, created: i64, closed: Option<i64>) -> i64 {
        c.execute(
            r#"insert into "audit_connections" ("rustdesk_id", "from_peer", "conn_type", "created_at", "closed_at") values (?, ?, 0, ?, ?)"#,
            rusqlite::params![id, from, laravel::ts(created), closed.map(laravel::ts)],
        )
        .unwrap();
        c.last_insert_rowid()
    }

    fn report(uuid: &str, id: &str, started: i64, ended: Option<i64>, bytes: i64) -> php::Arr {
        let mut items = vec![
            ("uuid".to_string(), Val::str(uuid)),
            ("id".to_string(), Val::str(id)),
            ("conn_type".to_string(), Val::Int(0)),
            ("controller_ip".to_string(), Val::str("203.0.113.5")),
            ("device_ip".to_string(), Val::str("198.51.100.7")),
            ("started_at".to_string(), Val::Int(started)),
        ];
        if let Some(e) = ended {
            items.push(("ended_at".to_string(), Val::Int(e)));
            items.push(("bytes".to_string(), Val::Int(bytes)));
        }
        let mut list = php::Arr::new();
        list.set(php::Key::Int(0), php::assoc(items));
        list
    }

    fn linked(c: &Connection, conn: i64) -> Option<i64> {
        c.query_row(r#"select "relay_session_id" from "audit_connections" where "id" = ?"#, [conn], |r| r.get(0)).unwrap()
    }

    #[test]
    fn the_tag_is_ours_or_nothing() {
        assert_eq!(from_tag(&Val::str("cd1/lan")), Some("lan"));
        assert_eq!(from_tag(&Val::str("cd1/punch-webrtc")), Some("punch-webrtc"));
        assert_eq!(from_tag(&Val::str("cd1/other")), None);
        assert_eq!(from_tag(&Val::str("lan")), None);
        assert_eq!(from_tag(&Val::Null), None);
    }

    #[test]
    fn what_a_row_says_about_its_path() {
        assert_eq!(transport(Some("punch"), false), Some("direct"));
        assert_eq!(transport(Some("punch"), true), Some("relay"), "a relay report beats the tag: a punch can still end relayed");
        assert_eq!(transport(None, false), None);
        assert_eq!(transport_label(transport(Some("lan"), false)), "LAN");
        assert_eq!(transport_label(None), "—");
    }

    #[test]
    fn a_relay_report_links_the_row_it_carried_and_a_late_copy_changes_nothing() {
        let c = db();
        let t = 1_800_000_000;
        // the login that held and a losing attempt that closed within seconds without one
        let won = conn(&c, "111", "222", t, Some(t + 600));
        let lost = conn(&c, "111", "", t + 1, Some(t + 3));
        store_relay_sessions(&c, &report("u1", "111", t, None, 0), t + 1).unwrap();
        assert_eq!(linked(&c, won), Some(1), "still relaying: the logged-in row");
        assert_eq!(linked(&c, lost), None);
        store_relay_sessions(&c, &report("u1", "111", t, Some(t + 600), 5_000_000), t + 601).unwrap();
        assert_eq!(linked(&c, won), Some(1));
        // the open arrives again after the close: the close stands
        store_relay_sessions(&c, &report("u1", "111", t, None, 0), t + 700).unwrap();
        let (ended, bytes): (Option<String>, i64) = c.query_row(r#"select "ended_at", "bytes" from "relay_sessions""#, [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert!(ended.is_some());
        assert_eq!(bytes, 5_000_000);
        assert_eq!(c.query_row(r#"select count(*) from "relay_sessions""#, [], |r| r.get::<_, i64>(0)).unwrap(), 1);
    }

    #[test]
    fn a_relay_that_closed_early_does_not_claim_a_connection_that_went_on() {
        let c = db();
        let t = 1_800_000_000;
        // the relay attempt lost the race to a direct one: it carried little and closed long before the row did
        let direct = conn(&c, "111", "222", t, None);
        store_relay_sessions(&c, &report("u1", "111", t, Some(t + 2), 300), t + 3).unwrap();
        assert_eq!(linked(&c, direct), None);
        // refresh when the row closes: the relay outlived it, so now it is the one
        let other = conn(&c, "333", "444", t, Some(t + 100));
        store_relay_sessions(&c, &report("u2", "333", t, Some(t + 99), 400), t + 100).unwrap();
        assert_eq!(linked(&c, other), Some(2));
    }

    #[test]
    fn an_unmatched_row_stays_unknown_and_refresh_finds_late_rows() {
        let c = db();
        let t = 1_800_000_000;
        store_relay_sessions(&c, &report("u1", "111", t, None, 0), t).unwrap();
        // the device's audit arrives after the report
        let late = conn(&c, "111", "222", t + 5, None);
        refresh(&c, &Val::str("111"), t + 5).unwrap();
        assert_eq!(linked(&c, late), Some(1));
        // another device's id is never linked
        let other = conn(&c, "999", "222", t + 5, None);
        refresh(&c, &Val::str("999"), t + 5).unwrap();
        assert_eq!(linked(&c, other), None);
    }

    #[test]
    fn the_filters_agree_with_transport() {
        let c = db();
        c.execute_batch(r#"insert into "audit_connections" ("rustdesk_id", "path") values ('1', 'lan'), ('2', 'punch'), ('3', 'punch-webrtc'), ('4', 'relay'), ('5', null)"#).unwrap();
        c.execute_batch(r#"insert into "relay_sessions" ("uuid", "rustdesk_id") values ('x', '2')"#).unwrap();
        c.execute_batch(r#"update "audit_connections" set "relay_session_id" = 1 where "rustdesk_id" = '2'"#).unwrap();
        let count = |sql: &str| -> i64 { c.query_row(&format!(r#"select count(*) from "audit_connections" where {sql}"#), [], |r| r.get(0)).unwrap() };
        assert_eq!(count(filter_sql("lan").unwrap()), 1);
        assert_eq!(count(filter_sql("direct").unwrap()), 1, "a punch that ended on the relay counts as relay");
        assert_eq!(count(filter_sql("relay").unwrap()), 2);
        assert_eq!(count(filter_sql("unknown").unwrap()), 1);
        assert!(filter_sql("anything").is_none());
        let by: Vec<String> = c.prepare(&format!(r#"select {TRANSPORT_SQL} from "audit_connections" order by "id""#)).unwrap().query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect();
        assert_eq!(by, ["lan", "relay", "direct", "relay", "unknown"]);
    }

    #[test]
    fn sizes_read_in_decimal_units() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(12_345_678), "12.3 MB");
        assert_eq!(human_bytes(3_000_000_000), "3.0 GB");
    }
}
