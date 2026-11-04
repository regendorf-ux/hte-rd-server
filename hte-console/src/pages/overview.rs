//! The Overview (`DashboardController`, the previous console's `LiveStats` and `ActiveSessions`): the stat tiles, the connections and
//! platform charts, the live sessions with their Disconnect, the client versions and the day's alarms. Every panel built
//! from the audit logs needs the audit permission, and a person who does not see every device only sees theirs.
//!
//! The two polled panels (`wire:poll.15s`) are fragments the page asks for again every 15 seconds.

use super::kit::*;
use super::{Ctx, Reply, Req};
use crate::php::{self, Fault, Val};
use crate::sqlite::{self as db, Row, P};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

const RANGES: [i64; 3] = [14, 30, 90];

fn can_audit(ctx: &Ctx) -> bool {
    ctx.allows("audit", "r")
}

/// The rustdesk ids the audit panels are limited to: None = every device.
fn scope(ctx: &Ctx, c: &Connection) -> Result<Option<Vec<String>>, Fault> {
    if !can_audit(ctx) || ctx.is_admin() {
        return Ok(None);
    }
    let w = visible(c, &ctx.user, false)?;
    let rows = db::rows(c, &format!(r#"select "rustdesk_id" from "devices"{}"#, w.sql()), &w.params.clone())?;
    Ok(Some(rows.iter().map(|r| s(r, "rustdesk_id")).collect()))
}

/// ` and "rustdesk_id" in (...)` for a limited person; a person with no devices matches nothing.
fn limit(ids: &Option<Vec<String>>) -> (String, Vec<P>) {
    match ids {
        None => (String::new(), vec![]),
        Some(v) if v.is_empty() => (" and 0 = 1".into(), vec![]),
        Some(v) => (format!(r#" and "rustdesk_id" in ({})"#, marks(v.len())), v.iter().map(|x| P(Val::str(x))).collect()),
    }
}

fn day(ts: i64) -> String {
    crate::laravel::ts(ts)[..10].to_string()
}

pub fn stats(ctx: &Ctx, c: &Connection) -> Result<Value, Fault> {
    let audit = can_audit(ctx);
    let admin = ctx.is_admin();
    let ids = scope(ctx, c)?;
    let window = online_window(c)?;
    let w = visible(c, &ctx.user, false)?;
    let base = w.sql();
    let params = w.params.clone();
    let devices = count(c, &format!(r#"select count(*) as aggregate from "devices"{base}"#), &params)?;
    let online = {
        let mut p = params.clone();
        p.push(P(Val::str(&crate::laravel::ts(ctx.now - window))));
        count(c, &format!(r#"select count(*) as aggregate from "devices"{base} and "last_online_at" > ?"#), &p)?
    };
    let new_devices = {
        let mut p = params.clone();
        p.push(P(Val::str(&crate::laravel::ts(ctx.now - 14 * 86400))));
        count(c, &format!(r#"select count(*) as aggregate from "devices"{base} and "created_at" >= ?"#), &p)?
    };
    let prior = {
        let mut p = params.clone();
        p.push(P(Val::str(&crate::laravel::ts(ctx.now - 28 * 86400))));
        p.push(P(Val::str(&crate::laravel::ts(ctx.now - 14 * 86400))));
        count(c, &format!(r#"select count(*) as aggregate from "devices"{base} and "created_at" between ? and ?"#), &p)?
    };
    let mut out = Map::new();
    out.insert("devices".into(), json!(devices));
    out.insert("online".into(), json!(online));
    out.insert("online_pct".into(), if devices > 0 { json!((online as f64 / devices as f64 * 100.0).round() as i64) } else { Value::Null });
    out.insert("device_trend".into(), json!(new_devices - prior));
    out.insert("admin".into(), json!(admin));
    out.insert("can_audit".into(), json!(audit));
    let today = day(ctx.now);
    let yesterday = day(ctx.now - 86400);
    out.insert("users".into(), if admin { json!(count(c, r#"select count(*) as aggregate from "users""#, &[])?) } else { Value::Null });
    out.insert(
        "users_today".into(),
        if admin {
            json!(count(c, r#"select count(distinct "user_id") as aggregate from "login_logs" where "successful" = ? and "client" in (?, ?) and strftime('%Y-%m-%d', "created_at") = cast(? as text)"#, &[P(Val::Bool(true)), P(Val::str("web")), P(Val::str("sso")), P(Val::str(&today))])?)
        } else {
            Value::Null
        },
    );
    let (cond, cp) = limit(&ids);
    let on_day = |d: &str| -> Result<i64, Fault> {
        let mut p = vec![P(Val::str(d))];
        p.extend(cp.clone());
        count(c, &format!(r#"select count(*) as aggregate from "audit_connections" where strftime('%Y-%m-%d', "created_at") = cast(? as text){cond}"#), &p)
    };
    let (conn_today, conn_yesterday) = if audit { (on_day(&today)?, on_day(&yesterday)?) } else { (0, 0) };
    out.insert("connections_today".into(), if audit { json!(conn_today) } else { Value::Null });
    out.insert("connection_trend".into(), json!(conn_today - conn_yesterday));
    let sessions = if audit {
        let mut p = vec![P(Val::str(&crate::laravel::ts(ctx.now - 86400)))];
        p.extend(cp.clone());
        count(c, &format!(r#"select count(*) as aggregate from "audit_connections" where "closed_at" is null and "from_peer" is not null and "from_peer" != '' and "created_at" >= ?{cond}"#), &p)?
    } else {
        0
    };
    out.insert("sessions".into(), json!(sessions));
    let (alarms, last) = if audit {
        let mut p = vec![P(Val::str(&crate::laravel::ts(ctx.now - 86400)))];
        p.extend(cp.clone());
        let n = count(c, &format!(r#"select count(*) as aggregate from "alarm_logs" where "created_at" >= ?{cond}"#), &p)?;
        let last = if n > 0 {
            db::first(c, &format!(r#"select "created_at" from "alarm_logs" where "created_at" >= ?{cond} order by "id" desc limit 1"#), &p)?.and_then(|r| ts_of(&r, "created_at"))
        } else {
            None
        };
        (n, last)
    } else {
        (0, None)
    };
    out.insert("alarms".into(), json!(alarms));
    out.insert("last_alarm".into(), last.map_or(Value::Null, |t| json!(super::time::ago(t, ctx.now, true))));
    Ok(Value::Object(out))
}

fn session_rows(ctx: &Ctx, c: &Connection) -> Result<Vec<Row>, Fault> {
    let ids = scope(ctx, c)?;
    let (cond, cp) = limit(&ids);
    let mut p = vec![P(Val::str(&crate::laravel::ts(ctx.now - 86400)))];
    p.extend(cp);
    db::rows(c, &format!(r#"select * from "audit_connections" where "closed_at" is null and "from_peer" is not null and "from_peer" != '' and "created_at" >= ?{cond} order by "id" desc limit 8"#), &p)
}

pub fn sessions(ctx: &Ctx, c: &Connection) -> Result<Value, Fault> {
    let tones = ["rd-tone-blue", "rd-tone-purple", "rd-tone-teal", "rd-tone-amber", "rd-tone-accent"];
    let rows = session_rows(ctx, c)?;
    let items: Vec<Value> = rows
        .iter()
        .map(|r| {
            let from = s(r, "from_peer");
            let name = s(r, "from_name");
            let who = if truthy(&name) { name } else { from.clone() };
            let t = r.val("conn_type").to_int();
            let tone = tones[(crc32(from.as_bytes()) as usize) % tones.len()];
            let created = ts_of(r, "created_at");
            json!({
                "id": r.id(), "who": who, "initial": who.chars().next().map(|c| c.to_string()).unwrap_or_default(), "from_peer": from, "tone": tone,
                "rustdesk_id": s(r, "rustdesk_id"), "link": client_link(c, &s(r, "rustdesk_id")).unwrap_or_default(),
                "type": t, "type_label": super::logs::conn_label(t), "disconnecting": !r.is_null("disconnect_requested_at"),
                "created": created.map(crate::laravel::ts).unwrap_or_default(), "ago": created.map(|t| super::time::ago(t, ctx.now, true)).unwrap_or_default(),
            })
        })
        .collect();
    Ok(json!({"sessions": items, "active": items.len(), "can_disconnect": ctx.allows("device", "rw")}))
}

/// `crc32()` as the previous console returns it (an unsigned 32-bit number).
fn crc32(b: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &x in b {
        crc ^= x as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

fn platform_of(os: &str) -> &'static str {
    let os = os.to_lowercase();
    if os.contains("windows") {
        "windows"
    } else if os.contains("mac") || os.contains("darwin") {
        "macos"
    } else if os.contains("android") {
        "android"
    } else if os.contains("ios") {
        "ios"
    } else if ["linux", "ubuntu", "debian", "fedora", "arch", "centos"].iter().any(|k| os.contains(k)) {
        "linux"
    } else {
        "unknown"
    }
}

pub fn index(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let audit = can_audit(ctx);
    let ids = scope(ctx, c)?;
    let requested = q(req, "range");
    let range = if req.input.get("range").map_or(false, |v| !matches!(v, Val::Arr(_))) && RANGES.contains(&php::str_to_int(requested.as_bytes())) { php::str_to_int(requested.as_bytes()) } else { RANGES[0] };

    // connections per day by type
    let series = if audit {
        let from_day = ctx.now - (range - 1) * 86400;
        let from = format!("{} 00:00:00", day(from_day));
        let (cond, cp) = limit(&ids);
        let mut p = vec![P(Val::str(&from))];
        p.extend(cp);
        let rows = db::rows(c, &format!(r#"select strftime('%Y-%m-%d', "created_at") as "day", "conn_type", count(*) as "c" from "audit_connections" where "created_at" >= ?{cond} group by "day", "conn_type""#), &p)?;
        let (mut labels, mut remote, mut file, mut other) = (vec![], vec![], vec![], vec![]);
        for i in 0..range {
            let t = from_day + i * 86400;
            let key = day(t);
            let d = chrono::DateTime::from_timestamp(t, 0).unwrap_or_default();
            labels.push(d.format("%b %-d").to_string());
            let n = |ty: i64| rows.iter().filter(|r| s(r, "day") == key && r.val("conn_type").to_int() == ty).map(|r| r.val("c").to_int()).sum::<i64>();
            remote.push(n(0));
            file.push(n(1));
            other.push(rows.iter().filter(|r| s(r, "day") == key && !matches!(r.val("conn_type").to_int(), 0 | 1)).map(|r| r.val("c").to_int()).sum::<i64>());
        }
        Some(json!({"labels": labels, "series": [{"name": "Remote Control", "data": remote}, {"name": "File Transfer", "data": file}, {"name": "Other", "data": other}]}))
    } else {
        None
    };

    // HTE: how the sessions of the range got through (path.rs): LAN, direct (hole punch or WebRTC), relay, unknown
    let paths = if audit {
        let (cond, cp) = limit(&ids);
        let mut p = vec![P(Val::str(&format!("{} 00:00:00", day(ctx.now - (range - 1) * 86400))))];
        p.extend(cp);
        let rows = db::rows(c, &format!(r#"select {} as "transport", count(*) as "c" from "audit_connections" where "created_at" >= ? and "from_peer" is not null and "from_peer" != ''{cond} group by "transport""#, crate::path::TRANSPORT_SQL), &p)?;
        let n = |k: &str| rows.iter().filter(|r| s(r, "transport") == k).map(|r| r.val("c").to_int()).sum::<i64>();
        let total: i64 = crate::path::FILTERS.iter().map(|(k, _)| n(k)).sum();
        let tones = [("lan", "rd-tone-teal"), ("direct", "rd-tone-blue"), ("relay", "rd-tone-amber"), ("unknown", "rd-tone-muted")];
        Some(json!({
            "total": total,
            "items": crate::path::FILTERS.iter().map(|(k, label)| {
                let count = n(k);
                let tone = tones.iter().find(|t| t.0 == *k).map_or("rd-tone-muted", |t| t.1);
                json!({"id": k, "label": label, "count": count, "tone": tone, "pct": if total > 0 { (count as f64 / total as f64 * 100.0).round() as i64 } else { 0 }, "width": if total > 0 { (count as f64 / total as f64 * 1000.0).round() / 10.0 } else { 0.0 }})
            }).collect::<Vec<_>>(),
        }))
    } else {
        None
    };

    // platform mix and versions over the devices the person sees
    let w = visible(c, &ctx.user, false)?;
    let devs = db::rows(c, &format!(r#"select "os" from "devices"{} order by "id" asc"#, w.sql()), &w.params.clone())?;
    let mut groups: Vec<(&str, i64)> = vec![];
    for d in &devs {
        let p = platform_of(&s(d, "os"));
        match groups.iter_mut().find(|(k, _)| *k == p) {
            Some(g) => g.1 += 1,
            None => groups.push((p, 1)),
        }
    }
    groups.sort_by(|a, b| b.1.cmp(&a.1));
    let name = |k: &str| match k { "windows" => "Windows", "macos" => "macOS", "linux" => "Linux", "android" => "Android", "ios" => "iOS", _ => "Unknown" };
    let mut labels: Vec<String> = groups.iter().take(3).map(|(k, _)| name(k).to_string()).collect();
    let mut values: Vec<i64> = groups.iter().take(3).map(|(_, n)| *n).collect();
    let other: i64 = groups.iter().skip(3).map(|(_, n)| *n).sum();
    if other > 0 {
        labels.push("Other".into());
        values.push(other);
    }
    let platform_total: i64 = values.iter().sum();
    let tones = ["rd-tone-blue", "rd-tone-accent", "rd-tone-teal", "rd-tone-purple", "rd-tone-amber"];
    let platforms: Vec<Value> = labels.iter().enumerate().map(|(i, l)| json!({"label": l, "count": values[i], "pct": (values[i] as f64 / platform_total as f64 * 100.0).round() as i64, "tone": tones[i % tones.len()]})).collect();

    let vrows = db::rows(c, &format!(r#"select COALESCE(NULLIF(version, ''), 'unknown') as v, COUNT(*) as c from "devices"{} group by v order by c desc limit 6"#, w.sql()), &w.params.clone())?;
    let vtotal: i64 = vrows.iter().map(|r| r.val("c").to_int()).sum();
    let vmax = vrows.iter().map(|r| r.val("c").to_int()).max().unwrap_or(0);
    let versions: Vec<Value> = vrows
        .iter()
        .map(|r| {
            let n = r.val("c").to_int();
            json!({"label": s(r, "v"), "count": n, "pct": (n as f64 / vtotal as f64 * 100.0).round() as i64, "width": if vmax > 0 { (n as f64 / vmax as f64 * 1000.0).round() / 10.0 } else { 0.0 }})
        })
        .collect();

    // the day's alarms
    let alarms = if audit {
        let (cond, cp) = limit(&ids);
        let mut p = vec![P(Val::str(&crate::laravel::ts(ctx.now - 86400)))];
        p.extend(cp);
        let rows = db::rows(c, &format!(r#"select * from "alarm_logs" where "created_at" >= ?{cond} order by "id" desc limit 5"#), &p)?;
        Some(
            rows.iter()
                .map(|a| {
                    let typ = a.val("typ").to_int();
                    let tone = match super::logs::alarm_severity(typ) { "danger" => "rd-tone-red", "warning" => "rd-tone-amber", _ => "rd-tone-muted" };
                    let created = ts_of(a, "created_at");
                    json!({"label": super::logs::alarm_label(typ), "source": if s(a, "rustdesk_id") == "console" { "Console".to_string() } else { s(a, "rustdesk_id") }, "tone": tone,
                           "when": created.map(crate::laravel::ts).unwrap_or_default(), "ago": created.map(|t| super::time::ago(t, ctx.now, true)).unwrap_or_default()})
                })
                .collect::<Vec<_>>(),
        )
    } else {
        None
    };

    let rw_setting = ctx.allows("setting", "rw");
    let prompt_setup = rw_setting
        && ctx.user.is_null("setup_wizard_dismissed_at")
        && ctx.user.is_null("setup_wizard_completed_at")
        && count(c, r#"select count(*) as aggregate from "devices" where "devices"."deleted_at" is null"#, &[])? == 0;
    let mail_on = {
        let t = |k: &str| db::setting(c, k, "").map(|v| lossy(&v).trim().to_string());
        t("smtp_enabled")? == "1" && !t("smtp_host")?.is_empty() && !t("smtp_from_address")?.is_empty()
    };
    let has_alerts = alarms.is_some();
    let page = json!({
        "stats": stats(ctx, c)?, "sess": if audit { sessions(ctx, c)? } else { Value::Null }, "audit": audit, "range": range, "ranges": RANGES,
        "connections": series.as_ref().map(|v| v.to_string()).unwrap_or_default(), "has_connections": series.is_some(), "paths": paths.unwrap_or(Value::Null),
        "platforms": platforms, "platform_total": platform_total, "platform_json": json!({"labels": labels, "values": values}).to_string(),
        "versions": versions, "version_total": vtotal, "alarms": alarms.unwrap_or_default(), "has_alerts": has_alerts,
        "prompt_setup": prompt_setup, "mail_warning": rw_setting && !mail_on,
    });
    let layout = ctx.layout(c, "overview", "Overview", "")?;
    Ok(Reply::Html(200, ctx.render("overview/index.html", layout, page)?))
}

/// GET /dashboard/stats: the tiles again (every 15 seconds).
pub fn stats_fragment(ctx: &Ctx, c: &Connection, _: &Req) -> Result<Reply, Fault> {
    Ok(Reply::Html(200, ctx.render("overview/stats.html", Value::Null, json!({"stats": stats(ctx, c)?}))?))
}

/// GET /dashboard/sessions: the live sessions again.
pub fn sessions_fragment(ctx: &Ctx, c: &Connection, _: &Req) -> Result<Reply, Fault> {
    Ok(Reply::Html(200, ctx.render("overview/sessions.html", Value::Null, json!({"sess": sessions(ctx, c)?, "csrf": ctx.session.token().unwrap_or("")}))?))
}

/// POST /dashboard/disconnect: ask the device to close a live session on its next heartbeat.
pub fn disconnect(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let body = Body::of(req);
    let id = body.int("id");
    let Some(session) = db::first(c, r#"select * from "audit_connections" where "id" = ? and "closed_at" is null limit 1"#, &[P(Val::Int(id))])? else {
        return Ok(Reply::Redirect("/".into()));
    };
    // an operator may only end a session on a device they can see, and only with write access to devices
    if !ctx.allows("device", "rw") {
        return Ok(Reply::Redirect("/".into()));
    }
    if !ctx.is_admin() {
        let mut w = visible(c, &ctx.user, false)?;
        w.add(r#""devices"."rustdesk_id" = ?"#, vec![P(session.val("rustdesk_id"))]);
        if count(c, &format!(r#"select count(*) as aggregate from "devices"{}"#, w.sql()), &w.params.clone())? == 0 {
            return Ok(Reply::Redirect("/".into()));
        }
    }
    let ts = crate::laravel::ts(ctx.now);
    db::exec(
        c,
        r#"update "audit_connections" set "disconnect_requested_at" = ?, "disconnect_sent_at" = null, "disconnect_requested_by" = ?, "updated_at" = ? where "id" = ?"#,
        &[P(Val::str(&ts)), P(Val::Int(ctx.uid())), P(Val::str(&ts)), P(Val::Int(id))],
    )?;
    let rid = s(&session, "rustdesk_id");
    audit(ctx, c, "session.disconnect", &format!("Requested disconnect of session {} on {}", s(&session, "conn_id"), rid), Some("device"), Some(&rid))?;
    Ok(Reply::Redirect("/".into()))
}
