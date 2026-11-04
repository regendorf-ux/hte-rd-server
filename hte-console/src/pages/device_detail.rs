//! One device (the previous console's `DeviceDetail`): identity and hardware, HTE Remote's "Who can reach this device" card with the
//! password row, the note, the address books that carry it, possible duplicates and the recent activity.
//!
//! The component's flags became the URL: `?edit=1` (the editor), `?delete=<id>` (the confirm step, for this device
//! or a twin), `?note=1` (the note editor), `?ab=1` (the address-book picker). Every action is a form post to
//! `/devices/<id>/do`; the outcome lines (`abResult`, `duplicateResult`) are one-request flashes.

use super::devices::{self, Modal};
use super::kit::*;
use super::{logs, time, Ctx, Reply, Req};
use crate::laravel::Cast;
use crate::php::{Fault, Val};
use crate::sqlite::{self as db, Row, P};
use crate::validate::{self, Rule};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

fn strcasecmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.bytes().map(|x| x.to_ascii_lowercase()).cmp(b.bytes().map(|x| x.to_ascii_lowercase()))
}

fn display_name(u: &Row) -> String {
    let name = s(u, "name");
    if name.is_empty() || name == "0" {
        s(u, "username")
    } else {
        name
    }
}

fn users_in(c: &Connection, ids: &[i64]) -> Result<Vec<Row>, Fault> {
    if ids.is_empty() {
        return Ok(vec![]);
    }
    find_in(c, "users", ids)
}

/// `Reach::sections($device)`: administrators, the owner, then each way into the device's group; a person once,
/// under the first section that lets them in. Each section is (label, sub, people).
pub fn sections(c: &Connection, device: &Row) -> Result<Vec<(String, Option<String>, Vec<Row>)>, Fault> {
    let mut seen: Vec<i64> = vec![];
    let mut out: Vec<(String, Option<String>, Vec<Row>)> = vec![];
    let mut add = |label: String, sub: Option<String>, users: Vec<Row>| {
        let mut fresh = vec![];
        for u in users {
            if !u.val("is_active").to_bool() || seen.contains(&u.id()) {
                continue;
            }
            seen.push(u.id());
            fresh.push(u);
        }
        if !fresh.is_empty() {
            fresh.sort_by(|a, b| strcasecmp(&display_name(a), &display_name(b)));
            out.push((label, sub, fresh));
        }
    };
    add("Administrators".into(), None, db::rows(c, r#"select * from "users" where "is_admin" = ? order by "username" asc"#, &[P(Val::Bool(true))])?);
    if !device.is_null("user_id") {
        if let Some(o) = find(c, "users", device.val("user_id").to_int())? {
            add("Owner".into(), None, vec![o]);
        }
    }
    let group = if device.is_null("device_group_id") { None } else { find(c, "device_groups", device.val("device_group_id").to_int())? };
    let Some(group) = group else { return Ok(out) };
    let name = format!("Group {}", s(&group, "name"));
    let gid = group.id();
    let direct = pivot_ids(c, "device_group_user", "device_group_id", "user_id", gid)?;
    add(name.clone(), Some("granted directly".into()), users_in(c, &direct)?);
    for ug in db::rows(
        c,
        r#"select "user_groups"."id", "user_groups"."name" from "device_group_user_group" inner join "user_groups" on "user_groups"."id" = "device_group_user_group"."user_group_id" where "device_group_user_group"."device_group_id" = ? order by "user_groups"."name" asc"#,
        &[P(Val::Int(gid))],
    )? {
        let members = pivot_ids(c, "user_group_user", "user_group_id", "user_id", ug.id())?;
        add(name.clone(), Some(format!("via user group {}", s(&ug, "name"))), users_in(c, &members)?);
    }
    let accesses = db::rows(c, r#"select * from "group_accesses" where "target_type" = ? and "target_id" = ?"#, &[P(Val::str("device_group")), P(Val::Int(gid))])?;
    let pick = |t: &str| -> Vec<i64> { accesses.iter().filter(|a| s(a, "accessor_type") == t).map(|a| a.val("accessor_id").to_int()).collect() };
    let direct_ids = pick("user");
    if !direct_ids.is_empty() {
        add(name.clone(), Some("group access".into()), users_in(c, &direct_ids)?);
    }
    let group_ids = pick("user_group");
    if !group_ids.is_empty() {
        let sql = format!(r#"select "id", "name" from "user_groups" where "id" in ({}) order by "name" asc"#, marks(group_ids.len()));
        for ug in db::rows(c, &sql, &ints_val(&group_ids))? {
            let members = pivot_ids(c, "user_group_user", "user_group_id", "user_id", ug.id())?;
            add(name.clone(), Some(format!("group access for user group {}", s(&ug, "name"))), users_in(c, &members)?);
        }
    }
    Ok(out)
}

/// `Passwords::rowFor($device)`: (tone, text, sub, can rotate).
fn password_row(c: &Connection, device: &Row, now: i64) -> Result<(String, String, String, bool), Fault> {
    let enabled = db::setting(c, crate::passwords::SETTING_ENABLED, "0")? == b"1";
    let row = db::first(c, r#"select * from "hte_device_passwords" where "rustdesk_id" = ? limit 1"#, &[P(Val::str(&s(device, "rustdesk_id")))])?;
    let t = |r: &Row, col: &str| ts_of(r, col);
    if !enabled {
        return Ok(("text-muted".into(), "Not managed by the console".into(), "Settings → Server".into(), false));
    }
    let Some(row) = row.filter(|r| !r.is_null("capable_at")) else {
        return Ok(("text-muted".into(), "Set on the computer itself".into(), "stock RustDesk or an HTE Remote too old to take one".into(), false));
    };
    if crate::passwords_sweep::pending(&row) {
        let sent = t(&row, "issued_at").map(|x| time::ago(x, now, false)).unwrap_or_default();
        return Ok(("text-warning".into(), format!("New one sent {sent}"), "waiting for the computer to confirm; the old one works until then".into(), false));
    }
    let days = crate::passwords_sweep::days(c)?;
    let confirmed = t(&row, "confirmed_at");
    let next = match (days > 0, confirmed) {
        (true, Some(at)) => format!("next change {}", time::ago(at + days * 86400, now, false)),
        _ => "changes when someone loses access".into(),
    };
    Ok((String::new(), format!("Its own, changed {}", confirmed.map(|x| time::ago(x, now, false)).unwrap_or_default()), next, true))
}

fn last_refusal(c: &Connection, device: &Row) -> Result<Option<Row>, Fault> {
    let to = crate::php::json_encode(&Val::str(&s(device, "rustdesk_id"))).unwrap_or_default();
    db::first(c, r#"select * from "alarm_logs" where "typ" = ? and "info" like ? order by "id" desc limit 1"#, &[P(Val::Int(102)), P(Val::str(&format!("%\"to\":{to}%")))])
}

fn books_with(c: &Connection, rid: &str) -> Result<Vec<Row>, Fault> {
    db::rows(c, r#"select * from "address_books" where exists (select * from "address_book_entries" where "address_books"."id" = "address_book_entries"."address_book_id" and "rustdesk_id" = ?)"#, &[P(Val::str(rid))])
}

/// The viewer's scope for this device's twins, as `Duplicates` takes it.
fn twins_of(ctx: &Ctx, c: &Connection, device: &Row) -> Result<Vec<(Row, &'static str, &'static str)>, Fault> {
    let scope = devices::dup_scope(c, &ctx.user)?;
    let d = crate::duplicates::Duplicates::of_scope(c, device, scope.as_ref().map(|(s, p)| (s.as_str(), p.as_slice())))?;
    d.twins_of(device.id())
}

fn can_write_book(ctx: &Ctx, c: &Connection, book: &Row, groups: &[i64]) -> Result<bool, Fault> {
    Ok(ctx.allows("address_book", "rw") && book_permission(c, &ctx.user, book, Some(groups))? >= PERM_READ_WRITE)
}

fn device_row(ctx: &Ctx, c: &Connection, id: i64) -> Result<Option<Row>, Fault> {
    devices::scoped_device(ctx, c, id)
}

/// `GET /devices/:id`
pub fn show(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let id = path_id(&req.path, 1);
    let Some(device) = device_row(ctx, c, id)? else { return Ok(abort(404)) };
    let modal = if q(req, "edit") == "1" && ctx.allows("device", "rw") {
        Modal::Edit { id, values: devices::edit_values(ctx, c, Some(&device))?, errors: Map::new() }
    } else if let Some(target) = Some(qint(req, "delete")).filter(|t| *t > 0).filter(|_| ctx.allows("device", "rw")) {
        let twin = target != id && twins_of(ctx, c, &device)?.iter().any(|(t, _, _)| t.id() == target);
        if target != id && !twin {
            return Ok(abort(404));
        }
        let d = db::first(c, r#"select * from "devices" where "id" = ? limit 1"#, &[P(Val::Int(target))])?;
        match d {
            Some(d) => {
                let from_books = entry_count(c, &[s(&d, "rustdesk_id")])? > 0;
                Modal::Delete { ids: vec![target], from_books }
            }
            None => Modal::None,
        }
    } else {
        Modal::None
    };
    render(ctx, c, id, 200, modal, req)
}

pub fn render(ctx: &Ctx, c: &Connection, id: i64, status: u16, modal: Modal, req: &Req) -> Result<Reply, Fault> {
    let Some(device) = device_row(ctx, c, id)? else { return Ok(abort(404)) };
    let now = ctx.now;
    let window = online_window(c)?;
    let trashed = !device.is_null("deleted_at");
    let online = is_online(&device, now, window);
    let can_audit = ctx.allows("audit", "r");
    let can_edit = ctx.allows("device", "rw");
    let can_books = ctx.allows("address_book", "rw");
    let rid = s(&device, "rustdesk_id");
    let can = device.val("can_initiate");
    let incoming_only = can == Val::Bool(false) || matches!(can, Val::Int(0));

    let group = if device.is_null("device_group_id") { None } else { find(c, "device_groups", device.val("device_group_id").to_int())? };
    let owner = if device.is_null("user_id") { None } else { find(c, "users", device.val("user_id").to_int())? };
    let strategy = if device.is_null("strategy_id_resolved") {
        None
    } else {
        db::first(c, r#"select * from "strategies" where "id" = ? and "deleted_at" is null limit 1"#, &[P(device.val("strategy_id_resolved"))])?
    };
    let os = s(&device, "os");
    let os_desc = {
        let mut parts = os.splitn(2, " / ");
        let first = parts.next().unwrap_or("");
        match parts.next() {
            Some(rest) if !rest.trim().is_empty() => rest.trim().to_string(),
            _ => first.to_string(),
        }
    };

    // address books that carry it: only those this person could open anyway
    let groups: Vec<i64> = if ctx.is_admin() { vec![] } else { user_group_ids(c, ctx.uid())? };
    let mut books = vec![];
    for b in books_with(c, &rid)? {
        if book_permission(c, &ctx.user, &b, Some(&groups))? > 0 {
            books.push(b);
        }
    }
    let ab_open = q(req, "ab") == "1" && can_books && !trashed;
    let addable: Vec<Value> = if ab_open {
        let have: Vec<i64> = books.iter().map(|b| b.id()).collect();
        writable_books(ctx, c)?.iter().filter(|b| !have.contains(&b.id())).map(|b| json!({"id": b.id(), "name": s(b, "name"), "personal": b.val("is_personal").to_bool()})).collect()
    } else {
        vec![]
    };
    let mut book_items = vec![];
    for b in &books {
        let label = if b.val("is_personal").to_bool() {
            match b.val("owner_user_id") {
                Val::Null => "Personal".to_string(),
                o => match find(c, "users", o.to_int())? {
                    Some(u) if !s(&u, "username").is_empty() => format!("{}'s personal", s(&u, "username")),
                    _ => "Personal".to_string(),
                },
            }
        } else {
            s(b, "name")
        };
        book_items.push(json!({"id": b.id(), "label": label, "name": s(b, "name"), "writable": can_books && can_write_book(ctx, c, b, &groups)?}));
    }

    // twins
    let twins = twins_of(ctx, c, &device)?;
    let twin_items: Vec<Value> = twins
        .iter()
        .map(|(t, _reason, label)| {
            let mut l = label.to_string();
            if let Some(f) = l.get_mut(0..1) {
                f.make_ascii_uppercase();
            }
            let name = { let a = s(t, "alias"); if truthy(&a) { a } else { s(t, "hostname") } };
            json!({
                "id": t.id(), "rustdesk_id": s(t, "rustdesk_id"), "name": name,
                "label": l, "online": is_online(t, now, window),
                "last_seen": diff_text(t, "last_online_at", now, "never"), "first_seen": ymd(t, "created_at").unwrap_or_else(|| "unknown".into()),
            })
        })
        .collect();
    let twin_count = twins.len();
    let twin_first = twins.first().map(|(t, _, _)| s(t, "rustdesk_id")).unwrap_or_default();

    // reach (administrators)
    let reach = if ctx.is_admin() && !trashed {
        let secs = sections(c, &device)?;
        let count: usize = secs.iter().map(|x| x.2.len()).sum();
        let last = last_refusal(c, &device)?;
        let info = last.as_ref().map(|l| s(l, "info")).unwrap_or_default();
        let info = logs::info_pairs(info.as_bytes());
        let get = |k: &str| info.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone()).unwrap_or_default();
        let (tone, text, sub, rotate) = password_row(c, &device, now)?;
        Some(json!({
            "enforced": crate::reach::enforced(c)?,
            "sections": secs.iter().map(|(label, sub, users)| json!({
                "label": label, "sub": sub,
                "users": users.iter().map(|u| json!({"id": u.id(), "username": s(u, "username"), "name": display_name(u)})).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "count": count,
            "people": if count == 1 { "person" } else { "people" },
            "pw": {"tone": tone, "text": text, "sub": sub, "rotate": rotate},
            "last": last.as_ref().map(|l| json!({"user": get("user"), "from": get("from"), "from_name": get("from_name"), "ago": diff_text(l, "created_at", now, "")})),
        }))
    } else {
        None
    };

    // activity
    let (mut conns, mut transfers, mut alarms, mut notes) = (vec![], vec![], vec![], vec![]);
    if can_audit {
        let note_users: Vec<i64> = vec![];
        let _ = note_users;
        let recent = db::rows(c, r#"select * from "audit_connections" where "rustdesk_id" = ? order by "created_at" desc limit 10"#, &[P(Val::str(&rid))])?;
        let relayed = crate::path::relay_bytes(c, &recent)?; // HTE: how each got through
        for r in recent {
            let (transport, carried) = logs::transport_of(&r, &relayed);
            let created = ts_of(&r, "created_at");
            let closed = ts_of(&r, "closed_at");
            let note_user = match r.val("note_user_id") {
                Val::Null => None,
                u => find(c, "users", u.to_int())?.map(|u| s(&u, "username")),
            };
            let from = { let a = s(&r, "from_name"); if truthy(&a) { a } else { let b = s(&r, "from_peer"); if truthy(&b) { b } else { "unknown".into() } } };
            conns.push(json!({
                "from": from, "ip": s(&r, "ip"), "note": s(&r, "note"), "note_user": note_user,
                "transport": transport.map(|_| crate::path::transport_label(transport)), "relay_size": carried.map(crate::path::human_bytes),
                "ago": created.map(|t| time::ago(t, now, false)).unwrap_or_default(),
                "duration": match (closed, created) { (Some(a), Some(b)) => Some(time::short_full(a, b)), _ => None },
            }));
        }
        for r in db::rows(c, r#"select * from "audit_file_transfers" where "rustdesk_id" = ? order by "created_at" desc limit 10"#, &[P(Val::str(&rid))])? {
            let path = s(&r, "path");
            let info = r.val("info").to_php_string().unwrap_or_default();
            let names = logs::file_names(&info);
            let clipboard = path.is_empty() && !names.is_empty();
            let label = logs::path_label(&path, &info, r.val("file_count").to_int());
            transfers.push(json!({
                "receive": matches!(r.val("direction"), Val::Int(1)), "clipboard": clipboard,
                "title": if clipboard { names.join(", ") } else { path.clone() },
                "label": if truthy(&label) { label } else { "—".into() },
                "ago": diff_text(&r, "created_at", now, ""),
            }));
        }
        for r in db::rows(c, r#"select * from "alarm_logs" where "rustdesk_id" = ? order by "created_at" desc limit 10"#, &[P(Val::str(&rid))])? {
            let typ = r.val("typ").to_int();
            alarms.push(json!({"severity": logs::alarm_severity(typ), "label": logs::alarm_label(typ), "ago": diff_text(&r, "created_at", now, "")}));
        }
        let mut subjects = vec![format!("device:{rid}")];
        for a in db::rows(c, r#"select "id" from "alarm_logs" where "rustdesk_id" = ? order by "id" desc limit 100"#, &[P(Val::str(&rid))])? {
            subjects.push(format!("alarm:{}", a.id()));
        }
        let sql = format!(r#"select * from "notification_deliveries" where "subject" in ({}) order by "created_at" desc, "id" desc limit 10"#, marks(subjects.len()));
        let params: Vec<P> = subjects.iter().map(|x| P(Val::str(x))).collect();
        for r in db::rows(c, &sql, &params)? {
            let event = s(&r, "event");
            let st = s(&r, "status");
            let tone = match st.as_str() { "sent" => "success", "failed" => "danger", _ => "secondary" };
            notes.push(json!({
                "label": notification_label(&event), "error": s(&r, "error"), "status": st, "tone": tone,
                "at": ts_of(&r, "created_at").map(|t| format!("{} UTC", crate::laravel::ts(t))).unwrap_or_default(),
                "ago": diff_text(&r, "created_at", now, ""),
            }));
        }
    }

    let url = format!("/devices/{id}");
    let layout = ctx.layout(c, "devices.show", "Device", "Manage")?;
    let note_editing = q(req, "note") == "1" && can_edit;
    let (note_errors, note_value) = (devices::flash(ctx, "note_error"), devices::flash(ctx, "note_value"));
    let title = { let a = s(&device, "alias"); if truthy(&a) { a } else { let h = s(&device, "hostname"); if truthy(&h) { h } else { rid.clone() } } };
    let page = json!({
        "id": id, "url": url,
        "d": {
            "rustdesk_id": rid, "alias": s(&device, "alias"), "hostname": s(&device, "hostname"),
            "title": title,
            "platform": platform_ui(&crate::duplicates::platform(&device.val("os"))),
            "terminal": !matches!(crate::duplicates::platform(&device.val("os")).as_str(), "android" | "ios"),
            "trashed": trashed, "online": online, "incoming_only": incoming_only, "link": client_link(c, &rid)?,
            "os": os, "os_desc": if truthy(&os_desc) { os_desc } else { "—".into() }, "cpu": s(&device, "cpu"), "memory": s(&device, "memory"),
            "version": s(&device, "version"), "username": s(&device, "username"), "ip": s(&device, "last_online_ip"),
            "lan_ip": s(&device, "lan_ip"), "lan_seen": diff_text(&device, "lan_ip_seen_at", now, ""),
            "registered_ip": s(&device, "registered_ip"), "uuid": s(&device, "uuid"),
            "first_seen": diff_text(&device, "created_at", now, "—"), "last_seen": diff_text(&device, "last_online_at", now, "never"),
            "last_seen_online": if online { "online just now".to_string() } else { format!("last seen {}", diff_text(&device, "last_online_at", now, "never")) },
            "group": group.as_ref().map(|g| s(g, "name")).unwrap_or_default(), "owner": owner.as_ref().map(|u| s(u, "username")).unwrap_or_default(),
            "strategy": strategy.as_ref().map(|r| s(r, "name")).unwrap_or_default(), "note": s(&device, "note"),
        },
        "can_edit": can_edit, "can_books": can_books, "can_audit": can_audit,
        "native_webclient": ctx.p.config.native_webclient,
        "twins": twin_items, "twin_count": twin_count, "twin_first": twin_first,
        "duplicate_result": devices::flash(ctx, "duplicate_result"),
        "reach": reach,
        "note_editing": note_editing, "note_error": note_errors,
        "note_value": if note_value.is_empty() { s(&device, "note") } else { note_value },
        "ab_open": ab_open, "addable": addable, "ab_error": devices::flash(ctx, "ab_error"), "ab_result": devices::flash(ctx, "ab_result"),
        "books": book_items,
        "conns": conns, "transfers": transfers, "alarms": alarms, "notes": notes,
        "modal": devices::modal_json(ctx, c, &modal, &url)?,
        "back": "",
    });
    Ok(Reply::Html(status, ctx.render("devices/detail.html", layout, page)?))
}

fn diff_text(r: &Row, col: &str, now: i64, none: &str) -> String {
    human(r, col, now, false).unwrap_or_else(|| none.to_string())
}

/// `AppriseNotifications::EVENTS[$event] ?? $event`
fn notification_label(event: &str) -> String {
    match event {
        "device.offline" => "Device offline",
        "device.online" => "Device recovered",
        "device.pending_approval" => "Device pending approval",
        "console.login_failed" => "Failed console login",
        "security.alarm" => "Security alarm",
        "remote_connection.failure" => "Repeated remote connection failure",
        "backup.completed" => "Backup completed",
        "backup.failed" => "Backup or off-site copy failed",
        other => other,
    }
    .to_string()
}

// ---------------------------------------------------------------------------------------------------- writes ---

/// `POST /devices/:id/do`
pub fn act(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let id = path_id(&req.path, 1);
    let body = Body::of(req);
    let url = format!("/devices/{id}");
    let Some(device) = device_row(ctx, c, id)? else { return Ok(abort(404)) };
    let rid = s(&device, "rustdesk_id");
    let back = Reply::Redirect(url.clone());
    match body.get("do").as_str() {
        "note" => {
            if !ctx.allows("device", "rw") {
                return Ok(abort(403));
            }
            let note = body.get("note");
            let mut data = crate::php::Arr::new();
            data.set(crate::php::Key::Str(b"note".to_vec()), Val::str(&note));
            let rules: [(&str, &[Rule]); 1] = [("note", &[Rule::Nullable, Rule::String, Rule::Max(500)])];
            let probe_fn = |rule: &Rule, v: &Val| probe(c, rule, v);
            if let Err(b) = validate::validate_db(&data, &rules, &probe_fn)? {
                let m = first_messages(&b);
                ctx.flash("note_error", Value::String(m.get("note").and_then(|v| v.as_str()).unwrap_or("").to_string()));
                ctx.flash("note_value", Value::String(note));
                return Ok(Reply::Redirect(format!("{url}?note=1")));
            }
            let mut d = device;
            let trimmed = note.trim_matches(|c| matches!(c, ' ' | '\t' | '\n' | '\r' | '\0' | '\x0B')).to_string();
            update(c, "devices", &mut d, vec![("note", Val::str(&trimmed), Cast::Plain)], ctx.now)?;
            audit(ctx, c, "device.update", &format!("Updated note on device {rid}"), Some("device"), Some(&rid))?;
            Ok(back)
        }
        "add-book" => {
            if !ctx.allows("address_book", "rw") {
                return Ok(abort(403));
            }
            if !device.is_null("deleted_at") {
                return Ok(abort(404));
            }
            let book_id = body.int("book_id");
            let books = writable_books(ctx, c)?;
            let Some(book) = books.iter().find(|b| b.id() == book_id) else {
                ctx.flash("ab_error", Value::String("Pick an address book.".into()));
                return Ok(Reply::Redirect(format!("{url}?ab=1")));
            };
            let name = s(book, "name");
            let exists = db::first(c, r#"select 1 as x from "address_book_entries" where "address_book_id" = ? and "rustdesk_id" = ? limit 1"#, &[P(Val::Int(book.id())), P(Val::str(&rid))])?.is_some();
            if exists {
                ctx.flash("ab_result", Value::String(format!("Already in {name}.")));
            } else {
                let mut cols = entry_columns(&device);
                cols.insert(0, ("address_book_id", Val::Int(book.id())));
                db::insert(c, "address_book_entries", cols, &crate::laravel::ts(ctx.now))?;
                audit(ctx, c, "address-book.peer-add", &format!("Added 1 device to address book {name} from the device detail page"), Some("address-book"), Some(&name))?;
                ctx.flash("ab_result", Value::String(format!("Added to {name}.")));
            }
            Ok(back)
        }
        "remove-book" => {
            if !ctx.allows("address_book", "rw") {
                return Ok(abort(403));
            }
            let Some(book) = find(c, "address_books", body.int("book_id"))? else { return Ok(abort(404)) };
            let groups: Vec<i64> = if ctx.is_admin() { vec![] } else { user_group_ids(c, ctx.uid())? };
            if !can_write_book(ctx, c, &book, &groups)? {
                return Ok(abort(403));
            }
            let removed = db::exec(c, r#"delete from "address_book_entries" where "address_book_id" = ? and "rustdesk_id" = ?"#, &[P(Val::Int(book.id())), P(Val::str(&rid))])?;
            let name = s(&book, "name");
            if removed > 0 {
                audit(ctx, c, "address-book.peer-delete", &format!("Removed device {rid} from address book {name} on the device detail page"), Some("address-book"), Some(&name))?;
            }
            ctx.flash("ab_result", Value::String(format!("Removed from {name}.")));
            Ok(back)
        }
        "dismiss" => {
            if !ctx.allows("device", "rw") {
                return Ok(abort(403));
            }
            let other = body.int("twin");
            let twins = twins_of(ctx, c, &device)?;
            let Some((twin, _, _)) = twins.into_iter().find(|(t, _, _)| t.id() == other) else { return Ok(abort(404)) };
            let (lo, hi) = (std::cmp::min(id, other), std::cmp::max(id, other));
            let exists = db::first(c, r#"select 1 as x from "device_duplicate_dismissals" where "device_id" = ? and "other_device_id" = ? limit 1"#, &[P(Val::Int(lo)), P(Val::Int(hi))])?.is_some();
            if !exists {
                db::insert(c, "device_duplicate_dismissals", vec![("device_id", Val::Int(lo)), ("other_device_id", Val::Int(hi)), ("user_id", Val::Int(ctx.uid()))], &crate::laravel::ts(ctx.now))?;
            }
            let trid = s(&twin, "rustdesk_id");
            audit(ctx, c, "device.duplicate-dismiss", &format!("Marked devices {rid} and {trid} as separate machines"), Some("device"), Some(&rid))?;
            ctx.flash("duplicate_result", Value::String(format!("Devices {rid} and {trid} will no longer be flagged.")));
            Ok(back)
        }
        "rotate-password" => {
            if !ctx.is_admin() {
                return Ok(abort(403));
            }
            let now_s = crate::laravel::ts(ctx.now);
            crate::passwords::issue(c, &ctx.p.n.crypt, rid.as_bytes(), &format!("changed by {}", s(&ctx.user, "username")), &now_s)?;
            audit(ctx, c, "hte.password", &format!("New password for {rid} (by hand)"), Some("device"), Some(&rid))?;
            Ok(back)
        }
        "release-id" => {
            if !ctx.allows("device", "rw") {
                return Ok(abort(403));
            }
            let addr = crate::release_id::address();
            let (ok, message) = match crate::release_id::release(&addr, &rid) {
                Ok(m) => (true, m),
                Err(m) => (false, m),
            };
            audit(ctx, c, "hte.release_id", &format!("Release ID {rid}: {}", if ok { "done" } else { "refused" }), Some("device"), Some(&rid))?;
            ctx.flash("duplicate_result", Value::String(message));
            Ok(back)
        }
        _ => Ok(back),
    }
}

/// `performDelete()` on the device page: a twin deleted from the callout leaves the page in place, anything else
/// deletes this device and returns to the list, which shows the outcome.
pub fn delete_from_detail(ctx: &Ctx, c: &Connection, detail: i64, ids: &[i64], from_books: bool) -> Result<Reply, Fault> {
    let Some(device) = device_row(ctx, c, detail)? else { return Ok(abort(404)) };
    if ids.len() == 1 && ids[0] != detail && twins_of(ctx, c, &device)?.iter().any(|(t, _, _)| t.id() == ids[0]) {
        let message = devices::delete_confirmed(ctx, c, ids, from_books)?;
        ctx.flash("duplicate_result", Value::String(message));
        return Ok(Reply::Redirect(format!("/devices/{detail}")));
    }
    let message = devices::delete_confirmed(ctx, c, &[detail], from_books)?;
    ctx.flash("bulk_result", Value::String(message));
    Ok(Reply::Redirect("/devices".into()))
}
