//! Devices (the previous console's `DeviceList`, with the `EditsDevices` and `DeletesDevices` concerns): the list with its chips,
//! filters, sort, column picker, recycle bin, pending-approval queue, bulk actions and CSV.
//!
//! The previous console's page components kept the component's state in the browser's memory; here the state is the URL (filters, `?edit=`,
//! `?create=1`, `?delete=`, `?columns=1`, `?pending=1`) and the person's own row (the column choice and the sort are
//! saved on the user, as the component saved them). Every action is a form post that redirects back with a one-request
//! flash (`bulk_result`, the line the component kept in `$bulkResult`); a step that needs a choice (the address-book and
//! group pickers, the delete confirmation) answers the post with the list and the dialog open.
//!
//! Who sees what is `Device::visibleTo` (kit.rs); every id that arrives with a request is scoped through it again.

use super::kit::*;
use super::{paginate, row_json, time, Ctx, Reply, Req};
use crate::laravel::Cast;
use crate::php::{Fault, Val};
use crate::sqlite::{self as db, Row, P};
use crate::validate::{self, Rule};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

pub const COLUMNS: [(&str, &str); 14] = [
    ("device", "Device"),
    ("alias", "Alias"),
    ("group", "Group"),
    ("owner", "Owner"),
    ("version", "Version"),
    ("os", "OS"),
    ("username", "User"),
    ("ip", "IP"),
    ("lan_ip", "LAN IP"),
    ("cpu", "CPU"),
    ("memory", "Memory"),
    ("uuid", "UUID"),
    ("first_seen", "First Seen"),
    ("last_seen", "Last Seen"),
];
const DEFAULT_COLUMNS: [&str; 6] = ["device", "alias", "group", "owner", "version", "last_seen"];
const SORTABLE: [(&str, &str); 10] = [
    ("id", "devices.rustdesk_id"),
    ("device", "devices.hostname"),
    ("alias", "devices.alias"),
    ("group", "__group__"),
    ("owner", "__owner__"),
    ("version", "devices.version"),
    ("os", "devices.os"),
    ("first_seen", "devices.created_at"),
    ("last_seen", "devices.last_online_at"),
    ("status", "__presence__"),
];
const PER_PAGE: i64 = 20;

/// The list's state: the previous console's page components properties that lived in the URL.
#[derive(Clone, Default)]
pub struct St {
    pub search: String,
    pub status: String,
    pub group: i64,
    pub owner: i64,
    pub trashed: bool,
    pub pending: bool,
    pub page: i64,
}

impl St {
    pub fn from(req: &Req) -> St {
        let flag = |k: &str| matches!(q(req, k).as_str(), "1" | "true" | "on");
        St {
            search: q(req, "search"),
            status: if q(req, "status").is_empty() { "all".into() } else { q(req, "status") },
            group: qint(req, "group"),
            owner: qint(req, "owner"),
            trashed: flag("trashed"),
            pending: flag("pending"),
            page: q(req, "page").parse::<i64>().ok().filter(|n| *n >= 1).map_or(1, |n| n.min(1_000_000_000)),
        }
    }

    /// From the hidden `back` field a form carries (the query string it was opened with).
    pub fn from_back(back: &str) -> St {
        let input = crate::laravel::Input::new("GET", None, Some(back), b"");
        let req = Req { method: "GET".into(), path: "/devices".into(), htmx: false, headers: Default::default(), input };
        St::from(&req)
    }

    /// `#[Url(except: ...)]`: what the address bar keeps, with a trailing `&` when not empty (the pager appends `page=`).
    pub fn query(&self) -> String {
        let mut pairs: Vec<(&str, Vec<u8>)> = vec![];
        if !self.search.is_empty() {
            pairs.push(("search", self.search.clone().into_bytes()));
        }
        if self.status != "all" {
            pairs.push(("status", self.status.clone().into_bytes()));
        }
        if self.group != 0 {
            pairs.push(("group", self.group.to_string().into_bytes()));
        }
        if self.owner != 0 {
            pairs.push(("owner", self.owner.to_string().into_bytes()));
        }
        if self.trashed {
            pairs.push(("trashed", b"1".to_vec()));
        }
        if self.pending {
            pairs.push(("pending", b"1".to_vec()));
        }
        crate::laravel::http_build_query(&pairs.iter().map(|(k, v)| (*k, v.as_slice())).collect::<Vec<_>>())
    }

    pub fn url(&self) -> String {
        let q = self.query();
        if q.is_empty() {
            "/devices".to_string()
        } else {
            format!("/devices?{q}")
        }
    }
}

// ------------------------------------------------------------------------------------- the person's saved view ---

pub struct SavedView {
    pub columns: Vec<String>,
    pub sort_field: String,
    pub sort_dir: String,
}

fn can_sort(ctx: &Ctx, field: &str) -> bool {
    SORTABLE.iter().any(|(k, _)| *k == field) && (field != "owner" || ctx.is_admin())
}

/// `mount()`: the saved column choice and sort, or the defaults.
pub fn saved_view(ctx: &Ctx) -> SavedView {
    let columns = match crate::laravel::from_json(&ctx.user.val("devices_columns")) {
        Val::Arr(a) => {
            let saved: Vec<String> = a.iter().filter_map(|(_, v)| if let Val::Str(b) = v { Some(lossy(b)) } else { None }).collect();
            COLUMNS.iter().map(|(k, _)| k.to_string()).filter(|k| saved.contains(k)).collect()
        }
        _ => DEFAULT_COLUMNS.iter().map(|k| k.to_string()).collect(),
    };
    let saved = s(&ctx.user, "devices_sort");
    if can_sort(ctx, &saved) {
        let dir = if s(&ctx.user, "devices_sort_direction") == "desc" { "desc" } else { "asc" };
        SavedView { columns, sort_field: saved, sort_dir: dir.into() }
    } else {
        SavedView { columns, sort_field: "last_seen".into(), sort_dir: "desc".into() }
    }
}

// ----------------------------------------------------------------------------------------------- the query ---

struct Query {
    where_sql: String,
    params: Vec<P>,
    order_sql: String,
    order_params: Vec<P>,
}

pub(crate) fn dup_scope(c: &Connection, user: &Row) -> Result<Option<(String, Vec<P>)>, Fault> {
    let mut w = Where::default();
    ownership(c, user, &mut w)?;
    Ok(w.parts.first().map(|p| (p.clone(), w.params.clone())))
}

fn dups(ctx: &Ctx, c: &Connection) -> Result<crate::duplicates::Duplicates, Fault> {
    let scope = dup_scope(c, &ctx.user)?;
    crate::duplicates::Duplicates::in_scope(c, scope.as_ref().map(|(s, p)| (s.as_str(), p.as_slice())))
}

/// `filteredQuery($user)` (scope, filters, order).
fn filtered(ctx: &Ctx, c: &Connection, st: &St, view: &SavedView, dup: Option<&crate::duplicates::Duplicates>) -> Result<Query, Fault> {
    let window = online_window(c)?;
    let cutoff = crate::laravel::ts(ctx.now - window);
    let mut w = visible(c, &ctx.user, st.trashed)?;
    if !st.search.is_empty() {
        let like = format!("%{}%", st.search);
        w.add(
            r#"("rustdesk_id" like ? or "alias" like ? or "hostname" like ? or "username" like ? or "last_online_ip" like ?)"#,
            (0..5).map(|_| P(Val::str(&like))).collect(),
        );
    }
    if !st.trashed && st.status == "online" {
        w.add(r#""last_online_at" > ?"#, vec![P(Val::str(&cutoff))]);
    }
    if !st.trashed && st.status == "offline" {
        w.add(r#"("last_online_at" is null or "last_online_at" <= ?)"#, vec![P(Val::str(&cutoff))]);
    }
    let dup_mode = !st.trashed && st.status == "duplicates";
    if dup_mode {
        let ids = dup.map(|d| d.ids()).unwrap_or_default();
        w.in_ints(r#""devices"."id""#, &ids);
    }
    if st.group > 0 {
        w.add(r#""device_group_id" = ?"#, vec![P(Val::Int(st.group))]);
    }
    if st.owner == -1 {
        w.add(r#""user_id" is null"#, vec![]);
    }
    if st.owner > 0 {
        w.add(r#""user_id" = ?"#, vec![P(Val::Int(st.owner))]);
    }
    let mut order: Vec<String> = vec![];
    let mut order_params: Vec<P> = vec![];
    if dup_mode {
        if let Some(d) = dup {
            let cluster = d.cluster_order()?;
            if !cluster.is_empty() {
                let mut cases = String::new();
                for (id, pos) in &cluster {
                    cases.push_str(&format!(" WHEN {id} THEN {pos}"));
                }
                order.push(format!("CASE devices.id{cases} ELSE {} END", cluster.len()));
            }
        }
    }
    let field = if can_sort(ctx, &view.sort_field) { view.sort_field.as_str() } else { "last_seen" };
    let dir = if view.sort_dir == "asc" { "asc" } else { "desc" };
    if field == "status" {
        order.push(format!("CASE WHEN devices.last_online_at > ? THEN 1 ELSE 0 END {dir}"));
        order_params.push(P(Val::str(&cutoff)));
    } else if field == "group" || field == "owner" {
        let (table, column, fk) = if field == "group" { ("device_groups", "name", "devices.device_group_id") } else { ("users", "username", "devices.user_id") };
        order.push(format!("{fk} is null"));
        order.push(format!(r#"(select "{column}" from "{table}" where "{table}"."id" = {fk}) {dir}"#));
    } else {
        let column = SORTABLE.iter().find(|(k, _)| *k == field).map(|(_, v)| *v).unwrap_or("devices.last_online_at");
        if ["device", "alias", "version", "os"].contains(&field) {
            order.push(format!("case when {column} is null or {column} = '' then 1 else 0 end"));
        } else if field == "last_seen" {
            order.push(format!("{column} is null"));
        }
        order.push(format!("{column} {dir}"));
    }
    order.push("devices.rustdesk_id asc".into());
    Ok(Query { where_sql: w.sql(), params: w.params, order_sql: order.join(", "), order_params })
}

fn run(c: &Connection, q: &Query, limit: Option<(i64, i64)>) -> Result<Vec<Row>, Fault> {
    let mut sql = format!(r#"select * from "devices"{} order by {}"#, q.where_sql, q.order_sql);
    if let Some((n, off)) = limit {
        sql.push_str(&format!(" limit {n} offset {off}"));
    }
    let mut params = q.params.clone();
    params.extend(q.order_params.iter().cloned());
    db::rows(c, &sql, &params)
}

/// The ids on the current page of a list (the selection a bulk step may touch).
fn page_ids(ctx: &Ctx, c: &Connection, st: &St) -> Result<Vec<i64>, Fault> {
    let view = saved_view(ctx);
    let d = if !st.trashed && st.status == "duplicates" { Some(dups(ctx, c)?) } else { None };
    let q = filtered(ctx, c, st, &view, d.as_ref())?;
    Ok(run(c, &q, Some((PER_PAGE, (st.page - 1) * PER_PAGE)))?.iter().map(|r| r.id()).collect())
}

// -------------------------------------------------------------------------------------------- shared lookups ---

/// `accessibleDeviceGroups()`: every group for an administrator, else the ones this person can reach.
pub fn accessible_groups(ctx: &Ctx, c: &Connection) -> Result<Vec<Row>, Fault> {
    if ctx.is_admin() {
        return db::rows(c, r#"select * from "device_groups" order by "name" asc"#, &[]);
    }
    let mut ids = crate::reach::accessible_device_group_ids(c, &ctx.user)?;
    if ids.is_empty() {
        ids = vec![0];
    }
    db::rows(c, &format!(r#"select * from "device_groups" where "id" in ({}) order by "name" asc"#, marks(ids.len())), &ints_val(&ids))
}

pub(crate) fn all_users(c: &Connection) -> Result<Vec<Row>, Fault> {
    db::rows(c, r#"select "id", "username" from "users" order by "username" asc"#, &[])
}

/// `scopedDevice($id)`: `Device::withTrashed()->visibleTo($user)->findOrFail`.
pub fn scoped_device(ctx: &Ctx, c: &Connection, id: i64) -> Result<Option<Row>, Fault> {
    let mut w = visible_with_trashed(c, &ctx.user)?;
    w.add(r#""devices"."id" = ?"#, vec![P(Val::Int(id))]);
    db::first(c, &format!(r#"select * from "devices"{} limit 1"#, w.sql()), &w.params)
}

/// The selection, scoped again: `Device::visibleTo($user)->whereIn('id', ...)`.
fn selected_devices(ctx: &Ctx, c: &Connection, ids: &[i64], order_by_rustdesk: bool) -> Result<Vec<Row>, Fault> {
    let ids: Vec<i64> = ids.iter().copied().filter(|i| *i != 0).collect();
    if ids.is_empty() {
        return Ok(vec![]);
    }
    let mut w = visible(c, &ctx.user, false)?;
    w.in_ints(r#""devices"."id""#, &ids);
    db::rows(c, &format!(r#"select * from "devices"{} order by {}"#, w.sql(), if order_by_rustdesk { r#""rustdesk_id" asc"# } else { r#""id" asc"# }), &w.params)
}

fn authorize(ctx: &Ctx, resource: &str, level: &str) -> Result<(), Reply> {
    if ctx.allows(resource, level) {
        Ok(())
    } else {
        Err(abort(403))
    }
}

/// Attempt an `authorizeConsole` and return the 403 page when it fails.
macro_rules! need {
    ($ctx:expr, $res:expr, $lvl:expr) => {
        if let Err(r) = authorize($ctx, $res, $lvl) {
            return Ok(r);
        }
    };
}

// -------------------------------------------------------------------------------------------------- the page ---

/// The dialog a page is showing, if any.
pub enum Modal {
    None,
    /// `id` 0 creates. `values` are what the form holds, `errors` the messages per field.
    Edit { id: i64, values: Map<String, Value>, errors: Map<String, Value> },
    Delete { ids: Vec<i64>, from_books: bool },
    Books { selected: Vec<i64>, error: String, chosen: i64 },
    Group { selected: Vec<i64>, error: String, chosen: i64 },
}

pub(crate) fn flash(ctx: &Ctx, key: &str) -> String {
    ctx.flashed.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

/// A `FormRequest` value list for the edit dialog.
pub fn edit_values(ctx: &Ctx, c: &Connection, device: Option<&Row>) -> Result<Map<String, Value>, Fault> {
    let mut m = Map::new();
    match device {
        None => {
            for (k, v) in [("rustdesk_id", json!("")), ("alias", json!("")), ("note", json!("")), ("group", json!(0)), ("user", json!(0)), ("strategy", json!(0)), ("can_initiate", json!(true))] {
                m.insert(k.into(), v);
            }
        }
        Some(d) => {
            m.insert("rustdesk_id".into(), json!(s(d, "rustdesk_id")));
            m.insert("alias".into(), json!(s(d, "alias")));
            m.insert("note".into(), json!(s(d, "note")));
            m.insert("group".into(), json!(d.val("device_group_id").to_int()));
            m.insert("user".into(), json!(d.val("user_id").to_int()));
            m.insert("can_initiate".into(), json!(d.val("can_initiate").to_php_string().map(|b| b != b"0").unwrap_or(true) && !(d.val("can_initiate") == Val::Bool(false))));
            let strategy = if ctx.is_admin() { assigned_strategy(c, "device", d.id())?.unwrap_or(0) } else { 0 };
            m.insert("strategy".into(), json!(strategy));
        }
    }
    Ok(m)
}

fn assigned_strategy(c: &Connection, level: &str, id: i64) -> Result<Option<i64>, Fault> {
    let (table, col) = match level {
        "device" => ("device_strategy", "device_id"),
        "user" => ("strategy_user", "user_id"),
        _ => ("device_group_strategy", "device_group_id"),
    };
    Ok(db::first(c, &format!(r#"select "strategy_id" from "{table}" where "{col}" = ? limit 1"#), &[P(Val::Int(id))])?.map(|r| r.val("strategy_id").to_int()))
}

/// `Strategy::explainFor($device)`
pub fn explain_for(c: &Connection, d: &Row, now: i64) -> Result<Value, Fault> {
    let user = if d.is_null("user_id") { None } else { find(c, "users", d.val("user_id").to_int())? };
    let group = if d.is_null("device_group_id") { None } else { find(c, "device_groups", d.val("device_group_id").to_int())? };
    let cands: [(&str, &str, Option<String>, Option<i64>); 3] = [
        ("device", "This device", Some(s(d, "rustdesk_id")), Some(d.id())),
        ("user", "Owner", user.as_ref().map(|u| s(u, "username")), if d.is_null("user_id") { None } else { Some(d.val("user_id").to_int()) }),
        ("device_group", "Device group", group.as_ref().map(|g| s(g, "name")), if d.is_null("device_group_id") { None } else { Some(d.val("device_group_id").to_int()) }),
    ];
    let live = |id: i64| db::first(c, r#"select * from "strategies" where "id" = ? and "deleted_at" is null limit 1"#, &[P(Val::Int(id))]);
    let mut steps = vec![];
    let mut winner = false;
    for (level, label, target, target_id) in cands {
        let strategy = match target_id {
            Some(t) => match assigned_strategy(c, level, t)? {
                Some(a) => live(a)?,
                None => None,
            },
            None => None,
        };
        let state = if target_id.is_none() {
            "unset"
        } else if strategy.is_none() {
            "none"
        } else if !strategy.as_ref().unwrap().val("enabled").to_bool() {
            "disabled"
        } else if winner {
            "overridden"
        } else {
            "applied"
        };
        if state == "applied" {
            winner = true;
        }
        steps.push(json!({"label": label, "target": target.unwrap_or_default(), "state": state, "name": strategy.as_ref().map(|r| s(r, "name")).unwrap_or_default()}));
    }
    let default = db::first(c, r#"select * from "strategies" where "is_default" = ? and "deleted_at" is null limit 1"#, &[P(Val::Int(1))])?;
    let dstate = match &default {
        None => "none",
        Some(r) if !r.val("enabled").to_bool() => "disabled",
        Some(_) if winner => "overridden",
        Some(_) => "applied",
    };
    steps.push(json!({"label": "Default strategy", "target": "", "state": dstate, "name": default.as_ref().map(|r| s(r, "name")).unwrap_or_default()}));
    let resolved = if d.is_null("strategy_id_resolved") { None } else { live(d.val("strategy_id_resolved").to_int())? };
    Ok(json!({
        "steps": steps,
        "resolved": resolved.as_ref().map(|r| s(r, "name")),
        "acked": human(d, "strategy_acked_at", now, false),
    }))
}

/// What a dialog's hidden `return` carries: the list's own URL, or `detail:<id>` for a device page.
fn ret_field(return_to: &str) -> String {
    match return_to.strip_prefix("/devices/") {
        Some(id) if id.parse::<i64>().is_ok() => format!("detail:{id}"),
        _ => return_to.to_string(),
    }
}

/// The dialog's data for a template.
pub fn modal_json(ctx: &Ctx, c: &Connection, modal: &Modal, return_to: &str) -> Result<Value, Fault> {
    Ok(match modal {
        Modal::None => json!({"kind": ""}),
        Modal::Edit { id, values, errors } => {
            let d = if *id != 0 { scoped_device(ctx, c, *id)? } else { None };
            let groups: Vec<Value> = accessible_groups(ctx, c)?.iter().map(|g| json!({"id": g.id(), "name": s(g, "name")})).collect();
            let users: Vec<Value> = all_users(c)?.iter().map(|u| json!({"id": u.id(), "username": s(u, "username")})).collect();
            // the template reads `errors.rustdesk_id` whether or not the field failed (strict undefined)
            let mut errors = errors.clone();
            errors.entry("rustdesk_id").or_insert_with(|| json!(""));
            let (strategies, explain) = match (&d, ctx.is_admin() && *id != 0) {
                (Some(d), true) => (
                    db::rows(c, r#"select "id", "name", "enabled" from "strategies" where "deleted_at" is null order by "name" asc"#, &[])?
                        .iter()
                        .map(|r| json!({"id": r.id(), "name": s(r, "name"), "enabled": r.val("enabled").to_bool()}))
                        .collect::<Vec<_>>(),
                    Some(explain_for(c, d, ctx.now)?),
                ),
                _ => (vec![], None),
            };
            json!({"kind": "edit", "id": id, "title": if *id == 0 { "Add Device" } else { "Edit Device" }, "values": values, "errors": errors, "groups": groups, "users": users,
                   "strategies": strategies, "explain": explain, "show_strategy": explain.is_some(), "return": return_to, "ret": ret_field(return_to)})
        }
        Modal::Delete { ids, from_books } => {
            let devices = selected_devices(ctx, c, ids, true)?;
            let rids: Vec<String> = devices.iter().map(|d| s(d, "rustdesk_id")).collect();
            let entries = entry_count(c, &rids)?;
            json!({"kind": "delete", "count": devices.len(), "first": rids.first().cloned().unwrap_or_default(), "entries": entries,
                   "entries_word": plural("entry", entries), "from_books": from_books, "ids": devices.iter().map(|d| d.id()).collect::<Vec<_>>(), "return": return_to, "ret": ret_field(return_to)})
        }
        Modal::Books { selected, error, chosen } => {
            let books: Vec<Value> = writable_books(ctx, c)?.iter().map(|b| json!({"id": b.id(), "name": s(b, "name"), "personal": b.val("is_personal").to_bool()})).collect();
            json!({"kind": "books", "selected": selected, "count": selected.len(), "word": plural("device", selected.len() as i64), "books": books, "error": error, "chosen": chosen, "return": return_to, "ret": ret_field(return_to)})
        }
        Modal::Group { selected, error, chosen } => {
            let groups: Vec<Value> = accessible_groups(ctx, c)?.iter().map(|g| json!({"id": g.id(), "name": s(g, "name")})).collect();
            json!({"kind": "group", "selected": selected, "count": selected.len(), "word": plural("device", selected.len() as i64), "groups": groups, "error": error, "chosen": chosen, "return": return_to, "ret": ret_field(return_to)})
        }
    })
}

fn diff_or(d: &Row, col: &str, now: i64, short: bool, none: &str) -> String {
    human(d, col, now, short).unwrap_or_else(|| none.to_string())
}

/// Everything the list template shows about one device.
fn device_json(
    c: &Connection,
    d: &Row,
    now: i64,
    window: i64,
    groups: &[Row],
    users: &[Row],
    dup: Option<&crate::duplicates::Duplicates>,
) -> Result<Value, Fault> {
    let os = s(d, "os");
    let platform = crate::duplicates::platform(&d.val("os"));
    let os_desc = {
        // `osDescription()`: the part after "family / " when there is one
        let mut parts = os.splitn(2, " / ");
        let first = parts.next().unwrap_or("");
        match parts.next() {
            Some(rest) if !rest.trim().is_empty() => rest.trim().to_string(),
            _ => first.to_string().replace(first, &os),
        }
    };
    let group = by_id(groups, &d.val("device_group_id")).map(|g| s(g, "name")).unwrap_or_default();
    let owner = by_id(users, &d.val("user_id")).map(|u| s(u, "username")).unwrap_or_default();
    let uuid = s(d, "uuid");
    let lan = s(d, "lan_ip");
    let can_initiate = d.val("can_initiate");
    let incoming_only = can_initiate == Val::Bool(false) || (matches!(can_initiate, Val::Int(0)));
    let dup_summary = match dup {
        Some(x) if x.has(d.id()) => Some(x.summary(d.id())?),
        _ => None,
    };
    let rid = s(d, "rustdesk_id");
    Ok(json!({
        "id": d.id(),
        "rustdesk_id": rid,
        "link": client_link(c, &rid)?,
        "platform": platform_ui(&platform),
        // the terminal is desktop only (RustDesk 1.4.1 or later on the device)
        "terminal": platform != "android" && platform != "ios",
        "hostname": s(d, "hostname"),
        "alias": s(d, "alias"),
        "group": group,
        "owner": owner,
        "version": s(d, "version"),
        "os": os,
        "os_desc_34": limit(&os_desc, 34),
        "os_desc_28": if truthy(&os) { limit(&os_desc, 28) } else { String::new() },
        "username": s(d, "username"),
        "ip": s(d, "last_online_ip"),
        "lan_ip": lan,
        "lan_title": if truthy(&lan) { format!("Seen during a connection {}", diff_or(d, "lan_ip_seen_at", now, false, "")) } else { "Not seen yet. Learned when a session is set up on the same network.".to_string() },
        "cpu": s(d, "cpu"),
        "cpu_24": limit(&s(d, "cpu"), 24),
        "memory": s(d, "memory"),
        "uuid": uuid,
        "uuid_12": limit(&uuid, 12),
        "created_at": ts_of(d, "created_at").map(crate::laravel::ts).unwrap_or_default(),
        "first_seen": ymd(d, "created_at").unwrap_or_else(|| "—".into()),
        "last_online_at": ts_of(d, "last_online_at").map(crate::laravel::ts).unwrap_or_default(),
        "last_seen": diff_or(d, "last_online_at", now, false, "never"),
        "last_seen_short": diff_or(d, "last_online_at", now, true, "never"),
        "created_ago": diff_or(d, "created_at", now, false, "—"),
        "created_ago_short": diff_or(d, "created_at", now, true, "—"),
        "online": is_online(d, now, window),
        "incoming_only": incoming_only,
        "duplicate": dup_summary,
    }))
}

/// `GET /devices`
pub fn index(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let st = St::from(req);
    let modal = if q(req, "create") == "1" && ctx.allows("device", "rw") {
        Modal::Edit { id: 0, values: edit_values(ctx, c, None)?, errors: Map::new() }
    } else if let Some(id) = Some(qint(req, "edit")).filter(|i| *i > 0) {
        need!(ctx, "device", "rw");
        let Some(d) = scoped_device(ctx, c, id)? else { return Ok(abort(404)) };
        Modal::Edit { id, values: edit_values(ctx, c, Some(&d))?, errors: Map::new() }
    } else if let Some(id) = Some(qint(req, "delete")).filter(|i| *i > 0) {
        need!(ctx, "device", "rw");
        if scoped_device(ctx, c, id)?.is_none() {
            return Ok(abort(404));
        }
        let devices = selected_devices(ctx, c, &[id], true)?;
        if devices.is_empty() {
            Modal::None
        } else {
            let rids: Vec<String> = devices.iter().map(|d| s(d, "rustdesk_id")).collect();
            Modal::Delete { ids: vec![id], from_books: entry_count(c, &rids)? > 0 }
        }
    } else {
        Modal::None
    };
    render(ctx, c, &st, 200, modal, req)
}

pub fn render(ctx: &Ctx, c: &Connection, st: &St, status: u16, modal: Modal, req: &Req) -> Result<Reply, Fault> {
    let user = &ctx.user;
    let window = online_window(c)?;
    let view = saved_view(ctx);
    let admin = ctx.is_admin();
    let (cutoff, now) = (crate::laravel::ts(ctx.now - window), ctx.now);

    // the chips
    let mut base = visible(c, user, false)?;
    let total = count(c, &format!(r#"select count(*) as aggregate from "devices"{}"#, base.sql()), &base.params)?;
    base.add(r#""last_online_at" > ?"#, vec![P(Val::str(&cutoff))]);
    let online = count(c, &format!(r#"select count(*) as aggregate from "devices"{}"#, base.sql()), &base.params)?;
    let trashed_w = visible(c, user, true)?;
    let trashed_count = count(c, &format!(r#"select count(*) as aggregate from "devices"{}"#, trashed_w.sql()), &trashed_w.params)?;
    let mut pw = Where::default();
    ownership(c, user, &mut pw)?;
    pw.add(r#""devices"."status" = ?"#, vec![P(Val::str("pending"))]);
    pw.add(r#""devices"."deleted_at" is null"#, vec![]);
    let pending_count = count(c, &format!(r#"select count(*) as aggregate from "devices"{}"#, pw.sql()), &pw.params)?;

    if st.pending {
        return render_pending(ctx, c, st, status, &pw, pending_count, req);
    }

    let dup = if !st.trashed { Some(dups(ctx, c)?) } else { None };
    let query = filtered(ctx, c, st, &view, dup.as_ref())?;
    let n = count(c, &format!(r#"select count(*) as aggregate from "devices"{}"#, query.where_sql), &query.params)?;
    let rows = run(c, &query, Some((PER_PAGE, (st.page - 1) * PER_PAGE)))?;
    let groups = accessible_groups(ctx, c)?;
    let users = all_users(c)?;
    let owners_in_rows: Vec<i64> = rows.iter().filter(|d| !d.is_null("user_id")).map(|d| d.val("user_id").to_int()).collect();
    let user_rows = if owners_in_rows.is_empty() { vec![] } else { find_in(c, "users", &owners_in_rows)? };
    let group_rows = {
        let ids: Vec<i64> = rows.iter().filter(|d| !d.is_null("device_group_id")).map(|d| d.val("device_group_id").to_int()).collect();
        if ids.is_empty() { vec![] } else { find_in(c, "device_groups", &ids)? }
    };
    let items: Vec<Value> = rows.iter().map(|d| device_json(c, d, now, window, &group_rows, &user_rows, dup.as_ref())).collect::<Result<_, _>>()?;
    let page = paginate::page(st.page, PER_PAGE, n, rows.len() as i64);

    let mut cols = Map::new();
    for (k, _) in COLUMNS {
        cols.insert(k.to_string(), json!(view.columns.iter().any(|c| c == k) && (k != "owner" || admin)));
    }
    let colspan = 4 + cols.values().filter(|v| v.as_bool() == Some(true)).count();
    let col_list: Vec<Value> = COLUMNS
        .iter()
        .filter(|(k, _)| *k != "owner" || admin)
        .map(|(k, l)| json!({"key": k, "label": l, "checked": view.columns.iter().any(|c| c == k)}))
        .collect();
    let sort_options: Vec<Value> = SORTABLE
        .iter()
        .filter(|(k, _)| *k != "owner" || admin)
        .map(|(k, _)| {
            let label = if *k == "id" { "ID".to_string() } else { COLUMNS.iter().find(|(c, _)| c == k).map(|(_, l)| l.to_string()).unwrap_or_else(|| "Status".into()) };
            json!({"key": k, "label": label, "selected": *k == view.sort_field})
        })
        .collect();
    let back = st.query();
    let return_to = st.url();
    let dup_count = dup.as_ref().map(|d| d.count());
    let result = flash(ctx, "bulk_result");
    let layout = ctx.layout(c, "devices", "Devices", "Manage")?;
    let with = |f: &dyn Fn(&mut St)| {
        let mut n = st.clone();
        n.page = 1;
        f(&mut n);
        n.url()
    };
    let join = |u: String, extra: &str| if u.contains('?') { format!("{u}&{extra}") } else { format!("{u}?{extra}") };
    let urls = json!({
        "all": with(&|n| { n.status = "all".into(); n.trashed = false; n.pending = false; }),
        "online": with(&|n| { n.status = "online".into(); n.trashed = false; n.pending = false; }),
        "offline": with(&|n| { n.status = "offline".into(); n.trashed = false; n.pending = false; }),
        "dups": with(&|n| { n.status = "duplicates".into(); n.trashed = false; n.pending = false; }),
        "pending": with(&|n| { n.pending = true; n.trashed = false; }),
        "trashed": with(&|n| { n.trashed = true; n.pending = false; }),
        "create": join(st.url(), "create=1"),
        "columns": join(st.url(), "columns=1"),
        "export": format!("/devices/export{}", if st.query().is_empty() { String::new() } else { format!("?{}", st.query()) }),
        "edit_prefix": join(st.url(), "edit="),
        "delete_prefix": join(st.url(), "delete="),
    });
    let sort_dir = view.sort_dir.clone();
    let page_json = json!({
        "chips": {"total": total, "online": online, "offline": total - online, "pending": pending_count, "trashed": trashed_count,
                  "dups": dup_count.unwrap_or(0), "show_dups": dup_count.map_or(false, |n| n > 0) || (!st.trashed && st.status == "duplicates") },
        "st": {"search": st.search, "status": st.status, "group": st.group, "owner": st.owner, "trashed": st.trashed},
        "back": back,
        "url": return_to,
        "urls": urls,
        "pending_tab": false,
        "columns_open": q(req, "columns") == "1",
        "col_list": col_list,
        "cols": cols,
        "colspan": colspan,
        "sort": {"field": view.sort_field, "dir": sort_dir},
        "sort_options": sort_options,
        "rows": items,
        "pager": page,
        "path": "/devices",
        "query": st.query_with_amp(),
        "groups": groups.iter().map(|g| json!({"id": g.id(), "name": s(g, "name")})).collect::<Vec<_>>(),
        "users": users.iter().map(|u| json!({"id": u.id(), "username": s(u, "username")})).collect::<Vec<_>>(),
        "can_rw": ctx.allows("device", "rw"),
        "can_book_rw": ctx.allows("address_book", "rw"),
        "can_setup": ctx.allows("setting", "r"),
        "is_admin": admin,
        "result": result,
        "modal": modal_json(ctx, c, &modal, &return_to)?,
        "native_webclient": ctx.p.config.native_webclient,
        "webclient_url": ctx.p.config.webclient_url,
        "csrf": ctx.session.token().unwrap_or(""),
        "total_pages": page_total(n),
    });
    Ok(Reply::Html(status, ctx.render("devices/index.html", layout, page_json)?))
}

fn page_total(n: i64) -> i64 {
    std::cmp::max((n + PER_PAGE - 1) / PER_PAGE, 1)
}

impl St {
    /// The pager's links: the filters, then `page=`.
    fn query_with_amp(&self) -> String {
        let q = self.query();
        if q.is_empty() {
            q
        } else {
            format!("{q}&")
        }
    }
}

fn render_pending(ctx: &Ctx, c: &Connection, st: &St, status: u16, pw: &Where, pending_count: i64, _req: &Req) -> Result<Reply, Fault> {
    let mut w = Where::default();
    w.parts = pw.parts.clone();
    w.params = pw.params.clone();
    if !st.search.is_empty() {
        let like = format!("%{}%", st.search);
        w.add(r#"("rustdesk_id" like ? or "hostname" like ? or "username" like ? or "last_online_ip" like ?)"#, (0..4).map(|_| P(Val::str(&like))).collect());
    }
    let n = count(c, &format!(r#"select count(*) as aggregate from "devices"{}"#, w.sql()), &w.params)?;
    let rows = db::rows(c, &format!(r#"select * from "devices"{} order by "created_at" desc limit {PER_PAGE} offset {}"#, w.sql(), (st.page - 1) * PER_PAGE), &w.params)?;
    let window = online_window(c)?;
    let items: Vec<Value> = rows.iter().map(|d| device_json(c, d, ctx.now, window, &[], &[], None)).collect::<Result<_, _>>()?;
    let page = paginate::page(st.page, PER_PAGE, n, rows.len() as i64);
    let layout = ctx.layout(c, "devices", "Devices", "Manage")?;
    let page_json = json!({
        "pending_count": pending_count,
        "st": {"search": st.search},
        "rows": items,
        "pager": page,
        "path": "/devices",
        "query": st.query_with_amp(),
        "can_rw": ctx.allows("device", "rw"),
        "back": st.query(),
        "csrf": ctx.session.token().unwrap_or(""),
    });
    Ok(Reply::Html(status, ctx.render("devices/pending.html", layout, page_json)?))
}

// ---------------------------------------------------------------------------------------------------- writes ---

fn redirect_back(back: &str) -> Reply {
    // only the known filters are carried over; `back` is rebuilt, never echoed
    Reply::Redirect(St::from_back(back).url())
}

fn bulk_result(ctx: &Ctx, text: &str) {
    ctx.flash("bulk_result", json!(text));
}

/// `POST /devices/sort`: a heading, the mobile picker, or the reverse arrow.
pub fn sort(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let body = Body::of(req);
    let back = body.get("back");
    let view = saved_view(ctx);
    let (field, dir) = if body.has("select") {
        let f = body.get("select");
        if !can_sort(ctx, &f) || view.sort_field == f {
            return Ok(redirect_back(&back));
        }
        (f, "asc".to_string())
    } else {
        let f = body.get("field");
        if !can_sort(ctx, &f) {
            return Ok(redirect_back(&back));
        }
        let dir = if view.sort_field == f && view.sort_dir == "asc" { "desc" } else { "asc" };
        (f, dir.to_string())
    };
    let mut row = ctx.user.clone();
    db::update_dirty(c, "users", &mut row, vec![("devices_sort", Val::str(&field), Cast::Plain), ("devices_sort_direction", Val::str(&dir), Cast::Plain)], &crate::laravel::ts(ctx.now))?;
    // resetPage(): the page parameter is not carried
    Ok(redirect_back(&back))
}

/// `POST /devices/columns`: the column picker (`updatedColumns`) or "Defaults" (`resetColumns`).
pub fn columns(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let body = Body::of(req);
    let mut row = ctx.user.clone();
    if body.has("reset") {
        db::update_dirty(c, "users", &mut row, vec![("devices_columns", Val::Null, Cast::Json)], &crate::laravel::ts(ctx.now))?;
    } else {
        let picked = body.list("columns");
        let canon: Vec<String> = COLUMNS.iter().map(|(k, _)| k.to_string()).filter(|k| picked.contains(k)).collect();
        let json = crate::php::json_encode(&Val::Arr({
            let mut a = crate::php::Arr::new();
            for k in &canon {
                a.push(Val::str(k));
            }
            a
        }))
        .unwrap_or_else(|| "[]".into());
        db::update_dirty(c, "users", &mut row, vec![("devices_columns", Val::str(&json), Cast::Json)], &crate::laravel::ts(ctx.now))?;
    }
    let back = body.get("back");
    let st = St::from_back(&back);
    let mut url = st.url();
    // the panel stays open while the boxes are ticked, and closes with "Done"
    if !body.has("done") {
        url.push_str(if url.contains('?') { "&columns=1" } else { "?columns=1" });
    }
    Ok(Reply::Redirect(url))
}

/// `POST /devices/bulk`: the bulk bar, and the steps of its dialogs.
pub fn bulk(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let body = Body::of(req);
    let st = St::from_back(&body.get("back"));
    let mut selected = body.ints("selected");
    { let mut seen = vec![]; selected.retain(|i| { if seen.contains(i) { false } else { seen.push(*i); true } }); }
    let todo = body.get("do");
    match todo.as_str() {
        "delete" => {
            need!(ctx, "device", "rw");
            if selected.is_empty() {
                return Ok(redirect_back(&body.get("back")));
            }
            let devices = selected_devices(ctx, c, &selected, true)?;
            if devices.is_empty() {
                return Ok(redirect_back(&body.get("back")));
            }
            let rids: Vec<String> = devices.iter().map(|d| s(d, "rustdesk_id")).collect();
            let from_books = entry_count(c, &rids)? > 0;
            render(ctx, c, &st, 200, Modal::Delete { ids: devices.iter().map(|d| d.id()).collect(), from_books }, req)
        }
        "incoming" | "outgoing" => {
            need!(ctx, "device", "rw");
            let incoming_only = todo == "incoming";
            let mut changed = 0i64;
            for mut d in selected_devices(ctx, c, &selected, false)? {
                let current = d.val("can_initiate");
                let is_incoming = current == Val::Bool(false) || matches!(current, Val::Int(0));
                if is_incoming == incoming_only {
                    continue;
                }
                update(c, "devices", &mut d, vec![("can_initiate", Val::Bool(!incoming_only), Cast::Bool)], ctx.now)?;
                changed += 1;
            }
            let label = if incoming_only { "incoming only" } else { "allowed to start sessions" };
            if changed > 0 {
                audit(ctx, c, "device.initiate", &format!("Set {changed} {} {label}", plural("device", changed)), Some("device"), Some(""))?;
            }
            bulk_result(ctx, &format!("{changed} {} set {label}.", plural("device", changed)));
            Ok(redirect_back(&body.get("back")))
        }
        "pick-group" => {
            need!(ctx, "device", "rw");
            if selected.is_empty() {
                return Ok(redirect_back(&body.get("back")));
            }
            render(ctx, c, &st, 200, Modal::Group { selected, error: String::new(), chosen: -1 }, req)
        }
        "move-group" => {
            need!(ctx, "device", "rw");
            if selected.is_empty() {
                return Ok(redirect_back(&body.get("back")));
            }
            let chosen = if body.has("group_id") { body.int("group_id") } else { -1 };
            let groups = accessible_groups(ctx, c)?;
            let group = if chosen == 0 { None } else { groups.iter().find(|g| g.id() == chosen).cloned() };
            let error = if chosen < 0 {
                "Pick a device group."
            } else if chosen > 0 && group.is_none() {
                "Pick an accessible device group."
            } else {
                ""
            };
            if !error.is_empty() {
                return render(ctx, c, &st, 200, Modal::Group { selected, error: error.into(), chosen }, req);
            }
            let page = page_ids(ctx, c, &st)?;
            let on_page: Vec<i64> = selected.iter().copied().filter(|i| page.contains(i)).collect();
            let devices: Vec<Row> = {
                // `->getCollection()->whereIn('id', ...)->values()`: the page's own order
                let all = selected_devices(ctx, c, &page, false)?;
                let mut ordered: Vec<Row> = vec![];
                for id in &page {
                    if on_page.contains(id) {
                        if let Some(r) = all.iter().find(|r| r.id() == *id) {
                            ordered.push(r.clone());
                        }
                    }
                }
                ordered
            };
            if devices.is_empty() {
                return Ok(redirect_back(&body.get("back")));
            }
            let target: Option<i64> = group.as_ref().map(|g| g.id());
            let target_name = group.as_ref().map(|g| s(g, "name")).unwrap_or_else(|| "No group".into());
            let (mut moved, mut unchanged) = (0i64, 0i64);
            for mut d in devices {
                if d.val("device_group_id").to_int() == target.unwrap_or(0) {
                    unchanged += 1;
                    continue;
                }
                let changed = update(c, "devices", &mut d, vec![("device_group_id", target.map_or(Val::Null, Val::Int), Cast::Plain)], ctx.now)?;
                if changed.iter().any(|x| x == "device_group_id" || x == "user_id") {
                    crate::strategy::sync_resolved_for(c, &mut d, &crate::laravel::ts(ctx.now))?;
                }
                moved += 1;
            }
            if moved > 0 {
                let tid = target.map(|t| t.to_string());
                audit(ctx, c, "device.group-move", &format!("Moved {moved} {} to {target_name}; {unchanged} unchanged.", plural("device", moved)), Some("device-group"), tid.as_deref())?;
            }
            bulk_result(ctx, &format!("Moved {moved} {} to {target_name}. {unchanged} unchanged.", plural("device", moved)));
            Ok(redirect_back(&body.get("back")))
        }
        "pick-books" => {
            need!(ctx, "address_book", "rw");
            if selected.is_empty() {
                return Ok(redirect_back(&body.get("back")));
            }
            personal_book(ctx, c)?;
            render(ctx, c, &st, 200, Modal::Books { selected, error: String::new(), chosen: 0 }, req)
        }
        "add-books" => {
            need!(ctx, "address_book", "rw");
            let chosen = body.int("book_id");
            let books = writable_books(ctx, c)?;
            let Some(book) = books.iter().find(|b| b.id() == chosen) else {
                return render(ctx, c, &st, 200, Modal::Books { selected, error: "Pick an address book.".into(), chosen }, req);
            };
            let existing: Vec<String> = db::rows(c, r#"select "rustdesk_id" from "address_book_entries" where "address_book_id" = ?"#, &[P(Val::Int(book.id()))])?.iter().map(|r| s(r, "rustdesk_id")).collect();
            let mut existing = existing;
            let (mut added, mut skipped) = (0i64, 0i64);
            for d in selected_devices(ctx, c, &selected, false)? {
                let rid = s(&d, "rustdesk_id");
                if existing.contains(&rid) {
                    skipped += 1;
                    continue;
                }
                let mut cols = entry_columns(&d);
                cols.insert(0, ("address_book_id", Val::Int(book.id())));
                db::insert(c, "address_book_entries", cols, &crate::laravel::ts(ctx.now))?;
                existing.push(rid);
                added += 1;
            }
            let name = s(book, "name");
            audit(ctx, c, "address-book.peer-add", &format!("Added {added} {} to address book {name} from the device list", plural("device", added)), Some("address-book"), Some(&name))?;
            bulk_result(ctx, &format!("Added {added} to {name}.{}", if skipped > 0 { format!(" {skipped} already there.") } else { String::new() }));
            Ok(redirect_back(&body.get("back")))
        }
        _ => Ok(redirect_back(&body.get("back"))),
    }
}

/// `deleteConfirmed()`: the recycle bin, and the address books when asked. Returns the outcome line.
pub fn delete_confirmed(ctx: &Ctx, c: &Connection, ids: &[i64], from_books: bool) -> Result<String, Fault> {
    let devices = selected_devices(ctx, c, ids, true)?;
    for d in &devices {
        // SoftDeletes::runSoftDelete: deleted_at and updated_at together
        let ts = crate::laravel::ts(ctx.now);
        db::exec(c, r#"update "devices" set "deleted_at" = ?, "updated_at" = ? where "id" = ?"#, &[P(Val::str(&ts)), P(Val::str(&ts)), P(Val::Int(d.id()))])?;
        let rid = s(d, "rustdesk_id");
        audit(ctx, c, "device.delete", &format!("Deleted device {rid}"), Some("device"), Some(&rid))?;
    }
    let n = devices.len() as i64;
    let mut message = if n == 1 { format!("Device {} moved to the recycle bin.", s(&devices[0], "rustdesk_id")) } else { format!("{n} {} moved to the recycle bin.", plural("device", n)) };
    if from_books && n > 0 {
        let rids: Vec<String> = devices.iter().map(|d| s(d, "rustdesk_id")).collect();
        let (removed, kept, _) = remove_from_books(ctx, c, &rids, "")?;
        message.push(' ');
        message.push_str(&removal_summary(removed, kept));
    }
    Ok(message)
}

/// `POST /devices/delete`: the confirm dialog's Delete button (from the list, or the detail page).
pub fn delete(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    need!(ctx, "device", "rw");
    let body = Body::of(req);
    let ids = body.ints("ids");
    let from_books = body.checked("from_books");
    let ret = body.get("return");
    if let Some(detail) = ret.strip_prefix("detail:").and_then(|v| v.parse::<i64>().ok()) {
        return super::device_detail::delete_from_detail(ctx, c, detail, &ids, from_books);
    }
    let message = delete_confirmed(ctx, c, &ids, from_books)?;
    bulk_result(ctx, &message);
    Ok(Reply::Redirect(if ret.starts_with("/devices") { ret } else { "/devices".into() }))
}

/// `POST /devices/act`: a row's Restore, Destroy, Approve or Reject.
pub fn act(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    need!(ctx, "device", "rw");
    let body = Body::of(req);
    let id = body.int("id");
    let back = body.get("back");
    match body.get("do").as_str() {
        "restore" => {
            let Some(d) = scoped_device(ctx, c, id)? else { return Ok(abort(404)) };
            // SoftDeletes::restore: deleted_at back to null, updated_at touched
            let mut d = d;
            update(c, "devices", &mut d, vec![("deleted_at", Val::Null, Cast::Date)], ctx.now)?;
            let rid = s(&d, "rustdesk_id");
            audit(ctx, c, "device.restore", &format!("Restored device {rid}"), Some("device"), Some(&rid))?;
        }
        "destroy" => {
            let Some(d) = scoped_device(ctx, c, id)? else { return Ok(abort(404)) };
            let rid = s(&d, "rustdesk_id");
            db::exec(c, r#"delete from "devices" where "id" = ?"#, &[P(Val::Int(d.id()))])?;
            audit(ctx, c, "device.destroy", &format!("Permanently deleted device {rid}"), Some("device"), Some(&rid))?;
        }
        "approve" | "reject" => {
            let mut w = Where::default();
            ownership(c, &ctx.user, &mut w)?;
            w.add(r#""devices"."status" = ?"#, vec![P(Val::str("pending"))]);
            w.add(r#""devices"."deleted_at" is null"#, vec![]);
            w.add(r#""devices"."id" = ?"#, vec![P(Val::Int(id))]);
            let Some(mut d) = db::first(c, &format!(r#"select * from "devices"{} limit 1"#, w.sql()), &w.params)? else { return Ok(abort(404)) };
            let rid = s(&d, "rustdesk_id");
            if body.get("do") == "approve" {
                update(c, "devices", &mut d, vec![("status", Val::str("active"), Cast::Plain)], ctx.now)?;
                audit(ctx, c, "device.approve", &format!("Approved device {rid}"), Some("device"), Some(&rid))?;
            } else {
                let ts = crate::laravel::ts(ctx.now);
                db::exec(c, r#"update "devices" set "deleted_at" = ?, "updated_at" = ? where "id" = ?"#, &[P(Val::str(&ts)), P(Val::str(&ts)), P(Val::Int(d.id()))])?;
                audit(ctx, c, "device.reject", &format!("Rejected device {rid}"), Some("device"), Some(&rid))?;
            }
        }
        _ => {}
    }
    Ok(redirect_back(&back))
}

/// `POST /devices/save`: the Add / Edit dialog (`EditsDevices::save`).
pub fn save(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    need!(ctx, "device", "rw");
    let body = Body::of(req);
    let id = body.int("id");
    let ret = body.get("return");
    let editing = if id != 0 { scoped_device(ctx, c, id)? } else { None };
    if id != 0 && editing.is_none() {
        return Ok(abort(404));
    }
    let rid = match &editing {
        Some(d) => s(d, "rustdesk_id"),
        None => body.get("rustdesk_id"),
    };
    let alias = body.get("alias");
    let note = body.get("note");
    let (group, owner, strategy) = (body.int("group_id"), body.int("user_id"), body.int("strategy_id"));
    let can_initiate = body.checked("can_initiate");
    let mut data = crate::php::Arr::new();
    for (k, v) in [("formRustdeskId", Val::str(&rid)), ("formAlias", Val::str(&alias)), ("formNote", Val::str(&note)), ("formGroupId", Val::Int(group)), ("formUserId", Val::Int(owner)), ("formStrategyId", Val::Int(strategy)), ("formCanInitiate", Val::Bool(can_initiate))] {
        data.set(crate::php::Key::Str(k.as_bytes().to_vec()), v);
    }
    let rules: [(&str, &[Rule]); 7] = [
        ("formRustdeskId", &[Rule::Required, Rule::String, Rule::Max(100)]),
        ("formAlias", &[Rule::Nullable, Rule::String, Rule::Max(255)]),
        ("formNote", &[Rule::Nullable, Rule::String, Rule::Max(500)]),
        ("formGroupId", &[Rule::Integer]),
        ("formUserId", &[Rule::Integer]),
        ("formStrategyId", &[Rule::Integer]),
        ("formCanInitiate", &[Rule::Boolean]),
    ];
    let probe_fn = |rule: &Rule, v: &Val| probe(c, rule, v);
    let mut errors: Map<String, Value> = Map::new();
    if let Err(b) = validate::validate_db(&data, &rules, &probe_fn)? {
        errors = first_messages(&b);
    } else if id == 0 {
        let mut u = crate::php::Arr::new();
        u.set(crate::php::Key::Str(b"formRustdeskId".to_vec()), Val::str(&rid));
        let ur: [(&str, &[Rule]); 1] = [("formRustdeskId", &[Rule::Unique("devices", "rustdesk_id", None)])];
        if let Err(b) = validate::validate_db(&u, &ur, &probe_fn)? {
            errors = first_messages(&b);
        }
    }
    if !errors.is_empty() {
        let mut values = Map::new();
        for (k, v) in [("rustdesk_id", json!(rid)), ("alias", json!(alias)), ("note", json!(note)), ("group", json!(group)), ("user", json!(owner)), ("strategy", json!(strategy)), ("can_initiate", json!(can_initiate))] {
            values.insert(k.into(), v);
        }
        // the messages are keyed by the previous console's page components property; the dialog reads them by its field names
        let mut by_field = Map::new();
        for (k, v) in &errors {
            let f = match k.as_str() {
                "formRustdeskId" => "rustdesk_id",
                "formAlias" => "alias",
                "formNote" => "note",
                other => other,
            };
            by_field.insert(f.to_string(), v.clone());
        }
        if let Some(detail) = ret.strip_prefix("detail:").and_then(|v| v.parse::<i64>().ok()) {
            return super::device_detail::render(ctx, c, detail, 422, Modal::Edit { id, values, errors: by_field }, req);
        }
        let st = St::from_back(ret.strip_prefix("/devices?").unwrap_or(""));
        return render(ctx, c, &st, 422, Modal::Edit { id, values, errors: by_field }, req);
    }
    let nullable_text = |v: &str| if truthy(v) { Val::str(v) } else { Val::Null };
    let nullable_id = |v: i64| if v != 0 { Val::Int(v) } else { Val::Null };
    if id == 0 {
        let new_id = db::insert(
            c,
            "devices",
            vec![
                ("alias", nullable_text(&alias)),
                ("note", nullable_text(&note)),
                ("device_group_id", nullable_id(group)),
                ("user_id", nullable_id(owner)),
                ("can_initiate", Val::Bool(can_initiate)),
                ("rustdesk_id", Val::str(&rid)),
                ("uuid", Val::str("")),
            ],
            &crate::laravel::ts(ctx.now),
        )?;
        if let Some(mut d) = find(c, "devices", new_id)? {
            crate::strategy::sync_resolved_for(c, &mut d, &crate::laravel::ts(ctx.now))?;
        }
        audit(ctx, c, "device.create", &format!("Created device {rid}"), Some("device"), Some(&rid))?;
    } else {
        let mut d = editing.unwrap();
        let changed = update(
            c,
            "devices",
            &mut d,
            vec![
                ("alias", nullable_text(&alias), Cast::Plain),
                ("note", nullable_text(&note), Cast::Plain),
                ("device_group_id", nullable_id(group), Cast::Plain),
                ("user_id", nullable_id(owner), Cast::Plain),
                ("can_initiate", Val::Bool(can_initiate), Cast::Bool),
            ],
            ctx.now,
        )?;
        if changed.iter().any(|x| x == "user_id" || x == "device_group_id") {
            crate::strategy::sync_resolved_for(c, &mut d, &crate::laravel::ts(ctx.now))?;
        }
        audit(ctx, c, "device.update", &format!("Updated device {rid}"), Some("device"), Some(&rid))?;
        if changed.iter().any(|x| x == "can_initiate") {
            audit(ctx, c, "device.initiate", &format!("Device {rid} set {}", if can_initiate { "allowed to start sessions" } else { "incoming only" }), Some("device"), Some(&rid))?;
        }
        if ctx.is_admin() {
            let current = assigned_strategy(c, "device", d.id())?.unwrap_or(0);
            let exists = strategy != 0 && db::first(c, r#"select 1 as x from "strategies" where "id" = ? and "deleted_at" is null limit 1"#, &[P(Val::Int(strategy))])?.is_some();
            if current != strategy && !(strategy != 0 && !exists) {
                strategy_assign(c, "device", d.id(), if strategy == 0 { None } else { Some(strategy) }, ctx.now)?;
                let name = if strategy == 0 { "none (inherits)".to_string() } else { db::first(c, r#"select "name" from "strategies" where "id" = ? limit 1"#, &[P(Val::Int(strategy))])?.map(|r| s(&r, "name")).unwrap_or_default() };
                audit(ctx, c, "strategy.assign", &format!("Device {rid} strategy set to {name}"), Some("device"), Some(&rid))?;
            }
        }
    }
    if ret.starts_with("detail:") {
        return Ok(Reply::Redirect(format!("/devices/{}", ret.trim_start_matches("detail:"))));
    }
    Ok(Reply::Redirect(if ret.starts_with("/devices") { ret } else { "/devices".into() }))
}

/// `GET /devices/export`: the current view as CSV (`exportCsv`). It leaves an audit line, as the action did.
pub fn export(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let st = St::from(req);
    let view = saved_view(ctx);
    let dup = if !st.trashed && st.status == "duplicates" { Some(dups(ctx, c)?) } else { None };
    let query = filtered(ctx, c, &st, &view, dup.as_ref())?;
    let rows = run(c, &query, None)?;
    audit(ctx, c, "device.export", &format!("Exported {} devices to CSV", rows.len()), Some("device"), Some(""))?;
    let group_ids: Vec<i64> = rows.iter().filter(|d| !d.is_null("device_group_id")).map(|d| d.val("device_group_id").to_int()).collect();
    let user_ids: Vec<i64> = rows.iter().filter(|d| !d.is_null("user_id")).map(|d| d.val("user_id").to_int()).collect();
    let groups = find_in(c, "device_groups", &group_ids)?;
    let users = find_in(c, "users", &user_ids)?;
    let mut out = super::logs::csv_line(
        &["row_id", "id", "cpu", "hostname", "memory", "os", "username", "uuid", "version", "last_online_time", "last_online_ip", "group_id", "alias", "created_at", "updated_at", "group_name", "owner", "status", "note", "registered_ip", "incoming_only", "lan_ip", "lan_ip_seen_at"]
            .iter()
            .map(|h| h.to_string())
            .collect::<Vec<_>>(),
    );
    let dt = |d: &Row, col: &str| ts_of(d, col).map(crate::laravel::ts).unwrap_or_default();
    for d in rows {
        let status = if !d.is_null("deleted_at") { "disabled" } else if s(&d, "status") == "pending" { "pending" } else { "active" };
        let can = d.val("can_initiate");
        let incoming = can == Val::Bool(false) || matches!(can, Val::Int(0));
        out.push_str(&super::logs::csv_line(&[
            d.id().to_string(),
            s(&d, "rustdesk_id"),
            s(&d, "cpu"),
            s(&d, "hostname"),
            s(&d, "memory"),
            s(&d, "os"),
            s(&d, "username"),
            s(&d, "uuid"),
            s(&d, "version"),
            dt(&d, "last_online_at"),
            s(&d, "last_online_ip"),
            s(&d, "device_group_id"),
            s(&d, "alias"),
            dt(&d, "created_at"),
            dt(&d, "updated_at"),
            by_id(&groups, &d.val("device_group_id")).map(|g| s(g, "name")).unwrap_or_default(),
            by_id(&users, &d.val("user_id")).map(|u| s(u, "username")).unwrap_or_default(),
            status.to_string(),
            s(&d, "note"),
            s(&d, "registered_ip"),
            (incoming as i32).to_string(),
            s(&d, "lan_ip"),
            dt(&d, "lan_ip_seen_at"),
        ]));
    }
    Ok(Reply::Csv { filename: "devices.csv".into(), body: out })
}

#[allow(dead_code)]
fn unused(_: &Row) -> Value {
    let _ = (row_json as fn(&Row) -> Value, time::ago as fn(i64, i64, bool) -> String);
    Value::Null
}
