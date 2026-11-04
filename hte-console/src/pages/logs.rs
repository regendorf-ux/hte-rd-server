//! The five log pages (the previous console's `AlarmLogList`, `ConnectionLog`, `FileTransferLog`, `LoginLogList`,
//! `ConsoleAuditList`): the same queries in the same order, the same filters, pages and CSV exports, as plain
//! `GET`s that htmx swaps in place (the filter bar is a form; the list under it is `#log-body`).
//!
//! Every filter is a query parameter, as the previous console's `#[Url]` properties were: `search`, `type` (alarms), `action`
//! (console), `dateFrom`, `dateTo`, `page`; `perPage` (20, 50, 100) was a component property there and is a
//! parameter here. Who sees what: the alarm, connection and file-transfer logs list only the approved devices a
//! non-administrator may see (`Device::visibleTo`), so the console's own alarms (`rustdesk_id = 'console'`) stay
//! administrators'; the login and console logs need the `audit` area at Manage level.

use super::{paginate, row_json, time, val_json, Ctx, Reply, Req};
use crate::php::{self, Fault, Val};
use crate::sqlite::{self as db, Row, P};
use rusqlite::Connection;
use serde_json::{json, Value};

const PER_PAGES: [i64; 3] = [20, 50, 100];

/// A page of rows and what the view needs about the paging.
struct Listing {
    rows: Vec<Row>,
    page: paginate::Page,
}

/// The filter bar, read from the query string like the previous console's page components properties (a missing one is '').
struct Filters {
    search: String,
    kind: String,
    action: String,
    /// HTE: the connection log's Path filter (`relay`, `direct`, `lan`, `unknown`)
    path: String,
    date_from: String,
    date_to: String,
    per_page: i64,
    page: i64,
}

fn text(req: &Req, key: &str) -> String {
    req.input.string(key).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default()
}

impl Filters {
    fn from(req: &Req) -> Filters {
        let per_page = text(req, "perPage").parse::<i64>().ok().filter(|n| PER_PAGES.contains(n)).unwrap_or(20);
        // The previous console's pagination: `page` is a positive integer, anything else is the first page
        let page = text(req, "page").parse::<i64>().ok().filter(|n| *n >= 1).unwrap_or(1);
        Filters { search: text(req, "search"), kind: text(req, "type"), action: text(req, "action"), path: text(req, "path"), date_from: text(req, "dateFrom"), date_to: text(req, "dateTo"), per_page, page }
    }

    /// The query string (with a trailing `&` when not empty) the pager's links repeat: what `#[Url(except: '')]`
    /// keeps, plus `perPage` when it is not the default.
    fn query(&self, with_kind: bool, with_action: bool) -> String {
        let mut pairs: Vec<(&str, &[u8])> = vec![];
        if !self.search.is_empty() {
            pairs.push(("search", self.search.as_bytes()));
        }
        if with_kind && !self.kind.is_empty() {
            pairs.push(("type", self.kind.as_bytes()));
        }
        if with_action && !self.action.is_empty() {
            pairs.push(("action", self.action.as_bytes()));
        }
        if crate::path::filter_sql(&self.path).is_some() {
            pairs.push(("path", self.path.as_bytes()));
        }
        if !self.date_from.is_empty() {
            pairs.push(("dateFrom", self.date_from.as_bytes()));
        }
        if !self.date_to.is_empty() {
            pairs.push(("dateTo", self.date_to.as_bytes()));
        }
        let per = self.per_page.to_string();
        if self.per_page != 20 {
            pairs.push(("perPage", per.as_bytes()));
        }
        if pairs.is_empty() {
            String::new()
        } else {
            format!("{}&", crate::laravel::http_build_query(&pairs))
        }
    }
}

/// A where clause under construction: SQL fragments joined with `and`, bound values in order.
#[derive(Default)]
struct Where {
    parts: Vec<String>,
    params: Vec<P>,
}

impl Where {
    fn add(&mut self, sql: &str, params: Vec<P>) {
        self.parts.push(sql.to_string());
        self.params.extend(params);
    }

    /// `->whereIn('rustdesk_id', $ids)`: an empty list is Laravel's `0 = 1`.
    fn rustdesk_in(&mut self, ids: &[String]) {
        if ids.is_empty() {
            self.add("0 = 1", vec![]);
        } else {
            self.add(&format!(r#""rustdesk_id" in ({})"#, vec!["?"; ids.len()].join(", ")), ids.iter().map(|i| P(Val::str(i))).collect());
        }
    }

    /// `->where(fn ($q) => $q->where(c1, 'like', $s)->orWhere(c2, ...))`
    fn like_any(&mut self, cols: &[&str], needle: &str) {
        let s = format!("%{needle}%");
        let sql = cols.iter().map(|c| format!(r#""{c}" like ?"#)).collect::<Vec<_>>().join(" or ");
        self.add(&format!("({sql})"), cols.iter().map(|_| P(Val::str(&s))).collect());
    }

    /// `->whereDate('created_at', '>=' / '<=', $date)` (SQLite grammar).
    fn date(&mut self, op: &str, date: &str) {
        self.add(&format!(r#"strftime('%Y-%m-%d', "created_at") {op} cast(? as text)"#), vec![P(Val::str(date))]);
    }

    fn sql(&self) -> String {
        if self.parts.is_empty() {
            String::new()
        } else {
            format!(" where {}", self.parts.join(" and "))
        }
    }
}

fn dates(w: &mut Where, f: &Filters) {
    if !f.date_from.is_empty() {
        w.date(">=", &f.date_from);
    }
    if !f.date_to.is_empty() {
        w.date("<=", &f.date_to);
    }
}

/// `->orderByDesc('created_at')->orderByDesc('id')->paginate($perPage)` (count first, then the page).
fn paginated(c: &Connection, table: &str, w: &Where, f: &Filters) -> Result<Listing, Fault> {
    let count = db::first(c, &format!(r#"select count(*) as aggregate from "{table}"{}"#, w.sql()), &w.params)?;
    let total = count.map(|r| r.val("aggregate").to_int()).unwrap_or(0);
    let sql = format!(r#"select * from "{table}"{} order by "created_at" desc, "id" desc limit {} offset {}"#, w.sql(), f.per_page, (f.page - 1) * f.per_page);
    let rows = db::rows(c, &sql, &w.params)?;
    let page = paginate::page(f.page, f.per_page, total, rows.len() as i64);
    Ok(Listing { rows, page })
}

/// Up to 10,000 rows for the CSV (`->limit(10000)->get()`).
fn export_rows(c: &Connection, table: &str, w: &Where) -> Result<Vec<Row>, Fault> {
    db::rows(c, &format!(r#"select * from "{table}"{} order by "created_at" desc, "id" desc limit 10000"#, w.sql()), &w.params)
}

// -------------------------------------------------------------------------------------------------- row helpers ---

fn s(r: &Row, col: &str) -> String {
    String::from_utf8_lossy(&r.val(col).to_php_string().unwrap_or_default()).into_owned()
}

/// The previous console truthiness of a string (`$x ?: '—'`).
fn falsy(v: &str) -> bool {
    v.is_empty() || v == "0"
}

fn dash(v: &str) -> String {
    if falsy(v) {
        "—".to_string()
    } else {
        v.to_string()
    }
}

fn ts_of(r: &Row, col: &str) -> Option<i64> {
    crate::laravel::parse_ts(&r.val(col))
}

/// `Csv::row`'s guard against spreadsheet formulas, then `fputcsv` (comma, double quote, backslash escape).
pub(crate) fn csv_line(cells: &[String]) -> String {
    let mut out = vec![];
    for cell in cells {
        let cell = if !cell.is_empty() && "=+-@\t\r".contains(cell.chars().next().unwrap()) { format!("'{cell}") } else { cell.clone() };
        out.push(fputcsv_field(&cell));
    }
    out.join(",") + "\n"
}

/// `fputcsv`: a field is enclosed when it holds a delimiter, an enclosure, the escape character, a newline, a
/// carriage return, a tab or a space; inside, an enclosure is doubled unless an escape character precedes it.
fn fputcsv_field(f: &str) -> String {
    if !f.chars().any(|c| matches!(c, ',' | '"' | '\\' | '\n' | '\r' | '\t' | ' ')) {
        return f.to_string();
    }
    let mut out = String::from("\"");
    let mut escaped = false;
    for ch in f.chars() {
        if ch == '\\' {
            escaped = true;
        } else if !escaped && ch == '"' {
            out.push('"');
        } else {
            escaped = false;
        }
        out.push(ch);
    }
    out.push('"');
    out
}

fn csv(filename: &str, header: &[&str], rows: Vec<Vec<String>>) -> Reply {
    let mut body = header.iter().map(|h| fputcsv_field(h)).collect::<Vec<_>>().join(",") + "\n";
    for r in rows {
        body.push_str(&csv_line(&r));
    }
    Reply::Csv { filename: filename.to_string(), body }
}

fn when_str(r: &Row) -> String {
    ts_of(r, "created_at").map(crate::laravel::ts).unwrap_or_default()
}

// ---------------------------------------------------------------------------------------------------- alarms ---

/// `AlarmLog::TYPES`: label and badge severity.
pub const ALARM_TYPES: &[(i64, &str, &str)] = &[
    (0, "IP whitelist block", "danger"),
    (1, "Many failed attempts (>30)", "danger"),
    (2, "Rapid access attempts", "warning"),
    (6, "IPv6 prefix attempts exceeded", "warning"),
    (7, "Terminal login backoff", "warning"),
    (8, "Terminal login concurrency", "warning"),
    (9, "Session scope violation", "danger"),
    (10, "ID whitelist block", "danger"),
    (100, "Console brute force", "danger"),
    (101, "Console password spraying", "danger"),
    (102, "Session refused: outside the person's access", "danger"),
    (103, "Session closed: access removed", "warning"),
];

pub fn alarm_label(typ: i64) -> String {
    ALARM_TYPES.iter().find(|t| t.0 == typ).map(|t| t.1.to_string()).unwrap_or_else(|| format!("Type {typ}"))
}

pub fn alarm_severity(typ: i64) -> &'static str {
    ALARM_TYPES.iter().find(|t| t.0 == typ).map(|t| t.2).unwrap_or("secondary")
}

/// `AlarmLog::infoPairs()`: the client's JSON `info` as scalar key/value pairs; empty when it is not JSON.
pub fn info_pairs(info: &[u8]) -> Vec<(String, String)> {
    let Some(Val::Arr(a)) = php::json_decode(info, &php::JsonOpts::default()) else { return vec![] };
    let mut out = vec![];
    for (k, v) in a.iter() {
        let key = String::from_utf8_lossy(&k.as_bytes()).into_owned();
        let value = match v {
            Val::Str(b) => String::from_utf8_lossy(b).into_owned(),
            Val::Int(i) => i.to_string(),
            Val::Float(f) => php::float_to_string(*f),
            Val::Bool(true) => "1".to_string(),
            Val::Bool(false) => String::new(),
            other => php::json_encode(other).unwrap_or_default(),
        };
        out.push((key, value));
    }
    out
}

fn alarm_where(ctx: &Ctx, c: &Connection, f: &Filters) -> Result<Where, Fault> {
    let mut w = Where::default();
    if !ctx.is_admin() {
        w.rustdesk_in(&ctx.visible_device_ids(c)?);
    }
    if !f.search.is_empty() {
        w.like_any(&["rustdesk_id", "info"], &f.search);
    }
    if !f.kind.is_empty() {
        w.add(r#""typ" = ?"#, vec![P(Val::Int(php::str_to_int(f.kind.as_bytes())))]);
    }
    dates(&mut w, f);
    Ok(w)
}

fn alarm_json(r: &Row, now: i64) -> Value {
    let typ = r.val("typ").to_int();
    let info = r.val("info").to_php_string().unwrap_or_default();
    let info_s = String::from_utf8_lossy(&info).into_owned();
    let pairs = info_pairs(&info);
    let conn = s(r, "conn_id");
    let created = ts_of(r, "created_at");
    json!({
        "id": r.id(),
        "when": when_str(r),
        "ago": created.map(|t| time::ago(t, now, false)).unwrap_or_default(),
        "ago_short": created.map(|t| time::ago(t, now, true)).unwrap_or_default(),
        "rustdesk_id": s(r, "rustdesk_id"),
        "is_console": s(r, "rustdesk_id") == "console",
        "type_label": alarm_label(typ),
        "severity": alarm_severity(typ),
        "has_pairs": !pairs.is_empty(),
        "pairs": pairs.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
        "info": info_s,
        "info_dash": dash(&info_s),
        "has_info": !falsy(&info_s),
        "conn_id": conn,
        "conn_dash": dash(&conn),
        "has_conn": !falsy(&conn),
    })
}

pub fn alarms(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let f = Filters::from(req);
    let w = alarm_where(ctx, c, &f)?;
    let l = paginated(c, "alarm_logs", &w, &f)?;
    let layout = ctx.layout(c, "logs.alarms", "Alarm Log", "Logs")?;
    let types: Vec<Value> = ALARM_TYPES.iter().map(|t| json!({"id": t.0, "label": t.1})).collect();
    let page = json!({
        "path": "/logs/alarms",
        "filters": {"search": f.search, "type": f.kind, "dateFrom": f.date_from, "dateTo": f.date_to, "perPage": f.per_page},
        "query": f.query(true, false),
        "types": types,
        "rows": l.rows.iter().map(|r| alarm_json(r, ctx.now)).collect::<Vec<_>>(),
        "pager": l.page,
    });
    Ok(Reply::Html(200, ctx.render("logs/alarms.html", layout, page)?))
}

pub fn alarms_export(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let f = Filters::from(req);
    let w = alarm_where(ctx, c, &f)?;
    let rows = export_rows(c, "alarm_logs", &w)?;
    Ok(csv(
        "alarm-log.csv",
        &["When", "Device", "Type", "Info", "Conn ID"],
        rows.iter().map(|r| vec![when_str(r), s(r, "rustdesk_id"), alarm_label(r.val("typ").to_int()), s(r, "info"), s(r, "conn_id")]).collect(),
    ))
}

// ------------------------------------------------------------------------------------------------ connections ---

const CONN_TYPES: &[(i64, &str, &str)] = &[
    (0, "Remote Control", "ri-remote-control-line"),
    (1, "File Transfer", "ri-file-transfer-line"),
    (2, "Port Forward", "ri-swap-line"),
    (3, "View Camera", "ri-camera-line"),
    (4, "Terminal", "ri-terminal-box-line"),
];

pub(crate) fn conn_label(t: i64) -> String {
    CONN_TYPES.iter().find(|x| x.0 == t).map(|x| x.1.to_string()).unwrap_or_else(|| format!("Type {t}"))
}

pub(crate) fn conn_icon(t: i64) -> &'static str {
    CONN_TYPES.iter().find(|x| x.0 == t).map(|x| x.2).unwrap_or("ri-question-line")
}

fn visible_only(ctx: &Ctx, c: &Connection, w: &mut Where) -> Result<(), Fault> {
    if !ctx.is_admin() {
        w.rustdesk_in(&ctx.visible_device_ids(c)?);
    }
    Ok(())
}

fn conn_where(ctx: &Ctx, c: &Connection, f: &Filters) -> Result<Where, Fault> {
    let mut w = Where::default();
    visible_only(ctx, c, &mut w)?;
    if !f.search.is_empty() {
        w.like_any(&["rustdesk_id", "from_peer", "from_name", "ip", "note"], &f.search);
    }
    if let Some(sql) = crate::path::filter_sql(&f.path) {
        w.add(sql, vec![]); // HTE
    }
    dates(&mut w, f);
    Ok(w)
}

/// `with('noteUser')`: the username of each distinct `note_user_id`.
fn note_users(c: &Connection, rows: &[Row]) -> Result<std::collections::HashMap<i64, String>, Fault> {
    let mut ids: Vec<i64> = vec![];
    for r in rows {
        if let Val::Int(i) = r.val("note_user_id") {
            if !ids.contains(&i) {
                ids.push(i);
            }
        }
    }
    let mut out = std::collections::HashMap::new();
    if !ids.is_empty() {
        let sql = format!(r#"select * from "users" where "users"."id" in ({})"#, vec!["?"; ids.len()].join(", "));
        for u in db::rows(c, &sql, &ids.iter().map(|i| P(Val::Int(*i))).collect::<Vec<_>>())? {
            out.insert(u.id(), s(&u, "username"));
        }
    }
    Ok(out)
}

/// HTE: how the row got through (`path.rs`) and, for a relayed one, what the relay carried (None until the relay reports it).
pub(crate) fn transport_of(r: &Row, relayed: &std::collections::HashMap<i64, i64>) -> (Option<&'static str>, Option<i64>) {
    let session = match r.val("relay_session_id") {
        Val::Int(i) => Some(i),
        _ => None,
    };
    let path = if r.is_null("path") { None } else { Some(s(r, "path")) };
    let transport = crate::path::transport(path.as_deref(), session.is_some());
    (transport, session.and_then(|i| relayed.get(&i).copied()))
}

fn conn_json(r: &Row, now: i64, users: &std::collections::HashMap<i64, String>, relayed: &std::collections::HashMap<i64, i64>) -> Value {
    let ctype = r.val("conn_type");
    let t = ctype.to_int();
    // the views compare `=== 1` and `=== 2`: strictly the integers
    let strict = matches!(ctype, Val::Int(_));
    let kind = match (strict, t) {
        (true, 1) => "file",
        (true, 2) => "forward",
        _ => "other",
    };
    let created = ts_of(r, "created_at");
    let closed = ts_of(r, "closed_at");
    let from_peer = s(r, "from_peer");
    let note = s(r, "note");
    let note_user = match r.val("note_user_id") {
        Val::Int(i) => users.get(&i).cloned(),
        _ => None,
    };
    let (transport, carried) = transport_of(r, relayed);
    json!({
        "id": r.id(),
        "when": when_str(r),
        "ago": created.map(|t| time::ago(t, now, false)).unwrap_or_default(),
        "ago_short": created.map(|t| time::ago(t, now, true)).unwrap_or_default(),
        "transport": transport.unwrap_or(""),
        "transport_label": crate::path::transport_label(transport),
        "relay_size": carried.map(crate::path::human_bytes).unwrap_or_default(),
        "rustdesk_id": s(r, "rustdesk_id"),
        "from_dash": dash(&from_peer),
        "from_name": s(r, "from_name"),
        "kind": kind,
        "type_label": conn_label(t),
        "type_icon": conn_icon(t),
        "ip": s(r, "ip"),
        "ip_dash": dash(&s(r, "ip")),
        "closed": closed.is_some(),
        "closed_at": closed.map(crate::laravel::ts).unwrap_or_default(),
        "duration": match (closed, created) { (Some(a), Some(b)) => time::short_absolute(a, b), _ => String::new() },
        "has_note": !falsy(&note),
        "note": note,
        "note_user": note_user,
    })
}

pub fn connections(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let f = Filters::from(req);
    let w = conn_where(ctx, c, &f)?;
    let l = paginated(c, "audit_connections", &w, &f)?;
    let users = note_users(c, &l.rows)?;
    let relayed = crate::path::relay_bytes(c, &l.rows)?;
    let layout = ctx.layout(c, "logs.connections", "Connection Log", "Logs")?;
    let paths: Vec<Value> = crate::path::FILTERS.iter().map(|(k, l)| json!({"id": k, "label": l})).collect();
    let page = json!({
        "path": "/logs/connections",
        "filters": {"search": f.search, "dateFrom": f.date_from, "dateTo": f.date_to, "perPage": f.per_page, "path": if crate::path::filter_sql(&f.path).is_some() { f.path.as_str() } else { "" }},
        "paths": paths,
        "query": f.query(false, false),
        "rows": l.rows.iter().map(|r| conn_json(r, ctx.now, &users, &relayed)).collect::<Vec<_>>(),
        "pager": l.page,
    });
    Ok(Reply::Html(200, ctx.render("logs/connections.html", layout, page)?))
}

pub fn connections_export(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let f = Filters::from(req);
    let w = conn_where(ctx, c, &f)?;
    let rows = export_rows(c, "audit_connections", &w)?;
    let users = note_users(c, &rows)?;
    let relayed = crate::path::relay_bytes(c, &rows)?;
    Ok(csv(
        "connection-log.csv",
        &["When", "Controlled Device", "From ID", "From Name", "Type", "IP", "Path", "Relayed (bytes)", "Closed At", "Duration (s)", "Note", "Note By"],
        rows.iter()
            .map(|r| {
                let (created, closed) = (ts_of(r, "created_at"), ts_of(r, "closed_at"));
                let (transport, carried) = transport_of(r, &relayed);
                vec![
                    when_str(r),
                    s(r, "rustdesk_id"),
                    s(r, "from_peer"),
                    s(r, "from_name"),
                    conn_label(r.val("conn_type").to_int()),
                    s(r, "ip"),
                    transport.map(|_| crate::path::transport_label(transport).to_string()).unwrap_or_default(),
                    carried.map(|b| b.to_string()).unwrap_or_default(),
                    closed.map(crate::laravel::ts).unwrap_or_else(|| "active".to_string()),
                    match (closed, created) {
                        (Some(a), Some(b)) => (a - b).abs().to_string(),
                        _ => String::new(),
                    },
                    s(r, "note"),
                    match r.val("note_user_id") {
                        Val::Int(i) => users.get(&i).cloned().unwrap_or_default(),
                        _ => String::new(),
                    },
                ]
            })
            .collect(),
    ))
}

// -------------------------------------------------------------------------------------------- file transfers ---

/// `AuditFileTransfer::transferredFiles()`: the names (non-empty strings) in `info.files`.
pub fn file_names(info: &[u8]) -> Vec<String> {
    let Some(Val::Arr(a)) = php::json_decode(info, &php::JsonOpts::default()) else { return vec![] };
    let Some(Val::Arr(files)) = a.get_str("files") else { return vec![] };
    let mut out = vec![];
    for (_, f) in files.iter() {
        if let Val::Arr(pair) = f {
            if let Some(Val::Str(n)) = pair.get(&php::Key::Int(0)) {
                if !n.is_empty() {
                    out.push(String::from_utf8_lossy(n).into_owned());
                }
            }
        }
    }
    out
}

/// `pathLabel(2)`: the path, else the first names and "+N more".
pub fn path_label(path: &str, info: &[u8], file_count: i64) -> String {
    if !path.is_empty() {
        return path.to_string();
    }
    let names = file_names(info);
    if names.is_empty() {
        return String::new();
    }
    let total = std::cmp::max(file_count, names.len() as i64);
    let label = names.iter().take(2).cloned().collect::<Vec<_>>().join(", ");
    let more = total - std::cmp::min(2, names.len() as i64);
    if more > 0 {
        format!("{label} +{more} more")
    } else {
        label
    }
}

fn transfer_where(ctx: &Ctx, c: &Connection, f: &Filters) -> Result<Where, Fault> {
    let mut w = Where::default();
    visible_only(ctx, c, &mut w)?;
    if !f.search.is_empty() {
        w.like_any(&["rustdesk_id", "from_peer", "from_name", "path", "info", "ip"], &f.search);
    }
    dates(&mut w, f);
    Ok(w)
}

fn transfer_json(r: &Row, now: i64) -> Value {
    let created = ts_of(r, "created_at");
    let path = s(r, "path");
    let info = r.val("info").to_php_string().unwrap_or_default();
    let names = file_names(&info);
    let count = r.val("file_count").to_int();
    let clipboard = path.is_empty() && !names.is_empty();
    let label = path_label(&path, &info, count);
    let from_peer = s(r, "from_peer");
    json!({
        "id": r.id(),
        "when": when_str(r),
        "ago": created.map(|t| time::ago(t, now, false)).unwrap_or_default(),
        "ago_short": created.map(|t| time::ago(t, now, true)).unwrap_or_default(),
        "rustdesk_id": s(r, "rustdesk_id"),
        "from_dash": dash(&from_peer),
        "from_name": s(r, "from_name"),
        "receive": matches!(r.val("direction"), Val::Int(1)),
        "clipboard": clipboard,
        "title": if clipboard { names.join(", ") } else { path.clone() },
        "label_dash": dash(&label),
        "file_count": count,
        "ip_dash": dash(&s(r, "ip")),
    })
}

pub fn file_transfers(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let f = Filters::from(req);
    let w = transfer_where(ctx, c, &f)?;
    let l = paginated(c, "audit_file_transfers", &w, &f)?;
    let layout = ctx.layout(c, "logs.file-transfers", "File Transfer Log", "Logs")?;
    let page = json!({
        "path": "/logs/file-transfers",
        "filters": {"search": f.search, "dateFrom": f.date_from, "dateTo": f.date_to, "perPage": f.per_page},
        "query": f.query(false, false),
        "rows": l.rows.iter().map(|r| transfer_json(r, ctx.now)).collect::<Vec<_>>(),
        "pager": l.page,
    });
    Ok(Reply::Html(200, ctx.render("logs/file-transfers.html", layout, page)?))
}

pub fn file_transfers_export(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let f = Filters::from(req);
    let w = transfer_where(ctx, c, &f)?;
    let rows = export_rows(c, "audit_file_transfers", &w)?;
    Ok(csv(
        "file-transfer-log.csv",
        &["When", "Device", "From ID", "From Name", "Direction", "Path", "Files", "IP", "File names"],
        rows.iter()
            .map(|r| {
                let info = r.val("info").to_php_string().unwrap_or_default();
                vec![
                    when_str(r),
                    s(r, "rustdesk_id"),
                    s(r, "from_peer"),
                    s(r, "from_name"),
                    if matches!(r.val("direction"), Val::Int(1)) { "Receive".into() } else { "Send".into() },
                    s(r, "path"),
                    s(r, "file_count"),
                    s(r, "ip"),
                    file_names(&info).join("; "),
                ]
            })
            .collect(),
    ))
}

// ----------------------------------------------------------------------------------------------------- logins ---

fn login_where(f: &Filters) -> Where {
    let mut w = Where::default();
    if !f.search.is_empty() {
        w.like_any(&["username", "device_id", "ip"], &f.search);
    }
    dates(&mut w, f);
    w
}

fn login_json(r: &Row, now: i64) -> Value {
    let created = ts_of(r, "created_at");
    let username = s(r, "username");
    let client = s(r, "client");
    let kind = match client.as_str() {
        "web" | "mobile" | "desktop" => client.clone(),
        _ => "other".to_string(),
    };
    let initial: String = if falsy(&username) { "?".into() } else { username.chars().next().map(|c| c.to_uppercase().collect()).unwrap_or_default() };
    let note = s(r, "note");
    let client_label = {
        let mut chars = client.chars();
        chars.next().map(|f| f.to_uppercase().collect::<String>() + chars.as_str()).unwrap_or_default()
    };
    json!({
        "id": r.id(),
        "when": when_str(r),
        "ago": created.map(|t| time::ago(t, now, false)).unwrap_or_default(),
        "ago_short": created.map(|t| time::ago(t, now, true)).unwrap_or_default(),
        "username": username,
        "initial": initial,
        "client_kind": kind,
        "client_label": client_label,
        "device_dash": dash(&s(r, "device_id")),
        "device_os": s(r, "device_os"),
        "ip_dash": dash(&s(r, "ip")),
        "successful": r.val("successful").to_bool(),
        "note": note,
        "has_note": !falsy(&note),
    })
}

pub fn logins(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let f = Filters::from(req);
    let w = login_where(&f);
    let l = paginated(c, "login_logs", &w, &f)?;
    let layout = ctx.layout(c, "logs.logins", "Login Log", "Logs")?;
    let page = json!({
        "path": "/logs/logins",
        "filters": {"search": f.search, "dateFrom": f.date_from, "dateTo": f.date_to, "perPage": f.per_page},
        "query": f.query(false, false),
        "rows": l.rows.iter().map(|r| login_json(r, ctx.now)).collect::<Vec<_>>(),
        "pager": l.page,
    });
    Ok(Reply::Html(200, ctx.render("logs/logins.html", layout, page)?))
}

pub fn logins_export(_ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let f = Filters::from(req);
    let rows = export_rows(c, "login_logs", &login_where(&f))?;
    Ok(csv(
        "login-log.csv",
        &["When", "Username", "Client", "Device ID", "Device OS", "IP", "Result", "Note"],
        rows.iter()
            .map(|r| {
                vec![
                    when_str(r),
                    s(r, "username"),
                    s(r, "client"),
                    s(r, "device_id"),
                    s(r, "device_os"),
                    s(r, "ip"),
                    if r.val("successful").to_bool() { "Success".into() } else { "Failed".into() },
                    s(r, "note"),
                ]
            })
            .collect(),
    ))
}

// ------------------------------------------------------------------------------------------------------ console ---

/// `ConsoleAuditList::ACTIONS`.
const ACTIONS: &[(&str, &str)] = &[
    ("account.update", "Profile updated"),
    ("account.password", "Password changed"),
    ("address-book.create", "Address book created"),
    ("address-book.update", "Address book updated"),
    ("address-book.delete", "Address book deleted"),
    ("address-book.rule-add", "Share rule added"),
    ("address-book.rule-update", "Share rule updated"),
    ("address-book.rule-delete", "Share rule deleted"),
    ("address-book.tag-add", "Tag added"),
    ("address-book.tag-update", "Tag updated"),
    ("address-book.tag-delete", "Tag deleted"),
    ("address-book.peer-add", "Entry added"),
    ("address-book.peer-update", "Entry updated"),
    ("address-book.peer-delete", "Entry removed"),
    ("api-token.create", "API token created"),
    ("api-token.revoke", "API token revoked"),
    ("backup.create", "Backup created"),
    ("backup.download", "Backup downloaded"),
    ("backup.restore", "Backup restored"),
    ("backup.delete", "Backup deleted"),
    ("backup.settings", "Backup settings changed"),
    ("client_download.create", "Download uploaded"),
    ("client_download.update", "Download updated"),
    ("client_download.publish", "Download published"),
    ("client_download.unpublish", "Download unpublished"),
    ("client_download.delete", "Download deleted"),
    ("device.create", "Device created"),
    ("device.update", "Device updated"),
    ("device.approve", "Device approved"),
    ("device.reject", "Device rejected"),
    ("device.enable", "Device enabled"),
    ("device.disable", "Device disabled"),
    ("device.initiate", "Session start permission changed"),
    ("device.assign", "Device assigned"),
    ("device.group-move", "Devices moved to a group"),
    ("device.duplicate-dismiss", "Duplicate flag dismissed"),
    ("device.export", "Devices exported"),
    ("device.delete", "Device deleted"),
    ("device.restore", "Device restored"),
    ("device.destroy", "Device destroyed"),
    ("group.create", "Group created"),
    ("group.update", "Group updated"),
    ("group.delete", "Group deleted"),
    ("logs.prune", "Logs pruned"),
    ("role.create", "Role created"),
    ("role.update", "Role updated"),
    ("role.delete", "Role deleted"),
    ("session.disconnect", "Session disconnected"),
    ("settings.update", "Settings updated"),
    ("settings.server-access", "Server access changed"),
    ("settings.server-ip-match", "Server IP matching changed"),
    ("settings.mail-test", "Test email sent"),
    ("settings.notification-test", "Test notification sent"),
    ("settings.presence-snooze", "Presence alerts snoozed"),
    ("settings.presence-snooze-clear", "Presence snooze cleared"),
    ("setup.complete", "Setup completed"),
    ("setup.dismiss", "Setup guide dismissed"),
    ("strategy.create", "Strategy created"),
    ("strategy.update", "Strategy updated"),
    ("strategy.toggle", "Strategy enabled/disabled"),
    ("strategy.rollback", "Strategy rolled back"),
    ("strategy.assign", "Strategy assigned"),
    ("strategy.delete", "Strategy deleted"),
    ("user.create", "User created"),
    ("user.update", "User updated"),
    ("user.enable", "User enabled"),
    ("user.disable", "User disabled"),
    ("user.force-logout", "User force-logout"),
    ("user.assign-devices", "Devices assigned to user"),
    ("user.invite", "Invitation sent"),
    ("user.invite-resend", "Invitation resent"),
    ("user.invite-revoke", "Invitation revoked"),
    ("user.invite-accept", "Invitation accepted"),
    ("user.2fa-enable", "Two-factor enabled"),
    ("user.2fa-disable", "Two-factor disabled"),
    ("user.2fa-recovery-regenerate", "Recovery codes regenerated"),
    ("user.2fa-reset", "Two-factor reset"),
    ("user.delete", "User deleted"),
];

/// `ConsoleAuditList::AREAS`: the dropdown's group per action prefix, in display order.
const AREAS: &[(&str, &str)] = &[
    ("user", "Users"),
    ("account", "Own account"),
    ("device", "Devices"),
    ("group", "Groups"),
    ("role", "Roles"),
    ("address-book", "Address books"),
    ("strategy", "Strategies"),
    ("session", "Sessions"),
    ("backup", "Backups"),
    ("client_download", "Client downloads"),
    ("api-token", "API tokens"),
    ("settings", "Settings"),
    ("setup", "Setup"),
    ("logs", "Logs"),
];

/// `groupedActions()`: group label to its (action, label) pairs, empty groups dropped.
fn action_groups() -> Vec<Value> {
    let mut groups: Vec<(String, Vec<(&str, &str)>)> = AREAS.iter().map(|(_, l)| (l.to_string(), vec![])).collect();
    for (action, label) in ACTIONS {
        let prefix = action.split('.').next().unwrap_or("");
        let area = AREAS.iter().find(|(p, _)| *p == prefix).map(|(_, l)| l.to_string()).unwrap_or_else(|| "Other".to_string());
        match groups.iter_mut().find(|(g, _)| *g == area) {
            Some((_, v)) => v.push((action, label)),
            None => groups.push((area, vec![(action, label)])),
        }
    }
    groups.into_iter().filter(|(_, v)| !v.is_empty()).map(|(g, v)| json!({"label": g, "actions": v.iter().map(|(a, l)| json!({"value": a, "label": l})).collect::<Vec<_>>()})).collect()
}

fn console_where(f: &Filters) -> Where {
    let mut w = Where::default();
    if !f.search.is_empty() {
        w.like_any(&["username", "summary"], &f.search);
    }
    // a known action matches exactly; anything else typed into the URL is a substring search
    if !f.action.is_empty() {
        if ACTIONS.iter().any(|(a, _)| *a == f.action) {
            w.add(r#""action" = ?"#, vec![P(Val::str(&f.action))]);
        } else {
            w.add(r#""action" like ?"#, vec![P(Val::str(&format!("%{}%", f.action)))]);
        }
    }
    dates(&mut w, f);
    w
}

pub fn console(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let f = Filters::from(req);
    let w = console_where(&f);
    let l = paginated(c, "console_audits", &w, &f)?;
    let layout = ctx.layout(c, "logs.console", "Console Audit", "Logs")?;
    let rows: Vec<Value> = l
        .rows
        .iter()
        .map(|r| {
            let mut v = row_json(r);
            let created = ts_of(r, "created_at");
            let username = s(r, "username");
            let m = v.as_object_mut().unwrap();
            m.insert("when".into(), json!(when_str(r)));
            m.insert("ago".into(), json!(created.map(|t| time::ago(t, ctx.now, false)).unwrap_or_default()));
            m.insert("ago_short".into(), json!(created.map(|t| time::ago(t, ctx.now, true)).unwrap_or_default()));
            m.insert("initial".into(), json!(if falsy(&username) { "?".to_string() } else { username.chars().next().map(|c| c.to_uppercase().collect()).unwrap_or_default() }));
            m.insert("has_target".into(), json!(!falsy(&s(r, "target_type")) || !falsy(&s(r, "target_id"))));
            m.insert("target_dash".into(), json!(dash(&s(r, "target_id"))));
            m.insert("ip_dash".into(), json!(dash(&s(r, "ip"))));
            m.insert("target_type_dash".into(), json!(if falsy(&s(r, "target_type")) { "—".to_string() } else { s(r, "target_type") }));
            v
        })
        .collect();
    let page = json!({
        "path": "/logs/console",
        "filters": {"search": f.search, "action": f.action, "dateFrom": f.date_from, "dateTo": f.date_to, "perPage": f.per_page},
        "query": f.query(false, true),
        "action_groups": action_groups(),
        "rows": rows,
        "pager": l.page,
    });
    let _ = val_json;
    Ok(Reply::Html(200, ctx.render("logs/console.html", layout, page)?))
}

pub fn console_export(_ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let f = Filters::from(req);
    let rows = export_rows(c, "console_audits", &console_where(&f))?;
    Ok(csv(
        "console-audit.csv",
        &["When", "Operator", "Action", "Target Type", "Target", "Details", "IP"],
        rows.iter().map(|r| vec![when_str(r), s(r, "username"), s(r, "action"), s(r, "target_type"), s(r, "target_id"), s(r, "summary"), s(r, "ip")]).collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fputcsv_like_php() {
        assert_eq!(fputcsv_field("plain"), "plain");
        assert_eq!(fputcsv_field("two words"), "\"two words\"");
        assert_eq!(fputcsv_field("a,b"), "\"a,b\"");
        assert_eq!(fputcsv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(fputcsv_field("2025-10-09 08:53:20"), "\"2025-10-09 08:53:20\"");
        // an escape character in front of a quote keeps it from being doubled
        assert_eq!(fputcsv_field("a\\\"b"), "\"a\\\"b\"");
        assert_eq!(csv_line(&["=SUM(A1)".into(), "ok".into()]), "'=SUM(A1),ok\n");
        assert_eq!(csv_line(&["".into(), "x".into()]), ",x\n");
    }

    #[test]
    fn alarm_info_the_way_the_model_reads_it() {
        assert_eq!(info_pairs(br#"{"ip":"1.2.3.4","n":3,"ok":true,"no":false,"x":null,"l":[1,2],"f":1.5}"#), vec![
            ("ip".to_string(), "1.2.3.4".to_string()),
            ("n".to_string(), "3".to_string()),
            ("ok".to_string(), "1".to_string()),
            ("no".to_string(), "".to_string()),
            ("x".to_string(), "null".to_string()),
            ("l".to_string(), "[1,2]".to_string()),
            ("f".to_string(), "1.5".to_string()),
        ]);
        assert!(info_pairs(b"not json").is_empty());
        assert!(info_pairs(b"\"just a string\"").is_empty());
        assert!(info_pairs(b"").is_empty());
        assert_eq!(alarm_label(102), "Session refused: outside the person's access");
        assert_eq!(alarm_label(55), "Type 55");
        assert_eq!(alarm_severity(55), "secondary");
    }

    #[test]
    fn file_transfer_labels() {
        let info = br#"{"files":[["a.pdf",10],["b.txt",5],["c.png",1]]}"#;
        assert_eq!(file_names(info), vec!["a.pdf", "b.txt", "c.png"]);
        assert_eq!(path_label("/tmp/x", info, 3), "/tmp/x");
        assert_eq!(path_label("", info, 3), "a.pdf, b.txt +1 more");
        assert_eq!(path_label("", info, 9), "a.pdf, b.txt +7 more");
        assert_eq!(path_label("", br#"{"files":[["a.pdf",10]]}"#, 1), "a.pdf");
        assert_eq!(path_label("", br#"{"files":[["",10]]}"#, 1), "");
        assert_eq!(path_label("", b"", 0), "");
    }

    #[test]
    fn the_action_dropdown_groups() {
        let g = action_groups();
        assert_eq!(g[0]["label"], "Users");
        assert_eq!(g.iter().map(|x| x["label"].as_str().unwrap()).collect::<Vec<_>>(), vec!["Users", "Own account", "Devices", "Groups", "Roles", "Address books", "Strategies", "Sessions", "Backups", "Client downloads", "API tokens", "Settings", "Setup", "Logs"]);
    }
}
