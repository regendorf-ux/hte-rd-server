//! What the phase 7b pages (devices, users, groups, address books, strategies, dashboard, settings) share: reading a
//! row as the previous console would echo it, the audit line every write leaves, the device scope, form input as the previous console's properties
//! held it, and a where-clause builder.

use super::{time, Ctx, Req};
use crate::laravel::Cast;
use crate::php::{self, Arr, Fault, Key, Val};
use crate::sqlite::{self as db, Row, P};
use rusqlite::Connection;
use serde_json::{json, Value};

pub fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// A cell as the previous console echoes it: null is empty.
pub fn s(r: &Row, col: &str) -> String {
    lossy(&r.val(col).to_php_string().unwrap_or_default())
}

pub fn opt(r: &Row, col: &str) -> Option<String> {
    if r.is_null(col) {
        None
    } else {
        Some(s(r, col))
    }
}

/// The previous console truthiness of a string (`$x ?: '—'`).
pub fn truthy(v: &str) -> bool {
    !v.is_empty() && v != "0"
}

pub fn dash(v: &str) -> String {
    if truthy(v) {
        v.to_string()
    } else {
        "—".to_string()
    }
}

pub fn ts_of(r: &Row, col: &str) -> Option<i64> {
    crate::laravel::parse_ts(&r.val(col))
}

/// `$model->col?->format('Y-m-d')`
pub fn ymd(r: &Row, col: &str) -> Option<String> {
    ts_of(r, col).map(|t| crate::laravel::ts(t)[..10].to_string())
}

/// `$model->col?->diffForHumans()`
pub fn human(r: &Row, col: &str, now: i64, short: bool) -> Option<String> {
    ts_of(r, col).map(|t| time::ago(t, now, short))
}

/// `Str::limit($value, $limit)` (the default `...`).
pub fn limit(value: &str, n: usize) -> String {
    crate::validate::str_limit(value, n, "...")
}

pub fn plural(word: &str, n: i64) -> String {
    if n == 1 {
        word.to_string()
    } else {
        match word {
            "entry" => "entries".into(),
            "person" => "people".into(),
            _ => format!("{word}s"),
        }
    }
}

/// A form field exactly as typed: no trimming, no empty-to-null (the previous console's properties).
pub struct Body {
    pub a: Arr,
}

impl Body {
    pub fn of(req: &Req) -> Body {
        Body { a: php::parse_str(&req.input.raw) }
    }

    pub fn has(&self, k: &str) -> bool {
        self.a.get_str(k).is_some()
    }

    pub fn get(&self, k: &str) -> String {
        match self.a.get_str(k) {
            Some(Val::Str(b)) => lossy(b),
            Some(Val::Int(i)) => i.to_string(),
            _ => String::new(),
        }
    }

    pub fn val(&self, k: &str) -> Val {
        Val::str(&self.get(k))
    }

    /// `(int) $property`
    pub fn int(&self, k: &str) -> i64 {
        php::str_to_int(self.get(k).as_bytes())
    }

    /// A checkbox: present and not "0"
    pub fn checked(&self, k: &str) -> bool {
        match self.a.get_str(k) {
            Some(Val::Str(b)) => b.as_slice() != b"0" && !b.is_empty(),
            Some(Val::Int(i)) => *i != 0,
            Some(Val::Arr(_)) => true,
            _ => false,
        }
    }

    /// `name[]=a&name[]=b` as strings, in order.
    pub fn list(&self, k: &str) -> Vec<String> {
        match self.a.get_str(k) {
            Some(Val::Arr(a)) => a.iter().filter_map(|(_, v)| if let Val::Str(b) = v { Some(lossy(b)) } else { None }).collect(),
            Some(Val::Str(b)) => vec![lossy(b)],
            _ => vec![],
        }
    }

    pub fn ints(&self, k: &str) -> Vec<i64> {
        self.list(k).iter().map(|v| php::str_to_int(v.as_bytes())).collect()
    }

    pub fn data(&self, keys: &[(&str, &str)]) -> Arr {
        let mut a = Arr::new();
        for (field, key) in keys {
            a.set(Key::Str(field.as_bytes().to_vec()), Val::str(&self.get(key)));
        }
        a
    }
}

/// A query-string value as text (`?search=` and the like).
pub fn q(req: &Req, key: &str) -> String {
    req.input.string(key).map(|b| lossy(&b)).unwrap_or_default()
}

pub fn qint(req: &Req, key: &str) -> i64 {
    php::str_to_int(q(req, key).as_bytes())
}

/// The last path segment(s) as an id: `/devices/12/note` with `idx` 1 gives 12.
pub fn path_id(path: &str, idx: usize) -> i64 {
    path.trim_matches('/').split('/').nth(idx).and_then(|v| v.parse::<i64>().ok()).unwrap_or(0)
}

/// `ConsoleAudit::record(...)` for the signed-in person.
pub fn audit(ctx: &Ctx, c: &Connection, action: &str, summary: &str, target_type: Option<&str>, target_id: Option<&str>) -> Result<(), Fault> {
    let text = |t: Option<&str>| t.map_or(Val::Null, Val::str);
    db::exec(
        c,
        r#"insert into "console_audits" ("user_id", "username", "action", "target_type", "target_id", "summary", "ip", "created_at") values (?, ?, ?, ?, ?, ?, ?, ?)"#,
        &[
            P(ctx.user.val("id")),
            P(ctx.user.val("username")),
            P(Val::str(action)),
            P(text(target_type)),
            P(text(target_id)),
            P(Val::str(&crate::validate::str_limit(summary, 250, "..."))),
            P(Val::str(&ctx.ip)),
            P(Val::str(&crate::laravel::ts(ctx.now))),
        ],
    )?;
    Ok(())
}

pub fn marks(n: usize) -> String {
    vec!["?"; n].join(", ")
}

pub fn ints_val(ids: &[i64]) -> Vec<P> {
    ids.iter().map(|i| P(Val::Int(*i))).collect()
}

/// A where clause under construction: fragments joined with `and`, values bound in order.
#[derive(Default)]
pub struct Where {
    pub parts: Vec<String>,
    pub params: Vec<P>,
}

impl Where {
    pub fn add(&mut self, sql: &str, params: Vec<P>) {
        self.parts.push(sql.to_string());
        self.params.extend(params);
    }

    /// `->whereIn(col, $ids)`; an empty list is Laravel's `0 = 1`.
    pub fn in_ints(&mut self, col: &str, ids: &[i64]) {
        if ids.is_empty() {
            self.add("0 = 1", vec![]);
        } else {
            self.add(&format!(r#"{col} in ({})"#, marks(ids.len())), ints_val(ids));
        }
    }

    pub fn sql(&self) -> String {
        if self.parts.is_empty() {
            String::new()
        } else {
            format!(" where {}", self.parts.join(" and "))
        }
    }
}

/// `Device::query()->ownershipVisibleTo($user)`: the person's owner/group half of the rule.
pub fn ownership(c: &Connection, user: &Row, w: &mut Where) -> Result<(), Fault> {
    if user.val("is_admin").to_bool() {
        return Ok(());
    }
    let groups = crate::reach::accessible_device_group_ids(c, user)?;
    let mut sql = String::from(r#"("devices"."user_id" = ?"#);
    let mut params = vec![P(user.val("id"))];
    if !groups.is_empty() {
        sql.push_str(&format!(r#" or "devices"."device_group_id" in ({})"#, marks(groups.len())));
        params.extend(ints_val(&groups));
    }
    sql.push(')');
    w.add(&sql, params);
    Ok(())
}

/// `Device::query()->visibleTo($user)`: ownership, approved, and (unless `trashed`) not in the recycle bin.
pub fn visible(c: &Connection, user: &Row, trashed: bool) -> Result<Where, Fault> {
    let mut w = Where::default();
    ownership(c, user, &mut w)?;
    if trashed {
        // the recycle bin (`visibleWithTrashed` + `onlyTrashed`, CortenDesk 1.21.0): a rejected device is soft-deleted but keeps
        // status 'pending', and held its unique ID while the bin hid it
        w.add(r#""devices"."deleted_at" is not null"#, vec![]);
    } else {
        w.add(r#""devices"."status" = ?"#, vec![P(Val::str("active"))]);
        w.add(r#""devices"."deleted_at" is null"#, vec![]);
    }
    Ok(w)
}

/// `Device::visibleWithTrashed($user)`: visibleTo, plus soft-deleted rows whatever their status (rejecting a pending
/// device soft-deletes it and leaves it `pending`, so plain visibleTo hid it from the recycle bin).
pub fn visible_with_trashed(c: &Connection, user: &Row) -> Result<Where, Fault> {
    let mut w = Where::default();
    ownership(c, user, &mut w)?;
    w.add(r#"("devices"."status" = 'active' or "devices"."deleted_at" is not null)"#, vec![]);
    Ok(w)
}

/// `Device::onlineWindow()`
pub fn online_window(c: &Connection) -> Result<i64, Fault> {
    let default = crate::envvar::var("HTE_REMOTE_ONLINE_WINDOW").ok().filter(|v| !v.is_empty()).unwrap_or_else(|| "60".into());
    let v = db::setting(c, "online_window", &default)?;
    Ok(if v.is_empty() || v == b"0" { 60 } else { php::str_to_int(&v) })
}

/// `$device->isOnline()`
pub fn is_online(d: &Row, now: i64, window: i64) -> bool {
    ts_of(d, "last_online_at").map_or(false, |t| t > now - window)
}

pub fn count(c: &Connection, sql: &str, params: &[P]) -> Result<i64, Fault> {
    Ok(db::first(c, sql, params)?.map(|r| r.val("aggregate").to_int()).unwrap_or(0))
}

/// `Model::find($id)` (no soft-delete handling: callers add their own condition).
pub fn find(c: &Connection, table: &str, id: i64) -> Result<Option<Row>, Fault> {
    db::first(c, &format!(r#"select * from "{table}" where "id" = ? limit 1"#, ), &[P(Val::Int(id))])
}

/// Rows of `table` whose `col` is in `ids`, by id.
pub fn find_in(c: &Connection, table: &str, ids: &[i64]) -> Result<Vec<Row>, Fault> {
    if ids.is_empty() {
        return Ok(vec![]);
    }
    db::rows(c, &format!(r#"select * from "{table}" where "id" in ({})"#, marks(ids.len())), &ints_val(ids))
}

pub fn by_id<'a>(rows: &'a [Row], id: &Val) -> Option<&'a Row> {
    rows.iter().find(|r| r.val("id") == *id || (r.val("id").to_int() == id.to_int() && !matches!(id, Val::Null)))
}

/// The pivot `table` rows' `col` values for `where key = id`.
pub fn pivot_ids(c: &Connection, table: &str, key: &str, col: &str, id: i64) -> Result<Vec<i64>, Fault> {
    Ok(db::rows(c, &format!(r#"select "{col}" from "{table}" where "{key}" = ?"#), &[P(Val::Int(id))])?.iter().map(|r| r.val(col).to_int()).collect())
}

/// `$model->update([...])` on a row, with the dirty-check rule; returns the columns that changed.
pub fn update(c: &Connection, table: &str, row: &mut Row, changes: Vec<(&str, Val, Cast)>, now: i64) -> Result<Vec<String>, Fault> {
    let mut changed = vec![];
    for (col, v, cast) in &changes {
        if !crate::laravel::equivalent(*cast, v, row.get(col))? {
            changed.push(col.to_string());
        }
    }
    db::update_dirty(c, table, row, changes, &crate::laravel::ts(now))?;
    Ok(changed)
}

/// `Strategy::assignTo($level, $targetId, $strategyId)`.
pub fn strategy_assign(c: &Connection, level: &str, target: i64, strategy: Option<i64>, now: i64) -> Result<(), Fault> {
    let (table, column) = match level {
        "device" => ("device_strategy", "device_id"),
        "user" => ("strategy_user", "user_id"),
        _ => ("device_group_strategy", "device_group_id"),
    };
    db::exec(c, &format!(r#"delete from "{table}" where "{column}" = ?"#), &[P(Val::Int(target))])?;
    if let Some(s) = strategy {
        db::exec(c, &format!(r#"insert into "{table}" ("{column}", "strategy_id") values (?, ?)"#), &[P(Val::Int(target)), P(Val::Int(s))])?;
    }
    recompute_level(c, level, target, now)
}

/// `Strategy::recomputeForLevel`: every device the change can reach (trashed ones too), in chunks of 500 by id.
pub fn recompute_level(c: &Connection, level: &str, target: i64, now: i64) -> Result<(), Fault> {
    let cond = match level {
        "device" => r#""id" = ?"#,
        "user" => r#""user_id" = ?"#,
        _ => r#""device_group_id" = ?"#,
    };
    let ts = crate::laravel::ts(now);
    let mut last = 0i64;
    loop {
        let rows = db::rows(c, &format!(r#"select * from "devices" where {cond} and "id" > ? order by "id" asc limit 500"#), &[P(Val::Int(target)), P(Val::Int(last))])?;
        if rows.is_empty() {
            return Ok(());
        }
        for mut d in rows {
            last = d.id();
            crate::strategy::sync_resolved_for(c, &mut d, &ts)?;
        }
    }
}

/// `Strategy::recomputeAll()`
pub fn recompute_all(c: &Connection, now: i64) -> Result<(), Fault> {
    let ts = crate::laravel::ts(now);
    let mut last = 0i64;
    loop {
        let rows = db::rows(c, r#"select * from "devices" where "id" > ? order by "id" asc limit 500"#, &[P(Val::Int(last))])?;
        if rows.is_empty() {
            return Ok(());
        }
        for mut d in rows {
            last = d.id();
            crate::strategy::sync_resolved_for(c, &mut d, &ts)?;
        }
    }
}

/// The messages of a failed `validate_db` body, first per field: `{field: message}`.
pub fn first_messages(body: &str) -> serde_json::Map<String, Value> {
    let mut out = serde_json::Map::new();
    if let Ok(v) = serde_json::from_str::<Value>(body) {
        if let Some(errors) = v.get("errors").and_then(|e| e.as_object()) {
            for (k, list) in errors {
                if let Some(m) = list.get(0).and_then(|m| m.as_str()) {
                    out.insert(k.clone(), json!(m));
                }
            }
        }
    }
    out
}

/// `Rule::unique(table, column)->ignore(id)` and `exists`, answered from the database.
pub fn probe(c: &Connection, rule: &crate::validate::Rule, v: &Val) -> Result<bool, Fault> {
    use crate::validate::Rule;
    match rule {
        Rule::Unique(table, col, ignore) => {
            let mut sql = format!(r#"select count(*) as aggregate from "{table}" where "{col}" = ?"#);
            let mut p = vec![P(v.clone())];
            if let Some(id) = ignore {
                sql.push_str(r#" and "id" <> ?"#);
                p.push(P(Val::Int(*id)));
            }
            Ok(count(c, &sql, &p)? == 0)
        }
        Rule::Exists(table, col) => Ok(count(c, &format!(r#"select count(*) as aggregate from "{table}" where "{col}" = ?"#), &[P(v.clone())])? > 0),
        _ => Ok(true),
    }
}

/// The platform's icon, colour class and label (`<x-platform-icon>`).
pub fn platform_ui(platform: &str) -> Value {
    let p = platform.to_lowercase().replace(' ', "");
    let p = if p.is_empty() { "unknown".to_string() } else if p == "macos" || p == "mac" { "macos".to_string() } else { p };
    let (icon, color) = match p.as_str() {
        "windows" => ("ri-windows-fill", "text-info"),
        "macos" => ("ri-apple-fill", "text-body"),
        "linux" => ("ri-ubuntu-fill", "text-warning"),
        "android" => ("ri-android-fill", "text-success"),
        "ios" => ("ri-apple-line", "text-body"),
        _ => ("ri-question-line", "text-muted"),
    };
    let label = match p.as_str() {
        "windows" => "Windows",
        "macos" => "macOS",
        "linux" => "Linux",
        "android" => "Android",
        "ios" => "iOS",
        _ => "Unknown",
    };
    json!({"icon": icon, "color": color, "label": label})
}

/// `rawurlencode`
pub fn rawurlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `ClientLink::to($id)`
pub fn client_link(c: &Connection, id: &str) -> Result<String, Fault> {
    let raw = db::setting(c, "client_url_scheme", &crate::envvar::var("HTE_REMOTE_CLIENT_URL_SCHEME").unwrap_or_default())?;
    let first = lossy(&raw);
    let scheme = first.trim().split(':').next().unwrap_or("").trim().to_lowercase();
    let ok = !scheme.is_empty()
        && scheme.chars().next().map_or(false, |c| c.is_ascii_lowercase())
        && scheme.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '+' | '.' | '-'));
    Ok(format!("{}://connection/new/{}", if ok { scheme } else { "rustdesk".into() }, rawurlencode(id)))
}

/// `abort(403)` / `abort(404)`: Laravel's error page.
pub fn abort(status: u16) -> super::Reply {
    let text = match status {
        403 => "Forbidden",
        404 => "Not Found",
        419 => "Page Expired",
        _ => "Server Error",
    };
    super::Reply::Html(status, crate::signin::error_page(status, text))
}

/// `User::userGroupIds()`
pub fn user_group_ids(c: &Connection, user_id: i64) -> Result<Vec<i64>, Fault> {
    Ok(db::rows(
        c,
        r#"select "user_groups"."id" from "user_groups" inner join "user_group_user" on "user_groups"."id" = "user_group_user"."user_group_id" where "user_group_user"."user_id" = ?"#,
        &[P(Val::Int(user_id))],
    )?
    .iter()
    .map(|r| r.val("id").to_int())
    .collect())
}

pub const PERM_READ: i64 = 1;
pub const PERM_READ_WRITE: i64 = 2;
pub const PERM_FULL: i64 = 3;

/// `AddressBook::permissionFor($user, $groupIds)`: 0 none, 1 read, 2 read/write, 3 full.
pub fn book_permission(c: &Connection, user: &Row, book: &Row, groups: Option<&[i64]>) -> Result<i64, Fault> {
    let uid = user.id();
    let admin = user.val("is_admin").to_bool();
    let owner = book.val("owner_user_id").to_int() == uid && !book.is_null("owner_user_id");
    if book.val("is_personal").to_bool() {
        if owner {
            return Ok(PERM_FULL);
        }
        if !admin {
            return Ok(0);
        }
        let orphan = find(c, "users", book.val("owner_user_id").to_int())?.is_none() || book.is_null("owner_user_id");
        return Ok(if orphan { PERM_FULL } else { 0 });
    }
    if owner || admin {
        return Ok(PERM_FULL);
    }
    let groups = match groups {
        Some(g) => g.to_vec(),
        None => user_group_ids(c, uid)?,
    };
    let rules = db::rows(c, r#"select * from "address_book_rules" where "address_book_id" = ?"#, &[P(book.val("id"))])?;
    let mut best = 0;
    for rule in rules {
        let hit = match s(&rule, "subject_type").as_str() {
            "everyone" => true,
            "user" => rule.val("subject_id").to_int() == uid,
            "group" => groups.contains(&rule.val("subject_id").to_int()),
            _ => false,
        };
        if hit {
            best = best.max(rule.val("permission").to_int());
        }
    }
    Ok(best)
}

/// `DeviceAddressBooks::writableBooks($user)`: the personal book first, then by name, where the tier is read-write or more.
pub fn writable_books(ctx: &Ctx, c: &Connection) -> Result<Vec<Row>, Fault> {
    if !ctx.allows("address_book", "rw") {
        return Ok(vec![]);
    }
    let groups = if ctx.is_admin() { vec![] } else { user_group_ids(c, ctx.uid())? };
    let books = db::rows(c, r#"select * from "address_books" order by "is_personal" desc, "name" asc"#, &[])?;
    let mut out = vec![];
    for b in books {
        if book_permission(c, &ctx.user, &b, Some(&groups))? >= PERM_READ_WRITE {
            out.push(b);
        }
    }
    Ok(out)
}

/// `AddressBook::personalFor($user)`: `firstOrCreate`.
pub fn personal_book(ctx: &Ctx, c: &Connection) -> Result<Row, Fault> {
    if let Some(b) = db::first(c, r#"select * from "address_books" where "owner_user_id" = ? and "is_personal" = ? limit 1"#, &[P(Val::Int(ctx.uid())), P(Val::Bool(true))])? {
        return Ok(b);
    }
    let id = db::insert(
        c,
        "address_books",
        vec![("owner_user_id", Val::Int(ctx.uid())), ("is_personal", Val::Bool(true)), ("name", Val::str("My address book")), ("guid", Val::str(&crate::laravel::uuid4()))],
        &crate::laravel::ts(ctx.now),
    )?;
    find(c, "address_books", id)?.ok_or_else(|| Fault::Other("inserted address book vanished".into()))
}

/// `DeviceAddressBooks::entryCount($rustdeskIds)`
pub fn entry_count(c: &Connection, ids: &[String]) -> Result<i64, Fault> {
    if ids.is_empty() {
        return Ok(0);
    }
    count(c, &format!(r#"select count(*) as aggregate from "address_book_entries" where "rustdesk_id" in ({})"#, marks(ids.len())), &ids.iter().map(|i| P(Val::str(i))).collect::<Vec<_>>())
}

/// `DeviceAddressBooks::entryAttributes($device)`: the columns a device carries into a book.
pub fn entry_columns(d: &Row) -> Vec<(&'static str, Val)> {
    let nullable = |v: String| if truthy(&v) { Val::str(&v) } else { Val::Null };
    vec![
        ("rustdesk_id", d.val("rustdesk_id")),
        ("alias", nullable(s(d, "alias"))),
        ("hostname", nullable(s(d, "hostname"))),
        ("platform", Val::str(crate::passwords_sweep::rustdesk_platform(&d.val("os")))),
        ("username", nullable(s(d, "username"))),
        ("tag_ids", Val::str("[]")),
    ]
}

/// `DeviceAddressBooks::remove($rustdeskIds, $actor)`: (removed, kept, books).
pub fn remove_from_books(ctx: &Ctx, c: &Connection, ids: &[String], source: &str) -> Result<(i64, i64, i64), Fault> {
    let (mut removed, mut kept, mut touched) = (0, 0, 0);
    if ids.is_empty() {
        return Ok((0, 0, 0));
    }
    let groups = if ctx.is_admin() { vec![] } else { user_group_ids(c, ctx.uid())? };
    let entries = db::rows(c, &format!(r#"select * from "address_book_entries" where "rustdesk_id" in ({})"#, marks(ids.len())), &ids.iter().map(|i| P(Val::str(i))).collect::<Vec<_>>())?;
    let mut order: Vec<i64> = vec![];
    for e in &entries {
        let b = e.val("address_book_id").to_int();
        if !order.contains(&b) {
            order.push(b);
        }
    }
    for book_id in order {
        let mine: Vec<&Row> = entries.iter().filter(|e| e.val("address_book_id").to_int() == book_id).collect();
        let book = find(c, "address_books", book_id)?;
        let allowed = match &book {
            Some(b) => ctx.allows("address_book", "rw") && book_permission(c, &ctx.user, b, Some(&groups))? >= PERM_READ_WRITE,
            None => false,
        };
        let Some(book) = book.filter(|_| allowed) else {
            kept += mine.len() as i64;
            continue;
        };
        let entry_ids: Vec<i64> = mine.iter().map(|e| e.id()).collect();
        db::exec(c, &format!(r#"delete from "address_book_entries" where "id" in ({})"#, marks(entry_ids.len())), &ints_val(&entry_ids))?;
        let n = mine.len() as i64;
        removed += n;
        touched += 1;
        let mut names: Vec<String> = vec![];
        for e in &mine {
            let r = s(e, "rustdesk_id");
            if !names.contains(&r) {
                names.push(r);
            }
        }
        let name = s(&book, "name");
        audit(
            ctx,
            c,
            "address-book.peer-delete",
            &format!("Removed {n} {} ({}) from address book {name} after device delete{source}", plural("entry", n), names.join(", ")),
            Some("address-book"),
            Some(&name),
        )?;
    }
    Ok((removed, kept, touched))
}

/// `DeviceAddressBooks::summary($result)`
pub fn removal_summary(removed: i64, kept: i64) -> String {
    let mut text = format!("Removed {removed} address-book {}.", plural("entry", removed));
    if kept > 0 {
        text.push_str(&format!(" {kept} kept in books you cannot edit."));
    }
    text
}

/// `BelongsToMany::sync($ids)`: detach what is no longer wanted, then attach the missing ones in order.
pub fn sync_pivot(c: &Connection, table: &str, key: &str, key_id: i64, other: &str, ids: &[i64]) -> Result<(), Fault> {
    let current = pivot_ids(c, table, key, other, key_id)?;
    let gone: Vec<i64> = current.iter().copied().filter(|i| !ids.contains(i)).collect();
    if !gone.is_empty() {
        let mut params = vec![P(Val::Int(key_id))];
        params.extend(ints_val(&gone));
        db::exec(c, &format!(r#"delete from "{table}" where "{key}" = ? and "{other}" in ({})"#, marks(gone.len())), &params)?;
    }
    let mut added: Vec<i64> = vec![];
    for i in ids {
        if !current.contains(i) && !added.contains(i) {
            added.push(*i);
        }
    }
    for i in added {
        db::exec(c, &format!(r#"insert into "{table}" ("{key}", "{other}") values (?, ?)"#), &[P(Val::Int(key_id)), P(Val::Int(i))])?;
    }
    Ok(())
}

/// `User::revokeAllAccess()`: client tokens, console sessions and trusted browsers go, the remember token rotates.
pub fn revoke_all_access(c: &Connection, user: &mut Row, now: i64) -> Result<(), Fault> {
    let id = user.val("id");
    db::exec(c, r#"delete from "client_tokens" where "client_tokens"."user_id" = ? and "client_tokens"."user_id" is not null"#, &[P(id.clone())])?;
    db::exec(c, r#"delete from "sessions" where "user_id" = ?"#, &[P(id.clone())])?;
    db::exec(c, r#"delete from "trusted_devices" where "user_id" = ?"#, &[P(id)])?;
    update(c, "users", user, vec![("remember_token", Val::str(&crate::laravel::str_random(60)), Cast::Plain)], now)?;
    Ok(())
}

/// A personal address book's contents and the book itself (`User::deleting`, `AddressBook` delete).
pub fn delete_book_rows(c: &Connection, id: i64) -> Result<(), Fault> {
    let b = [P(Val::Int(id))];
    db::exec(c, r#"delete from "address_book_entries" where "address_book_entries"."address_book_id" = ? and "address_book_entries"."address_book_id" is not null"#, &b)?;
    db::exec(c, r#"delete from "tags" where "tags"."address_book_id" = ? and "tags"."address_book_id" is not null"#, &b)?;
    db::exec(c, r#"delete from "address_book_rules" where "address_book_rules"."address_book_id" = ? and "address_book_rules"."address_book_id" is not null"#, &b)?;
    db::exec(c, r#"delete from "address_books" where "id" = ?"#, &b)?;
    Ok(())
}

/// `grantableDeviceGroupIds($ids)`: what the actor can see themselves (an administrator is unclamped).
pub fn grantable_device_group_ids(ctx: &Ctx, c: &Connection, ids: &[i64]) -> Result<Vec<i64>, Fault> {
    let mut out: Vec<i64> = vec![];
    for i in ids {
        if !out.contains(i) {
            out.push(*i);
        }
    }
    if ctx.is_admin() {
        return Ok(out);
    }
    let own = crate::reach::accessible_device_group_ids(c, &ctx.user)?;
    Ok(out.into_iter().filter(|i| own.contains(i)).collect())
}

/// `UserGroup::grantedDeviceGroupIds()`
pub fn granted_device_group_ids(c: &Connection, group: i64) -> Result<Vec<i64>, Fault> {
    let mut out = pivot_ids(c, "device_group_user_group", "user_group_id", "device_group_id", group)?;
    for r in db::rows(c, r#"select "target_id" from "group_accesses" where "target_type" = ? and "accessor_type" = ? and "accessor_id" = ?"#, &[P(Val::str("device_group")), P(Val::str("user_group")), P(Val::Int(group))])? {
        let t = r.val("target_id").to_int();
        if !out.contains(&t) {
            out.push(t);
        }
    }
    Ok(out)
}

/// `grantableUserGroupIds($ids)`: groups whose grants the actor could hand out themselves.
pub fn grantable_user_group_ids(ctx: &Ctx, c: &Connection, ids: &[i64]) -> Result<Vec<i64>, Fault> {
    let mut out: Vec<i64> = vec![];
    for i in ids {
        if !out.contains(i) {
            out.push(*i);
        }
    }
    if ctx.is_admin() || out.is_empty() {
        return Ok(out);
    }
    let allowed = crate::reach::accessible_device_group_ids(c, &ctx.user)?;
    let mut keep = vec![];
    for g in find_in(c, "user_groups", &out)? {
        if granted_device_group_ids(c, g.id())?.iter().all(|d| allowed.contains(d)) {
            keep.push(g.id());
        }
    }
    Ok(keep)
}

/// `grantableDeviceGroups()`: the picker's rows.
pub fn grantable_device_groups(ctx: &Ctx, c: &Connection) -> Result<Vec<Row>, Fault> {
    if ctx.is_admin() {
        return db::rows(c, r#"select * from "device_groups" order by "name" asc"#, &[]);
    }
    let mut ids = crate::reach::accessible_device_group_ids(c, &ctx.user)?;
    if ids.is_empty() {
        ids = vec![0];
    }
    db::rows(c, &format!(r#"select * from "device_groups" where "id" in ({}) order by "name" asc"#, marks(ids.len())), &ints_val(&ids))
}

/// `grantableUserGroups()`
pub fn grantable_user_groups(ctx: &Ctx, c: &Connection) -> Result<Vec<Row>, Fault> {
    let all = db::rows(c, r#"select * from "user_groups" order by "name" asc"#, &[])?;
    if ctx.is_admin() {
        return Ok(all);
    }
    let ids: Vec<i64> = all.iter().map(|g| g.id()).collect();
    let ok = grantable_user_group_ids(ctx, c, &ids)?;
    Ok(all.into_iter().filter(|g| ok.contains(&g.id())).collect())
}

/// `$user->displayName()`
pub fn display_name(u: &Row) -> String {
    let n = s(u, "name");
    if n.is_empty() || n == "0" { s(u, "username") } else { n }
}

/// A user-supplied id list to a validator array value (the previous console's page components sends integers).
pub fn int_array(ids: &[i64]) -> Val {
    let mut a = Arr::new();
    for i in ids {
        a.push(Val::Int(*i));
    }
    Val::Arr(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_links_are_encoded() {
        assert_eq!(rawurlencode("a b/ç"), "a%20b%2F%C3%A7");
    }

    #[test]
    fn plurals_the_way_the_views_use_them() {
        assert_eq!(plural("device", 1), "device");
        assert_eq!(plural("device", 2), "devices");
        assert_eq!(plural("entry", 3), "entries");
    }
}
