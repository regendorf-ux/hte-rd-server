//! Strategies (the previous console's `StrategyList`): named client-option policies, their editor with the impact review that
//! precedes every write, assignments, the immutable revision history, and the fleet compliance view.
//!
//! State is the URL (`?create=1`, `?edit=`, `?delete=`, `?assign=`, `?history=`, `?compliance=`). The previous console's page components kept the
//! reviewed change on the server between the review and the Apply; here the review page carries the proposal as hidden
//! fields together with a fingerprint of the proposal and of everything the impact depends on (every strategy, every
//! assignment, every active device's owner, group and resolved strategy). Apply recomputes the fingerprint and refuses
//! a change that no longer matches what was reviewed, exactly as `confirmSave` does.

use super::kit::*;
use super::{Ctx, Reply, Req};
use crate::laravel::Cast;
use crate::php::{self, Arr, Fault, Key, Val};
use crate::sqlite::{self as db, Row, P};
use crate::strategy as engine;
use rusqlite::Connection;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

// ------------------------------------------------------------------------------------------------ catalogue ---

#[derive(Clone, Copy)]
enum K {
    Bool,
    Enum(&'static [(&'static str, &'static str)]),
    Int(i64, i64),
    Text,
    Ice,
}

struct O {
    key: &'static str,
    group: &'static str,
    kind: K,
    label: &'static str,
    help: &'static str,
}

const fn o(key: &'static str, group: &'static str, kind: K, label: &'static str, help: &'static str) -> O {
    O { key, group, kind, label, help }
}

/// `Strategy::OPTION_KEYS` in order, decorated with `StrategyList::OPTION_META`.
const OPTS: &[O] = &[
    o("access-mode", "permissions", K::Enum(&[("full", "Full access"), ("view", "View only"), ("custom", "Custom (use the controls below)")]), "Access mode", "Master switch. \"Full\" forces every permission below on and \"View only\" forces them all off, whatever the individual controls say. Desktop only — ignored by the Android and iOS clients."),
    o("enable-keyboard", "permissions", K::Bool, "Keyboard & mouse", ""),
    o("enable-clipboard", "permissions", K::Bool, "Clipboard", ""),
    o("enable-file-transfer", "permissions", K::Bool, "File transfer", ""),
    o("enable-audio", "permissions", K::Bool, "Audio", ""),
    o("enable-camera", "permissions", K::Bool, "Camera", ""),
    o("enable-terminal", "permissions", K::Bool, "Terminal", ""),
    o("enable-tunnel", "permissions", K::Bool, "TCP tunnelling", ""),
    o("enable-remote-restart", "permissions", K::Bool, "Remote restart", ""),
    o("enable-record-session", "permissions", K::Bool, "Session recording", "Whether the connecting side is permitted to record."),
    o("enable-block-input", "permissions", K::Bool, "Block local input", "Windows only in the client UI."),
    o("enable-privacy-mode", "permissions", K::Bool, "Privacy mode", ""),
    o("enable-remote-printer", "permissions", K::Bool, "Remote printing", "Windows only. Re-checked per print job, so it takes effect mid-session."),
    o("verification-method", "security", K::Enum(&[("use-temporary-password", "One-time password only"), ("use-permanent-password", "Permanent password only"), ("use-both-passwords", "Either password")]), "Password type", ""),
    o("approve-mode", "security", K::Enum(&[("password", "Password only"), ("click", "Accept on the device only"), ("password-click", "Password or accept on the device")]), "How connections are approved", ""),
    o("temporary-password-length", "security", K::Enum(&[("6", "6 characters"), ("8", "8 characters"), ("10", "10 characters")]), "One-time password length", "Applies the next time the password is regenerated, not immediately."),
    o("allow-numeric-one-time-password", "security", K::Bool, "Digits-only one-time password", "Applies at the next regeneration."),
    o("whitelist", "security", K::Text, "IP whitelist", "Comma-separated IPs or CIDRs that may connect; empty means allow all. Entries that do not parse simply never match, so a typo here can lock everyone out of the device."),
    o("direct-server", "security", K::Bool, "Accept direct IP connections", "Off: every session goes through the ID server, where per-person reach is checked. Keep it off on every device."),
    o("allow-only-conn-window-open", "security", K::Bool, "Only accept while the client window is open", "Desktop only."),
    o("enable-trusted-devices", "security", K::Bool, "Offer \"trust this device\" on 2FA", ""),
    o("allow-remote-config-modification", "security", K::Bool, "Enable remote configuration modification", "Lets the connecting side change this device's settings during a session."),
    o("allow-auto-disconnect", "security", K::Bool, "Disconnect idle sessions", ""),
    o("auto-disconnect-timeout", "security", K::Int(1, 1440), "Idle timeout (minutes)", "Only read when idle disconnect is on. 1–1440."),
    o("allow-scope-violation-alarm", "security", K::Bool, "Raise an alarm on an out-of-scope message", ""),
    o("allow-scope-violation-close", "security", K::Bool, "Close the session on an out-of-scope message", ""),
    o("enable-abr", "display", K::Bool, "Adaptive bitrate", ""),
    o("allow-remove-wallpaper", "display", K::Bool, "Remove the wallpaper during a session", "Windows and Linux."),
    o("allow-auto-record-incoming", "display", K::Bool, "Record incoming sessions automatically", ""),
    o("keep-awake-during-incoming-sessions", "display", K::Bool, "Keep the device awake during a session", ""),
    o("enable-lan-discovery", "display", K::Bool, "Answer LAN discovery", ""),
    o("allow-auto-update", "client", K::Bool, "Auto update", "Lets the client update itself. The client only exposes this on installed Windows, and on installed macOS that is not a custom build — elsewhere (Linux, portable installs, custom-branded builds) the toggle is hidden, so setting it here may have no visible effect."),
    o("ice-servers", "network", K::Ice, "WebRTC ICE servers", "Comma-separated STUN and TURN servers for WebRTC connections, e.g. stun:stun.example.com:3478, turn://user:password@turn.example.com:3478. Listing a STUN server replaces the client's built-in public ones; TURN alone keeps them. Every device in the strategy receives the TURN password. Needs RustDesk 1.5.0 or later."),
];

const GROUPS: &[(&str, &str, &str, &str)] = &[
    ("permissions", "Permissions", "ri-shield-keyhole-line", "What an incoming session may do. Applied when the next session is authorised — sessions already running keep the values they started with."),
    ("security", "Security & password", "ri-lock-password-line", "How the device authorises incoming connections. Most of these take effect within one heartbeat; the two password-shape options only apply the next time the one-time password is regenerated."),
    ("display", "Capture & display", "ri-macbook-line", "Screen capture and desktop behaviour during a session."),
    ("client", "Client & updates", "ri-refresh-line", "How the RustDesk client maintains itself. Unlike the groups above, these are not about an incoming session."),
    ("network", "Network", "ri-route-line", "How the client reaches other devices. Read at the start of each connection."),
];

fn catalog_json() -> Vec<Value> {
    GROUPS
        .iter()
        .map(|(g, title, icon, help)| {
            let options: Vec<Value> = OPTS
                .iter()
                .filter(|x| x.group == *g)
                .map(|x| {
                    let allow = x.key.starts_with("allow-");
                    let choices: Option<Vec<Value>> = match x.kind {
                        K::Bool => Some(vec![json!({"v": "Y", "l": if allow { "Allowed" } else { "Enabled" }}), json!({"v": "N", "l": if allow { "Not allowed" } else { "Disabled" }})]),
                        K::Enum(list) => Some(list.iter().map(|(v, l)| json!({"v": v, "l": l})).collect()),
                        _ => None,
                    };
                    json!({"key": x.key, "label": x.label, "help": x.help, "choices": choices})
                })
                .collect();
            json!({"key": g, "title": title, "icon": icon, "help": help, "options": options})
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------- the form ---

#[derive(Clone, Default)]
struct Form {
    id: i64,
    name: String,
    note: String,
    enabled: bool,
    is_default: bool,
    enforce: bool,
    timeout: String,
    revision_note: String,
    options: Vec<(String, String)>,
    delete_id: i64,
    restore_id: i64,
}

impl Form {
    fn blank() -> Form {
        Form { enabled: true, timeout: "15".into(), options: OPTS.iter().map(|x| (x.key.to_string(), String::new())).collect(), ..Default::default() }
    }

    fn of_strategy(s: &Row) -> Form {
        let map = option_map(s);
        let mut f = Form::blank();
        f.id = s.id();
        f.name = crate::pages::kit::s(s, "name");
        f.note = crate::pages::kit::s(s, "note");
        f.enabled = s.val("enabled").to_bool();
        f.is_default = s.val("is_default").to_bool();
        f.enforce = s.val("enforce").to_bool();
        let t = s.val("confirmation_timeout_minutes").to_int();
        f.timeout = (if t == 0 { 15 } else { t }).to_string();
        for (k, v) in &map {
            if let Some(slot) = f.options.iter_mut().find(|(ok, _)| ok.as_bytes() == k.as_slice()) {
                slot.1 = lossy(v);
            }
        }
        f
    }

    fn of_body(b: &Body) -> Form {
        let options = OPTS.iter().map(|x| (x.key.to_string(), b.get(&format!("opt_{}", x.key)))).collect();
        Form {
            id: b.int("id"),
            name: b.get("name"),
            note: b.get("note"),
            enabled: b.checked("enabled"),
            is_default: b.checked("is_default"),
            enforce: b.checked("enforce"),
            timeout: b.get("timeout"),
            revision_note: b.get("revision_note"),
            options,
            delete_id: b.int("delete_id"),
            restore_id: b.int("restore_id"),
        }
    }

    fn json(&self) -> Value {
        let mut opts = Map::new();
        for (k, v) in &self.options {
            opts.insert(k.clone(), json!(v));
        }
        json!({"id": self.id, "name": self.name, "note": self.note, "enabled": self.enabled, "is_default": self.is_default, "enforce": self.enforce, "timeout": self.timeout,
               "revision_note": self.revision_note, "options": opts, "delete_id": self.delete_id, "restore_id": self.restore_id})
    }
}

/// `$strategy->optionMap()`
fn option_map(s: &Row) -> engine::Map {
    match crate::laravel::from_json(&s.val("options")) {
        Val::Arr(a) => engine::sanitize_options(&a),
        _ => vec![],
    }
}

fn pairs(m: &engine::Map) -> Vec<(String, String)> {
    m.iter().map(|(k, v)| (lossy(k), lossy(v))).collect()
}

fn arr_of(pairs: &[(String, String)]) -> Arr {
    let mut a = Arr::new();
    for (k, v) in pairs {
        a.set(Key::from_bytes(k.as_bytes()), Val::str(v));
    }
    a
}

/// The proposal a review is about.
#[derive(Clone)]
struct Snap {
    target: i64,
    name: String,
    note: Option<String>,
    enabled: bool,
    is_default: bool,
    enforce: bool,
    timeout: i64,
    options: Vec<(String, String)>,
    revision_note: String,
    operation: &'static str,
    restore: Option<i64>,
}

impl Snap {
    fn of_form(f: &Form, options: Vec<(String, String)>) -> Snap {
        Snap {
            target: f.id,
            name: f.name.clone(),
            note: if f.note.is_empty() { None } else { Some(f.note.clone()) },
            enabled: f.enabled,
            is_default: f.is_default,
            enforce: f.enforce,
            timeout: php::str_to_int(f.timeout.as_bytes()),
            options,
            revision_note: f.revision_note.clone(),
            operation: if f.delete_id > 0 { "delete" } else if f.restore_id > 0 { "restore" } else { "save" },
            restore: if f.restore_id > 0 { Some(f.restore_id) } else { None },
        }
    }
}

/// `validatedOptions()`: trimmed, empty ones left out, the whole numbers range-checked.
fn validated_options(f: &Form) -> (Vec<(String, String)>, Map<String, Value>) {
    let mut out = vec![];
    let mut errors = Map::new();
    for (k, v) in &f.options {
        let v = lossy(php::trim(v.as_bytes()));
        let Some(x) = OPTS.iter().find(|x| x.key == k) else { continue };
        if v.is_empty() {
            continue;
        }
        if let K::Int(min, max) = x.kind {
            let ok = v.bytes().all(|b| b.is_ascii_digit()) && php::str_to_int(v.as_bytes()) >= min && php::str_to_int(v.as_bytes()) <= max;
            if !ok {
                errors.insert(k.clone(), json!(format!("Enter a whole number between {min} and {max}.")));
                continue;
            }
        }
        let mut v = v;
        if let K::Ice = x.kind {
            match crate::ice::normalize(&v) {
                Some(n) => v = n,
                None => {
                    let msg = match crate::ice::first_invalid(&v) {
                        Some(bad) => format!("{bad} is not a STUN or TURN server the client will use. A TURN entry needs a user name and password: turn://user:password@host:3478."),
                        None => format!("At most {} servers.", crate::ice::MAX_ENTRIES),
                    };
                    errors.insert(k.clone(), json!(msg));
                    continue;
                }
            }
        }
        out.push((k.clone(), v));
    }
    (out, errors)
}

/// The base validation of the editor (`previewSave`'s `validate`): the first message per field.
fn validate_form(c: &Connection, f: &Form) -> Result<Map<String, Value>, Fault> {
    let mut e = Map::new();
    let len = |v: &str| crate::validate::mb_strlen(v.as_bytes());
    if f.name.trim().is_empty() {
        e.insert("name".into(), json!("The name field is required."));
    } else if len(&f.name) > 255 {
        e.insert("name".into(), json!("The name field must not be greater than 255 characters."));
    } else if count(c, r#"select count(*) as aggregate from "strategies" where "name" = ? and "id" <> ?"#, &[P(Val::str(&f.name)), P(Val::Int(f.id))])? > 0 {
        e.insert("name".into(), json!("The name has already been taken."));
    }
    if len(&f.note) > 500 {
        e.insert("note".into(), json!("The note field must not be greater than 500 characters."));
    }
    let t = f.timeout.trim();
    if t.is_empty() {
        e.insert("timeout".into(), json!("The form confirmation timeout field is required."));
    } else if t.parse::<i64>().is_err() {
        e.insert("timeout".into(), json!("The form confirmation timeout field must be an integer."));
    } else {
        let n: i64 = t.parse().unwrap();
        if n < 1 {
            e.insert("timeout".into(), json!("The form confirmation timeout field must be at least 1."));
        } else if n > 10080 {
            e.insert("timeout".into(), json!("The form confirmation timeout field must not be greater than 10080."));
        }
    }
    if len(&f.revision_note) > 500 {
        e.insert("revision_note".into(), json!("The revision note field must not be greater than 500 characters."));
    }
    Ok(e)
}

// -------------------------------------------------------------------------------------------- the review ---

struct Impact {
    option_changes: Vec<(String, Option<String>, Option<String>)>,
    dangerous: Vec<(String, Option<String>, Option<String>)>,
    resets: Vec<String>,
    count: i64,
    sample: Vec<Value>,
    metadata: Vec<(String, Value, Value)>,
    fingerprint: String,
}

fn bool_text(v: &Value) -> String {
    match v {
        Value::Bool(b) => (if *b { "Yes" } else { "No" }).into(),
        Value::Null => "—".into(),
        Value::String(t) => t.clone(),
        other => other.to_string(),
    }
}

/// `StrategyImpact::preview($strategy, $proposed)`
fn preview(c: &Connection, strategy: Option<&Row>, p: &Snap) -> Result<Impact, Fault> {
    let before_opts: Vec<(String, String)> = strategy.map(|s| pairs(&option_map(s))).unwrap_or_default();
    let after_opts = pairs(&engine::sanitize_options(&arr_of(&p.options)));
    let mut keys: Vec<String> = vec![];
    for (k, _) in before_opts.iter().chain(after_opts.iter()) {
        if !keys.contains(k) {
            keys.push(k.clone());
        }
    }
    let mut changes: Vec<(String, Option<String>, Option<String>)> = vec![];
    for k in keys {
        let old = before_opts.iter().find(|(x, _)| *x == k).map(|(_, v)| v.clone());
        let new = after_opts.iter().find(|(x, _)| *x == k).map(|(_, v)| v.clone());
        if old != new {
            changes.push((k, old, new));
        }
    }
    changes.sort_by(|a, b| php::smart_strcmp(a.0.as_bytes(), b.0.as_bytes()));
    let danger: &[(&str, &[&str])] = &[("access-mode", &["view"]), ("enable-keyboard", &["N"]), ("enable-file-transfer", &["N"]), ("enable-terminal", &["N"]), ("allow-remote-config-modification", &["Y"])];
    let dangerous: Vec<_> = changes
        .iter()
        .filter(|(k, _, after)| danger.iter().any(|(dk, vals)| dk == k && after.as_ref().map_or(false, |a| vals.contains(&a.as_str()))))
        .cloned()
        .collect();
    let resets: Vec<String> = changes.iter().filter(|(_, b, a)| b.is_some() && a.is_none()).map(|(k, _, _)| k.clone()).collect();

    let before_meta = |key: &str| -> Value {
        match (strategy, key) {
            (None, "name") | (None, "note") => Value::Null,
            (None, "enabled") | (None, "is_default") | (None, "enforce") => json!(false),
            (None, _) => json!(15),
            (Some(s), "name") => json!(crate::pages::kit::s(s, "name")),
            (Some(s), "note") => if s.is_null("note") { Value::Null } else { json!(crate::pages::kit::s(s, "note")) },
            (Some(s), "enabled") => json!(s.val("enabled").to_bool()),
            (Some(s), "is_default") => json!(s.val("is_default").to_bool()),
            (Some(s), "enforce") => json!(s.val("enforce").to_bool()),
            (Some(s), _) => { let t = s.val("confirmation_timeout_minutes").to_int(); json!(if t == 0 { 15 } else { t }) }
        }
    };
    let after_meta = |key: &str| -> Value {
        match key {
            "name" => json!(p.name),
            "note" => p.note.as_ref().map_or(Value::Null, |n| json!(n)),
            "enabled" => json!(p.enabled),
            "is_default" => json!(p.is_default),
            "enforce" => json!(p.enforce),
            _ => json!(p.timeout),
        }
    };
    let metadata: Vec<(String, Value, Value)> = ["name", "note", "enabled", "is_default", "enforce", "confirmation_timeout_minutes"]
        .iter()
        .filter(|k| before_meta(k) != after_meta(k))
        .map(|k| (k.to_string(), before_meta(k), after_meta(k)))
        .collect();
    let policy_changed = !changes.is_empty() || before_meta("enabled") != after_meta("enabled") || before_meta("is_default") != after_meta("is_default") || before_meta("enforce") != after_meta("enforce");

    // ---- the scan: who would end up with a different strategy, and the fingerprint of everything it read
    let mut hash = Sha256::new();
    let mut proposed = Map::new();
    proposed.insert("name".into(), json!(p.name));
    proposed.insert("note".into(), p.note.as_ref().map_or(Value::Null, |n| json!(n)));
    proposed.insert("enabled".into(), json!(p.enabled));
    proposed.insert("is_default".into(), json!(p.is_default));
    proposed.insert("enforce".into(), json!(p.enforce));
    proposed.insert("confirmation_timeout_minutes".into(), json!(p.timeout));
    let mut o = Map::new();
    for (k, v) in &after_opts {
        o.insert(k.clone(), json!(v));
    }
    proposed.insert("options".into(), Value::Object(o));
    proposed.insert("operation".into(), json!(p.operation));
    proposed.insert("restore_revision_id".into(), p.restore.map_or(Value::Null, |r| json!(r)));
    hash.update(json!({"strategy_id": strategy.map(|s| s.id()), "proposed": Value::Object(proposed)}).to_string().as_bytes());
    let target = strategy.map(|s| s.id()).unwrap_or(-1);
    let all = db::rows(c, r#"select * from "strategies" where "strategies"."deleted_at" is null order by "id" asc"#, &[])?;
    let mut enabled: Vec<(i64, bool)> = all.iter().map(|s| (s.id(), s.val("enabled").to_bool())).collect();
    match enabled.iter_mut().find(|(i, _)| *i == target) {
        Some(slot) => slot.1 = p.enabled,
        None => enabled.push((target, p.enabled)),
    }
    for s in &all {
        let t = s.val("confirmation_timeout_minutes").to_int();
        hash.update(format!("strategy:{}:{}:{}:{}:{}:{}:{};", s.id(), crate::pages::kit::s(s, "name"), s.val("enabled").to_bool() as i32, s.val("is_default").to_bool() as i32, s.val("enforce").to_bool() as i32, if t == 0 { 15 } else { t }, json!(pairs(&option_map(s)))).as_bytes());
    }
    let default_id: Option<i64> = if p.enabled && p.is_default {
        Some(target)
    } else {
        all.iter().find(|s| Some(s.id()) != strategy.map(|x| x.id()) && s.val("enabled").to_bool() && s.val("is_default").to_bool()).map(|s| s.id())
    };
    let mut direct: Vec<(i64, i64)> = vec![];
    let mut owners: Vec<(i64, i64)> = vec![];
    let mut groups: Vec<(i64, i64)> = vec![];
    for (level, table, col, dest) in [("device", "device_strategy", "device_id", 0), ("user", "strategy_user", "user_id", 1), ("device_group", "device_group_strategy", "device_group_id", 2)] {
        for r in db::rows(c, &format!(r#"select * from "{table}" order by "{col}" asc"#), &[])? {
            let (t, s) = (r.val(col).to_int(), r.val("strategy_id").to_int());
            hash.update(format!("{level}:{t}:{s};").as_bytes());
            match dest { 0 => direct.push((t, s)), 1 => owners.push((t, s)), _ => groups.push((t, s)) }
        }
    }
    let lookup = |list: &[(i64, i64)], k: i64| list.iter().find(|(t, _)| *t == k).map(|(_, s)| *s);
    let mut count_n = 0;
    let mut sample: Vec<(String, Value)> = vec![];
    let devices = db::rows(c, r#"select * from "devices" where "status" = ? and "devices"."deleted_at" is null order by "id" asc"#, &[P(Val::str("active"))])?;
    for d in &devices {
        let user = if d.is_null("user_id") { None } else { Some(d.val("user_id").to_int()) };
        let group = if d.is_null("device_group_id") { None } else { Some(d.val("device_group_id").to_int()) };
        let resolved = if d.is_null("strategy_id_resolved") { None } else { Some(d.val("strategy_id_resolved").to_int()) };
        hash.update(format!("device:{}:{}:{}:{};", d.id(), user.map_or(String::new(), |u| u.to_string()), group.map_or(String::new(), |g| g.to_string()), resolved.map_or(String::new(), |r| r.to_string())).as_bytes());
        let candidates: [(&str, Option<i64>); 4] = [("device", lookup(&direct, d.id())), ("user", user.and_then(|u| lookup(&owners, u))), ("device_group", group.and_then(|g| lookup(&groups, g))), ("default", default_id)];
        let mut winner: Option<i64> = None;
        let mut level = "";
        for (lv, cand) in candidates {
            if let Some(cid) = cand {
                if enabled.iter().find(|(i, _)| *i == cid).map_or(false, |(_, e)| *e) {
                    winner = Some(cid);
                    level = lv;
                    break;
                }
            }
        }
        if policy_changed && (winner != resolved || winner == Some(target)) {
            count_n += 1;
            if sample.len() < 50 {
                let alias = crate::pages::kit::s(d, "alias");
                let host = crate::pages::kit::s(d, "hostname");
                let rid = crate::pages::kit::s(d, "rustdesk_id");
                sample.push((rid.clone(), json!({"rustdesk_id": rid, "label": if truthy(&alias) { alias } else if truthy(&host) { host } else { rid.clone() }, "winning_level": level.replace('_', " ")})));
            }
        }
    }
    sample.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    Ok(Impact { option_changes: changes, dangerous, resets, count: count_n, sample: sample.into_iter().map(|(_, v)| v).collect(), metadata, fingerprint: hex::encode(hash.finalize()) })
}

fn impact_json(i: &Impact) -> Value {
    let show = |v: &Option<String>| v.clone().unwrap_or_else(|| "Not managed".into());
    json!({
        "count": i.count,
        "dangerous": i.dangerous.iter().map(|(k, _, a)| json!({"key": k, "after": a.clone().unwrap_or_default()})).collect::<Vec<_>>(),
        "resets": i.resets, "resets_line": i.resets.join(", "),
        "changes": i.option_changes.iter().map(|(k, b, a)| json!({"key": k, "before": show(b), "after": show(a)})).collect::<Vec<_>>(),
        "metadata": i.metadata.iter().map(|(k, b, a)| {
            let label = { let mut cs = k.chars(); let t = cs.next().map(|f| f.to_uppercase().collect::<String>() + cs.as_str()).unwrap_or_default(); t.replace('_', " ") };
            json!({"label": label, "before": bool_text(b), "after": bool_text(a)})
        }).collect::<Vec<_>>(),
        "sample": i.sample, "fingerprint": i.fingerprint,
    })
}

// -------------------------------------------------------------------------------------------- writes core ---

pub(crate) fn tx<T>(c: &Connection, f: impl FnOnce() -> Result<T, Fault>) -> Result<T, Fault> {
    c.execute_batch("begin immediate").map_err(|e| Fault::Other(e.to_string()))?;
    match f() {
        Ok(v) => {
            c.execute_batch("commit").map_err(|e| Fault::Other(e.to_string()))?;
            Ok(v)
        }
        Err(e) => {
            let _ = c.execute_batch("rollback");
            Err(e)
        }
    }
}

fn obj(pairs: Vec<(&str, Val)>) -> Val {
    let mut a = Arr::new();
    for (k, v) in pairs {
        a.set(Key::Str(k.as_bytes().to_vec()), v);
    }
    Val::Arr(a)
}

fn snapshot_val(s: &Row) -> Val {
    let note = if s.is_null("note") { Val::Null } else { Val::str(&crate::pages::kit::s(s, "note")) };
    let opts = option_map(s);
    let mut o = Arr::new();
    for (k, v) in &opts {
        o.set(Key::from_bytes(k), Val::Str(v.clone()));
    }
    obj(vec![
        ("name", Val::str(&crate::pages::kit::s(s, "name"))),
        ("note", note),
        ("enabled", Val::Bool(s.val("enabled").to_bool())),
        ("is_default", Val::Bool(s.val("is_default").to_bool())),
        ("enforce", Val::Bool(s.val("enforce").to_bool())),
        ("options", Val::Arr(o)),
    ])
}

/// `StrategyRevision::capture($strategy, $userId, $note)`; returns the new revision's id.
fn capture(ctx: &Ctx, c: &Connection, s: &Row, note: &str) -> Result<i64, Fault> {
    let next = count(c, r#"select coalesce(max("revision"), 0) as aggregate from "strategy_revisions" where "strategy_id" = ?"#, &[P(Val::Int(s.id()))])? + 1;
    let affected = count(c, r#"select count(*) as aggregate from "devices" where "strategy_id_resolved" = ? and "devices"."deleted_at" is null"#, &[P(Val::Int(s.id()))])?;
    let snapshot = php::json_encode(&snapshot_val(s)).ok_or_else(|| Fault::Other("json_encode failed".into()))?;
    db::insert(
        c,
        "strategy_revisions",
        vec![
            ("strategy_id", Val::Int(s.id())),
            ("revision", Val::Int(next)),
            ("snapshot", Val::str(&snapshot)),
            ("change_note", Val::str(note)),
            ("created_by", Val::Int(ctx.uid())),
            ("created_by_name", ctx.user.val("username")),
            ("affected_devices", Val::Int(affected)),
        ],
        &crate::laravel::ts(ctx.now),
    )
}

fn set_active(ctx: &Ctx, c: &Connection, id: i64, revision: i64) -> Result<(), Fault> {
    if let Some(mut s) = find(c, "strategies", id)? {
        update(c, "strategies", &mut s, vec![("active_revision_id", Val::Int(revision), Cast::Plain)], ctx.now)?;
    }
    Ok(())
}

/// `confirmSave`'s save branch: returns (strategy, creating).
fn apply_save(ctx: &Ctx, c: &Connection, p: &Snap) -> Result<(Row, bool), Fault> {
    tx(c, || {
        let mut target = if p.target > 0 { find(c, "strategies", p.target)? } else { None };
        let displaced = if p.is_default {
            db::first(c, r#"select * from "strategies" where "id" <> ? and "is_default" = ? and "strategies"."deleted_at" is null limit 1"#, &[P(Val::Int(target.as_ref().map_or(0, |t| t.id()))), P(Val::Bool(true))])?
        } else {
            None
        };
        let note = p.note.as_ref().map_or(Val::Null, |n| Val::str(n));
        let opts = engine::map_json(&engine::sanitize_options(&arr_of(&p.options)))?;
        let now_s = crate::laravel::ts(ctx.now);
        let creating = target.is_none();
        let (id, default_changed, flags_changed) = match target.as_mut() {
            Some(t) => {
                let changed = update(
                    c,
                    "strategies",
                    t,
                    vec![
                        ("name", Val::str(&p.name), Cast::Plain),
                        ("note", note, Cast::Plain),
                        ("enabled", Val::Bool(p.enabled), Cast::Bool),
                        ("is_default", Val::Bool(p.is_default), Cast::Bool),
                        ("enforce", Val::Bool(p.enforce), Cast::Bool),
                        ("confirmation_timeout_minutes", Val::Int(p.timeout), Cast::Plain),
                        ("options", opts, Cast::Plain),
                    ],
                    ctx.now,
                )?;
                (t.id(), changed.iter().any(|x| x == "is_default"), changed.iter().any(|x| x == "enabled" || x == "is_default"))
            }
            None => {
                let id = db::insert(
                    c,
                    "strategies",
                    vec![
                        ("name", Val::str(&p.name)),
                        ("note", note),
                        ("enabled", Val::Bool(p.enabled)),
                        ("is_default", Val::Bool(p.is_default)),
                        ("enforce", Val::Bool(p.enforce)),
                        ("confirmation_timeout_minutes", Val::Int(p.timeout)),
                        ("options", opts),
                    ],
                    &now_s,
                )?;
                (id, true, true)
            }
        };
        // the `saved` hook: at most one default, and every device re-resolves when the flags moved
        if p.is_default && default_changed {
            db::exec(c, r#"update "strategies" set "is_default" = ?, "updated_at" = ? where "id" <> ? and "is_default" = ? and "strategies"."deleted_at" is null"#, &[P(Val::Bool(false)), P(Val::str(&now_s)), P(Val::Int(id)), P(Val::Bool(true))])?;
        }
        if flags_changed {
            recompute_all(c, ctx.now)?;
        }
        let fresh = find(c, "strategies", id)?.ok_or_else(|| Fault::Other("saved strategy vanished".into()))?;
        let note_text = if !p.revision_note.is_empty() { p.revision_note.clone() } else if creating { "Initial revision".to_string() } else { "Saved from the strategy editor".to_string() };
        let rev = capture(ctx, c, &fresh, &note_text)?;
        set_active(ctx, c, id, rev)?;
        if let Some(d) = displaced {
            let d = find(c, "strategies", d.id())?.ok_or_else(|| Fault::Other("displaced strategy vanished".into()))?;
            let r = capture(ctx, c, &d, &format!("Default status moved to {}", p.name))?;
            set_active(ctx, c, d.id(), r)?;
        }
        let out = find(c, "strategies", id)?.ok_or_else(|| Fault::Other("saved strategy vanished".into()))?;
        Ok((out, creating))
    })
}

/// `$strategy->delete()` with the model's hooks.
fn soft_delete(ctx: &Ctx, c: &Connection, mut s: Row) -> Result<(), Fault> {
    tx(c, || {
        for table in ["device_strategy", "strategy_user", "device_group_strategy"] {
            db::exec(c, &format!(r#"delete from "{table}" where "strategy_id" = ?"#), &[P(Val::Int(s.id()))])?;
        }
        let renamed = format!("{} (deleted {})", crate::pages::kit::s(&s, "name"), crate::laravel::ts(ctx.now));
        update(c, "strategies", &mut s, vec![("enabled", Val::Bool(false), Cast::Bool), ("is_default", Val::Bool(false), Cast::Bool), ("name", Val::str(&renamed), Cast::Plain)], ctx.now)?;
        let ts = crate::laravel::ts(ctx.now);
        db::exec(c, r#"update "strategies" set "deleted_at" = ?, "updated_at" = ? where "id" = ?"#, &[P(Val::str(&ts)), P(Val::str(&ts)), P(Val::Int(s.id()))])?;
        recompute_all(c, ctx.now)
    })
}

// ------------------------------------------------------------------------------------------------- views ---

enum View {
    None,
    Editor { form: Form, errors: Map<String, Value> },
    Review { form: Form, impact: Impact, error: String },
    Assign { id: i64, tab: String, search: String },
    History { id: i64, from: i64, to: i64 },
    Compliance { id: i64, state: String },
}

fn when(ts: Option<i64>) -> Option<String> {
    ts.and_then(|t| chrono::DateTime::from_timestamp(t, 0)).map(|d| d.format("%b %-d, %Y %-I:%M %p UTC").to_string())
}

pub fn index(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let rw = ctx.allows("strategy", "rw");
    let view = if q(req, "create") == "1" {
        if !rw {
            return Ok(abort(403));
        }
        View::Editor { form: Form::blank(), errors: Map::new() }
    } else if qint(req, "edit") > 0 {
        if !rw {
            return Ok(abort(403));
        }
        let Some(s) = active(c, qint(req, "edit"))? else { return Ok(abort(404)) };
        View::Editor { form: Form::of_strategy(&s), errors: Map::new() }
    } else if qint(req, "delete") > 0 {
        if !rw {
            return Ok(abort(403));
        }
        let Some(s) = active(c, qint(req, "delete"))? else { return Ok(abort(404)) };
        return delete_review(ctx, c, &s, String::new());
    } else if qint(req, "assign") > 0 {
        if !rw {
            return Ok(abort(403));
        }
        if active(c, qint(req, "assign"))?.is_none() {
            return Ok(abort(404));
        }
        let tab = q(req, "tab");
        View::Assign { id: qint(req, "assign"), tab: if ["devices", "users", "groups"].contains(&tab.as_str()) { tab } else { "devices".into() }, search: q(req, "search") }
    } else if qint(req, "history") > 0 {
        let id = qint(req, "history");
        if active(c, id)?.is_none() {
            return Ok(abort(404));
        }
        let ids: Vec<i64> = db::rows(c, r#"select "id" from "strategy_revisions" where "strategy_id" = ? order by "revision" asc"#, &[P(Val::Int(id))])?.iter().map(|r| r.id()).collect();
        let (def_from, def_to) = (if ids.len() > 1 { ids[0] } else { 0 }, ids.last().copied().unwrap_or(0));
        let given = req.input.string("from").is_ok() || req.input.string("to").is_ok();
        View::History { id, from: if given { qint(req, "from") } else { def_from }, to: if given { qint(req, "to") } else { def_to } }
    } else if qint(req, "compliance") > 0 {
        if !ctx.is_admin() {
            return Ok(abort(403));
        }
        if active(c, qint(req, "compliance"))?.is_none() {
            return Ok(abort(404));
        }
        let st = q(req, "state");
        View::Compliance { id: qint(req, "compliance"), state: if st == "all" || ["confirmed", "pending", "stale", "offline", "overridden"].contains(&st.as_str()) { st } else { "all".into() } }
    } else {
        View::None
    };
    render(ctx, c, 200, view)
}

fn active(c: &Connection, id: i64) -> Result<Option<Row>, Fault> {
    db::first(c, r#"select * from "strategies" where "id" = ? and "strategies"."deleted_at" is null limit 1"#, &[P(Val::Int(id))])
}

/// `deleteStrategy`: the editor's values with enabled and default off, straight to the review.
fn delete_review(ctx: &Ctx, c: &Connection, s: &Row, error: String) -> Result<Reply, Fault> {
    let mut f = Form::of_strategy(s);
    f.enabled = false;
    f.is_default = false;
    f.delete_id = s.id();
    let (options, _) = validated_options(&f);
    let snap = Snap::of_form(&f, options);
    let impact = preview(c, Some(s), &snap)?;
    render(ctx, c, if error.is_empty() { 200 } else { 422 }, View::Review { form: f, impact, error })
}

fn render(ctx: &Ctx, c: &Connection, status: u16, view: View) -> Result<Reply, Fault> {
    let strategies = db::rows(
        c,
        r#"select "strategies".*,
            (select count(*) from "devices" inner join "device_strategy" on "devices"."id" = "device_strategy"."device_id" where "strategies"."id" = "device_strategy"."strategy_id" and "devices"."deleted_at" is null) as "devices_count",
            (select count(*) from "users" inner join "strategy_user" on "users"."id" = "strategy_user"."user_id" where "strategies"."id" = "strategy_user"."strategy_id") as "users_count",
            (select count(*) from "device_groups" inner join "device_group_strategy" on "device_groups"."id" = "device_group_strategy"."device_group_id" where "strategies"."id" = "device_group_strategy"."strategy_id") as "device_groups_count",
            (select count(*) from "devices" where "strategies"."id" = "devices"."strategy_id_resolved" and "devices"."deleted_at" is null) as "resolved_devices_count"
           from "strategies" where "strategies"."deleted_at" is null order by "is_default" desc, "name" asc"#,
        &[],
    )?;
    let items: Vec<Value> = strategies
        .iter()
        .map(|s| {
            let n = option_map(s).len();
            json!({"id": s.id(), "name": crate::pages::kit::s(s, "name"), "note": crate::pages::kit::s(s, "note"), "is_default": s.val("is_default").to_bool(), "enforce": s.val("enforce").to_bool(), "enabled": s.val("enabled").to_bool(),
                   "options": n, "devices": s.val("devices_count").to_int(), "users": s.val("users_count").to_int(), "groups": s.val("device_groups_count").to_int(), "resolved": s.val("resolved_devices_count").to_int()})
        })
        .collect();
    let no_default = !strategies.is_empty() && !strategies.iter().any(|s| s.val("is_default").to_bool());
    let dialog = dialog_json(ctx, c, &strategies, view)?;
    let layout = ctx.layout(c, "strategies", "Strategies", "Manage")?;
    let page = json!({"strategies": items, "no_default": no_default, "can_manage": ctx.allows("strategy", "rw"), "is_admin": ctx.is_admin(), "catalog": catalog_json(), "dialog": dialog});
    Ok(Reply::Html(status, ctx.render("strategies/index.html", layout, page)?))
}

fn dialog_json(ctx: &Ctx, c: &Connection, strategies: &[Row], view: View) -> Result<Value, Fault> {
    Ok(match view {
        View::None => json!({"kind": ""}),
        View::Editor { form, errors } => {
            let mut e = errors.clone();
            for k in ["name", "note", "timeout", "revision_note"] {
                e.entry(k.to_string()).or_insert(Value::Null);
            }
            let mut oe = Map::new();
            for x in OPTS {
                oe.insert(x.key.to_string(), errors.get(&format!("opt.{}", x.key)).cloned().unwrap_or(Value::Null));
            }
            json!({"kind": "editor", "title": if form.id == 0 { "Add Strategy" } else { "Edit Strategy" }, "form": form.json(), "errors": e, "opt_errors": oe})
        }
        View::Review { form, impact, error } => {
            let title = if form.delete_id > 0 { "Review strategy deletion" } else if form.restore_id > 0 { "Review revision restore" } else { "Review strategy impact" };
            let button = if form.delete_id > 0 { "Delete strategy" } else if form.restore_id > 0 { "Restore revision" } else { "Apply strategy" };
            json!({"kind": "review", "title": title, "button": button, "deleting": form.delete_id > 0, "restoring": form.restore_id > 0, "form": form.json(), "impact": impact_json(&impact), "error": error})
        }
        View::Assign { id, tab, search } => {
            let s = strategies.iter().find(|s| s.id() == id).cloned().ok_or_else(|| Fault::Other("assign target vanished".into()))?;
            let name = crate::pages::kit::s(&s, "name");
            let cur_dev = pivot_ids(c, "device_strategy", "strategy_id", "device_id", id)?;
            let cur_usr = pivot_ids(c, "strategy_user", "strategy_id", "user_id", id)?;
            let cur_grp = pivot_ids(c, "device_group_strategy", "strategy_id", "device_group_id", id)?;
            let mut sql = String::from(r#"select "id", "rustdesk_id", "alias", "hostname" from "devices" where "devices"."deleted_at" is null"#);
            let mut params: Vec<P> = vec![];
            if !search.is_empty() && tab == "devices" {
                let like = format!("%{search}%");
                sql.push_str(r#" and ("rustdesk_id" like ? or "alias" like ? or "hostname" like ?)"#);
                params.extend((0..3).map(|_| P(Val::str(&like))));
            }
            sql.push_str(r#" order by "rustdesk_id" asc limit 200"#);
            let devices = db::rows(c, &sql, &params)?;
            let users = db::rows(c, r#"select "id", "username", "name" from "users" order by "username" asc"#, &[])?;
            let groups = db::rows(c, r#"select "id", "name" from "device_groups" order by "name" asc"#, &[])?;
            let taken = |table: &str, col: &str, ids: Vec<i64>| -> Result<Vec<(i64, String)>, Fault> {
                if ids.is_empty() {
                    return Ok(vec![]);
                }
                Ok(db::rows(c, &format!(r#"select "{table}"."{col}" as "t", "strategies"."name" as "n" from "{table}" inner join "strategies" on "strategies"."id" = "{table}"."strategy_id" where "{table}"."{col}" in ({})"#, marks(ids.len())), &ints_val(&ids))?.iter().map(|r| (r.val("t").to_int(), crate::pages::kit::s(r, "n"))).collect())
            };
            let t_dev = taken("device_strategy", "device_id", devices.iter().map(|d| d.id()).collect())?;
            let t_usr = taken("strategy_user", "user_id", users.iter().map(|d| d.id()).collect())?;
            let t_grp = taken("device_group_strategy", "device_group_id", groups.iter().map(|d| d.id()).collect())?;
            let other = |list: &[(i64, String)], i: i64| list.iter().find(|(t, _)| *t == i).map(|(_, n)| n.clone()).filter(|n| *n != name);
            let shown: Vec<i64> = devices.iter().map(|d| d.id()).collect();
            json!({
                "kind": "assign", "id": id, "name": name, "tab": tab, "search": search, "capped": devices.len() >= 200,
                "counts": {"devices": cur_dev.len(), "users": cur_usr.len(), "groups": cur_grp.len()},
                "devices": devices.iter().map(|d| { let a = crate::pages::kit::s(d, "alias"); let h = crate::pages::kit::s(d, "hostname"); let label = if truthy(&a) { a } else { h };
                    json!({"id": d.id(), "rustdesk_id": crate::pages::kit::s(d, "rustdesk_id"), "label": label, "checked": cur_dev.contains(&d.id()), "taken": other(&t_dev, d.id())}) }).collect::<Vec<_>>(),
                "hidden_devices": cur_dev.iter().filter(|i| !shown.contains(i)).collect::<Vec<_>>(),
                "users": users.iter().map(|u| json!({"id": u.id(), "username": crate::pages::kit::s(u, "username"), "name": crate::pages::kit::s(u, "name"), "checked": cur_usr.contains(&u.id()), "taken": other(&t_usr, u.id())})).collect::<Vec<_>>(),
                "groups": groups.iter().map(|g| json!({"id": g.id(), "name": crate::pages::kit::s(g, "name"), "checked": cur_grp.contains(&g.id()), "taken": other(&t_grp, g.id())})).collect::<Vec<_>>(),
            })
        }
        View::History { id, from, to } => {
            let s = strategies.iter().find(|s| s.id() == id).cloned().ok_or_else(|| Fault::Other("history target vanished".into()))?;
            let revs = db::rows(c, r#"select * from "strategy_revisions" where "strategy_id" = ? order by "revision" desc"#, &[P(Val::Int(id))])?;
            let creators = find_in(c, "users", &revs.iter().filter(|r| !r.is_null("created_by")).map(|r| r.val("created_by").to_int()).collect::<Vec<_>>())?;
            let snap_of = |r: &Row| -> Value { serde_json::from_slice(&r.val("snapshot").to_php_string().unwrap_or_default()).unwrap_or(Value::Null) };
            let comparison = match (revs.iter().find(|r| r.id() == from), revs.iter().find(|r| r.id() == to)) {
                (Some(a), Some(b)) if from > 0 && to > 0 => Some(diff_snapshots(&snap_of(a), &snap_of(b))),
                _ => None,
            };
            let mut asc: Vec<&Row> = revs.iter().collect();
            asc.sort_by_key(|r| r.val("revision").to_int());
            let active_rev = if s.is_null("active_revision_id") { 0 } else { s.val("active_revision_id").to_int() };
            json!({
                "kind": "history", "id": id, "name": crate::pages::kit::s(&s, "name"), "from": from, "to": to,
                "choices": asc.iter().map(|r| json!({"id": r.id(), "n": r.val("revision").to_int()})).collect::<Vec<_>>(),
                "comparison": comparison, "has_revisions": !revs.is_empty(),
                "revisions": revs.iter().map(|r| {
                    let by = { let n = crate::pages::kit::s(r, "created_by_name"); if !r.is_null("created_by_name") { n } else { by_id(&creators, &r.val("created_by")).map(|u| crate::pages::kit::s(u, "username")).unwrap_or_else(|| "System".into()) } };
                    json!({"id": r.id(), "n": r.val("revision").to_int(), "active": active_rev == r.id(), "by": by, "when": when(ts_of(r, "created_at")).unwrap_or_default(), "affected": r.val("affected_devices").to_int(), "note": crate::pages::kit::s(r, "change_note")})
                }).collect::<Vec<_>>(),
            })
        }
        View::Compliance { id, state } => {
            let s = strategies.iter().find(|s| s.id() == id).cloned().ok_or_else(|| Fault::Other("compliance target vanished".into()))?;
            let sum = compliance(c, ctx.now, &s, &state)?;
            let total: i64 = if state == "all" { sum.counts.iter().map(|(_, n)| *n).sum() } else { sum.counts.iter().find(|(k, _)| *k == state).map(|(_, n)| *n).unwrap_or(0) };
            json!({
                "kind": "compliance", "id": id, "name": crate::pages::kit::s(&s, "name"), "state": state, "total": total, "shown": sum.devices.len(),
                "counts": sum.counts.iter().map(|(k, n)| json!({"state": k, "n": n})).collect::<Vec<_>>(),
                "devices": sum.devices,
            })
        }
    })
}

/// `StrategyRevision::diffSnapshots`
fn diff_snapshots(before: &Value, after: &Value) -> Vec<Value> {
    let mut out = vec![];
    let show = |v: &Value| match v {
        Value::Bool(b) => (if *b { "Yes" } else { "No" }).to_string(),
        Value::Null => "Not managed".to_string(),
        Value::String(t) => t.clone(),
        other => other.to_string(),
    };
    for k in ["name", "note", "enabled", "is_default", "enforce"] {
        let (b, a) = (before.get(k).cloned().unwrap_or(Value::Null), after.get(k).cloned().unwrap_or(Value::Null));
        if b != a {
            out.push(json!({"key": k, "before": show(&b), "after": show(&a)}));
        }
    }
    let empty = Map::new();
    let bo = before.get("options").and_then(|o| o.as_object()).unwrap_or(&empty);
    let ao = after.get("options").and_then(|o| o.as_object()).unwrap_or(&empty);
    let mut keys: Vec<&String> = vec![];
    for k in bo.keys().chain(ao.keys()) {
        if !keys.contains(&k) {
            keys.push(k);
        }
    }
    for k in keys {
        let (b, a) = (bo.get(k).cloned().unwrap_or(Value::Null), ao.get(k).cloned().unwrap_or(Value::Null));
        if b != a {
            out.push(json!({"key": format!("options.{k}"), "before": show(&b), "after": show(&a)}));
        }
    }
    out
}

// --------------------------------------------------------------------------------------------- compliance ---

struct Summary {
    counts: Vec<(&'static str, i64)>,
    devices: Vec<Value>,
}

const STATES: [&str; 5] = ["confirmed", "pending", "stale", "offline", "overridden"];

/// `StrategyCompliance::summary($strategy, $state)` for one strategy.
fn compliance(c: &Connection, now: i64, strategy: &Row, state: &str) -> Result<Summary, Fault> {
    let id = strategy.id();
    let desired: engine::Map = if strategy.val("enabled").to_bool() { option_map(strategy) } else { vec![] };
    // when the option map last changed: the oldest revision of the run that still carries the current map
    let revs = db::rows(c, r#"select "snapshot", "created_at" from "strategy_revisions" where "strategy_id" = ? order by "revision" desc"#, &[P(Val::Int(id))])?;
    let mut changed_at: Option<i64> = None;
    for r in &revs {
        let snap: Value = serde_json::from_slice(&r.val("snapshot").to_php_string().unwrap_or_default()).unwrap_or(Value::Null);
        let mut a = Arr::new();
        if let Some(o) = snap.get("options").and_then(|o| o.as_object()) {
            for (k, v) in o {
                if let Some(t) = v.as_str() {
                    a.set(Key::from_bytes(k.as_bytes()), Val::str(t));
                }
            }
        }
        if engine::sanitize_options(&a) != desired {
            break;
        }
        changed_at = ts_of(r, "created_at");
    }
    let changed_at = changed_at.or_else(|| ts_of(strategy, "updated_at"));
    let timeout = { let t = strategy.val("confirmation_timeout_minutes").to_int(); if t == 0 { 1 } else { t.max(1) } };
    let window = online_window(c)?;
    let rows = db::rows(
        c,
        r#"select "devices".*, "ds"."strategy_id" as "direct_strategy_id", "su"."strategy_id" as "owner_strategy_id", "dgs"."strategy_id" as "group_strategy_id" from "devices"
           left join "device_strategy" as "ds" on "ds"."device_id" = "devices"."id"
           left join "strategy_user" as "su" on "su"."user_id" = "devices"."user_id"
           left join "device_group_strategy" as "dgs" on "dgs"."device_group_id" = "devices"."device_group_id"
           where "devices"."status" = ? and "devices"."deleted_at" is null order by "devices"."id" asc"#,
        &[P(Val::str("active"))],
    )?;
    let mut counts: Vec<(&'static str, i64)> = STATES.iter().map(|s| (*s, 0)).collect();
    let mut detail: Vec<(String, Value)> = vec![];
    let mut stored = 0;
    let limit = 200;
    let mut record = |counts: &mut Vec<(&'static str, i64)>, d: &Row, st: &'static str| {
        counts.iter_mut().find(|(k, _)| *k == st).unwrap().1 += 1;
        if (state != "all" && state != st) || stored >= limit {
            return;
        }
        let alias = crate::pages::kit::s(d, "alias");
        let host = crate::pages::kit::s(d, "hostname");
        let label = if truthy(&alias) { alias } else if truthy(&host) { host } else { "Unlabelled".to_string() };
        let rid = crate::pages::kit::s(d, "rustdesk_id");
        detail.push((rid.clone(), json!({"id": d.id(), "rustdesk_id": rid, "label": label, "state": st,
            "last_online": when(ts_of(d, "last_online_at")).unwrap_or_else(|| "Never".into()), "sent": when(ts_of(d, "strategy_sent_at")).unwrap_or_else(|| "—".into()), "confirmed": when(ts_of(d, "strategy_acked_at")).unwrap_or_else(|| "—".into())})));
        stored += 1;
    };
    for d in &rows {
        let resolved = if d.is_null("strategy_id_resolved") { None } else { Some(d.val("strategy_id_resolved").to_int()) };
        if resolved == Some(id) {
            let acked = engine::string_map(&d.val("strategy_acked_options"));
            let sent_at = ts_of(d, "strategy_sent_at");
            let acked_at = ts_of(d, "strategy_acked_at");
            let st: &'static str = if acked_at.is_some() && acked == desired && sent_at.map_or(true, |s| acked_at.unwrap() >= s) {
                "confirmed"
            } else {
                let sent = engine::string_map(&d.val("strategy_options"));
                let from = if sent == desired { sent_at.or(changed_at) } else { changed_at };
                match from {
                    Some(f) if f <= now - timeout * 60 => if is_online(d, now, window) { "stale" } else { "offline" },
                    _ => "pending",
                }
            };
            record(&mut counts, d, st);
        }
        let mut cand: Vec<i64> = vec![];
        for col in ["direct_strategy_id", "owner_strategy_id", "group_strategy_id"] {
            if !d.is_null(col) {
                let v = d.val(col).to_int();
                if !cand.contains(&v) {
                    cand.push(v);
                }
            }
        }
        if cand.contains(&id) && resolved != Some(id) {
            record(&mut counts, d, "overridden");
        }
    }
    detail.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut devices: Vec<Value> = detail.into_iter().map(|(_, v)| v).collect();
    if state == "all" {
        // collect()->flatten(1)->sortBy('rustdesk_id'): a stable sort with the previous console's own comparison
        devices.sort_by(|a, b| php::smart_strcmp(a["rustdesk_id"].as_str().unwrap_or("").as_bytes(), b["rustdesk_id"].as_str().unwrap_or("").as_bytes()));
    }
    Ok(Summary { counts, devices })
}

// -------------------------------------------------------------------------------------------------- posts ---

/// `POST /strategies/preview`: the editor's Review Impact.
pub fn preview_post(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if !ctx.allows("strategy", "rw") {
        return Ok(abort(403));
    }
    let body = Body::of(req);
    let form = Form::of_body(&body);
    if form.id > 0 && active(c, form.id)?.is_none() {
        return Ok(abort(404));
    }
    if body.get("step") == "edit" {
        return render(ctx, c, 200, View::Editor { form, errors: Map::new() });
    }
    let mut errors = validate_form(c, &form)?;
    if errors.is_empty() {
        let (options, oerrs) = validated_options(&form);
        if !oerrs.is_empty() {
            for (k, v) in oerrs {
                errors.insert(format!("opt.{k}"), v);
            }
            return render(ctx, c, 422, View::Editor { form, errors });
        }
        let target = if form.id > 0 { active(c, form.id)? } else { None };
        let snap = Snap::of_form(&form, options);
        let impact = preview(c, target.as_ref(), &snap)?;
        return render(ctx, c, 200, View::Review { form, impact, error: String::new() });
    }
    render(ctx, c, 422, View::Editor { form, errors })
}

/// `POST /strategies/confirm`: Apply, Delete or Restore after the review.
pub fn confirm(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if !ctx.allows("strategy", "rw") {
        return Ok(abort(403));
    }
    let body = Body::of(req);
    let form = Form::of_body(&body);
    let fingerprint = body.get("fingerprint");
    let target = if form.id > 0 { active(c, form.id)? } else { None };
    if form.id > 0 && target.is_none() {
        return Ok(abort(404));
    }
    // a deletion is rebuilt from the stored strategy, not from what the page carried
    let form = match (&target, form.delete_id) {
        (Some(t), d) if d > 0 => {
            let mut f = Form::of_strategy(t);
            f.enabled = false;
            f.is_default = false;
            f.delete_id = d;
            f
        }
        _ => form,
    };
    if form.delete_id > 0 && form.delete_id != form.id {
        return Ok(abort(404));
    }
    let (options, _) = validated_options(&form);
    let snap = Snap::of_form(&form, options);
    let current = preview(c, target.as_ref(), &snap)?;
    let again = |error: &str| -> Result<Reply, Fault> {
        let mut fresh = current_impact_clone(&current);
        fresh.fingerprint = current.fingerprint.clone();
        render(ctx, c, 422, View::Review { form: form.clone(), impact: fresh, error: error.into() })
    };
    if fingerprint.is_empty() {
        return again("Review the strategy impact before applying it.");
    }
    if fingerprint != current.fingerprint {
        return again("The strategy or fleet changed after the preview. Review the impact again.");
    }
    if form.delete_id > 0 {
        let t = target.ok_or_else(|| Fault::Other("deletion target missing".into()))?;
        let name = crate::pages::kit::s(&t, "name");
        soft_delete(ctx, c, t)?;
        audit(ctx, c, "strategy.delete", &format!("Deleted strategy {name}"), Some("strategy"), Some(&name))?;
        return Ok(Reply::Redirect("/strategies".into()));
    }
    let (strategy, creating) = apply_save(ctx, c, &snap)?;
    let restoring = snap.restore.is_some();
    let n = option_map(&strategy).len();
    let name = crate::pages::kit::s(&strategy, "name");
    audit(
        ctx,
        c,
        if restoring { "strategy.rollback" } else if creating { "strategy.create" } else { "strategy.update" },
        &format!("{} strategy {name} ({n} option(s))", if restoring { "Restored" } else if creating { "Created" } else { "Updated" }),
        Some("strategy"),
        Some(&name),
    )?;
    Ok(Reply::Redirect("/strategies".into()))
}

fn current_impact_clone(i: &Impact) -> Impact {
    Impact {
        option_changes: i.option_changes.clone(),
        dangerous: i.dangerous.clone(),
        resets: i.resets.clone(),
        count: i.count,
        sample: i.sample.clone(),
        metadata: i.metadata.clone(),
        fingerprint: i.fingerprint.clone(),
    }
}

/// `POST /strategies/toggle`
pub fn toggle(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if !ctx.allows("strategy", "rw") {
        return Ok(abort(403));
    }
    let body = Body::of(req);
    let Some(mut s) = active(c, body.int("id"))? else { return Ok(abort(404)) };
    let enabled = !s.val("enabled").to_bool();
    tx(c, || {
        update(c, "strategies", &mut s, vec![("enabled", Val::Bool(enabled), Cast::Bool)], ctx.now)?;
        recompute_all(c, ctx.now)?;
        let fresh = find(c, "strategies", s.id())?.ok_or_else(|| Fault::Other("strategy vanished".into()))?;
        let rev = capture(ctx, c, &fresh, "Toggled enabled state")?;
        set_active(ctx, c, s.id(), rev)
    })?;
    let name = crate::pages::kit::s(&s, "name");
    audit(ctx, c, "strategy.toggle", &format!("{} strategy {name}", if enabled { "Enabled" } else { "Disabled" }), Some("strategy"), Some(&name))?;
    Ok(Reply::Redirect("/strategies".into()))
}

/// `POST /strategies/restore`: History's "Restore as new revision" opens the review of the restore.
pub fn restore(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if !ctx.allows("strategy", "rw") {
        return Ok(abort(403));
    }
    let body = Body::of(req);
    let Some(rev) = find(c, "strategy_revisions", body.int("id"))? else { return Ok(abort(404)) };
    let Some(s) = active(c, rev.val("strategy_id").to_int())? else { return Ok(abort(404)) };
    let snap: Value = serde_json::from_slice(&rev.val("snapshot").to_php_string().unwrap_or_default()).unwrap_or(Value::Null);
    let mut f = Form::of_strategy(&s);
    f.restore_id = rev.id();
    f.revision_note = format!("Restored revision {}", rev.val("revision").to_int());
    f.note = snap.get("note").and_then(|n| n.as_str()).unwrap_or("").to_string();
    f.enforce = snap.get("enforce").and_then(|n| n.as_bool()).unwrap_or(false);
    for slot in f.options.iter_mut() {
        slot.1 = String::new();
    }
    if let Some(o) = snap.get("options").and_then(|o| o.as_object()) {
        for (k, v) in o {
            if let Some(slot) = f.options.iter_mut().find(|(ok, _)| ok == k) {
                slot.1 = match v {
                    Value::String(t) => t.clone(),
                    Value::Bool(b) => (if *b { "1" } else { "" }).into(),
                    Value::Number(n) => n.to_string(),
                    _ => String::new(),
                };
            }
        }
    }
    let errors = validate_form(c, &f)?;
    if !errors.is_empty() {
        return render(ctx, c, 422, View::Editor { form: f, errors });
    }
    let (options, oerrs) = validated_options(&f);
    if !oerrs.is_empty() {
        let mut e = Map::new();
        for (k, v) in oerrs {
            e.insert(format!("opt.{k}"), v);
        }
        return render(ctx, c, 422, View::Editor { form: f, errors: e });
    }
    let snap = Snap::of_form(&f, options);
    let impact = preview(c, Some(&s), &snap)?;
    render(ctx, c, 200, View::Review { form: f, impact, error: String::new() })
}

/// `POST /strategies/assign`: Save Assignment.
pub fn assign(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if !ctx.allows("strategy", "rw") {
        return Ok(abort(403));
    }
    let body = Body::of(req);
    let Some(s) = active(c, body.int("id"))? else { return Ok(abort(404)) };
    let (dev, usr, grp) = (body.ints("device_ids"), body.ints("user_ids"), body.ints("group_ids"));
    let exists = |table: &str, ids: &[i64]| -> Result<bool, Fault> {
        for i in ids {
            if count(c, &format!(r#"select count(*) as aggregate from "{table}" where "id" = ?"#), &[P(Val::Int(*i))])? == 0 {
                return Ok(false);
            }
        }
        Ok(true)
    };
    if !(exists("devices", &dev)? && exists("users", &usr)? && exists("device_groups", &grp)?) {
        return render(ctx, c, 422, View::Assign { id: s.id(), tab: "devices".into(), search: String::new() });
    }
    let mut changed = 0;
    for (level, table, col, current, desired) in [
        ("device", "device_strategy", "device_id", pivot_ids(c, "device_strategy", "strategy_id", "device_id", s.id())?, &dev),
        ("user", "strategy_user", "user_id", pivot_ids(c, "strategy_user", "strategy_id", "user_id", s.id())?, &usr),
        ("device_group", "device_group_strategy", "device_group_id", pivot_ids(c, "device_group_strategy", "strategy_id", "device_group_id", s.id())?, &grp),
    ] {
        let _ = (table, col);
        let mut want: Vec<i64> = vec![];
        for i in desired.iter() {
            if !want.contains(i) {
                want.push(*i);
            }
        }
        for i in want.iter().filter(|i| !current.contains(i)) {
            strategy_assign(c, level, *i, Some(s.id()), ctx.now)?;
            changed += 1;
        }
        for i in current.iter().filter(|i| !want.contains(i)) {
            strategy_assign(c, level, *i, None, ctx.now)?;
            changed += 1;
        }
    }
    let name = crate::pages::kit::s(&s, "name");
    audit(ctx, c, "strategy.assign", &format!("Assignments for strategy {name}: {} device(s), {} user(s), {} device group(s) ({changed} change(s))", dev.len(), usr.len(), grp.len()), Some("strategy"), Some(&name))?;
    Ok(Reply::Redirect("/strategies".into()))
}
