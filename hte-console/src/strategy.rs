//! Strategy delivery in the heartbeat answer: a line-by-line port of `App\Models\Strategy` (v1.15.0-hte.1):
//! `sanitizeOptions`, `resolve`/`syncResolvedFor` (run when sysinfo creates a device) and `deliveryFor`.
//! The console UI that edits strategies stays in the previous console; this side only reads them and writes the device's
//! delivery state (strategy_version, strategy_options, strategy_acked_*, strategy_sent_at).

use crate::sqlite::{self as db, Row, P};
use crate::laravel::{self, Cast};
use crate::php::{self, Arr, Fault, Key, Val};
use rusqlite::Connection;

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

enum Kind {
    Bool,
    Enum(&'static [&'static str]),
    Int(i64, i64),
    Text,
    /// RustDesk 1.5's STUN/TURN list (`crate::ice`), stored in canonical form
    Ice,
}

/// `Strategy::OPTION_KEYS`: the allow-list of pushable keys (a security control: anything else is dropped).
fn spec(key: &[u8]) -> Option<Kind> {
    use Kind::*;
    Some(match key {
        b"access-mode" => Enum(&["", "full", "view", "custom"]),
        b"enable-keyboard" | b"enable-clipboard" | b"enable-file-transfer" | b"enable-audio" | b"enable-camera"
        | b"enable-terminal" | b"enable-tunnel" | b"enable-remote-restart" | b"enable-record-session"
        | b"enable-block-input" | b"enable-privacy-mode" | b"enable-remote-printer" => Bool,
        b"verification-method" => Enum(&["", "use-temporary-password", "use-permanent-password", "use-both-passwords"]),
        b"approve-mode" => Enum(&["", "password", "click", "password-click"]),
        b"temporary-password-length" => Enum(&["", "6", "8", "10"]),
        b"allow-numeric-one-time-password" => Bool,
        b"whitelist" => Text,
        b"direct-server" | b"allow-only-conn-window-open" | b"enable-trusted-devices" | b"allow-remote-config-modification"
        | b"allow-auto-disconnect" => Bool,
        b"auto-disconnect-timeout" => Int(1, 1440),
        b"allow-scope-violation-alarm" | b"allow-scope-violation-close" => Bool,
        b"enable-abr" | b"allow-remove-wallpaper" | b"allow-auto-record-incoming" | b"keep-awake-during-incoming-sessions"
        | b"enable-lan-discovery" | b"allow-auto-update" => Bool,
        // not an incoming-session control: a bad value costs WebRTC only (the client falls back to its other transports)
        b"ice-servers" => Ice,
        _ => return None,
    })
}

/// An option map: string keys to string values, in `ksort` order.
pub type Map = Vec<(Vec<u8>, Vec<u8>)>;

fn ksorted(mut m: Map) -> Map {
    m.sort_by(|a, b| php::smart_strcmp(&a.0, &b.0));
    m
}

/// `Strategy::sanitizeOptions($options)`
pub fn sanitize_options(options: &Arr) -> Map {
    let mut clean: Vec<(Vec<u8>, Vec<u8>)> = vec![];
    for (k, v) in options.iter() {
        let key = k.as_bytes();
        let Some(kind) = spec(&key) else { continue };
        let value = match v {
            Val::Null => continue,
            Val::Bool(b) => if *b { b"Y".to_vec() } else { b"N".to_vec() },
            Val::Int(_) | Val::Float(_) => match v.to_php_string() {
                Ok(s) => s,
                Err(_) => continue,
            },
            Val::Str(s) => s.clone(),
            Val::Arr(_) => continue,
        };
        let mut value = php::trim(&value).to_vec();
        let ok = match kind {
            Kind::Ice => match crate::ice::normalize(&lossy(&value)) {
                Some(n) => {
                    value = n.into_bytes();
                    true
                }
                None => false,
            },
            Kind::Bool => value.is_empty() || value == b"Y" || value == b"N",
            Kind::Enum(vals) => vals.iter().any(|x| x.as_bytes() == value.as_slice()),
            Kind::Int(min, max) => {
                value.is_empty() || (value.iter().all(u8::is_ascii_digit) && {
                    let n = php::str_to_int(&value);
                    n >= min && n <= max
                })
            }
            Kind::Text => true,
        };
        if ok {
            match clean.iter_mut().find(|(ck, _)| *ck == key) {
                Some(slot) => slot.1 = value,
                None => clean.push((key, value)),
            }
        }
    }
    ksorted(clean)
}

/// `Strategy::stringMap($value)` over an `array`-cast column: only string keys with string values survive.
pub fn string_map(column: &Val) -> Map {
    let Val::Arr(a) = laravel::from_json(column) else { return vec![] };
    let mut m: Map = vec![];
    for (k, v) in a.iter() {
        if let (Key::Str(k), Val::Str(v)) = (k, v) {
            m.push((k.clone(), v.clone()));
        }
    }
    ksorted(m)
}

/// The value the previous console writes for an `array`-cast column holding this map (`json_encode`, `[]` when empty).
pub fn map_json(m: &Map) -> Result<Val, Fault> {
    let mut a = Arr::new();
    for (k, v) in m {
        a.set(Key::from_bytes(k), Val::Str(v.clone()));
    }
    php::json_encode(&Val::Arr(a)).map(|s| Val::str(&s)).ok_or_else(|| Fault::Other("json_encode failed".into()))
}

pub fn map_val(m: &Map) -> Val {
    let mut a = Arr::new();
    for (k, v) in m {
        a.set(Key::from_bytes(k), Val::Str(v.clone()));
    }
    Val::Arr(a)
}

/// `Strategy::find($id)` (soft-deleted strategies excluded).
fn find(c: &Connection, id: i64) -> Result<Option<Row>, Fault> {
    db::first(c, r#"select * from "strategies" where "strategies"."id" = ? and "strategies"."deleted_at" is null limit 1"#, &[P(Val::Int(id))])
}

/// `$strategy->configOptions()`: nothing when disabled.
fn config_options(s: &Row) -> Map {
    if !s.val("enabled").to_bool() {
        return vec![];
    }
    match laravel::from_json(&s.val("options")) {
        Val::Arr(a) => sanitize_options(&a),
        _ => vec![],
    }
}

/// `Strategy::resolve($device)`: device > owner > device group > default; disabled strategies are skipped.
pub fn resolve(c: &Connection, device: &Row) -> Result<Option<i64>, Fault> {
    let any = db::first(c, r#"select exists(select * from "strategies" where "enabled" = ? and "strategies"."deleted_at" is null) as "exists""#, &[P(Val::Int(1))])?;
    if !any.map_or(false, |r| r.val("exists").to_bool()) {
        return Ok(None);
    }
    let levels: [(&str, &str, Val); 3] = [
        ("device_strategy", "device_id", device.val("id")),
        ("strategy_user", "user_id", device.val("user_id")),
        ("device_group_strategy", "device_group_id", device.val("device_group_id")),
    ];
    for (table, column, target) in levels {
        if matches!(target, Val::Null) {
            continue;
        }
        let sql = format!(
            r#"select "strategies"."id" from "{table}" inner join "strategies" on "strategies"."id" = "{table}"."strategy_id" where "{table}"."{column}" = ? and "strategies"."enabled" = ? limit 1"#
        );
        if let Some(r) = db::first(c, &sql, &[P(target), P(Val::Int(1))])? {
            if !r.is_null("id") {
                return Ok(Some(r.val("id").to_int()));
            }
        }
    }
    let d = db::first(c, r#"select "id" from "strategies" where "is_default" = ? and "enabled" = ? and "strategies"."deleted_at" is null limit 1"#, &[P(Val::Int(1)), P(Val::Int(1))])?;
    Ok(d.filter(|r| !r.is_null("id")).map(|r| r.val("id").to_int()))
}

/// `Strategy::syncResolvedFor($device)`
pub fn sync_resolved_for(c: &Connection, device: &mut Row, now: &str) -> Result<(), Fault> {
    let resolved = resolve(c, device)?;
    if device.val("strategy_id_resolved").to_int() != resolved.unwrap_or(0) {
        let v = resolved.map_or(Val::Null, Val::Int);
        db::update_dirty(c, "devices", device, vec![("strategy_id_resolved", v, Cast::Plain)], now)?;
    }
    Ok(())
}

pub const ACK_REFRESH_SECONDS: i64 = 60;

/// What the heartbeat answer carries: `modified_at` and `strategy.config_options`.
pub struct Delivery {
    pub modified_at: i64,
    pub options: Map,
}

/// `Strategy::deliveryFor($device, $echoedVersion)`, with the device writes it makes.
pub fn delivery_for(c: &Connection, device: &mut Row, echoed: i64, now_unix: i64) -> Result<Option<Delivery>, Fault> {
    let now = laravel::ts(now_unix);
    if device.val("status") != Val::str("active") {
        return Ok(None);
    }
    let strategy = match device.val("strategy_id_resolved") {
        Val::Null => None,
        v => find(c, v.to_int())?,
    };
    let desired = strategy.as_ref().map(config_options).unwrap_or_default();
    let mut acked = string_map(&device.val("strategy_acked_options"));
    let mut version = match device.val("strategy_version") {
        Val::Null => None,
        v => Some(v.to_int()),
    };
    if desired.is_empty() && acked.is_empty() && version.is_none() {
        return Ok(None);
    }
    let sent = string_map(&device.val("strategy_options"));

    if version.is_some() && Some(echoed) == version {
        let stale = match device.val("strategy_acked_at") {
            Val::Null => true,
            v => laravel::parse_ts(&v).ok_or_else(|| Fault::Other("unparsable strategy_acked_at".into()))? < now_unix - ACK_REFRESH_SECONDS,
        };
        if acked != sent || stale {
            db::update_dirty(
                c,
                "devices",
                device,
                vec![("strategy_acked_options", map_json(&sent)?, Cast::Json), ("strategy_acked_at", Val::str(&now), Cast::Date)],
                &now,
            )?;
        }
        acked = sent.clone();
    }

    if version.is_none() || sent != desired {
        let v = std::cmp::max(now_unix, version.unwrap_or(0).saturating_add(1));
        version = Some(v);
        db::update_dirty(
            c,
            "devices",
            device,
            vec![("strategy_version", Val::Int(v), Cast::Plain), ("strategy_options", map_json(&desired)?, Cast::Json), ("strategy_sent_at", Val::str(&now), Cast::Date)],
            &now,
        )?;
    }
    let version = version.unwrap_or(0);

    if echoed == version {
        let enforce = strategy.as_ref().map_or(false, |s| s.val("enforce").to_bool());
        if !enforce || desired.is_empty() {
            return Ok(None);
        }
        return Ok(Some(Delivery { modified_at: version, options: desired }));
    }

    let mut wire = desired.clone();
    for (k, _) in acked.iter().chain(sent.iter()) {
        if !wire.iter().any(|(w, _)| w == k) {
            wire.push((k.clone(), vec![]));
        }
    }
    let wire = ksorted(wire);
    if wire.is_empty() {
        return Ok(None);
    }
    if device.is_null("strategy_sent_at") {
        db::update_dirty(c, "devices", device, vec![("strategy_sent_at", Val::str(&now), Cast::Date)], &now)?;
    }
    Ok(Some(Delivery { modified_at: version, options: wire }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arr(json: &str) -> Arr {
        match php::json_decode(json.as_bytes(), &php::JsonOpts::default()) {
            Some(Val::Arr(a)) => a,
            _ => panic!("not an object"),
        }
    }

    #[test]
    fn sanitize_drops_unknown_keys_and_bad_values() {
        let m = sanitize_options(&arr(
            r#"{"2fa":"x","stop-service":"Y","enable-audio":true,"direct-server":"N","access-mode":"bogus",
               "auto-disconnect-timeout":30.0,"temporary-password-length":8,"whitelist":" 10.0.0.0/8 ","enable-camera":null,"enable-tunnel":["Y"]}"#,
        ));
        let got: Vec<(String, String)> = m.into_iter().map(|(k, v)| (String::from_utf8(k).unwrap(), String::from_utf8(v).unwrap())).collect();
        let want: Vec<(String, String)> = [
            ("auto-disconnect-timeout", "30"),
            ("direct-server", "N"),
            ("enable-audio", "Y"),
            ("temporary-password-length", "8"),
            ("whitelist", "10.0.0.0/8"),
        ]
        .iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
        assert_eq!(got, want);
        let m = sanitize_options(&arr(r#"{"auto-disconnect-timeout":"0"}"#));
        assert!(m.is_empty());
        let m = sanitize_options(&arr(r#"{"auto-disconnect-timeout":"+5"}"#));
        assert!(m.is_empty());
    }

    #[test]
    fn string_map_keeps_string_pairs_only() {
        let m = string_map(&Val::str(r#"{"b":"1","a":"2","5":"x","c":3}"#));
        assert_eq!(m, vec![(b"a".to_vec(), b"2".to_vec()), (b"b".to_vec(), b"1".to_vec())]);
        assert!(string_map(&Val::str("[]")).is_empty());
        assert!(string_map(&Val::Null).is_empty());
        assert_eq!(map_json(&vec![]).unwrap(), Val::str("[]"));
        assert_eq!(map_json(&vec![(b"w".to_vec(), b"1.0/8".to_vec())]).unwrap(), Val::str(r#"{"w":"1.0\/8"}"#));
    }
}
