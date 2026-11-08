//! `App\Services\DuplicateDevices` (issue #91) and `Device::platform()`, for the admin API's `possible_duplicates`.
//!
//! The same two grouped queries and one fetch as the previous console; the pairing, the dismissals and the ordering of the twins are
//! The previous console's, rule for rule. Only rows in the scope take part (the admin API passes the approved, not trashed devices).

use crate::laravel;
use crate::php::{self, Fault, Val};
use crate::sqlite::{self as db, Row, P};
use regex::Regex;
use rusqlite::Connection;
use std::collections::HashMap;

const HOST_SQL: &str = "LOWER(TRIM(devices.hostname))";
const USER_SQL: &str = "LOWER(TRIM(devices.username))";
const COLUMNS: &str = r#""devices"."id", "devices"."rustdesk_id", "devices"."uuid", "devices"."hostname", "devices"."username", "devices"."os", "devices"."alias", "devices"."last_online_at", "devices"."created_at""#;
/// `Device::query()->approved()`: the soft-delete scope and `status = 'active'`.
const SCOPE: &str = r#""status" = 'active' and "devices"."deleted_at" is null"#;

const GENERIC_HOSTNAMES: &[&str] = &[
    "localhost", "localhost.localdomain", "localdomain", "ubuntu", "debian", "raspberrypi", "kali", "fedora", "centos", "archlinux", "linux",
    "android", "windows", "pc", "desktop", "laptop", "computer", "workstation", "server", "host", "user-pc", "admin-pc", "vm", "unknown",
    "default", "none", "(none)",
];

/// How long both rows must report in side by side to count as two machines (CortenDesk 1.23.0, issue #159).
const CONCURRENT_SECONDS: i64 = 3600;

fn strength(reason: &str) -> u8 {
    if reason == "uuid" { 2 } else { 1 }
}

/// `Device::platform()`: windows, macos, android, ios, linux or unknown, from the OS string.
pub fn platform(os: &Val) -> String {
    let os = match os {
        Val::Null => String::new(),
        v => String::from_utf8_lossy(&v.to_php_string().unwrap_or_default()).to_ascii_lowercase(),
    };
    let has = |s: &str| os.contains(s);
    if has("windows") {
        "windows"
    } else if has("mac") || has("darwin") {
        "macos"
    } else if has("android") {
        "android"
    } else if has("ios") {
        "ios"
    } else if has("linux") || has("ubuntu") || has("debian") || has("fedora") || has("arch") || has("centos") {
        "linux"
    } else {
        "unknown"
    }
    .to_string()
}

/// `mb_strtolower(trim($value))`
fn normalize(v: &Val) -> Result<String, Fault> {
    let s = v.to_php_string()?;
    Ok(String::from_utf8_lossy(php::trim(&s)).to_lowercase())
}

pub fn is_generic_hostname(hostname: &str) -> bool {
    static PATTERN: once_cell::sync::Lazy<Regex> =
        once_cell::sync::Lazy::new(|| Regex::new(r"^(macbook(-?pro|-?air)?|imac(-?pro)?|mac-?(mini|studio|pro)|iphone|ipad)(-\d+)?(\.local)?$").unwrap());
    let host = hostname.trim_matches([' ', '\t', '\n', '\r', '\0', '\x0b']).to_lowercase();
    host.is_empty() || GENERIC_HOSTNAMES.contains(&host.as_str()) || PATTERN.is_match(&host)
}

/// Grouping key for the hostname signal: hostname, OS user and platform, or None.
fn match_key(d: &Row) -> Result<Option<Vec<u8>>, Fault> {
    let host = normalize(&d.val("hostname"))?;
    let user = normalize(&d.val("username"))?;
    let platform = platform(&d.val("os"));
    if host.is_empty() || user.is_empty() || is_generic_hostname(&host) || platform == "android" || platform == "ios" {
        return Ok(None);
    }
    let mut k = host.into_bytes();
    k.push(0);
    k.extend_from_slice(user.as_bytes());
    k.push(0);
    k.extend_from_slice(platform.as_bytes());
    Ok(Some(k))
}

fn ts_of(d: &Row) -> Result<i64, Fault> {
    match d.val("last_online_at") {
        Val::Null => Ok(0),
        v => laravel::parse_ts(&v).ok_or_else(|| Fault::Other("unparsable devices.last_online_at".into())),
    }
}

pub struct Duplicates {
    /// device id -> [(twin id, reason)] in the order the previous console's array holds them
    pairs: HashMap<i64, Vec<(i64, &'static str)>>,
    /// the keys of `pairs` in the previous console's array order (first pairing first)
    order: Vec<i64>,
    devices: HashMap<i64, Row>,
}

/// The viewer's part of `Device::visibleTo` (the owner/group condition), as an extra `and (...)`.
pub type Scope<'a> = Option<(&'a str, &'a [P])>;

impl Duplicates {
    fn empty() -> Duplicates {
        Duplicates { pairs: HashMap::new(), order: vec![], devices: HashMap::new() }
    }

    /// Duplicates among every approved device (`DuplicateDevices::in`).
    pub fn all(c: &Connection) -> Result<Duplicates, Fault> {
        Duplicates::in_scope(c, None)
    }

    /// Duplicates among the devices in a viewer's scope: `extra` is the ownership condition of `visibleTo`.
    pub fn in_scope(c: &Connection, extra: Scope) -> Result<Duplicates, Fault> {
        let (xs, xp): (String, Vec<P>) = match extra {
            Some((sql, p)) => (format!(" and {sql}"), p.to_vec()),
            None => (String::new(), vec![]),
        };
        let uuids: Vec<Vec<u8>> = db::rows(
            c,
            &format!(r#"select "devices"."uuid" from "devices" where {SCOPE}{xs} and "devices"."uuid" != ? group by "devices"."uuid" having COUNT(*) > 1"#),
            &xp.iter().cloned().chain(std::iter::once(P(Val::str("")))).collect::<Vec<_>>(),
        )?
        .into_iter()
        .map(|r| r.val("uuid").to_php_string())
        .collect::<Result<_, _>>()?;

        let host_rows = db::rows(
            c,
            &format!(
                r#"select {HOST_SQL} as host_key from "devices" where {SCOPE}{xs} and "devices"."hostname" is not null and "devices"."username" is not null and {USER_SQL} != '' group by {HOST_SQL}, {USER_SQL} having COUNT(*) > 1"#
            ),
            &xp,
        )?;
        let mut hosts: Vec<Vec<u8>> = vec![];
        for r in host_rows {
            let h = r.val("host_key").to_php_string()?;
            if is_generic_hostname(&String::from_utf8_lossy(&h)) || hosts.contains(&h) {
                continue;
            }
            hosts.push(h);
        }
        if uuids.is_empty() && hosts.is_empty() {
            return Ok(Duplicates::empty());
        }
        let mut conds: Vec<String> = vec![];
        let mut params: Vec<P> = xp.clone();
        let mut tail: Vec<P> = vec![];
        if !uuids.is_empty() {
            conds.push(format!(r#""devices"."uuid" in ({})"#, vec!["?"; uuids.len()].join(", ")));
            tail.extend(uuids.into_iter().map(|u| P(Val::Str(u))));
        }
        if !hosts.is_empty() {
            conds.push(format!("{HOST_SQL} in ({})", vec!["?"; hosts.len()].join(", ")));
            tail.extend(hosts.into_iter().map(|h| P(Val::Str(h))));
        }
        params.extend(tail);
        let rows = db::rows(c, &format!(r#"select {COLUMNS} from "devices" where {SCOPE}{xs} and ({}) "#, conds.join(" or ")), &params)?;
        Duplicates::build(c, rows)
    }

    /// Duplicates of one device among the approved devices (`DuplicateDevices::of`).
    pub fn of(c: &Connection, device: &Row) -> Result<Duplicates, Fault> {
        Duplicates::of_scope(c, device, None)
    }

    /// Duplicates of one device among the devices in a viewer's scope (`DuplicateDevices::of($device, $scope)`).
    pub fn of_scope(c: &Connection, device: &Row, extra: Scope) -> Result<Duplicates, Fault> {
        let (xs, xp): (String, Vec<P>) = match extra {
            Some((sql, p)) => (format!(" and {sql}"), p.to_vec()),
            None => (String::new(), vec![]),
        };
        if !device.is_null("deleted_at") {
            return Ok(Duplicates::empty());
        }
        let uuid = device.val("uuid").to_php_string()?;
        let host = match_key(device)?;
        if uuid.is_empty() && host.is_none() {
            return Ok(Duplicates::empty());
        }
        let mut conds: Vec<String> = vec![];
        let mut params: Vec<P> = xp;
        if !uuid.is_empty() {
            conds.push(r#""devices"."uuid" = ?"#.into());
            params.push(P(Val::Str(uuid)));
        }
        if host.is_some() {
            conds.push(format!("({HOST_SQL} = ? and {USER_SQL} = ?)"));
            params.push(P(Val::str(&normalize(&device.val("hostname"))?)));
            params.push(P(Val::str(&normalize(&device.val("username"))?)));
        }
        let rows = db::rows(c, &format!(r#"select {COLUMNS} from "devices" where {SCOPE}{xs} and ({}) "#, conds.join(" or ")), &params)?;
        // outside the scope (pending): nothing to say
        if !rows.iter().any(|r| r.id() == device.id()) {
            return Ok(Duplicates::empty());
        }
        Duplicates::build(c, rows)
    }

    fn build(c: &Connection, rows: Vec<Row>) -> Result<Duplicates, Fault> {
        let mut d = Duplicates::empty();
        for r in &rows {
            d.devices.insert(r.id(), r.clone());
        }
        // groupBy('uuid') over the rows whose uuid is not empty, groups in order of first appearance
        let mut by_uuid: Vec<(Vec<u8>, Vec<i64>)> = vec![];
        for r in &rows {
            let u = r.val("uuid").to_php_string()?;
            if u.is_empty() {
                continue;
            }
            match by_uuid.iter_mut().find(|(k, _)| *k == u) {
                Some((_, g)) => g.push(r.id()),
                None => by_uuid.push((u, vec![r.id()])),
            }
        }
        for (_, g) in &by_uuid {
            d.pair_up(g, "uuid");
        }
        let mut by_host: Vec<(Vec<u8>, Vec<i64>)> = vec![];
        for r in &rows {
            let Some(k) = match_key(r)? else { continue };
            match by_host.iter_mut().find(|(x, _)| *x == k) {
                Some((_, g)) => g.push(r.id()),
                None => by_host.push((k, vec![r.id()])),
            }
        }
        for (_, g) in &by_host {
            d.pair_up(g, "hostname_user");
        }
        d.drop_dismissed(c)?;
        Ok(d)
    }

    /// `DuplicateDevices::concurrent`: both rows reported in well after the later one appeared. A reinstalled machine stops
    /// reporting under its old ID, so two rows that both kept reporting are two machines (cloned from one image, they share a
    /// hardware ID and so a UUID). A row that never reported, or has no creation time, decides nothing.
    fn concurrent(&self, a: i64, b: i64) -> bool {
        let stamp = |id: i64, col: &str| self.devices.get(&id).and_then(|d| match d.val(col) {
            Val::Null => None,
            v => laravel::parse_ts(&v),
        });
        let (Some(seen_a), Some(seen_b), Some(born_a), Some(born_b)) =
            (stamp(a, "last_online_at"), stamp(b, "last_online_at"), stamp(a, "created_at"), stamp(b, "created_at"))
        else {
            return false;
        };
        seen_a.min(seen_b) > born_a.max(born_b) + CONCURRENT_SECONDS
    }

    fn pair_up(&mut self, group: &[i64], why: &'static str) {
        for i in 0..group.len() {
            for j in i + 1..group.len() {
                let (a, b) = (group[i], group[j]);
                if self.concurrent(a, b) {
                    continue;
                }
                let current = self.pairs.get(&a).and_then(|l| l.iter().find(|(o, _)| *o == b)).map(|(_, r)| *r);
                if current.map_or(true, |cur| strength(why) > strength(cur)) {
                    for (x, y) in [(a, b), (b, a)] {
                        if !self.pairs.contains_key(&x) {
                            self.order.push(x);
                        }
                        let list = self.pairs.entry(x).or_default();
                        match list.iter_mut().find(|(o, _)| *o == y) {
                            Some(slot) => slot.1 = why,
                            None => list.push((y, why)),
                        }
                    }
                }
            }
        }
    }

    fn drop_dismissed(&mut self, c: &Connection) -> Result<(), Fault> {
        if self.pairs.is_empty() {
            return Ok(());
        }
        let ids: Vec<i64> = self.pairs.keys().copied().collect();
        let marks = vec!["?"; ids.len()].join(", ");
        let sql = format!(r#"select "device_id", "other_device_id" from "device_duplicate_dismissals" where "device_id" in ({marks}) and "other_device_id" in ({marks})"#);
        let params: Vec<P> = ids.iter().chain(ids.iter()).map(|i| P(Val::Int(*i))).collect();
        for r in db::rows(c, &sql, &params)? {
            let (a, b) = (r.val("device_id").to_int(), r.val("other_device_id").to_int());
            for (x, y) in [(a, b), (b, a)] {
                if let Some(l) = self.pairs.get_mut(&x) {
                    l.retain(|(o, _)| *o != y);
                }
            }
        }
        self.pairs.retain(|_, l| !l.is_empty());
        let pairs = &self.pairs;
        self.order.retain(|k| pairs.contains_key(k));
        Ok(())
    }

    // ---- what the device pages ask (the model's own accessors) ----

    pub fn has(&self, id: i64) -> bool {
        self.pairs.contains_key(&id)
    }

    /// Every flagged device id, in the previous console's array order.
    pub fn ids(&self) -> Vec<i64> {
        self.order.clone()
    }

    pub fn count(&self) -> usize {
        self.pairs.len()
    }

    /// `twinsOf($id)`: (the twin, the reason, the label), strongest reason first, then most recently seen.
    pub fn twins_of(&self, id: i64) -> Result<Vec<(Row, &'static str, &'static str)>, Fault> {
        let mut twins: Vec<(u8, i64, Row, &'static str)> = vec![];
        for (other, reason) in self.pairs.get(&id).map(|l| l.as_slice()).unwrap_or(&[]) {
            let Some(d) = self.devices.get(other) else { continue };
            twins.push((strength(reason), ts_of(d)?, d.clone(), reason));
        }
        twins.sort_by(|x, y| (y.0, y.1).cmp(&(x.0, x.1)));
        Ok(twins.into_iter().map(|t| (t.2, t.3, if t.3 == "uuid" { "same device UUID" } else { "same hostname and user" })).collect())
    }

    /// "Possible duplicate of 123 (same device UUID)" for a tooltip.
    pub fn summary(&self, id: i64) -> Result<String, Fault> {
        let parts: Vec<String> = self
            .twins_of(id)?
            .iter()
            .map(|(d, _, label)| format!("{} ({label})", String::from_utf8_lossy(&d.val("rustdesk_id").to_php_string().unwrap_or_default())))
            .collect();
        Ok(if parts.is_empty() { String::new() } else { format!("Possible duplicate of {}", parts.join(", ")) })
    }

    /// `clusterOrder()`: flagged ids mapped to the position of their connected cluster, the most recently seen first.
    pub fn cluster_order(&self) -> Result<HashMap<i64, usize>, Fault> {
        let mut parent: HashMap<i64, i64> = HashMap::new();
        fn find(parent: &mut HashMap<i64, i64>, x: i64) -> i64 {
            let p = *parent.entry(x).or_insert(x);
            if p == x {
                x
            } else {
                let r = find(parent, p);
                parent.insert(x, r);
                r
            }
        }
        for a in &self.order {
            for (b, _) in &self.pairs[a] {
                let (ra, rb) = (find(&mut parent, *a), find(&mut parent, *b));
                if ra != rb {
                    parent.insert(ra, rb);
                }
            }
        }
        let mut clusters: Vec<(i64, Vec<i64>)> = vec![];
        for id in &self.order {
            let root = find(&mut parent, *id);
            match clusters.iter_mut().find(|(r, _)| *r == root) {
                Some((_, ids)) => ids.push(*id),
                None => clusters.push((root, vec![*id])),
            }
        }
        let mut list: Vec<Vec<i64>> = clusters.into_iter().map(|(_, ids)| ids).collect();
        let mut latest: HashMap<usize, i64> = HashMap::new();
        for (i, ids) in list.iter().enumerate() {
            let mut m = 0;
            for id in ids {
                m = m.max(self.devices.get(id).map(ts_of).transpose()?.unwrap_or(0));
            }
            latest.insert(i, m);
        }
        let mut idx: Vec<usize> = (0..list.len()).collect();
        idx.sort_by(|x, y| latest[y].cmp(&latest[x]).then_with(|| list[*x].iter().min().cmp(&list[*y].iter().min())));
        let mut out = HashMap::new();
        for (pos, i) in idx.into_iter().enumerate() {
            for id in std::mem::take(&mut list[i]) {
                out.insert(id, pos);
            }
        }
        Ok(out)
    }

    /// `rustdeskIdsOf($id)`: the twins' RustDesk ids, strongest reason first, then most recently seen.
    pub fn rustdesk_ids_of(&self, id: i64) -> Result<Vec<Val>, Fault> {
        let mut twins: Vec<(u8, i64, Vec<u8>)> = vec![];
        for (other, reason) in self.pairs.get(&id).map(|l| l.as_slice()).unwrap_or(&[]) {
            let Some(d) = self.devices.get(other) else { continue };
            twins.push((strength(reason), ts_of(d)?, d.val("rustdesk_id").to_php_string()?));
        }
        // usort is stable: [$y.strength, $y.ts] <=> [$x.strength, $x.ts]
        twins.sort_by(|x, y| (y.0, y.1).cmp(&(x.0, x.1)));
        Ok(twins.into_iter().map(|t| Val::Str(t.2)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_like_the_model() {
        for (os, p) in [
            ("windows / Windows 10", "windows"),
            ("Mac OS 14", "macos"),
            ("Darwin", "macos"),
            ("Android 13", "android"),
            ("iOS 17", "ios"),
            ("Ubuntu 22.04", "linux"),
            ("freebsd", "unknown"),
        ] {
            assert_eq!(platform(&Val::str(os)), p, "{os}");
        }
        assert_eq!(platform(&Val::Null), "unknown");
    }

    #[test]
    fn generic_hostnames() {
        for g in ["localhost", "MacBook-Pro", "macbook-air-2.local", "iPhone", "imac-pro", "mac-mini", "UBUNTU", "  pc "] {
            assert!(is_generic_hostname(g), "{g}");
        }
        for s in ["RECEPTION", "desktop-ab12cd3", "macbook-pro-of-ana", "iphone-x"] {
            assert!(!is_generic_hostname(s), "{s}");
        }
    }
}
