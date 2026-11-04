// Added for HTE Remote on 2026-10-16. See HTE.md.
// This file is part of a modified version of cortendesk-server, distributed
// under the AGPL-3.0 like the original.

//! Per-person reach, enforced where sessions start.
//!
//! The console already decides which devices a signed-in person *sees*
//! (their own devices plus the device groups granted to them or to their user
//! groups; administrators see everything). With this module the same rule
//! decides which devices they may *reach*: the policy hbbs pulls every few
//! seconds carries, per console user, the set of devices they may start a
//! session to, and `check` refuses any other target.
//!
//! Who is asking comes from `policy::check_initiator`, which already works it
//! out: the console's web-client ticket names the user in its subject
//! (`cdw1.<expiry>.web-<user id>.<hmac>`), a signed-in client's access token
//! maps to a user through `token_users`, and an initiator found by IP alone is
//! nobody. While enforcement is off nothing here refuses anything.
//!
//! Refusals are reported to the console in batches (`POST
//! /api/server/refusals`), one per person and target per minute, so a
//! client's retries make one alarm row, not ten.

use hbb_common::log;
use serde_derive::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const DENY_SCOPE: &str =
    "You are not given access to this device. Ask your administrator to add it to your scope.";
pub const DENY_NOBODY: &str =
    "Sign in to the console with your account to start sessions. Only signed-in people may reach devices on this server.";

/// Report the same person failing on the same target once in this long.
const REPEAT_WINDOW: Duration = Duration::from_secs(60);
const MAX_PENDING: usize = 2000;
const MAX_BATCH: usize = 200;

/// One console user, as the console sends it.
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct ScopeUser {
    /// The console username, for the log line and the alarm.
    #[serde(default)]
    pub name: String,
    /// Administrators: every device.
    #[serde(default)]
    pub all: bool,
    /// Device ids this person may reach when `all` is false.
    #[serde(default)]
    pub devices: HashSet<String>,
}

/// The `scope` block of the policy. Absent or empty means off.
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Scope {
    #[serde(default)]
    pub enforce: bool,
    /// console user id -> that person.
    #[serde(default)]
    pub users: HashMap<String, ScopeUser>,
    /// sha256 hex of a console access token -> console user id.
    #[serde(default)]
    pub token_users: HashMap<String, String>,
}

/// Who is asking, as `policy::check_initiator` found them.
pub enum Person<'a> {
    /// A valid console web-client ticket (the whole token).
    Web(&'a str),
    /// A signed-in client: sha256 hex of its access token.
    Token(&'a str),
    /// Found by IP only, or not at all.
    Nobody,
}

impl Scope {
    /// Appended to the `policy` admin command's line.
    pub fn describe(&self) -> String {
        format!(
            " scope={} people={}",
            if self.enforce { "on" } else { "off" },
            self.users.len()
        )
    }

    fn user_of(&self, person: &Person) -> Option<(&String, &ScopeUser)> {
        let uid = match person {
            Person::Web(ticket) => web_user(ticket)?,
            Person::Token(hash) => self.token_users.get(*hash)?.as_str(),
            Person::Nobody => return None,
        };
        self.users.get_key_value(uid)
    }
}

/// `cdw1.<expiry>.web-<user id>.<hmac>` -> the user id. The signature and
/// expiry are the caller's business (`policy::ticket_valid`).
pub fn web_user(ticket: &str) -> Option<&str> {
    ticket.split('.').nth(2)?.strip_prefix("web-")
}

/// May `person`, sitting at `from_device`, reach `target`? `ip` is the TCP
/// peer address, for the report only.
pub fn check(
    scope: &Scope,
    person: &Person,
    target: &str,
    ip: IpAddr,
    from_device: &str,
) -> Result<(), &'static str> {
    if !scope.enforce {
        return Ok(());
    }
    let Some((uid, user)) = scope.user_of(person) else {
        if note_refusal("", "", from_device, target, ip, "not signed in") {
            log::info!("Scope: nobody signed in at {from_device} ({ip}) may not reach {target}");
        }
        return Err(DENY_NOBODY);
    };
    if user.all || user.devices.contains(target) {
        return Ok(());
    }
    if note_refusal(uid, &user.name, from_device, target, ip, "outside scope") {
        log::info!(
            "Scope: {} (user {uid}) at {from_device} ({ip}) may not reach {target}",
            user.name
        );
    }
    Err(DENY_SCOPE)
}

/// HTE relay gate: is this `RelayResponse` really the target answering? It
/// must name a registered device that may receive sessions, and come from the
/// address that device registered from.
pub async fn target_answers(pm: &crate::peer::PeerMap, id: &str, from: IpAddr) -> bool {
    fn norm(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        }
    }
    if id.is_empty() || crate::policy::check_target(id).is_err() {
        return false;
    }
    let Some(peer) = pm.get_in_memory(id).await else { return false };
    // A device registered over TCP or WebSocket (1.3.0) is known by its stream's client address.
    let registered = {
        let peer = peer.read().await;
        match peer.stream.as_ref().filter(|s| s.alive()) {
            Some(stream) => stream.connection.addr.ip(),
            None => peer.socket_addr.ip(),
        }
    };
    norm(registered) == norm(from)
}

#[derive(Debug, Serialize, Clone)]
struct Refusal {
    user_id: String,
    user_name: String,
    from: String,
    to: String,
    ip: String,
    reason: String,
    at: u64,
}

#[derive(Default)]
struct Refusals {
    pending: Vec<Refusal>,
    recent: HashMap<(String, String, String), Instant>,
}

lazy_static::lazy_static! {
    static ref REFUSALS: Mutex<Refusals> = Default::default();
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Queue a refusal for the console. False when the same person failed on the
/// same target within the window (a retry), or the queue is full.
fn note_refusal(uid: &str, name: &str, from: &str, to: &str, ip: IpAddr, reason: &str) -> bool {
    let Ok(mut r) = REFUSALS.lock() else { return false };
    let key = (uid.to_owned(), from.to_owned(), to.to_owned());
    if let Some(tm) = r.recent.get(&key) {
        if tm.elapsed() < REPEAT_WINDOW {
            return false;
        }
    }
    r.recent.retain(|_, tm| tm.elapsed() < REPEAT_WINDOW);
    r.recent.insert(key, Instant::now());
    if r.pending.len() >= MAX_PENDING {
        return false;
    }
    r.pending.push(Refusal {
        user_id: uid.to_owned(),
        user_name: name.to_owned(),
        from: from.to_owned(),
        to: to.to_owned(),
        ip: match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        }
        .to_string(),
        reason: reason.to_owned(),
        at: now_secs(),
    });
    true
}

/// Send queued refusals to the console. Called from the policy loop; kept
/// for the next round when the console does not answer.
pub async fn report(client: &reqwest::Client, url: &str, secret: &str) {
    let batch: Vec<Refusal> = match REFUSALS.lock() {
        Ok(mut r) => {
            let n = r.pending.len().min(MAX_BATCH);
            r.pending.drain(..n).collect()
        }
        Err(_) => return,
    };
    if batch.is_empty() {
        return;
    }
    let ok = client
        .post(format!("{url}/api/server/refusals"))
        .bearer_auth(secret)
        .json(&serde_json::json!({ "refusals": batch }))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);
    if !ok {
        log::debug!("Scope: refusal report failed, retrying next round");
        if let Ok(mut r) = REFUSALS.lock() {
            let room = MAX_PENDING.saturating_sub(r.pending.len());
            let mut keep = batch;
            keep.truncate(room);
            keep.append(&mut r.pending);
            r.pending = keep;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> Scope {
        let mut users = HashMap::new();
        users.insert(
            "7".to_owned(),
            ScopeUser { name: "mperez".into(), all: false, devices: ["t1".to_owned()].into() },
        );
        users.insert("8".to_owned(), ScopeUser { name: "jdoe".into(), all: true, devices: Default::default() });
        let mut token_users = HashMap::new();
        token_users.insert("hash-7".to_owned(), "7".to_owned());
        Scope { enforce: true, users, token_users }
    }

    fn ip() -> IpAddr {
        "10.0.0.9".parse().unwrap()
    }

    #[test]
    fn web_ticket_subject_names_the_user() {
        assert_eq!(web_user("cdw1.1700000000.web-12.abcd"), Some("12"));
        assert_eq!(web_user("cdw1.1700000000.other-12.abcd"), None);
        assert_eq!(web_user("garbage"), None);
    }

    #[test]
    fn off_means_everything_passes() {
        let s = Scope::default();
        assert!(check(&s, &Person::Nobody, "t9", ip(), "").is_ok());
        assert!(check(&s, &Person::Token("unknown"), "t9", ip(), "d").is_ok());
    }

    #[test]
    fn a_person_reaches_their_devices_and_nothing_else() {
        let s = scope();
        assert!(check(&s, &Person::Token("hash-7"), "t1", ip(), "d7").is_ok());
        assert_eq!(check(&s, &Person::Token("hash-7"), "t2", ip(), "d7"), Err(DENY_SCOPE));
        assert!(check(&s, &Person::Web("cdw1.1.web-8.x"), "t2", ip(), "web").is_ok());
        assert_eq!(check(&s, &Person::Web("cdw1.1.web-7.x"), "t2", ip(), "web"), Err(DENY_SCOPE));
        assert_eq!(check(&s, &Person::Token("hash-unknown"), "t1", ip(), "d"), Err(DENY_NOBODY));
        assert_eq!(check(&s, &Person::Nobody, "t1", ip(), "d"), Err(DENY_NOBODY));
    }

    #[test]
    fn a_retry_within_the_window_is_reported_once() {
        let s = scope();
        for _ in 0..3 {
            let _ = check(&s, &Person::Token("hash-7"), "unit-t3", ip(), "unit-d7");
        }
        let r = REFUSALS.lock().unwrap();
        let mine: Vec<_> = r.pending.iter().filter(|x| x.to == "unit-t3").collect();
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].user_name, "mperez");
        assert_eq!(mine[0].from, "unit-d7");
        assert_eq!(mine[0].reason, "outside scope");
    }
}
