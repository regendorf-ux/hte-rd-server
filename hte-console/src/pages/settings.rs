//! Settings (the previous console's `SettingsPage` and HTE Remote's `ScopeSettings`): one form, eight tabs, and the same rows in `settings`.
//!
//! Every tab is rendered into the one form (a tab link only shows its pane), so Save writes what every tab holds, as
//! `SettingsPage::save()` does, and an edit on one tab survives a visit to another. A secret (the SSO client secret, the
//! SMTP password, the three Apprise transport values) is write-only: the page never carries one back, not even into a
//! page that failed validation; a blank field keeps the stored value, a filled one is stored with `Crypt::encryptString`
//! (the APP_KEY's AES-256-CBC payload), and only "is one stored" reaches a template.
//!
//! Prune now and the Backups tab are in `backups`, the API tokens page in `api_tokens`. Not ported here, and shown as
//! not available: the Test connection, Send test email and Send test notification buttons (they call out over the
//! network, which a handler holding the database lock must not do).

use super::kit::*;
use super::{Ctx, Reply, Req};
use crate::php::{self, Arr, Fault, Key, Val};
use crate::sqlite::{self as db, Row, P};
use crate::validate::{self, Rule};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

const TABS: &[(&str, &str, &str)] = &[
    ("server", "ri-server-line", "Server"),
    ("client", "ri-download-2-line", "Client Setup"),
    ("security", "ri-shield-keyhole-line", "Security"),
    ("sso", "ri-shield-user-line", "SSO"),
    ("email", "ri-mail-send-line", "Email"),
    ("notifications", "ri-notification-3-line", "Notifications"),
    ("maintenance", "ri-database-2-line", "Maintenance"),
    ("backups", "ri-archive-line", "Backups"),
];

/// `AppriseNotifications::EVENTS` (the order the page lists them in).
const EVENTS: &[(&str, &str)] = &[
    ("device.offline", "Device offline"),
    ("device.online", "Device recovered"),
    ("device.pending_approval", "Device pending approval"),
    ("console.login_failed", "Failed console login"),
    ("security.alarm", "Security alarm"),
    ("remote_connection.failure", "Repeated remote connection failure"),
    ("backup.completed", "Backup completed"),
    ("backup.failed", "Backup or off-site copy failed"),
];
const SCOPED_EVENTS: &[&str] = &["device.offline", "device.online"];
const MAX_ATTEMPTS: i64 = 3;
/// `Passwords::DAY_CHOICES`
const DAY_CHOICES: &[(i64, &str)] = &[(7, "Every 7 days"), (30, "Every 30 days"), (90, "Every 90 days"), (0, "Only when someone loses access")];

const STRINGS: &[&str] = &[
    "id_server", "relay_server", "public_key", "rdgen_url", "client_url_scheme", "server_access_mode", "oidc_discovery_url", "oidc_public_base_url", "oidc_client_id", "oidc_scopes",
    "oidc_button_label", "oidc_new_user_policy", "oidc_allowed_domains", "smtp_host", "smtp_encryption", "smtp_username", "smtp_from_address", "smtp_from_name", "apprise_mode",
    "online_window", "log_retention_days", "default_device_group_id", "oidc_default_group_id", "smtp_port", "email_trusted_device_days", "apprise_cooldown_minutes",
    "apprise_offline_grace_minutes", "hte_password_days", "web_client_ice_servers",
];
const BOOLS: &[&str] = &[
    "downloads_on_login", "require_device_approval", "auto_approve_signed_in", "server_ip_match", "hte_scope_enforce", "hte_passwords", "two_factor_required", "two_factor_required_admins",
    "web_client_webrtc", "email_login_verification", "oidc_enabled", "oidc_default_admin", "oidc_require_verified_email", "oidc_logout_enabled", "oidc_disable_local_login", "smtp_enabled", "apprise_enabled",
];
/// Write-only inputs: read from a post, never from the database, never given back.
const SECRETS: &[&str] = &["oidc_client_secret", "smtp_password", "apprise_endpoint", "apprise_config_key", "apprise_urls"];

type Values = Map<String, Value>;

fn suffix(event: &str) -> String {
    event.replace('.', "_")
}

fn txt(c: &Connection, key: &str, default: &str) -> Result<String, Fault> {
    Ok(lossy(&db::setting(c, key, default)?))
}

fn on(c: &Connection, key: &str) -> Result<bool, Fault> {
    Ok(db::setting(c, key, "0")? == b"1")
}

/// `Setting::put($key, $value)`: an unchanged value writes nothing.
fn put(ctx: &Ctx, c: &Connection, key: &str, value: &str) -> Result<(), Fault> {
    crate::backup::put_setting(c, key, value, ctx.now).map_err(Fault::Other)
}

/// `webclient_webrtc`: unlike CortenDesk (on unless turned off) HTE Remote has it OFF until someone turns it on, because a direct
/// WebRTC session does not pass the relay (see `pages::webclient`).
pub(crate) fn webrtc_on(c: &Connection) -> Result<bool, Fault> {
    on(c, "webclient_webrtc")
}

fn bool_s(b: bool) -> &'static str {
    if b { "1" } else { "0" }
}

/// `Setting::server($name)`: the saved value when it is not blank, else the environment's.
pub(crate) fn server_value(c: &Connection, name: &str, envs: &[&str]) -> Result<String, Fault> {
    let saved = txt(c, name, "")?.trim().to_string();
    if !saved.is_empty() {
        return Ok(saved);
    }
    Ok(envs.iter().filter_map(|e| crate::envvar::var(e).ok()).map(|v| v.trim().to_string()).find(|v| !v.is_empty()).unwrap_or_default())
}

fn env_or(name: &str, default: &str) -> String {
    crate::envvar::var(name).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.to_string())
}

fn int_of(s: &str) -> i64 {
    php::str_to_int(s.trim().as_bytes())
}

/// The mount: what the page shows before anyone has typed anything.
fn load(ctx: &Ctx, c: &Connection) -> Result<(Values, Vec<(String, String)>), Fault> {
    let mut v = Values::new();
    let s = |v: &mut Values, k: &str, x: String| {
        v.insert(k.to_string(), json!(x));
    };
    let b = |v: &mut Values, k: &str, x: bool| {
        v.insert(k.to_string(), json!(x));
    };
    s(&mut v, "id_server", server_value(c, "id_server", &["HTE_CONSOLE_ID_SERVER", "HTE_REMOTE_ID_SERVER"])?);
    s(&mut v, "relay_server", server_value(c, "relay_server", &["HTE_CONSOLE_RELAY_SERVER", "HTE_REMOTE_RELAY_SERVER"])?);
    s(&mut v, "public_key", server_value(c, "public_key", &["HTE_CONSOLE_PUBLIC_KEY", "HTE_REMOTE_PUBLIC_KEY"])?);
    let window = txt(c, "online_window", &env_or("HTE_REMOTE_ONLINE_WINDOW", "60"))?;
    s(&mut v, "online_window", (if int_of(&window) == 0 { 60 } else { int_of(&window) }).to_string());
    s(&mut v, "rdgen_url", txt(c, "rdgen_url", &ctx.p.config.rdgen_default)?);
    s(&mut v, "client_url_scheme", scheme(c)?);
    // HTE: off until chosen (a direct session does not pass the relay)
    b(&mut v, "web_client_webrtc", webrtc_on(c)?);
    s(&mut v, "web_client_ice_servers", txt(c, "webclient_ice_servers", "")?);
    b(&mut v, "downloads_on_login", txt(c, "downloads_on_login", if truthy_env("HTE_REMOTE_DOWNLOADS_ON_LOGIN", true) { "1" } else { "0" })? == "1");
    s(&mut v, "log_retention_days", int_of(&txt(c, "log_retention_days", &env_or("HTE_REMOTE_LOG_RETENTION_DAYS", "365"))?).to_string());
    b(&mut v, "require_device_approval", on(c, "require_device_approval")?);
    b(&mut v, "auto_approve_signed_in", on(c, "auto_approve_signed_in")?);
    let default_group = int_of(&txt(c, "default_device_group_id", "0")?);
    let default_group = if default_group > 0 && find(c, "device_groups", default_group)?.is_some() { default_group } else { 0 };
    s(&mut v, "default_device_group_id", default_group.to_string());
    s(&mut v, "server_access_mode", server_mode(c)?);
    b(&mut v, "server_ip_match", on(c, "server_ip_match")?);
    b(&mut v, "hte_scope_enforce", on(c, "hte_scope_enforce")?);
    b(&mut v, "hte_passwords", on(c, "hte_pw_enabled")?);
    s(&mut v, "hte_password_days", crate::passwords_sweep::days(c)?.to_string());
    b(&mut v, "two_factor_required", on(c, "two_factor_required")?);
    b(&mut v, "two_factor_required_admins", on(c, "two_factor_required_admins")?);

    b(&mut v, "oidc_enabled", on(c, "oidc_enabled")?);
    s(&mut v, "oidc_discovery_url", txt(c, "oidc_discovery_url", "")?);
    s(&mut v, "oidc_public_base_url", txt(c, "oidc_public_base_url", "")?);
    s(&mut v, "oidc_client_id", txt(c, "oidc_client_id", "")?);
    s(&mut v, "oidc_scopes", txt(c, "oidc_scopes", "openid email profile")?);
    s(&mut v, "oidc_button_label", txt(c, "oidc_button_label", "")?);
    s(&mut v, "oidc_new_user_policy", txt(c, "oidc_new_user_policy", "deny")?);
    b(&mut v, "oidc_default_admin", on(c, "oidc_default_admin")?);
    s(&mut v, "oidc_default_group_id", int_of(&txt(c, "oidc_default_group_id", "0")?).to_string());
    s(&mut v, "oidc_allowed_domains", txt(c, "oidc_allowed_domains", "")?);
    b(&mut v, "oidc_require_verified_email", on(c, "oidc_require_verified_email")?);
    b(&mut v, "oidc_logout_enabled", on(c, "oidc_logout_enabled")?);
    b(&mut v, "oidc_disable_local_login", on(c, "oidc_disable_local_login")?);

    b(&mut v, "smtp_enabled", on(c, "smtp_enabled")?);
    s(&mut v, "smtp_host", txt(c, "smtp_host", "")?);
    let port = int_of(&txt(c, "smtp_port", "587")?);
    s(&mut v, "smtp_port", (if port == 0 { 587 } else { port }).to_string());
    s(&mut v, "smtp_encryption", txt(c, "smtp_encryption", "starttls")?);
    s(&mut v, "smtp_username", txt(c, "smtp_username", "")?);
    s(&mut v, "smtp_from_address", txt(c, "smtp_from_address", "")?);
    s(&mut v, "smtp_from_name", txt(c, "smtp_from_name", "")?);
    b(&mut v, "email_login_verification", on(c, "email_login_verification")?);
    let days = int_of(&txt(c, "email_trusted_device_days", "30")?);
    s(&mut v, "email_trusted_device_days", (if days == 0 { 30 } else { days }).to_string());

    b(&mut v, "apprise_enabled", on(c, "apprise_enabled")?);
    s(&mut v, "apprise_mode", (if txt(c, "apprise_delivery_mode", "config")? == "urls" { "urls" } else { "config" }).into());
    let cooldown = int_of(&txt(c, "apprise_cooldown_minutes", "15")?);
    s(&mut v, "apprise_cooldown_minutes", (if cooldown == 0 { 15 } else { cooldown }).to_string());
    s(&mut v, "apprise_offline_grace_minutes", int_of(&txt(c, "apprise_offline_grace_minutes", "0")?).to_string());
    for (event, _) in EVENTS {
        let x = suffix(event);
        b(&mut v, &format!("apprise_event_{x}"), on(c, &format!("apprise_event_{x}"))?);
        s(&mut v, &format!("apprise_scope_{x}"), (if txt(c, &format!("apprise_scope_{x}"), "all")? == "selected" { "selected" } else { "all" }).into());
        for kind in ["groups", "devices"] {
            let raw = txt(c, &format!("apprise_scope_{kind}_{x}"), "[]")?;
            let ids: Vec<i64> = serde_json::from_str::<Vec<Value>>(&raw).unwrap_or_default().iter().map(|i| i.as_i64().or_else(|| i.as_str().map(int_of)).unwrap_or(0)).filter(|i| *i != 0).collect();
            v.insert(format!("apprise_scope_{kind}_{x}"), json!(ids));
        }
    }
    let stored: Vec<(String, String)> = serde_json::from_str::<Value>(&txt(c, "relay_servers", "[]")?)
        .ok()
        .and_then(|j| j.as_array().cloned())
        .map(|a| a.iter().map(|r| (value_text(r.get("address")), value_text(r.get("geo")))).collect())
        .unwrap_or_default();
    Ok((v, stored))
}

fn value_text(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(true)) => "1".into(),
        _ => String::new(),
    }
}

fn truthy_env(name: &str, default: bool) -> bool {
    match crate::envvar::var(name) {
        Ok(v) => matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "on" | "yes"),
        Err(_) => default,
    }
}

/// `ClientLink::scheme()`
fn scheme(c: &Connection) -> Result<String, Fault> {
    let raw = txt(c, "client_url_scheme", &env_or("HTE_REMOTE_CLIENT_URL_SCHEME", "rustdesk"))?;
    let n = normalize_scheme(&raw);
    Ok(if n.is_empty() { "rustdesk".into() } else { n })
}

/// `ClientLink::normalize()`
fn normalize_scheme(v: &str) -> String {
    let s = v.trim().split(':').next().unwrap_or("").trim().to_lowercase();
    let ok = s.chars().next().map_or(false, |c| c.is_ascii_lowercase()) && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '+' | '.' | '-'));
    if ok { s } else { String::new() }
}

pub(crate) fn server_mode(c: &Connection) -> Result<String, Fault> {
    Ok(if txt(c, "server_access_mode", "open")? == "approved" { "approved" } else { "open" }.into())
}

/// The post, as `SettingsPage`'s public properties would hold it. A checkbox that is not sent is off.
fn from_body(b: &Body) -> (Values, Vec<(String, String)>) {
    let mut v = Values::new();
    for k in STRINGS.iter().chain(SECRETS.iter()) {
        v.insert((*k).into(), json!(b.get(k)));
    }
    for k in BOOLS {
        v.insert((*k).into(), json!(b.checked(k)));
    }
    for (event, _) in EVENTS {
        let x = suffix(event);
        v.insert(format!("apprise_event_{x}"), json!(b.checked(&format!("apprise_event_{x}"))));
        v.insert(format!("apprise_scope_{x}"), json!(if b.get(&format!("apprise_scope_{x}")) == "selected" { "selected" } else { "all" }));
        for kind in ["groups", "devices"] {
            let ids: Vec<i64> = b.ints(&format!("apprise_scope_{kind}_{x}[]")).into_iter().chain(b.ints(&format!("apprise_scope_{kind}_{x}"))).collect();
            let mut seen: Vec<i64> = vec![];
            for i in ids {
                if !seen.contains(&i) {
                    seen.push(i);
                }
            }
            v.insert(format!("apprise_scope_{kind}_{x}"), json!(seen));
        }
    }
    let (addr, geo) = (b.list("relay_address"), b.list("relay_geo"));
    let relays = (0..addr.len().max(geo.len())).map(|i| (addr.get(i).cloned().unwrap_or_default(), geo.get(i).cloned().unwrap_or_default())).collect();
    (v, relays)
}

fn vs(v: &Values, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

fn vb(v: &Values, k: &str) -> bool {
    v.get(k).and_then(|x| x.as_bool()).unwrap_or(false)
}

fn vids(v: &Values, k: &str) -> Vec<i64> {
    v.get(k).and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|i| i.as_i64()).collect()).unwrap_or_default()
}

/// A typed-int property's value for the validator: a number when it reads as one.
fn num(v: &Values, k: &str) -> Val {
    let t = vs(v, k);
    let t = t.trim();
    let neg = t.strip_prefix('-').unwrap_or(t);
    if !neg.is_empty() && neg.bytes().all(|b| b.is_ascii_digit()) {
        return Val::Int(t.parse().unwrap_or(0));
    }
    Val::str(&vs(v, k))
}

fn camel_to_snake(k: &str) -> String {
    let mut out = String::new();
    for ch in k.chars() {
        if ch.is_uppercase() {
            out.push('_');
            out.extend(ch.to_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// Which tab shows a validated field (`SettingsPage::tabForField`).
fn tab_for(field: &str) -> Option<&'static str> {
    let root = field.split('.').next().unwrap_or("");
    Some(match root {
        r if r.starts_with("oidc") => "sso",
        r if r.starts_with("smtp") => "email",
        r if r.starts_with("apprise") => "notifications",
        "logRetentionDays" => "maintenance",
        "twoFactorRequired" | "twoFactorRequiredAdmins" | "emailLoginVerification" | "emailTrustedDeviceDays" => "security",
        "idServer" | "relayServer" | "publicKey" | "onlineWindow" | "rdgenUrl" | "clientUrlScheme" | "downloadsOnLogin" | "relayServers" | "requireDeviceApproval" | "autoApproveSignedIn"
        | "defaultDeviceGroupId" | "serverAccessMode" | "serverIpMatch" | "webClientWebrtc" | "webClientIceServers" => "server",
        _ => return None,
    })
}

/// An error key as the template reads it: `idServer` -> `id_server`, `relayServers.2.geo` -> `relay_2_geo`.
fn error_key(k: &str) -> String {
    let parts: Vec<&str> = k.split('.').collect();
    if parts.len() == 3 && parts[0] == "relayServers" {
        return format!("relay_{}_{}", parts[1], parts[2]);
    }
    camel_to_snake(k)
}

/// `save()`'s `validate([...])`. Returns the first message per field, keyed as `tab_for` wants (camelCase), in rule order.
fn validate_values(v: &Values, relays: &[(String, String)]) -> Vec<(String, String)> {
    let mut d = Arr::new();
    let st = |k: &str| Val::str(&vs(v, k));
    for (camel, snake) in [
        ("idServer", "id_server"), ("relayServer", "relay_server"), ("publicKey", "public_key"), ("rdgenUrl", "rdgen_url"), ("clientUrlScheme", "client_url_scheme"),
        ("serverAccessMode", "server_access_mode"), ("oidcDiscoveryUrl", "oidc_discovery_url"), ("oidcPublicBaseUrl", "oidc_public_base_url"), ("oidcClientId", "oidc_client_id"),
        ("oidcClientSecret", "oidc_client_secret"), ("oidcScopes", "oidc_scopes"), ("oidcButtonLabel", "oidc_button_label"), ("oidcNewUserPolicy", "oidc_new_user_policy"),
        ("oidcAllowedDomains", "oidc_allowed_domains"), ("smtpHost", "smtp_host"), ("smtpEncryption", "smtp_encryption"), ("smtpUsername", "smtp_username"), ("smtpPassword", "smtp_password"),
        ("smtpFromAddress", "smtp_from_address"), ("smtpFromName", "smtp_from_name"), ("appriseEndpoint", "apprise_endpoint"), ("appriseMode", "apprise_mode"),
        ("appriseConfigKey", "apprise_config_key"), ("appriseUrls", "apprise_urls"),
    ] {
        d.set(Key::from_bytes(camel.as_bytes()), st(snake));
    }
    for (camel, snake) in [
        ("onlineWindow", "online_window"), ("logRetentionDays", "log_retention_days"), ("defaultDeviceGroupId", "default_device_group_id"), ("oidcDefaultGroupId", "oidc_default_group_id"),
        ("smtpPort", "smtp_port"), ("emailTrustedDeviceDays", "email_trusted_device_days"), ("appriseCooldownMinutes", "apprise_cooldown_minutes"),
        ("appriseOfflineGraceMinutes", "apprise_offline_grace_minutes"),
    ] {
        d.set(Key::from_bytes(camel.as_bytes()), num(v, snake));
    }
    let mut rows = Arr::new();
    for (a, g) in relays {
        let mut r = Arr::new();
        r.set(Key::from_bytes(b"address"), Val::str(a));
        r.set(Key::from_bytes(b"geo"), Val::str(g));
        rows.push(Val::Arr(r));
    }
    d.set(Key::from_bytes(b"relayServers"), Val::Arr(rows));
    let rules: &[(&str, &[Rule])] = &[
        ("idServer", &[Rule::Nullable, Rule::String, Rule::Max(255)]),
        ("relayServer", &[Rule::Nullable, Rule::String, Rule::Max(255)]),
        ("publicKey", &[Rule::Nullable, Rule::String, Rule::Max(255)]),
        ("onlineWindow", &[Rule::Required, Rule::Integer, Rule::Min(20), Rule::Max(600)]),
        ("rdgenUrl", &[Rule::Nullable, Rule::Url, Rule::Max(255)]),
        ("clientUrlScheme", &[Rule::Nullable, Rule::String, Rule::Max(64)]),
        ("logRetentionDays", &[Rule::Required, Rule::Integer, Rule::Min(0), Rule::Max(3650)]),
        ("defaultDeviceGroupId", &[Rule::Required, Rule::Integer, Rule::Min(0)]),
        ("serverAccessMode", &[Rule::Required, Rule::In(&["open", "approved"])]),
        ("relayServers", &[Rule::Array]),
        ("relayServers.*.address", &[Rule::Nullable, Rule::String, Rule::Max(255)]),
        ("relayServers.*.geo", &[Rule::Nullable, Rule::String, Rule::Max(64)]),
        ("oidcDiscoveryUrl", &[Rule::Nullable, Rule::Url, Rule::Max(255)]),
        ("oidcPublicBaseUrl", &[Rule::Nullable, Rule::Url, Rule::Max(255)]),
        ("oidcClientId", &[Rule::Nullable, Rule::String, Rule::Max(255)]),
        ("oidcClientSecret", &[Rule::Nullable, Rule::String, Rule::Max(512)]),
        ("oidcScopes", &[Rule::Nullable, Rule::String, Rule::Max(255)]),
        ("oidcButtonLabel", &[Rule::Nullable, Rule::String, Rule::Max(64)]),
        ("oidcNewUserPolicy", &[Rule::Required, Rule::In(&["deny", "pending", "active"])]),
        ("oidcDefaultGroupId", &[Rule::Nullable, Rule::Integer, Rule::Min(0)]),
        ("oidcAllowedDomains", &[Rule::Nullable, Rule::String, Rule::Max(512)]),
        ("smtpHost", &[Rule::Nullable, Rule::String, Rule::Max(255)]),
        ("smtpPort", &[Rule::Required, Rule::Integer, Rule::Min(1), Rule::Max(65535)]),
        ("smtpEncryption", &[Rule::Required, Rule::In(&["starttls", "ssl", "none"])]),
        ("smtpUsername", &[Rule::Nullable, Rule::String, Rule::Max(255)]),
        ("smtpPassword", &[Rule::Nullable, Rule::String, Rule::Max(512)]),
        ("smtpFromAddress", &[Rule::Nullable, Rule::Email, Rule::Max(255)]),
        ("smtpFromName", &[Rule::Nullable, Rule::String, Rule::Max(64)]),
        ("emailTrustedDeviceDays", &[Rule::Required, Rule::Integer, Rule::Min(1), Rule::Max(365)]),
        ("appriseEndpoint", &[Rule::Nullable, Rule::UrlWeb, Rule::Max(2048)]),
        ("appriseMode", &[Rule::Required, Rule::In(&["config", "urls"])]),
        ("appriseConfigKey", &[Rule::Nullable, Rule::String, Rule::Max(255)]),
        ("appriseUrls", &[Rule::Nullable, Rule::String, Rule::Max(10000)]),
        ("appriseCooldownMinutes", &[Rule::Required, Rule::Integer, Rule::Min(0), Rule::Max(1440)]),
        ("appriseOfflineGraceMinutes", &[Rule::Required, Rule::Integer, Rule::Min(0), Rule::Max(1440)]),
    ];
    match validate::validate(&d, &rules) {
        Ok(_) => vec![],
        Err(body) => {
            let mut out = vec![];
            if let Ok(j) = serde_json::from_str::<Value>(&body) {
                if let Some(e) = j.get("errors").and_then(|e| e.as_object()) {
                    for (k, list) in e {
                        if let Some(m) = list.get(0).and_then(|m| m.as_str()) {
                            out.push((k.clone(), m.to_string()));
                        }
                    }
                }
            }
            out
        }
    }
}

/// `ServerLink::status()`'s link state as the page reads it, from the pull marker the ID server link leaves in the cache.
pub(crate) struct Link {
    pub configured: bool,
    pub at: Option<i64>,
    /// the marker's `at` as stored (Fleet Diagnostics' download shows it)
    pub at_raw: Option<String>,
    /// a pull marker exists (the previous console's `is_array($pull)`)
    pub has_pull: bool,
    pub agent: String,
    pub fresh: bool,
    pub needed: bool,
    pub ok: Option<bool>,
    pub note: String,
}

fn pull_marker(ctx: &Ctx, c: &Connection) -> Result<(Option<i64>, Option<String>, bool, String), Fault> {
    let Some(raw) = ctx.p.store.get_raw(c, crate::cache::PULL_KEY, ctx.now)? else { return Ok((None, None, false, String::new())) };
    let t = String::from_utf8_lossy(&raw).into_owned();
    let grab = |name: &str| -> Option<String> {
        let marker = format!("s:{}:\"{}\";s:", name.len(), name);
        let rest = &t[t.find(&marker)? + marker.len()..];
        let (len, rest) = rest.split_once(":\"")?;
        let len: usize = len.parse().ok()?;
        rest.get(..len).map(str::to_string)
    };
    let at_raw = grab("at");
    let at = at_raw.as_deref().and_then(crate::backup::parse_when).map(|d| d.timestamp());
    Ok((at, at_raw.filter(|_| at.is_some()), t.starts_with("a:"), grab("agent").unwrap_or_default()))
}

pub(crate) fn link(ctx: &Ctx, c: &Connection) -> Result<Link, Fault> {
    let (at, at_raw, has_pull, agent) = pull_marker(ctx, c)?;
    let fresh = at.map_or(false, |a| a > ctx.now - 60);
    let needed = server_mode(c)? == "approved" || count(c, r#"select count(*) as aggregate from "devices" where "status" = ? and "can_initiate" = ? and "devices"."deleted_at" is null"#, &[P(Val::str("active")), P(Val::Bool(false))])? > 0;
    let configured = crate::envvar::var("HTE_REMOTE_SERVER_SECRET").map(|s| !s.trim().is_empty()).unwrap_or(false)
        || std::fs::read_to_string(crate::envvar::var("HTE_CONSOLE_SERVER_SECRET_FILE").unwrap_or_else(|_| "/data/.server_secret".into())).map(|s| !s.trim().is_empty()).unwrap_or(false);
    let note = match (configured, at) {
        (false, _) => "Not configured. Approved-only mode and incoming-only devices are not enforced.".to_string(),
        (true, None) => "Configured, but the ID server has never fetched the policy.".to_string(),
        (true, Some(a)) if !fresh => format!("The ID server last fetched the policy {}.", super::time::ago(a, ctx.now, false)),
        (true, Some(a)) => format!("The ID server fetched the policy {}.", super::time::ago(a, ctx.now, false)),
    };
    Ok(Link { configured, at, at_raw, has_pull, agent, fresh: configured && fresh, needed, ok: if configured && fresh { Some(true) } else if needed { Some(false) } else { None }, note })
}

/// `ScopeSettings::hteScopeStatus()`
fn scope_status(ctx: &Ctx, c: &Connection, l: &Link) -> Result<(String, String), Fault> {
    let hte = l.agent.contains("-hte.");
    let version = l.agent.replace("hte-rd-server/", "").replace("cortendesk-server/", "").trim().to_string();
    Ok(if !on(c, "hte_scope_enforce")? {
        ("text-muted".into(), "Off: scoping only decides what each person sees.".into())
    } else if !l.configured || l.at.is_none() {
        ("text-danger".into(), "On, but no ID server is fetching the policy, so nothing is enforced.".into())
    } else if !hte {
        ("text-danger".into(), format!("On, but the linked ID server ({}) is not the HTE build and ignores it.", if version.is_empty() { "unknown build" } else { &version }))
    } else if !l.fresh {
        ("text-warning".into(), format!("On; the HTE ID server ({version}) last fetched the policy {}.", super::time::ago(l.at.unwrap_or(0), ctx.now, false)))
    } else {
        ("text-success".into(), format!("On and enforced by the HTE ID server ({version})."))
    })
}

/// `Passwords::summary()`
fn password_summary(c: &Connection) -> Result<(String, String), Fault> {
    if !on(c, "hte_pw_enabled")? {
        return Ok(("text-muted".into(), "Off: computers keep the password they were installed with.".into()));
    }
    let rows = db::rows(c, r#"select * from "hte_device_passwords" where "capable_at" is not null"#, &[])?;
    let own = rows.iter().filter(|r| r.val("confirmed_version").to_int() > 0 && !crate::passwords_sweep::pending(r)).count() as i64;
    let waiting = rows.iter().filter(|r| crate::passwords_sweep::pending(r)).count() as i64;
    let total = count(c, r#"select count(*) as aggregate from "devices" where "status" = ? and "devices"."deleted_at" is null"#, &[P(Val::str("active"))])?;
    let all_rows = count(c, r#"select count(*) as aggregate from "hte_device_passwords" where "capable_at" is not null"#, &[])?;
    let other = (total - all_rows).max(0);
    let mut text = format!("Own passwords: {own} of {total} computers.");
    if waiting > 0 {
        text += &format!(" {waiting} waiting for the computer to confirm.");
    }
    if other > 0 {
        text += &format!(" {other} on stock RustDesk or an older HTE Remote (their password is set on the computer).");
    }
    Ok((if waiting > 0 { "text-warning" } else { "text-success" }.into(), text))
}

fn mail_enabled(c: &Connection) -> Result<bool, Fault> {
    Ok(txt(c, "smtp_enabled", "0")?.trim() == "1" && !txt(c, "smtp_host", "")?.trim().is_empty() && !txt(c, "smtp_from_address", "")?.trim().is_empty())
}

fn device_label(r: &Row) -> String {
    let a = s(r, "alias");
    let h = s(r, "hostname");
    if truthy(&a) { a } else if truthy(&h) { h } else { s(r, "rustdesk_id") }
}

// ---------------------------------------------------------------------------------------------------- render ---

struct Page {
    status: u16,
    values: Values,
    relays: Vec<(String, String)>,
    errors: Vec<(String, String)>,
    tab: String,
    saved: bool,
    form_error: String,
    snooze: Values,
}

fn tab_of(t: &str) -> String {
    (if TABS.iter().any(|(k, _, _)| *k == t) { t } else { "server" }).to_string()
}

fn render(ctx: &Ctx, c: &Connection, p: Page) -> Result<Reply, Fault> {
    let can_manage = ctx.allows("setting", "rw");
    let is_admin = ctx.is_admin();
    let l = link(ctx, c)?;
    let (scope_tone, scope_text) = scope_status(ctx, c, &l)?;
    let (pw_tone, pw_text) = password_summary(c)?;
    let mut errs = Map::new();
    for (k, m) in &p.errors {
        errs.insert(error_key(k), json!(m));
    }
    let mut err_all = Map::new();
    for k in STRINGS.iter().chain(BOOLS.iter()).chain(SECRETS.iter()) {
        err_all.insert((*k).to_string(), errs.get(*k).cloned().unwrap_or(Value::Null));
    }
    for k in ["presence_snooze_target_id", "presence_snooze_minutes", "appriseOfflineGraceMinutes"] {
        err_all.insert(k.to_string(), errs.get(k).cloned().unwrap_or(Value::Null));
    }
    let relays: Vec<Value> = p
        .relays
        .iter()
        .enumerate()
        .map(|(i, (a, g))| json!({"address": a, "geo": g, "e_address": errs.get(&format!("relay_{i}_address")).cloned().unwrap_or(Value::Null), "e_geo": errs.get(&format!("relay_{i}_geo")).cloned().unwrap_or(Value::Null)}))
        .collect();

    // groups and devices the selects offer
    let mut default_groups = db::rows(c, r#"select "id", "name" from "device_groups" order by "name" asc"#, &[])?;
    if !is_admin {
        let mut visible = crate::reach::accessible_device_group_ids(c, &ctx.user)?;
        let current = int_of(&vs(&p.values, "default_device_group_id"));
        if current > 0 {
            visible.push(current);
        }
        default_groups.retain(|g| visible.contains(&g.id()));
    }
    let all_groups = db::rows(c, r#"select "id", "name" from "device_groups" order by "name" asc"#, &[])?;
    let user_groups = db::rows(c, r#"select "id", "name" from "user_groups" order by "name" asc"#, &[])?;
    let approved = db::rows(c, r#"select "id", "rustdesk_id", "alias", "hostname" from "devices" where "status" = ? and "devices"."deleted_at" is null order by COALESCE(NULLIF(alias, ''), NULLIF(hostname, ''), rustdesk_id)"#, &[P(Val::str("active"))])?;
    let opt = |rows: &[Row]| -> Vec<Value> { rows.iter().map(|g| json!({"id": g.id(), "name": s(g, "name")})).collect() };
    let dev_opts: Vec<Value> = approved.iter().map(|d| json!({"id": d.id(), "label": device_label(d)})).collect();

    let events: Vec<Value> = EVENTS
        .iter()
        .map(|(event, label)| {
            let x = suffix(event);
            json!({
                "event": event, "key": x, "dom": event.replace('.', "-"), "label": label, "scoped": SCOPED_EVENTS.contains(event),
                "enabled": vb(&p.values, &format!("apprise_event_{x}")), "scope": vs(&p.values, &format!("apprise_scope_{x}")),
                "groups": vids(&p.values, &format!("apprise_scope_groups_{x}")), "devices": vids(&p.values, &format!("apprise_scope_devices_{x}")),
            })
        })
        .collect();

    // the stored-or-not flags: the only thing a secret ever contributes to a page
    let set = |key: &str| -> Result<bool, Fault> { Ok(!txt(c, key, "")?.trim().is_empty()) };
    let mail_on = mail_enabled(c)?;
    let mail_broken = {
        let active = txt(c, "email_login_verification", "0")? == "1" && mail_on;
        let failed = txt(c, "smtp_failed_at", "")?;
        let ok_at = txt(c, "smtp_ok_at", "")?;
        let healthy = failed.is_empty() || (!ok_at.is_empty() && ok_at >= failed);
        (active && !healthy, if healthy { String::new() } else { txt(c, "smtp_last_error", "")?.trim().to_string() })
    };
    let no_email = count(c, r#"select count(*) as aggregate from "users" where "is_active" = ? and ("email" is null or "email" = '')"#, &[P(Val::Bool(true))])?;

    // presence snoozes (administrators only)
    let mut snoozes = vec![];
    if is_admin {
        for r in db::rows(c, r#"select * from "device_presence_snoozes" where "expires_at" > ? order by "expires_at" asc"#, &[P(Val::str(&crate::laravel::ts(ctx.now)))])? {
            let kind = s(&r, "target_type");
            let id = r.val("target_id").to_int();
            let name = if kind == "group" {
                all_groups.iter().find(|g| g.id() == id).map(|g| s(g, "name"))
            } else {
                approved.iter().find(|d| d.id() == id).map(device_label)
            }
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| "Deleted target".into());
            let until = ts_of(&r, "expires_at").unwrap_or(0);
            snoozes.push(json!({"id": r.id(), "kind": if kind == "group" { "Group" } else { "Device" }, "name": name,
                "until": chrono::DateTime::from_timestamp(until, 0).map(|d| d.format("%a, %b %-d, %Y %-I:%M %p").to_string()).unwrap_or_default(), "human": super::time::ago(until, ctx.now, false)}));
        }
    }

    // recent deliveries
    let deliveries = db::rows(c, r#"select * from "notification_deliveries" order by "created_at" desc, "id" desc limit 10"#, &[])?;
    let mut by_rid: Vec<(i64, String)> = vec![];
    let mut alarm_ids: Vec<(i64, i64)> = vec![];
    for d in &deliveries {
        let subject = s(d, "subject");
        if let Some(rid) = subject.strip_prefix("device:") {
            by_rid.push((d.id(), rid.to_string()));
        } else if let Some(a) = subject.strip_prefix("alarm:") {
            alarm_ids.push((d.id(), int_of(a)));
        }
    }
    if !alarm_ids.is_empty() {
        let ids: Vec<i64> = alarm_ids.iter().map(|(_, a)| *a).collect();
        for r in db::rows(c, &format!(r#"select "id", "rustdesk_id" from "alarm_logs" where "id" in ({})"#, marks(ids.len())), &ints_val(&ids))? {
            for (did, aid) in &alarm_ids {
                if *aid == r.id() {
                    by_rid.retain(|(x, _)| x != did);
                    by_rid.push((*did, s(&r, "rustdesk_id")));
                }
            }
        }
    }
    let mut rid_devices: Vec<Row> = vec![];
    if !by_rid.is_empty() {
        let mut rids: Vec<String> = by_rid.iter().map(|(_, r)| r.clone()).collect();
        rids.sort();
        rids.dedup();
        rid_devices = db::rows(c, &format!(r#"select "id", "rustdesk_id", "alias", "hostname" from "devices" where "devices"."deleted_at" is null and "rustdesk_id" in ({})"#, marks(rids.len())), &rids.iter().map(|r| P(Val::str(r))).collect::<Vec<_>>())?;
    }
    let delivery_items: Vec<Value> = deliveries
        .iter()
        .map(|d| {
            let event = s(d, "event");
            let label = EVENTS.iter().find(|(e, _)| *e == event).map(|(_, l)| l.to_string()).unwrap_or(event);
            let device = by_rid.iter().find(|(x, _)| *x == d.id()).and_then(|(_, rid)| rid_devices.iter().find(|r| s(r, "rustdesk_id") == *rid)).map(|r| {
                let alias = s(r, "alias");
                let name = (if truthy(&alias) { alias } else { s(r, "hostname") }).trim().to_string();
                json!({"id": r.id(), "label": if name.is_empty() { "Device".to_string() } else { name }, "rustdesk_id": s(r, "rustdesk_id")})
            });
            let status = s(d, "status");
            let next = ts_of(d, "next_retry_at");
            let retry = status == "failed" && next.is_some();
            let attempts = d.val("attempts").to_int();
            let created = ts_of(d, "created_at");
            let tone = if retry { "warning" } else { match status.as_str() { "sent" => "success", "failed" => "danger", _ => "secondary" } };
            let line = if retry {
                format!("Attempt {attempts} of {MAX_ATTEMPTS} · next retry")
            } else if status == "superseded" {
                format!("Attempt {attempts} of {MAX_ATTEMPTS} · retry dropped, a newer event replaced it")
            } else if attempts > 1 {
                format!("{} {attempts} of {MAX_ATTEMPTS}", if status == "sent" { "Sent on attempt" } else { "Failed after attempt" })
            } else {
                String::new()
            };
            json!({
                "title": s(d, "title"), "event": label, "device": device, "tone": tone, "badge": if retry { "retrying".to_string() } else { status },
                "created_title": created.map(|t| format!("{} UTC", crate::laravel::ts(t))).unwrap_or_default(), "created": created.map(|t| super::time::ago(t, ctx.now, false)).unwrap_or_default(),
                "error": s(d, "error"), "line": line, "retry": retry,
                "next_title": next.map(|t| format!("{} UTC", crate::laravel::ts(t))).unwrap_or_default(), "next": next.map(|t| super::time::ago(t, ctx.now, false)).unwrap_or_default(),
            })
        })
        .collect();

    let tabs: Vec<Value> = TABS.iter().map(|(k, i, l)| json!({"key": k, "icon": i, "label": l})).collect();
    let layout = ctx.layout(c, "settings", "Settings", "System")?;
    let page = json!({
        "tab": p.tab, "tabs": tabs, "v": Value::Object(p.values.clone()), "e": Value::Object(err_all), "relays": relays, "saved": p.saved,
        "form_error": p.form_error, "any_errors": !p.errors.is_empty() || !p.form_error.is_empty(), "can_manage": can_manage, "is_admin": is_admin,
        "set": {"oidc_client_secret": set("oidc_client_secret")?, "smtp_password": set("smtp_password")?, "apprise_endpoint": set("apprise_endpoint")?, "apprise_config_key": set("apprise_config_key")?, "apprise_urls": set("apprise_urls")?},
        "api_url": crate::envvar::var("APP_URL").unwrap_or_default().trim_end_matches('/').to_string(),
        "oidc_callback": format!("{}/login/oidc/callback", crate::envvar::var("APP_URL").unwrap_or_default().trim_end_matches('/')),
        "link": {"ok": l.ok, "note": l.note, "tone": match l.ok { Some(true) => "text-success", Some(false) => "text-danger", None => "text-muted" }},
        "scope": {"tone": scope_tone, "text": scope_text}, "pw": {"tone": pw_tone, "text": pw_text},
        "day_choices": DAY_CHOICES.iter().map(|(d, l)| json!({"d": d, "label": l, "suffix": if *d != 0 { format!(" ({d})") } else { String::new() }})).collect::<Vec<_>>(),
        "default_groups": opt(&default_groups), "user_groups": opt(&user_groups), "all_groups": opt(&all_groups), "devices": dev_opts, "events": events,
        "mail_enabled": mail_on, "mail_broken": mail_broken.0, "mail_error": mail_broken.1, "mail_flash": ctx.flashed.get("mail_broken").and_then(|v| v.as_str()).unwrap_or(""), "mail_test": ctx.flashed.get("mail_test").cloned().unwrap_or(Value::Null),
        "no_email": no_email, "snoozes": snoozes, "snooze": Value::Object(p.snooze.clone()), "deliveries": delivery_items,
        "tok": super::api_tokens::card(ctx, c)?, "about": {"version": crate::REMOTE_VERSION, "api": ctx.p.n.api_version}, "backups": super::backups::pane(ctx, c, &p.tab)?,
    });
    Ok(Reply::Html(p.status, ctx.render("settings/index.html", layout, page)?))
}

fn snooze_blank() -> Values {
    let mut m = Values::new();
    m.insert("type".into(), json!("device"));
    m.insert("target".into(), json!("0"));
    m.insert("minutes".into(), json!("60"));
    m
}

fn page(ctx: &Ctx, c: &Connection, status: u16, tab: &str) -> Result<Reply, Fault> {
    let (values, relays) = load(ctx, c)?;
    render(ctx, c, Page { status, values, relays, errors: vec![], tab: tab.into(), saved: !ctx.flashed.get("settings_saved").map_or(true, |v| v.is_null()), form_error: String::new(), snooze: snooze_blank() })
}

/// GET /settings
pub fn index(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    page(ctx, c, 200, &tab_of(&q(req, "tab")))
}

/// POST /settings/relay: add a blank relay row, or drop one, keeping everything else typed on the page.
pub fn relay(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if !ctx.allows("setting", "rw") {
        return Ok(abort(403));
    }
    let body = Body::of(req);
    let (values, mut relays) = from_body(&body);
    let action = body.get("do");
    if action == "add" {
        relays.push((String::new(), String::new()));
    } else if let Some(i) = action.strip_prefix("remove:").and_then(|i| i.parse::<usize>().ok()) {
        if i < relays.len() {
            relays.remove(i);
        }
    }
    render(ctx, c, Page { status: 200, values: scrub(values), relays, errors: vec![], tab: "server".into(), saved: false, form_error: String::new(), snooze: snooze_blank() })
}

/// What a re-rendered page keeps of the post: the secrets are never given back.
fn scrub(mut v: Values) -> Values {
    for k in SECRETS {
        v.remove(*k);
    }
    v
}

fn failed(ctx: &Ctx, c: &Connection, values: Values, relays: Vec<(String, String)>, errors: Vec<(String, String)>, tab: &str, form_error: &str) -> Result<Reply, Fault> {
    render(ctx, c, Page { status: 422, values: scrub(values), relays, errors, tab: tab.into(), saved: false, form_error: form_error.into(), snooze: snooze_blank() })
}

/// POST /settings/save: `SettingsPage::save()`
pub fn save(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if !ctx.allows("setting", "rw") {
        return Ok(abort(403));
    }
    let body = Body::of(req);
    let (v, relays) = from_body(&body);
    let tab = tab_of(&body.get("tab"));

    let errors = validate_values(&v, &relays);
    if let Some((first, _)) = errors.first() {
        let t = tab_for(first).map(str::to_string).unwrap_or(tab);
        return failed(ctx, c, v, relays, errors, &t, "");
    }
    let custom = |field: &str, msg: &str, tab: &str| -> Vec<(String, String)> {
        let _ = tab;
        vec![(field.to_string(), msg.to_string())]
    };
    let scheme_in = vs(&v, "client_url_scheme");
    if !scheme_in.trim().is_empty() && normalize_scheme(&scheme_in).is_empty() {
        return failed(ctx, c, v, relays, custom("clientUrlScheme", "Letters, digits, \"+\", \"-\" and \".\" only, starting with a letter.", "server"), "server", "");
    }
    if crate::ice::normalize(&vs(&v, "web_client_ice_servers")).is_none() {
        let msg = match crate::ice::first_invalid(&vs(&v, "web_client_ice_servers")) {
            Some(bad) => format!("{bad} is not a STUN or TURN server the client will use. A TURN entry needs a user name and password: turn://user:password@host:3478."),
            None => format!("At most {} servers.", crate::ice::MAX_ENTRIES),
        };
        return failed(ctx, c, v, relays, custom("webClientIceServers", &msg, "server"), "server", "");
    }
    let group = int_of(&vs(&v, "default_device_group_id"));
    if group > 0 && find(c, "device_groups", group)?.is_none() {
        return failed(ctx, c, v, relays, custom("defaultDeviceGroupId", "That device group no longer exists.", "server"), "server", "");
    }
    // turning SSO on without what it needs would hide the password form behind a door that does not open
    if vb(&v, "oidc_enabled") {
        let missing_secret = vs(&v, "oidc_client_secret").is_empty() && txt(c, "oidc_client_secret", "")?.trim().is_empty();
        if vs(&v, "oidc_discovery_url").is_empty() || vs(&v, "oidc_client_id").is_empty() || missing_secret {
            return failed(ctx, c, v, relays, custom("oidcDiscoveryUrl", "Provider URL, client ID and client secret are all required to enable SSO.", "sso"), "sso", "");
        }
    }
    if vb(&v, "smtp_enabled") && (vs(&v, "smtp_host").trim().is_empty() || vs(&v, "smtp_from_address").trim().is_empty()) {
        return failed(ctx, c, v, relays, custom("smtpHost", "Host and From address are both required to enable email.", "email"), "email", "");
    }

    let now_s = |k: &str, x: &str| put(ctx, c, k, x);
    super::strategies_tx(c, || {
        // the relay pool: blank rows dropped, the rest as JSON
        let pool: Vec<(String, String)> = relays.iter().map(|(a, g)| (a.trim().to_string(), g.trim().to_string())).filter(|(a, _)| !a.is_empty()).collect();
        let mut rows = Arr::new();
        for (a, g) in &pool {
            rows.push(obj_val(vec![("address", Val::str(a)), ("geo", Val::str(g))]));
        }
        now_s("relay_servers", &php::json_encode(&Val::Arr(rows)).unwrap_or_else(|| "[]".into()))?;
        now_s("id_server", vs(&v, "id_server").trim())?;
        now_s("relay_server", vs(&v, "relay_server").trim())?;
        now_s("public_key", vs(&v, "public_key").trim())?;
        now_s("online_window", &int_of(&vs(&v, "online_window")).to_string())?;
        now_s("rdgen_url", vs(&v, "rdgen_url").trim_end_matches('/'))?;
        let scheme_v = normalize_scheme(&scheme_in);
        now_s("client_url_scheme", if scheme_v.is_empty() { "rustdesk" } else { &scheme_v })?;
        now_s("downloads_on_login", bool_s(vb(&v, "downloads_on_login")))?;
        if vb(&v, "web_client_webrtc") != webrtc_on(c)? {
            now_s("webclient_webrtc", bool_s(vb(&v, "web_client_webrtc")))?;
            audit(ctx, c, "settings.webclient-webrtc", &format!("The web client {} WebRTC", if vb(&v, "web_client_webrtc") { "may use" } else { "no longer uses" }), Some("settings"), None)?;
        }
        let ice = crate::ice::normalize(&vs(&v, "web_client_ice_servers")).unwrap_or_default();
        if ice != txt(c, "webclient_ice_servers", "")? {
            // the list can hold a TURN password: the log says that it changed, never what it says
            audit(ctx, c, "settings.webclient-ice", if ice.is_empty() { "The web client's ICE servers were cleared" } else { "The web client's ICE servers were changed" }, Some("settings"), None)?;
        }
        now_s("webclient_ice_servers", &ice)?;
        now_s("log_retention_days", &int_of(&vs(&v, "log_retention_days")).to_string())?;
        now_s("require_device_approval", bool_s(vb(&v, "require_device_approval")))?;
        now_s("auto_approve_signed_in", bool_s(vb(&v, "auto_approve_signed_in")))?;
        now_s("default_device_group_id", &group.to_string())?;
        let mode = vs(&v, "server_access_mode");
        if mode != server_mode(c)? {
            now_s("server_access_mode", &mode)?;
            audit(ctx, c, "settings.server-access", &format!("Server access set to {mode}"), Some("settings"), None)?;
        }
        if vb(&v, "server_ip_match") != on(c, "server_ip_match")? {
            now_s("server_ip_match", bool_s(vb(&v, "server_ip_match")))?;
            audit(ctx, c, "settings.server-ip-match", &format!("Signed-out devices {} by IP address", if vb(&v, "server_ip_match") { "identified" } else { "not identified" }), Some("settings"), None)?;
        }
        // HTE: computer passwords, then per-person reach
        let days = int_of(&vs(&v, "hte_password_days"));
        let days = if DAY_CHOICES.iter().any(|(d, _)| *d == days) { days } else { 30 };
        if days != crate::passwords_sweep::days(c)? {
            now_s("hte_pw_days", &days.to_string())?;
            let label = DAY_CHOICES.iter().find(|(d, _)| *d == days).map(|(_, l)| *l).unwrap_or("");
            audit(ctx, c, "settings.hte-passwords", &format!("Computer passwords change: {label}"), Some("settings"), None)?;
        }
        if vb(&v, "hte_passwords") != on(c, "hte_pw_enabled")? {
            now_s("hte_pw_enabled", bool_s(vb(&v, "hte_passwords")))?;
            audit(ctx, c, "settings.hte-passwords", &format!("Each computer {} its own password from the console", if vb(&v, "hte_passwords") { "gets" } else { "no longer gets" }), Some("settings"), None)?;
        }
        if vb(&v, "hte_scope_enforce") != on(c, "hte_scope_enforce")? {
            now_s("hte_scope_enforce", bool_s(vb(&v, "hte_scope_enforce")))?;
            audit(ctx, c, "settings.hte-scope", &format!("Per-person reach {} by the ID server", if vb(&v, "hte_scope_enforce") { "enforced" } else { "no longer enforced" }), Some("settings"), None)?;
        }
        now_s("two_factor_required", bool_s(vb(&v, "two_factor_required")))?;
        now_s("two_factor_required_admins", bool_s(vb(&v, "two_factor_required_admins")))?;

        now_s("oidc_enabled", bool_s(vb(&v, "oidc_enabled")))?;
        now_s("oidc_discovery_url", vs(&v, "oidc_discovery_url").trim().trim_end_matches('/'))?;
        now_s("oidc_public_base_url", vs(&v, "oidc_public_base_url").trim().trim_end_matches('/'))?;
        now_s("oidc_client_id", vs(&v, "oidc_client_id").trim())?;
        now_s("oidc_scopes", vs(&v, "oidc_scopes").trim())?;
        now_s("oidc_button_label", vs(&v, "oidc_button_label").trim())?;
        now_s("oidc_new_user_policy", &vs(&v, "oidc_new_user_policy"))?;
        now_s("oidc_default_admin", bool_s(vb(&v, "oidc_default_admin")))?;
        now_s("oidc_default_group_id", &int_of(&vs(&v, "oidc_default_group_id")).to_string())?;
        now_s("oidc_allowed_domains", vs(&v, "oidc_allowed_domains").trim())?;
        now_s("oidc_require_verified_email", bool_s(vb(&v, "oidc_require_verified_email")))?;
        now_s("oidc_logout_enabled", bool_s(vb(&v, "oidc_logout_enabled")))?;
        now_s("oidc_disable_local_login", bool_s(vb(&v, "oidc_disable_local_login")))?;
        // blank keeps the stored secret
        let secret = |name: &str| vs(&v, name);
        if !secret("oidc_client_secret").is_empty() {
            now_s("oidc_client_secret", &ctx.p.n.crypt.encrypt_string(secret("oidc_client_secret").as_bytes()))?;
        }

        now_s("smtp_enabled", bool_s(vb(&v, "smtp_enabled")))?;
        now_s("smtp_host", vs(&v, "smtp_host").trim())?;
        now_s("smtp_port", &int_of(&vs(&v, "smtp_port")).to_string())?;
        now_s("smtp_encryption", &vs(&v, "smtp_encryption"))?;
        now_s("smtp_username", vs(&v, "smtp_username").trim())?;
        now_s("smtp_from_address", vs(&v, "smtp_from_address").trim())?;
        now_s("smtp_from_name", vs(&v, "smtp_from_name").trim())?;
        now_s("email_trusted_device_days", &int_of(&vs(&v, "email_trusted_device_days")).to_string())?;

        now_s("apprise_enabled", bool_s(vb(&v, "apprise_enabled")))?;
        now_s("apprise_delivery_mode", &vs(&v, "apprise_mode"))?;
        now_s("apprise_cooldown_minutes", &int_of(&vs(&v, "apprise_cooldown_minutes")).to_string())?;
        now_s("apprise_offline_grace_minutes", &int_of(&vs(&v, "apprise_offline_grace_minutes")).to_string())?;
        for (event, _) in EVENTS {
            let x = suffix(event);
            now_s(&format!("apprise_event_{x}"), bool_s(vb(&v, &format!("apprise_event_{x}"))))?;
            now_s(&format!("apprise_scope_{x}"), &vs(&v, &format!("apprise_scope_{x}")))?;
            for kind in ["groups", "devices"] {
                let ids = vids(&v, &format!("apprise_scope_{kind}_{x}"));
                let mut list = Arr::new();
                for i in ids {
                    list.push(Val::Int(i));
                }
                now_s(&format!("apprise_scope_{kind}_{x}"), &php::json_encode(&Val::Arr(list)).unwrap_or_else(|| "[]".into()))?;
            }
        }
        let crypt = |plain: &str| ctx.p.n.crypt.encrypt_string(plain.as_bytes());
        if !secret("apprise_endpoint").is_empty() {
            now_s("apprise_endpoint", &crypt(secret("apprise_endpoint").trim()))?;
        }
        if !secret("apprise_config_key").is_empty() {
            now_s("apprise_config_key", &crypt(secret("apprise_config_key").trim()))?;
        }
        if !secret("apprise_urls").is_empty() {
            let text = secret("apprise_urls");
            let mut list = Arr::new();
            for line in text.trim().split(['\r', '\n']) {
                let t = line.trim();
                if !t.is_empty() && t != "0" {
                    list.push(Val::str(t));
                }
            }
            now_s("apprise_urls", &crypt(&php::json_encode(&Val::Arr(list)).unwrap_or_else(|| "[]".into())))?;
        }
        if !secret("smtp_password").is_empty() {
            now_s("smtp_password", &crypt(&secret("smtp_password")))?;
        }
        // an emailed sign-in code can only be armed once email works
        let verify = vb(&v, "email_login_verification") && mail_enabled(c)?;
        now_s("email_login_verification", bool_s(verify))?;
        audit(ctx, c, "settings.update", "Updated server settings", Some("settings"), None)
    })?;
    // endpoints and keys may have moved with the provider URL
    ctx.p.n.signin.oidc.forget();
    ctx.flash("settings_saved", json!(true));
    Ok(Reply::Redirect(format!("/settings?tab={tab}")))
}

fn obj_val(pairs: Vec<(&str, Val)>) -> Val {
    let mut a = Arr::new();
    for (k, v) in pairs {
        a.set(Key::Str(k.as_bytes().to_vec()), v);
    }
    Val::Arr(a)
}

/// POST /settings/snooze: the presence-alert maintenance windows (administrators only).
pub fn snooze(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if !ctx.is_admin() {
        return Ok(abort(403));
    }
    let body = Body::of(req);
    let action = body.get("do");
    if let Some(id) = action.strip_prefix("clear:").and_then(|i| i.parse::<i64>().ok()) {
        db::exec(c, r#"delete from "device_presence_snoozes" where "id" = ?"#, &[P(Val::Int(id))])?;
        audit(ctx, c, "settings.presence-snooze-clear", "Cleared a device presence alert snooze", Some("settings"), None)?;
        return Ok(Reply::Redirect("/settings?tab=notifications".into()));
    }
    let kind = body.get("snooze_type");
    let target = body.get("snooze_target");
    let minutes = body.get("snooze_minutes");
    let mut d = Arr::new();
    d.set(Key::from_bytes(b"presenceSnoozeTargetType"), Val::str(&kind));
    d.set(Key::from_bytes(b"presenceSnoozeTargetId"), if target.trim().parse::<i64>().is_ok() { Val::Int(target.trim().parse().unwrap_or(0)) } else { Val::str(&target) });
    d.set(Key::from_bytes(b"presenceSnoozeMinutes"), if minutes.trim().parse::<i64>().is_ok() { Val::Int(minutes.trim().parse().unwrap_or(0)) } else { Val::str(&minutes) });
    let rules: [(&str, &[Rule]); 3] = [
        ("presenceSnoozeTargetType", &[Rule::Required, Rule::In(&["device", "group"])]),
        ("presenceSnoozeTargetId", &[Rule::Required, Rule::Integer, Rule::Min(1)]),
        ("presenceSnoozeMinutes", &[Rule::Required, Rule::Integer, Rule::Min(15), Rule::Max(10080)]),
    ];
    let mut snooze_state = snooze_blank();
    snooze_state.insert("type".into(), json!(kind));
    snooze_state.insert("target".into(), json!(target));
    snooze_state.insert("minutes".into(), json!(minutes));
    if let Err(b) = validate::validate(&d, &rules) {
        let m = first_messages(&b);
        let errors: Vec<(String, String)> = m
            .iter()
            .map(|(k, v)| (match k.as_str() { "presenceSnoozeTargetId" => "presence_snooze_target_id".to_string(), "presenceSnoozeMinutes" => "presence_snooze_minutes".to_string(), o => o.to_string() }, v.as_str().unwrap_or("").to_string()))
            .collect();
        let (values, relays) = load(ctx, c)?;
        return render(ctx, c, Page { status: 422, values, relays, errors, tab: "notifications".into(), saved: false, form_error: String::new(), snooze: snooze_state });
    }
    let id = int_of(&target);
    let table = if kind == "group" { "device_groups" } else { "devices" };
    let ok = if kind == "group" { find(c, table, id)?.is_some() } else { db::first(c, r#"select * from "devices" where "id" = ? and "status" = ? and "devices"."deleted_at" is null limit 1"#, &[P(Val::Int(id)), P(Val::str("active"))])?.is_some() };
    if !ok {
        return Ok(abort(404));
    }
    let expires = ctx.now + int_of(&minutes) * 60;
    let (ts_exp, ts_now) = (crate::laravel::ts(expires), crate::laravel::ts(ctx.now));
    let existing = db::first(c, r#"select * from "device_presence_snoozes" where "target_type" = ? and "target_id" = ? limit 1"#, &[P(Val::str(&kind)), P(Val::Int(id))])?;
    match existing {
        Some(r) => {
            db::exec(c, r#"update "device_presence_snoozes" set "expires_at" = ?, "updated_at" = ? where "id" = ?"#, &[P(Val::str(&ts_exp)), P(Val::str(&ts_now)), P(Val::Int(r.id()))])?;
        }
        None => {
            db::insert(c, "device_presence_snoozes", vec![("target_type", Val::str(&kind)), ("target_id", Val::Int(id)), ("expires_at", Val::str(&ts_exp))], &ts_now)?;
        }
    }
    audit(ctx, c, "settings.presence-snooze", &format!("Snoozed device presence alerts until {ts_exp}"), Some("settings"), None)?;
    Ok(Reply::Redirect("/settings?tab=notifications".into()))
}

/// `Setting::relayServers()`'s addresses: the pool's non-empty rows, else the single `relay_server` (or its environment default).
pub(crate) fn relay_pool(c: &Connection) -> Result<Vec<String>, Fault> {
    let raw = txt(c, "relay_servers", "")?;
    if !raw.is_empty() {
        if let Ok(Value::Array(rows)) = serde_json::from_str::<Value>(&raw) {
            let list: Vec<String> = rows.iter().map(|r| value_text(r.get("address")).trim().to_string()).filter(|a| !a.is_empty()).collect();
            if !list.is_empty() {
                return Ok(list);
            }
        }
    }
    let single = server_value(c, "relay_server", &["HTE_CONSOLE_RELAY_SERVER", "HTE_REMOTE_RELAY_SERVER"])?;
    Ok(if single.is_empty() { vec![] } else { vec![single] })
}
