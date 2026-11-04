//! Phase 8 (0.8.2): the sign-in's second steps and the pages reached from an e-mailed link, ported from
//! v1.15.0-hte.1 `AuthController` (the TOTP / recovery-code challenge, the e-mailed new-browser code and its resend),
//! `TrustedDevice`, `LoginEmailVerification` and `PasswordResetController` + `PasswordReset`:
//!
//!   GET|POST /login/2fa                a pending marker (`2fa`, 5 minutes) in the guest session, set by the password step
//!   GET|POST /login/email, POST /login/email/resend   the same for an e-mailed code (`email_verify`, 10 minutes)
//!   GET|POST /forgot-password, /reset-password/{token}   only while mail is on and password sign-in is allowed
//!
//! Same rows as the previous console: `two_factor_recovery_codes.used_at`, `users.totp_last_timestep`, `trusted_devices`,
//! `password_resets`, `login_logs` (`note`), `alarm_logs` (100 per account+address per cooldown). Same throttles
//! (5 a minute per account+address on both code steps, 3 resends, the routes' 6 and 20 a minute per address).
//! The guest session holds the markers; nothing is signed in until a step is cleared, and then `login::complete`
//! issues a new session id.

use super::login::{self, already_signed_in, csrf, guest_session, keep, login_log_note, page_expired, rate_limited, redirect, signed_in, Out, Web};
use super::session::Session;
use super::{html, Pages};
use crate::laravel;
use crate::php::{self, Fault, Val};
use crate::sqlite::{self as db, Row, P};
use rusqlite::Connection;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

/// `AuthController::PENDING_TTL`, `EMAIL_PENDING_TTL`
const PENDING_TTL: i64 = 300;
const EMAIL_PENDING_TTL: i64 = 600;
/// `TwoFactor::RECOVERY_LOW_THRESHOLD`
const RECOVERY_LOW: i64 = 2;
/// `PasswordReset::TTL_MINUTES`
const RESET_TTL_MIN: i64 = 60;
/// `TrustedDevice::COOKIE`, `DEFAULT_DAYS`
const DEVICE_COOKIE: &str = "cd_device";
const NEUTRAL: &str = "If that account exists and has an email address, a reset link is on its way.";
const EXPIRED_STEP: &str = "Your sign-in session expired. Please sign in again.";
const BAD_LINK: &str = "That reset link is invalid or has expired. Request a new one.";

// -------------------------------------------------------------------------------------------- helpers ---

/// A guest page in the HTE Remote guest layout.
fn page(p: &Pages, w: &Web, s: &Session, template: &str, title: &str, mut vars: Value) -> Result<Out, Fault> {
    let flashed = s.flashed();
    let error = flashed.get("errors").and_then(|e| e.as_object()).and_then(|m| m.values().next()).and_then(|v| v.get(0)).and_then(|v| v.as_str()).unwrap_or("").to_string();
    if let Value::Object(m) = &mut vars {
        m.insert("app_name".into(), json!(p.n.signin.app_name));
        m.insert("version".into(), json!(crate::REMOTE_VERSION));
        m.insert("root".into(), json!(w.root));
        m.insert("csrf".into(), json!(s.token().unwrap_or("")));
        m.insert("title".into(), json!(title));
        m.insert("error".into(), json!(error));
        m.insert("status".into(), json!(flashed.get("status").and_then(|v| v.as_str()).unwrap_or("")));
        m.insert("old_login".into(), json!(flashed.get("_old_input").and_then(|o| o.get("login")).and_then(|v| v.as_str()).unwrap_or("")));
    }
    let body = p.view.render(template, vars).map_err(Fault::Other)?;
    Ok(Out::new(html(200, body, false)))
}

/// Render a guest page and keep (age) its session.
fn show(p: &Pages, c: &Connection, w: &Web, s: &Session, template: &str, title: &str, vars: Value) -> Result<Out, Fault> {
    let mut out = page(p, w, s, template, title, vars)?;
    keep(p, c, w, s, s.data.clone(), vec![], &mut out)?;
    Ok(out)
}

/// `back()->withErrors([$field => $message])` (and old input) to one of these pages.
fn back(p: &Pages, c: &Connection, w: &Web, s: &Session, data: Map<String, Value>, to: &str, field: &str, message: &str, old: Option<Value>) -> Result<Out, Fault> {
    let mut out = Out::new(redirect(&format!("{}{to}", w.root)));
    let mut flashes = vec![("errors", json!({ field: [message] }))];
    if let Some(o) = old {
        flashes.push(("_old_input", o));
    }
    keep(p, c, w, s, data, flashes, &mut out)?;
    Ok(out)
}

fn with_status(p: &Pages, c: &Connection, w: &Web, s: &Session, data: Map<String, Value>, to: &str, status: &str) -> Result<Out, Fault> {
    let mut out = Out::new(redirect(&format!("{}{to}", w.root)));
    keep(p, c, w, s, data, vec![("status", json!(status))], &mut out)?;
    Ok(out)
}

fn user_by_id(c: &Connection, id: i64) -> Result<Option<Row>, Fault> {
    db::first(c, r#"select * from "users" where "users"."id" = ? limit 1"#, &[P(Val::Int(id))])
}

fn text(r: &Row, col: &str) -> String {
    String::from_utf8_lossy(&r.val(col).to_php_string().unwrap_or_default()).into_owned()
}

fn input(w: &Web, k: &str) -> Option<Val> {
    w.input.get(k).cloned().filter(|v| !matches!(v, Val::Null))
}

/// `$request->validate([$k => ['required', 'string']])`: the message, if it fails.
fn required_string(w: &Web, k: &str) -> Option<String> {
    match w.input.get(k) {
        None | Some(Val::Null) => Some(format!("The {k} field is required.")),
        Some(Val::Arr(_)) => Some(format!("The {k} field must be a string.")),
        _ => None,
    }
}

/// The local part of `APP_URL`'s host, for EHLO and the Message-ID.
fn local_domain(root: &str) -> String {
    url::Url::parse(root).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default()
}

/// Render a mail template and send it through the configured relay. False when not sent (recorded as the previous console does).
fn send_mail(p: &Pages, c: &Connection, w: &Web, to: &str, subject: &str, template: &str, mut vars: Value) -> Result<bool, Fault> {
    if let Value::Object(m) = &mut vars {
        m.insert("app_name".into(), json!(p.n.signin.app_name));
        m.insert("root".into(), json!(w.root.trim_end_matches('/')));
    }
    let html = p.view.render(template, vars).map_err(Fault::Other)?;
    let msg = crate::mail::Message { to: to.to_string(), subject: subject.to_string(), html };
    crate::mail::send(c, &p.n.crypt, &p.n.signin.app_name, &local_domain(&w.root), &msg, w.now)
}

/// Route throttles (`throttle:<max>,1,<prefix>`): Laravel's key, the prefix and sha1 of `|<ip>`.
pub(super) fn route_throttled(p: &Pages, w: &Web, (prefix, max, post_only): (&str, u64, bool)) -> bool {
    if post_only && w.method != "POST" {
        return false;
    }
    use sha1::Digest as _;
    let key = format!("{prefix}{}", hex::encode(sha1::Sha1::digest(format!("|{}", w.ip).as_bytes()))).into_bytes();
    let mut l = p.n.limiter.lock().unwrap_or_else(|e| e.into_inner());
    if l.too_many(&key, max, w.now) {
        return true;
    }
    l.hit(&key, 60, w.now);
    false
}

/// `$user->is_admin || $user->consoleAllows('setting', 'rw')`
pub(super) fn may_repair_mail(c: &Connection, user: &Row) -> Result<bool, Fault> {
    if user.val("is_admin").to_bool() {
        return Ok(true);
    }
    if user.is_null("role_id") {
        return Ok(false);
    }
    let role = db::first(c, r#"select * from "roles" where "roles"."id" = ? limit 1"#, &[P(user.val("role_id"))])?;
    let perms: Value = role.and_then(|r| r.val("permissions").to_php_string().ok()).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
    Ok(perms.get("setting").and_then(|v| v.as_str()) == Some("rw"))
}

/// The pending marker under `key`, when it is younger than `ttl` (else it is dropped from `data`).
fn pending(data: &mut Map<String, Value>, key: &str, ttl: i64, now: i64) -> Option<Map<String, Value>> {
    let m = data.get(key)?.as_object()?.clone();
    m.get("user_id")?.as_i64().filter(|id| *id > 0)?;
    if m.get("at").and_then(|v| v.as_i64()).unwrap_or(0) + ttl < now {
        data.remove(key);
        return None;
    }
    Some(m)
}

// ------------------------------------------------------------------------------------------- two-factor ---

/// The password step's hand-off: a pending marker, then the challenge page.
pub(super) fn start_two_factor(p: &Pages, c: &Connection, w: &Web, s: &Session, user: &Row, remember: bool) -> Result<Out, Fault> {
    let mut data = s.data.clone();
    data.insert("2fa".into(), json!({"user_id": user.id(), "at": w.now, "remember": remember}));
    let mut out = Out::new(redirect(&format!("{}/login/2fa", w.root)));
    keep(p, c, w, s, data, vec![], &mut out)?;
    Ok(out)
}

/// `pendingUser()`: the account the marker names, still active and still enrolled.
fn two_factor_user(c: &Connection, data: &mut Map<String, Value>, now: i64) -> Result<Option<(Row, bool)>, Fault> {
    let Some(m) = pending(data, "2fa", PENDING_TTL, now) else { return Ok(None) };
    let remember = m.get("remember").and_then(|v| v.as_bool()).unwrap_or(false);
    let user = user_by_id(c, m.get("user_id").and_then(|v| v.as_i64()).unwrap_or(0))?;
    Ok(user.filter(|u| u.val("is_active").to_bool() && u.val("totp_enabled").to_bool()).map(|u| (u, remember)))
}

pub(super) fn two_factor_show(p: &Pages, c: &Connection, w: &Web) -> Result<Out, Fault> {
    let s = guest_session(p, c, w)?;
    if signed_in(c, &s)? {
        return already_signed_in(p, c, w, &s);
    }
    let mut data = s.data.clone();
    if two_factor_user(c, &mut data, w.now)?.is_none() {
        let mut out = Out::new(redirect(&format!("{}/login", w.root)));
        keep(p, c, w, &s, data, vec![], &mut out)?;
        return Ok(out);
    }
    show(p, c, w, &s, "auth/two-factor-challenge.html", "Two-Factor Authentication", json!({}))
}

pub(super) fn two_factor_post(p: &Pages, c: &Connection, w: &Web) -> Result<Out, Fault> {
    let s = guest_session(p, c, w)?;
    if !csrf(p, &s, w) {
        return Ok(page_expired());
    }
    if signed_in(c, &s)? {
        return already_signed_in(p, c, w, &s);
    }
    let mut data = s.data.clone();
    let Some((user, remember)) = two_factor_user(c, &mut data, w.now)? else {
        return back(p, c, w, &s, data, "/login", "code", EXPIRED_STEP, None);
    };
    if let Some(m) = required_string(w, "code") {
        return back(p, c, w, &s, data, "/login/2fa", "code", &m, None);
    }
    let code = String::from_utf8_lossy(php::trim(&w.input.string("code")?)).into_owned();
    let key = crate::signin::code_throttle_key(user.id());
    let info = vec![("ip", Val::str(&w.ip)), ("username", user.val("username")), ("step", Val::str("two-factor")), ("attempts", Val::Int(crate::signin::CODE_MAX_PER_ACCOUNT as i64))];
    if let Some(m) = rate_limited(p, c, w, &key, crate::signin::CODE_MAX_PER_ACCOUNT, login::TYP_BRUTE_FORCE, info)? {
        return back(p, c, w, &s, data, "/login/2fa", "code", &m, None);
    }
    let result = if looks_like_recovery(&code) { consume_recovery(c, &user, &code, w.now)? } else { consume_totp(p, c, &user, &code, w.now)? };
    let warning = match result {
        Err(m) => {
            p.n.limiter.lock().unwrap_or_else(|e| e.into_inner()).hit(&key, crate::signin::CODE_DECAY, w.now);
            return back(p, c, w, &s, data, "/login/2fa", "code", m, None);
        }
        Ok(warning) => warning,
    };
    p.n.limiter.lock().unwrap_or_else(|e| e.into_inner()).clear(&key);
    tracing::info!("console sign-in: second factor accepted");
    let flashes = warning.map(|m| vec![("twofactor_warning".to_string(), json!(m))]).unwrap_or_default();
    let guest = Session { data, ..s };
    login::complete_with(p, c, w, &guest, &user, false, remember, vec![], flashes)
}

/// `TwoFactor::looksLikeRecoveryCode()`: XXXXX-XXXXX, letters and digits.
pub fn looks_like_recovery(v: &str) -> bool {
    let v = v.trim();
    let b = v.as_bytes();
    b.len() == 11 && b[5] == b'-' && b.iter().enumerate().all(|(i, c)| i == 5 || c.is_ascii_alphanumeric())
}

/// `TwoFactor::consumeTotp()`, through phase 2's port (the replay guard is the same conditional update).
fn consume_totp(p: &Pages, c: &Connection, user: &Row, code: &str, now: i64) -> Result<Result<Option<String>, &'static str>, Fault> {
    Ok(match crate::signin::consume_totp(&p.n, c, user, code.as_bytes(), now)? {
        None => Ok(None),
        Some(m) => Err(m),
    })
}

/// `consumeRecoveryCode()`: a bcrypt match among the unused codes, burnt by a conditional update; a warning when few remain.
fn consume_recovery(c: &Connection, user: &Row, code: &str, now: i64) -> Result<Result<Option<String>, &'static str>, Fault> {
    let wrong = "That recovery code is invalid or already used.";
    let normalized = code.trim().to_ascii_uppercase();
    let rows = db::rows(c, r#"select * from "two_factor_recovery_codes" where "two_factor_recovery_codes"."user_id" = ? and "two_factor_recovery_codes"."user_id" is not null and "used_at" is null"#, &[P(user.val("id"))])?;
    let mut found = None;
    for r in &rows {
        if laravel::hash_check(normalized.as_bytes(), &r.val("code_hash"))? {
            found = Some(r.id());
            break;
        }
    }
    let Some(id) = found else { return Ok(Err(wrong)) };
    let claimed = db::exec(
        c,
        r#"update "two_factor_recovery_codes" set "used_at" = ? where "two_factor_recovery_codes"."user_id" = ? and "two_factor_recovery_codes"."user_id" is not null and "two_factor_recovery_codes"."id" = ? and "used_at" is null"#,
        &[P(Val::str(&laravel::ts(now))), P(user.val("id")), P(Val::Int(id))],
    )?;
    if claimed == 0 {
        return Ok(Err(wrong));
    }
    let left = db::first(c, r#"select count(*) as aggregate from "two_factor_recovery_codes" where "two_factor_recovery_codes"."user_id" = ? and "two_factor_recovery_codes"."user_id" is not null and "used_at" is null"#, &[P(user.val("id"))])?
        .map(|r| r.val("aggregate").to_int())
        .unwrap_or(0);
    Ok(Ok((left <= RECOVERY_LOW).then(|| format!("You have {left} recovery code(s) left. Regenerate them from Account \u{2192} Two-Factor Authentication."))))
}

// --------------------------------------------------------------------------------------- e-mailed codes ---

/// `TrustedDevice::trustDays()`
fn trust_days(c: &Connection) -> Result<i64, Fault> {
    let v = String::from_utf8_lossy(&db::setting(c, "email_trusted_device_days", "30")?).trim().parse::<i64>().unwrap_or(0);
    Ok(if v == 0 { 30 } else { v.clamp(1, 365) })
}

fn device_cookie(c: &Connection, w: &Web, plain: &str) -> Result<String, Fault> {
    let days = trust_days(c)?;
    let max = days * 86400;
    let expires = chrono::DateTime::<chrono::Utc>::from_timestamp(w.now + max, 0).unwrap_or_default().format("%a, %d-%b-%Y %H:%M:%S GMT");
    Ok(format!("{DEVICE_COOKIE}={plain}; expires={expires}; Max-Age={max}; path=/; httponly; samesite=lax{}", if w.secure { "; secure" } else { "" }))
}

/// `LoginEmailVerification::required()` (TrustedDevice::matches slides a known browser's trust and re-sends its cookie).
pub(super) fn email_required(p: &Pages, c: &Connection, w: &Web, user: &Row, cookies: &mut Vec<String>) -> Result<bool, Fault> {
    let _ = p;
    if !(db::setting(c, "email_login_verification", "0")? == b"1" && crate::mail::enabled(c)?) {
        return Ok(false);
    }
    if php::trim(&user.val("email").to_php_string()?).is_empty() {
        return Ok(false);
    }
    let plain = super::session::cookie_value(&w.cookie, DEVICE_COOKIE).map(|v| String::from_utf8_lossy(&v).into_owned()).unwrap_or_default();
    if plain.is_empty() {
        return Ok(true);
    }
    let hash = hex::encode(Sha256::digest(plain.as_bytes()));
    let device = db::first(
        c,
        r#"select * from "trusted_devices" where "user_id" = ? and "token_hash" = ? and "expires_at" > ? limit 1"#,
        &[P(user.val("id")), P(Val::str(&hash)), P(Val::str(&laravel::ts(w.now)))],
    )?;
    let Some(mut d) = device else { return Ok(true) };
    let days = trust_days(c)?;
    db::update_dirty(
        c,
        "trusted_devices",
        &mut d,
        vec![
            ("last_used_at", Val::str(&laravel::ts(w.now)), laravel::Cast::Date),
            ("expires_at", Val::str(&laravel::ts(w.now + days * 86400)), laravel::Cast::Date),
            ("ip", Val::str(&w.ip), laravel::Cast::Plain),
        ],
        &laravel::ts(w.now),
    )?;
    cookies.push(device_cookie(c, w, &plain)?);
    Ok(false)
}

/// `TrustedDevice::remember()`
fn remember_device(c: &Connection, w: &Web, user: &Row) -> Result<String, Fault> {
    let plain = laravel::str_random(48);
    let days = trust_days(c)?;
    let label: String = w.ua.chars().take(250).collect();
    db::insert(
        c,
        "trusted_devices",
        vec![
            ("user_id", user.val("id")),
            ("token_hash", Val::str(&hex::encode(Sha256::digest(plain.as_bytes())))),
            ("label", Val::str(&label)),
            ("ip", Val::str(&w.ip)),
            ("last_used_at", Val::str(&laravel::ts(w.now))),
            ("expires_at", Val::str(&laravel::ts(w.now + days * 86400))),
        ],
        &laravel::ts(w.now),
    )?;
    device_cookie(c, w, &plain)
}

/// `startEmailVerification()`: a fresh 6-digit code mailed, its bcrypt hash in the marker. Err(()) when not sent
/// (the `login_logs` row the previous console writes for it is written here too).
pub(super) fn start_email(p: &Pages, c: &Connection, w: &Web, s: &Session, user: &Row, remember: bool) -> Result<Result<Out, ()>, Fault> {
    use rand::Rng;
    let code = format!("{:06}", rand::rngs::OsRng.gen_range(0..1_000_000u32));
    let email = text(user, "email");
    let username = text(user, "username");
    let sent = send_mail(
        p,
        c,
        w,
        &email,
        &format!("{code} is your {} sign-in code", p.n.signin.app_name),
        "mail/login-code.html",
        json!({"code": code, "username": username, "ip": w.ip, "minutes": EMAIL_PENDING_TTL / 60}),
    )?;
    if !sent {
        tracing::warn!("sign-in verification email could not be sent");
        login_log_note(c, user.val("id"), user.val("username"), "web", &w.ip, true, Some("email-verification send failed"), w.now)?;
        return Ok(Err(()));
    }
    let mut data = s.data.clone();
    data.insert(
        "email_verify".into(),
        json!({"user_id": user.id(), "at": w.now, "remember": remember, "code_hash": laravel::hash_make(code.as_bytes())?, "sent_to": email}),
    );
    let mut out = Out::new(redirect(&format!("{}/login/email", w.root)));
    keep(p, c, w, s, data, vec![], &mut out)?;
    Ok(Ok(out))
}

/// `emailPendingUser()`
fn email_user(c: &Connection, data: &mut Map<String, Value>, now: i64) -> Result<Option<(Row, Map<String, Value>)>, Fault> {
    let Some(m) = pending(data, "email_verify", EMAIL_PENDING_TTL, now) else { return Ok(None) };
    let user = user_by_id(c, m.get("user_id").and_then(|v| v.as_i64()).unwrap_or(0))?;
    Ok(user.filter(|u| u.val("is_active").to_bool()).map(|u| (u, m)))
}

/// `LoginEmailVerification::maskEmail()`: j••••@example.com
pub fn mask_email(email: &str) -> String {
    let Some((local, domain)) = email.split_once('@') else { return String::new() };
    let mut chars = local.chars();
    let first: String = chars.next().map(String::from).unwrap_or_default();
    let rest = local.chars().count().saturating_sub(1).max(1);
    format!("{first}{}@{domain}", "\u{2022}".repeat(rest))
}

pub(super) fn email_show(p: &Pages, c: &Connection, w: &Web) -> Result<Out, Fault> {
    let s = guest_session(p, c, w)?;
    if signed_in(c, &s)? {
        return already_signed_in(p, c, w, &s);
    }
    let mut data = s.data.clone();
    let Some((_, m)) = email_user(c, &mut data, w.now)? else {
        let mut out = Out::new(redirect(&format!("{}/login", w.root)));
        keep(p, c, w, &s, data, vec![], &mut out)?;
        return Ok(out);
    };
    let sent_to = mask_email(m.get("sent_to").and_then(|v| v.as_str()).unwrap_or(""));
    show(p, c, w, &s, "auth/email-challenge.html", "Verify Sign-In", json!({"sent_to": sent_to, "trust_days": trust_days(c)?}))
}

pub(super) fn email_post(p: &Pages, c: &Connection, w: &Web) -> Result<Out, Fault> {
    let s = guest_session(p, c, w)?;
    if !csrf(p, &s, w) {
        return Ok(page_expired());
    }
    if signed_in(c, &s)? {
        return already_signed_in(p, c, w, &s);
    }
    let mut data = s.data.clone();
    let Some((user, m)) = email_user(c, &mut data, w.now)? else {
        return back(p, c, w, &s, data, "/login", "code", EXPIRED_STEP, None);
    };
    if let Some(msg) = required_string(w, "code") {
        return back(p, c, w, &s, data, "/login/email", "code", &msg, None);
    }
    let code: Vec<u8> = w.input.string("code")?.into_iter().filter(u8::is_ascii_digit).collect();
    let key = crate::signin::code_throttle_key(user.id());
    let info = vec![("ip", Val::str(&w.ip)), ("username", user.val("username")), ("step", Val::str("email-verification")), ("attempts", Val::Int(crate::signin::CODE_MAX_PER_ACCOUNT as i64))];
    if let Some(msg) = rate_limited(p, c, w, &key, crate::signin::CODE_MAX_PER_ACCOUNT, login::TYP_BRUTE_FORCE, info)? {
        return back(p, c, w, &s, data, "/login/email", "code", &msg, None);
    }
    let hash = m.get("code_hash").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if hash.is_empty() || !laravel::hash_check(&code, &Val::str(&hash))? {
        p.n.limiter.lock().unwrap_or_else(|e| e.into_inner()).hit(&key, crate::signin::CODE_DECAY, w.now);
        return back(p, c, w, &s, data, "/login/email", "code", "That code is incorrect or has expired.", None);
    }
    p.n.limiter.lock().unwrap_or_else(|e| e.into_inner()).clear(&key);
    let cookie = remember_device(c, w, &user)?;
    let remember = m.get("remember").and_then(|v| v.as_bool()).unwrap_or(false);
    data.remove("email_verify");
    tracing::info!("console sign-in: e-mailed code accepted");
    let guest = Session { data, ..s };
    let mut out = login::complete(p, c, w, &guest, &user, false, remember)?;
    out.cookies.push(cookie);
    Ok(out)
}

pub(super) fn email_resend(p: &Pages, c: &Connection, w: &Web) -> Result<Out, Fault> {
    let s = guest_session(p, c, w)?;
    if !csrf(p, &s, w) {
        return Ok(page_expired());
    }
    if signed_in(c, &s)? {
        return already_signed_in(p, c, w, &s);
    }
    let mut data = s.data.clone();
    let Some((user, m)) = email_user(c, &mut data, w.now)? else {
        let mut out = Out::new(redirect(&format!("{}/login", w.root)));
        keep(p, c, w, &s, data, vec![], &mut out)?;
        return Ok(out);
    };
    let key = format!("email-verify-resend:{}|{}", user.id(), w.ip).into_bytes();
    {
        let mut l = p.n.limiter.lock().unwrap_or_else(|e| e.into_inner());
        if l.too_many(&key, 3, w.now) {
            let wait = l.available_in(&key, w.now);
            drop(l);
            return back(p, c, w, &s, data, "/login/email", "code", &format!("Too many attempts. Try again in {wait} seconds."), None);
        }
        l.hit(&key, login::DECAY, w.now);
    }
    let remember = m.get("remember").and_then(|v| v.as_bool()).unwrap_or(false);
    let s2 = Session { data: data.clone(), ..s.clone() };
    match start_email(p, c, w, &s2, &user, remember)? {
        Ok(_) => {
            // the new marker is saved; the page says so
            let fresh = super::websession::load_id(c, &p.own, w.now, &s.id)?.unwrap_or(s2);
            with_status(p, c, w, &fresh, fresh.data.clone(), "/login/email", "A new code is on its way.")
        }
        Err(()) => {
            if !may_repair_mail(c, &user)? {
                data.remove("email_verify");
                return back(p, c, w, &s, data, "/login", "username", "Sign-in is temporarily unavailable: this console cannot send verification codes. Contact an administrator.", None);
            }
            data.remove("email_verify");
            let guest = Session { data, ..s };
            let mut out = login::complete_with(p, c, w, &guest, &user, false, remember, vec![("mail_repair".into(), json!(true))], vec![])?;
            out.resp = redirect(&format!("{}/settings?tab=email", w.root));
            Ok(out)
        }
    }
}

// ----------------------------------------------------------------------------------------- password reset ---

/// `available()`: a working relay, and password sign-in not switched off.
fn reset_available(p: &Pages, c: &Connection) -> Result<bool, Fault> {
    let s = crate::oidc::Settings::load(c, &p.n.crypt)?;
    Ok(crate::mail::enabled(c)? && !s.local_login_disabled(p.n.signin.oidc.env_disabled))
}

fn to_login(p: &Pages, c: &Connection, w: &Web, s: &Session) -> Result<Out, Fault> {
    let mut out = Out::new(redirect(&format!("{}/login", w.root)));
    keep(p, c, w, s, s.data.clone(), vec![], &mut out)?;
    Ok(out)
}

/// `mayReset()`
fn may_reset(u: &Row) -> bool {
    u.val("is_active").to_bool() && u.val("auth_provider") != Val::str("oidc") && u.val("oidc_status") != Val::str("pending") && !php::trim(&u.val("email").to_php_string().unwrap_or_default()).is_empty()
}

pub(super) fn forgot_show(p: &Pages, c: &Connection, w: &Web) -> Result<Out, Fault> {
    let s = guest_session(p, c, w)?;
    if signed_in(c, &s)? {
        return already_signed_in(p, c, w, &s);
    }
    if !reset_available(p, c)? {
        return to_login(p, c, w, &s);
    }
    show(p, c, w, &s, "auth/password-request.html", "Reset Password", json!({}))
}

pub(super) fn forgot_post(p: &Pages, c: &Connection, w: &Web) -> Result<Out, Fault> {
    let s = guest_session(p, c, w)?;
    if !csrf(p, &s, w) {
        return Ok(page_expired());
    }
    if signed_in(c, &s)? {
        return already_signed_in(p, c, w, &s);
    }
    if !reset_available(p, c)? {
        return to_login(p, c, w, &s);
    }
    let old = input(w, "login").and_then(|v| if let Val::Arr(_) = v { None } else { v.to_php_string().ok() }).map(|b| json!({"login": String::from_utf8_lossy(&b)}));
    let login_text = String::from_utf8_lossy(php::trim(&w.input.get("login").and_then(|v| v.to_php_string().ok()).unwrap_or_default())).into_owned();
    let invalid = required_string(w, "login").or_else(|| (login_text.chars().count() > 255).then(|| "The login field must not be greater than 255 characters.".to_string()));
    if let Some(m) = invalid {
        return back(p, c, w, &s, s.data.clone(), "/forgot-password", "login", &m, old);
    }
    let user = db::first(c, r#"select * from "users" where "username" = ? or LOWER(email) = ? limit 1"#, &[P(Val::str(&login_text)), P(Val::str(&login_text.to_lowercase()))])?;
    let mail = match user {
        Some(u) if may_reset(&u) => dispatch_link(p, c, w, &u)?,
        Some(_) => {
            tracing::info!("password reset refused (account not resettable)");
            None
        }
        None => None,
    };
    // the same answer at the same speed whatever the account: the mail goes after it, without the lock
    let mut out = with_status(p, c, w, &s, s.data.clone(), "/forgot-password", NEUTRAL)?;
    if let Some((msg, id)) = mail {
        out.later.push((msg, Some(id)));
    }
    Ok(out)
}

/// `PasswordReset::issue()` and the mail to send (after the answer, without the database lock).
fn dispatch_link(p: &Pages, c: &Connection, w: &Web, u: &Row) -> Result<Option<(crate::mail::Message, i64)>, Fault> {
    let ts = laravel::ts(w.now);
    // one live link per account (Eloquent's query-builder update also sets updated_at)
    db::exec(
        c,
        r#"update "password_resets" set "used_at" = ?, "updated_at" = ? where "user_id" = ? and "used_at" is null"#,
        &[P(Val::str(&ts)), P(Val::str(&ts)), P(u.val("id"))],
    )?;
    let plain = format!("rst_{}", laravel::str_random(48));
    let id = db::insert(
        c,
        "password_resets",
        vec![
            ("user_id", u.val("id")),
            ("token_hash", Val::str(&hex::encode(Sha256::digest(plain.as_bytes())))),
            ("requested_ip", Val::str(&w.ip)),
            ("expires_at", Val::str(&laravel::ts(w.now + RESET_TTL_MIN * 60))),
        ],
        &ts,
    )?;
    let url = format!("{}/reset-password/{plain}", w.root);
    let html = p
        .view
        .render("mail/password-reset.html", json!({"app_name": p.n.signin.app_name, "root": w.root.trim_end_matches('/'), "username": text(u, "username"), "url": url, "minutes": RESET_TTL_MIN, "ip": w.ip}))
        .map_err(Fault::Other)?;
    let msg = crate::mail::Message { to: text(u, "email"), subject: format!("Reset your {} password", p.n.signin.app_name), html };
    Ok(Some((msg, id)))
}

fn token_of(w: &Web) -> String {
    let last = w.path.rsplit('/').next().unwrap_or("");
    String::from_utf8_lossy(&php::urldecode(last.as_bytes())).into_owned()
}

/// `PasswordReset::findValid()`
fn find_reset(c: &Connection, plain: &str, now: i64) -> Result<Option<Row>, Fault> {
    db::first(
        c,
        r#"select * from "password_resets" where "token_hash" = ? and "used_at" is null and "expires_at" > ? limit 1"#,
        &[P(Val::str(&hex::encode(Sha256::digest(plain.as_bytes())))), P(Val::str(&laravel::ts(now)))],
    )
}

pub(super) fn reset_show(p: &Pages, c: &Connection, w: &Web) -> Result<Out, Fault> {
    let s = guest_session(p, c, w)?;
    if signed_in(c, &s)? {
        return already_signed_in(p, c, w, &s);
    }
    let token = token_of(w);
    if !reset_available(p, c)? || find_reset(c, &token, w.now)?.is_none() {
        return back(p, c, w, &s, s.data.clone(), "/login", "username", BAD_LINK, None);
    }
    show(p, c, w, &s, "auth/password-reset.html", "Choose a New Password", json!({"token": token}))
}

/// `['required', 'string', 'min:8', 'confirmed']` (and `same:password_confirmation` for the invitation): the first message.
pub(super) fn new_password_error(w: &Web, confirmed_message: &str, confirmation_required: Option<&str>) -> Option<(&'static str, String)> {
    let pw = w.input.get("password");
    let first = match pw {
        None | Some(Val::Null) => Some("The password field is required.".to_string()),
        Some(Val::Arr(_)) => Some("The password field must be a string.".to_string()),
        Some(v) => {
            let t = v.to_php_string().unwrap_or_default();
            if String::from_utf8_lossy(&t).chars().count() < 8 {
                Some("The password field must be at least 8 characters.".to_string())
            } else if w.input.get("password_confirmation").and_then(|c| c.to_php_string().ok()) != Some(t) {
                Some(confirmed_message.to_string())
            } else {
                None
            }
        }
    };
    if let Some(m) = first {
        return Some(("password", m));
    }
    if let Some(m) = confirmation_required {
        if matches!(w.input.get("password_confirmation"), None | Some(Val::Null)) {
            return Some(("password_confirmation", m.to_string()));
        }
    }
    None
}

pub(super) fn reset_post(p: &Pages, c: &Connection, w: &Web) -> Result<Out, Fault> {
    let s = guest_session(p, c, w)?;
    if !csrf(p, &s, w) {
        return Ok(page_expired());
    }
    if signed_in(c, &s)? {
        return already_signed_in(p, c, w, &s);
    }
    if !reset_available(p, c)? {
        return to_login(p, c, w, &s);
    }
    let token = token_of(w);
    if let Some((field, m)) = new_password_error(w, "The password field confirmation does not match.", None) {
        return back(p, c, w, &s, s.data.clone(), &format!("/reset-password/{}", crate::laravel::urlencode(token.as_bytes())), field, &m, None);
    }
    let reset = find_reset(c, &token, w.now)?;
    let user = match &reset {
        Some(r) => user_by_id(c, r.val("user_id").to_int())?,
        None => None,
    };
    let (Some(reset), Some(mut user)) = (reset, user.filter(may_reset)) else {
        return back(p, c, w, &s, s.data.clone(), "/login", "username", BAD_LINK, None);
    };
    let ts = laravel::ts(w.now);
    // burn the link before changing anything: of two racing submissions only one proceeds
    let claimed = db::exec(c, r#"update "password_resets" set "used_at" = ?, "updated_at" = ? where "id" = ? and "used_at" is null"#, &[P(Val::str(&ts)), P(Val::str(&ts)), P(reset.val("id"))])?;
    if claimed != 1 {
        return back(p, c, w, &s, s.data.clone(), "/login", "username", "That reset link has already been used.", None);
    }
    let hash = laravel::hash_make(&w.input.string("password")?)?;
    super::kit::update(c, "users", &mut user, vec![("password", Val::str(&hash), laravel::Cast::Plain)], w.now)?;
    // the recovery path for a compromised account ends every session and client token (force logout's revocation)
    super::kit::revoke_all_access(c, &mut user, w.now)?;
    login_log_note(c, user.val("id"), user.val("username"), "web", &w.ip, true, Some("password reset"), w.now)?;
    tracing::info!("password reset completed");
    with_status(p, c, w, &s, s.data.clone(), "/login", "Your password has been reset. Sign in with the new one.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_and_shapes() {
        assert_eq!(mask_email("john@example.com"), "j\u{2022}\u{2022}\u{2022}@example.com");
        assert_eq!(mask_email("j@example.com"), "j\u{2022}@example.com");
        assert_eq!(mask_email("nobody"), "");
        assert!(looks_like_recovery("ABCDE-23456"));
        assert!(looks_like_recovery(" abcde-23456 "));
        assert!(!looks_like_recovery("123456"));
        assert!(!looks_like_recovery("ABCDE_23456"));
    }
}
