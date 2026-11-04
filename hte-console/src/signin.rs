//! Phase 2: the RustDesk client's sign-in, ported from v1.15.0-hte.1 statement by statement:
//!
//!   GET|HEAD /api/login-options              ClientAuthController::loginOptions
//!   POST     /api/login                       ClientAuthController::login (password, then TOTP; challenge, verifyCode)
//!   POST     /api/logout, /api/currentUser    ClientAuthController (behind the `client-token` guard)
//!   POST     /api/oidc/auth                   ClientOidcController::auth
//!   GET      /api/oidc/auth-query             ClientOidcController::authQuery
//!   GET      /login/oidc/client-callback      ClientOidcController::browserCallback (+ OidcUserResolver)
//!
//! with what they write: `client_tokens` (ClientToken::issue, the guard's `last_used_at`), `oidc_auth_requests`,
//! `login_logs`, `users` (OIDC linking and provisioning, the TOTP replay pointer), `alarm_logs` (brute force on the
//! code step), `devices` (DeviceEnrollment::signedIn: a pending device is approved and owned on sign-in).
//!
//! Not ported: the emailed sign-in code (it needs the console's mail relay): with `email_login_verification` on and
//! mail configured, a password sign-in gets the previous console's own fail-closed answer, and `serve` warns at start. Apprise
//! notifications (failed sign-in, device pending) are not sent (Apprise is not ported). Differences from the previous console that a
//! valid client cannot see are listed in the crate's README ("Phase 2: deliberate differences").

use crate::api::{fail, Native, Reply};
use crate::laravel::{self, Cast, Input};
use crate::oidc::{OidcError, Settings};
use crate::php::{self, Fault, Val};
use crate::sqlite::{self as db, Row, P};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

/// `ClientToken::LIFETIME_DAYS`
pub const TOKEN_LIFETIME_DAYS: i64 = 30;
/// `OidcAuthRequest::TTL_SECONDS`
pub const OIDC_REQUEST_TTL: i64 = 300;
/// ClientAuthController: `CHALLENGE_TTL`, `CHALLENGE_TRIES`, `MAX_PER_ACCOUNT`, `DECAY`, `ALARM_COOLDOWN`.
pub const CHALLENGE_TTL: i64 = 600;
pub const CHALLENGE_TRIES: u32 = 5;
pub const MAX_PER_ACCOUNT: u64 = 5;
pub const DECAY: i64 = 60;
/// Wrong 2FA, recovery and e-mailed codes: 10 per account in 15 minutes from any address, one count shared by the console's sign-in and the
/// RustDesk client's (CortenDesk 1.19.0).
pub const CODE_MAX_PER_ACCOUNT: u64 = 10;
pub const CODE_DECAY: i64 = 900;
pub fn code_throttle_key(user_id: i64) -> Vec<u8> {
    format!("login-code:{user_id}").into_bytes()
}
/// `AlarmLog::TYP_BRUTE_FORCE`
pub const TYP_BRUTE_FORCE: i64 = 100;
/// The client keeps polling while it reads exactly this.
pub const PENDING: &str = "No authed oidc is found";

/// A code prompt between the password step and the code step (the previous console keeps it in its cache, keyed by sha256(secret)).
#[derive(Clone, Debug)]
pub struct Challenge {
    pub user_id: i64,
    pub tfa: bool,
    pub device_id: Vec<u8>,
    pub expires: i64,
    pub tries: u32,
    pub code_hash: Option<String>,
}

/// Process memory phase 2 needs besides the database.
pub struct State {
    pub oidc: crate::oidc::Oidc,
    pub challenges: std::sync::Mutex<crate::api::Generations<Challenge>>,
    /// `Cache::add('alarm-raised:'.sha1($key), true, 300)`
    pub alarms: std::sync::Mutex<crate::api::Nonces>,
    /// Browser callbacks being completed right now, by state (a second use of one state waits for nothing: refused).
    pub inflight: std::sync::Mutex<std::collections::HashSet<String>>,
    /// `HTE_CONSOLE_PUBLIC_URL`: the console's own origin as browsers and the identity provider know it. When set,
    /// the OIDC redirect URI and the page's links come from it, never from the request's Host header.
    pub public_url: Option<String>,
    /// `APP_NAME` (page titles), as the CortenDesk image has it.
    pub app_name: String,
}

impl State {
    pub fn new(oidc: crate::oidc::Oidc, public_url: Option<String>, app_name: String) -> State {
        State {
            oidc,
            challenges: std::sync::Mutex::new(crate::api::Generations::new(CHALLENGE_TTL, 100_000)),
            alarms: std::sync::Mutex::new(crate::api::Nonces::default()),
            inflight: std::sync::Mutex::new(Default::default()),
            public_url: public_url.map(|u| u.trim_end_matches('/').to_string()),
            app_name,
        }
    }

    pub fn from_env() -> State {
        let public = crate::envvar::var("HTE_CONSOLE_PUBLIC_URL").ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        let app_name = crate::envvar::var("APP_NAME").ok().filter(|v| !v.is_empty()).unwrap_or_else(|| "HTE Remote".into());
        State::new(crate::oidc::Oidc::from_env(), public, app_name)
    }
}

fn json(pairs: Vec<(&str, Val)>) -> Result<Reply, Fault> {
    let v = php::assoc(pairs.into_iter().map(|(k, v)| (k.to_string(), v)));
    Ok(Reply::Json(200, php::json_encode(&v).ok_or_else(|| Fault::Other("json_encode failed".into()))?))
}

fn error(m: &str) -> Result<Reply, Fault> {
    json(vec![("error", Val::str(m))])
}

/// `$deviceInfo[$k] ?? null`
fn info(device_info: &php::Arr, k: &str) -> Val {
    device_info.get_str(k).cloned().unwrap_or(Val::Null)
}

/// `(array) $request->input('deviceInfo', [])`
fn device_info(input: &Input) -> php::Arr {
    input.get("deviceInfo").map(|v| v.to_array()).unwrap_or_default()
}

/// `$a ?? $b` (null counts as missing)
fn or(v: Val, d: Val) -> Val {
    if matches!(v, Val::Null) { d } else { v }
}

// ------------------------------------------------------------------------------------------------ users ---

pub fn find_user(c: &Connection, id: &Val) -> Result<Option<Row>, Fault> {
    db::first(c, r#"select * from "users" where "users"."id" = ? limit 1"#, &[P(id.clone())])
}

/// `SerializesUsers::userPayload()`, encoded (`info` must be an object).
pub fn user_payload(u: &Row) -> Result<String, Fault> {
    let username = u.val("username");
    let display = if u.val("name").to_bool() { u.val("name") } else { username.clone() };
    let v = php::assoc(vec![
        ("name".to_string(), username),
        ("display_name".to_string(), display),
        ("email".to_string(), Val::Str(u.val("email").to_php_string()?)),
        ("note".to_string(), Val::Str(u.val("note").to_php_string()?)),
        ("status".to_string(), Val::Int(if u.val("is_active").to_bool() { 1 } else { 0 })),
        ("is_admin".to_string(), Val::Bool(u.val("is_admin").to_bool())),
    ]);
    let s = php::json_encode(&v).ok_or_else(|| Fault::Other("json_encode of the user failed".into()))?;
    Ok(format!("{},\"info\":{{}}}}", &s[..s.len() - 1]))
}

/// The AuthBody both sign-in paths answer with.
fn auth_body(token: &str, user: &Row) -> Result<Reply, Fault> {
    let mut t = String::new();
    php::enc_str(token.as_bytes(), &mut t).ok_or_else(|| Fault::Other("token".into()))?;
    Ok(Reply::Json(200, format!(r#"{{"access_token":{t},"type":"access_token","tfa_type":"","secret":"","user":{}}}"#, user_payload(user)?)))
}

// ------------------------------------------------------------------------------------- tokens and guard ---

/// `ClientToken::issue($user, $deviceInfo)`: returns the new token.
pub fn issue_token(c: &Connection, user: &Row, id: Val, uuid: Val, os: Val, name: Val, typ: Val, now: i64) -> Result<String, Fault> {
    let token = laravel::str_random(48);
    db::insert(
        c,
        "client_tokens",
        vec![
            ("user_id", user.val("id")),
            ("token", Val::str(&token)),
            ("device_id", id),
            ("device_uuid", uuid),
            ("device_os", os),
            ("device_name", name),
            ("client_type", typ),
            ("expires_at", Val::str(&laravel::ts(now + TOKEN_LIFETIME_DAYS * 86_400))),
        ],
        &laravel::ts(now),
    )?;
    Ok(token)
}

/// The `client-token` guard (AppServiceProvider): the bearer's row, valid and owned by an active user; its
/// `last_used_at` is stamped (saveQuietly still writes updated_at).
pub fn authenticate(c: &Connection, bearer: Option<&[u8]>, now: i64) -> Result<Option<(Row, Row)>, Fault> {
    // `if (! $bearer)`: absent, "" and "0" are no token
    let Some(b) = bearer.filter(|b| !b.is_empty() && *b != b"0") else { return Ok(None) };
    let Some(mut token) = db::first(c, r#"select * from "client_tokens" where "token" = ? limit 1"#, &[P(Val::Str(b.to_vec()))])? else {
        return Ok(None);
    };
    // the lookup is by equality in SQLite; compare again in constant time before trusting it
    if !php::hash_equals(&token.val("token").to_php_string()?, b) {
        return Ok(None);
    }
    let valid = match token.val("expires_at") {
        Val::Null => true,
        v => laravel::parse_ts(&v).ok_or_else(|| Fault::Other("unparsable client_tokens.expires_at".into()))? > now,
    };
    if !valid {
        return Ok(None);
    }
    let Some(user) = find_user(c, &token.val("user_id"))? else { return Ok(None) };
    if !user.val("is_active").to_bool() {
        return Ok(None);
    }
    let ts = laravel::ts(now);
    db::update_dirty(c, "client_tokens", &mut token, vec![("last_used_at", Val::str(&ts), Cast::Date)], &ts)?;
    Ok(Some((token, user)))
}

/// POST /api/logout: the token is deleted; `{}` whatever happens.
pub fn logout(c: &Connection, token: &Row) -> Reply {
    match db::exec(c, r#"delete from "client_tokens" where "id" = ?"#, &[P(token.val("id"))]) {
        Ok(_) => Reply::Json(200, "{}".into()),
        Err(f) => fail("logout", &f),
    }
}

/// POST /api/currentUser
pub fn current_user(user: &Row) -> Reply {
    match user_payload(user) {
        Ok(s) => Reply::Json(200, s),
        Err(f) => fail("currentUser", &f),
    }
}

// ------------------------------------------------------------------------------------- login-options ---

/// GET /api/login-options
pub fn login_options(n: &Native, c: &Connection) -> Reply {
    let run = || -> Result<Reply, Fault> {
        let s = Settings::load(c, &n.crypt)?;
        if !s.is_enabled(n.signin.oidc.env_disabled) {
            return Ok(Reply::Json(200, "[]".into()));
        }
        // 'common-oidc/'.json_encode([['name' => ...]]), then the list itself json-encoded
        let inner = php::json_encode(&{
            let mut a = php::Arr::new();
            a.push(php::assoc(vec![("name".to_string(), Val::Str(s.client_provider_name().into_bytes()))]));
            Val::Arr(a)
        })
        .ok_or_else(|| Fault::Other("json".into()))?;
        let mut list = php::Arr::new();
        list.push(Val::Str(format!("common-oidc/{inner}").into_bytes()));
        Ok(Reply::Json(200, php::json_encode(&Val::Arr(list)).ok_or_else(|| Fault::Other("json".into()))?))
    };
    run().unwrap_or_else(|f| fail("login-options", &f))
}

// ------------------------------------------------------------------------------------------- password ---

fn login_log(c: &Connection, input: &Input, username: Val, user_id: Val, ok: bool, note: Val, ip: &str, now: i64) -> Result<(), Fault> {
    let di = device_info(input);
    db::insert(
        c,
        "login_logs",
        vec![
            ("user_id", user_id),
            ("username", username),
            ("client", or(info(&di, "type"), Val::str("client"))),
            ("device_id", input.get("id").cloned().unwrap_or(Val::Null)),
            ("device_os", info(&di, "os")),
            ("ip", Val::str(ip)),
            ("successful", Val::Bool(ok)),
            ("note", note),
        ],
        &laravel::ts(now),
    )?;
    Ok(())
}

/// `LoginEmailVerification::isActive()`
pub(crate) fn email_verification_active(c: &Connection) -> Result<bool, Fault> {
    let t = |k: &str| -> Result<Vec<u8>, Fault> { Ok(php::trim(&db::setting(c, k, "")?).to_vec()) };
    Ok(db::setting(c, "email_login_verification", "0")? == b"1" && t("smtp_enabled")? == b"1" && !t("smtp_host")?.is_empty() && !t("smtp_from_address")?.is_empty())
}

/// `RequireTwoFactor::isRequiredFor($user)`
pub(crate) fn two_factor_required(c: &Connection, user: &Row) -> Result<bool, Fault> {
    if db::setting(c, "two_factor_required", "0")? == b"1" {
        return Ok(true);
    }
    if user.val("is_admin").to_bool() && db::setting(c, "two_factor_required_admins", "0")? == b"1" {
        return Ok(true);
    }
    if user.is_null("role_id") {
        return Ok(false);
    }
    let role = db::first(c, r#"select * from "roles" where "roles"."id" = ? limit 1"#, &[P(user.val("role_id"))])?;
    Ok(role.map_or(false, |r| r.val("require_two_factor").to_bool()))
}

/// POST /api/login
pub fn login(n: &Native, c: &Connection, input: &Input, ip: &str, now: i64) -> Reply {
    login_inner(n, c, input, ip, now).unwrap_or_else(|f| fail("login", &f))
}

fn login_inner(n: &Native, c: &Connection, input: &Input, ip: &str, now: i64) -> Result<Reply, Fault> {
    let s = Settings::load(c, &n.crypt)?;
    if s.local_login_disabled(n.signin.oidc.env_disabled) {
        return error("Password sign-in is disabled. Use single sign-on.");
    }
    let typ = input.get("type");
    if typ == Some(&Val::str("email_code")) || typ == Some(&Val::str("tfa_code")) {
        return verify_code(n, c, input, ip, now);
    }
    let username = input.string("username")?;
    let password = input.string("password")?;
    let user = db::first(c, r#"select * from "users" where "username" = ? limit 1"#, &[P(Val::Str(username.clone()))])?;
    let ok = match &user {
        Some(u) if u.val("is_active").to_bool() && !password.is_empty() => laravel::hash_check(&password, &u.val("password"))?,
        _ => {
            // Hardened: as long as a wrong password, so the answer's timing does not tell which names exist.
            laravel::hash_check_dummy(&password);
            false
        }
    };
    let uid = if ok { user.as_ref().map_or(Val::Null, |u| u.val("id")) } else { Val::Null };
    login_log(c, input, Val::Str(username), uid, ok, Val::Null, ip, now)?;
    let Some(user) = user.filter(|_| ok) else {
        tracing::info!("client sign-in: wrong credentials");
        return error("Wrong credentials");
    };
    if user.val("auth_provider") == Val::str("oidc") {
        return error("This account signs in through single sign-on.");
    }
    if user.val("oidc_status") == Val::str("pending") {
        return error("Your account is waiting for administrator approval.");
    }
    if user.val("totp_enabled").to_bool() {
        return challenge(n, input, &user, now);
    }
    if two_factor_required(c, &user)? {
        return error("Two-factor authentication is required. Set it up in the web console, then sign in again.");
    }
    if email_verification_active(c)? && !php::trim(&user.val("email").to_php_string()?).is_empty() {
        return email_challenge(n, c, input, &user, ip, now);
    }
    sign_in(c, input, &user, ip, now)
}

fn challenge_key(secret: &[u8]) -> [u8; 32] {
    let mut k = b"client-login-challenge:".to_vec();
    k.extend_from_slice(hex::encode(Sha256::digest(secret)).as_bytes());
    Sha256::digest(&k).into()
}

/// `challenge($request, $user, 'tfa')`
fn challenge(n: &Native, input: &Input, user: &Row, now: i64) -> Result<Reply, Fault> {
    let pending = Challenge { user_id: user.id(), tfa: true, device_id: input.string("id")?, expires: now + CHALLENGE_TTL, tries: 0, code_hash: None };
    let secret = laravel::str_random(40);
    n.signin.challenges.lock().unwrap_or_else(|e| e.into_inner()).put(challenge_key(secret.as_bytes()), pending, now + CHALLENGE_TTL, now);
    // array_filter(['name' => ..., 'email' => null]): falsy values go
    let mut u = vec![];
    if user.val("username").to_bool() {
        u.push(("name".to_string(), user.val("username")));
    }
    let user_obj = if u.is_empty() { "[]".to_string() } else { php::json_encode(&php::assoc(u)).ok_or_else(|| Fault::Other("json".into()))? };
    let mut s = String::new();
    php::enc_str(secret.as_bytes(), &mut s).ok_or_else(|| Fault::Other("json".into()))?;
    Ok(Reply::Json(200, format!(r#"{{"type":"email_check","tfa_type":"tfa_check","secret":{s},"user":{user_obj}}}"#)))
}

/// `challenge($request, $user, 'email')` (phase 8, 0.8.2): a 6-digit code mailed through the console's relay, its bcrypt
/// hash kept with the prompt; when it cannot be sent the client gets the previous console's fail-closed answer (it cannot repair a relay).
fn email_challenge(n: &Native, c: &Connection, input: &Input, user: &Row, ip: &str, now: i64) -> Result<Reply, Fault> {
    use rand::Rng;
    static VIEW: once_cell::sync::Lazy<Option<crate::pages::view::View>> = once_cell::sync::Lazy::new(|| crate::pages::view::View::embedded().ok());
    let code = format!("{:06}", rand::rngs::OsRng.gen_range(0..1_000_000u32));
    let email = String::from_utf8_lossy(&user.val("email").to_php_string()?).into_owned();
    let username = String::from_utf8_lossy(&user.val("username").to_php_string()?).into_owned();
    let root = n.signin.public_url.clone().unwrap_or_default();
    let html = VIEW
        .as_ref()
        .ok_or_else(|| Fault::Other("templates unavailable".into()))?
        .render("mail/login-code.html", serde_json::json!({"app_name": n.signin.app_name, "root": root, "code": code, "username": username, "ip": ip, "minutes": CHALLENGE_TTL / 60}))
        .map_err(Fault::Other)?;
    let msg = crate::mail::Message { to: email.clone(), subject: format!("{code} is your {} sign-in code", n.signin.app_name), html };
    let domain = url::Url::parse(&root).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default();
    if !crate::mail::send(c, &n.crypt, &n.signin.app_name, &domain, &msg, now)? {
        return error("Sign-in is temporarily unavailable: this console cannot send verification codes. Contact an administrator.");
    }
    let pending = Challenge { user_id: user.id(), tfa: false, device_id: input.string("id")?, expires: now + CHALLENGE_TTL, tries: 0, code_hash: Some(laravel::hash_make(code.as_bytes())?) };
    let secret = laravel::str_random(40);
    n.signin.challenges.lock().unwrap_or_else(|e| e.into_inner()).put(challenge_key(secret.as_bytes()), pending, now + CHALLENGE_TTL, now);
    let mut u = vec![];
    if user.val("username").to_bool() {
        u.push(("name".to_string(), user.val("username")));
    }
    let masked = crate::pages::challenge::mask_email(&email);
    if !masked.is_empty() {
        u.push(("email".to_string(), Val::str(&masked)));
    }
    let user_obj = if u.is_empty() { "[]".to_string() } else { php::json_encode(&php::assoc(u)).ok_or_else(|| Fault::Other("json".into()))? };
    let mut s = String::new();
    php::enc_str(secret.as_bytes(), &mut s).ok_or_else(|| Fault::Other("json".into()))?;
    tracing::info!("client sign-in: e-mailed code sent");
    Ok(Reply::Json(200, format!(r#"{{"type":"email_check","tfa_type":"email_check","secret":{s},"user":{user_obj}}}"#)))
}

/// `verifyCode($request)`: the code step.
fn verify_code(n: &Native, c: &Connection, input: &Input, ip: &str, now: i64) -> Result<Reply, Fault> {
    let expired = || error("Your sign-in expired. Sign in again.");
    let secret = input.string("secret")?;
    let key = challenge_key(&secret);
    let pending = if secret.is_empty() { None } else { n.signin.challenges.lock().unwrap_or_else(|e| e.into_inner()).get(&key, now).map(|(p, _)| p) };
    let user = match &pending {
        Some(p) => find_user(c, &Val::Int(p.user_id))?,
        None => None,
    };
    let (Some(mut pending), Some(user)) = (pending, user) else { return expired() };
    if !user.val("is_active").to_bool() || pending.device_id != input.string("id")? {
        return expired();
    }
    let throttle_key = code_throttle_key(user.id());
    let too_many = n.limiter.lock().unwrap_or_else(|e| e.into_inner()).too_many(&throttle_key, CODE_MAX_PER_ACCOUNT, now);
    if too_many {
        let mut alarm_key = b"alarm-raised:".to_vec();
        alarm_key.extend_from_slice(hex::encode(sha1_of(&throttle_key)).as_bytes());
        let first = n.signin.alarms.lock().unwrap_or_else(|e| e.into_inner()).add(Sha256::digest(&alarm_key).into(), 300, now);
        if first {
            let info = php::assoc(vec![
                ("ip".to_string(), Val::str(ip)),
                ("username".to_string(), user.val("username")),
                ("step".to_string(), Val::str(if pending.tfa { "client-two-factor" } else { "client-email-verification" })),
                ("attempts".to_string(), Val::Int(CODE_MAX_PER_ACCOUNT as i64)),
            ]);
            let info = php::json_encode(&info).ok_or_else(|| Fault::Other("json".into()))?;
            db::insert(c, "alarm_logs", vec![("rustdesk_id", Val::str("console")), ("typ", Val::Int(TYP_BRUTE_FORCE)), ("info", Val::Str(info.into_bytes()))], &laravel::ts(now))?;
            tracing::warn!("client sign-in: too many wrong codes for one account (alarm raised)");
        }
        let wait = n.limiter.lock().unwrap_or_else(|e| e.into_inner()).available_in(&throttle_key, now);
        return error(&format!("Too many attempts. Try again in {wait} seconds."));
    }
    // `$request->input('tfaCode') ?: $request->input('verificationCode', '')`, digits only
    let raw = match input.get("tfaCode") {
        Some(v) if v.to_bool() => v.to_php_string()?,
        _ => input.string("verificationCode")?,
    };
    let code: Vec<u8> = raw.into_iter().filter(u8::is_ascii_digit).collect();
    let err: Option<&str> = if pending.tfa {
        if user.val("totp_enabled").to_bool() { consume_totp(n, c, &user, &code, now)? } else { Some("Your sign-in expired. Sign in again.") }
    } else {
        let h = pending.code_hash.clone().unwrap_or_default();
        if laravel::hash_check(&code, &Val::Str(h.into_bytes()))? { None } else { Some("That code is incorrect or has expired.") }
    };
    if let Some(m) = err {
        n.limiter.lock().unwrap_or_else(|e| e.into_inner()).hit(&throttle_key, CODE_DECAY, now);
        login_log(c, input, user.val("username"), Val::Null, false, Val::str("wrong verification code"), ip, now)?;
        pending.tries += 1;
        let left = pending.expires - now;
        let mut store = n.signin.challenges.lock().unwrap_or_else(|e| e.into_inner());
        if pending.tries >= CHALLENGE_TRIES || left <= 0 {
            store.remove(&key);
        } else {
            store.put(key, pending, now + left, now);
        }
        return error(m);
    }
    // one prompt, one token: Cache::pull
    let pulled = {
        let mut store = n.signin.challenges.lock().unwrap_or_else(|e| e.into_inner());
        let had = store.get(&key, now).is_some();
        store.remove(&key);
        had
    };
    if !pulled {
        return expired();
    }
    n.limiter.lock().unwrap_or_else(|e| e.into_inner()).clear(&throttle_key);
    sign_in(c, input, &user, ip, now)
}

fn sha1_of(b: &[u8]) -> [u8; 20] {
    use sha1::Digest as _;
    sha1::Sha1::digest(b).into()
}

/// `TwoFactor::consumeTotp($user, $code)`: None when accepted (and the step burnt), else the message.
pub(crate) fn consume_totp(n: &Native, c: &Connection, user: &Row, code: &[u8], now: i64) -> Result<Option<&'static str>, Fault> {
    // `totp_secret` has the `encrypted` cast: Crypt::decryptString on read, a DecryptException (500) when it fails
    let secret = match user.val("totp_secret") {
        Val::Null => Val::Null,
        v => Val::Str(n.crypt.decrypt_string(&v.to_php_string()?)?),
    };
    let step = if secret.to_bool() { crate::totp::verify(&secret.to_php_string()?, code, now)? } else { None };
    let Some(step) = step else { return Ok(Some("That code is incorrect or has expired.")) };
    let claimed = db::exec(
        c,
        r#"update "users" set "totp_last_timestep" = ?, "updated_at" = ? where "id" = ? and ("totp_last_timestep" is null or "totp_last_timestep" < ?)"#,
        &[P(Val::Int(step)), P(Val::str(&laravel::ts(now))), P(user.val("id")), P(Val::Int(step))],
    )?;
    if claimed == 0 {
        return Ok(Some("That code has already been used. Wait for the next one."));
    }
    Ok(None)
}

/// `signIn($request, $user)`: the token, the device, the AuthBody.
fn sign_in(c: &Connection, input: &Input, user: &Row, ip: &str, now: i64) -> Result<Reply, Fault> {
    let di = device_info(input);
    let raw = |k: &str| input.get(k).cloned().unwrap_or(Val::Null);
    let token = issue_token(c, user, raw("id"), raw("uuid"), info(&di, "os"), info(&di, "name"), info(&di, "type"), now)?;
    signed_in(c, user, &Val::Str(input.string("id")?), &Val::Str(input.string("uuid")?), &info(&di, "os"), Some(ip), now)?;
    tracing::info!("client sign-in: password accepted, token issued");
    auth_body(&token, user)
}

// ------------------------------------------------------------------------------------ device enrollment ---

/// `DeviceEnrollment::signedIn($user, ['id', 'uuid', 'os'], $ip)`: register the device the client signed in from,
/// or approve it (owned by this user when it had no owner) when `auto_approve_signed_in` says so.
pub fn signed_in(c: &Connection, user: &Row, id: &Val, uuid: &Val, os: &Val, ip: Option<&str>, now: i64) -> Result<(), Fault> {
    let id = php::trim(&id.to_php_string()?).to_vec();
    if id.is_empty() {
        return Ok(());
    }
    let ts = laravel::ts(now);
    let find = |c: &Connection| db::first(c, r#"select * from "devices" where "rustdesk_id" = ? limit 1"#, &[P(Val::Str(id.clone()))]);
    let mut device = match find(c)? {
        Some(d) if !d.is_null("deleted_at") => return Ok(()),
        Some(d) => d,
        None => {
            let gate = Val::Str(db::setting(c, "require_device_approval", "0")?).to_bool();
            let mut cols: Vec<(&str, Val)> = vec![
                ("rustdesk_id", Val::Str(id.clone())),
                ("uuid", Val::Str(uuid.to_php_string()?)),
                ("os", Val::Str(os.to_php_string()?)),
                ("status", Val::str(if gate { "pending" } else { "active" })),
                ("user_id", user.val("id")),
                ("registered_ip", ip.map_or(Val::Null, Val::str)),
            ];
            if Val::Str(db::setting(c, "new_devices_incoming_only", "0")?).to_bool() {
                cols.push(("can_initiate", Val::Bool(false)));
            }
            let group_id = Val::Str(db::setting(c, "default_device_group_id", "0")?).to_int();
            if group_id > 0 {
                if let Some(g) = db::first(c, r#"select * from "device_groups" where "device_groups"."id" = ? limit 1"#, &[P(Val::Int(group_id))])? {
                    cols.push(("device_group_id", g.val("id")));
                }
            }
            let mut row = Row(cols.iter().map(|(k, v)| (k.to_string(), v.clone())).collect());
            match db::insert(c, "devices", cols, &ts) {
                Ok(new_id) => {
                    row.set("id", Val::Int(new_id));
                    row.set("updated_at", Val::str(&ts));
                    row.set("created_at", Val::str(&ts));
                    crate::strategy::sync_resolved_for(c, &mut row, &ts)?;
                    crate::sync::approve_if_signed_in(c, &mut row, Some(user), now)?;
                    return Ok(());
                }
                // UniqueConstraintViolationException: the client's first sysinfo landed in the same instant
                Err(f) if is_unique_violation(&f) => match find(c)? {
                    Some(d) => d,
                    None => return Ok(()),
                },
                Err(f) => return Err(f),
            }
        }
    };
    crate::sync::approve_if_signed_in(c, &mut device, Some(user), now)?;
    Ok(())
}

fn is_unique_violation(f: &Fault) -> bool {
    matches!(f, Fault::Other(m) if m.contains("UNIQUE constraint failed"))
}

// ------------------------------------------------------------------------------------------ client OIDC ---

/// The first half of POST /api/oidc/auth (database only): None when SSO is off (the answer is given), else the
/// new row's (id, code, state, nonce, verifier) and the settings.
pub struct Started {
    pub id: i64,
    pub code: String,
    pub state: String,
    pub nonce: String,
    pub verifier: String,
    pub settings: Settings,
}

pub fn oidc_start(n: &Native, c: &Connection, input: &Input, now: i64) -> Result<Result<Started, Reply>, Fault> {
    let s = Settings::load(c, &n.crypt)?;
    if !s.is_enabled(n.signin.oidc.env_disabled) {
        return Ok(Err(error("Single sign-on is not enabled on this server.")?));
    }
    let di = device_info(input);
    // `(string) $request->input('op') ?: null`
    let op = Val::Str(input.string("op")?);
    let op = if op.to_bool() { op } else { Val::Null };
    let (code, state, nonce, verifier) = (laravel::str_random(40), laravel::str_random(40), laravel::str_random(40), laravel::str_random(96));
    let raw = |k: &str| input.get(k).cloned().unwrap_or(Val::Null);
    let id = db::insert(
        c,
        "oidc_auth_requests",
        vec![
            ("code", Val::str(&code)),
            ("state", Val::str(&state)),
            ("nonce", Val::str(&nonce)),
            ("verifier", Val::str(&verifier)),
            ("op", op),
            ("device_id", raw("id")),
            ("device_uuid", raw("uuid")),
            ("device_os", info(&di, "os")),
            ("device_name", info(&di, "name")),
            ("client_type", info(&di, "type")),
            ("expires_at", Val::str(&laravel::ts(now + OIDC_REQUEST_TTL))),
        ],
        &laravel::ts(now),
    )?;
    Ok(Ok(Started { id, code, state, nonce, verifier, settings: s }))
}

/// The answer once the authorization URL is (or is not) built.
pub fn oidc_started(c: &Connection, st: &Started, url: Result<String, OidcError>) -> Reply {
    let run = || -> Result<Reply, Fault> {
        match url {
            Ok(u) => json(vec![("code", Val::str(&st.code)), ("url", Val::str(&u))]),
            Err(OidcError::Msg(m)) => {
                db::exec(c, r#"delete from "oidc_auth_requests" where "id" = ?"#, &[P(Val::Int(st.id))])?;
                tracing::warn!(error = %m, "OIDC: client sign-in could not start");
                error(&m)
            }
            Err(OidcError::Fault(f)) => Err(f),
        }
    };
    run().unwrap_or_else(|f| fail("oidc/auth", &f))
}

fn pending_answer(m: &str) -> Result<Reply, Fault> {
    error(m)
}

/// `$pending->isExpired()`: an expiry in the past.
fn expired_row(r: &Row, now: i64) -> Result<bool, Fault> {
    Ok(match r.val("expires_at") {
        Val::Null => false,
        v => laravel::parse_ts(&v).ok_or_else(|| Fault::Other("unparsable oidc_auth_requests.expires_at".into()))? < now,
    })
}

/// `belongsToDevice($request->query('id'), $request->query('uuid'))` (typed ?string: an array is a TypeError).
fn belongs_to_device(r: &Row, id: Option<&Val>, uuid: Option<&Val>) -> Result<bool, Fault> {
    for (expected, given) in [(r.val("device_id"), id), (r.val("device_uuid"), uuid)] {
        if let Some(Val::Arr(_)) = given {
            return Err(Fault::Other("belongsToDevice: an array where ?string is declared (TypeError)".into()));
        }
        let e = expected.to_php_string()?;
        if !matches!(expected, Val::Null) && !e.is_empty() {
            let g = given.map_or(Ok(vec![]), |v| v.to_php_string())?;
            if !php::hash_equals(&e, &g) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// GET /api/oidc/auth-query
pub fn auth_query(c: &Connection, input: &Input, now: i64) -> Reply {
    auth_query_inner(c, input, now).unwrap_or_else(|f| fail("oidc/auth-query", &f))
}

fn auth_query_inner(c: &Connection, input: &Input, now: i64) -> Result<Reply, Fault> {
    let code = input.query_string("code")?;
    let row = db::first(c, r#"select * from "oidc_auth_requests" where "code" = ? limit 1"#, &[P(Val::Str(code.clone()))])?;
    let Some(row) = row else { return pending_answer(PENDING) };
    if expired_row(&row, now)? || !php::hash_equals(&row.val("code").to_php_string()?, &code) {
        return pending_answer(PENDING);
    }
    if !belongs_to_device(&row, input.query("id"), input.query("uuid"))? {
        return pending_answer(PENDING);
    }
    let delete = |c: &Connection| db::exec(c, r#"delete from "oidc_auth_requests" where "id" = ?"#, &[P(row.val("id"))]);
    if row.val("failure").to_bool() {
        delete(c)?;
        return error(&String::from_utf8_lossy(&row.val("failure").to_php_string()?));
    }
    if row.is_null("authorized_at") || row.is_null("access_token") {
        return pending_answer(PENDING);
    }
    let Some(user) = (if row.is_null("user_id") { None } else { find_user(c, &row.val("user_id"))? }) else {
        delete(c)?;
        return error("That account is no longer available.");
    };
    let token = String::from_utf8_lossy(&row.val("access_token").to_php_string()?).into_owned();
    delete(c)?;
    auth_body(&token, &user)
}

// ------------------------------------------------------------------------------------- browser callback ---

/// A rendered `auth.oidc-client-result` page (or Laravel's error page).
#[derive(Debug, Clone, PartialEq)]
pub struct Page {
    pub status: u16,
    pub ok: bool,
    pub message: String,
}

/// The first half of the callback (database only): the pending row, or the page to show at once.
pub enum CallbackStart {
    Page(Page),
    Exchange { row: Row, code: String, settings: Settings },
}

const EXPIRED_PAGE: &str = "This sign-in request has expired. Start again from HTE Remote.";

pub fn callback_start(n: &Native, c: &Connection, input: &Input, now: i64) -> Result<CallbackStart, Fault> {
    let state = input.query_string("state")?;
    let row = db::first(c, r#"select * from "oidc_auth_requests" where "state" = ? limit 1"#, &[P(Val::Str(state.clone()))])?;
    let expired = CallbackStart::Page(Page { status: 400, ok: false, message: EXPIRED_PAGE.into() });
    let Some(row) = row else { return Ok(expired) };
    if expired_row(&row, now)? || !php::hash_equals(&row.val("state").to_php_string()?, &state) {
        return Ok(expired);
    }
    // Hardened: a state completes once. The previous console would exchange again and overwrite the result (a reload after success
    // turned it into a failure; a second code could replace the token the client is about to collect).
    if !row.is_null("authorized_at") || row.val("failure").to_bool() {
        return Ok(expired);
    }
    if input.query("error").map_or(false, Val::to_bool) {
        return Ok(CallbackStart::Page(callback_fail(c, &row, "The identity provider rejected the sign-in.", now)?));
    }
    let code = String::from_utf8_lossy(&input.query_string("code")?).into_owned();
    Ok(CallbackStart::Exchange { row, code, settings: Settings::load(c, &n.crypt)? })
}

/// `fail($pending, $message)`: recorded for the poller, shown with 403.
fn callback_fail(c: &Connection, row: &Row, m: &str, now: i64) -> Result<Page, Fault> {
    let mut row = row.clone();
    let ts = laravel::ts(now);
    db::update_dirty(c, "oidc_auth_requests", &mut row, vec![("failure", Val::str(m), Cast::Plain)], &ts)?;
    Ok(Page { status: 403, ok: false, message: m.into() })
}

fn oidc_log(c: &Connection, row: &Row, username: Option<&Val>, user_id: Val, ok: bool, ip: &str, now: i64) -> Result<(), Fault> {
    let username = match username {
        Some(u) if u.to_bool() => u.clone(),
        _ => Val::str("sso"),
    };
    let client = if row.val("client_type").to_bool() { row.val("client_type") } else { Val::str("client") };
    db::insert(
        c,
        "login_logs",
        vec![
            ("user_id", if ok { user_id } else { Val::Null }),
            ("username", username),
            ("client", client),
            ("device_id", row.val("device_id")),
            ("device_os", row.val("device_os")),
            ("ip", Val::str(ip)),
            ("successful", Val::Bool(ok)),
        ],
        &laravel::ts(now),
    )?;
    Ok(())
}

/// The second half of the callback, after the token exchange: resolve the person, issue the token, approve the
/// device, record the result for the client's poll.
pub fn callback_finish(c: &Connection, row: &Row, claims: Result<Val, OidcError>, ip: &str, now: i64) -> Result<Page, Fault> {
    let claims = match claims {
        Ok(cl) => cl,
        Err(OidcError::Msg(m)) => {
            tracing::warn!(error = %m, "OIDC: client callback failed");
            return callback_fail(c, row, &m, now);
        }
        Err(OidcError::Fault(f)) => return Err(f),
    };
    let outcome = crate::resolver::resolve(c, &claims, now)?;
    let user = match outcome {
        crate::resolver::Outcome::Ok(u) => u,
        crate::resolver::Outcome::Refused(m) => {
            oidc_log(c, row, None, Val::Null, false, ip, now)?;
            tracing::info!("OIDC: client sign-in refused by the account rules");
            return callback_fail(c, row, &m, now);
        }
    };
    let token = issue_token(c, &user, row.val("device_id"), row.val("device_uuid"), row.val("device_os"), row.val("device_name"), row.val("client_type"), now)?;
    signed_in(c, &user, &row.val("device_id"), &row.val("device_uuid"), &row.val("device_os"), None, now)?;
    let mut row = row.clone();
    let ts = laravel::ts(now);
    db::update_dirty(
        c,
        "oidc_auth_requests",
        &mut row,
        vec![("user_id", user.val("id"), Cast::Plain), ("access_token", Val::str(&token), Cast::Plain), ("authorized_at", Val::str(&ts), Cast::Date)],
        &ts,
    )?;
    oidc_log(c, &row, Some(&user.val("username")), row.val("user_id"), true, ip, now)?;
    tracing::info!("OIDC: client signed in, token held for the poll");
    let display = if user.val("name").to_bool() { user.val("name") } else { user.val("username") };
    let display = String::from_utf8_lossy(&display.to_php_string()?).into_owned();
    Ok(Page { status: 200, ok: true, message: format!("You are signed in as {display}. You can close this tab and return to HTE Remote.") })
}

/// the previous console's view `resources/views/auth/oidc-client-result` in HTE Remote's guest layout. `root` is the console's origin.
pub fn render_page(p: &Page, root: &str, app_name: &str, version: &str) -> String {
    let e = laravel::e;
    let asset = |path: &str| e(&format!("{root}/{path}?v={version}"));
    let title = if p.ok { "Signed In" } else { "Sign-In Failed" };
    let foot = if p.ok {
        String::new()
    } else {
        "\n                <p class=\"rd-auth-foot-note mt-3\">\n                    Return to HTE Remote and try again, or contact your administrator.\n                </p>\n".to_string()
    };
    let css = ["assets/vendor/bootstrap/bootstrap.min.css", "assets/vendor/remixicon/remixicon.css", "assets/fonts/figtree/figtree.css", "assets/css/spacing.css", "assets/css/shell.css", "assets/css/hte-remote.css", "assets/css/hte-brand.css", "assets/css/hte-auth.css"]
        .iter()
        .map(|c| format!("    <link href=\"{}\" rel=\"stylesheet\" type=\"text/css\"/>\n", asset(c)))
        .collect::<String>();
    format!(
        r#"
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="utf-8"/>
    <title>{title} | {app}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="{csrf}">
    <link rel="icon" type="image/png" href="{icon}">

    <script src="{theme}"></script>
{css}</head>

<body class="hte-auth position-relative">

    <div class="hte-auth-page">
            <div class="card">

        <div class="card-header rd-auth-head py-3 text-center d-flex align-items-center justify-content-center">
            <a href="{home}" class="rd-auth-brand mb-0">
                <img src="{logo}" alt="HTE Remote" width="60" height="60" class="rd-auth-brand-logo">
                <span class="rd-auth-brand-wordmark">HTE <span>Remote</span></span>
            </a>
        </div>

        <div class="card-body p-4 text-center">
            <span class="rd-auth-icon {tone}">
                <i class="{icon_class}"></i>
            </span>

            <h4 class="rd-auth-title">
                {heading}
            </h4>

            <p class="rd-auth-sub mb-0">{message}</p>
{foot}        </div>
    </div>
        <p class="hte-auth-note">HTE Remote &mdash; self-hosted remote support</p>
    </div>

    <script src="{bundle}"></script>
    <script src="{shell}"></script>
</body>
</html>
"#,
        app = e(app_name),
        csrf = laravel::str_random(40),
        icon = asset("assets/images/hte-remote.png"),
        theme = asset("assets/js/theme-init.js"),
        home = e(root),
        logo = e(&format!("{root}/assets/images/hte-remote.png")),
        tone = if p.ok { "rd-tone-green" } else { "rd-tone-red" },
        icon_class = if p.ok { "ri-checkbox-circle-line" } else { "ri-error-warning-line" },
        heading = if p.ok { "Signed in to HTE Remote" } else { "Sign-in failed" },
        message = e(&p.message),
        bundle = asset("assets/vendor/bootstrap/bootstrap.bundle.min.js"),
        shell = asset("assets/js/shell.js"),
    )
}

/// Laravel's own error page (no custom views in the console): `<code> | <text>`.
pub fn error_page(status: u16, text: &str) -> String {
    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n    <head>\n        <meta charset=\"utf-8\">\n        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\n        <title>{text}</title>\n    </head>\n    <body class=\"antialiased\">\n        <div class=\"relative flex items-top justify-center min-h-screen sm:items-center sm:pt-0\">\n            <div class=\"max-w-xl mx-auto sm:px-6 lg:px-8\">\n                <div class=\"flex items-center pt-8 sm:justify-start sm:pt-0\">\n                    <div class=\"px-4 text-lg text-gray-500 border-r border-gray-400 tracking-wider\">\n                        {status}                    </div>\n\n                    <div class=\"ml-4 text-lg text-gray-500 uppercase tracking-wider\">\n                        {text}                    </div>\n                </div>\n            </div>\n        </div>\n    </body>\n</html>\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_shape() {
        let u = Row(vec![
            ("username".into(), Val::str("anna")),
            ("name".into(), Val::Null),
            ("email".into(), Val::Null),
            ("note".into(), Val::str("a/b")),
            ("is_active".into(), Val::Int(1)),
            ("is_admin".into(), Val::Int(0)),
        ]);
        assert_eq!(user_payload(&u).unwrap(), r#"{"name":"anna","display_name":"anna","email":"","note":"a\/b","status":1,"is_admin":false,"info":{}}"#);
    }

    #[test]
    fn page_escapes_the_message() {
        let p = Page { status: 403, ok: false, message: "<script>x</script> & \"q\"".into() };
        let h = render_page(&p, "https://remote.example", "HTE Remote", "1.15.0-hte.1");
        assert!(h.contains("&lt;script&gt;x&lt;/script&gt; &amp; &quot;q&quot;"));
        assert!(!h.contains("<script>x"));
        assert!(h.contains("<title>Sign-In Failed | HTE Remote</title>"));
        assert!(h.contains("https://remote.example/assets/css/hte-auth.css?v=1.15.0-hte.1"));
        assert!(h.contains("Return to HTE Remote and try again"));
    }

    #[test]
    fn challenge_keys_differ_per_secret() {
        assert_ne!(challenge_key(b"a"), challenge_key(b"b"));
        assert_eq!(challenge_key(b"a"), challenge_key(b"a"));
    }
}
