//! Phase 5: the admin automation API, answered natively. A port of the previous console's (v1.15.0-hte.1) token guard,
//! middleware and controllers, statement by statement:
//!
//!   /api/v1/users, /devices, /user-groups, /device-groups, /address-books (+ peers, tags, rules), /audits/*   48 routes
//!   POST /api/devices/cli                                       `rustdesk --assign`              1 route
//!
//! Every route sits behind `auth:api-token` (a bearer from `api_tokens`, stored as its sha256), `throttle:120,1`
//! (per token owner, own prefix per route group), the route's model bindings, and `api-token-can:<resource>,<level>`,
//! in the order Laravel runs them (the router sorts SubstituteBindings after the throttle and before the ability
//! check). Nothing is reachable without a token that is active, unexpired, owned by an active user who still holds
//! "manage API tokens", and whose matrix covers the route.
//!
//! This file is the HTTP side and the guard (routing as Laravel's router does it, the middleware chain, the
//! `{code,data,message}` envelope, pagination, bindings, the console audit line). The controllers are in
//! `admin_ctl.rs` (the v1 API) and `device_cli.rs` (`--assign`).

use crate::api::{blocking, fail, header_str, json_message, respond, Native, Reply};
use crate::laravel::{self, Cast, Input};
use crate::php::{self, Arr, Fault, Val};
use crate::sqlite::{self as db, Row, P};
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, Method, Request, Response};
use axum::routing::any;
use axum::Router;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;

// ------------------------------------------------------------------------------------------------- routes ---

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    UsersIndex,
    UsersShow,
    UsersStore,
    UsersEnable,
    UsersDisable,
    UsersForceLogout,
    UsersDestroy,
    DevIndex,
    DevShow,
    DevEnable,
    DevDisable,
    DevAssign,
    DevDestroy,
    UgIndex,
    UgShow,
    UgStore,
    UgUpdate,
    UgDestroy,
    UgAddMember,
    UgRemoveMember,
    DgIndex,
    DgShow,
    DgStore,
    DgUpdate,
    DgDestroy,
    DgAddMember,
    DgRemoveMember,
    AbIndex,
    AbShow,
    AbStore,
    AbUpdate,
    AbDestroy,
    AbPeers,
    AbPeerStore,
    AbPeerUpdate,
    AbPeerDestroy,
    AbTags,
    AbTagStore,
    AbTagUpdate,
    AbTagDestroy,
    AbRules,
    AbRuleStore,
    AbRuleUpdate,
    AbRuleDestroy,
    AuConn,
    AuFile,
    AuAlarm,
    AuConsole,
    Assign,
}

/// What a `{param}` is bound to (implicit route model binding, by primary key).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bind {
    User,
    Device,
    /// `->withTrashed()`
    DeviceTrashed,
    UserGroup,
    DeviceGroup,
    AddressBook,
    Peer,
    Tag,
    Rule,
}

impl Bind {
    fn model(self) -> &'static str {
        match self {
            Bind::User => "User",
            Bind::Device | Bind::DeviceTrashed => "Device",
            Bind::UserGroup => "UserGroup",
            Bind::DeviceGroup => "DeviceGroup",
            Bind::AddressBook => "AddressBook",
            Bind::Peer => "AddressBookEntry",
            Bind::Tag => "Tag",
            Bind::Rule => "AddressBookRule",
        }
    }
    fn table(self) -> &'static str {
        match self {
            Bind::User => "users",
            Bind::Device | Bind::DeviceTrashed => "devices",
            Bind::UserGroup => "user_groups",
            Bind::DeviceGroup => "device_groups",
            Bind::AddressBook => "address_books",
            Bind::Peer => "address_book_entries",
            Bind::Tag => "tags",
            Bind::Rule => "address_book_rules",
        }
    }
}

#[derive(Debug)]
pub struct Route {
    pub method: &'static str,
    /// `{}` is a `{param}` segment
    pub pattern: &'static str,
    pub op: Op,
    /// `api-token-can:<resource>,<level>`
    pub resource: &'static str,
    pub level: &'static str,
    pub binds: &'static [Bind],
}

const fn r(method: &'static str, pattern: &'static str, op: Op, resource: &'static str, level: &'static str, binds: &'static [Bind]) -> Route {
    Route { method, pattern, op, resource, level, binds }
}

use Bind::*;
use Op::*;

/// routes/api (the `v1` group) and routes/client-cli, in file order.
pub const ROUTES: &[Route] = &[
    r("GET", "/api/v1/users", UsersIndex, "user", "r", &[]),
    r("GET", "/api/v1/users/{}", UsersShow, "user", "r", &[User]),
    r("POST", "/api/v1/users", UsersStore, "user", "rw", &[]),
    r("POST", "/api/v1/users/{}/enable", UsersEnable, "user", "rw", &[User]),
    r("POST", "/api/v1/users/{}/disable", UsersDisable, "user", "rw", &[User]),
    r("POST", "/api/v1/users/{}/force-logout", UsersForceLogout, "user", "rw", &[User]),
    r("DELETE", "/api/v1/users/{}", UsersDestroy, "user", "rw", &[User]),
    r("GET", "/api/v1/devices", DevIndex, "device", "r", &[]),
    r("GET", "/api/v1/devices/{}", DevShow, "device", "r", &[Device]),
    r("POST", "/api/v1/devices/{}/enable", DevEnable, "device", "rw", &[DeviceTrashed]),
    r("POST", "/api/v1/devices/{}/disable", DevDisable, "device", "rw", &[Device]),
    r("POST", "/api/v1/devices/{}/assign", DevAssign, "device", "rw", &[Device]),
    r("DELETE", "/api/v1/devices/{}", DevDestroy, "device", "rw", &[DeviceTrashed]),
    r("GET", "/api/v1/user-groups", UgIndex, "group", "r", &[]),
    r("GET", "/api/v1/user-groups/{}", UgShow, "group", "r", &[UserGroup]),
    r("POST", "/api/v1/user-groups", UgStore, "group", "rw", &[]),
    r("PUT", "/api/v1/user-groups/{}", UgUpdate, "group", "rw", &[UserGroup]),
    r("DELETE", "/api/v1/user-groups/{}", UgDestroy, "group", "rw", &[UserGroup]),
    r("POST", "/api/v1/user-groups/{}/members", UgAddMember, "group", "rw", &[UserGroup]),
    r("DELETE", "/api/v1/user-groups/{}/members", UgRemoveMember, "group", "rw", &[UserGroup]),
    r("GET", "/api/v1/device-groups", DgIndex, "group", "r", &[]),
    r("GET", "/api/v1/device-groups/{}", DgShow, "group", "r", &[DeviceGroup]),
    r("POST", "/api/v1/device-groups", DgStore, "group", "rw", &[]),
    r("PUT", "/api/v1/device-groups/{}", DgUpdate, "group", "rw", &[DeviceGroup]),
    r("DELETE", "/api/v1/device-groups/{}", DgDestroy, "group", "rw", &[DeviceGroup]),
    r("POST", "/api/v1/device-groups/{}/members", DgAddMember, "group", "rw", &[DeviceGroup]),
    r("DELETE", "/api/v1/device-groups/{}/members", DgRemoveMember, "group", "rw", &[DeviceGroup]),
    r("GET", "/api/v1/address-books", AbIndex, "address_book", "r", &[]),
    r("GET", "/api/v1/address-books/{}", AbShow, "address_book", "r", &[AddressBook]),
    r("POST", "/api/v1/address-books", AbStore, "address_book", "rw", &[]),
    r("PUT", "/api/v1/address-books/{}", AbUpdate, "address_book", "rw", &[AddressBook]),
    r("DELETE", "/api/v1/address-books/{}", AbDestroy, "address_book", "rw", &[AddressBook]),
    r("GET", "/api/v1/address-books/{}/peers", AbPeers, "address_book", "r", &[AddressBook]),
    r("POST", "/api/v1/address-books/{}/peers", AbPeerStore, "address_book", "rw", &[AddressBook]),
    r("PUT", "/api/v1/address-books/{}/peers/{}", AbPeerUpdate, "address_book", "rw", &[AddressBook, Peer]),
    r("DELETE", "/api/v1/address-books/{}/peers/{}", AbPeerDestroy, "address_book", "rw", &[AddressBook, Peer]),
    r("GET", "/api/v1/address-books/{}/tags", AbTags, "address_book", "r", &[AddressBook]),
    r("POST", "/api/v1/address-books/{}/tags", AbTagStore, "address_book", "rw", &[AddressBook]),
    r("PUT", "/api/v1/address-books/{}/tags/{}", AbTagUpdate, "address_book", "rw", &[AddressBook, Tag]),
    r("DELETE", "/api/v1/address-books/{}/tags/{}", AbTagDestroy, "address_book", "rw", &[AddressBook, Tag]),
    r("GET", "/api/v1/address-books/{}/rules", AbRules, "address_book", "r", &[AddressBook]),
    r("POST", "/api/v1/address-books/{}/rules", AbRuleStore, "address_book", "rw", &[AddressBook]),
    r("PUT", "/api/v1/address-books/{}/rules/{}", AbRuleUpdate, "address_book", "rw", &[AddressBook, Rule]),
    r("DELETE", "/api/v1/address-books/{}/rules/{}", AbRuleDestroy, "address_book", "rw", &[AddressBook, Rule]),
    r("GET", "/api/v1/audits/conn", AuConn, "audit", "r", &[]),
    r("GET", "/api/v1/audits/file", AuFile, "audit", "r", &[]),
    r("GET", "/api/v1/audits/alarm", AuAlarm, "audit", "r", &[]),
    r("GET", "/api/v1/audits/console", AuConsole, "audit", "r", &[]),
    r("POST", "/api/devices/cli", Assign, "device", "rw", &[]),
];

/// The paths Caddy sends here (and the shadow must never record).
pub fn is_admin_path(path: &str) -> bool {
    path.starts_with("/api/v1/") || path == "/api/devices/cli"
}

/// Laravel's `Router::$verbs` order, which the 405 message lists in.
const VERBS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];

#[derive(Debug)]
enum Lookup {
    Found(&'static Route, Vec<Vec<u8>>),
    /// the URI exists, the method does not: the methods that do
    NotAllowed(Vec<&'static str>),
    NoRoute,
}

/// `rawurldecode`: `%XX` only (a `+` stays a plus).
fn rawurldecode(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' && i + 2 < s.len() {
            let hex = |c: u8| (c as char).to_digit(16);
            if let (Some(h), Some(l)) = (hex(s[i + 1]), hex(s[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(s[i]);
        i += 1;
    }
    out
}

/// Laravel's `UriValidator`: `rtrim($path, '/') ?: '/'`, decoded, against each route's pattern; the first route that
/// matches the URI and the method wins; with none for the method, the methods of the routes that match the URI.
fn lookup(method: &str, raw_path: &[u8]) -> Lookup {
    let end = raw_path.iter().rposition(|&c| c != b'/').map_or(0, |i| i + 1);
    let decoded = rawurldecode(if end == 0 { b"/" } else { &raw_path[..end] });
    let segs: Vec<&[u8]> = decoded.split(|&c| c == b'/').collect();
    let mut allowed: Vec<&'static str> = vec![];
    for route in ROUTES {
        let pat: Vec<&str> = route.pattern.split('/').collect();
        if pat.len() != segs.len() {
            continue;
        }
        let mut params = vec![];
        let ok = pat.iter().zip(&segs).all(|(p, s)| {
            if *p == "{}" {
                params.push(s.to_vec());
                !s.is_empty()
            } else {
                p.as_bytes() == *s
            }
        });
        if !ok {
            continue;
        }
        if route.method == method || (method == "HEAD" && route.method == "GET") {
            return Lookup::Found(route, params);
        }
        for v in VERBS {
            if (*v == route.method || (*v == "HEAD" && route.method == "GET")) && !allowed.contains(v) {
                allowed.push(*v);
            }
        }
    }
    if allowed.is_empty() {
        return Lookup::NoRoute;
    }
    allowed.sort_by_key(|v| VERBS.iter().position(|x| x == v));
    Lookup::NotAllowed(allowed)
}

/// Registers the paths; `lookup` decides the rest. `/api/v1/*` takes every shape under it, so an unknown one gets
/// Laravel's own 404 JSON instead of reaching the previous console; `/api/v1` itself and the other casings stay the previous console's.
pub fn mount(r: Router<Arc<Native>>) -> Router<Arc<Native>> {
    r.route("/api/v1/*rest", any(handle)).route("/api/devices/cli", any(handle))
}

/// The largest body an admin route reads (`HTE_CONSOLE_ADMIN_MAX_BODY_BYTES`, default 1 MiB).
fn max_body() -> usize {
    crate::envvar::var("HTE_CONSOLE_ADMIN_MAX_BODY_BYTES").ok().and_then(|v| v.trim().parse().ok()).unwrap_or(1024 * 1024)
}

/// An answer: Laravel's JSON, or `--assign`'s plain text (an empty 200 is success).
pub enum Out {
    R(Reply),
    /// `response($text, $status)->header('Content-Type', 'text/plain')`
    Plain(u16, String),
}

type Headers = Vec<(&'static str, String)>;

fn build(out: Out, headers: Headers, head: bool) -> Response<Body> {
    match out {
        Out::R(r) => respond(r, headers, head),
        Out::Plain(status, text) => {
            let mut resp = respond(Reply::Text(status, text.into_bytes()), headers, head);
            resp.headers_mut().insert(header::CONTENT_TYPE, header::HeaderValue::from_static("text/plain; charset=UTF-8"));
            resp
        }
    }
}

async fn handle(State(n): State<Arc<Native>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, req: Request<Body>) -> Response<Body> {
    let (parts, body) = req.into_parts();
    let method = parts.method.as_str().to_string();
    let head = parts.method == Method::HEAD;
    let raw_path = parts.uri.path().to_string();

    // HandleCors (api/* only): a preflight never reaches the route.
    if parts.method == Method::OPTIONS && parts.headers.contains_key("access-control-request-method") {
        let mut extra = vec![
            ("access-control-allow-methods", header_str(&parts.headers, "access-control-request-method").unwrap_or("").to_ascii_uppercase()),
            ("access-control-max-age", "0".to_string()),
            ("vary", "Access-Control-Request-Method, Access-Control-Request-Headers".to_string()),
        ];
        if let Some(h) = header_str(&parts.headers, "access-control-request-headers") {
            extra.push(("access-control-allow-headers", h.to_string()));
        }
        return respond(Reply::Text(204, vec![]), extra, false);
    }

    // `$request->path()`: the raw path without surrounding slashes
    let shown = {
        let t = raw_path.trim_matches('/');
        if t.is_empty() { "/" } else { t }.to_string()
    };
    let lookup_method = if parts.method == Method::OPTIONS { "OPTIONS" } else { method.as_str() };
    let (route, params) = match lookup(lookup_method, raw_path.as_bytes()) {
        Lookup::Found(r, p) => (r, p),
        Lookup::NoRoute => return respond(json_message(404, &format!("The route {shown} could not be found.")), vec![], head),
        Lookup::NotAllowed(allowed) => {
            if parts.method == Method::OPTIONS {
                // the router answers OPTIONS for a known path itself
                return respond(Reply::Text(200, vec![]), vec![("allow", allowed.join(",")), ("vary", "Access-Control-Request-Method".into())], false);
            }
            let msg = format!("The {method} method is not supported for route {shown}. Supported methods: {}.", allowed.join(", "));
            return respond(json_message(405, &msg), vec![("allow", allowed.join(", "))], head);
        }
    };

    // ValidatePostSize, bounded here far below the previous console's limit
    let max = max_body();
    let declared = header_str(&parts.headers, "content-length").and_then(|v| v.trim().parse::<u64>().ok());
    if declared.map_or(false, |l| l > max as u64) {
        return respond(json_message(413, "The POST data is too large."), vec![], false);
    }
    let body = match axum::body::to_bytes(body, max).await {
        Ok(b) => b,
        Err(_) => return respond(json_message(413, "The POST data is too large."), vec![], false),
    };
    let xff: Vec<&str> = parts.headers.get_all("x-forwarded-for").iter().filter_map(|v| v.to_str().ok()).collect();
    let ip = laravel::client_ip(peer.ip(), &xff, &n.trusted);
    let input = Input::new(&method, header_str(&parts.headers, header::CONTENT_TYPE.as_str()), parts.uri.query(), &body);
    let bearer = laravel::bearer_token(parts.headers.get(header::AUTHORIZATION).map(|v| v.as_bytes()));
    let now = n.now();
    let out = blocking(&n, move |n, c| run(n, c, route, params, bearer, &input, &ip, now)).await;
    match out {
        Some((out, headers)) => build(out, headers, head),
        None => respond(Reply::server_error(), vec![], head),
    }
}

// ------------------------------------------------------------------------------------------ rate limiting ---

/// Laravel's `throttle:120,1,<prefix>` key for an authenticated user: the prefix and sha1 of the user id.
fn throttle_key(prefix: &str, user_id: i64) -> Vec<u8> {
    use sha1::Digest as _;
    format!("{prefix}{}", hex::encode(sha1::Sha1::digest(user_id.to_string().as_bytes()))).into_bytes()
}

const MAX_ATTEMPTS: u64 = 120;

fn too_many(max: u64, retry: i64, now: i64) -> (Out, Headers) {
    (
        Out::R(json_message(429, "Too Many Attempts.")),
        vec![
            ("x-ratelimit-limit", max.to_string()),
            ("x-ratelimit-remaining", "0".to_string()),
            ("retry-after", retry.to_string()),
            ("x-ratelimit-reset", (now + retry).to_string()),
        ],
    )
}

/// Hardening the previous console does not have: a client address that keeps presenting tokens nobody issued is slowed down
/// (300 refused sign-ins a minute per address, then 429). A valid client never meets it.
const AUTH_FAILURES_PER_MINUTE: u64 = 300;

fn failure_key(ip: &str) -> Vec<u8> {
    format!("admin-api-auth-failures|{ip}").into_bytes()
}

// ----------------------------------------------------------------------------------------------- the guard ---

pub struct Auth {
    pub token: Row,
    pub user: Row,
}

/// `Permissions::rank()` of whatever the matrix holds: the string form of a scalar (the previous console coerces it), a TypeError
/// for an array.
fn rank(have: &Val) -> Result<i64, Fault> {
    if matches!(have, Val::Arr(_)) {
        return Err(Fault::Other("Permissions::rank(): Argument #1 must be of type string, array given".into()));
    }
    Ok(match have.to_php_string()?.as_slice() {
        b"rw" => 2,
        b"r" => 1,
        _ => 0,
    })
}

fn level_rank(level: &str) -> i64 {
    match level {
        "rw" => 2,
        "r" => 1,
        _ => 0,
    }
}

/// `ApiToken::allows($resource, $required)`: the matrix's level for the resource (`none` when absent) covers it.
pub fn token_allows(token: &Row, resource: &str, required: &str) -> Result<bool, Fault> {
    let have = match laravel::from_json(&token.val("permissions")) {
        Val::Arr(a) => a.get_str(resource).filter(|v| !matches!(v, Val::Null)).cloned().unwrap_or_else(|| Val::str("none")),
        _ => Val::str("none"),
    };
    Ok(rank(&have)? >= level_rank(required))
}

/// `User::consoleAllows($resource, $level)` for the token owner: administrators pass; a role-holder is answered by
/// the role's matrix; a user with no role gets the legacy baseline (`token` is none there).
pub(crate) fn console_allows(c: &Connection, user: &Row, resource: &str, level: &str) -> Result<bool, Fault> {
    if user.val("is_admin").to_bool() {
        return Ok(true);
    }
    let role = match user.val("role_id") {
        Val::Null => None,
        id => db::first(c, r#"select * from "roles" where "id" = ? limit 1"#, &[P(id)])?,
    };
    match role {
        Some(role) => {
            // Role::levelFor: the stored level when it is one of none|r|rw, else none
            let level_have = match laravel::from_json(&role.val("permissions")) {
                Val::Arr(a) => a.get_str(resource).cloned().unwrap_or(Val::Null),
                _ => Val::Null,
            };
            let have = match &level_have {
                Val::Str(s) if s == b"none" || s == b"r" || s == b"rw" => s.clone(),
                _ => b"none".to_vec(),
            };
            Ok(rank(&Val::Str(have))? >= level_rank(level))
        }
        None => {
            // Permissions::LEGACY_USER
            let have = match resource {
                "device" | "address_book" => "rw",
                "audit" => "r",
                _ => "none",
            };
            Ok(level_rank(have) >= level_rank(level))
        }
    }
}

/// The `api-token` guard (AppServiceProvider::boot): the bearer's `api_tokens` row (by sha256, active and not
/// expired), its owner existing, active and still holding "manage API tokens". None is "Unauthenticated.".
pub fn authenticate(c: &Connection, bearer: Option<&[u8]>, now: i64) -> Result<Option<Auth>, Fault> {
    // `if (! $bearer)`: absent, "" and "0" are no token
    let Some(b) = bearer.filter(|b| !b.is_empty() && *b != b"0") else { return Ok(None) };
    let hash = hex::encode(Sha256::digest(b));
    let Some(token) = db::first(c, r#"select * from "api_tokens" where "token_hash" = ? limit 1"#, &[P(Val::str(&hash))])? else { return Ok(None) };
    // the lookup is by equality in SQLite; compare again in constant time before trusting it
    if !php::hash_equals(&token.val("token_hash").to_php_string()?, hash.as_bytes()) {
        return Ok(None);
    }
    // ApiToken::isValid()
    if !token.val("is_active").to_bool() {
        return Ok(None);
    }
    match token.val("expires_at") {
        Val::Null => {}
        v => {
            let exp = laravel::parse_ts(&v).ok_or_else(|| Fault::Other("unparsable api_tokens.expires_at".into()))?;
            if exp <= now {
                return Ok(None);
            }
        }
    }
    let user = match token.val("user_id") {
        Val::Null => None,
        id => db::first(c, r#"select * from "users" where "id" = ? limit 1"#, &[P(id)])?,
    };
    let Some(user) = user else { return Ok(None) };
    if !user.val("is_active").to_bool() || !console_allows(c, &user, "token", "rw")? {
        return Ok(None);
    }
    Ok(Some(Auth { token, user }))
}

// ------------------------------------------------------------------------------------------------- the run ---

fn run(n: &Native, c: &Connection, route: &'static Route, params: Vec<Vec<u8>>, bearer: Option<Vec<u8>>, input: &Input, ip: &str, now: i64) -> (Out, Headers) {
    let server_error = || (Out::R(Reply::server_error()), vec![]);

    // 0. a client address that keeps failing to authenticate
    {
        let l = n.limiter.lock().unwrap_or_else(|e| e.into_inner());
        if l.too_many(&failure_key(ip), AUTH_FAILURES_PER_MINUTE, now) {
            return too_many(AUTH_FAILURES_PER_MINUTE, l.available_in(&failure_key(ip), now), now);
        }
    }

    // 1. auth:api-token
    let auth = match authenticate(c, bearer.as_deref(), now) {
        Ok(Some(a)) => a,
        Ok(None) => {
            n.limiter.lock().unwrap_or_else(|e| e.into_inner()).hit(&failure_key(ip), 60, now);
            return (Out::R(json_message(401, "Unauthenticated.")), vec![]);
        }
        Err(f) => return (Out::R(fail("api-token guard", &f)), vec![]),
    };
    let Auth { mut token, user } = auth;

    // 2. throttle:120,1,<prefix>
    let prefix = if route.op == Op::Assign { "client-cli" } else { "admin-api" };
    let key = throttle_key(prefix, user.id());
    {
        let mut l = n.limiter.lock().unwrap_or_else(|e| e.into_inner());
        if l.too_many(&key, MAX_ATTEMPTS, now) {
            return too_many(MAX_ATTEMPTS, l.available_in(&key, now), now);
        }
        l.hit(&key, 60, now);
    }
    let with_headers = |out: Out| -> (Out, Headers) {
        let l = n.limiter.lock().unwrap_or_else(|e| e.into_inner());
        (out, vec![("x-ratelimit-limit", MAX_ATTEMPTS.to_string()), ("x-ratelimit-remaining", l.remaining(&key, MAX_ATTEMPTS, now).to_string())])
    };

    // 3. SubstituteBindings (the v1 group): each {param} is a row by id, or a 404 naming the model and the value
    let mut bound: Vec<Row> = vec![];
    for (bind, value) in route.binds.iter().zip(&params) {
        let trashed = if *bind == Bind::Device { r#" and "deleted_at" is null"# } else { "" };
        let sql = format!(r#"select * from "{}" where "id" = ?{trashed} limit 1"#, bind.table());
        match db::first(c, &sql, &[P(Val::Str(value.clone()))]) {
            Ok(Some(row)) => bound.push(row),
            Ok(None) => {
                let shown = String::from_utf8_lossy(value);
                return with_headers(Out::R(json_message(404, &format!("No query results for model [App\\Models\\{}] {shown}", bind.model()))));
            }
            Err(f) => return server_error_with(fail("route binding", &f), &with_headers),
        }
    }

    // 4. api-token-can:<resource>,<level>: the token again (its owner may have changed since the guard), then the matrix
    match authenticate(c, bearer.as_deref(), now) {
        Ok(Some(_)) => {}
        Ok(None) => return with_headers(Out::R(envelope_error(401, "Unauthenticated."))),
        Err(f) => return server_error_with(fail("api-token-can", &f), &with_headers),
    }
    match token_allows(&token, route.resource, route.level) {
        Ok(true) => {}
        Ok(false) => {
            let msg = format!("Token lacks '{}' permission on '{}'.", route.level, route.resource);
            return with_headers(Out::R(envelope_error(403, &msg)));
        }
        Err(f) => return server_error_with(fail("api-token-can", &f), &with_headers),
    }
    // ApiToken::markUsed()
    let ts = laravel::ts(now);
    if let Err(f) = db::update_dirty(c, "api_tokens", &mut token, vec![("last_used_at", Val::str(&ts), Cast::Date)], &ts) {
        return server_error_with(fail("api-token-can", &f), &with_headers);
    }

    // 5. the controller
    let cx = Cx { n, c, user, token, input, bound, now, ip: ip.to_string() };
    let out = match route.op {
        Assign => crate::device_cli::assign(&cx),
        _ => crate::admin_ctl::dispatch(&cx, route.op).map(Out::R),
    };
    match out {
        Ok(o) => with_headers(o),
        // an uncaught exception: Laravel's 500, without the limiter's headers (as the device routes)
        Err(f) => {
            let _ = fail(&format!("admin api {:?}", route.op), &f);
            server_error()
        }
    }
}

fn server_error_with(r: Reply, with_headers: &dyn Fn(Out) -> (Out, Headers)) -> (Out, Headers) {
    let _ = with_headers;
    (Out::R(r), vec![])
}

/// `{code, data: null, message}` as ApiTokenCan and the controllers' `fail()` answer.
fn envelope_error(status: u16, message: &str) -> Reply {
    Reply::Json(status, format!(r#"{{"code":{status},"data":null,"message":{}}}"#, jstr(message.as_bytes()).unwrap_or_else(|_| "\"\"".into())))
}

// ------------------------------------------------------------------------------------------------ context ---

/// Everything a controller needs: the token and its owner (`$request->user()`), the bound rows in route order.
pub struct Cx<'a> {
    pub n: &'a Native,
    pub c: &'a Connection,
    pub user: Row,
    pub token: Row,
    pub input: &'a Input,
    pub bound: Vec<Row>,
    pub now: i64,
    pub ip: String,
}

pub fn enc(v: &Val) -> Result<String, Fault> {
    php::json_encode(v).ok_or_else(|| Fault::Other("json_encode failed (invalid UTF-8)".into()))
}

pub fn jstr(b: &[u8]) -> Result<String, Fault> {
    let mut o = String::new();
    php::enc_str(b, &mut o).ok_or_else(|| Fault::Other("json_encode failed (invalid UTF-8)".into()))?;
    Ok(o)
}

pub fn list(items: Vec<Val>) -> Val {
    let mut a = Arr::new();
    for i in items {
        a.push(i);
    }
    Val::Arr(a)
}

pub fn obj(pairs: Vec<(&str, Val)>) -> Val {
    php::assoc(pairs.into_iter().map(|(k, v)| (k.to_string(), v)))
}

/// `$request->filled($key)`: present and not an empty string (arrays and booleans always count).
pub fn filled(input: &Input, key: &str) -> Result<bool, Fault> {
    Ok(match input.get(key) {
        None | Some(Val::Null) => false,
        Some(Val::Bool(_)) | Some(Val::Arr(_)) => true,
        Some(v) => !php::trim(&v.to_php_string()?).is_empty(),
    })
}

/// `head(Arr::flatten($value))`: what the query builder binds for an array value.
pub fn flat_first(v: &Val) -> Val {
    fn first(v: &Val) -> Option<Val> {
        match v {
            Val::Arr(a) => a.iter().find_map(|(_, x)| first(x)),
            other => Some(other.clone()),
        }
    }
    match v {
        Val::Arr(_) => first(v).unwrap_or(Val::Bool(false)),
        other => other.clone(),
    }
}

/// `$value` formatted as Carbon's `toIso8601String()` (UTC), null stays null.
pub fn iso(v: &Val) -> Result<Val, Fault> {
    if matches!(v, Val::Null) {
        return Ok(Val::Null);
    }
    let t = laravel::parse_ts(v).ok_or_else(|| Fault::Other("unparsable timestamp".into()))?;
    let d = chrono::DateTime::from_timestamp(t, 0).ok_or_else(|| Fault::Other("timestamp out of range".into()))?;
    Ok(Val::str(&d.format("%Y-%m-%dT%H:%M:%S+00:00").to_string()))
}

/// `$request->boolean($key)`: `filter_var($value, FILTER_VALIDATE_BOOLEAN)`.
pub fn request_boolean(input: &Input, key: &str) -> bool {
    match input.get(key) {
        Some(Val::Bool(b)) => *b,
        Some(Val::Int(i)) => *i == 1,
        Some(Val::Float(f)) => *f == 1.0,
        Some(Val::Str(s)) => matches!(php::trim(s).to_ascii_lowercase().as_slice(), b"1" | b"true" | b"on" | b"yes"),
        _ => false,
    }
}

impl Cx<'_> {
    pub fn ts(&self) -> String {
        laravel::ts(self.now)
    }
    pub fn uid(&self) -> i64 {
        self.user.id()
    }

    // ------------------------------------------------------------------------------------------ envelope ---

    pub fn ok(&self, data: Val, message: &str) -> Result<Reply, Fault> {
        self.envelope(200, data, message)
    }

    pub fn created(&self, data: Val, message: &str) -> Result<Reply, Fault> {
        self.envelope(201, data, message)
    }

    fn envelope(&self, status: u16, data: Val, message: &str) -> Result<Reply, Fault> {
        let body = obj(vec![("code", Val::Int(0)), ("data", data), ("message", Val::str(message))]);
        Ok(Reply::Json(status, enc(&body)?))
    }

    /// `fail($message, $status, $code)`
    pub fn fail(&self, message: &str, status: u16, code: i64) -> Result<Reply, Fault> {
        let body = obj(vec![("code", Val::Int(code)), ("data", Val::Null), ("message", Val::str(message))]);
        Ok(Reply::Json(status, enc(&body)?))
    }

    /// `abort_unless(false, 404)`: Laravel's JSON for an HttpException with no message.
    pub fn abort_404(&self) -> Result<Reply, Fault> {
        Ok(json_message(404, ""))
    }

    /// A 422 from `$request->validate()`.
    pub fn invalid(&self, body: String) -> Result<Reply, Fault> {
        Ok(Reply::Json(422, body))
    }

    // ------------------------------------------------------------------------------------------- queries ---

    /// `(int) $request->query('page_size', $request->query('per_page', 50))`, clamped to 1..200.
    pub fn per_page(&self) -> i64 {
        let q = |k: &str| self.input.query(k).filter(|v| !matches!(v, Val::Null));
        let n = q("page_size").or_else(|| q("per_page")).map_or(50, |v| v.to_int());
        n.min(200).max(1)
    }

    /// `Paginator::resolveCurrentPage()`: `input('page')` when it is an integer of at least 1, else 1.
    pub fn current_page(&self) -> i64 {
        match self.input.get("page") {
            Some(v) if crate::validate::filter_int(v) && v.to_int() >= 1 => v.to_int(),
            _ => 1,
        }
    }

    /// `->paginate($this->perPage($request))` and the envelope: `from`/`where_sql` are this crate's constants, the
    /// parameters bound. `transform` makes each item of the page.
    pub fn paginated(
        &self,
        select: &str,
        from: &str,
        where_sql: &str,
        params: Vec<P>,
        order: &str,
        transform: impl FnOnce(Vec<Row>) -> Result<Vec<Val>, Fault>,
    ) -> Result<Reply, Fault> {
        let per = self.per_page();
        let page = self.current_page();
        let total = db::first(self.c, &format!(r#"select count(*) as aggregate from {from}{where_sql}"#), &params)?.map_or(0, |r| r.val("aggregate").to_int());
        let rows = if total > 0 {
            let offset = (page - 1).saturating_mul(per);
            db::rows(self.c, &format!(r#"select {select} from {from}{where_sql} order by {order} limit {per} offset {offset}"#), &params)?
        } else {
            vec![]
        };
        let items = transform(rows)?;
        let last = ((total + per - 1) / per).max(1);
        let body = obj(vec![
            ("code", Val::Int(0)),
            ("data", list(items)),
            ("total", Val::Int(total)),
            ("current", Val::Int(page)),
            ("total_pages", Val::Int(last)),
            ("message", Val::str("")),
        ]);
        Ok(Reply::Json(200, enc(&body)?))
    }

    /// `'%'.$request->query($key).'%'` (a missing or null value is empty; an array is the previous console's warning, a 500)
    pub fn like(&self, key: &str) -> Result<Val, Fault> {
        let v = self.input.query(key).cloned().unwrap_or(Val::Null);
        let mut s = b"%".to_vec();
        s.extend(v.to_php_string()?);
        s.push(b'%');
        Ok(Val::Str(s))
    }

    /// `Model::find($input)` for a request value: an array is `findMany` (a collection, which the callers then use
    /// as a model: the previous console throws), a scalar the primary key.
    pub fn find_by_input(&self, table: &str, soft_deletes: bool, v: &Val) -> Result<Option<Row>, Fault> {
        if matches!(v, Val::Arr(_)) {
            return Err(Fault::Other("a collection used as a model (find() with an array)".into()));
        }
        let soft = if soft_deletes { r#" and "deleted_at" is null"# } else { "" };
        db::first(self.c, &format!(r#"select * from "{table}" where "id" = ?{soft} limit 1"#), &[P(v.clone())])
    }

    /// `Model::where($column, $value)->first()` (soft-deleted rows excluded when the model has the scope)
    pub fn find_by(&self, table: &str, soft_deletes: bool, column: &str, v: &Val) -> Result<Option<Row>, Fault> {
        let soft = if soft_deletes { r#" and "deleted_at" is null"# } else { "" };
        db::first(self.c, &format!(r#"select * from "{table}" where "{column}" = ?{soft} limit 1"#), &[P(flat_first(v))])
    }

    // ------------------------------------------------------------------------------------------- writes ---

    /// `ConsoleAudit::record(...)`: attributed to the token's owner, from the request's client address.
    pub fn audit(&self, action: &str, summary: &str, target_type: Option<&str>, target_id: Option<&str>) -> Result<(), Fault> {
        let text = |t: Option<&str>| t.map_or(Val::Null, Val::str);
        db::exec(
            self.c,
            r#"insert into "console_audits" ("user_id", "username", "action", "target_type", "target_id", "summary", "ip", "created_at") values (?, ?, ?, ?, ?, ?, ?, ?)"#,
            &[
                P(self.user.val("id")),
                P(self.user.val("username")),
                P(Val::str(action)),
                P(text(target_type)),
                P(text(target_id)),
                P(Val::str(&crate::validate::str_limit(summary, 250, "..."))),
                P(Val::str(&self.ip)),
                P(Val::str(&self.ts())),
            ],
        )?;
        Ok(())
    }

    /// `Model::create($attributes)`: insert, then the row as the model holds it (the attributes given, the new id,
    /// both timestamps).
    pub fn create(&self, table: &str, cols: Vec<(&str, Val)>) -> Result<Row, Fault> {
        let ts = self.ts();
        let id = db::insert(self.c, table, cols.iter().map(|(k, v)| (*k, v.clone())).collect(), &ts)?;
        let mut row = Row::default();
        for (k, v) in cols {
            row.set(k, v);
        }
        row.set("id", Val::Int(id));
        row.set("updated_at", Val::str(&ts));
        row.set("created_at", Val::str(&ts));
        Ok(row)
    }

    /// `$model->update($changes)`: only what Eloquent sees as changed is written. Returns the columns that changed.
    pub fn update(&self, table: &str, row: &mut Row, changes: Vec<(&str, Val, Cast)>) -> Result<Vec<String>, Fault> {
        let mut changed = vec![];
        for (col, v, cast) in &changes {
            if !laravel::equivalent(*cast, v, row.get(col))? {
                changed.push(col.to_string());
            }
        }
        db::update_dirty(self.c, table, row, changes, &self.ts())?;
        Ok(changed)
    }

    /// `Strategy::recomputeAll()`: every device, trashed or not, re-resolved (chunks of 500 by id).
    pub fn recompute_all(&self) -> Result<(), Fault> {
        let ts = self.ts();
        let mut last = 0i64;
        loop {
            let rows = db::rows(self.c, r#"select * from "devices" where "id" > ? order by "id" asc limit 500"#, &[P(Val::Int(last))])?;
            if rows.is_empty() {
                return Ok(());
            }
            for mut d in rows {
                last = d.id();
                crate::strategy::sync_resolved_for(self.c, &mut d, &ts)?;
            }
        }
    }

    /// `Device::onlineWindow()`: the `online_window` setting, else `HTE_REMOTE_ONLINE_WINDOW`, else 60; 0 means 60.
    pub fn online_window(&self) -> Result<i64, Fault> {
        let default = crate::envvar::var("HTE_REMOTE_ONLINE_WINDOW").ok().filter(|v| !v.is_empty()).unwrap_or_else(|| "60".into());
        let v = db::setting(self.c, "online_window", &default)?;
        Ok(if v.is_empty() || v == b"0" { 60 } else { php::str_to_int(&v) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn there_are_49_routes_and_lookup_follows_laravel() {
        assert_eq!(ROUTES.len(), 49);
        match lookup("GET", b"/api/v1/users/5/") {
            Lookup::Found(r, p) => assert_eq!((r.op, p), (UsersShow, vec![b"5".to_vec()])),
            other => panic!("{other:?}"),
        }
        match lookup("DELETE", b"/api/v1/address-books/a/peers/7") {
            Lookup::Found(r, p) => assert_eq!((r.op, p.len()), (AbPeerDestroy, 2)),
            other => panic!("{other:?}"),
        }
        // HEAD finds the GET route; a method with no route lists the ones that exist
        assert!(matches!(lookup("HEAD", b"/api/v1/users"), Lookup::Found(r, _) if r.op == UsersIndex));
        match lookup("PUT", b"/api/v1/users") {
            Lookup::NotAllowed(m) => assert_eq!(m, vec!["GET", "HEAD", "POST"]),
            other => panic!("{other:?}"),
        }
        assert!(matches!(lookup("GET", b"/api/v1/nope"), Lookup::NoRoute));
        assert!(matches!(lookup("GET", b"/api/v1/users//5"), Lookup::NoRoute));
        // an encoded slash decodes before matching: three segments, no route
        assert!(matches!(lookup("GET", b"/api/v1/users/5%2F6"), Lookup::NoRoute));
        assert!(matches!(lookup("POST", b"/api/devices/cli"), Lookup::Found(r, _) if r.op == Assign));
    }

    #[test]
    fn tokens_are_judged_by_their_matrix() {
        let mut t = Row::default();
        t.set("permissions", Val::str(r#"{"device":"rw","user":"r","audit":"none","group":5,"address_book":null}"#));
        assert!(token_allows(&t, "device", "rw").unwrap());
        assert!(token_allows(&t, "user", "r").unwrap());
        assert!(!token_allows(&t, "user", "rw").unwrap());
        assert!(!token_allows(&t, "audit", "r").unwrap());
        // an odd level reads as its string form (rank 0), a null or missing one as none
        assert!(!token_allows(&t, "group", "r").unwrap());
        assert!(!token_allows(&t, "address_book", "r").unwrap());
        assert!(!token_allows(&t, "strategy", "r").unwrap());
        // an array in the matrix is the previous console's TypeError
        t.set("permissions", Val::str(r#"{"device":["rw"]}"#));
        assert!(token_allows(&t, "device", "r").is_err());
        // a matrix that is not an object grants nothing
        t.set("permissions", Val::str("5"));
        assert!(!token_allows(&t, "device", "r").unwrap());
        t.set("permissions", Val::Null);
        assert!(!token_allows(&t, "device", "r").unwrap());
    }

    #[test]
    fn flatten_and_iso() {
        let v = php::json_decode(br#"[[ ], ["a", ["b"]], "c"]"#, &php::JsonOpts::default()).unwrap();
        assert_eq!(flat_first(&v), Val::str("a"));
        assert_eq!(flat_first(&Val::Arr(Arr::new())), Val::Bool(false));
        assert_eq!(iso(&Val::str("2026-10-24 12:00:05")).unwrap(), Val::str("2026-10-24T12:00:05+00:00"));
        assert_eq!(iso(&Val::Null).unwrap(), Val::Null);
    }
}
