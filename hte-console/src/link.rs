//! Phase 3: the server link, the endpoints the ID server (hbbs) calls (routes/api, v1.15.0-hte.1):
//!
//!   GET  /api/server/policy       ServerLinkController::policy   (ServerLink::policy + HTE Remote's scope block)
//!   POST /api/server/local-addrs  ServerLinkController::localAddrs
//!   POST /api/server/refusals     App\Hte\RefusalsController::store (alarm 102)
//!   POST /api/server/relay-sessions  the relay's report of each session it carried (path.rs)
//!
//! behind `VerifyServerSecret` (404 while no secret is set, 401 for a wrong one, `hash_equals`) and
//! `throttle:600,1,server-link`. hbbs runs inside the CortenDesk container and reaches the console at
//! `HTE_REMOTE_CONSOLE_URL` (loopback by default), so these move when that URL points here, not through Caddy.
//! The policy is ETag'd as the previous console does it (sha256 of the body, quoted; `If-None-Match` answered 304), and every pull
//! is recorded in Laravel's cache (`ServerLink::recordPull`) for Settings and Fleet Diagnostics.
//!
//! Not ported: the security-alarm notification per refusal (Apprise; off at HTE, a no-op in the previous console then).

use crate::api::{fail, Limiter, Native, Reply};
use crate::cache::{self, Store};
use crate::laravel::{self, Cast, Input};
use crate::php::{self, Fault, Val};
use crate::sqlite::{self as db, P};
use crate::validate::{self, Rule};
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

/// What the link needs beyond the shared `Native`.
pub struct Link {
    /// `config('cortendesk.server_secret')`; empty = the link is off (404). Never logged.
    secret: String,
    pub store: Store,
    limiter: Mutex<Limiter>,
}

impl Link {
    pub fn new(secret: &str, store: Store) -> Link {
        Link { secret: secret.trim().to_string(), store, limiter: Mutex::new(Limiter::default()) }
    }

    /// As the CortenDesk image gets it: `HTE_REMOTE_SERVER_SECRET`, else the file the entrypoint generates
    /// (`HTE_CONSOLE_SERVER_SECRET_FILE`, default `/data/.server_secret`), trimmed.
    pub fn from_env() -> Result<Link, String> {
        let secret = server_secret();
        let link = Link::new(&secret, Store::from_env()?);
        if link.secret.is_empty() {
            tracing::warn!("server link: no secret (HTE_REMOTE_SERVER_SECRET or the secret file): /api/server/* answer 404 as the previous console does unlinked");
        }
        Ok(link)
    }
}

/// The shared secret the ID server and the console sign with: `HTE_REMOTE_SERVER_SECRET`, else the secret file; empty = the link is off.
/// Never logged.
pub fn server_secret() -> String {
    {
        match crate::envvar::var("HTE_REMOTE_SERVER_SECRET").ok().filter(|s| !s.trim().is_empty()) {
            Some(s) => s,
            None => {
                let path = crate::envvar::var("HTE_CONSOLE_SERVER_SECRET_FILE").unwrap_or_else(|_| "/data/.server_secret".into());
                match std::fs::read_to_string(&path) {
                    Ok(s) => s,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                    Err(e) => {
                        // The CortenDesk image writes it root-only; the deploy passes it in the environment instead
                        tracing::warn!("server link: cannot read {path} ({e}); set HTE_REMOTE_SERVER_SECRET");
                        String::new()
                    }
                }
            }
        }
    }
    .trim()
    .to_string()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    Policy,
    LocalAddrs,
    Refusals,
    RelaySessions,
}

impl Route {
    fn uri(self) -> &'static str {
        match self {
            Route::Policy => "api/server/policy",
            Route::LocalAddrs => "api/server/local-addrs",
            Route::Refusals => "api/server/refusals",
            Route::RelaySessions => "api/server/relay-sessions",
        }
    }
    fn methods(self) -> &'static [&'static str] {
        match self {
            Route::Policy => &["GET", "HEAD"],
            _ => &["POST"],
        }
    }
}

/// The server-link paths, for main.rs to merge in front of phase 1/2's router.
pub fn routes(native: Arc<Native>, link: Arc<Link>) -> Router {
    let mut r = Router::new();
    for (path, route) in [("/api/server/policy", Route::Policy), ("/api/server/local-addrs", Route::LocalAddrs), ("/api/server/refusals", Route::Refusals), ("/api/server/relay-sessions", Route::RelaySessions)] {
        r = r.route(path, any(move |s, c, req| handle(s, c, req, route)));
    }
    r.with_state((native, link))
}

type Headers = Vec<(&'static str, String)>;

/// A JSON (or empty) answer with Laravel's `api/*` headers.
fn respond(status: u16, body: Option<String>, extra: Headers, head: bool) -> Response<Body> {
    let mut b = Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header(header::CACHE_CONTROL, "no-cache, private")
        .header("access-control-allow-origin", "*");
    if body.is_some() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    for (k, v) in extra {
        if let Ok(v) = HeaderValue::from_str(&v) {
            b = b.header(k, v);
        }
    }
    b.body(if head { Body::empty() } else { Body::from(body.unwrap_or_default()) }).unwrap_or_else(|_| Response::new(Body::empty()))
}

fn message(status: u16, msg: &str) -> (u16, String) {
    let mut s = String::new();
    let _ = php::enc_str(msg.as_bytes(), &mut s);
    (status, format!(r#"{{"message":{s}}}"#))
}

fn reply_parts(r: Reply) -> (u16, String) {
    match r {
        Reply::Json(s, b) => (s, b),
        Reply::Text(s, b) => (s, String::from_utf8_lossy(&b).into_owned()),
    }
}

fn header_str<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

async fn handle(State((n, link)): State<(Arc<Native>, Arc<Link>)>, ConnectInfo(peer): ConnectInfo<SocketAddr>, req: Request<Body>, route: Route) -> Response<Body> {
    let (parts, body) = req.into_parts();
    let method = parts.method.clone();
    let head = method == Method::HEAD;
    // HandleCors: a preflight never reaches the route
    if method == Method::OPTIONS && parts.headers.contains_key("access-control-request-method") {
        let mut extra = vec![
            ("access-control-allow-methods", header_str(&parts.headers, "access-control-request-method").unwrap_or("").to_ascii_uppercase()),
            ("access-control-max-age", "0".to_string()),
            ("vary", "Access-Control-Request-Method, Access-Control-Request-Headers".to_string()),
        ];
        if let Some(h) = header_str(&parts.headers, "access-control-request-headers") {
            extra.push(("access-control-allow-headers", h.to_string()));
        }
        let mut r = respond(204, None, extra, false);
        r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=UTF-8"));
        return r;
    }
    if !route.methods().contains(&method.as_str()) {
        if method == Method::OPTIONS {
            let mut r = respond(200, None, vec![("allow", route.methods().join(",")), ("vary", "Access-Control-Request-Method".into())], false);
            r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=UTF-8"));
            return r;
        }
        let (s, b) = message(405, &format!("The {} method is not supported for route {}. Supported methods: {}.", method, route.uri(), route.methods().join(", ")));
        return respond(s, Some(b), vec![("allow", route.methods().join(", "))], head);
    }
    // ValidatePostSize, bounded below the previous console's limit: 500 entries of the longest values hbbs may send fit
    let max = max_body();
    let declared = header_str(&parts.headers, "content-length").and_then(|v| v.trim().parse::<u64>().ok());
    let too_large = || {
        let (s, b) = message(413, "The POST data is too large.");
        respond(s, Some(b), vec![], false)
    };
    if declared.map_or(false, |l| l > max as u64) {
        return too_large();
    }
    let Ok(body) = axum::body::to_bytes(body, max).await else { return too_large() };

    // VerifyServerSecret
    if link.secret.is_empty() {
        return respond(404, Some(r#"{"error":"Server link is not configured."}"#.into()), vec![], head);
    }
    let bearer = laravel::bearer_token(parts.headers.get(header::AUTHORIZATION).map(|v| v.as_bytes())).unwrap_or_default();
    if !php::hash_equals(link.secret.as_bytes(), &bearer) {
        return respond(401, Some(r#"{"error":"Invalid server secret."}"#.into()), vec![], head);
    }

    // throttle:600,1,server-link (the key: the prefix and sha1 of "|<ip>")
    let xff: Vec<&str> = parts.headers.get_all("x-forwarded-for").iter().filter_map(|v| v.to_str().ok()).collect();
    let ip = laravel::client_ip(peer.ip(), &xff, &n.trusted);
    let now = n.now();
    let key = {
        use sha1::Digest as _;
        format!("server-link{}", hex::encode(sha1::Sha1::digest(format!("|{ip}").as_bytes()))).into_bytes()
    };
    {
        let mut l = link.limiter.lock().unwrap_or_else(|e| e.into_inner());
        if l.too_many(&key, 600, now) {
            let retry = l.available_in(&key, now);
            let (s, b) = message(429, "Too Many Attempts.");
            return respond(
                s,
                Some(b),
                vec![("x-ratelimit-limit", "600".into()), ("x-ratelimit-remaining", "0".into()), ("retry-after", retry.to_string()), ("x-ratelimit-reset", (now + retry).to_string())],
                head,
            );
        }
        l.hit(&key, 60, now);
    }
    let rate = |link: &Link| -> Headers {
        let l = link.limiter.lock().unwrap_or_else(|e| e.into_inner());
        vec![("x-ratelimit-limit", "600".into()), ("x-ratelimit-remaining", l.remaining(&key, 600, now).to_string())]
    };

    let input = Input::new(method.as_str(), header_str(&parts.headers, header::CONTENT_TYPE.as_str()), parts.uri.query(), &body);
    let agent = header_str(&parts.headers, "user-agent").map(str::to_string).unwrap_or_default();
    let if_none_match = header_str(&parts.headers, "if-none-match").map(str::to_string);
    let (n2, link2) = (n.clone(), link.clone());
    let out = tokio::task::spawn_blocking(move || {
        // the bodies are validated before the shared connection is taken (other routes wait on it)
        let lock = || n2.db.lock().unwrap_or_else(|e| e.into_inner());
        match route {
            Route::Policy => policy(&lock(), &link2.store, &agent, now),
            Route::LocalAddrs => Ok(match validate::validate(input.all(), ADDR_RULES) {
                Err(body) => Reply::Json(422, body),
                Ok(data) => local_addrs(&lock(), &data, now),
            }),
            Route::Refusals => Ok(match validate::validate(input.all(), REFUSAL_RULES) {
                Err(body) => Reply::Json(422, body),
                Ok(data) => refusals(&lock(), &data, now),
            }),
            Route::RelaySessions => Ok(match validate::validate(input.all(), SESSION_RULES) {
                Err(body) => Reply::Json(422, body),
                Ok(data) => relay_sessions(&lock(), &data, now),
            }),
        }
    })
    .await;
    match out {
        Ok(Ok(Reply::Json(200, body))) if route == Route::Policy => {
            let etag = format!("\"{}\"", hex::encode(Sha256::digest(body.as_bytes())));
            let mut headers = rate(&link);
            headers.push(("etag", etag.clone()));
            if not_modified(if_none_match.as_deref(), &etag) {
                return respond(304, None, headers, true);
            }
            respond(200, Some(body), headers, head)
        }
        // Laravel renders an exception inside the route pipeline: the limiter adds its headers to a 500 too
        Ok(Ok(reply)) => {
            let (s, b) = reply_parts(reply);
            respond(s, Some(b), rate(&link), head)
        }
        Ok(Err(f)) => {
            let (s, b) = reply_parts(fail("server link", &f));
            respond(s, Some(b), rate(&link), head)
        }
        Err(_) => {
            let (s, b) = reply_parts(Reply::server_error());
            respond(s, Some(b), vec![], head)
        }
    }
}

/// Symfony's `Response::isNotModified()` for an ETag (weak comparison, `*` matches; the first If-None-Match header).
fn not_modified(if_none_match: Option<&str>, etag: &str) -> bool {
    let Some(h) = if_none_match else { return false };
    let etag = etag.strip_prefix("W/").unwrap_or(etag);
    h.split(',').map(str::trim).filter(|t| !t.is_empty()).any(|t| {
        let t = t.strip_prefix("W/").unwrap_or(t);
        t == etag || t == "*"
    })
}

/// `mb_substr($agent, 0, 80)` (characters by UTF-8 lead byte, as mbstring counts them).
fn agent_prefix(agent: &str) -> String {
    let b = agent.as_bytes();
    let (mut i, mut n) = (0, 0);
    while i < b.len() && n < 80 {
        i += match b[i] {
            0xC0..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF7 => 4,
            _ => 1,
        };
        n += 1;
    }
    String::from_utf8_lossy(&b[..i.min(b.len())]).into_owned()
}

/// `ServerLinkController::policy`: the policy, then `ServerLink::recordPull` (on every pull, a 304 included).
fn policy(c: &Connection, store: &Store, agent: &str, now: i64) -> Result<Reply, Fault> {
    let body = crate::reach::server_policy(c, now)?;
    let at = chrono::DateTime::from_timestamp(now, 0).map(|d| d.format("%Y-%m-%dT%H:%M:%S+00:00").to_string()).unwrap_or_default();
    let pull = php::assoc(vec![("at".to_string(), Val::str(&at)), ("agent".to_string(), Val::str(&agent_prefix(agent)))]);
    store.forever(c, cache::PULL_KEY, &pull, now)?;
    Ok(Reply::Json(200, body))
}

const ADDR_RULES: &[(&str, &[Rule])] = &[
    ("addrs", &[Rule::Required, Rule::Array, Rule::Max(500)]),
    ("addrs.*.id", &[Rule::Required, Rule::String, Rule::Max(100)]),
    ("addrs.*.ip", &[Rule::Required, Rule::Ip]),
    ("addrs.*.seen_at", &[Rule::Nullable, Rule::Integer, Rule::Min(0)]),
];

const REFUSAL_RULES: &[(&str, &[Rule])] = &[
    ("refusals", &[Rule::Required, Rule::Array, Rule::Max(500)]),
    ("refusals.*.user_id", &[Rule::Nullable, Rule::String, Rule::Max(40)]),
    ("refusals.*.user_name", &[Rule::Nullable, Rule::String, Rule::Max(255)]),
    ("refusals.*.from", &[Rule::Nullable, Rule::String, Rule::Max(100)]),
    ("refusals.*.to", &[Rule::Required, Rule::String, Rule::Max(100)]),
    ("refusals.*.ip", &[Rule::Nullable, Rule::String, Rule::Max(64)]),
    ("refusals.*.reason", &[Rule::Nullable, Rule::String, Rule::Max(100)]),
    ("refusals.*.at", &[Rule::Nullable, Rule::Integer, Rule::Min(0)]),
];

const SESSION_RULES: &[(&str, &[Rule])] = &[
    ("sessions", &[Rule::Required, Rule::Array, Rule::Max(500)]),
    ("sessions.*.uuid", &[Rule::Required, Rule::String, Rule::Max(64)]),
    ("sessions.*.id", &[Rule::Required, Rule::String, Rule::Max(100)]),
    ("sessions.*.conn_type", &[Rule::Nullable, Rule::Integer, Rule::Min(0), Rule::Max(255)]),
    ("sessions.*.controller_ip", &[Rule::Nullable, Rule::Ip]),
    ("sessions.*.device_ip", &[Rule::Nullable, Rule::Ip]),
    ("sessions.*.started_at", &[Rule::Nullable, Rule::Integer, Rule::Min(0)]),
    ("sessions.*.ended_at", &[Rule::Nullable, Rule::Integer, Rule::Min(0)]),
    ("sessions.*.bytes", &[Rule::Nullable, Rule::Integer, Rule::Min(0)]),
];

/// `HTE_CONSOLE_SERVER_LINK_MAX_BODY_BYTES` (default 4 MiB): 500 refusals of the longest values allowed, written with
/// JSON escapes, stay below it.
fn max_body() -> usize {
    crate::envvar::var("HTE_CONSOLE_SERVER_LINK_MAX_BODY_BYTES").ok().and_then(|v| v.trim().parse().ok()).unwrap_or(4 * 1024 * 1024)
}

/// POST /api/server/local-addrs, on the validated data
fn local_addrs(c: &Connection, data: &php::Arr, now: i64) -> Reply {
    match local_addrs_inner(c, data, now) {
        Ok(n) => Reply::Json(200, format!(r#"{{"updated":{n}}}"#)),
        Err(f) => fail("server/local-addrs", &f),
    }
}

fn local_addrs_inner(c: &Connection, data: &php::Arr, now: i64) -> Result<usize, Fault> {
    let ts = laravel::ts(now);
    let mut updated = 0;
    let addrs = data.get_str("addrs").map(|v| v.to_array()).unwrap_or_default();
    for (_, addr) in addrs.iter() {
        // $addr['id'], $addr['ip']: a missing key is a warning, which Laravel turns into an exception
        let Val::Arr(addr) = addr else { return Err(Fault::Other("local-addrs: an entry is not an array".into())) };
        let id = addr.get_str("id").ok_or_else(|| Fault::Other("local-addrs: entry without id".into()))?.clone();
        let ip = addr.get_str("ip").ok_or_else(|| Fault::Other("local-addrs: entry without ip".into()))?.clone();
        // isset($addr['seen_at']) ? Carbon::createFromTimestamp(...) : now; never in the future
        let seen = match addr.get_str("seen_at") {
            None | Some(Val::Null) => now,
            Some(v) => v.to_int(),
        }
        .min(now);
        let Some(mut device) = db::first(c, r#"select * from "devices" where "rustdesk_id" = ? and "devices"."deleted_at" is null limit 1"#, &[P(Val::Str(id.to_php_string()?))])? else {
            continue;
        };
        // Out-of-order batches must not roll the address back.
        if !device.is_null("lan_ip_seen_at") {
            let at = laravel::parse_ts(&device.val("lan_ip_seen_at")).ok_or_else(|| Fault::Other("unparsable devices.lan_ip_seen_at".into()))?;
            if at > seen {
                continue;
            }
        }
        db::update_dirty(c, "devices", &mut device, vec![("lan_ip", ip, Cast::Plain), ("lan_ip_seen_at", Val::str(&laravel::ts(seen)), Cast::Date)], &ts)?;
        updated += 1;
    }
    Ok(updated)
}

/// POST /api/server/refusals, on the validated data
fn refusals(c: &Connection, data: &php::Arr, now: i64) -> Reply {
    let list = data.get_str("refusals").map(|v| v.to_array()).unwrap_or_default();
    match crate::reach::record_refusals(c, &list, now) {
        Ok(n) => Reply::Json(200, format!(r#"{{"recorded":{n}}}"#)),
        Err(f) => fail("server/refusals", &f),
    }
}

/// POST /api/server/relay-sessions, on the validated data
fn relay_sessions(c: &Connection, data: &php::Arr, now: i64) -> Reply {
    let list = data.get_str("sessions").map(|v| v.to_array()).unwrap_or_default();
    match crate::path::store_relay_sessions(c, &list, now) {
        Ok(n) => Reply::Json(200, format!(r#"{{"stored":{n}}}"#)),
        Err(f) => fail("server/relay-sessions", &f),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etags_compare_like_symfony() {
        let e = "\"abc\"";
        assert!(not_modified(Some("\"abc\""), e));
        assert!(not_modified(Some("W/\"abc\""), e));
        assert!(not_modified(Some("\"x\", \"abc\""), e));
        assert!(not_modified(Some("*"), e));
        assert!(!not_modified(Some("abc"), e));
        assert!(!not_modified(None, e));
    }

    #[test]
    fn agent_is_cut_at_80_characters() {
        assert_eq!(agent_prefix("cortendesk-server/1.1.1"), "cortendesk-server/1.1.1");
        assert_eq!(agent_prefix(&"é".repeat(100)).chars().count(), 80);
    }
}
