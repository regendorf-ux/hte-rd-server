//! Phase 7: the console's pages, one group at a time, answered here behind the Laravel session; every other path
//! (and every request that has no valid session) is handed to the previous console unchanged, so nothing is ever served
//! to someone the previous console has not signed in.
//!
//! The request pipeline of a page (what Laravel's `web` group and the route's middleware do, in their order):
//!   1. the session cookie -> the `sessions` row -> the signed-in user (`auth`); none: forward to the previous console, which
//!      redirects to its sign-in page (and handles the remember-me cookie, which is not read here)
//!   2. `EnsureUserIsActive`, `RequireTwoFactor`, `RequireEmailAddress`, `RequireMailHealthy`: when any of them
//!      would redirect, the request is forwarded to the previous console, which does exactly that
//!   3. CSRF (`PreventRequestForgery`) for anything that is not a read: a refusal is Laravel's 419 page
//!   4. `console-can:<area>,<level>`: a refusal redirects to the overview with the flash `denied`
//!   5. the page's handler, on the one database connection; its flash messages and a regenerated session id are
//!      written afterwards, then the session cookie is re-sent (Laravel re-sends it on every response)

pub mod account;
pub mod address_books;
pub mod assets;
pub mod device_detail;
pub mod diagnostics;
pub mod roles;
pub mod devices;
pub mod kit;
pub mod logs;
pub mod overview;
pub mod paginate;
pub mod session;
pub mod login;
pub mod challenge;
pub mod invitations;
pub mod twofactor;
pub mod mailtest;
pub mod websession;
pub mod api_tokens;
pub mod backups;
pub mod settings;
pub mod strategies;
pub mod unavailable;
pub mod webclient;

/// One write transaction (`begin immediate` .. `commit`, rolled back on an error).
pub(crate) fn strategies_tx<T>(c: &rusqlite::Connection, f: impl FnOnce() -> Result<T, crate::php::Fault>) -> Result<T, crate::php::Fault> {
    strategies::tx(c, f)
}
pub mod groups;
pub mod time;
pub mod users;
pub mod view;

use crate::api::Native;
use crate::laravel::{self, Input};
use crate::php::{Fault, Val};
use crate::sqlite::{self as db, Row, P};
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use rusqlite::Connection;
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceExt;

pub struct Pages {
    pub n: Arc<Native>,
    /// The previous console (the shadow proxy), for everything not served here. None: a request without a session is
    /// redirected to `/login` (tests and a standalone run).
    pub php: Option<Router>,
    pub session: session::SessionConfig,
    pub view: view::View,
    pub store: crate::cache::Store,
    pub config: PageConfig,
    /// Phase 8: hte-console's own sign-in and session (`websession`, `login`).
    pub own: websession::OwnConfig,
}

/// What the previous console reads from `config()` for its layout: the same environment variables.
#[derive(Clone, Debug)]
pub struct PageConfig {
    pub update_check: bool,
    pub native_webclient: bool,
    pub webclient_url: String,
    pub rdgen_default: String,
}

impl PageConfig {
    pub fn from_env() -> PageConfig {
        let get = |n: &str| crate::envvar::var(n).ok();
        // filter_var(..., FILTER_VALIDATE_BOOL): unset is the default, anything not truthy is false
        let boolean = |n: &str, default: bool| match get(n) {
            None => default,
            Some(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes"),
        };
        PageConfig {
            update_check: crate::update_check::enabled(),
            native_webclient: boolean("HTE_REMOTE_NATIVE_WEBCLIENT", true),
            webclient_url: get("HTE_REMOTE_WEBCLIENT_URL").unwrap_or_default(),
            rdgen_default: get("HTE_REMOTE_RDGEN_URL").unwrap_or_else(|| "https://rdgen.crayoneater.org".into()),
        }
    }
}

// ------------------------------------------------------------------------------------------- what a handler gets ---

/// The signed-in person and what the pipeline learned about the request.
pub struct Ctx<'a> {
    pub p: &'a Pages,
    pub user: Row,
    pub role: Option<Row>,
    pub session: session::Session,
    /// The flash values the previous request left (`session('denied')`).
    pub flashed: Map<String, Value>,
    pub root: String,
    pub ip: String,
    pub now: i64,
    pub secure: bool,
    /// Flash for the next request, written after the handler.
    pub flash_out: std::cell::RefCell<Vec<(String, Value)>>,
    /// Set by a handler that regenerated the session (a password change): the cookie then carries this id.
    pub new_session_id: std::cell::RefCell<Option<String>>,
}

pub struct Req {
    pub method: String,
    pub path: String,
    pub htmx: bool,
    pub headers: HeaderMap,
    /// `$request->input()`: the query and the form or JSON body, TrimStrings and ConvertEmptyStringsToNull applied.
    pub input: Input,
}

pub enum Reply {
    Html(u16, String),
    Redirect(String),
    NoContent,
    Json(u16, String),
    Csv { filename: String, body: String },
    /// A stored file handed out as it is (a backup archive).
    Bytes { filename: String, body: Vec<u8> },
    /// A generated download (`streamDownload` with its own content type, `no-store`): the diagnostics JSON.
    Download { filename: String, content_type: &'static str, body: Vec<u8> },
}

pub type Handler = for<'a> fn(&Ctx<'a>, &Connection, &Req) -> Result<Reply, Fault>;

pub struct Route {
    pub path: &'static str,
    pub methods: &'static [&'static str],
    /// `console-can:<area>,<level>`; None for a page every signed-in person may open.
    pub need: Option<(&'static str, &'static str)>,
    pub handler: Handler,
}

impl<'a> Ctx<'a> {
    pub fn uid(&self) -> i64 {
        self.user.id()
    }

    pub fn is_admin(&self) -> bool {
        self.user.val("is_admin").to_bool()
    }

    /// `User::consoleAllows($resource, $level)`.
    pub fn allows(&self, resource: &str, level: &str) -> bool {
        if self.is_admin() {
            return true;
        }
        let rank = |l: &str| match l {
            "rw" => 2,
            "r" => 1,
            _ => 0,
        };
        let have = match &self.role {
            Some(r) => {
                let perms: Value = r.val("permissions").to_php_string().ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
                match perms.get(resource).and_then(|v| v.as_str()) {
                    Some(l @ ("none" | "r" | "rw")) => l.to_string(),
                    _ => "none".to_string(),
                }
            }
            None => legacy_level(resource).to_string(),
        };
        rank(&have) >= rank(level)
    }

    pub fn display_name(&self) -> String {
        let name = String::from_utf8_lossy(&self.user.val("name").to_php_string().unwrap_or_default()).into_owned();
        if name.is_empty() || name == "0" {
            String::from_utf8_lossy(&self.user.val("username").to_php_string().unwrap_or_default()).into_owned()
        } else {
            name
        }
    }

    pub fn theme(&self) -> String {
        match String::from_utf8_lossy(&self.user.val("theme").to_php_string().unwrap_or_default()).as_ref() {
            t @ ("dark" | "light" | "system") => t.to_string(),
            _ => "dark".to_string(),
        }
    }

    pub fn flash(&self, key: &str, value: Value) {
        self.flash_out.borrow_mut().push((key.to_string(), value));
    }

    /// `$user->visibleTo` for a non-admin: the ids of the approved devices they may see.
    pub fn visible_device_ids(&self, c: &Connection) -> Result<Vec<String>, Fault> {
        let rows = crate::reach::visible_devices(c, &self.user, None, "")?;
        Ok(rows.iter().map(|r| String::from_utf8_lossy(&r.val("rustdesk_id").to_php_string().unwrap_or_default()).into_owned()).collect())
    }

    /// The layout's variables: the sidebar's permissions, the top bar's identity, the flash, the release check.
    /// `route` is the Laravel route name the sidebar highlights (`logs.alarms`), `title` the page's title.
    pub fn layout(&self, c: &Connection, route: &str, title: &str, subtitle: &str) -> Result<Value, Fault> {
        let role_name = if self.is_admin() {
            "Administrator".to_string()
        } else {
            match &self.role {
                Some(r) => String::from_utf8_lossy(&r.val("name").to_php_string().unwrap_or_default()).into_owned(),
                None => "User".to_string(),
            }
        };
        let username = String::from_utf8_lossy(&self.user.val("username").to_php_string().unwrap_or_default()).into_owned();
        let can_settings = self.allows("setting", "r");
        let rdgen = db::setting(c, "rdgen_url", &self.p.config.rdgen_default)?;
        let (upgrade, checked) = if can_settings { self.p.update_state(c, self.now)? } else { (None, false) };
        Ok(json!({
            "app_name": self.p.n.signin.app_name,
            "route": route,
            "in_logs": route.starts_with("logs."),
            "in_diagnostics": route.starts_with("diagnostics"),
            "title": title,
            "subtitle": subtitle,
            "csrf": self.session.token().unwrap_or(""),
            "theme": self.theme(),
            "version": crate::REMOTE_VERSION,
            "now": self.now,
            "year": chrono::DateTime::<chrono::Utc>::from_timestamp(self.now, 0).map(|d| chrono::Datelike::year(&d)).unwrap_or(2026),
            "user": {
                "username": username,
                "display_name": self.display_name(),
                "initial": username.chars().next().map(|c| c.to_uppercase().collect::<String>()).unwrap_or_else(|| "A".into()),
                "role": role_name,
            },
            "can": {
                "devices": self.allows("device", "r"),
                "address_books": self.allows("address_book", "r"),
                "groups": self.allows("group", "r"),
                "users": self.allows("user", "r"),
                "strategies": self.allows("strategy", "r"),
                "audit": self.allows("audit", "r"),
                "audit_manage": self.allows("audit", "rw"),
                "settings": can_settings,
                "roles": self.is_admin(),
            },
            "native_webclient": self.p.config.native_webclient,
            "webclient_url": self.p.config.webclient_url,
            "rdgen_url": String::from_utf8_lossy(&rdgen).into_owned(),
            "update": {"enabled": self.p.config.update_check, "upgrade": upgrade, "checked": checked, "repo": crate::update_check::repo(), "tag_prefix": crate::update_check::TAG_PREFIX, "released": crate::RELEASED_AT},
            "flash_denied": self.flashed.get("denied").and_then(|v| v.as_str()).unwrap_or(""),
        }))
    }

    /// Render a page: the layout's variables, the page's own, in one context.
    pub fn render(&self, template: &str, layout: Value, page: Value) -> Result<String, Fault> {
        let mut all = match layout {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        if let Value::Object(m) = page {
            all.extend(m);
        }
        self.p.view.render(template, Value::Object(all)).map_err(Fault::Other)
    }
}

/// `Permissions::LEGACY_USER`: what a person with no role may do.
pub fn legacy_level(resource: &str) -> &'static str {
    match resource {
        "device" | "address_book" => "rw",
        "audit" => "r",
        _ => "none",
    }
}

impl Pages {
    /// `(upgrade available, a release is known)` from the cached release check (`update_check::CACHE_KEY`, filled once a
    /// day by `update_check::start` from the project's own release tags), compared with HTE Remote's version. Nothing cached: "unknown".
    fn update_state(&self, c: &Connection, now: i64) -> Result<(Option<String>, bool), Fault> {
        if !self.config.update_check {
            return Ok((None, false));
        }
        let raw = self.store.get_raw(c, crate::update_check::CACHE_KEY, now)?;
        let latest = raw.and_then(|b| unserialize_string(&b)).filter(|s| !s.is_empty());
        let current = crate::REMOTE_VERSION.to_string();
        let upgrade = match &latest {
            Some(l) if !current.is_empty() && version_compare(l, &current) > 0 => Some(l.clone()),
            _ => None,
        };
        Ok((upgrade, latest.is_some()))
    }
}

/// `unserialize()` of a cached string: `s:<len>:"<bytes>";`.
pub(crate) fn unserialize_string(b: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(b).ok()?;
    let rest = s.strip_prefix("s:")?;
    let (len, rest) = rest.split_once(':')?;
    let len: usize = len.parse().ok()?;
    let body = rest.strip_prefix('"')?;
    body.get(..len).map(str::to_string)
}

/// The previous console's `version_compare($a, $b)`: -1, 0 or 1.
pub fn version_compare(a: &str, b: &str) -> i32 {
    fn canon(v: &str) -> Vec<String> {
        let mut out: Vec<String> = vec![];
        let mut cur = String::new();
        let mut last: Option<bool> = None; // is_digit of the previous character
        for ch in v.chars() {
            if matches!(ch, '-' | '_' | '+' | '.') {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                last = None;
                continue;
            }
            let d = ch.is_ascii_digit();
            if let Some(l) = last {
                if l != d && !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            cur.push(ch);
            last = Some(d);
        }
        if !cur.is_empty() {
            out.push(cur);
        }
        out
    }
    fn order(form: &str) -> i32 {
        for (name, o) in [("dev", 0), ("alpha", 1), ("a", 1), ("beta", 2), ("b", 2), ("RC", 3), ("rc", 3), ("#", 4), ("pl", 5), ("p", 5)] {
            if form.starts_with(name) {
                return o;
            }
        }
        -1
    }
    let special = |x: &str, y: &str| (order(x) - order(y)).signum();
    let (pa, pb) = (canon(a), canon(b));
    let mut i = 0;
    while i < pa.len() && i < pb.len() {
        let (x, y) = (&pa[i], &pb[i]);
        let (dx, dy) = (x.as_bytes()[0].is_ascii_digit(), y.as_bytes()[0].is_ascii_digit());
        let c = match (dx, dy) {
            (true, true) => x.parse::<i64>().unwrap_or(0).cmp(&y.parse::<i64>().unwrap_or(0)) as i32,
            (false, false) => special(x, y),
            (true, false) => special("#N#", y),
            (false, true) => special(x, "#N#"),
        };
        if c != 0 {
            return c;
        }
        i += 1;
    }
    if i < pa.len() {
        return if pa[i].as_bytes()[0].is_ascii_digit() { 1 } else { special(&pa[i], "#N#") };
    }
    if i < pb.len() {
        return if pb[i].as_bytes()[0].is_ascii_digit() { -1 } else { special("#N#", &pb[i]) };
    }
    0
}

// ----------------------------------------------------------------------------------------------- the pipeline ---

enum Out {
    Forward,
    Done(Response<Body>),
}

pub fn html(status: u16, body: String, head: bool) -> Response<Body> {
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header(header::CONTENT_TYPE, "text/html; charset=UTF-8")
        .header(header::CACHE_CONTROL, "no-cache, private")
        .body(if head { Body::empty() } else { Body::from(body) })
        .unwrap()
}

fn error_response(status: u16, text: &str, head: bool) -> Response<Body> {
    html(status, crate::signin::error_page(status, text), head)
}

fn redirect(to: &str) -> Response<Body> {
    // Laravel's RedirectResponse
    let body = format!("<!DOCTYPE html>\n<html>\n    <head>\n        <meta charset=\"UTF-8\" />\n        <meta http-equiv=\"refresh\" content=\"0;url='{u}'\" />\n\n        <title>Redirecting to {u}</title>\n    </head>\n    <body>\n        Redirecting to <a href=\"{u}\">{u}</a>.\n    </body>\n</html>", u = laravel::e(to));
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, HeaderValue::from_str(to).unwrap_or(HeaderValue::from_static("/")))
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-cache, private")
        .body(Body::from(body))
        .unwrap()
}

fn header_bytes<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a [u8]> {
    h.get(name).map(|v| v.as_bytes())
}

fn hstr<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

/// Everything the gate decides before a handler runs. Err(Out) ends the request.
fn gate<'a>(p: &'a Pages, c: &Connection, parts: &axum::http::request::Parts, body: &[u8], peer: SocketAddr, route: &Route) -> Result<(Ctx<'a>, Req), Out> {
    let now = p.n.now();
    // the local page comparison (`replay/compare-local.sh`) renders each page at the second the previous console answered it; only while
    // the console runs on a set clock (HTE_CONSOLE_CLOCK_START), never in production
    let now = if p.n.clock_is_set() { hstr(&parts.headers, "x-hte-replay-clock").and_then(|v| v.trim().parse::<i64>().ok()).unwrap_or(now) } else { now };
    let fault = |f: Fault| {
        tracing::error!("page: {}", match &f {
            Fault::Other(m) => m.as_str(),
            _ => "fault",
        });
        Out::Done(error_response(500, "Server Error", false))
    };
    let cookie_header = parts.headers.get_all(header::COOKIE).iter().filter_map(|v| v.to_str().ok()).collect::<Vec<_>>().join("; ");
    let trusted = &p.n.trusted;
    let xff: Vec<&str> = parts.headers.get_all("x-forwarded-for").iter().filter_map(|v| v.to_str().ok()).collect();
    let ip = laravel::client_ip(peer.ip(), &xff, trusted);
    let root = crate::api::request_root(&p.n, &parts.headers, peer.ip()).unwrap_or_default();
    let secure = root.starts_with("https://");
    // phase 8: without a session, hte-console's own sign-in page when it has one (HTE_CONSOLE_SIGNIN), else the previous console's
    let to_login = |message: Option<&str>| {
        if !p.own.signin {
            return Out::Forward;
        }
        let pq = parts.uri.path_and_query().map_or("/", |x| x.as_str());
        let ua = hstr(&parts.headers, "user-agent").unwrap_or("");
        Out::Done(login::to_login(p, c, &cookie_header, &root, secure, &ip, ua, parts.method.as_str(), pq, now, message))
    };
    let sess = match session::load_any(c, &p.session, &p.own, &p.n.crypt, now, &cookie_header, secure) {
        Ok(Some(s)) if s.user_id().is_some() => s,
        Ok(_) => return Err(to_login(None)),
        Err(f) => return Err(fault(f)),
    };
    let Some(uid) = sess.user_id() else { return Err(to_login(None)) };
    let user = match db::first(c, r#"select * from "users" where "id" = ? limit 1"#, &[P(Val::Int(uid))]) {
        Ok(Some(u)) => u,
        Ok(None) => return Err(to_login(None)),
        Err(f) => return Err(fault(f)),
    };
    // our own session: revoked anywhere (remember_token rotated) or the account disabled ends it here
    if sess.own {
        match websession::still_valid(c, &sess, &user) {
            Ok(true) => {}
            Ok(false) => return Err(to_login(None)),
            Err(f) => return Err(fault(f)),
        }
    }
    // EnsureUserIsActive: the previous console signs the person out
    if !user.val("is_active").to_bool() {
        return Err(Out::Forward);
    }
    let role = match user.val("role_id") {
        Val::Null => None,
        id => match db::first(c, r#"select * from "roles" where "id" = ? limit 1"#, &[P(id)]) {
            Ok(r) => r,
            Err(f) => return Err(fault(f)),
        },
    };
    let flashed = sess.flashed();
    let ctx = Ctx {
        p,
        user,
        role,
        session: sess,
        flashed,
        root,
        ip,
        now,
        secure,
        flash_out: Default::default(),
        new_session_id: Default::default(),
    };
    let method = parts.method.as_str().to_string();
    let content_type = hstr(&parts.headers, "content-type");
    let input = Input::new(&method, content_type, parts.uri.query(), body);
    // CSRF
    let csrf = session::csrf_ok(
        &p.n.crypt,
        &ctx.session,
        &method,
        hstr(&parts.headers, "sec-fetch-site"),
        input.get("_token").and_then(|v| v.to_php_string().ok()).as_deref(),
        header_bytes(&parts.headers, "x-csrf-token"),
        header_bytes(&parts.headers, "x-xsrf-token"),
    );
    if !csrf {
        return Err(Out::Done(error_response(419, "Page Expired", false)));
    }
    let req = Req { method, path: parts.uri.path().to_string(), htmx: parts.headers.contains_key("hx-request"), headers: parts.headers.clone(), input };
    // RequireTwoFactor / RequireEmailAddress / RequireMailHealthy (after the CSRF check, as the web group orders them)
    match required_step(c, &ctx, &req.path) {
        Ok(None) => {}
        Ok(Some((to, key, message))) => {
            ctx.flash(key, json!(message));
            let to = format!("{}{to}", ctx.root);
            return Err(Out::Done(finish(&ctx, c, redirect(&to), false)));
        }
        Err(f) => return Err(fault(f)),
    }
    // console-can
    if let Some((area, level)) = route.need {
        if !ctx.allows(area, level) {
            ctx.flash("denied", json!("That section is restricted."));
            let to = format!("{}/", ctx.root);
            return Err(Out::Done(finish(&ctx, c, redirect(&to), false)));
        }
    }
    Ok((ctx, req))
}

/// The three middlewares that send a signed-in person somewhere else first (phase 8 answers them here):
/// `RequireTwoFactor` (enrolment, only `/account/two-factor` stays open; single sign-on sessions exempt),
/// `RequireEmailAddress` (an address while e-mailed codes are on; `/account*` stays open) and `RequireMailHealthy`
/// (a person let in to repair a broken relay goes to Settings → Email until it works; the marker drops once it does).
fn required_step(c: &Connection, ctx: &Ctx, path: &str) -> Result<Option<(&'static str, &'static str, &'static str)>, Fault> {
    let flag = |k: &str| -> Result<bool, Fault> { Ok(db::setting(c, k, "0")? == b"1") };
    let user = &ctx.user;
    if !ctx.session.via_oidc() {
        if !user.val("totp_enabled").to_bool() && path != "/account/two-factor" {
            let required = flag("two_factor_required")?
                || (user.val("is_admin").to_bool() && flag("two_factor_required_admins")?)
                || ctx.role.as_ref().map_or(false, |r| r.val("require_two_factor").to_bool());
            if required {
                return Ok(Some(("/account/two-factor", "twofactor_enforced", "Two-factor authentication is required. Please set it up to continue.")));
            }
        }
        let email = String::from_utf8_lossy(&user.val("email").to_php_string().unwrap_or_default()).into_owned();
        if email.trim().is_empty() && !path.starts_with("/account") && flag("email_login_verification")? && crate::mail::enabled(c)? {
            return Ok(Some(("/account", "email_required", "Sign-in verification is enabled on this console, so your account needs an email address. Add one to continue.")));
        }
    }
    let truthy = |v: &Value| !matches!(v, Value::Null | Value::Bool(false)) && v.as_str().map_or(true, |s| !s.is_empty() && s != "0");
    if ctx.session.data.get("mail_repair").map_or(false, truthy) {
        if !(flag("email_login_verification")? && crate::mail::enabled(c)?) || crate::mail::is_healthy(c)? {
            // fixed: the marker goes
            let mut data = ctx.session.data.clone();
            data.remove("mail_repair");
            let _ = session::save(c, &ctx.session, &data, ctx.now);
            return Ok(None);
        }
        if !(path.starts_with("/settings") || path.starts_with("/account")) {
            return Ok(Some(("/settings?tab=email", "mail_broken", "This console cannot send email, so nobody else can sign in while verification is enabled. Fix the settings below and send a test message.")));
        }
    }
    Ok(None)
}

/// What every authenticated response does at the end: write the session's changes and re-send its cookie.
fn finish(ctx: &Ctx, c: &Connection, mut resp: Response<Body>, _head: bool) -> Response<Body> {
    let flash = std::mem::take(&mut *ctx.flash_out.borrow_mut());
    let mut data = ctx.session.data.clone();
    let mut changed = false;
    // Laravel saves a session by flashing first and ageing last (`Store::save`): a message flashed here is "old" for
    // the next request, and the one after that never sees it
    for (k, v) in flash {
        session::flash(&mut data, &k, v);
        changed = true;
    }
    if let Some(a) = session::aged(&data) {
        data = a;
        changed = true;
    }
    let mut id = ctx.session.id.clone();
    if let Some(new) = ctx.new_session_id.borrow().clone() {
        // the regenerated session row carries the (unchanged) data as it was when it was copied; bring it up to date
        if let Ok(Some(s)) = session::reload(c, &ctx.p.session, &ctx.p.own, ctx.now, &ctx.session, &new) {
            if let Some(t) = s.data.get("_token") {
                data.insert("_token".into(), t.clone());
            }
            let _ = session::save(c, &s, &data, ctx.now);
        }
        id = new;
    } else if changed {
        // a lost race is not retried: the next request ages the flash again
        let _ = session::save(c, &ctx.session, &data, ctx.now);
    } else {
        let _ = session::touch(c, &ctx.session, ctx.now);
    }
    let cookie = websession::cookie_for(&ctx.p.session, &ctx.p.own, &ctx.p.n.crypt, &ctx.session, &id, ctx.secure, ctx.now);
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    // phase 8: the previous console's bridged session is re-sent with ours, so the previous console's pages keep working as long as ours does
    if ctx.session.own {
        if let Ok(Some(l)) = websession::bridged_id(c, &ctx.session) {
            if let Ok(v) = HeaderValue::from_str(&session::set_cookie(&ctx.p.session, &ctx.p.n.crypt, &l, ctx.secure, ctx.now)) {
                resp.headers_mut().append(header::SET_COOKIE, v);
            }
        }
    }
    resp
}

fn reply_to_response(ctx: &Ctx, r: Reply, head: bool) -> Response<Body> {
    match r {
        Reply::Html(status, body) => html(status, body, head),
        Reply::Redirect(to) => redirect(&if to.starts_with('/') { format!("{}{to}", ctx.root) } else { to }),
        Reply::NoContent => Response::builder().status(StatusCode::NO_CONTENT).header(header::CACHE_CONTROL, "no-cache, private").body(Body::empty()).unwrap(),
        Reply::Json(status, body) => Response::builder()
            .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CACHE_CONTROL, "no-store, private")
            .body(if head { Body::empty() } else { Body::from(body) })
            .unwrap(),
        Reply::Csv { filename, body } => Response::builder()
            .status(StatusCode::OK)
            // streamDownload sets no content type of its own: Symfony fills in its default
            .header(header::CONTENT_TYPE, "text/html; charset=UTF-8")
            .header(header::CONTENT_DISPOSITION, format!("attachment; filename={filename}"))
            .header(header::CACHE_CONTROL, "no-cache, private")
            .body(if head { Body::empty() } else { Body::from(body) })
            .unwrap(),
        Reply::Download { filename, content_type, body } => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CONTENT_DISPOSITION, format!("attachment; filename={filename}"))
            .header(header::CACHE_CONTROL, "no-store, private")
            .body(if head { Body::empty() } else { Body::from(body) })
            .unwrap(),
        Reply::Bytes { filename, body } => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/x-tar")
            .header(header::CONTENT_DISPOSITION, format!("attachment; filename={filename}"))
            .header(header::CACHE_CONTROL, "no-store, private")
            .body(if head { Body::empty() } else { Body::from(body) })
            .unwrap(),
    }
}

/// Largest form body a page reads: forms here are a few hundred bytes.
fn max_body() -> usize {
    crate::envvar::var("HTE_CONSOLE_PAGE_MAX_BODY_BYTES").ok().and_then(|v| v.trim().parse().ok()).unwrap_or(64 * 1024)
}

fn upload_max() -> usize {
    crate::envvar::var("HTE_CONSOLE_UPLOAD_MAX_BYTES").ok().and_then(|v| v.trim().parse().ok()).unwrap_or(256 << 20)
}

async fn serve(State(p): State<Arc<Pages>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, req: Request<Body>, idx: usize) -> Response<Body> {
    let route = &ROUTES[idx];
    let (parts, body) = req.into_parts();
    let head = parts.method == Method::HEAD;
    // the backup upload is the one form that carries a file
    let max = if parts.uri.path() == "/settings/backups/upload" { upload_max() } else { max_body() };
    // read the body first: a forwarded request needs it again, a served one parses it
    let declared = hstr(&parts.headers, "content-length").and_then(|v| v.trim().parse::<usize>().ok());
    if declared.map_or(false, |n| n > max) {
        return error_response(413, "Content Too Large", head);
    }
    let bytes = match axum::body::to_bytes(body, max).await {
        Ok(b) => b,
        Err(_) => return error_response(413, "Content Too Large", head),
    };
    if !route.methods.contains(&parts.method.as_str()) && !(head && route.methods.contains(&"GET")) {
        // Laravel answers 405 only after routing and the session; the previous console's own answer is what the person gets, so nothing is
        // served (not even a 405) before the session has been checked
        return forward(&p, Request::from_parts(parts, Body::from(bytes))).await;
    }
    let p2 = p.clone();
    let bytes_c = bytes.clone();
    let joined = tokio::task::spawn_blocking(move || {
        let out = {
            let conn = p2.n.db.lock().unwrap_or_else(|e| e.into_inner());
            match gate(&p2, &conn, &parts, &bytes_c, peer, &ROUTES[idx]) {
                Err(o) => o,
                Ok((ctx, req)) => match Ok::<(), Fault>(()) {
                    Err(_) => Out::Done(error_response(500, "Server Error", head)),
                    Ok(()) => match (ROUTES[idx].handler)(&ctx, &conn, &req) {
                        Ok(r) => {
                            // a page answered to a form post (a dialog re-opened with its messages): the address bar keeps the page's own URL
                            let keep_url = req.method == "POST" && matches!(r, Reply::Html(..));
                            let mut resp = reply_to_response(&ctx, r, head);
                            if keep_url {
                                resp.headers_mut().insert("HX-Push-Url", HeaderValue::from_static("false"));
                            }
                            Out::Done(finish(&ctx, &conn, resp, head))
                        }
                        Err(f) => {
                            tracing::error!("page {}: {}", req.path, match &f {
                                Fault::Other(m) => m.as_str(),
                                _ => "fault",
                            });
                            Out::Done(error_response(500, "Server Error", head))
                        }
                    },
                },
            }
        };
        (out, parts)
    })
    .await;
    match joined {
        Ok((Out::Done(r), _)) => r,
        Ok((Out::Forward, parts)) => forward(&p, Request::from_parts(parts, Body::from(bytes))).await,
        Err(_) => error_response(500, "Server Error", head),
    }
}

/// Hand the request to the previous console unchanged (its session redirect, its own page); without the previous console, to the sign-in page.
pub(super) async fn forward(p: &Pages, req: Request<Body>) -> Response<Body> {
    match &p.php {
        Some(php) => match php.clone().oneshot(req).await {
            Ok(r) => r,
            Err(e) => match e {},
        },
        None => redirect("/login"),
    }
}

async fn asset(State(_p): State<Arc<Pages>>, axum::extract::Path(path): axum::extract::Path<String>, req: Request<Body>) -> Response<Body> {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return error_response(405, "Method Not Allowed", false);
    }
    assets::respond(&path, req.method() == Method::HEAD)
}

/// `GET /robots.txt`, byte for byte what the previous console's `public/robots.txt` says.
async fn robots(req: Request<Body>) -> Response<Body> {
    static_file(req.method(), "text/plain; charset=utf-8", b"User-agent: *\nDisallow:\n")
}

/// `GET /favicon.ico`: the previous console's file is empty (the pages name their icon in the head); the same answer here.
async fn favicon(req: Request<Body>) -> Response<Body> {
    static_file(req.method(), "image/x-icon", b"")
}

fn static_file(method: &Method, ctype: &'static str, bytes: &'static [u8]) -> Response<Body> {
    if method != Method::GET && method != Method::HEAD {
        return error_response(405, "Method Not Allowed", false);
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, ctype)
        .header(header::CACHE_CONTROL, "public, max-age=86400")
        .body(if method == Method::HEAD { Body::empty() } else { Body::from(bytes) })
        .unwrap()
}

/// `GET /health/live`: `{"live":true}`; 429 past the previous console's limit.
async fn health_live(State(p): State<Arc<Pages>>, req: Request<Body>) -> Response<Body> {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return error_response(405, "Method Not Allowed", false);
    }
    if !diagnostics::probe_allowed("live", p.n.now()) {
        return health_json(429, r#"{"live":false}"#.into());
    }
    health_json(200, r#"{"live":true}"#.into())
}

fn health_json(status: u16, body: String) -> Response<Body> {
    let mut b = Response::builder().status(StatusCode::from_u16(status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE)).header(header::CONTENT_TYPE, "application/json").header(header::CACHE_CONTROL, "no-cache, private");
    if status == 429 {
        b = b.header(header::RETRY_AFTER, "60");
    }
    b.body(Body::from(body)).unwrap()
}

/// `GET /health/ready`: the database, the ID server and every relay (`FleetDiagnostics::readiness`); 503 when not ready, 429
/// past the previous console's limit. The database lock is held only to read the targets, never while probing.
async fn health_ready(State(p): State<Arc<Pages>>, req: Request<Body>) -> Response<Body> {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return error_response(405, "Method Not Allowed", false);
    }
    if !diagnostics::probe_allowed("ready", p.n.now()) {
        return health_json(429, r#"{"ready":false,"database":false,"id_server":false,"relay_server":false}"#.into());
    }
    let p2 = p.clone();
    let (status, body) = tokio::task::spawn_blocking(move || {
        let targets = {
            let conn = p2.n.db.lock().unwrap_or_else(|e| e.into_inner());
            diagnostics::readiness_targets(&conn)
        };
        diagnostics::ready_body(diagnostics::readiness(targets))
    })
    .await
    .unwrap_or((503, r#"{"ready":false,"database":false,"id_server":false,"relay_server":false}"#.into()));
    health_json(status, body)
}

/// `GET /up`: Laravel's health page (status 200, "Application up"), without its external font and Tailwind script.
async fn health_up(State(p): State<Arc<Pages>>, req: Request<Body>) -> Response<Body> {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return error_response(405, "Method Not Allowed", false);
    }
    let body = format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n    <meta charset=\"utf-8\">\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\n    <title>{}</title>\n</head>\n<body>\n    <h2>Application up</h2>\n    <p>HTTP request received.</p>\n</body>\n</html>\n",
        laravel::e(&p.n.signin.app_name)
    );
    html(200, body, req.method() == Method::HEAD)
}

async fn not_found(req: Request<Body>) -> Response<Body> {
    error_response(404, "Not Found", req.method() == Method::HEAD)
}

async fn rdclient(State(_p): State<Arc<Pages>>, axum::extract::Path(path): axum::extract::Path<String>, req: Request<Body>) -> Response<Body> {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return error_response(405, "Method Not Allowed", false);
    }
    webclient::respond(&path, req.uri().query(), req.headers(), req.method() == Method::HEAD)
}

pub static ROUTES: &[Route] = &[
    Route { path: "/logs/alarms", methods: &["GET"], need: Some(("audit", "r")), handler: logs::alarms },
    Route { path: "/logs/alarms/export", methods: &["GET"], need: Some(("audit", "r")), handler: logs::alarms_export },
    Route { path: "/logs/connections", methods: &["GET"], need: Some(("audit", "r")), handler: logs::connections },
    Route { path: "/logs/connections/export", methods: &["GET"], need: Some(("audit", "r")), handler: logs::connections_export },
    Route { path: "/logs/file-transfers", methods: &["GET"], need: Some(("audit", "r")), handler: logs::file_transfers },
    Route { path: "/logs/file-transfers/export", methods: &["GET"], need: Some(("audit", "r")), handler: logs::file_transfers_export },
    Route { path: "/logs/logins", methods: &["GET"], need: Some(("audit", "rw")), handler: logs::logins },
    Route { path: "/logs/logins/export", methods: &["GET"], need: Some(("audit", "rw")), handler: logs::logins_export },
    Route { path: "/logs/console", methods: &["GET"], need: Some(("audit", "rw")), handler: logs::console },
    Route { path: "/logs/console/export", methods: &["GET"], need: Some(("audit", "rw")), handler: logs::console_export },
    Route { path: "/devices", methods: &["GET"], need: Some(("device", "r")), handler: devices::index },
    Route { path: "/devices/export", methods: &["GET"], need: Some(("device", "r")), handler: devices::export },
    Route { path: "/devices/sort", methods: &["POST"], need: Some(("device", "r")), handler: devices::sort },
    Route { path: "/devices/columns", methods: &["POST"], need: Some(("device", "r")), handler: devices::columns },
    Route { path: "/devices/bulk", methods: &["POST"], need: Some(("device", "r")), handler: devices::bulk },
    Route { path: "/devices/save", methods: &["POST"], need: Some(("device", "r")), handler: devices::save },
    Route { path: "/devices/delete", methods: &["POST"], need: Some(("device", "r")), handler: devices::delete },
    Route { path: "/devices/act", methods: &["POST"], need: Some(("device", "r")), handler: devices::act },
    Route { path: "/devices/:id", methods: &["GET"], need: Some(("device", "r")), handler: device_detail::show },
    Route { path: "/devices/:id/do", methods: &["POST"], need: Some(("device", "r")), handler: device_detail::act },
    Route { path: "/strategies", methods: &["GET"], need: Some(("strategy", "r")), handler: strategies::index },
    Route { path: "/strategies/preview", methods: &["POST"], need: Some(("strategy", "r")), handler: strategies::preview_post },
    Route { path: "/strategies/confirm", methods: &["POST"], need: Some(("strategy", "r")), handler: strategies::confirm },
    Route { path: "/strategies/toggle", methods: &["POST"], need: Some(("strategy", "r")), handler: strategies::toggle },
    Route { path: "/strategies/restore", methods: &["POST"], need: Some(("strategy", "r")), handler: strategies::restore },
    Route { path: "/strategies/assign", methods: &["POST"], need: Some(("strategy", "r")), handler: strategies::assign },
    Route { path: "/address-books", methods: &["GET"], need: Some(("address_book", "r")), handler: address_books::index },
    Route { path: "/address-books/act", methods: &["POST"], need: Some(("address_book", "r")), handler: address_books::act },
    Route { path: "/groups", methods: &["GET"], need: Some(("group", "r")), handler: groups::index },
    Route { path: "/groups/save", methods: &["POST"], need: Some(("group", "r")), handler: groups::save },
    Route { path: "/groups/act", methods: &["POST"], need: Some(("group", "r")), handler: groups::act },
    Route { path: "/users", methods: &["GET"], need: Some(("user", "r")), handler: users::index },
    Route { path: "/users/save", methods: &["POST"], need: Some(("user", "r")), handler: users::save },
    Route { path: "/users/act", methods: &["POST"], need: Some(("user", "r")), handler: users::act },
    Route { path: "/users/assign", methods: &["POST"], need: Some(("user", "r")), handler: users::assign },
    Route { path: "/users/:id", methods: &["GET"], need: Some(("user", "r")), handler: users::show },
    Route { path: "/", methods: &["GET"], need: None, handler: overview::index },
    Route { path: "/dashboard/stats", methods: &["GET"], need: None, handler: overview::stats_fragment },
    Route { path: "/dashboard/sessions", methods: &["GET"], need: Some(("audit", "r")), handler: overview::sessions_fragment },
    Route { path: "/dashboard/disconnect", methods: &["POST"], need: Some(("audit", "r")), handler: overview::disconnect },
    Route { path: "/webclient", methods: &["GET"], need: None, handler: webclient::show },
    Route { path: "/webclient/devices", methods: &["GET"], need: None, handler: webclient::devices },
    Route { path: "/webclient/credential", methods: &["POST"], need: None, handler: webclient::credential },
    Route { path: "/settings", methods: &["GET"], need: Some(("setting", "r")), handler: settings::index },
    Route { path: "/settings/mail-test", methods: &["POST"], need: Some(("setting", "r")), handler: mailtest::send },
    Route { path: "/settings/save", methods: &["POST"], need: Some(("setting", "r")), handler: settings::save },
    Route { path: "/settings/relay", methods: &["POST"], need: Some(("setting", "r")), handler: settings::relay },
    Route { path: "/settings/snooze", methods: &["POST"], need: Some(("setting", "r")), handler: settings::snooze },
    Route { path: "/settings/prune", methods: &["POST"], need: Some(("setting", "r")), handler: backups::prune },
    Route { path: "/settings/backups/run", methods: &["POST"], need: Some(("setting", "r")), handler: backups::run },
    Route { path: "/settings/backups/save", methods: &["POST"], need: Some(("setting", "r")), handler: backups::save },
    Route { path: "/settings/backups/delete", methods: &["POST"], need: Some(("setting", "r")), handler: backups::delete },
    Route { path: "/settings/backups/restore", methods: &["POST"], need: Some(("setting", "r")), handler: backups::restore },
    Route { path: "/settings/backups/test", methods: &["POST"], need: Some(("setting", "r")), handler: backups::test },
    Route { path: "/settings/backups/upload", methods: &["POST"], need: Some(("setting", "r")), handler: backups::upload },
    Route { path: "/settings/backups/download", methods: &["GET"], need: Some(("setting", "rw")), handler: backups::download },
    Route { path: "/settings/backups/:name", methods: &["GET"], need: Some(("setting", "rw")), handler: backups::download_by_path },
    Route { path: "/diagnostics", methods: &["GET"], need: Some(("setting", "r")), handler: diagnostics::index },
    Route { path: "/diagnostics/export", methods: &["GET"], need: Some(("setting", "r")), handler: diagnostics::export },
    Route { path: "/roles", methods: &["GET"], need: None, handler: roles::index },
    Route { path: "/roles/save", methods: &["POST"], need: None, handler: roles::save },
    Route { path: "/roles/delete", methods: &["POST"], need: None, handler: roles::delete },
    Route { path: "/invitations", methods: &["GET"], need: Some(("user", "rw")), handler: invitations::to_users },
    Route { path: "/users/invitations", methods: &["POST"], need: Some(("user", "r")), handler: invitations::post },
    Route { path: "/account/two-factor", methods: &["GET", "POST"], need: None, handler: twofactor::page },
    Route { path: "/api-tokens", methods: &["GET", "POST"], need: Some(("token", "r")), handler: api_tokens::index },
    Route { path: "/api-tokens/revoke", methods: &["POST"], need: Some(("token", "r")), handler: api_tokens::revoke },
    Route { path: "/client-downloads", methods: &["GET"], need: Some(("setting", "r")), handler: unavailable::client_downloads },
    Route { path: "/setup", methods: &["GET"], need: Some(("setting", "r")), handler: unavailable::setup },
    Route { path: "/account", methods: &["GET"], need: None, handler: account::show },
    Route { path: "/account/profile", methods: &["POST"], need: None, handler: account::save_profile },
    Route { path: "/account/password", methods: &["POST"], need: None, handler: account::update_password },
    Route { path: "/account/theme", methods: &["POST"], need: None, handler: account::theme },
];

/// The pages' routes and `/assets/*`. Merge with the API router; `php` (the field) is the optional upstream fallback for what is not served here.
pub fn routes(n: Arc<Native>, php: Option<Router>) -> Result<Router, String> {
    routes_with(n, php, websession::OwnConfig::from_env())
}

/// `routes` with phase 8's switches given (tests).
pub fn routes_with(n: Arc<Native>, php: Option<Router>, own: websession::OwnConfig) -> Result<Router, String> {
    let store = crate::cache::Store::from_env()?;
    // phase 8's table (additive; the previous console never reads it)
    websession::migrate(&n.db.lock().unwrap_or_else(|e| e.into_inner()))?;
    let pages = Arc::new(Pages {
        own,
        session: session::SessionConfig::from_env(&n.signin.app_name),
        view: view::View::from_env()?,
        store,
        config: PageConfig::from_env(),
        php,
        n,
    });
    let mut r: Router<Arc<Pages>> = Router::new();
    for (i, route) in ROUTES.iter().enumerate() {
        r = r.route(route.path, any(move |s: State<Arc<Pages>>, c: ConnectInfo<SocketAddr>, req: Request<Body>| serve(s, c, req, i)));
    }
    r = r.route("/health/live", any(health_live));
    r = r.route("/health/ready", any(health_ready));
    r = r.route("/up", any(health_up));
    // Client downloads are not ported (none at HTE): their public pages and Laravel's signed local-disk URLs answer 404 here
    r = r.route("/downloads", any(not_found));
    r = r.route("/downloads/*rest", any(not_found));
    r = r.route("/storage/*rest", any(not_found));
    r = login::routes(r);
    r = r.route("/assets/*path", any(asset));
    r = r.route("/rdclient/*path", any(rdclient));
    // The previous console's `public/robots.txt` and its empty `public/favicon.ico`, the two files its web server served beside /assets (phase 9)
    r = r.route("/robots.txt", any(robots));
    r = r.route("/favicon.ico", any(favicon));
    Ok(r.with_state(pages))
}

/// A row as JSON for a template: the previous console's values (INTEGER -> int, TEXT -> string, NULL -> null).
pub fn row_json(r: &Row) -> Value {
    let mut m = Map::new();
    for (k, v) in &r.0 {
        m.insert(k.clone(), val_json(v));
    }
    Value::Object(m)
}

pub fn val_json(v: &Val) -> Value {
    match v {
        Val::Null => Value::Null,
        Val::Bool(b) => json!(b),
        Val::Int(i) => json!(i),
        Val::Float(f) => json!(f),
        Val::Str(s) => json!(String::from_utf8_lossy(s)),
        Val::Arr(_) => Value::Null,
    }
}

#[derive(Serialize)]
pub struct Nothing {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn php_version_compare() {
        assert_eq!(version_compare("1.15.0", "1.15.0"), 0);
        assert_eq!(version_compare("1.16.0", "1.15.0-hte.1"), 1);
        assert_eq!(version_compare("1.14.0", "1.15.0"), -1);
        assert_eq!(version_compare("1.15.0-hte.1", "1.15.0-hte.1"), 0);
        // an unknown suffix sorts below the plain release, so upstream's 1.15.0 is "newer" than 1.15.0-hte.1
        assert_eq!(version_compare("1.15.0", "1.15.0-hte.1"), 1);
        assert_eq!(version_compare("1.15.0-hte.2", "1.15.0-hte.1"), 1);
        assert_eq!(version_compare("1.10.0", "1.9.9"), 1);
        assert_eq!(version_compare("1.0.0-beta1", "1.0.0-alpha"), 1);
        assert_eq!(version_compare("1.0.0rc1", "1.0.0"), -1);
    }

    #[test]
    fn cached_release_string() {
        assert_eq!(unserialize_string(br#"s:6:"1.15.1";"#), Some("1.15.1".to_string()));
        assert_eq!(unserialize_string(br#"s:0:"";"#), Some(String::new()));
        assert_eq!(unserialize_string(b"b:0;"), None);
    }

    #[test]
    fn legacy_levels() {
        assert_eq!(legacy_level("audit"), "r");
        assert_eq!(legacy_level("device"), "rw");
        assert_eq!(legacy_level("user"), "none");
    }
}
