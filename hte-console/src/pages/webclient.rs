//! The in-browser RustDesk client: the page (`WebClientPageController@show`, the previous console's view `resources/views/webclient`), its
//! prebuilt bundle (`public/rdclient/`: app.js, app.css, session.worker.js, logo.png), branded HTE Remote, and the
//! per-person credential the page asks for so a signed-in person connects without typing a password.
//!
//! The upstream bundle in `rdclient/` is never edited. What is served is a copy with a short, listed set of text
//! substitutions (`BRAND_JS`, `BRAND_CSS`), each of which must match exactly the number of times counted below: a bundle
//! that changes under us fails the test instead of being half-branded. The source maps are not served (the served files
//! differ from them) and their `sourceMappingURL` lines are dropped.
//!
//! The list and the password: the bundle has no list of computers (it takes an ID), so `assets/js/hte-webclient.js` adds
//! one above the ID field, filled from `GET /webclient/devices` (the computers the person may reach now). The desktop client
//! gets the password from the person's own "HTE Remote" book, a copy the sweep refreshes each minute; the browser asks
//! `POST /webclient/credential`, which evaluates the reach rule on the request and answers with the computer's confirmed
//! password (the value the book copies), else nothing. Nothing is logged and the answers are not cacheable. The bundle
//! itself is not patched: the script fills the password box the bundle already reads, then presses Connect.

use super::kit::*;
use super::{Ctx, Reply, Req};
use crate::php::{Fault, Val};
use crate::sqlite::{self as db, P};
use axum::body::Body;
use axum::http::{header, HeaderMap, Response, StatusCode};
use hmac::{Hmac, Mac};
use include_dir::{include_dir, Dir};
use rusqlite::Connection;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

static BUNDLE: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/rdclient");

/// (find, replace, how many times the upstream bundle contains it)
pub const BRAND_JS: &[(&str, &str, usize)] = &[
    // the wordmark in the sign-in card and in the top bar
    ("Corten<span>Desk</span>", "HTE <span>Remote</span>", 2),
    // the logo's alt text
    (r#"alt="CortenDesk""#, r#"alt="HTE Remote""#, 1),
    // the browser tab title while connected
    (r"\u2014 CortenDesk`", r"\u2014 HTE Remote`", 1),
    // ... and in the terminal window (CortenDesk 1.18)
    (r"\xB7 CortenDesk`", r"\xB7 HTE Remote`", 1),
    // the source map is not served
    ("//# sourceMappingURL=app.js.map", "", 1),
];

/// CortenDesk's rust orange becomes HTE blue (the tokens of `css/hte-brand.css`): the accents, the gradient's highlight and the logo's glow.
pub const BRAND_CSS: &[(&str, &str, usize)] = &[
    ("#e2652e", "#0a66e8", 1),
    ("#d35a24", "#0a66e8", 1),
    ("#c9531f", "#0854c0", 4),
    ("#b74a1a", "#0854c0", 1),
    ("#e77e42", "#3b8dff", 5),
    ("rgba(201,83,31,", "rgba(10,102,232,", 1),
    ("/*# sourceMappingURL=app.css.map */", "", 1),
];

pub const BRAND_WORKER: &[(&str, &str, usize)] = &[("//# sourceMappingURL=session.worker.js.map", "", 1)];

fn apply(src: &str, table: &[(&str, &str, usize)]) -> Result<String, String> {
    let mut out = src.to_string();
    for (find, with, want) in table {
        let n = out.matches(find).count();
        if n != *want {
            return Err(format!("the bundle has {n} of {find:?}, expected {want}: the upstream client changed; update the substitutions"));
        }
        out = out.replace(find, with);
    }
    Ok(out)
}

struct Served {
    body: Vec<u8>,
    ctype: &'static str,
    etag: String,
}

fn served(body: Vec<u8>, ctype: &'static str) -> Served {
    let mut h = Sha256::new();
    h.update(&body);
    let etag = format!("\"{}\"", hex::encode(&h.finalize()[..12]));
    Served { body, ctype, etag }
}

fn file(name: &str) -> &'static str {
    std::str::from_utf8(BUNDLE.get_file(name).unwrap_or_else(|| panic!("rdclient/{name} is not embedded")).contents()).expect("the bundle is UTF-8")
}

struct Files {
    app_js: Served,
    app_css: Served,
    worker: Served,
    logo: Served,
}

fn files() -> &'static Files {
    static F: OnceLock<Files> = OnceLock::new();
    F.get_or_init(|| {
        // a bundle the substitutions do not fit is a build fault, caught by the test; at run time fall back to the unmodified text
        let app_js = apply(file("app.js"), BRAND_JS).unwrap_or_else(|e| {
            tracing::error!("webclient: {e}");
            file("app.js").to_string()
        });
        let app_css = apply(file("app.css"), BRAND_CSS).unwrap_or_else(|e| {
            tracing::error!("webclient: {e}");
            file("app.css").to_string()
        });
        let worker = apply(file("session.worker.js"), BRAND_WORKER).unwrap_or_else(|_| file("session.worker.js").to_string());
        let logo = super::assets::find("images/hte-remote.png").expect("the HTE Remote logo is embedded").to_vec();
        Files {
            app_js: served(app_js.into_bytes(), "text/javascript; charset=utf-8"),
            app_css: served(app_css.into_bytes(), "text/css; charset=utf-8"),
            worker: served(worker.into_bytes(), "text/javascript; charset=utf-8"),
            logo: served(logo, "image/png"),
        }
    })
}

/// The cache-bust value the page puts after `?v=` (the previous console: the bundle's mtime): the served script's own hash.
pub fn version() -> String {
    files().app_js.etag.trim_matches('"')[..10].to_string()
}

/// `/rdclient/<name>`: public static files, as the previous console's web server served them. `?v=` makes them cacheable for a year; without it they revalidate.
pub fn respond(name: &str, query: Option<&str>, headers: &HeaderMap, head: bool) -> Response<Body> {
    let f = files();
    let s = match name {
        "app.js" => &f.app_js,
        "app.css" => &f.app_css,
        "session.worker.js" => &f.worker,
        "logo.png" => &f.logo,
        _ => return Response::builder().status(StatusCode::NOT_FOUND).header(header::CONTENT_TYPE, "text/plain").body(Body::from("Not Found")).unwrap(),
    };
    let versioned = query.map_or(false, |q| q.split('&').any(|p| p.starts_with("v=") && p.len() > 2));
    let cache = if versioned { "public, max-age=31536000, immutable" } else { "no-cache" };
    let fresh = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map_or(false, |v| v.split(',').any(|t| t.trim().trim_start_matches("W/") == s.etag));
    let b = Response::builder().header(header::ETAG, &s.etag).header(header::CACHE_CONTROL, cache).header("x-content-type-options", "nosniff");
    if fresh {
        return b.status(StatusCode::NOT_MODIFIED).body(Body::empty()).unwrap();
    }
    b.status(StatusCode::OK)
        .header(header::CONTENT_TYPE, s.ctype)
        .header(header::CONTENT_LENGTH, s.body.len())
        .body(if head { Body::empty() } else { Body::from(s.body.clone()) })
        .unwrap()
}

// ----------------------------------------------------------------------------------------------------- the page ---

fn env(name: &str) -> String {
    crate::envvar::var(name).unwrap_or_default().trim().to_string()
}

/// `WebClientPageController::wsBase`: `ws(s)://host[:port]` from APP_URL (the previous console's default `http://localhost`), the request's own address when APP_URL has no host.
fn ws_base(headers: &HeaderMap) -> String {
    let app_url = crate::envvar::var("APP_URL").unwrap_or_else(|_| "http://localhost".into());
    let host_of = |u: &str| -> Option<(bool, String, Option<u16>)> {
        let (scheme, rest) = u.split_once("://")?;
        let auth = rest.split(['/', '?', '#']).next().unwrap_or("");
        let auth = auth.rsplit('@').next().unwrap_or("");
        let (host, port) = if auth.starts_with('[') {
            match auth.find(']') {
                Some(i) => (auth[..=i].to_string(), auth[i + 1..].strip_prefix(':').and_then(|p| p.parse::<u16>().ok())),
                None => (auth.to_string(), None),
            }
        } else {
            match auth.rsplit_once(':') {
                Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => (h.to_string(), p.parse::<u16>().ok()),
                _ => (auth.to_string(), None),
            }
        };
        if host.is_empty() {
            return None;
        }
        Some((scheme.eq_ignore_ascii_case("https"), host, port))
    };
    let parsed = host_of(app_url.trim()).or_else(|| {
        let host = headers.get(header::HOST).and_then(|v| v.to_str().ok())?;
        let https = headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok()).map_or(false, |p| p.eq_ignore_ascii_case("https"));
        host_of(&format!("{}://{host}", if https { "https" } else { "http" }))
    });
    let Some((secure, host, port)) = parsed else { return String::new() };
    let port = port.filter(|p| *p != if secure { 443 } else { 80 });
    format!("{}://{host}{}", if secure { "wss" } else { "ws" }, port.map(|p| format!(":{p}")).unwrap_or_default())
}

/// `ServerLink::webTicket`: the page's ticket for the ID server (`cdw1.<expiry>.web-<id>.<hmac>`), empty while the link is off.
fn web_ticket(user_id: i64, now: i64) -> String {
    let secret = crate::link::server_secret();
    if secret.is_empty() {
        return String::new();
    }
    let signed = format!("cdw1.{}.web-{user_id}", now + 12 * 3600);
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).expect("hmac takes any key length");
    m.update(signed.as_bytes());
    format!("{signed}.{}", hex::encode(m.finalize().into_bytes()))
}

fn server_key(c: &Connection) -> Result<String, Fault> {
    let saved = String::from_utf8_lossy(&db::setting(c, "public_key", "")?).trim().to_string();
    if !saved.is_empty() {
        return Ok(saved);
    }
    Ok(["HTE_CONSOLE_PUBLIC_KEY", "HTE_REMOTE_PUBLIC_KEY"].iter().map(|e| env(e)).find(|v| !v.is_empty()).unwrap_or_default())
}

/// RustDesk 1.5 WebRTC for the page: `null` while Settings > Server has "Web client uses WebRTC" off (HTE Remote's default), else the
/// ICE servers the browser should use (`""` = the browser client's built-in public STUN servers). A direct WebRTC session goes
/// from the browser to the device without the relay; the ID server still carries the offer, and the device still asks for the
/// password, which `credential` gives only for a computer in the person's reach.
fn webrtc(c: &Connection) -> Result<Value, Fault> {
    if !super::settings::webrtc_on(c)? {
        return Ok(Value::Null);
    }
    let saved = String::from_utf8_lossy(&db::setting(c, "webclient_ice_servers", "")?).into_owned();
    Ok(json!({"iceServers": crate::ice::normalize(&saved).unwrap_or_default()}))
}

/// GET /webclient[?id=...]
pub fn show(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let (mut ws_id, mut ws_relay) = (env("HTE_REMOTE_WS_ID_URL"), env("HTE_REMOTE_WS_RELAY_URL"));
    if ws_id.is_empty() || ws_relay.is_empty() {
        let base = ws_base(&req.headers);
        if ws_id.is_empty() && !base.is_empty() {
            ws_id = format!("{base}/ws/id");
        }
        if ws_relay.is_empty() && !base.is_empty() {
            ws_relay = format!("{base}/ws/relay");
        }
    }
    let user_id = ctx.uid();
    let name = String::from_utf8_lossy(&ctx.user.val("name").to_php_string().unwrap_or_default()).into_owned();
    let username = String::from_utf8_lossy(&ctx.user.val("username").to_php_string().unwrap_or_default()).into_owned();
    let my_name = if !name.is_empty() && name != "0" {
        name
    } else if !username.is_empty() && username != "0" {
        username
    } else {
        "HTE Remote".to_string()
    };
    let peer = q(req, "id");
    let v = version();
    let config = json!({
        "peerId": peer,
        "serverKeyB64": server_key(c)?,
        "wsIdUrl": ws_id,
        "wsRelayUrl": ws_relay,
        "myId": format!("web-{user_id}"),
        "myName": my_name,
        "signalToken": web_ticket(user_id, ctx.now),
        "version": ctx.p.n.api_version,
        "webrtc": webrtc(c)?,
        "workerUrl": format!("/rdclient/session.worker.js?v={v}"),
        // HTE: where the page asks for the person's own password for a computer, and the token that call needs
        "hteCredentialUrl": "/webclient/credential",
        "hteDevicesUrl": "/webclient/devices",
        "hteCsrf": ctx.session.token().unwrap_or(""),
    });
    let theme = ctx.theme();
    // `?mode=terminal` is the bundle's terminal page (the Terminal action in the device list): same sign-in, same password rule
    let what = if q(req, "mode") == "terminal" { "HTE Remote Terminal" } else { "HTE Remote Web Client" };
    let title = if peer.is_empty() { what.to_string() } else { format!("{peer} — {what}") };
    Ok(Reply::Html(
        200,
        ctx.render(
            "webclient.html",
            Value::Null,
            json!({"title": title, "theme": theme, "version": v, "app_version": ctx.p.n.api_version, "config": config.to_string()}),
        )?,
    ))
}

// ------------------------------------------------------------------------------------------------ the password ---

/// GET /webclient/devices: the computers the signed-in person may reach right now (the reach rule, evaluated on every call:
/// the same set and order `/api/peers` gives the desktop client), for the list the page shows. Not cacheable.
pub fn devices(ctx: &Ctx, c: &Connection, _: &Req) -> Result<Reply, Fault> {
    let window = online_window(c)?;
    let rows = crate::reach::visible_devices(c, &ctx.user, None, "rustdesk_id")?;
    let list: Vec<Value> = rows
        .iter()
        .map(|d| {
            let (alias, host) = (s(d, "alias"), s(d, "hostname"));
            let name = if truthy(&alias) { alias } else { host };
            json!({"id": s(d, "rustdesk_id"), "name": name, "os": s(d, "os"), "user": s(d, "username"), "online": is_online(d, ctx.now, window)})
        })
        .collect();
    Ok(Reply::Json(200, json!({"devices": list}).to_string()))
}

/// POST /webclient/credential {id}: `{"password": "..."}` for any computer the signed-in person may reach NOW (the reach rule,
/// evaluated on this request), else 404 `{}`; a computer outside their reach never gets a password. The password is the
/// computer's confirmed one (`hte_device_passwords.confirmed_enc`), the value the sweep copies into the person's book for the
/// desktop client; a computer on stock RustDesk, or whose new password is not confirmed yet, has none and answers 404 too.
pub fn credential(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let none = || Ok(Reply::Json(404, "{}".into()));
    let id = super::kit::Body::of(req).get("id");
    let id = id.trim().to_string();
    if id.is_empty() || id.len() > 64 {
        return none();
    }
    let mut w = visible(c, &ctx.user, false)?;
    w.add(r#""devices"."rustdesk_id" = ?"#, vec![P(Val::str(&id))]);
    if count(c, &format!(r#"select count(*) as aggregate from "devices"{}"#, w.sql()), &w.params.clone())? == 0 {
        return none();
    }
    let Some(row) = db::first(c, r#"select "confirmed_enc" from "hte_device_passwords" where "rustdesk_id" = ? limit 1"#, &[P(Val::str(&id))])? else { return none() };
    let enc = row.val("confirmed_enc");
    if !enc.to_bool() {
        return none();
    }
    let Ok(plain) = ctx.p.n.crypt.decrypt_string(&enc.to_php_string()?) else { return none() };
    Ok(Reply::Json(200, json!({"password": String::from_utf8_lossy(&plain)}).to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bundle_takes_the_branding_exactly() {
        let js = apply(file("app.js"), BRAND_JS).unwrap();
        assert!(!js.contains("CortenDesk") && !js.contains("Corten<span>"), "a CortenDesk string is left on screen");
        assert_eq!(js.matches("HTE <span>Remote</span>").count(), 2);
        assert!(!js.contains("sourceMappingURL"));
        let css = apply(file("app.css"), BRAND_CSS).unwrap();
        for orange in ["#e2652e", "#d35a24", "#c9531f", "#b74a1a", "#e77e42", "201,83,31"] {
            assert!(!css.contains(orange), "{orange}");
        }
        assert!(apply(file("session.worker.js"), BRAND_WORKER).is_ok());
        // a different bundle is refused, not half-branded
        assert!(apply("nothing to brand", BRAND_JS).is_err());
    }

    #[test]
    fn what_is_served_is_a_copy() {
        // the originals keep their upstream text
        assert!(file("app.js").contains("Corten<span>Desk</span>"));
        let f = files();
        assert!(!String::from_utf8_lossy(&f.app_js.body).contains("CortenDesk"));
        assert_eq!(f.logo.body, super::super::assets::find("images/hte-remote.png").unwrap());
    }

    #[test]
    fn static_files_carry_types_etag_and_cache_rules() {
        let h = HeaderMap::new();
        let r = respond("app.js", Some("v=abc"), &h, false);
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers()[header::CONTENT_TYPE], "text/javascript; charset=utf-8");
        assert_eq!(r.headers()[header::CACHE_CONTROL], "public, max-age=31536000, immutable");
        let etag = r.headers()[header::ETAG].to_str().unwrap().to_string();
        assert_eq!(respond("app.css", None, &h, false).headers()[header::CACHE_CONTROL], "no-cache");
        assert_eq!(respond("app.css", None, &h, false).headers()[header::CONTENT_TYPE], "text/css; charset=utf-8");
        assert_eq!(respond("logo.png", None, &h, false).headers()[header::CONTENT_TYPE], "image/png");
        let mut inm = HeaderMap::new();
        inm.insert(header::IF_NONE_MATCH, etag.parse().unwrap());
        assert_eq!(respond("app.js", None, &inm, false).status(), 304);
        assert_eq!(respond("app.js.map", None, &h, false).status(), 404);
        assert_eq!(respond("../Cargo.toml", None, &h, false).status(), 404);
        assert_eq!(respond("app.js", None, &h, true).status(), 200);
    }

    #[test]
    fn the_websocket_base_follows_app_url() {
        let h = HeaderMap::new();
        std::env::set_var("APP_URL", "https://rustdesk.example.test");
        assert_eq!(ws_base(&h), "wss://rustdesk.example.test");
        std::env::set_var("APP_URL", "http://10.0.0.5:8080");
        assert_eq!(ws_base(&h), "ws://10.0.0.5:8080");
        std::env::set_var("APP_URL", "https://x.test:443");
        assert_eq!(ws_base(&h), "wss://x.test");
        std::env::remove_var("APP_URL");
    }
}
