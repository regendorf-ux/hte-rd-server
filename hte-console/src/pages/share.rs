//! Share links (CortenDesk 1.21.0, HTE guardrails): a secret link that opens the web client for ONE device, for someone without a
//! console account. HTE's rules, in the order they are enforced:
//!   * off until Settings > Server turns it on AND `HTE_REMOTE_SHARE_LINKS` is set (`enabled`)
//!   * only a signed-in person who may reach the device under the reach rule makes a link for it; administrators only unless
//!     Settings says "anyone who may edit that device" (`may_create`)
//!   * the link's ticket (`cdw2`) is bound to the device, signed, and judged by hbbs against the console's list of LIVE links
//!     (`live_policy`): ending a link, its expiry, its creator losing reach, or the switch going off all end it at the ID server
//!     within one policy pull, whatever the page still says. hbbs also refuses it unless the server admits approved devices only.
//!   * the viewer sends no password, so the device's own accept window decides each time (nothing here ever hands out a password)
//! The link is `/s#<token>`; the fragment never reaches a server, the page posts it to `/s/start`. Only its sha256 is stored.

use super::kit::{abort, audit, truthy, Body as Form};
use super::*;
use crate::reach;
use axum::body::to_bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, Method};
use axum::routing::any;
use sha2::{Digest, Sha256};

pub const SCHEMA: &str = r#"create table if not exists "device_shares" ("id" integer primary key autoincrement not null, "device_id" integer not null, "user_id" integer not null, "label" varchar not null, "token_hash" varchar not null, "max_viewers" integer not null default '1', "expires_at" datetime not null, "revoked_at" datetime, "last_used_at" datetime, "created_at" datetime, "updated_at" datetime);
create unique index if not exists "device_shares_token_hash_unique" on "device_shares" ("token_hash");
create index if not exists "device_shares_device_id_index" on "device_shares" ("device_id");
create table if not exists "device_share_sessions" ("id" integer primary key autoincrement not null, "device_share_id" integer not null, "key_hash" varchar not null, "ip" varchar, "user_agent" varchar, "started_at" datetime not null, "last_seen_at" datetime not null, "ended_at" datetime);
create unique index if not exists "device_share_sessions_key_hash_unique" on "device_share_sessions" ("key_hash");
create index if not exists "device_share_sessions_share_index" on "device_share_sessions" ("device_share_id", "ended_at");"#;

/// How long a link may live: key, minutes, label.
pub const DURATIONS: [(&str, i64, &str); 5] = [("15m", 15, "15 minutes"), ("1h", 60, "1 hour"), ("8h", 480, "8 hours"), ("24h", 1440, "24 hours"), ("7d", 10080, "7 days")];
pub const MAX_VIEWERS: i64 = 10;
/// A ticket for hbbs lives this long (and never past the link); the open page asks for a fresh one with each ping.
const TICKET_TTL: i64 = 300;
const PING_SECONDS: i64 = 30;
/// A viewer counts while its last ping is younger than this.
const LIVE_SECONDS: i64 = 90;

fn text(r: &Row, k: &str) -> String {
    String::from_utf8_lossy(&r.val(k).to_php_string().unwrap_or_default()).into_owned()
}

fn sha(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// Setting off (the default), or the environment switch missing: no link works, none can be made.
pub fn enabled(c: &Connection) -> Result<bool, Fault> {
    let env = crate::envvar::var("HTE_REMOTE_SHARE_LINKS").unwrap_or_default();
    let env_on = matches!(env.trim().to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes");
    Ok(env_on && db::setting(c, "hte_share_links", "0")? == b"1")
}

pub fn env_on() -> bool {
    matches!(crate::envvar::var("HTE_REMOTE_SHARE_LINKS").unwrap_or_default().trim().to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes")
}

/// Settings > Server "Who may make share links": administrators only (the default) or anyone who may edit the device.
fn anyone_with_reach(c: &Connection) -> Result<bool, Fault> {
    Ok(db::setting(c, "hte_share_who", "admin")? == b"reach")
}

/// May `user` make links for `device` (a `devices` row)? Signed-in, active, allowed by Settings, and the device is one the reach rule
/// gives them: administrators reach everything, anyone else only what the console shows them.
fn may_create(c: &Connection, user: &Row, device: &Row) -> Result<bool, Fault> {
    if !user.val("is_active").to_bool() || device.val("status") != Val::str("active") || !device.is_null("deleted_at") {
        return Ok(false);
    }
    let admin = user.val("is_admin").to_bool();
    if !admin && !(anyone_with_reach(c)? && crate::admin::console_allows(c, user, "device", "rw")?) {
        return Ok(false);
    }
    if admin {
        return Ok(true);
    }
    let rid = text(device, "rustdesk_id");
    Ok(reach::visible_devices(c, user, None, "rustdesk_id")?.iter().any(|d| text(d, "rustdesk_id") == rid))
}

/// A link is live while it is not ended, not expired, its device is still there and approved, and its creator may still make it.
fn live(c: &Connection, share: &Row, now: i64) -> Result<Option<Row>, Fault> {
    if !share.is_null("revoked_at") || crate::laravel::parse_ts(&share.val("expires_at")).map_or(true, |e| e <= now) {
        return Ok(None);
    }
    let Some(device) = db::first(c, r#"select * from "devices" where "id" = ? limit 1"#, &[P(share.val("device_id"))])? else { return Ok(None) };
    let Some(user) = db::first(c, r#"select * from "users" where "id" = ? limit 1"#, &[P(share.val("user_id"))])? else { return Ok(None) };
    Ok(if may_create(c, &user, &device)? { Some(device) } else { None })
}

/// What hbbs gets in `scope.shares`: every live link, by id, with its one device and expiry. `None` when there are none (or the
/// feature is off), so the policy is byte-for-byte what it was before this feature.
pub fn live_policy(c: &Connection, now: i64) -> Result<Option<String>, Fault> {
    if !enabled(c)? {
        return Ok(None);
    }
    let mut out = serde_json::Map::new();
    for share in db::rows(c, r#"select * from "device_shares" where "revoked_at" is null and "expires_at" > ? order by "id" asc"#, &[P(Val::str(&crate::laravel::ts(now)))])? {
        if let Some(device) = live(c, &share, now)? {
            let expires = crate::laravel::parse_ts(&share.val("expires_at")).unwrap_or(0);
            out.insert(share.id().to_string(), json!({"device": text(&device, "rustdesk_id"), "expires": expires}));
        }
    }
    Ok(if out.is_empty() { None } else { Some(Value::Object(out).to_string()) })
}

/// `ServerLink::shareTicket`: bound to the link's device, signed, short-lived and never past the link's own expiry.
pub fn ticket(rustdesk_id: &str, share_id: i64, expires_at: i64, now: i64) -> String {
    super::webclient::sign_ticket(&format!("cdw2.{}.{rustdesk_id}.share-{share_id}", (now + TICKET_TTL).min(expires_at)))
}

// ------------------------------------------------------------------------------------------------ the device page ---

fn when(unix: i64, now: i64) -> String {
    super::time::ago(unix, now, false)
}

/// The "Share screen" card of the device page. `None` while the feature is off or this person may not make links for the device
/// and has none of their own to see.
pub fn card(ctx: &Ctx, c: &Connection, device: &Row) -> Result<Value, Fault> {
    if !enabled(c)? || !device.is_null("deleted_at") {
        return Ok(Value::Null);
    }
    let can_create = may_create(c, &ctx.user, device)?;
    let admin = ctx.is_admin();
    let mut sql = String::from(r#"select * from "device_shares" where "device_id" = ?"#);
    let mut params = vec![P(device.val("id"))];
    if !admin {
        sql.push_str(r#" and "user_id" = ?"#);
        params.push(P(Val::Int(ctx.uid())));
    }
    sql.push_str(r#" order by case when "revoked_at" is null and "expires_at" > ? then 0 else 1 end, "id" desc limit 20"#);
    params.push(P(Val::str(&crate::laravel::ts(ctx.now))));
    let rows = db::rows(c, &sql, &params)?;
    if !can_create && rows.is_empty() {
        return Ok(Value::Null);
    }
    let mut items = vec![];
    for r in &rows {
        let expires = crate::laravel::parse_ts(&r.val("expires_at")).unwrap_or(0);
        let state = if !r.is_null("revoked_at") { "ended" } else if expires <= ctx.now { "expired" } else { "active" };
        let watching: i64 = db::first(
            c,
            r#"select count(*) as n from "device_share_sessions" where "device_share_id" = ? and "ended_at" is null and "last_seen_at" > ?"#,
            &[P(r.val("id")), P(Val::str(&crate::laravel::ts(ctx.now - LIVE_SECONDS)))],
        )?
        .map(|x| x.val("n").to_int())
        .unwrap_or(0);
        let maker = db::first(c, r#"select "name", "username" from "users" where "id" = ? limit 1"#, &[P(r.val("user_id"))])?
            .map(|u| if text(&u, "name").is_empty() { text(&u, "username") } else { text(&u, "name") })
            .unwrap_or_default();
        let max = r.val("max_viewers").to_int();
        items.push(json!({
            "id": r.id(), "label": text(r, "label"), "state": state, "watching": watching, "max": max,
            "expires": if state == "active" { format!("Expires {}", when(expires, ctx.now).replace(" ago", "").replacen("in ", "in ", 1)) } else { String::new() },
            "expires_at": expires,
            "last_used": if r.is_null("last_used_at") { "Not used yet".to_string() } else { format!("Last used {}", when(crate::laravel::parse_ts(&r.val("last_used_at")).unwrap_or(0), ctx.now)) },
            "maker": maker, "can_end": state == "active" && (admin || r.val("user_id").to_int() == ctx.uid()),
        }));
    }
    let new_link = ctx.flashed.get("share_link").and_then(|v| v.as_str()).unwrap_or("").to_string();
    Ok(json!({
        "items": items, "can_create": can_create, "admin_only": !anyone_with_reach(c)?,
        "new_link": new_link, "error": ctx.flashed.get("share_error").and_then(|v| v.as_str()).unwrap_or(""),
        "form": ctx.flashed.get("share_form").cloned().unwrap_or(Value::Null),
        "durations": DURATIONS.iter().map(|(k, _, l)| json!({"key": k, "label": l})).collect::<Vec<_>>(), "max_viewers": MAX_VIEWERS,
    }))
}

/// `do=share-create` on the device page: the link is shown once, in the page that follows.
pub fn create(ctx: &Ctx, c: &Connection, device: &Row, body: &Form, url: &str) -> Result<Reply, Fault> {
    let back = |msg: &str| {
        ctx.flash("share_error", Value::String(msg.to_string()));
        ctx.flash("share_form", json!({"label": body.get("label"), "duration": body.get("duration"), "viewers": body.get("viewers")}));
        Reply::Redirect(format!("{url}?tab=details#share"))
    };
    if !enabled(c)? {
        return Ok(abort(404));
    }
    if !may_create(c, &ctx.user, device)? {
        return Ok(abort(403));
    }
    let label = body.get("label").trim().to_string();
    let Some((key, minutes, _)) = DURATIONS.iter().find(|(k, _, _)| *k == body.get("duration")) else { return Ok(back("Pick how long the link is valid.")) };
    let viewers = body.int("viewers");
    if label.is_empty() {
        return Ok(back("Say who the link is for."));
    }
    if label.chars().count() > 100 {
        return Ok(back("The label may not be longer than 100 characters."));
    }
    if !(1..=MAX_VIEWERS).contains(&viewers) {
        return Ok(back(&format!("Viewers at the same time must be between 1 and {MAX_VIEWERS}.")));
    }
    let mut raw = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut raw);
    let token = hex::encode(raw);
    let rid = text(device, "rustdesk_id");
    db::insert(
        c,
        "device_shares",
        vec![
            ("device_id", device.val("id")),
            ("user_id", Val::Int(ctx.uid())),
            ("label", Val::str(&label)),
            ("token_hash", Val::str(&sha(&token))),
            ("max_viewers", Val::Int(viewers)),
            ("expires_at", Val::str(&crate::laravel::ts(ctx.now + minutes * 60))),
        ],
        &crate::laravel::ts(ctx.now),
    )?;
    audit(ctx, c, "device.share.create", &format!("Created share link \"{label}\" for device {rid} (up to {viewers} at a time, {key})"), Some("device"), Some(&rid))?;
    ctx.flash("share_link", Value::String(format!("{}/s#{token}", ctx.root.trim_end_matches('/'))));
    Ok(Reply::Redirect(format!("{url}?tab=details#share")))
}

/// `do=share-end`: the creator or an administrator. Takes effect at the ID server on its next policy pull (a few seconds).
pub fn end(ctx: &Ctx, c: &Connection, device: &Row, body: &Form, url: &str) -> Result<Reply, Fault> {
    let Some(share) = db::first(c, r#"select * from "device_shares" where "id" = ? and "device_id" = ? limit 1"#, &[P(Val::Int(body.int("share"))), P(device.val("id"))])? else { return Ok(abort(404)) };
    if !ctx.is_admin() && share.val("user_id").to_int() != ctx.uid() {
        return Ok(abort(404));
    }
    if share.is_null("revoked_at") {
        let now = crate::laravel::ts(ctx.now);
        db::exec(c, r#"update "device_shares" set "revoked_at" = ?, "updated_at" = ? where "id" = ?"#, &[P(Val::str(&now)), P(Val::str(&now)), P(share.val("id"))])?;
        db::exec(c, r#"update "device_share_sessions" set "ended_at" = ? where "device_share_id" = ? and "ended_at" is null"#, &[P(Val::str(&now)), P(share.val("id"))])?;
        let rid = text(device, "rustdesk_id");
        audit(ctx, c, "device.share.revoke", &format!("Ended share link \"{}\" for device {rid}", text(&share, "label")), Some("device"), Some(&rid))?;
    }
    Ok(Reply::Redirect(format!("{url}?tab=details#share")))
}

// ---------------------------------------------------------------------------------------------- the public pages ---

const PAGE: &str = r##"<!DOCTYPE html>
<html lang="en" data-bs-theme="dark" data-rd-theme-pref="dark">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
    <meta name="referrer" content="no-referrer">
    <meta name="robots" content="noindex, nofollow">
    <title>Shared screen — HTE Remote</title>
    <link rel="shortcut icon" type="image/png" href="/assets/images/hte-remote.png">
    <link rel="stylesheet" href="/assets/vendor/remixicon/remixicon.css">
    <link rel="stylesheet" href="/rdclient/app.css?v=@V@">
    <style>
        html, body { height: 100%; margin: 0; overflow: hidden; background: #000; }
        #rd-root { height: 100vh; height: 100dvh; }
        #cd-share-error { display: none; position: fixed; inset: 0; align-items: center; justify-content: center;
            color: #e8e8e8; font: 16px/1.5 system-ui, sans-serif; text-align: center; padding: 24px; }
        #cd-share-error.on { display: flex; }
        #cd-share-error img { display: block; margin: 0 auto 16px; }
    </style>
</head>
<body>
    <div id="cd-share-error" role="alert">
        <div>
            <img src="/assets/images/hte-remote.png" alt="" width="48" height="48">
            <p id="cd-share-error-text">This share link is not valid, has expired, or was ended by its owner.</p>
        </div>
    </div>
    <div id="rd-root">
        <div id="rd-toolbar"></div>
        <div id="rd-viewport">
            <canvas id="rd-canvas"></canvas>
            <div id="rd-stats"></div>
            <div id="rd-overlay"></div>
        </div>
    </div>
    <script>
        (function () {
            var token = (location.hash || '').replace(/^#/, '');
            var fail = function (message) {
                if (message) document.getElementById('cd-share-error-text').textContent = message;
                document.getElementById('rd-root').style.display = 'none';
                document.getElementById('cd-share-error').classList.add('on');
            };
            if (!/^[a-f0-9]{64}$/.test(token)) { fail(); return; }
            fetch('/s/start', {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                body: JSON.stringify({ token: token })
            }).then(function (r) {
                return r.json().catch(function () { return {}; }).then(function (body) {
                    return r.ok ? body : Promise.reject(body.error || '');
                });
            }).then(function (info) {
                var c = info.client;
                window.__RD__ = {
                    peerId: c.peerId,
                    serverKeyB64: c.serverKeyB64,
                    wsIdUrl: c.wsIdUrl,
                    wsRelayUrl: c.wsRelayUrl,
                    myId: c.myId,
                    myName: c.myName,
                    signalToken: c.signalToken || '',
                    webrtc: c.webrtc || null,
                    version: '@V@',
                    workerUrl: '/rdclient/session.worker.js?v=@V@',
                    share: {
                        token: token,
                        session: info.session,
                        label: info.label,
                        deviceName: info.device_name,
                        expiresAt: info.expires_at,
                        pingSeconds: info.ping_seconds,
                        pingUrl: '/s/ping',
                        endUrl: '/s/end',
                        csrfToken: ''
                    }
                };
                document.title = (info.device_name || info.label) + ' — HTE Remote';
                return import('/rdclient/app.js?v=@V@');
            }).catch(function (message) { fail(typeof message === 'string' ? message : ''); });
        })();
    </script>
</body>
</html>
"##;

pub fn routes(r: Router<Arc<Pages>>) -> Router<Arc<Pages>> {
    r.route("/s", any(page)).route("/s/start", any(start)).route("/s/ping", any(ping)).route("/s/end", any(end_session))
}

fn reply(status: u16, body: String, ctype: &str, extra: &[(&str, &str)]) -> Response<Body> {
    let mut b = Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header(header::CONTENT_TYPE, ctype)
        .header(header::CACHE_CONTROL, "no-store")
        .header("X-Robots-Tag", "noindex, nofollow");
    for (k, v) in extra {
        b = b.header(*k, *v);
    }
    b.body(Body::from(body)).unwrap()
}

fn refuse(status: u16, reason: &str) -> Response<Body> {
    let error = match reason {
        "link_full" => "This share link already has as many viewers as it allows. Try again later.",
        "link_ended" => "This share link has ended.",
        _ => "This share link is not valid, has expired, or was ended by its owner.",
    };
    reply(status, json!({"reason": reason, "error": error}).to_string(), "application/json", &[])
}

async fn page(State(p): State<Arc<Pages>>, req: Request<Body>) -> Response<Body> {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return error_response(405, "Method Not Allowed", false);
    }
    let on = {
        let c = p.n.db.lock().unwrap_or_else(|e| e.into_inner());
        enabled(&c).unwrap_or(false)
    };
    if !on {
        return error_response(404, "Not Found", false);
    }
    let v = crate::REMOTE_VERSION;
    reply(200, PAGE.replace("@V@", v), "text/html; charset=UTF-8", &[("Referrer-Policy", "no-referrer"), ("X-Frame-Options", "DENY")])
}

struct Hit {
    share: Row,
    device: Row,
}

/// The usable link for a token (a 64-digit hex string), or None.
fn find(c: &Connection, token: &str, now: i64) -> Result<Option<Hit>, Fault> {
    if token.len() != 64 || !token.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Ok(None);
    }
    let Some(share) = db::first(c, r#"select * from "device_shares" where "token_hash" = ? limit 1"#, &[P(Val::str(&sha(token)))])? else { return Ok(None) };
    Ok(live(c, &share, now)?.map(|device| Hit { share, device }))
}

fn live_viewers(c: &Connection, share_id: i64, now: i64) -> Result<i64, Fault> {
    Ok(db::first(
        c,
        r#"select count(*) as n from "device_share_sessions" where "device_share_id" = ? and "ended_at" is null and "last_seen_at" > ?"#,
        &[P(Val::Int(share_id)), P(Val::str(&crate::laravel::ts(now - LIVE_SECONDS)))],
    )?
    .map(|x| x.val("n").to_int())
    .unwrap_or(0))
}

async fn json_body(req: Request<Body>) -> (HeaderMap, Value) {
    let (parts, body) = req.into_parts();
    let bytes = to_bytes(body, 4096).await.unwrap_or_default();
    (parts.headers, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn arg(v: &Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

async fn start(State(p): State<Arc<Pages>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, req: Request<Body>) -> Response<Body> {
    if req.method() != Method::POST {
        return error_response(405, "Method Not Allowed", false);
    }
    let (headers, body) = json_body(req).await;
    let xff: Vec<&str> = headers.get_all("x-forwarded-for").iter().filter_map(|v| v.to_str().ok()).collect();
    let ip = laravel::client_ip(peer.ip(), &xff, &p.n.trusted);
    let ua: String = hstr(&headers, "user-agent").unwrap_or("").chars().take(250).collect();
    let (ws_id, ws_relay) = super::webclient::ws_urls(&headers);
    let now = p.n.now();
    let c = p.n.db.lock().unwrap_or_else(|e| e.into_inner());
    let out = (|| -> Result<Response<Body>, Fault> {
        if !enabled(&c)? {
            return Ok(error_response(404, "Not Found", false));
        }
        let Some(hit) = find(&c, &arg(&body, "token"), now)? else { return Ok(refuse(404, "link_invalid")) };
        let sid = hit.share.id();
        let mut raw = [0u8; 24];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut raw);
        let key = hex::encode(raw);
        let stamp = crate::laravel::ts(now);
        // write first, then count: two viewers taking the last slot at once cannot both see room (one writer at a time on this connection)
        db::exec(
            &c,
            r#"insert into "device_share_sessions" ("device_share_id", "key_hash", "ip", "user_agent", "started_at", "last_seen_at") values (?, ?, ?, ?, ?, ?)"#,
            &[P(Val::Int(sid)), P(Val::str(&sha(&key))), P(Val::str(&ip)), P(Val::str(&ua)), P(Val::str(&stamp)), P(Val::str(&stamp))],
        )?;
        let session = db::first(&c, "select last_insert_rowid() as id", &[])?.map(|r| r.val("id").to_int()).unwrap_or(0);
        if live_viewers(&c, sid, now)? > hit.share.val("max_viewers").to_int() {
            db::exec(&c, r#"delete from "device_share_sessions" where "id" = ?"#, &[P(Val::Int(session))])?;
            return Ok(refuse(409, "link_full"));
        }
        db::exec(&c, r#"update "device_shares" set "last_used_at" = ? where "id" = ?"#, &[P(Val::str(&stamp)), P(Val::Int(sid))])?;
        let rid = text(&hit.device, "rustdesk_id");
        let label = text(&hit.share, "label");
        reach::console_audit_system(&c, "device.share.open", &format!("Share link \"{label}\" opened for device {rid} from {ip}"), "device", rid.as_bytes(), now)?;
        let expires = crate::laravel::parse_ts(&hit.share.val("expires_at")).unwrap_or(0);
        let name = {
            let a = text(&hit.device, "alias");
            if truthy(&a) { a } else { let h = text(&hit.device, "hostname"); if truthy(&h) { h } else { rid.clone() } }
        };
        // a viewer gets STUN only: TURN credentials stay with signed-in people
        let webrtc = match super::webclient::webrtc(&c)? {
            Value::Null => Value::Null,
            v => {
                let list = v.get("iceServers").and_then(|x| x.as_str()).unwrap_or("");
                let stun: Vec<&str> = crate::ice::entries(list).into_iter().filter(|e| e.to_ascii_lowercase().starts_with("stun:") || e.to_ascii_lowercase().starts_with("stuns:")).collect();
                json!({"iceServers": stun.join(",")})
            }
        };
        let short: String = label.chars().take(60).collect();
        Ok(reply(
            200,
            json!({
                "session": key, "label": label, "device_name": name, "expires_at": expires, "ping_seconds": PING_SECONDS,
                "client": {
                    "peerId": rid, "serverKeyB64": super::webclient::server_key(&c)?, "wsIdUrl": ws_id, "wsRelayUrl": ws_relay,
                    "myId": format!("share-{sid}"), "myName": format!("{short} (share link)"),
                    "signalToken": ticket(&rid, sid, expires, now), "webrtc": webrtc,
                },
            })
            .to_string(),
            "application/json",
            &[],
        ))
    })();
    out.unwrap_or_else(|_| error_response(500, "Server Error", false))
}

/// The open session for this token and session key, with its live link.
fn session_of(c: &Connection, body: &Value) -> Result<Option<(Row, Row)>, Fault> {
    let (token, key) = (arg(body, "token"), arg(body, "session"));
    if token.len() != 64 || key.is_empty() {
        return Ok(None);
    }
    let Some(session) = db::first(c, r#"select * from "device_share_sessions" where "key_hash" = ? and "ended_at" is null limit 1"#, &[P(Val::str(&sha(&key)))])? else { return Ok(None) };
    let Some(share) = db::first(c, r#"select * from "device_shares" where "id" = ? and "token_hash" = ? limit 1"#, &[P(session.val("device_share_id")), P(Val::str(&sha(&token)))])? else { return Ok(None) };
    Ok(Some((session, share)))
}

async fn ping(State(p): State<Arc<Pages>>, req: Request<Body>) -> Response<Body> {
    if req.method() != Method::POST {
        return error_response(405, "Method Not Allowed", false);
    }
    let (_, body) = json_body(req).await;
    let now = p.n.now();
    let c = p.n.db.lock().unwrap_or_else(|e| e.into_inner());
    let out = (|| -> Result<Response<Body>, Fault> {
        if !enabled(&c)? {
            return Ok(error_response(404, "Not Found", false));
        }
        let Some((session, share)) = session_of(&c, &body)? else { return Ok(refuse(410, "link_ended")) };
        let stamp = crate::laravel::ts(now);
        let end = |why: &str| -> Result<Response<Body>, Fault> {
            db::exec(&c, r#"update "device_share_sessions" set "ended_at" = ? where "id" = ?"#, &[P(Val::str(&stamp)), P(session.val("id"))])?;
            Ok(refuse(410, why))
        };
        let Some(device) = live(&c, &share, now)? else { return end("link_ended") };
        // lapsed (no ping for a while): its slot may have gone to someone else, so it comes back only if there is room
        let seen = crate::laravel::parse_ts(&session.val("last_seen_at")).unwrap_or(0);
        db::exec(&c, r#"update "device_share_sessions" set "last_seen_at" = ? where "id" = ?"#, &[P(Val::str(&stamp)), P(session.val("id"))])?;
        if seen <= now - LIVE_SECONDS && live_viewers(&c, share.id(), now)? > share.val("max_viewers").to_int() {
            return end("link_full");
        }
        let expires = crate::laravel::parse_ts(&share.val("expires_at")).unwrap_or(0);
        Ok(reply(200, json!({"ok": true, "signal_token": ticket(&text(&device, "rustdesk_id"), share.id(), expires, now)}).to_string(), "application/json", &[]))
    })();
    out.unwrap_or_else(|_| error_response(500, "Server Error", false))
}

async fn end_session(State(p): State<Arc<Pages>>, req: Request<Body>) -> Response<Body> {
    if req.method() != Method::POST {
        return error_response(405, "Method Not Allowed", false);
    }
    let (_, body) = json_body(req).await;
    let now = p.n.now();
    let c = p.n.db.lock().unwrap_or_else(|e| e.into_inner());
    if enabled(&c).unwrap_or(false) {
        if let Ok(Some((session, _))) = session_of(&c, &body) {
            let _ = db::exec(&c, r#"update "device_share_sessions" set "ended_at" = ? where "id" = ?"#, &[P(Val::str(&crate::laravel::ts(now))), P(session.val("id"))]);
        }
    }
    reply(200, json!({"ok": true}).to_string(), "application/json", &[])
}
