//! Browser checks.
//!
//! Every HTML page carries a stylesheet, a 1x1 pixel and a tiny script, each
//! with a unique URL so it is fetched on every page view:
//!
//! - HTTP libraries never load subresources and never run JavaScript.
//! - Automation frameworks (Playwright, Selenium, Puppeteer) expose
//!   `navigator.webdriver`; old headless Chrome says so in its UA and has no
//!   window frame.
//! - People move the mouse, scroll and type; scripted browsers mostly don't.
//!
//! The script reports on load and again on `pagehide` with interaction counts.

use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, USER_AGENT};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::middleware::classifier::{apply_verdict, policy_for, rescore, RequestContext};
use crate::middleware::client_ip;
use crate::server::AppState;
use crate::telemetry::metrics::inc;

/// Every check lives under this path; requests here are attributed to a
/// session but never scored or counted as page views.
pub const CHECK_PREFIX: &str = "/_np/";

const PIXEL: &[u8] = &[
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
    0xff, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
];

const SCRIPT: &str = r#"(function(){var n="__NONCE__",u="/_np/b",m=0,s=0,k=0,t=Date.now(),o={passive:true};function f(e){try{var d=JSON.stringify({n:n,e:e,wd:!!navigator.webdriver,hl:/HeadlessChrome/.test(navigator.userAgent)||(window.outerWidth===0&&window.outerHeight===0),mm:m,sc:s,kd:k,t:Date.now()-t});if(navigator.sendBeacon){navigator.sendBeacon(u,d)}else{fetch(u,{method:"POST",body:d,keepalive:true})}}catch(_){}}addEventListener("mousemove",function(){m++},o);addEventListener("touchstart",function(){m++},o);addEventListener("scroll",function(){s++},o);addEventListener("keydown",function(){k++});f("load");addEventListener("pagehide",function(){f("hide")})})();"#;

pub fn is_check_path(path: &str) -> bool {
    path.starts_with(CHECK_PREFIX)
}

pub fn random_nonce() -> String {
    format!("{:016x}", rand::random::<u64>())
}

/// Goes inside `<head>`.
pub fn head_tags(nonce: &str) -> String {
    format!("<link rel=\"stylesheet\" href=\"/_np/s/{nonce}.css\">")
}

/// Goes right before `</body>`.
pub fn body_tags(nonce: &str) -> String {
    format!(
        "<img src=\"/_np/p/{nonce}.gif\" alt=\"\" width=\"1\" height=\"1\" style=\"position:absolute;left:-9999px\">\n<script>{}</script>\n",
        SCRIPT.replace("__NONCE__", nonce)
    )
}

/// Insert the checks into an HTML document (before `</head>` and `</body>`;
/// appended when those tags are missing).
pub fn inject(html: &str, nonce: &str) -> String {
    let lower = html.to_ascii_lowercase(); // same byte offsets as `html`
    let head = head_tags(nonce);
    let body = body_tags(nonce);
    let mut out = String::with_capacity(html.len() + head.len() + body.len());
    match (lower.find("</head>"), lower.rfind("</body>")) {
        (Some(h), Some(b)) if h < b => {
            out.push_str(&html[..h]);
            out.push_str(&head);
            out.push_str(&html[h..b]);
            out.push_str(&body);
            out.push_str(&html[b..]);
        }
        (_, Some(b)) => {
            out.push_str(&html[..b]);
            out.push_str(&head);
            out.push_str(&body);
            out.push_str(&html[b..]);
        }
        _ => {
            out.push_str(html);
            out.push_str(&head);
            out.push_str(&body);
        }
    }
    out
}

fn session_of(req: &Request) -> Option<uuid::Uuid> {
    req.extensions().get::<RequestContext>().and_then(|c| c.session_id)
}

fn record_asset(state: &AppState, req: &Request) {
    inc(&state.telemetry.metrics.assets_served);
    if let Some(id) = session_of(req) {
        state.sessions.with_session(&id, |s| s.behavior.assets_fetched += 1);
    }
}

pub async fn stylesheet(State(state): State<AppState>, req: Request) -> Response {
    record_asset(&state, &req);
    ([(CONTENT_TYPE, "text/css; charset=utf-8"), (CACHE_CONTROL, "no-store")], "/* site styles */\n").into_response()
}

pub async fn pixel(State(state): State<AppState>, req: Request) -> Response {
    record_asset(&state, &req);
    ([(CONTENT_TYPE, "image/gif"), (CACHE_CONTROL, "no-store")], PIXEL).into_response()
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Payload {
    /// "load" or "hide".
    e: String,
    wd: bool,
    hl: bool,
    mm: u64,
    sc: u64,
    kd: u64,
}

/// Receives the script's report, updates the session's behaviour and
/// re-classifies it on the spot (so the very next navigation is trapped).
pub async fn beacon(State(state): State<AppState>, req: Request) -> Response {
    inc(&state.telemetry.metrics.beacons_received);
    let ccfg = &state.config.classifier;
    let id = session_of(&req);
    let ip = client_ip(&req, state.config.server.trust_forwarded_for);
    let ua_lower = req
        .headers()
        .get(USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let Ok(body) = to_bytes(req.into_body(), 4096).await else {
        return StatusCode::NO_CONTENT.into_response();
    };
    let Some(id) = id else {
        return StatusCode::NO_CONTENT.into_response();
    };
    let payload: Payload = serde_json::from_slice(&body).unwrap_or_default();
    let policy = policy_for(ccfg, ip, &ua_lower);

    let result = state.sessions.with_session(&id, |s| {
        let b = &mut s.behavior;
        b.js_beacons += 1;
        b.interactions = b
            .interactions
            .saturating_add(payload.mm.min(10_000) + payload.sc.min(10_000) + payload.kd.min(10_000));
        let mut flags: Vec<&'static str> = Vec::new();
        if payload.wd && !b.webdriver {
            b.webdriver = true;
            flags.push("webdriver");
        }
        if payload.hl && !b.headless {
            b.headless = true;
            flags.push("headless_browser");
        }
        let path = s.last_path.clone();
        for flag in &flags {
            s.push_timeline("flag", &path, None, Some(format!("browser reported {flag} ({})", payload.e)));
        }
        rescore(s, ccfg);
        let transitions = apply_verdict(s, ccfg, &policy, None);
        (transitions, flags.contains(&"webdriver"))
    });

    if let Some((transitions, webdriver)) = result {
        if webdriver {
            inc(&state.telemetry.metrics.webdriver_detected);
            state.telemetry.event(Some(id), "webdriver_detected", serde_json::json!({ "user_agent": ua_lower }));
        }
        for t in &transitions {
            state.telemetry.transition(t);
        }
    }
    StatusCode::NO_CONTENT.into_response()
}
