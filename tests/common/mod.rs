#![allow(dead_code)]

use axum::body::{to_bytes, Body};
use axum::http::header::{ACCEPT, ACCEPT_LANGUAGE, AUTHORIZATION, CONTENT_TYPE, COOKIE, REFERER, SET_COOKIE, USER_AGENT};
use axum::http::Request;
use axum::response::Response;
use axum::Router;
use nepenthes::config::Config;
use nepenthes::routes::app_router;
use nepenthes::AppState;

pub const BOT_UA: &str = "python-requests/2.32.3";
pub const BROWSER_UA: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

/// Fast, self-contained config: no storage, no drip delay, no hops, no rate limit.
pub fn test_config() -> Config {
    let mut cfg = Config::default();
    cfg.storage.enabled = false;
    cfg.rate_limit.enabled = false;
    cfg.tarpit.min_delay_ms = 0;
    cfg.tarpit.max_delay_ms = 0;
    cfg.redirect.hop_probability = 0.0;
    cfg.limits.bandwidth_bytes_per_sec = 0;
    cfg.server.secret = "test-secret".into();
    cfg
}

pub async fn build(cfg: Config) -> (Router, AppState) {
    let state = AppState::build(cfg).await.expect("state builds");
    (app_router(state.clone()), state)
}

pub fn bot_request(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header(USER_AGENT, BOT_UA)
        .header(ACCEPT, "*/*")
        .body(Body::empty())
        .unwrap()
}

/// A real browser's navigation request. `cookie` / `referer` are sent when given.
pub fn browser_nav(uri: &str, cookie: Option<&str>, referer: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .uri(uri)
        .header(USER_AGENT, BROWSER_UA)
        .header(ACCEPT, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        .header(ACCEPT_LANGUAGE, "en-US,en;q=0.9")
        .header("sec-fetch-mode", "navigate")
        .header("sec-fetch-dest", "document");
    if let Some(c) = cookie {
        b = b.header(COOKIE, c);
    }
    if let Some(r) = referer {
        b = b.header(REFERER, r);
    }
    b.body(Body::empty()).unwrap()
}

pub fn browser_request(uri: &str) -> Request<Body> {
    browser_nav(uri, None, None)
}

/// A browser subresource request (stylesheet, image, beacon) from the same client.
pub fn browser_subresource(method: &str, uri: &str, dest: &str, cookie: Option<&str>, body: &str) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(USER_AGENT, BROWSER_UA)
        .header(ACCEPT, "*/*")
        .header(ACCEPT_LANGUAGE, "en-US,en;q=0.9")
        .header("sec-fetch-mode", "no-cors")
        .header("sec-fetch-dest", dest);
    if let Some(c) = cookie {
        b = b.header(COOKIE, c);
    }
    if !body.is_empty() {
        b = b.header(CONTENT_TYPE, "text/plain;charset=UTF-8");
    }
    b.body(Body::from(body.to_owned())).unwrap()
}

pub fn post_json(uri: &str, json: &str, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::post(uri).header(CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    builder.body(Body::from(json.to_owned())).unwrap()
}

pub fn get(uri: &str) -> Request<Body> {
    Request::get(uri).body(Body::empty()).unwrap()
}

/// `name=value` of the session cookie set on a response.
pub fn session_cookie(resp: &Response) -> Option<String> {
    resp.headers()
        .get(SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(str::to_owned)
}

pub async fn body_text(resp: Response) -> String {
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    String::from_utf8(bytes.to_vec()).expect("utf-8 body")
}

pub async fn body_json(resp: Response) -> serde_json::Value {
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    serde_json::from_slice(&bytes).expect("json body")
}
