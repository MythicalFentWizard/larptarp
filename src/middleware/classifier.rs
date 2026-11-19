//! Request classifier.
//!
//! Two kinds of evidence feed one confidence score per session:
//!
//! - **Header signals**, scored on every page request: User-Agent, missing
//!   Accept-Language / Sec-Fetch headers, wildcard Accept, touching the maze.
//! - **Behaviour signals**, accumulated over the session: ignoring cookies,
//!   request rate, never loading subresources, never running JavaScript,
//!   `navigator.webdriver`, headless hints, no mouse/scroll/key activity,
//!   inhumanly fast navigation and missing Referer headers.
//!
//! Confidence only ratchets up, and containment is sticky. The classifier
//! drives the `New -> Classified -> Normal | Contained` transitions, and
//! re-contains fingerprints remembered from earlier sessions on sight.

use std::net::IpAddr;
use std::time::Instant;

use axum::extract::{Request, State};
use axum::http::header::{ACCEPT, ACCEPT_LANGUAGE, COOKIE, REFERER, SET_COOKIE, USER_AGENT};
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::config::{ClassifierConfig, ClassifierMode};
use crate::engine::beacon::is_check_path;
use crate::engine::navigation::fnv1a;
use crate::engine::session::{clip, Outcome, Remembered, Session, SessionState, Transition};
use crate::server::AppState;
use crate::telemetry::metrics::inc;

/// Attached to every request that passes the classifier.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub session_id: Option<Uuid>,
    pub state: SessionState,
    pub confidence: f32,
    pub client_ip: IpAddr,
}

impl RequestContext {
    pub fn untracked(client_ip: IpAddr) -> Self {
        Self { session_id: None, state: SessionState::Normal, confidence: 0.0, client_ip }
    }
}

/// What the session has revealed so far, as seen by the scorer.
#[derive(Debug, Clone, Copy, Default)]
pub struct Hints {
    pub request_count: u64,
    pub cookie_ever_seen: bool,
    pub recent_rps: f64,
    pub beacon_pages: u32,
    pub assets_fetched: u32,
    pub js_beacons: u32,
    pub webdriver: bool,
    pub headless: bool,
    pub interactions: u64,
    pub fast_navigations: u32,
    pub missing_referer: u32,
}

impl Hints {
    pub fn from_session(s: &Session) -> Self {
        let b = &s.behavior;
        Self {
            request_count: s.request_count,
            cookie_ever_seen: s.cookie_seen,
            recent_rps: s.recent_rps(),
            beacon_pages: b.beacon_pages,
            assets_fetched: b.assets_fetched,
            js_beacons: b.js_beacons,
            webdriver: b.webdriver,
            headless: b.headless,
            interactions: b.interactions,
            fast_navigations: b.fast_navigations,
            missing_referer: b.missing_referer,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Score {
    pub value: f32,
    pub reasons: Vec<&'static str>,
}

impl Score {
    fn add(&mut self, weight: f32, reason: &'static str) {
        if weight > 0.0 {
            self.value += weight;
            self.reasons.push(reason);
        }
    }
}

/// Signals carried by a single request's headers and path.
pub fn score_headers(cfg: &ClassifierConfig, headers: &HeaderMap, path: &str, trap_prefix: &str) -> Score {
    let w = &cfg.weights;
    let mut score = Score::default();
    let ua = header_str(headers, &USER_AGENT).trim().to_ascii_lowercase();
    if ua.is_empty() {
        score.add(w.empty_user_agent, "empty_user_agent");
    } else if matches_any(&ua, &cfg.bot_user_agents) {
        score.add(w.known_bot_user_agent, "known_bot_user_agent");
    }
    if headers.get(ACCEPT_LANGUAGE).is_none() {
        score.add(w.missing_accept_language, "missing_accept_language");
    }
    match headers.get(ACCEPT).and_then(|v| v.to_str().ok()).map(str::trim) {
        None | Some("") => score.add(w.wildcard_accept, "missing_accept"),
        Some("*/*") => score.add(w.wildcard_accept, "wildcard_accept"),
        _ => {}
    }
    if headers.get("sec-fetch-mode").is_none() && headers.get("sec-fetch-dest").is_none() {
        score.add(w.missing_sec_fetch, "missing_sec_fetch");
    }
    if is_trap_path(path, trap_prefix) {
        score.add(w.honeypot, "honeypot_path");
    }
    score
}

/// Signals accumulated over the whole session.
pub fn score_behavior(cfg: &ClassifierConfig, h: &Hints) -> Score {
    let w = &cfg.weights;
    let mut score = Score::default();
    if h.request_count >= 3 && !h.cookie_ever_seen {
        score.add(w.ignores_cookies, "ignores_cookies");
    }
    if cfg.high_rate_rps > 0.0 && h.recent_rps >= cfg.high_rate_rps {
        score.add(w.high_rate, "high_request_rate");
    }
    if cfg.beacon && h.beacon_pages >= 2 && h.assets_fetched == 0 {
        score.add(w.no_subresources, "no_subresources");
    }
    if cfg.beacon && h.beacon_pages >= 2 && h.js_beacons == 0 {
        score.add(w.no_javascript, "no_javascript");
    }
    if h.webdriver {
        score.add(w.webdriver, "webdriver");
    }
    if h.headless {
        score.add(w.headless_browser, "headless_browser");
    }
    if h.js_beacons >= 3 && h.interactions == 0 {
        score.add(w.no_interaction, "no_interaction");
    }
    if h.fast_navigations >= 3 {
        score.add(w.fast_navigation, "fast_navigation");
    }
    if h.missing_referer >= 3 {
        score.add(w.missing_referer, "missing_referer");
    }
    score
}

/// Header and behaviour signals together. 0.0 looks like a person with a
/// browser, 1.0 is certainly automated.
pub fn score_request(cfg: &ClassifierConfig, headers: &HeaderMap, path: &str, trap_prefix: &str, hints: &Hints) -> Score {
    let mut score = score_headers(cfg, headers, path, trap_prefix);
    let behavior = score_behavior(cfg, hints);
    score.value = (score.value + behavior.value).clamp(0.0, 1.0);
    score.reasons.extend(behavior.reasons);
    score
}

/// Recompute a session's confidence from its latest header score plus its behaviour.
pub fn rescore(s: &mut Session, cfg: &ClassifierConfig) {
    let behavior = score_behavior(cfg, &Hints::from_session(s));
    let total = (s.header_score + behavior.value).clamp(0.0, 1.0);
    if total > s.confidence {
        s.confidence = total;
        let mut signals = s.header_signals.clone();
        signals.extend(behavior.reasons);
        s.signals = signals;
    }
}

/// Containment policy for one client.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub exempt: bool,
    pub forced: bool,
    pub may_contain: bool,
}

pub fn policy_for(cfg: &ClassifierConfig, ip: IpAddr, user_agent_lower: &str) -> Policy {
    let exempt = cfg.never_contain_ips.contains(&ip) || matches_any(user_agent_lower, &cfg.never_contain_user_agents);
    let forced = !exempt
        && (cfg.mode == ClassifierMode::ContainAll || matches_any(user_agent_lower, &cfg.always_contain_user_agents));
    Policy { exempt, forced, may_contain: !exempt && cfg.mode != ClassifierMode::Off }
}

/// Drive `New -> Classified -> Normal | Contained` (or straight to Blocked /
/// Contained for remembered fingerprints).
pub fn apply_verdict(
    s: &mut Session,
    cfg: &ClassifierConfig,
    policy: &Policy,
    recalled: Option<Remembered>,
) -> Vec<Transition> {
    let mut out = Vec::new();
    if s.state == SessionState::New {
        if let Ok(t) = s.transition(SessionState::Classified, "first request") {
            out.push(t);
        }
    }
    if let (Some(r), SessionState::Classified, true) = (recalled, s.state, policy.may_contain) {
        s.restored = true;
        s.confidence = s.confidence.max(r.confidence);
        let (to, reason) = if r.blocked {
            (SessionState::Blocked, "fingerprint was blocked in an earlier session")
        } else {
            (SessionState::Contained, "fingerprint was contained in an earlier session")
        };
        if let Ok(t) = s.transition(to, reason) {
            out.push(t);
        }
        return out;
    }

    let contain = policy.may_contain && (policy.forced || s.confidence >= cfg.threshold);
    let target = match s.state {
        SessionState::Classified if contain => Some(SessionState::Contained),
        SessionState::Classified => Some(SessionState::Normal),
        SessionState::Normal if contain => Some(SessionState::Contained),
        _ => None,
    };
    if let Some(to) = target {
        let reason = match (to, policy.forced) {
            (SessionState::Contained, true) => "forced by configuration".to_string(),
            (SessionState::Contained, false) => format!(
                "confidence {:.2} >= threshold {:.2} ({})",
                s.confidence,
                cfg.threshold,
                s.signals.join(", ")
            ),
            _ => format!("confidence {:.2} below threshold {:.2}", s.confidence, cfg.threshold),
        };
        if let Ok(t) = s.transition(to, reason) {
            out.push(t);
        }
    }
    out
}

pub fn is_trap_path(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix).is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

pub fn matches_any(user_agent_lower: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| !p.is_empty() && user_agent_lower.contains(p.as_str()))
}

pub fn fingerprint(ip: IpAddr, user_agent: &str, accept_language: &str) -> u64 {
    fnv1a(format!("{ip}|{user_agent}|{accept_language}").as_bytes())
}

const STATIC_EXTENSIONS: &[&str] = &[
    "css", "js", "mjs", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "avif", "bmp", "woff", "woff2",
    "ttf", "otf", "eot", "mp4", "webm", "mp3", "wav", "json", "xml", "txt", "pdf", "zip",
];

/// Is this a page view (a document) rather than a subresource or API call?
pub fn is_navigation(headers: &HeaderMap, path: &str) -> bool {
    if let Some(dest) = headers.get("sec-fetch-dest").and_then(|v| v.to_str().ok()) {
        return dest == "document" || dest == "iframe";
    }
    let last = path.rsplit('/').next().unwrap_or("");
    match last.rsplit_once('.') {
        Some((_, ext)) => !STATIC_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()),
        None => true,
    }
}

fn header_str<'a>(headers: &'a HeaderMap, name: &HeaderName) -> &'a str {
    headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("")
}

fn read_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.trim())
}

fn cookie_header(name: &str, id: Uuid, max_age_secs: u64) -> Option<HeaderValue> {
    HeaderValue::from_str(&format!("{name}={id}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_secs}")).ok()
}

enum Verdict {
    Tracked {
        ctx: RequestContext,
        transitions: Vec<Transition>,
        set_cookie: Option<HeaderValue>,
        created: bool,
        restored: bool,
        resumed: bool,
    },
    Untracked(RequestContext),
    /// Session table is full and this request looks like something we would contain.
    Shed,
}

pub async fn classify(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    match evaluate(&state, &req) {
        Verdict::Shed => crate::routes::overloaded(),
        Verdict::Untracked(ctx) => {
            req.extensions_mut().insert(ctx);
            next.run(req).await
        }
        Verdict::Tracked { ctx, transitions, set_cookie, created, restored, resumed } => {
            let m = &state.telemetry.metrics;
            if created {
                inc(&m.sessions_created);
            }
            if let Some(id) = ctx.session_id {
                if restored {
                    inc(&m.sessions_restored);
                    state.telemetry.event(Some(id), "restored", json!({ "state": ctx.state }));
                }
                if resumed {
                    inc(&m.sessions_resumed);
                    tracing::info!(session = %id, "abandoned session came back");
                    state.telemetry.event(Some(id), "resumed", json!({}));
                }
            }
            for t in &transitions {
                state.telemetry.transition(t);
            }
            req.extensions_mut().insert(ctx);
            let mut resp = next.run(req).await;
            if let Some(cookie) = set_cookie {
                resp.headers_mut().append(SET_COOKIE, cookie);
            }
            resp
        }
    }
}

fn evaluate(state: &AppState, req: &Request) -> Verdict {
    let cfg = &state.config;
    let ccfg = &cfg.classifier;
    let prefix = cfg.tarpit.prefix.as_str();
    let ip = super::client_ip(req, cfg.server.trust_forwarded_for);
    let headers = req.headers();
    let path = req.uri().path();

    let user_agent = header_str(headers, &USER_AGENT);
    let ua_lower = user_agent.to_ascii_lowercase();
    let cookie_id = read_cookie(headers, &cfg.server.cookie_name).and_then(|v| Uuid::parse_str(v).ok());
    let fp = fingerprint(ip, user_agent, header_str(headers, &ACCEPT_LANGUAGE));

    // Browser-check requests: attribute to an existing session, never score or count them.
    if is_check_path(path) {
        let ctx = match state.sessions.lookup(cookie_id, fp) {
            Some(id) => RequestContext { session_id: Some(id), ..RequestContext::untracked(ip) },
            None => RequestContext::untracked(ip),
        };
        return Verdict::Untracked(ctx);
    }

    let policy = policy_for(ccfg, ip, &ua_lower);
    let now = Utc::now();

    let Some(resolved) = state.sessions.resolve(cookie_id, fp, ip, user_agent, now) else {
        // Session table full: classify statelessly and shed anything we'd trap.
        inc(&state.telemetry.metrics.overload_rejections);
        let score = score_headers(ccfg, headers, path, prefix);
        return if policy.may_contain && (policy.forced || score.value >= ccfg.threshold) {
            Verdict::Shed
        } else {
            Verdict::Untracked(RequestContext::untracked(ip))
        };
    };

    let recalled = if resolved.created { state.sessions.recall(fp) } else { None };
    let navigation = is_navigation(headers, path);
    let has_referer = headers.contains_key(REFERER);
    let header_score = score_headers(ccfg, headers, path, prefix);
    let instant = Instant::now();

    let result = state.sessions.with_session(&resolved.id, |s| {
        s.touch(now, instant);
        let presented = cookie_id == Some(s.id);
        if presented {
            s.cookie_seen = true;
        }
        if navigation {
            s.behavior.record_navigation(instant, has_referer, ccfg.min_human_dwell_ms);
            s.last_path = clip(path, 300);
        }
        let mut resumed = false;
        if s.state == SessionState::Contained && s.outcome == Outcome::Abandoned {
            s.outcome = Outcome::Trapped;
            s.push_timeline("resumed", path, None, None);
            resumed = true;
        }

        s.header_score = header_score.value;
        s.header_signals = header_score.reasons.clone();
        rescore(s, ccfg);
        let transitions = apply_verdict(s, ccfg, &policy, recalled);

        let set_cookie =
            if presented { None } else { cookie_header(&cfg.server.cookie_name, s.id, cfg.session.max_lifetime_secs) };
        let ctx = RequestContext { session_id: Some(s.id), state: s.state, confidence: s.confidence, client_ip: ip };
        (ctx, transitions, set_cookie, s.restored && resolved.created, resumed)
    });

    match result {
        Some((ctx, transitions, set_cookie, restored, resumed)) => {
            Verdict::Tracked { ctx, transitions, set_cookie, created: resolved.created, restored, resumed }
        }
        // Swept between resolve and use: serve it without tracking.
        None => Verdict::Untracked(RequestContext::untracked(ip)),
    }
}
