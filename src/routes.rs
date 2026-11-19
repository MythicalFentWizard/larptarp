//! Data-plane routing: normal traffic vs the tarpit manager.

use std::sync::atomic::Ordering;
use std::time::Instant;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{ACCEPT, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG};
use axum::http::{header, StatusCode};
use axum::middleware::from_fn_with_state;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use bytes::Bytes;
use chrono::Utc;
use futures::StreamExt;
use rand::Rng;
use serde_json::json;
use tower::limit::GlobalConcurrencyLimitLayer;
use tower::ServiceExt;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::services::ServeDir;
use uuid::Uuid;

use crate::engine::beacon;
use crate::engine::navigation::{path_depth, path_hash, NavOutcome};
use crate::engine::redirect::redirect_response;
use crate::engine::session::{Outcome, SessionState, Transition};
use crate::engine::tarpit::{escape_html, MazeRequest, OnDone};
use crate::middleware::classifier::{self, is_trap_path, RequestContext};
use crate::middleware::{client_ip, rate_limit, request_trace};
use crate::proxy;
use crate::server::AppState;
use crate::storage::database::RequestRecord;
use crate::telemetry::metrics::{add, inc};

/// The tarpit listener. Layers run outermost-first:
/// panic guard -> global in-flight cap -> trace -> rate limit -> classifier -> handler.
pub fn app_router(state: AppState) -> Router {
    let inflight = state.config.limits.max_inflight_requests;
    Router::new()
        .route("/robots.txt", get(robots))
        .route("/exit", get(exit_page))
        .route("/_np/s/{file}", get(beacon::stylesheet))
        .route("/_np/p/{file}", get(beacon::pixel))
        .route("/_np/b", post(beacon::beacon))
        .fallback(dispatch)
        .layer(from_fn_with_state(state.clone(), classifier::classify))
        .layer(from_fn_with_state(state.clone(), rate_limit::rate_limit))
        .layer(from_fn_with_state(state.clone(), request_trace::trace))
        .layer(GlobalConcurrencyLimitLayer::new(inflight))
        .layer(CatchPanicLayer::new())
        .with_state(state)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    Normal,
    NotFound,
    Maze,
    Search,
    Hop,
    Exit,
    Operator,
    Blocked,
    Overload,
    Killswitch,
}

impl RouteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RouteKind::Normal => "normal",
            RouteKind::NotFound => "not_found",
            RouteKind::Maze => "maze",
            RouteKind::Search => "search",
            RouteKind::Hop => "hop",
            RouteKind::Exit => "exit",
            RouteKind::Operator => "operator_redirect",
            RouteKind::Blocked => "blocked",
            RouteKind::Overload => "overload",
            RouteKind::Killswitch => "killswitch",
        }
    }

    /// Maze pages are recorded when their stream ends (with duration and size).
    fn recorded_on_stream_end(self) -> bool {
        matches!(self, RouteKind::Maze | RouteKind::Search)
    }
}

/// What the request looked like, for records written after it is answered.
#[derive(Debug, Clone)]
struct RequestMeta {
    method: String,
    /// Path plus query string.
    target: String,
}

struct Routed {
    resp: Response,
    kind: RouteKind,
    /// The response carries the browser checks.
    beaconed: bool,
}

async fn dispatch(State(state): State<AppState>, req: Request) -> Response {
    let started = Instant::now();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().map(str::to_owned);
    let Some(ctx) = req.extensions().get::<RequestContext>().cloned() else {
        return normal_response(&state, req).await.0;
    };
    let meta = RequestMeta {
        method: req.method().to_string(),
        target: match &query {
            Some(q) => format!("{path}?{q}"),
            None => path.clone(),
        },
    };

    let routed = route_request(&state, &ctx, req, &path, query.as_deref(), &meta).await;

    let m = &state.telemetry.metrics;
    match routed.kind {
        RouteKind::Normal | RouteKind::NotFound => inc(&m.normal_requests),
        RouteKind::Maze | RouteKind::Search | RouteKind::Hop | RouteKind::Exit | RouteKind::Killswitch => {
            inc(&m.trap_requests)
        }
        _ => {}
    }
    if let Some(id) = ctx.session_id {
        let status = routed.resp.status().as_u16();
        if !routed.kind.recorded_on_stream_end() {
            state.sessions.with_session(&id, |s| {
                if routed.beaconed {
                    s.behavior.beacon_pages += 1;
                }
                s.push_timeline(routed.kind.as_str(), &meta.target, Some(status), None);
            });
            state.telemetry.request(RequestRecord {
                session_id: id,
                at: Utc::now(),
                method: meta.method,
                path: meta.target,
                status,
                route: routed.kind.as_str(),
                duration_ms: Some(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)),
                bytes: None,
            });
        }
    }
    routed.resp
}

async fn route_request(
    state: &AppState,
    ctx: &RequestContext,
    req: Request,
    path: &str,
    query: Option<&str>,
    meta: &RequestMeta,
) -> Routed {
    let simple = |resp: Response, kind: RouteKind| Routed { resp, kind, beaconed: false };
    let Some(id) = ctx.session_id else {
        let (resp, beaconed) = normal_response(state, req).await;
        return Routed { resp, kind: RouteKind::Normal, beaconed };
    };
    if ctx.state == SessionState::Blocked {
        return simple(forbidden(), RouteKind::Blocked);
    }

    // One-shot redirect scheduled on the control plane.
    if let Some(dest) = state.sessions.with_session(&id, |s| s.pending_redirect.take()).flatten() {
        inc(&state.telemetry.metrics.redirects_operator);
        state.telemetry.redirect(id, "operator", &dest, 0);
        return simple(redirect_response(&dest), RouteKind::Operator);
    }

    match ctx.state {
        SessionState::Completed if state.redirects.is_exit_path(path) => {
            let (resp, beaconed) = normal_response(state, req).await;
            Routed { resp, kind: RouteKind::Normal, beaconed }
        }
        SessionState::Completed => {
            let dest = state.redirects.exit_destination();
            inc(&state.telemetry.metrics.redirects_exit);
            state.telemetry.redirect(id, "exit", dest, 0);
            simple(redirect_response(dest), RouteKind::Exit)
        }
        SessionState::Contained => {
            let maze = state.tarpit.parse(path, query);
            let (resp, kind) = contained(state, id, maze, meta).await;
            simple(resp, kind)
        }
        // Exempt clients (or mode = off) never see the maze.
        _ if is_trap_path(path, &state.config.tarpit.prefix) => simple(not_found(), RouteKind::NotFound),
        _ => {
            let (resp, beaconed) = normal_response(state, req).await;
            Routed { resp, kind: RouteKind::Normal, beaconed }
        }
    }
}

enum TrapDecision {
    Exit(Option<Transition>),
    Hop(u32),
    Serve { outcome: NavOutcome, seq: u64 },
}

/// The tarpit manager: enforce the trap rules for a contained session.
async fn contained(state: &AppState, id: Uuid, maze: MazeRequest, meta: &RequestMeta) -> (Response, RouteKind) {
    let m = &state.telemetry.metrics;
    if state.killswitch.load(Ordering::Relaxed) {
        inc(&m.killswitch_hits);
        return (disarmed(), RouteKind::Killswitch);
    }
    let Some(permit) = state.tarpit.try_reserve_stream() else {
        inc(&m.overload_rejections);
        return (overloaded(), RouteKind::Overload);
    };

    let cfg = &state.config;
    let redirects = &state.redirects;
    let roll: f64 = rand::thread_rng().gen();
    let hash = path_hash(&meta.target);
    let depth = path_depth(&maze.path, &cfg.tarpit.prefix);
    let is_search = maze.search.is_some();
    let kind = if is_search { RouteKind::Search } else { RouteKind::Maze };
    let beacon_enabled = cfg.classifier.beacon;

    // Every rule is checked and applied under the session lock, atomically.
    let decision = state.sessions.with_session(&id, |s| {
        s.trap_requests += 1;
        let budget = cfg.session.max_requests_per_session;
        if budget > 0 && s.request_count > budget {
            let reason = format!("request budget of {budget} exhausted");
            let t = s.transition(SessionState::Completed, reason).ok();
            s.outcome = Outcome::BudgetExhausted;
            return TrapDecision::Exit(t);
        }
        if redirects.should_hop(s.redirect_chain, roll) {
            s.redirect_chain += 1;
            s.redirects_issued += 1;
            let note = format!("hop {} of max {}", s.redirect_chain, redirects.max_depth());
            s.push_timeline("hop", &meta.target, Some(302), Some(note));
            return TrapDecision::Hop(s.redirect_chain);
        }
        s.redirect_chain = 0;
        s.navigation_depth = s.navigation_depth.saturating_add(1);
        s.nav.max_path_depth = s.nav.max_path_depth.max(depth);
        if is_search {
            s.searches += 1;
        }
        if beacon_enabled {
            s.behavior.beacon_pages += 1;
        }
        let outcome = s.nav.record(hash, cfg.session.loop_window, cfg.session.loop_threshold);
        let note = match outcome {
            NavOutcome::Loop { hits } => Some(format!("loop: visited {hits} times")),
            NavOutcome::Revisit { hits } => Some(format!("revisit #{hits}")),
            NavOutcome::Fresh => None,
        };
        let seq = s.push_timeline(kind.as_str(), &meta.target, Some(200), note);
        s.active_streams += 1;
        TrapDecision::Serve { outcome, seq }
    });

    match decision {
        None => (overloaded(), RouteKind::Overload),
        Some(TrapDecision::Exit(transition)) => {
            if let Some(t) = &transition {
                state.telemetry.transition(t);
            }
            let dest = redirects.exit_destination();
            inc(&m.redirects_exit);
            state.telemetry.redirect(id, "exit", dest, 0);
            (redirect_response(dest), RouteKind::Exit)
        }
        Some(TrapDecision::Hop(chain)) => {
            let url = state.tarpit.hop_url(&maze, (id.as_u128() as u64) ^ u64::from(chain));
            inc(&m.redirects_hop);
            state.telemetry.redirect(id, "hop", &url, chain);
            (redirect_response(&url), RouteKind::Hop)
        }
        Some(TrapDecision::Serve { outcome, seq }) => {
            if let NavOutcome::Loop { hits } = outcome {
                inc(&m.loops_detected);
                tracing::info!(session = %id, path = %meta.target, hits, "navigation loop detected");
                state.telemetry.event(Some(id), "loop_detected", json!({ "path": meta.target, "hits": hits }));
            }
            inc(if is_search { &m.searches_served } else { &m.trap_pages_served });

            let sessions = state.sessions.clone();
            let telemetry = state.telemetry.clone();
            let meta = meta.clone();
            let on_done: OnDone = Box::new(move |stats| {
                let ms = u64::try_from(stats.elapsed.as_millis()).unwrap_or(u64::MAX);
                sessions.with_session(&id, |s| {
                    s.trapped_ms = s.trapped_ms.saturating_add(ms);
                    s.bytes_sent = s.bytes_sent.saturating_add(stats.bytes);
                    s.active_streams = s.active_streams.saturating_sub(1);
                    s.last_activity = Utc::now();
                    s.complete_timeline(seq, ms, stats.bytes);
                });
                let m = &telemetry.metrics;
                add(&m.trapped_ms_total, ms);
                add(&m.trap_bytes_sent, stats.bytes);
                inc(if stats.completed { &m.trap_streams_completed } else { &m.trap_streams_aborted });
                telemetry.request(RequestRecord {
                    session_id: id,
                    at: Utc::now(),
                    method: meta.method,
                    path: meta.target,
                    status: 200,
                    route: kind.as_str(),
                    duration_ms: Some(ms),
                    bytes: Some(stats.bytes),
                });
            });
            (state.tarpit.serve(maze, permit, on_done).await, kind)
        }
    }
}

// ------------------------------------------------------------ normal traffic

/// Answer a legitimate request: upstream site, static directory, or the
/// built-in pages. Returns whether the browser checks were included.
async fn normal_response(state: &AppState, req: Request) -> (Response, bool) {
    let cfg = &state.config;
    if let (Some(client), Some(upstream)) = (&state.proxy, cfg.normal.upstream_url.as_deref()) {
        let ip = client_ip(&req, cfg.server.trust_forwarded_for);
        let wants_html = classifier::is_navigation(req.headers(), req.uri().path())
            && req
                .headers()
                .get(ACCEPT)
                .and_then(|v| v.to_str().ok())
                .map_or(true, |a| a.contains("text/html") || a.contains("*/*"));
        let identity = cfg.classifier.beacon && wants_html;
        let (resp, ok) = proxy::forward(client, upstream, req, ip, identity).await;
        inc(if ok { &state.telemetry.metrics.proxied_requests } else { &state.telemetry.metrics.proxy_errors });
        return maybe_inject(state, resp).await;
    }
    if let Some(dir) = &cfg.normal.static_dir {
        let resp = match ServeDir::new(dir).oneshot(req).await {
            Ok(resp) => resp.map(Body::new),
            Err(never) => match never {},
        };
        return maybe_inject(state, resp).await;
    }
    let beacon = cfg.classifier.beacon;
    match req.uri().path() {
        "/" | "/index.html" => (Html(landing_page(state)).into_response(), beacon),
        "/about" => (Html(about_page(state)).into_response(), beacon),
        _ => (not_found(), false),
    }
}

/// Add the browser checks to an HTML response (uncompressed, UTF-8, under the
/// size limit). Anything else passes through untouched.
async fn maybe_inject(state: &AppState, resp: Response) -> (Response, bool) {
    let cfg = &state.config;
    let headers = resp.headers();
    let content_type = headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
    let is_html = content_type.trim_start().starts_with("text/html");
    let utf8 = !content_type.contains("charset=") || content_type.contains("charset=utf-8");
    let encoded = headers
        .get(CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|e| !e.trim().eq_ignore_ascii_case("identity"));
    let too_big = headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|len| len > cfg.normal.max_inject_bytes);
    if !cfg.classifier.beacon || !is_html || !utf8 || encoded || too_big || !resp.status().is_success() {
        return (resp, false);
    }

    let (mut parts, body) = resp.into_parts();
    let mut stream = body.into_data_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(chunk) => {
                buf.extend_from_slice(&chunk);
                if buf.len() > cfg.normal.max_inject_bytes {
                    // Too large after all: send what we have, then the rest, untouched.
                    let head = futures::stream::once(async move { Ok::<Bytes, axum::Error>(Bytes::from(buf)) });
                    return (Response::from_parts(parts, Body::from_stream(head.chain(stream))), false);
                }
            }
            Err(_) => return (proxy::bad_gateway(), false),
        }
    }
    match String::from_utf8(buf) {
        Ok(html) => {
            let injected = beacon::inject(&html, &beacon::random_nonce());
            parts.headers.remove(CONTENT_LENGTH);
            parts.headers.remove(ETAG);
            (Response::from_parts(parts, Body::from(injected)), true)
        }
        Err(e) => (Response::from_parts(parts, Body::from(e.into_bytes())), false),
    }
}

fn page_shell(state: &AppState, title: &str, body: &str) -> String {
    let cfg = &state.config;
    let site = escape_html(&cfg.normal.site_name);
    let title = escape_html(title);
    let prefix = &cfg.tarpit.prefix;
    let nonce = beacon::random_nonce();
    let (head_checks, body_checks) = if cfg.classifier.beacon {
        (beacon::head_tags(&nonce), beacon::body_tags(&nonce))
    } else {
        (String::new(), String::new())
    };
    // A visible entry for agents that only read what is on screen.
    let visible = if cfg.normal.visible_entry_link {
        format!(
            "<section><h2>Archive</h2><form action=\"{prefix}/search\" method=\"get\"><input name=\"q\" placeholder=\"Search the archive\" size=\"32\"> <button>Search</button></form>\
             <p>Browse the <a href=\"{prefix}/\">full archive index</a>.</p></section>"
        )
    } else {
        String::new()
    };
    // The `.hp` link is the honeypot: invisible to people, `rel=nofollow` for
    // polite crawlers, disallowed in robots.txt. Only clients that ignore all
    // three follow it into the maze.
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} &middot; {site}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:42rem;margin:3rem auto;padding:0 1rem;line-height:1.6;color:#222}}.hp{{position:absolute;left:-10000px;width:1px;height:1px;overflow:hidden}}</style>
{head_checks}
</head>
<body>
<header><h1>{site}</h1><nav><a href="/">Home</a> &middot; <a href="/about">About</a></nav></header>
<main>
{body}
{visible}
</main>
<a class="hp" href="{prefix}/" rel="nofollow" tabindex="-1" aria-hidden="true">Full archive index</a>
<footer><p>&copy; {site}</p></footer>
{body_checks}</body>
</html>
"#
    )
}

fn landing_page(state: &AppState) -> String {
    page_shell(
        state,
        "Home",
        "<p>Welcome. This site publishes short notes and reference material.</p>\n\
         <p>Nothing here changes very often; check back occasionally.</p>",
    )
}

fn about_page(state: &AppState) -> String {
    page_shell(state, "About", "<p>A small, quiet website maintained by one person.</p>")
}

async fn robots(State(state): State<AppState>) -> Response {
    let ours = format!("User-agent: *\nDisallow: {}/\n", state.config.tarpit.prefix);
    let mut text = ours.clone();
    if let (Some(client), Some(upstream)) = (&state.proxy, state.config.normal.upstream_url.as_deref()) {
        if let Some(theirs) = proxy::upstream_robots(client, upstream).await {
            text = format!("{}\n\n{ours}", theirs.trim_end());
        }
    }
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], text).into_response()
}

async fn exit_page() -> Html<&'static str> {
    Html(
        "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Session closed</title></head>\
         <body><h1>Session closed</h1><p>There is nothing further here.</p></body></html>\n",
    )
}

// ------------------------------------------------------------ canned replies

pub fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, Html("<!DOCTYPE html><title>403 Forbidden</title><h1>Forbidden</h1>\n")).into_response()
}

pub fn not_found() -> Response {
    (StatusCode::NOT_FOUND, Html("<!DOCTYPE html><title>404 Not Found</title><h1>Not Found</h1>\n")).into_response()
}

/// Cheap answer when a global limit is hit.
pub fn overloaded() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::RETRY_AFTER, "30")],
        Html("<!DOCTYPE html><title>503 Service Unavailable</title><h1>Service Unavailable</h1>\n"),
    )
        .into_response()
}

/// Answer to contained sessions while the killswitch is engaged.
pub fn disarmed() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::RETRY_AFTER, "3600")],
        Html("<!DOCTYPE html><title>503 Service Unavailable</title><h1>Service Unavailable</h1>\n"),
    )
        .into_response()
}
