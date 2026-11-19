//! Control plane: a separate listener for managing sessions, redirects, the
//! killswitch and telemetry, plus a live dashboard at `/`.
//! Bind it to loopback and/or set `control.token`.

use std::fmt::Write as _;

use axum::extract::{Path, Query, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::config::Config;
use crate::engine::session::{Outcome, SessionError, SessionSnapshot, SessionState};
use crate::server::AppState;
use crate::storage::database::Database;

const DASHBOARD: &str = include_str!("dashboard.html");

pub fn control_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/health", get(health))
        .route("/metrics", get(metrics_json))
        .route("/metrics/prometheus", get(metrics_prometheus))
        .route("/sessions", get(list_sessions))
        .route("/sessions/{id}", get(get_session))
        .route("/sessions/{id}/timeline", get(session_timeline))
        .route("/sessions/{id}/release", post(release_session))
        .route("/sessions/{id}/block", post(block_session))
        .route("/sessions/{id}/contain", post(contain_session))
        .route("/sessions/{id}/redirect", post(redirect_session))
        .route("/killswitch", get(get_killswitch).post(set_killswitch))
        .route("/config", get(get_config))
        .route("/history/sessions", get(history_sessions))
        .route("/history/sessions/{id}/requests", get(history_session_requests))
        .route("/history/events", get(history_events))
        .route("/history/summary", get(history_summary))
        .route("/storage/prune", post(prune_storage))
        .layer(from_fn_with_state(state.clone(), require_token))
        .with_state(state)
}

pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

type ApiResult<T> = Result<Json<T>, ApiError>;

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Bearer token, or `?token=` so the dashboard can be opened in a browser.
async fn require_token(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if let Some(expected) = state.config.control.token.as_deref() {
        let from_header = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|t| t.trim().to_string());
        let from_query = req.uri().query().and_then(|q| {
            url::form_urlencoded::parse(q.as_bytes()).find(|(k, _)| k == "token").map(|(_, v)| v.into_owned())
        });
        let ok = from_header.or(from_query).is_some_and(|t| constant_time_eq(t.as_bytes(), expected.as_bytes()));
        if !ok {
            return ApiError(StatusCode::UNAUTHORIZED, "missing or invalid bearer token".into()).into_response();
        }
    }
    next.run(req).await
}

async fn dashboard() -> Html<&'static str> {
    Html(DASHBOARD)
}

fn uptime_secs(state: &AppState) -> i64 {
    (Utc::now() - state.started_at).num_seconds()
}

async fn health(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "uptime_secs": uptime_secs(&state),
        "killswitch": state.killswitch_engaged(),
        "active_sessions": state.sessions.len(),
    }))
}

async fn metrics_json(State(state): State<AppState>) -> Json<Value> {
    let counters = state.telemetry.metrics.snapshot();
    let downtime_secs = counters.trapped_ms_total as f64 / 1000.0;
    Json(json!({
        "uptime_secs": uptime_secs(&state),
        "killswitch": state.killswitch_engaged(),
        "enemy_downtime_secs": downtime_secs,
        "gauges": {
            "active_sessions": state.sessions.len(),
            "sessions_by_state": state.sessions.count_by_state(),
            "sessions_by_outcome": state.sessions.count_by_outcome(),
            "active_trap_streams": state.tarpit.active_streams(),
            "remembered_fingerprints": state.sessions.remembered_count(),
            "rate_limited_ips_tracked": state.limiter.tracked(),
        },
        "counters": counters,
    }))
}

async fn metrics_prometheus(State(state): State<AppState>) -> impl IntoResponse {
    let mut out = String::with_capacity(4096);
    state.telemetry.metrics.render_prometheus(&mut out);
    let _ = writeln!(out, "# HELP nepenthes_active_sessions Sessions in the in-memory cache");
    let _ = writeln!(out, "# TYPE nepenthes_active_sessions gauge");
    let counts = state.sessions.count_by_state();
    for st in SessionState::ALL {
        let n = counts.get(st.as_str()).copied().unwrap_or(0);
        let _ = writeln!(out, "nepenthes_active_sessions{{state=\"{}\"}} {n}", st.as_str());
    }
    let _ = writeln!(out, "# HELP nepenthes_active_trap_streams Maze pages currently dripping");
    let _ = writeln!(out, "# TYPE nepenthes_active_trap_streams gauge");
    let _ = writeln!(out, "nepenthes_active_trap_streams {}", state.tarpit.active_streams());
    let _ = writeln!(out, "# HELP nepenthes_remembered_fingerprints Contained/blocked fingerprints remembered");
    let _ = writeln!(out, "# TYPE nepenthes_remembered_fingerprints gauge");
    let _ = writeln!(out, "nepenthes_remembered_fingerprints {}", state.sessions.remembered_count());
    let _ = writeln!(out, "# HELP nepenthes_killswitch 1 when the trap is disarmed");
    let _ = writeln!(out, "# TYPE nepenthes_killswitch gauge");
    let _ = writeln!(out, "nepenthes_killswitch {}", u8::from(state.killswitch_engaged()));
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")], out)
}

#[derive(Deserialize)]
struct ListQuery {
    state: Option<String>,
    limit: Option<usize>,
}

async fn list_sessions(State(state): State<AppState>, Query(q): Query<ListQuery>) -> ApiResult<Value> {
    let filter = match q.state.as_deref().filter(|s| !s.is_empty() && *s != "all") {
        Some(s) => Some(
            SessionState::parse(s).ok_or_else(|| ApiError(StatusCode::BAD_REQUEST, format!("unknown state `{s}`")))?,
        ),
        None => None,
    };
    let sessions = state.sessions.list(filter, q.limit.unwrap_or(100).min(10_000));
    Ok(Json(json!({ "count": sessions.len(), "sessions": sessions })))
}

fn not_found(id: Uuid) -> ApiError {
    ApiError(StatusCode::NOT_FOUND, format!("session {id} not found"))
}

async fn get_session(State(state): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<SessionSnapshot> {
    state.sessions.get(&id).map(Json).ok_or_else(|| not_found(id))
}

/// Everything the agent did, step by step, plus summary stats.
async fn session_timeline(State(state): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Value> {
    let session = state.sessions.get(&id).ok_or_else(|| not_found(id))?;
    let timeline = state.sessions.timeline(&id).unwrap_or_default();
    let count = |kind: &str| timeline.iter().filter(|e| e.kind == kind).count();
    let page_ms: Vec<u64> = timeline.iter().filter_map(|e| e.duration_ms).collect();
    let stats = json!({
        "outcome": session.outcome,
        "maze_pages": count("maze"),
        "searches": count("search"),
        "hops": count("hop"),
        "normal_pages": count("normal"),
        "loops_detected": session.loops_detected,
        "unique_pages": session.unique_pages,
        "time_trapped_ms": session.trapped_ms,
        "session_ms": session.duration_ms,
        "quiet_for_ms": (Utc::now() - session.last_activity).num_milliseconds().max(0),
        "median_dwell_ms": session.median_dwell_ms,
        "avg_page_drip_ms": if page_ms.is_empty() { None } else { Some(page_ms.iter().sum::<u64>() / page_ms.len() as u64) },
        "signals": session.signals,
    });
    Ok(Json(json!({ "session": session, "stats": stats, "timeline": timeline })))
}

fn operator_transition(
    state: &AppState,
    id: Uuid,
    to: SessionState,
    action: &'static str,
    outcome: Option<Outcome>,
) -> ApiResult<Value> {
    let t = state
        .sessions
        .with_session(&id, |s| {
            let t = s.transition(to, action)?;
            if let Some(o) = outcome {
                s.outcome = o;
            }
            Ok::<_, SessionError>(t)
        })
        .ok_or(SessionError::NotFound(id))
        .and_then(|r| r)
        .map_err(|e| match e {
            SessionError::NotFound(_) => ApiError(StatusCode::NOT_FOUND, e.to_string()),
            SessionError::IllegalTransition { .. } => ApiError(StatusCode::CONFLICT, e.to_string()),
        })?;
    state.telemetry.transition(&t);
    state.telemetry.event(Some(id), "operator_action", json!({ "action": action, "from": t.from, "to": t.to }));
    Ok(Json(json!({ "session": id, "from": t.from, "to": t.to })))
}

/// Finish the session: every further request is sent to the exit destination.
async fn release_session(State(state): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Value> {
    operator_transition(&state, id, SessionState::Completed, "operator release", Some(Outcome::Released))
}

async fn block_session(State(state): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Value> {
    operator_transition(&state, id, SessionState::Blocked, "operator block", None)
}

async fn contain_session(State(state): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Value> {
    operator_transition(&state, id, SessionState::Contained, "operator contain", None)
}

#[derive(Deserialize)]
struct RedirectBody {
    destination: String,
}

/// Schedule a one-shot redirect for the session's next request (allowlist enforced).
async fn redirect_session(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<RedirectBody>,
) -> ApiResult<Value> {
    let dest = state
        .redirects
        .validate(&body.destination)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?;
    let scheduled = state.sessions.with_session(&id, |s| s.pending_redirect = Some(dest.clone())).is_some();
    if !scheduled {
        return Err(not_found(id));
    }
    state.telemetry.event(Some(id), "operator_redirect_scheduled", json!({ "destination": dest }));
    Ok(Json(json!({ "session": id, "pending_redirect": dest })))
}

async fn get_killswitch(State(state): State<AppState>) -> Json<Value> {
    Json(json!({ "engaged": state.killswitch_engaged() }))
}

#[derive(Deserialize)]
struct KillswitchBody {
    engaged: bool,
}

async fn set_killswitch(State(state): State<AppState>, Json(body): Json<KillswitchBody>) -> Json<Value> {
    let previous = state.killswitch_engaged();
    state.set_killswitch(body.engaged);
    if body.engaged {
        tracing::warn!("killswitch ENGAGED: the trap is disarmed");
    } else {
        tracing::warn!("killswitch released: the trap is armed");
    }
    state.telemetry.event(None, "killswitch", json!({ "engaged": body.engaged, "previous": previous }));
    Json(json!({ "engaged": body.engaged, "previous": previous }))
}

async fn get_config(State(state): State<AppState>) -> Json<Config> {
    Json(state.config.redacted())
}

#[derive(Deserialize)]
struct HistoryQuery {
    limit: Option<i64>,
}

fn database(state: &AppState) -> Result<&Database, ApiError> {
    state.db.as_ref().ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, "storage is disabled".into()))
}

fn internal(err: anyhow::Error) -> ApiError {
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{err:#}"))
}

fn history_limit(q: &HistoryQuery) -> i64 {
    q.limit.unwrap_or(100).clamp(1, 10_000)
}

async fn history_sessions(State(state): State<AppState>, Query(q): Query<HistoryQuery>) -> ApiResult<Value> {
    let rows = database(&state)?.recent_sessions(history_limit(&q)).await.map_err(internal)?;
    Ok(Json(json!({ "count": rows.len(), "sessions": rows })))
}

async fn history_session_requests(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(q): Query<HistoryQuery>,
) -> ApiResult<Value> {
    let rows = database(&state)?.session_requests(id, history_limit(&q)).await.map_err(internal)?;
    Ok(Json(json!({ "session": id, "count": rows.len(), "requests": rows })))
}

async fn history_events(State(state): State<AppState>, Query(q): Query<HistoryQuery>) -> ApiResult<Value> {
    let rows = database(&state)?.recent_events(history_limit(&q)).await.map_err(internal)?;
    Ok(Json(json!({ "count": rows.len(), "events": rows })))
}

async fn history_summary(State(state): State<AppState>) -> ApiResult<Value> {
    Ok(Json(database(&state)?.summary().await.map_err(internal)?))
}

/// Run the retention job now.
async fn prune_storage(State(state): State<AppState>) -> ApiResult<Value> {
    database(&state)?;
    let deleted = state.prune_storage().await.map_err(internal)?;
    Ok(Json(json!({ "deleted_rows": deleted, "retention_days": state.config.storage.retention_days })))
}
