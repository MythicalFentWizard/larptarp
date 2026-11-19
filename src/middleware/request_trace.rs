//! Request tracing: assigns a request id, resolves the client IP once and
//! wraps the request in a `tracing` span.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use tracing::Instrument;

use crate::server::AppState;
use crate::telemetry::metrics::inc;

#[derive(Debug, Clone, Copy)]
pub struct RequestId(pub u64);

#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub IpAddr);

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

pub async fn trace(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    let ip = super::resolve_ip(&req, state.config.server.trust_forwarded_for);
    req.extensions_mut().insert(RequestId(id));
    req.extensions_mut().insert(ClientIp(ip));
    inc(&state.telemetry.metrics.requests_total);

    let span = tracing::debug_span!("request", id, method = %req.method(), path = %req.uri().path(), %ip);
    let started = Instant::now();
    let resp = next.run(req).instrument(span.clone()).await;
    span.in_scope(|| {
        tracing::debug!(
            status = resp.status().as_u16(),
            ms = started.elapsed().as_millis() as u64,
            "response headers sent"
        )
    });
    resp
}
