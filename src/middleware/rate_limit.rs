//! Per-IP token-bucket rate limiting.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;

use crate::config::RateLimitConfig;
use crate::server::AppState;
use crate::telemetry::metrics::inc;

struct Bucket {
    tokens: f64,
    last: Instant,
}

pub struct RateLimiter {
    enabled: bool,
    rate: f64,
    burst: f64,
    buckets: DashMap<IpAddr, Bucket>,
}

impl RateLimiter {
    pub fn new(cfg: &RateLimitConfig) -> Self {
        Self { enabled: cfg.enabled, rate: cfg.per_ip_rps, burst: cfg.burst.max(1.0), buckets: DashMap::new() }
    }

    /// Take one token for `ip`; on refusal returns how long until a token is available.
    pub fn check(&self, ip: IpAddr, now: Instant) -> Result<(), Duration> {
        if !self.enabled {
            return Ok(());
        }
        let mut b = self.buckets.entry(ip).or_insert(Bucket { tokens: self.burst, last: now });
        let elapsed = now.saturating_duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + elapsed * self.rate).min(self.burst);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64((1.0 - b.tokens) / self.rate))
        }
    }

    /// Forget clients that have been quiet for `idle`.
    pub fn sweep(&self, now: Instant, idle: Duration) {
        self.buckets.retain(|_, b| now.saturating_duration_since(b.last) < idle);
    }

    pub fn tracked(&self) -> usize {
        self.buckets.len()
    }
}

pub async fn rate_limit(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let ip = super::client_ip(&req, state.config.server.trust_forwarded_for);
    match state.limiter.check(ip, Instant::now()) {
        Ok(()) => next.run(req).await,
        Err(retry_after) => {
            inc(&state.telemetry.metrics.rate_limited);
            tracing::debug!(%ip, "rate limited");
            let secs = retry_after.as_secs_f64().ceil().max(1.0) as u64;
            (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, secs.to_string())], "Too Many Requests\n")
                .into_response()
        }
    }
}
