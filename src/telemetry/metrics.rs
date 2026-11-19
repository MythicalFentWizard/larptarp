//! Counters, the telemetry pipeline into storage, and logging setup.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::Utc;
use serde::Serialize;
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use crate::config::{LogFormat, TelemetryConfig};
use crate::engine::session::{SessionSnapshot, SessionState, Transition};
use crate::storage::database::{EventRecord, RedirectRecord, RequestRecord, StorageEvent};

pub fn inc(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

pub fn add(counter: &AtomicU64, n: u64) {
    counter.fetch_add(n, Ordering::Relaxed);
}

macro_rules! counters {
    ($($name:ident => $help:literal),* $(,)?) => {
        #[derive(Debug, Default)]
        pub struct Metrics { $(pub $name: AtomicU64,)* }

        #[derive(Debug, Clone, Serialize)]
        pub struct MetricsSnapshot { $(pub $name: u64,)* }

        impl Metrics {
            pub fn snapshot(&self) -> MetricsSnapshot {
                MetricsSnapshot { $($name: self.$name.load(Ordering::Relaxed),)* }
            }

            /// Prometheus text exposition of every counter.
            pub fn render_prometheus(&self, out: &mut String) {
                $(
                    let _ = writeln!(out, "# HELP nepenthes_{} {}", stringify!($name), $help);
                    let _ = writeln!(out, "# TYPE nepenthes_{} counter", stringify!($name));
                    let _ = writeln!(out, "nepenthes_{} {}", stringify!($name), self.$name.load(Ordering::Relaxed));
                )*
            }
        }
    };
}

counters! {
    requests_total => "HTTP requests received by the tarpit listener",
    normal_requests => "Requests answered with normal site content",
    proxied_requests => "Normal requests forwarded to the upstream site",
    proxy_errors => "Normal requests the upstream site failed to answer",
    trap_requests => "Requests from contained sessions",
    trap_pages_served => "Maze pages started",
    searches_served => "Fake search result pages started",
    trap_streams_completed => "Maze pages delivered to the end",
    trap_streams_aborted => "Maze pages abandoned by the client mid-drip",
    trap_bytes_sent => "Bytes dripped to contained sessions",
    trapped_ms_total => "Milliseconds contained clients spent waiting on maze pages (enemy downtime)",
    redirects_hop => "Redirect hops issued inside the maze",
    redirects_exit => "Exit redirects issued to finished sessions",
    redirects_operator => "One-shot redirects scheduled by an operator and delivered",
    loops_detected => "Navigation loops detected",
    sessions_created => "Sessions created",
    sessions_contained => "Sessions moved into containment",
    sessions_restored => "Sessions contained on sight because their fingerprint was remembered",
    sessions_abandoned => "Contained sessions that went quiet (the client gave up)",
    sessions_resumed => "Abandoned sessions that came back",
    sessions_completed => "Sessions completed",
    sessions_expired => "Sessions expired",
    sessions_blocked => "Sessions blocked",
    assets_served => "Browser-check stylesheets and pixels served",
    beacons_received => "JavaScript beacons received",
    webdriver_detected => "Sessions whose browser reported navigator.webdriver",
    rate_limited => "Requests rejected by the per-IP rate limiter",
    overload_rejections => "Requests shed because a global limit was reached",
    killswitch_hits => "Maze requests answered while the killswitch was engaged",
    storage_dropped => "Telemetry records dropped because the storage queue was full",
    retention_deleted => "Stored rows deleted by the retention job",
}

/// Cheap to clone; handed to every request.
#[derive(Clone)]
pub struct Telemetry {
    pub metrics: Arc<Metrics>,
    tx: Option<mpsc::Sender<StorageEvent>>,
    log_requests: bool,
}

impl Telemetry {
    pub fn new(tx: Option<mpsc::Sender<StorageEvent>>, log_requests: bool) -> Self {
        Self { metrics: Arc::new(Metrics::default()), tx, log_requests }
    }

    /// Never blocks the request path: if the writer is behind, the record is dropped and counted.
    fn send(&self, event: StorageEvent) {
        if let Some(tx) = &self.tx {
            if tx.try_send(event).is_err() {
                inc(&self.metrics.storage_dropped);
            }
        }
    }

    pub fn session(&self, snapshot: SessionSnapshot) {
        self.send(StorageEvent::Session(Box::new(snapshot)));
    }

    pub fn transition(&self, t: &Transition) {
        let m = &self.metrics;
        match t.to {
            SessionState::Contained => {
                inc(&m.sessions_contained);
                tracing::info!(session = %t.session_id, reason = %t.reason, "session contained");
            }
            SessionState::Completed => {
                inc(&m.sessions_completed);
                tracing::info!(session = %t.session_id, reason = %t.reason, "session completed");
            }
            SessionState::Blocked => {
                inc(&m.sessions_blocked);
                tracing::info!(session = %t.session_id, reason = %t.reason, "session blocked");
            }
            SessionState::Expired => {
                inc(&m.sessions_expired);
                tracing::debug!(session = %t.session_id, reason = %t.reason, "session expired");
            }
            _ => tracing::debug!(
                session = %t.session_id,
                from = t.from.as_str(),
                to = t.to.as_str(),
                reason = %t.reason,
                "session transition"
            ),
        }
        self.send(StorageEvent::Transition(t.clone()));
    }

    pub fn request(&self, record: RequestRecord) {
        if self.log_requests {
            self.send(StorageEvent::Request(record));
        }
    }

    pub fn redirect(&self, session_id: Uuid, kind: &'static str, destination: &str, depth: u32) {
        self.send(StorageEvent::Redirect(RedirectRecord {
            session_id,
            at: Utc::now(),
            kind,
            destination: destination.to_string(),
            depth,
        }));
    }

    pub fn event(&self, session_id: Option<Uuid>, kind: &'static str, detail: Value) {
        self.send(StorageEvent::Event(EventRecord { session_id, at: Utc::now(), kind, detail }));
    }

    /// Wait until everything queued so far has been written.
    pub async fn flush(&self) {
        if let Some(tx) = &self.tx {
            let (ack, done) = oneshot::channel();
            if tx.send(StorageEvent::Flush(ack)).await.is_ok() {
                let _ = done.await;
            }
        }
    }
}

pub fn init_tracing(cfg: &TelemetryConfig) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cfg.log_level));
    let builder = tracing_subscriber::fmt().with_env_filter(filter).with_target(false);
    let _ = match cfg.log_format {
        LogFormat::Json => builder.json().try_init(),
        LogFormat::Pretty => builder.try_init(),
    };
}
