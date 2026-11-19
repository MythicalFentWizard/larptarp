//! Shared state, background maintenance and the two listeners.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::engine::redirect::RedirectController;
use crate::engine::session::SessionManager;
use crate::engine::tarpit::Tarpit;
use crate::middleware::rate_limit::RateLimiter;
use crate::storage::database::{spawn_writer, Database};
use crate::telemetry::metrics::{add, inc, Telemetry};
use crate::{control, proxy, routes};

/// Everything a request handler needs. Cheap to clone.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub sessions: Arc<SessionManager>,
    pub tarpit: Arc<Tarpit>,
    pub redirects: Arc<RedirectController>,
    pub limiter: Arc<RateLimiter>,
    pub telemetry: Telemetry,
    pub killswitch: Arc<AtomicBool>,
    pub db: Option<Database>,
    /// Client for `normal.upstream_url`, when legitimate traffic is proxied.
    pub proxy: Option<reqwest::Client>,
    pub started_at: DateTime<Utc>,
}

fn secs_ago(secs: u64) -> DateTime<Utc> {
    TimeDelta::try_seconds(i64::try_from(secs).unwrap_or(i64::MAX))
        .and_then(|d| Utc::now().checked_sub_signed(d))
        .unwrap_or(DateTime::<Utc>::MIN_UTC)
}

impl AppState {
    /// Validate the config, open storage and build every component.
    /// Spawns the storage writer, so it must run inside a Tokio runtime.
    pub async fn build(mut config: Config) -> Result<Self> {
        config.normalize();
        config.validate()?;
        if config.server.secret == "change-me" {
            warn!("server.secret is still the default; set it so your maze differs from every other deployment");
        }
        if config.control.enabled && config.control.token.is_none() && !config.control.bind.ip().is_loopback() {
            warn!(bind = %config.control.bind, "control plane is reachable off-host without a token");
        }

        let redirects = RedirectController::new(&config.redirect).context("invalid [redirect] config")?;
        let tarpit = Tarpit::new(&config.tarpit, &config.limits, &config.server.secret, config.classifier.beacon)
            .context("building the maze")?;
        let proxy = match &config.normal.upstream_url {
            Some(_) => Some(proxy::build_client().context("building the upstream site client")?),
            None => None,
        };
        let sessions = SessionManager::new(config.session.clone());

        let (db, telemetry) = if config.storage.enabled {
            let db = Database::connect(&config.storage.database_url)
                .await
                .with_context(|| format!("opening database {}", config.storage.database_url))?;
            // Fingerprints contained or blocked before a restart are trapped on sight.
            let since = secs_ago(config.session.remember_secs);
            let limit = i64::try_from(config.session.max_remembered).unwrap_or(i64::MAX);
            let remembered = db.load_remembered(since, limit).await.context("loading remembered fingerprints")?;
            if !remembered.is_empty() {
                info!(count = remembered.len(), "remembered contained/blocked fingerprints from earlier runs");
            }
            for (fp, r) in remembered {
                sessions.remember(fp, r);
            }
            let (tx, rx) = mpsc::channel(config.storage.channel_capacity);
            spawn_writer(
                db.clone(),
                rx,
                config.storage.batch_size,
                Duration::from_millis(config.storage.flush_interval_ms.max(10)),
            );
            (Some(db), Telemetry::new(Some(tx), config.storage.log_requests))
        } else {
            (None, Telemetry::new(None, false))
        };

        Ok(Self {
            sessions: Arc::new(sessions),
            tarpit: Arc::new(tarpit),
            redirects: Arc::new(redirects),
            limiter: Arc::new(RateLimiter::new(&config.rate_limit)),
            killswitch: Arc::new(AtomicBool::new(config.limits.killswitch)),
            telemetry,
            db,
            proxy,
            started_at: Utc::now(),
            config: Arc::new(config),
        })
    }

    pub fn killswitch_engaged(&self) -> bool {
        self.killswitch.load(Ordering::Relaxed)
    }

    pub fn set_killswitch(&self, engaged: bool) {
        self.killswitch.store(engaged, Ordering::Relaxed);
    }

    /// Queue snapshots of every session changed since the last call.
    pub fn persist_dirty_sessions(&self) -> usize {
        let snapshots = self.sessions.take_dirty();
        let n = snapshots.len();
        for s in snapshots {
            self.telemetry.session(s);
        }
        n
    }

    /// Expire idle / too-old sessions and persist their final state.
    pub fn sweep_sessions(&self) -> usize {
        let expired = self.sessions.sweep(Utc::now());
        let n = expired.len();
        for (snapshot, transition) in expired {
            if let Some(t) = transition {
                self.telemetry.transition(&t);
            }
            self.telemetry.session(snapshot);
        }
        n
    }

    /// Record contained clients that stopped requesting pages: they gave up.
    pub fn check_abandoned(&self, now: DateTime<Utc>) -> usize {
        let abandoned = self.sessions.mark_abandoned(now, self.config.session.abandon_after_secs);
        let n = abandoned.len();
        for s in abandoned {
            inc(&self.telemetry.metrics.sessions_abandoned);
            info!(
                session = %s.id,
                trapped_secs = s.trapped_ms / 1000,
                pages = s.navigation_depth,
                unique_pages = s.unique_pages,
                loops = s.loops_detected,
                last_path = %s.last_path,
                "agent gave up"
            );
            self.telemetry.event(
                Some(s.id),
                "abandoned",
                json!({
                    "trapped_ms": s.trapped_ms,
                    "session_ms": s.duration_ms,
                    "navigation_depth": s.navigation_depth,
                    "unique_pages": s.unique_pages,
                    "searches": s.searches,
                    "loops_detected": s.loops_detected,
                    "median_dwell_ms": s.median_dwell_ms,
                    "last_path": s.last_path,
                }),
            );
            self.telemetry.session(s);
        }
        n
    }

    /// Delete stored rows older than `storage.retention_days`.
    pub async fn prune_storage(&self) -> Result<u64> {
        let (Some(db), days) = (&self.db, self.config.storage.retention_days) else {
            return Ok(0);
        };
        if days == 0 {
            return Ok(0);
        }
        let deleted = db.prune(secs_ago(days.saturating_mul(86_400))).await?;
        add(&self.telemetry.metrics.retention_deleted, deleted);
        if deleted > 0 {
            info!(deleted, retention_days = days, "pruned old telemetry");
        }
        Ok(deleted)
    }
}

/// Periodic cleanup (expiry, abandonment, rate-limit buckets), persistence
/// and retention.
pub fn spawn_maintenance(state: AppState, mut shutdown: watch::Receiver<bool>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut sweep = tokio::time::interval(Duration::from_secs(state.config.session.cleanup_interval_secs.max(1)));
        let mut persist = tokio::time::interval(Duration::from_secs(state.config.storage.persist_interval_secs.max(1)));
        let mut retention = tokio::time::interval(Duration::from_secs(3_600));
        for timer in [&mut sweep, &mut persist, &mut retention] {
            timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
        }
        loop {
            tokio::select! {
                _ = sweep.tick() => {
                    state.check_abandoned(Utc::now());
                    let expired = state.sweep_sessions();
                    if expired > 0 {
                        tracing::debug!(expired, "session sweep");
                    }
                    state.limiter.sweep(Instant::now(), Duration::from_secs(300));
                }
                _ = persist.tick() => {
                    state.persist_dirty_sessions();
                }
                _ = retention.tick() => {
                    if let Err(err) = state.prune_storage().await {
                        warn!(error = %err, "retention job failed");
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    })
}

async fn wait_for_shutdown(mut rx: watch::Receiver<bool>) {
    let _ = rx.wait_for(|stop| *stop).await;
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

/// Run the tarpit and the control plane until Ctrl+C.
pub async fn run(config: Config) -> Result<()> {
    let state = AppState::build(config).await?;
    let cfg = state.config.clone();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let maintenance = spawn_maintenance(state.clone(), shutdown_rx.clone());

    let listener = TcpListener::bind(cfg.server.bind)
        .await
        .with_context(|| format!("binding tarpit listener on {}", cfg.server.bind))?;
    let app = routes::app_router(state.clone());
    let rx = shutdown_rx.clone();
    let mut data_plane = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(wait_for_shutdown(rx))
            .await
    });
    info!(addr = %cfg.server.bind, maze = %cfg.tarpit.prefix, "tarpit listening");
    if let Some(up) = &cfg.normal.upstream_url {
        info!(upstream = %up, "normal traffic is proxied to the upstream site");
    }

    let control_plane = if cfg.control.enabled {
        let listener = TcpListener::bind(cfg.control.bind)
            .await
            .with_context(|| format!("binding control plane on {}", cfg.control.bind))?;
        let app = control::control_router(state.clone());
        let rx = shutdown_rx.clone();
        info!(addr = %cfg.control.bind, "control plane listening (dashboard at /)");
        Some(tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
                .with_graceful_shutdown(wait_for_shutdown(rx))
                .await
        }))
    } else {
        None
    };

    if state.killswitch_engaged() {
        warn!("killswitch is ENGAGED at startup: the trap is disarmed");
    }

    let stopped_early = tokio::select! {
        _ = shutdown_signal() => {
            info!("shutdown requested; draining open connections");
            false
        }
        res = &mut data_plane => {
            error!(result = ?res, "tarpit listener stopped unexpectedly");
            true
        }
    };

    let _ = shutdown_tx.send(true);
    let grace = Duration::from_secs(cfg.server.shutdown_grace_secs);
    let drain = async {
        if !stopped_early {
            let _ = data_plane.await;
        }
        if let Some(control_plane) = control_plane {
            let _ = control_plane.await;
        }
    };
    if tokio::time::timeout(grace, drain).await.is_err() {
        warn!("grace period elapsed with maze streams still open; closing anyway");
    }
    let _ = maintenance.await;

    // Final persistence of everything still in memory.
    for snapshot in state.sessions.snapshot_all() {
        state.telemetry.session(snapshot);
    }
    if tokio::time::timeout(Duration::from_secs(5), state.telemetry.flush()).await.is_err() {
        warn!("timed out flushing telemetry to storage");
    }
    info!("stopped");
    Ok(())
}
