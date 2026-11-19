//! SQLite persistence.
//!
//! The HTTP path never touches the database. Handlers push records into a
//! bounded channel (`Telemetry`), and a single writer task batches them into
//! transactions. Active sessions live in memory and are snapshotted here
//! periodically, when they expire, and at shutdown.
//!
//! Tables: sessions, requests, transitions, events, redirects. The schema is
//! versioned with `PRAGMA user_version` and upgraded in place.

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Row, SqlitePool};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::engine::session::{Remembered, SessionSnapshot, Transition};

#[derive(Debug, Clone)]
pub struct RequestRecord {
    pub session_id: Uuid,
    pub at: DateTime<Utc>,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub route: &'static str,
    pub duration_ms: Option<u64>,
    pub bytes: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct EventRecord {
    pub session_id: Option<Uuid>,
    pub at: DateTime<Utc>,
    pub kind: &'static str,
    pub detail: Value,
}

#[derive(Debug, Clone)]
pub struct RedirectRecord {
    pub session_id: Uuid,
    pub at: DateTime<Utc>,
    pub kind: &'static str,
    pub destination: String,
    pub depth: u32,
}

pub enum StorageEvent {
    Session(Box<SessionSnapshot>),
    Request(RequestRecord),
    Transition(Transition),
    Event(EventRecord),
    Redirect(RedirectRecord),
    /// Write everything queued before this marker, then acknowledge.
    Flush(oneshot::Sender<()>),
}

/// Schema migrations; index + 1 is the `user_version` after applying.
const MIGRATIONS: &[&[&str]] = &[
    // v1: initial schema
    &[
        "CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            fingerprint TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            user_agent TEXT NOT NULL,
            state TEXT NOT NULL,
            confidence REAL NOT NULL,
            signals TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            duration_ms INTEGER NOT NULL,
            request_count INTEGER NOT NULL,
            trap_requests INTEGER NOT NULL,
            navigation_depth INTEGER NOT NULL,
            max_path_depth INTEGER NOT NULL,
            unique_pages INTEGER NOT NULL,
            loops_detected INTEGER NOT NULL,
            trapped_ms INTEGER NOT NULL,
            bytes_sent INTEGER NOT NULL,
            redirects_issued INTEGER NOT NULL
        )",
        "CREATE INDEX IF NOT EXISTS idx_sessions_last_seen ON sessions(last_seen)",
        "CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            ts TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            status INTEGER NOT NULL,
            route TEXT NOT NULL
        )",
        "CREATE INDEX IF NOT EXISTS idx_requests_session ON requests(session_id)",
        "CREATE TABLE IF NOT EXISTS transitions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            ts TEXT NOT NULL,
            from_state TEXT NOT NULL,
            to_state TEXT NOT NULL,
            reason TEXT NOT NULL
        )",
        "CREATE INDEX IF NOT EXISTS idx_transitions_session ON transitions(session_id)",
        "CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            ts TEXT NOT NULL,
            kind TEXT NOT NULL,
            detail TEXT NOT NULL
        )",
        "CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind)",
        "CREATE TABLE IF NOT EXISTS redirects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            ts TEXT NOT NULL,
            kind TEXT NOT NULL,
            destination TEXT NOT NULL,
            depth INTEGER NOT NULL
        )",
        "CREATE INDEX IF NOT EXISTS idx_redirects_session ON redirects(session_id)",
    ],
    // v2: outcomes, behaviour, restart memory, per-request timing, retention indexes
    &[
        "ALTER TABLE sessions ADD COLUMN outcome TEXT NOT NULL DEFAULT 'none'",
        "ALTER TABLE sessions ADD COLUMN ever_contained INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN ever_blocked INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN restored INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN searches INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN median_dwell_ms INTEGER",
        "ALTER TABLE sessions ADD COLUMN last_path TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE sessions ADD COLUMN behavior TEXT NOT NULL DEFAULT '{}'",
        "ALTER TABLE requests ADD COLUMN duration_ms INTEGER",
        "ALTER TABLE requests ADD COLUMN bytes INTEGER",
        "CREATE INDEX IF NOT EXISTS idx_sessions_fingerprint ON sessions(fingerprint)",
        "CREATE INDEX IF NOT EXISTS idx_requests_ts ON requests(ts)",
        "CREATE INDEX IF NOT EXISTS idx_transitions_ts ON transitions(ts)",
        "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)",
        "CREATE INDEX IF NOT EXISTS idx_redirects_ts ON redirects(ts)",
    ],
];

fn to_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

#[derive(Clone)]
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// Open (creating if needed) the database and bring the schema up to date.
    pub async fn connect(url: &str) -> Result<Self> {
        let in_memory = url.contains(":memory:") || url.contains("mode=memory");
        if !in_memory {
            let file = url.trim_start_matches("sqlite://").trim_start_matches("sqlite:");
            let file = file.split('?').next().unwrap_or(file);
            if let Some(dir) = Path::new(file).parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
            }
        }

        let mut opts = SqliteConnectOptions::from_str(url)
            .with_context(|| format!("invalid database_url `{url}`"))?
            .create_if_missing(true)
            .busy_timeout(Duration::from_secs(5));
        if !in_memory {
            opts = opts.journal_mode(SqliteJournalMode::Wal).synchronous(SqliteSynchronous::Normal);
        }

        // An in-memory database lives exactly as long as its single connection.
        let pool_opts = if in_memory {
            SqlitePoolOptions::new().max_connections(1).min_connections(1).idle_timeout(None).max_lifetime(None)
        } else {
            SqlitePoolOptions::new().max_connections(4)
        };
        let pool = pool_opts.connect_with(opts).await?;
        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    pub async fn migrate(&self) -> Result<()> {
        let current: i64 = sqlx::query("PRAGMA user_version").fetch_one(&self.pool).await?.try_get(0)?;
        for (i, statements) in MIGRATIONS.iter().enumerate() {
            let version = i as i64 + 1;
            if version <= current {
                continue;
            }
            let mut tx = self.pool.begin().await?;
            for stmt in statements.iter() {
                sqlx::query(stmt).execute(&mut *tx).await.with_context(|| format!("schema migration v{version}"))?;
            }
            let pragma = format!("PRAGMA user_version = {version}");
            sqlx::query(&pragma).execute(&mut *tx).await?;
            tx.commit().await?;
        }
        Ok(())
    }

    /// Write a batch of records in one transaction.
    pub async fn write_batch(&self, batch: &[StorageEvent]) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        for event in batch {
            match event {
                StorageEvent::Session(s) => {
                    sqlx::query(
                        "INSERT INTO sessions (id, fingerprint, client_ip, user_agent, state, confidence, signals,
                            created_at, last_seen, duration_ms, request_count, trap_requests, navigation_depth,
                            max_path_depth, unique_pages, loops_detected, trapped_ms, bytes_sent, redirects_issued,
                            outcome, ever_contained, ever_blocked, restored, searches, median_dwell_ms, last_path, behavior)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                         ON CONFLICT(id) DO UPDATE SET
                            state = excluded.state, confidence = excluded.confidence, signals = excluded.signals,
                            last_seen = excluded.last_seen, duration_ms = excluded.duration_ms,
                            request_count = excluded.request_count, trap_requests = excluded.trap_requests,
                            navigation_depth = excluded.navigation_depth, max_path_depth = excluded.max_path_depth,
                            unique_pages = excluded.unique_pages, loops_detected = excluded.loops_detected,
                            trapped_ms = excluded.trapped_ms, bytes_sent = excluded.bytes_sent,
                            redirects_issued = excluded.redirects_issued, outcome = excluded.outcome,
                            ever_contained = excluded.ever_contained, ever_blocked = excluded.ever_blocked,
                            restored = excluded.restored, searches = excluded.searches,
                            median_dwell_ms = excluded.median_dwell_ms, last_path = excluded.last_path,
                            behavior = excluded.behavior",
                    )
                    .bind(s.id.to_string())
                    .bind(s.fingerprint.clone())
                    .bind(s.client_ip.clone())
                    .bind(s.user_agent.clone())
                    .bind(s.state.as_str())
                    .bind(f64::from(s.confidence))
                    .bind(serde_json::to_string(&s.signals).unwrap_or_else(|_| "[]".into()))
                    .bind(s.created_at.to_rfc3339())
                    .bind(s.last_seen.to_rfc3339())
                    .bind(s.duration_ms)
                    .bind(to_i64(s.request_count))
                    .bind(to_i64(s.trap_requests))
                    .bind(i64::from(s.navigation_depth))
                    .bind(i64::from(s.max_path_depth))
                    .bind(to_i64(s.unique_pages))
                    .bind(i64::from(s.loops_detected))
                    .bind(to_i64(s.trapped_ms))
                    .bind(to_i64(s.bytes_sent))
                    .bind(to_i64(s.redirects_issued))
                    .bind(s.outcome.as_str())
                    .bind(s.ever_contained)
                    .bind(s.ever_blocked)
                    .bind(s.restored)
                    .bind(i64::from(s.searches))
                    .bind(s.median_dwell_ms.map(to_i64))
                    .bind(s.last_path.clone())
                    .bind(serde_json::to_string(&s.behavior).unwrap_or_else(|_| "{}".into()))
                    .execute(&mut *tx)
                    .await?;
                }
                StorageEvent::Request(r) => {
                    sqlx::query(
                        "INSERT INTO requests (session_id, ts, method, path, status, route, duration_ms, bytes)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    )
                    .bind(r.session_id.to_string())
                    .bind(r.at.to_rfc3339())
                    .bind(r.method.clone())
                    .bind(r.path.clone())
                    .bind(i64::from(r.status))
                    .bind(r.route)
                    .bind(r.duration_ms.map(to_i64))
                    .bind(r.bytes.map(to_i64))
                    .execute(&mut *tx)
                    .await?;
                }
                StorageEvent::Transition(t) => {
                    sqlx::query("INSERT INTO transitions (session_id, ts, from_state, to_state, reason) VALUES (?, ?, ?, ?, ?)")
                        .bind(t.session_id.to_string())
                        .bind(t.at.to_rfc3339())
                        .bind(t.from.as_str())
                        .bind(t.to.as_str())
                        .bind(t.reason.clone())
                        .execute(&mut *tx)
                        .await?;
                }
                StorageEvent::Event(e) => {
                    sqlx::query("INSERT INTO events (session_id, ts, kind, detail) VALUES (?, ?, ?, ?)")
                        .bind(e.session_id.map(|id| id.to_string()))
                        .bind(e.at.to_rfc3339())
                        .bind(e.kind)
                        .bind(e.detail.to_string())
                        .execute(&mut *tx)
                        .await?;
                }
                StorageEvent::Redirect(r) => {
                    sqlx::query("INSERT INTO redirects (session_id, ts, kind, destination, depth) VALUES (?, ?, ?, ?, ?)")
                        .bind(r.session_id.to_string())
                        .bind(r.at.to_rfc3339())
                        .bind(r.kind)
                        .bind(r.destination.clone())
                        .bind(i64::from(r.depth))
                        .execute(&mut *tx)
                        .await?;
                }
                StorageEvent::Flush(_) => {}
            }
        }
        tx.commit().await
    }

    /// Fingerprints that were contained or blocked since `since`, oldest first
    /// (so the newest record for a fingerprint wins when inserted in order).
    pub async fn load_remembered(&self, since: DateTime<Utc>, limit: i64) -> Result<Vec<(u64, Remembered)>> {
        let rows = sqlx::query(
            "SELECT fingerprint, outcome, confidence, last_seen FROM sessions
             WHERE (ever_contained = 1 OR ever_blocked = 1) AND last_seen >= ?
             ORDER BY last_seen DESC LIMIT ?",
        )
        .bind(since.to_rfc3339())
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        let mut out: Vec<(u64, Remembered)> = rows
            .iter()
            .filter_map(|r| {
                let fp = u64::from_str_radix(&r.try_get::<String, _>("fingerprint").ok()?, 16).ok()?;
                let outcome: String = r.try_get("outcome").ok()?;
                let confidence: f64 = r.try_get("confidence").ok()?;
                let last_seen: String = r.try_get("last_seen").ok()?;
                let last_seen = DateTime::parse_from_rfc3339(&last_seen).ok()?.with_timezone(&Utc);
                Some((fp, Remembered { blocked: outcome == "blocked", confidence: confidence as f32, last_seen }))
            })
            .collect();
        out.reverse();
        Ok(out)
    }

    /// Delete rows older than `before`. Returns the number of rows removed.
    pub async fn prune(&self, before: DateTime<Utc>) -> Result<u64> {
        let cutoff = before.to_rfc3339();
        let mut total = 0;
        for (table, column) in [
            ("requests", "ts"),
            ("transitions", "ts"),
            ("events", "ts"),
            ("redirects", "ts"),
            ("sessions", "last_seen"),
        ] {
            let sql = format!("DELETE FROM {table} WHERE {column} < ?");
            total += sqlx::query(&sql).bind(cutoff.as_str()).execute(&self.pool).await?.rows_affected();
        }
        Ok(total)
    }

    /// Most recently active persisted sessions.
    pub async fn recent_sessions(&self, limit: i64) -> Result<Vec<Value>> {
        let rows = sqlx::query(
            "SELECT id, state, outcome, client_ip, user_agent, confidence, signals, created_at, last_seen,
                    duration_ms, request_count, trap_requests, searches, navigation_depth, unique_pages,
                    loops_detected, trapped_ms, bytes_sent, redirects_issued, restored, median_dwell_ms, last_path
             FROM sessions ORDER BY last_seen DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                let signals: String = r.try_get("signals")?;
                Ok(json!({
                    "id": r.try_get::<String, _>("id")?,
                    "state": r.try_get::<String, _>("state")?,
                    "outcome": r.try_get::<String, _>("outcome")?,
                    "client_ip": r.try_get::<String, _>("client_ip")?,
                    "user_agent": r.try_get::<String, _>("user_agent")?,
                    "confidence": r.try_get::<f64, _>("confidence")?,
                    "signals": serde_json::from_str::<Value>(&signals).unwrap_or(Value::Null),
                    "created_at": r.try_get::<String, _>("created_at")?,
                    "last_seen": r.try_get::<String, _>("last_seen")?,
                    "duration_ms": r.try_get::<i64, _>("duration_ms")?,
                    "request_count": r.try_get::<i64, _>("request_count")?,
                    "trap_requests": r.try_get::<i64, _>("trap_requests")?,
                    "searches": r.try_get::<i64, _>("searches")?,
                    "navigation_depth": r.try_get::<i64, _>("navigation_depth")?,
                    "unique_pages": r.try_get::<i64, _>("unique_pages")?,
                    "loops_detected": r.try_get::<i64, _>("loops_detected")?,
                    "trapped_ms": r.try_get::<i64, _>("trapped_ms")?,
                    "bytes_sent": r.try_get::<i64, _>("bytes_sent")?,
                    "redirects_issued": r.try_get::<i64, _>("redirects_issued")?,
                    "restored": r.try_get::<bool, _>("restored")?,
                    "median_dwell_ms": r.try_get::<Option<i64>, _>("median_dwell_ms")?,
                    "last_path": r.try_get::<String, _>("last_path")?,
                }))
            })
            .collect()
    }

    /// Stored requests of one session, newest first.
    pub async fn session_requests(&self, session_id: Uuid, limit: i64) -> Result<Vec<Value>> {
        let rows = sqlx::query(
            "SELECT ts, method, path, status, route, duration_ms, bytes FROM requests
             WHERE session_id = ? ORDER BY id DESC LIMIT ?",
        )
        .bind(session_id.to_string())
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(json!({
                    "ts": r.try_get::<String, _>("ts")?,
                    "method": r.try_get::<String, _>("method")?,
                    "path": r.try_get::<String, _>("path")?,
                    "status": r.try_get::<i64, _>("status")?,
                    "route": r.try_get::<String, _>("route")?,
                    "duration_ms": r.try_get::<Option<i64>, _>("duration_ms")?,
                    "bytes": r.try_get::<Option<i64>, _>("bytes")?,
                }))
            })
            .collect()
    }

    pub async fn recent_events(&self, limit: i64) -> Result<Vec<Value>> {
        let rows = sqlx::query("SELECT session_id, ts, kind, detail FROM events ORDER BY id DESC LIMIT ?")
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|r| {
                let detail: String = r.try_get("detail")?;
                Ok(json!({
                    "session_id": r.try_get::<Option<String>, _>("session_id")?,
                    "ts": r.try_get::<String, _>("ts")?,
                    "kind": r.try_get::<String, _>("kind")?,
                    "detail": serde_json::from_str::<Value>(&detail).unwrap_or(Value::String(detail)),
                }))
            })
            .collect()
    }

    /// Totals across everything ever persisted.
    pub async fn summary(&self) -> Result<Value> {
        let totals = sqlx::query(
            "SELECT COUNT(*) AS sessions,
                    COALESCE(SUM(trapped_ms), 0) AS trapped_ms,
                    COALESCE(SUM(trap_requests), 0) AS trap_requests,
                    COALESCE(SUM(bytes_sent), 0) AS bytes_sent,
                    COALESCE(SUM(loops_detected), 0) AS loops_detected,
                    COALESCE(SUM(ever_contained), 0) AS ever_contained
             FROM sessions",
        )
        .fetch_one(&self.pool)
        .await?;
        let requests: i64 = sqlx::query("SELECT COUNT(*) AS n FROM requests").fetch_one(&self.pool).await?.try_get("n")?;
        let group = |column: &'static str| {
            let sql = format!("SELECT {column} AS k, COUNT(*) AS n FROM sessions GROUP BY {column}");
            let pool = self.pool.clone();
            async move {
                sqlx::query(&sql)
                    .fetch_all(&pool)
                    .await?
                    .iter()
                    .map(|r| Ok((r.try_get::<String, _>("k")?, Value::from(r.try_get::<i64, _>("n")?))))
                    .collect::<Result<serde_json::Map<String, Value>>>()
            }
        };
        let by_state = group("state").await?;
        let by_outcome = group("outcome").await?;
        let trapped_ms: i64 = totals.try_get("trapped_ms")?;
        Ok(json!({
            "sessions": totals.try_get::<i64, _>("sessions")?,
            "sessions_ever_contained": totals.try_get::<i64, _>("ever_contained")?,
            "requests": requests,
            "trap_requests": totals.try_get::<i64, _>("trap_requests")?,
            "bytes_sent": totals.try_get::<i64, _>("bytes_sent")?,
            "loops_detected": totals.try_get::<i64, _>("loops_detected")?,
            "trapped_ms": trapped_ms,
            "enemy_downtime_hours": trapped_ms as f64 / 3_600_000.0,
            "by_state": by_state,
            "by_outcome": by_outcome,
        }))
    }
}

/// Single writer: batches records into transactions every `flush_every` or
/// whenever `batch_size` records are queued.
pub fn spawn_writer(
    db: Database,
    mut rx: mpsc::Receiver<StorageEvent>,
    batch_size: usize,
    flush_every: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf: Vec<StorageEvent> = Vec::with_capacity(batch_size);
        let mut tick = tokio::time::interval(flush_every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                msg = rx.recv() => match msg {
                    Some(StorageEvent::Flush(ack)) => {
                        flush(&db, &mut buf).await;
                        let _ = ack.send(());
                    }
                    Some(event) => {
                        buf.push(event);
                        if buf.len() >= batch_size {
                            flush(&db, &mut buf).await;
                        }
                    }
                    None => {
                        flush(&db, &mut buf).await;
                        break;
                    }
                },
                _ = tick.tick() => flush(&db, &mut buf).await,
            }
        }
    })
}

async fn flush(db: &Database, buf: &mut Vec<StorageEvent>) {
    if buf.is_empty() {
        return;
    }
    if let Err(err) = db.write_batch(buf).await {
        tracing::error!(error = %err, records = buf.len(), "failed to persist telemetry batch");
    }
    buf.clear();
}
