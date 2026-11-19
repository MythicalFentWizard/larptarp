//! Session state machine and the centralized in-memory session cache.
//!
//! Every mutation of a session happens while holding that session's DashMap
//! shard lock (`with_session`), so concurrent requests from the same client
//! can never interleave half-applied state transitions. Persistence is
//! asynchronous: changed sessions are marked dirty and written to SQLite by a
//! background task, never on the request path.

use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use std::time::Instant;

use chrono::{DateTime, Utc};
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::navigation::NavState;
use crate::config::SessionConfig;

/// Request timestamps kept per session to estimate its request rate.
const RATE_WINDOW: usize = 16;
/// Page-to-page dwell samples kept per session.
const DWELL_SAMPLES: usize = 64;
const MAX_USER_AGENT_LEN: usize = 512;
const MAX_TIMELINE_PATH: usize = 300;

/// Truncate to at most `max` bytes on a char boundary.
pub fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    New,
    Classified,
    Normal,
    Contained,
    Completed,
    Expired,
    Blocked,
}

impl SessionState {
    pub const ALL: [SessionState; 7] = [
        SessionState::New,
        SessionState::Classified,
        SessionState::Normal,
        SessionState::Contained,
        SessionState::Completed,
        SessionState::Expired,
        SessionState::Blocked,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            SessionState::New => "new",
            SessionState::Classified => "classified",
            SessionState::Normal => "normal",
            SessionState::Contained => "contained",
            SessionState::Completed => "completed",
            SessionState::Expired => "expired",
            SessionState::Blocked => "blocked",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        Self::ALL.into_iter().find(|st| st.as_str().eq_ignore_ascii_case(s))
    }

    /// The legal edges of the state machine.
    ///
    /// ```text
    /// New -> Classified -> Normal ----> Contained -> Completed
    ///                  \_______________/     \          |
    ///   any live state -> Blocked              \-> Expired <- (idle / lifetime sweep)
    /// ```
    pub fn can_transition_to(self, next: SessionState) -> bool {
        use SessionState::*;
        matches!(
            (self, next),
            (New, Classified | Blocked | Expired)
                | (Classified, Normal | Contained | Blocked | Expired)
                | (Normal, Contained | Completed | Blocked | Expired)
                | (Contained, Completed | Blocked | Expired)
                | (Completed, Blocked | Expired)
                | (Blocked, Completed | Expired)
        )
    }
}

/// How a trap ended (or is going) for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Never contained.
    #[default]
    None,
    /// Contained and still requesting pages.
    Trapped,
    /// Contained, then went quiet: the client gave up.
    Abandoned,
    /// Hit `max_requests_per_session` and was sent to the exit.
    BudgetExhausted,
    /// Released by an operator.
    Released,
    Blocked,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::None => "none",
            Outcome::Trapped => "trapped",
            Outcome::Abandoned => "abandoned",
            Outcome::BudgetExhausted => "budget_exhausted",
            Outcome::Released => "released",
            Outcome::Blocked => "blocked",
        }
    }
}

/// What the client's browser (or lack of one) has revealed so far.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Behavior {
    /// Page navigations (documents, not assets).
    pub navigations: u32,
    /// HTML pages served that carried the browser checks.
    pub beacon_pages: u32,
    /// Check stylesheets / pixels fetched.
    pub assets_fetched: u32,
    /// JS beacons received.
    pub js_beacons: u32,
    pub webdriver: bool,
    pub headless: bool,
    /// Mouse, touch, scroll and key events reported by the beacon.
    pub interactions: u64,
    pub fast_navigations: u32,
    pub missing_referer: u32,
    #[serde(skip)]
    pub dwell_ms: VecDeque<u64>,
    #[serde(skip)]
    pub last_navigation: Option<Instant>,
}

impl Behavior {
    pub fn record_navigation(&mut self, now: Instant, has_referer: bool, min_dwell_ms: u64) {
        if let Some(prev) = self.last_navigation {
            let dwell = u64::try_from(now.saturating_duration_since(prev).as_millis()).unwrap_or(u64::MAX);
            if dwell < min_dwell_ms {
                self.fast_navigations += 1;
            }
            if self.dwell_ms.len() == DWELL_SAMPLES {
                self.dwell_ms.pop_front();
            }
            self.dwell_ms.push_back(dwell);
        }
        if self.navigations > 0 && !has_referer {
            self.missing_referer += 1;
        }
        self.navigations += 1;
        self.last_navigation = Some(now);
    }

    /// Median time between page navigations: how long the client "thinks" per step.
    pub fn median_dwell_ms(&self) -> Option<u64> {
        if self.dwell_ms.is_empty() {
            return None;
        }
        let mut v: Vec<u64> = self.dwell_ms.iter().copied().collect();
        v.sort_unstable();
        Some(v[v.len() / 2])
    }
}

/// One step in a session's history.
#[derive(Debug, Clone, Serialize)]
pub struct TimelineEntry {
    pub seq: u64,
    pub at: DateTime<Utc>,
    /// Milliseconds since the session started.
    pub offset_ms: i64,
    pub kind: &'static str,
    pub path: String,
    pub status: Option<u16>,
    /// For maze pages: how long the drip took (filled when the stream ends).
    pub duration_ms: Option<u64>,
    pub bytes: Option<u64>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Transition {
    pub session_id: Uuid,
    pub from: SessionState,
    pub to: SessionState,
    pub reason: String,
    pub at: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("session {0} not found")]
    NotFound(Uuid),
    #[error("illegal session transition {from:?} -> {to:?}")]
    IllegalTransition { from: SessionState, to: SessionState },
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: Uuid,
    pub state: SessionState,
    pub created_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    /// Last request or finished maze stream.
    pub last_activity: DateTime<Utc>,
    pub request_count: u64,
    /// Maze pages traversed by this session.
    pub navigation_depth: u32,
    pub fingerprint: u64,
    pub client_ip: IpAddr,
    pub user_agent: String,
    pub confidence: f32,
    pub signals: Vec<&'static str>,
    /// Header score of the latest page request (behaviour is added on top).
    pub header_score: f32,
    pub header_signals: Vec<&'static str>,
    pub behavior: Behavior,
    pub cookie_seen: bool,
    pub trap_requests: u64,
    pub searches: u32,
    /// Time this client spent waiting on maze pages ("enemy downtime").
    pub trapped_ms: u64,
    pub bytes_sent: u64,
    /// Consecutive redirect hops issued without serving a page.
    pub redirect_chain: u32,
    pub redirects_issued: u64,
    /// One-shot redirect scheduled by an operator.
    pub pending_redirect: Option<String>,
    pub nav: NavState,
    pub outcome: Outcome,
    pub ever_contained: bool,
    pub ever_blocked: bool,
    /// Contained straight away because its fingerprint was remembered.
    pub restored: bool,
    pub active_streams: u32,
    pub last_path: String,
    recent_hits: VecDeque<Instant>,
    timeline: VecDeque<TimelineEntry>,
    timeline_cap: usize,
    timeline_seq: u64,
    dirty: bool,
}

impl Session {
    pub fn new(
        id: Uuid,
        fingerprint: u64,
        client_ip: IpAddr,
        user_agent: &str,
        now: DateTime<Utc>,
        timeline_cap: usize,
    ) -> Self {
        Self {
            id,
            state: SessionState::New,
            created_at: now,
            last_seen: now,
            last_activity: now,
            request_count: 0,
            navigation_depth: 0,
            fingerprint,
            client_ip,
            user_agent: user_agent.chars().take(MAX_USER_AGENT_LEN).collect(),
            confidence: 0.0,
            signals: Vec::new(),
            header_score: 0.0,
            header_signals: Vec::new(),
            behavior: Behavior::default(),
            cookie_seen: false,
            trap_requests: 0,
            searches: 0,
            trapped_ms: 0,
            bytes_sent: 0,
            redirect_chain: 0,
            redirects_issued: 0,
            pending_redirect: None,
            nav: NavState::default(),
            outcome: Outcome::None,
            ever_contained: false,
            ever_blocked: false,
            restored: false,
            active_streams: 0,
            last_path: String::new(),
            recent_hits: VecDeque::with_capacity(RATE_WINDOW),
            timeline: VecDeque::new(),
            timeline_cap,
            timeline_seq: 0,
            dirty: true,
        }
    }

    /// Apply a state transition, refusing edges the state machine does not allow.
    pub fn transition(&mut self, to: SessionState, reason: impl Into<String>) -> Result<Transition, SessionError> {
        if !self.state.can_transition_to(to) {
            return Err(SessionError::IllegalTransition { from: self.state, to });
        }
        let reason = reason.into();
        let t = Transition { session_id: self.id, from: self.state, to, reason: reason.clone(), at: Utc::now() };
        self.state = to;
        match to {
            SessionState::Contained => {
                self.ever_contained = true;
                self.outcome = Outcome::Trapped;
            }
            SessionState::Blocked => {
                self.ever_blocked = true;
                self.outcome = Outcome::Blocked;
            }
            _ => {}
        }
        self.dirty = true;
        let note = format!("{} -> {}: {}", t.from.as_str(), to.as_str(), reason);
        let path = self.last_path.clone();
        self.push_timeline("transition", &path, None, Some(note));
        Ok(t)
    }

    /// Register an incoming request.
    pub fn touch(&mut self, now: DateTime<Utc>, instant: Instant) {
        self.last_seen = now;
        self.last_activity = now;
        self.request_count += 1;
        if self.recent_hits.len() == RATE_WINDOW {
            self.recent_hits.pop_front();
        }
        self.recent_hits.push_back(instant);
        self.dirty = true;
    }

    /// Requests per second over the last few requests (0 until there is enough data).
    pub fn recent_rps(&self) -> f64 {
        if self.recent_hits.len() < 4 {
            return 0.0;
        }
        let (Some(first), Some(last)) = (self.recent_hits.front(), self.recent_hits.back()) else {
            return 0.0;
        };
        let span = last.duration_since(*first).as_secs_f64();
        (self.recent_hits.len() - 1) as f64 / span.max(0.001)
    }

    /// Append to the timeline; returns the entry's sequence number.
    pub fn push_timeline(&mut self, kind: &'static str, path: &str, status: Option<u16>, note: Option<String>) -> u64 {
        self.timeline_seq += 1;
        if self.timeline_cap == 0 {
            return self.timeline_seq;
        }
        if self.timeline.len() >= self.timeline_cap {
            self.timeline.pop_front();
        }
        let at = Utc::now();
        self.timeline.push_back(TimelineEntry {
            seq: self.timeline_seq,
            at,
            offset_ms: (at - self.created_at).num_milliseconds().max(0),
            kind,
            path: clip(path, MAX_TIMELINE_PATH),
            status,
            duration_ms: None,
            bytes: None,
            note,
        });
        self.timeline_seq
    }

    /// Fill in how long a maze page took once its stream has ended.
    pub fn complete_timeline(&mut self, seq: u64, duration_ms: u64, bytes: u64) {
        if let Some(e) = self.timeline.iter_mut().rev().find(|e| e.seq == seq) {
            e.duration_ms = Some(duration_ms);
            e.bytes = Some(bytes);
        }
    }

    pub fn timeline(&self) -> Vec<TimelineEntry> {
        self.timeline.iter().cloned().collect()
    }

    pub fn snapshot(&self) -> SessionSnapshot {
        SessionSnapshot {
            id: self.id,
            state: self.state,
            outcome: self.outcome,
            created_at: self.created_at,
            last_seen: self.last_seen,
            last_activity: self.last_activity,
            duration_ms: (self.last_seen - self.created_at).num_milliseconds().max(0),
            request_count: self.request_count,
            trap_requests: self.trap_requests,
            searches: self.searches,
            navigation_depth: self.navigation_depth,
            max_path_depth: self.nav.max_path_depth,
            unique_pages: self.nav.unique_pages() as u64,
            loops_detected: self.nav.loops_detected,
            fingerprint: format!("{:016x}", self.fingerprint),
            client_ip: self.client_ip.to_string(),
            user_agent: self.user_agent.clone(),
            confidence: self.confidence,
            signals: self.signals.iter().map(|s| s.to_string()).collect(),
            behavior: self.behavior.clone(),
            median_dwell_ms: self.behavior.median_dwell_ms(),
            trapped_ms: self.trapped_ms,
            bytes_sent: self.bytes_sent,
            redirects_issued: self.redirects_issued,
            pending_redirect: self.pending_redirect.clone(),
            ever_contained: self.ever_contained,
            ever_blocked: self.ever_blocked,
            restored: self.restored,
            active_streams: self.active_streams,
            last_path: self.last_path.clone(),
        }
    }
}

/// Read-only copy of a session for the control plane and for persistence.
#[derive(Debug, Clone, Serialize)]
pub struct SessionSnapshot {
    pub id: Uuid,
    pub state: SessionState,
    pub outcome: Outcome,
    pub created_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub duration_ms: i64,
    pub request_count: u64,
    pub trap_requests: u64,
    pub searches: u32,
    pub navigation_depth: u32,
    pub max_path_depth: u32,
    pub unique_pages: u64,
    pub loops_detected: u32,
    pub fingerprint: String,
    pub client_ip: String,
    pub user_agent: String,
    pub confidence: f32,
    pub signals: Vec<String>,
    pub behavior: Behavior,
    pub median_dwell_ms: Option<u64>,
    pub trapped_ms: u64,
    pub bytes_sent: u64,
    pub redirects_issued: u64,
    pub pending_redirect: Option<String>,
    pub ever_contained: bool,
    pub ever_blocked: bool,
    pub restored: bool,
    pub active_streams: u32,
    pub last_path: String,
}

/// A fingerprint that was contained or blocked before.
#[derive(Debug, Clone, Copy)]
pub struct Remembered {
    pub blocked: bool,
    pub confidence: f32,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy)]
pub struct Resolved {
    pub id: Uuid,
    pub created: bool,
    pub via_cookie: bool,
}

/// Centralized owner of every live session.
///
/// Lock order: `by_fingerprint` may be held while touching `sessions`, never
/// the other way round, so the two maps cannot deadlock.
pub struct SessionManager {
    sessions: DashMap<Uuid, Session>,
    by_fingerprint: DashMap<u64, Uuid>,
    remembered: DashMap<u64, Remembered>,
    cfg: SessionConfig,
}

impl SessionManager {
    pub fn new(cfg: SessionConfig) -> Self {
        Self { sessions: DashMap::new(), by_fingerprint: DashMap::new(), remembered: DashMap::new(), cfg }
    }

    pub fn config(&self) -> &SessionConfig {
        &self.cfg
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    fn new_session(&self, fingerprint: u64, client_ip: IpAddr, user_agent: &str, now: DateTime<Utc>) -> Uuid {
        let id = Uuid::new_v4();
        let s = Session::new(id, fingerprint, client_ip, user_agent, now, self.cfg.timeline_max_entries);
        self.sessions.insert(id, s);
        id
    }

    /// Find the session for a request (cookie first, then fingerprint) or
    /// create one. Returns `None` when a new session would exceed
    /// `max_concurrent_sessions`.
    pub fn resolve(
        &self,
        cookie: Option<Uuid>,
        fingerprint: u64,
        client_ip: IpAddr,
        user_agent: &str,
        now: DateTime<Utc>,
    ) -> Option<Resolved> {
        if let Some(id) = cookie {
            if self.sessions.contains_key(&id) {
                return Some(Resolved { id, created: false, via_cookie: true });
            }
        }
        if let Some(id) = self.by_fingerprint.get(&fingerprint).map(|r| *r.value()) {
            if self.sessions.contains_key(&id) {
                return Some(Resolved { id, created: false, via_cookie: false });
            }
        }
        if self.sessions.len() >= self.cfg.max_concurrent_sessions {
            return None;
        }

        // Holding the fingerprint entry makes "look up or create" atomic, so two
        // simultaneous first requests from one client share one session.
        let mut created = false;
        let id = match self.by_fingerprint.entry(fingerprint) {
            Entry::Occupied(mut e) => {
                let existing = *e.get();
                if self.sessions.contains_key(&existing) {
                    existing
                } else {
                    let id = self.new_session(fingerprint, client_ip, user_agent, now);
                    e.insert(id);
                    created = true;
                    id
                }
            }
            Entry::Vacant(v) => {
                let id = self.new_session(fingerprint, client_ip, user_agent, now);
                v.insert(id);
                created = true;
                id
            }
        };
        Some(Resolved { id, created, via_cookie: false })
    }

    /// Find an existing session without creating one.
    pub fn lookup(&self, cookie: Option<Uuid>, fingerprint: u64) -> Option<Uuid> {
        if let Some(id) = cookie {
            if self.sessions.contains_key(&id) {
                return Some(id);
            }
        }
        self.by_fingerprint.get(&fingerprint).map(|r| *r.value()).filter(|id| self.sessions.contains_key(id))
    }

    /// Run `f` with exclusive access to one session. Everything done inside is
    /// atomic with respect to other requests for the same session. `f` must
    /// not call back into the manager.
    pub fn with_session<R>(&self, id: &Uuid, f: impl FnOnce(&mut Session) -> R) -> Option<R> {
        self.sessions.get_mut(id).map(|mut s| {
            s.dirty = true;
            f(&mut s)
        })
    }

    pub fn transition(&self, id: &Uuid, to: SessionState, reason: &str) -> Result<Transition, SessionError> {
        self.with_session(id, |s| s.transition(to, reason)).ok_or(SessionError::NotFound(*id))?
    }

    pub fn get(&self, id: &Uuid) -> Option<SessionSnapshot> {
        self.sessions.get(id).map(|s| s.snapshot())
    }

    pub fn timeline(&self, id: &Uuid) -> Option<Vec<TimelineEntry>> {
        self.sessions.get(id).map(|s| s.timeline())
    }

    /// Most recently active sessions first.
    pub fn list(&self, state: Option<SessionState>, limit: usize) -> Vec<SessionSnapshot> {
        let mut out: Vec<SessionSnapshot> = self
            .sessions
            .iter()
            .filter(|s| state.map_or(true, |st| s.state == st))
            .map(|s| s.snapshot())
            .collect();
        out.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        out.truncate(limit);
        out
    }

    pub fn count_by_state(&self) -> BTreeMap<&'static str, usize> {
        let mut counts = BTreeMap::new();
        for s in self.sessions.iter() {
            *counts.entry(s.state.as_str()).or_insert(0) += 1;
        }
        counts
    }

    pub fn count_by_outcome(&self) -> BTreeMap<&'static str, usize> {
        let mut counts = BTreeMap::new();
        for s in self.sessions.iter() {
            *counts.entry(s.outcome.as_str()).or_insert(0) += 1;
        }
        counts
    }

    // ------------------------------------------------------------ memory

    pub fn remember(&self, fingerprint: u64, r: Remembered) {
        if self.cfg.max_remembered == 0 {
            return;
        }
        if self.remembered.len() >= self.cfg.max_remembered && !self.remembered.contains_key(&fingerprint) {
            return;
        }
        self.remembered.insert(fingerprint, r);
    }

    pub fn recall(&self, fingerprint: u64) -> Option<Remembered> {
        self.remembered.get(&fingerprint).map(|r| *r.value())
    }

    pub fn remembered_count(&self) -> usize {
        self.remembered.len()
    }

    // ------------------------------------------------------- maintenance

    /// Mark contained sessions that went quiet as abandoned (the client gave up).
    pub fn mark_abandoned(&self, now: DateTime<Utc>, after_secs: u64) -> Vec<SessionSnapshot> {
        if after_secs == 0 {
            return Vec::new();
        }
        let after_ms = i64::try_from(after_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
        let mut out = Vec::new();
        for mut s in self.sessions.iter_mut() {
            let quiet_ms = (now - s.last_activity).num_milliseconds();
            if s.state == SessionState::Contained
                && s.outcome == Outcome::Trapped
                && s.active_streams == 0
                && quiet_ms >= after_ms
            {
                s.outcome = Outcome::Abandoned;
                s.dirty = true;
                let path = s.last_path.clone();
                s.push_timeline("abandoned", &path, None, Some(format!("no requests for {}s", quiet_ms / 1000)));
                out.push(s.snapshot());
            }
        }
        out
    }

    /// Expire sessions that are idle or too old, remove them from the cache
    /// and return their final snapshots (for persistence). Contained and
    /// blocked fingerprints are remembered.
    pub fn sweep(&self, now: DateTime<Utc>) -> Vec<(SessionSnapshot, Option<Transition>)> {
        let idle_ms = i64::try_from(self.cfg.idle_timeout_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
        let life_ms = i64::try_from(self.cfg.max_lifetime_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
        let is_stale = |s: &Session| {
            (now - s.last_seen).num_milliseconds() >= idle_ms || (now - s.created_at).num_milliseconds() >= life_ms
        };

        // Collect first; never hold a `sessions` lock while touching `by_fingerprint`.
        let stale: Vec<Uuid> = self.sessions.iter().filter(|s| is_stale(s.value())).map(|s| *s.key()).collect();

        let mut out = Vec::with_capacity(stale.len());
        for id in stale {
            if let Some((_, mut s)) = self.sessions.remove_if(&id, |_, s| is_stale(s)) {
                let reason = if (now - s.created_at).num_milliseconds() >= life_ms { "max lifetime reached" } else { "idle timeout" };
                let t = s.transition(SessionState::Expired, reason).ok();
                self.by_fingerprint.remove_if(&s.fingerprint, |_, v| *v == id);
                if s.ever_contained || s.ever_blocked {
                    self.remember(
                        s.fingerprint,
                        Remembered { blocked: s.outcome == Outcome::Blocked, confidence: s.confidence, last_seen: s.last_seen },
                    );
                }
                out.push((s.snapshot(), t));
            }
        }

        let keep_ms = i64::try_from(self.cfg.remember_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
        self.remembered.retain(|_, r| (now - r.last_seen).num_milliseconds() < keep_ms);
        out
    }

    /// Snapshots of sessions changed since the last call.
    pub fn take_dirty(&self) -> Vec<SessionSnapshot> {
        let mut out = Vec::new();
        for mut s in self.sessions.iter_mut() {
            if s.dirty {
                s.dirty = false;
                out.push(s.snapshot());
            }
        }
        out
    }

    pub fn snapshot_all(&self) -> Vec<SessionSnapshot> {
        self.sessions.iter().map(|s| s.snapshot()).collect()
    }
}
