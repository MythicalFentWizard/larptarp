mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use axum::http::header::{ACCEPT, ACCEPT_LANGUAGE, SET_COOKIE, USER_AGENT};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use chrono::{TimeDelta, Utc};
use common::*;
use nepenthes::config::{ClassifierMode, Config, SessionConfig};
use nepenthes::engine::navigation::{path_hash, NavOutcome, NavState};
use nepenthes::engine::session::{SessionManager, SessionState};
use nepenthes::middleware::classifier::{score_request, Hints};
use tower::ServiceExt;

const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7));

#[test]
fn state_machine_allows_only_legal_transitions() {
    use SessionState::*;
    assert!(New.can_transition_to(Classified));
    assert!(Classified.can_transition_to(Normal));
    assert!(Classified.can_transition_to(Contained));
    assert!(Normal.can_transition_to(Contained));
    assert!(Contained.can_transition_to(Completed));
    assert!(Contained.can_transition_to(Expired));
    assert!(Contained.can_transition_to(Blocked));

    assert!(!New.can_transition_to(Contained), "must be classified first");
    assert!(!Contained.can_transition_to(Normal), "containment is sticky");
    assert!(!Completed.can_transition_to(Contained));
    assert!(!Expired.can_transition_to(Classified), "expired is terminal");
    assert!(!Contained.can_transition_to(Contained));
}

#[test]
fn illegal_transitions_are_rejected_without_changing_state() {
    let mgr = SessionManager::new(SessionConfig::default());
    let id = mgr.resolve(None, 1, IP, "ua", Utc::now()).unwrap().id;
    let t = mgr.transition(&id, SessionState::Classified, "test").unwrap();
    assert_eq!((t.from, t.to), (SessionState::New, SessionState::Classified));
    assert!(mgr.transition(&id, SessionState::Completed, "skip ahead").is_err());
    assert_eq!(mgr.get(&id).unwrap().state, SessionState::Classified);
}

#[test]
fn sessions_are_reused_by_fingerprint_and_cookie() {
    let mgr = SessionManager::new(SessionConfig::default());
    let now = Utc::now();
    let a = mgr.resolve(None, 42, IP, "agent", now).unwrap();
    assert!(a.created);
    let b = mgr.resolve(None, 42, IP, "agent", now).unwrap();
    assert!(!b.created);
    assert_eq!(a.id, b.id);
    let c = mgr.resolve(Some(a.id), 99, IP, "agent", now).unwrap();
    assert_eq!(c.id, a.id, "a valid cookie wins over a changed fingerprint");
    assert!(c.via_cookie);
    assert_eq!(mgr.len(), 1);
}

#[test]
fn session_cap_rejects_new_sessions_but_keeps_existing_ones() {
    let mgr = SessionManager::new(SessionConfig { max_concurrent_sessions: 2, ..SessionConfig::default() });
    let now = Utc::now();
    assert!(mgr.resolve(None, 1, IP, "a", now).is_some());
    assert!(mgr.resolve(None, 2, IP, "b", now).is_some());
    assert!(mgr.resolve(None, 3, IP, "c", now).is_none());
    assert!(mgr.resolve(None, 1, IP, "a", now).is_some());
}

#[test]
fn idle_sessions_expire_on_sweep() {
    let mgr = SessionManager::new(SessionConfig { idle_timeout_secs: 60, ..SessionConfig::default() });
    let now = Utc::now();
    let id = mgr.resolve(None, 7, IP, "a", now).unwrap().id;

    assert!(mgr.sweep(now + TimeDelta::try_seconds(30).unwrap()).is_empty());
    let expired = mgr.sweep(now + TimeDelta::try_seconds(61).unwrap());
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].0.state, SessionState::Expired);
    assert!(expired[0].1.is_some(), "expiry is recorded as a transition");
    assert!(mgr.get(&id).is_none());
    assert!(mgr.resolve(None, 7, IP, "a", now).unwrap().created, "fingerprint is free again");
}

#[test]
fn loop_detection_fires_at_threshold() {
    let mut nav = NavState::default();
    let a = path_hash("/archive/a");
    let b = path_hash("/archive/b");
    assert_eq!(nav.record(a, 16, 3), NavOutcome::Fresh);
    assert_eq!(nav.record(b, 16, 3), NavOutcome::Fresh);
    assert_eq!(nav.record(a, 16, 3), NavOutcome::Revisit { hits: 2 });
    assert_eq!(nav.record(a, 16, 3), NavOutcome::Loop { hits: 3 });
    assert_eq!(nav.loops_detected, 1);
    assert_eq!(nav.unique_pages(), 2);
    assert_eq!(path_hash("/archive/a/"), a, "trailing slash is the same page");
}

#[test]
fn classifier_scores_bots_above_browsers() {
    let cfg = Config::default();
    let mut bot = HeaderMap::new();
    bot.insert(USER_AGENT, HeaderValue::from_static(BOT_UA));
    bot.insert(ACCEPT, HeaderValue::from_static("*/*"));
    let bot_score = score_request(&cfg.classifier, &bot, "/", "/archive", &Hints::default());
    assert!(bot_score.value >= cfg.classifier.threshold, "{bot_score:?}");
    assert!(bot_score.reasons.contains(&"known_bot_user_agent"));

    let mut browser = HeaderMap::new();
    browser.insert(USER_AGENT, HeaderValue::from_static(BROWSER_UA));
    browser.insert(ACCEPT, HeaderValue::from_static("text/html"));
    browser.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US"));
    browser.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
    let browser_score = score_request(&cfg.classifier, &browser, "/", "/archive", &Hints::default());
    assert!(browser_score.value < cfg.classifier.threshold, "{browser_score:?}");

    let honeypot = score_request(&cfg.classifier, &browser, "/archive/x", "/archive", &Hints::default());
    assert!(honeypot.value >= cfg.classifier.threshold, "touching the maze is decisive");
}

#[tokio::test]
async fn bot_is_contained_and_served_the_maze() {
    let (app, state) = build(test_config()).await;
    let resp = app.clone().oneshot(bot_request("/")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get(SET_COOKIE).is_some(), "session cookie is set");
    let html = body_text(resp).await;
    assert!(html.contains("Related entries"));
    assert!(html.contains("href=\"/archive/"), "every link leads into the maze");

    let contained = state.sessions.list(Some(SessionState::Contained), 10);
    assert_eq!(contained.len(), 1);
    assert_eq!(contained[0].navigation_depth, 1);
    assert!(contained[0].signals.iter().any(|s| s == "known_bot_user_agent"));
    assert_eq!(state.telemetry.metrics.snapshot().trap_streams_completed, 1);
}

#[tokio::test]
async fn browser_sees_the_normal_site_until_it_touches_the_honeypot() {
    let (app, state) = build(test_config()).await;
    let resp = app.clone().oneshot(browser_request("/")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_text(resp).await;
    assert!(html.contains("Field Notes"));
    assert!(html.contains("class=\"hp\" href=\"/archive/\""), "hidden honeypot link is present");
    assert_eq!(state.sessions.list(Some(SessionState::Normal), 10).len(), 1);

    let resp = app.clone().oneshot(browser_request("/archive/")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let _ = body_text(resp).await;
    assert_eq!(state.sessions.list(Some(SessionState::Contained), 10).len(), 1);
    assert_eq!(state.sessions.len(), 1, "same client, same session");
}

#[tokio::test]
async fn maze_pages_are_deterministic_per_url() {
    let (app, _) = build(test_config()).await;
    let a = body_text(app.clone().oneshot(bot_request("/archive/harbour/ledger")).await.unwrap()).await;
    let b = body_text(app.clone().oneshot(bot_request("/archive/harbour/ledger/")).await.unwrap()).await;
    let c = body_text(app.clone().oneshot(bot_request("/archive/harbour/drawer")).await.unwrap()).await;
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[tokio::test]
async fn exempt_user_agents_are_never_contained() {
    let mut cfg = test_config();
    cfg.classifier.never_contain_user_agents.push("Python-Requests".into());
    let (app, state) = build(cfg).await;
    let resp = app.clone().oneshot(bot_request("/archive/x")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert!(state.sessions.list(Some(SessionState::Contained), 10).is_empty());
}

#[tokio::test]
async fn contain_all_mode_traps_browsers_too() {
    let mut cfg = test_config();
    cfg.classifier.mode = ClassifierMode::ContainAll;
    let (app, state) = build(cfg).await;
    let html = body_text(app.clone().oneshot(browser_request("/")).await.unwrap()).await;
    assert!(html.contains("Related entries"));
    assert_eq!(state.sessions.list(Some(SessionState::Contained), 10).len(), 1);
}

#[tokio::test]
async fn telemetry_is_persisted_to_sqlite() {
    let mut cfg = test_config();
    cfg.storage.enabled = true;
    cfg.storage.database_url = "sqlite::memory:".into();
    let (app, state) = build(cfg).await;
    for _ in 0..3 {
        let resp = app.clone().oneshot(bot_request("/archive/a")).await.unwrap();
        let _ = body_text(resp).await;
    }
    state.persist_dirty_sessions();
    state.telemetry.flush().await;

    let db = state.db.as_ref().unwrap();
    let sessions = db.recent_sessions(10).await.unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0]["state"], "contained");
    assert_eq!(sessions[0]["navigation_depth"], 3);

    let summary = db.summary().await.unwrap();
    assert_eq!(summary["requests"], 3);
    assert_eq!(summary["loops_detected"], 1);

    let events = db.recent_events(10).await.unwrap();
    assert!(events.iter().any(|e| e["kind"] == "loop_detected"), "{events:?}");
}

#[test]
fn shipped_config_file_is_valid() {
    let cfg = Config::load(Path::new("config/server.toml")).expect("config/server.toml parses");
    assert_eq!(cfg.tarpit.prefix, "/archive");
    assert_eq!(cfg.redirect.exit_destination, "/exit");
}
