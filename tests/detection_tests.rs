//! Browser checks, agent-tuned maze content, give-up tracking, restart memory,
//! retention, the reverse proxy and the dashboard.

mod common;

use std::net::SocketAddr;

use axum::http::header::{ACCEPT, USER_AGENT};
use axum::http::{Request, StatusCode};
use axum::routing::{get as get_route, post as post_route};
use axum::Router;
use chrono::{TimeDelta, Utc};
use common::*;
use nepenthes::control::control_router;
use nepenthes::engine::session::{Outcome, SessionState};
use nepenthes::storage::database::{RequestRecord, StorageEvent};
use tower::ServiceExt;

// ------------------------------------------------------------ browser checks

#[tokio::test]
async fn pages_carry_the_browser_checks() {
    let (app, _) = build(test_config()).await;
    let html = body_text(app.clone().oneshot(browser_request("/")).await.unwrap()).await;
    assert!(html.contains("/_np/s/") && html.contains("/_np/p/") && html.contains("/_np/b"), "{html}");
    let maze = body_text(app.clone().oneshot(bot_request("/archive/x")).await.unwrap()).await;
    assert!(maze.contains("/_np/s/"), "maze pages carry them too");
}

#[tokio::test]
async fn webdriver_beacon_contains_a_browser_session_immediately() {
    let (app, state) = build(test_config()).await;
    let resp = app.clone().oneshot(browser_request("/")).await.unwrap();
    let _ = body_text(resp).await;
    assert_eq!(state.sessions.list(Some(SessionState::Normal), 10).len(), 1);

    let beacon = browser_subresource("POST", "/_np/b", "empty", None, r#"{"e":"load","wd":true}"#);
    let resp = app.clone().oneshot(beacon).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let contained = state.sessions.list(Some(SessionState::Contained), 10);
    assert_eq!(contained.len(), 1, "webdriver alone is enough");
    assert!(contained[0].signals.iter().any(|s| s == "webdriver"));
    assert_eq!(state.telemetry.metrics.snapshot().webdriver_detected, 1);

    let html = body_text(app.clone().oneshot(browser_request("/")).await.unwrap()).await;
    assert!(html.contains("Related entries"), "the next navigation lands in the maze");
}

#[tokio::test]
async fn browser_that_never_loads_subresources_is_contained() {
    let (app, state) = build(test_config()).await;
    let mut contained_after = None;
    for i in 1..=6 {
        let path = if i % 2 == 0 { "/about" } else { "/" };
        let _ = body_text(app.clone().oneshot(browser_request(path)).await.unwrap()).await;
        if !state.sessions.list(Some(SessionState::Contained), 10).is_empty() {
            contained_after = Some(i);
            break;
        }
    }
    let n = contained_after.expect("a fake browser that skips CSS/JS gets contained");
    assert!(n <= 4, "contained after {n} pages");
    let s = &state.sessions.list(Some(SessionState::Contained), 1)[0];
    assert!(s.signals.iter().any(|x| x == "no_subresources"), "{:?}", s.signals);
}

#[tokio::test]
async fn real_browser_behaviour_stays_normal() {
    let mut cfg = test_config();
    cfg.classifier.min_human_dwell_ms = 0; // tests run faster than any human
    cfg.classifier.high_rate_rps = 0.0;
    let (app, state) = build(cfg).await;

    let first = app.clone().oneshot(browser_nav("/", None, None)).await.unwrap();
    let cookie = session_cookie(&first).expect("cookie");
    let _ = body_text(first).await;
    let mut previous = "http://localhost/".to_string();
    for i in 0..6 {
        for (method, uri, dest, body) in [
            ("GET", "/_np/s/abc.css", "style", ""),
            ("GET", "/_np/p/abc.gif", "image", ""),
            ("POST", "/_np/b", "empty", r#"{"e":"load"}"#),
            ("POST", "/_np/b", "empty", r#"{"e":"hide","mm":24,"sc":3}"#),
        ] {
            let resp = app.clone().oneshot(browser_subresource(method, uri, dest, Some(&cookie), body)).await.unwrap();
            assert!(resp.status().is_success());
        }
        let path = if i % 2 == 0 { "/about" } else { "/" };
        let resp = app.clone().oneshot(browser_nav(path, Some(&cookie), Some(&previous))).await.unwrap();
        let _ = body_text(resp).await;
        previous = format!("http://localhost{path}");
    }
    let sessions = state.sessions.list(None, 10);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].state, SessionState::Normal, "signals: {:?}", sessions[0].signals);
    assert!(sessions[0].behavior.assets_fetched >= 12 && sessions[0].behavior.js_beacons >= 12);
}

// -------------------------------------------------------------- maze content

#[tokio::test]
async fn topic_is_echoed_from_the_requested_path() {
    let (app, _) = build(test_config()).await;
    let html = body_text(app.clone().oneshot(bot_request("/pricing/enterprise-plans")).await.unwrap()).await;
    assert!(html.contains("Pricing Enterprise Plans"), "title echoes the request");
    assert!(html.contains("href=\"/archive/pricing-enterprise-plans/"), "links carry the topic deeper");
}

#[tokio::test]
async fn pagination_always_has_a_next_part() {
    let (app, _) = build(test_config()).await;
    let html = body_text(app.clone().oneshot(bot_request("/archive/harbour/p7")).await.unwrap()).await;
    assert!(html.contains("Part 7 of"), "shows its place in the series");
    assert!(html.contains("href=\"/archive/harbour/p8\""), "next part exists");
    assert!(html.contains("href=\"/archive/harbour/p6\""), "previous part exists");
    assert!(html.contains("Continued in part 8"));
}

#[tokio::test]
async fn search_returns_endless_relevant_results() {
    let (app, state) = build(test_config()).await;
    let html =
        body_text(app.clone().oneshot(bot_request("/archive/search?q=quarterly+revenue+2024")).await.unwrap()).await;
    assert!(html.contains("Search results for &quot;quarterly revenue 2024&quot;"));
    assert!(html.contains("href=\"/archive/quarterly-revenue-2024/"), "results lead into the topic");
    assert!(html.contains("page=2"), "there is always another page of results");
    assert_eq!(state.sessions.list(None, 1)[0].searches, 1);
}

// ------------------------------------------------- timeline and give-up tracking

#[tokio::test]
async fn timeline_records_the_agents_path() {
    let (app, state) = build(test_config()).await;
    for path in ["/archive/a", "/archive/b", "/archive/search?q=ledger"] {
        let _ = body_text(app.clone().oneshot(bot_request(path)).await.unwrap()).await;
    }
    let id = state.sessions.list(None, 1)[0].id;
    let control = control_router(state.clone());
    let resp = control.oneshot(get(&format!("/sessions/{id}/timeline"))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["stats"]["maze_pages"], 2);
    assert_eq!(v["stats"]["searches"], 1);
    let timeline = v["timeline"].as_array().unwrap();
    let pages: Vec<_> = timeline.iter().filter(|e| e["kind"] == "maze").collect();
    assert_eq!(pages.len(), 2);
    assert!(pages.iter().all(|e| e["duration_ms"].is_u64() && e["bytes"].as_u64().unwrap() > 0));
    assert!(timeline.iter().any(|e| e["kind"] == "transition"));
}

#[tokio::test]
async fn quiet_agents_are_marked_abandoned_and_can_resume() {
    let (app, state) = build(test_config()).await;
    let _ = body_text(app.clone().oneshot(bot_request("/archive/a")).await.unwrap()).await;
    assert_eq!(state.check_abandoned(Utc::now()), 0, "not quiet yet");
    assert_eq!(state.check_abandoned(Utc::now() + TimeDelta::try_hours(1).unwrap()), 1);
    let s = &state.sessions.list(None, 1)[0];
    assert_eq!(s.outcome, Outcome::Abandoned);
    assert_eq!(state.telemetry.metrics.snapshot().sessions_abandoned, 1);

    let _ = body_text(app.clone().oneshot(bot_request("/archive/b")).await.unwrap()).await;
    let s = &state.sessions.list(None, 1)[0];
    assert_eq!(s.outcome, Outcome::Trapped, "it came back");
    let timeline = state.sessions.timeline(&s.id).unwrap();
    assert!(timeline.iter().any(|e| e.kind == "abandoned") && timeline.iter().any(|e| e.kind == "resumed"));
}

// ------------------------------------------------- restart memory + retention

#[tokio::test]
async fn contained_fingerprints_survive_a_restart() {
    let path = std::env::temp_dir().join(format!("nepenthes-test-{}.db", uuid::Uuid::new_v4()));
    let url = format!("sqlite://{}", path.to_string_lossy().replace('\\', "/"));
    let mut cfg = test_config();
    cfg.storage.enabled = true;
    cfg.storage.database_url = url;

    {
        let (app, state) = build(cfg.clone()).await;
        // A browser-looking client that walked into the maze.
        let _ = body_text(app.clone().oneshot(browser_request("/archive/x")).await.unwrap()).await;
        assert_eq!(state.sessions.list(Some(SessionState::Contained), 1).len(), 1);
        state.persist_dirty_sessions();
        state.telemetry.flush().await;
    }

    let (app, state) = build(cfg).await;
    let html = body_text(app.clone().oneshot(browser_request("/")).await.unwrap()).await;
    assert!(html.contains("Related entries"), "trapped on its first request after the restart");
    let s = &state.sessions.list(None, 1)[0];
    assert!(s.restored);
    assert_eq!(state.telemetry.metrics.snapshot().sessions_restored, 1);
    drop(state);
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn retention_prunes_old_rows() {
    let mut cfg = test_config();
    cfg.storage.enabled = true;
    cfg.storage.database_url = "sqlite::memory:".into();
    cfg.storage.retention_days = 30;
    let (_, state) = build(cfg).await;
    let db = state.db.as_ref().unwrap();
    let record = |days_ago: i64| {
        StorageEvent::Request(RequestRecord {
            session_id: uuid::Uuid::new_v4(),
            at: Utc::now() - TimeDelta::try_days(days_ago).unwrap(),
            method: "GET".into(),
            path: "/archive/x".into(),
            status: 200,
            route: "maze",
            duration_ms: Some(10),
            bytes: Some(100),
        })
    };
    db.write_batch(&[record(45), record(31), record(1)]).await.unwrap();
    assert_eq!(state.prune_storage().await.unwrap(), 2);
    assert_eq!(db.summary().await.unwrap()["requests"], 1);
}

// -------------------------------------------------------------- reverse proxy

async fn spawn_upstream() -> SocketAddr {
    let app = Router::new()
        .route("/", get_route(|| async { axum::response::Html("<html><head><title>Real</title></head><body><p>upstream home</p></body></html>") }))
        .route("/api/data", get_route(|| async { axum::Json(serde_json::json!({ "ok": true })) }))
        .route("/echo", post_route(|body: String| async move { body }))
        .route("/robots.txt", get_route(|| async { "User-agent: *\nDisallow: /private/\n" }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

#[tokio::test]
async fn normal_traffic_is_proxied_to_the_real_site() {
    let upstream = spawn_upstream().await;
    let mut cfg = test_config();
    cfg.normal.upstream_url = Some(format!("http://{upstream}"));
    let (app, state) = build(cfg).await;

    let html = body_text(app.clone().oneshot(browser_request("/")).await.unwrap()).await;
    assert!(html.contains("upstream home"));
    assert!(html.contains("/_np/s/") && html.contains("</body>"), "checks injected into the real page");

    let api = Request::get("/api/data")
        .header(USER_AGENT, BROWSER_UA)
        .header(ACCEPT, "application/json")
        .header("accept-language", "en")
        .header("sec-fetch-dest", "empty")
        .body(axum::body::Body::empty())
        .unwrap();
    assert_eq!(body_text(app.clone().oneshot(api).await.unwrap()).await, r#"{"ok":true}"#, "JSON untouched");

    let echo = browser_subresource("POST", "/echo", "empty", None, "hello upstream");
    assert_eq!(body_text(app.clone().oneshot(echo).await.unwrap()).await, "hello upstream");

    let robots = body_text(app.clone().oneshot(get("/robots.txt")).await.unwrap()).await;
    assert!(robots.contains("Disallow: /private/") && robots.contains("Disallow: /archive/"));

    let maze = body_text(app.clone().oneshot(bot_request("/")).await.unwrap()).await;
    assert!(maze.contains("Related entries"), "bots get the maze, not the real site");
    assert!(state.telemetry.metrics.snapshot().proxied_requests >= 3);
}

// ------------------------------------------------------------------ dashboard

#[tokio::test]
async fn dashboard_is_served_and_accepts_a_query_token() {
    let mut cfg = test_config();
    cfg.control.token = Some("s3cret".into());
    let (_, state) = build(cfg).await;
    let control = control_router(state);

    assert_eq!(control.clone().oneshot(get("/")).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    let resp = control.clone().oneshot(get("/?token=s3cret")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_text(resp).await.contains("<title>Nepenthes Control</title>"));
    assert_eq!(control.clone().oneshot(get("/metrics?token=s3cret")).await.unwrap().status(), StatusCode::OK);
}
