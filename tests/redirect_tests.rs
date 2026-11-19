mod common;

use axum::body::Body;
use axum::http::header::LOCATION;
use axum::http::{Request, StatusCode};
use common::*;
use nepenthes::config::RedirectConfig;
use nepenthes::control::control_router;
use nepenthes::engine::redirect::{RedirectController, RedirectError};
use nepenthes::engine::session::SessionState;
use nepenthes::AppState;
use tower::ServiceExt;

fn controller(allow: &[&str]) -> RedirectController {
    RedirectController::new(&RedirectConfig {
        exit_destination: "/exit".into(),
        allowlist: allow.iter().map(|s| s.to_string()).collect(),
        ..RedirectConfig::default()
    })
    .unwrap()
}

#[test]
fn allowlisted_destinations_are_accepted() {
    let rc = controller(&["/exit", "/released/*", "https://example.org"]);
    assert!(rc.is_allowed("/exit"));
    assert!(rc.is_allowed("/exit?from=maze"));
    assert!(rc.is_allowed("/released/thanks"));
    assert!(rc.is_allowed("https://example.org/"));
    assert!(rc.is_allowed("https://EXAMPLE.org/some/page"));
    assert!(rc.is_allowed("https://example.org:443/x"));
}

#[test]
fn open_redirect_tricks_are_rejected() {
    let rc = controller(&["/exit", "/released/*", "https://example.org"]);
    for bad in [
        "",
        "//evil.example",
        "/\\evil.example",
        "https://evil.example",
        "https://example.org.evil.example",
        "http://example.org",
        "https://example.org:8443/",
        "https://user@example.org/",
        "javascript:alert(1)",
        "/released/../archive",
        "/released/%2e%2e/archive",
        "/exit2",
        "/ex\nit",
        "ftp://example.org",
    ] {
        assert!(!rc.is_allowed(bad), "{bad:?} must be rejected");
    }
}

#[test]
fn exit_destination_must_be_on_the_allowlist() {
    let err = RedirectController::new(&RedirectConfig {
        exit_destination: "https://elsewhere.example/".into(),
        allowlist: vec!["/exit".into()],
        ..RedirectConfig::default()
    })
    .unwrap_err();
    assert!(matches!(err, RedirectError::NotAllowed(_)), "{err:?}");
}

#[tokio::test]
async fn server_refuses_to_start_with_an_unlisted_exit() {
    let mut cfg = test_config();
    cfg.redirect.exit_destination = "https://elsewhere.example/".into();
    assert!(AppState::build(cfg).await.is_err());
}

#[tokio::test]
async fn hop_chain_is_bounded_by_max_redirect_depth() {
    let mut cfg = test_config();
    cfg.redirect.hop_probability = 1.0;
    cfg.redirect.max_redirect_depth = 3;
    let (app, _) = build(cfg).await;

    let mut uri = "/".to_string();
    let mut statuses = Vec::new();
    for _ in 0..5 {
        let resp = app.clone().oneshot(bot_request(&uri)).await.unwrap();
        statuses.push(resp.status());
        if let Some(location) = resp.headers().get(LOCATION) {
            let location = location.to_str().unwrap().to_string();
            assert!(location.starts_with("/archive/"), "hops stay inside the maze: {location}");
            uri = location;
        }
        let _ = body_text(resp).await;
    }
    use StatusCode as S;
    assert_eq!(statuses, vec![S::FOUND, S::FOUND, S::FOUND, S::OK, S::FOUND]);
}

#[tokio::test]
async fn exhausted_sessions_are_redirected_to_the_exit() {
    let mut cfg = test_config();
    cfg.session.max_requests_per_session = 3;
    let (app, state) = build(cfg).await;

    for i in 0..3 {
        let resp = app.clone().oneshot(bot_request(&format!("/archive/page{i}"))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = body_text(resp).await;
    }
    let resp = app.clone().oneshot(bot_request("/archive/page3")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(resp.headers()[LOCATION], "/exit");

    let resp = app.clone().oneshot(bot_request("/anything-else")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND, "completed sessions keep going to the exit");

    let resp = app.clone().oneshot(bot_request("/exit")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "the exit itself never redirects");
    assert_eq!(state.sessions.list(Some(SessionState::Completed), 10).len(), 1);
}

#[tokio::test]
async fn operator_redirects_are_validated_and_one_shot() {
    let (app, state) = build(test_config()).await;
    let control = control_router(state.clone());
    let _ = body_text(app.clone().oneshot(bot_request("/")).await.unwrap()).await;
    let id = state.sessions.list(None, 1)[0].id;
    let uri = format!("/sessions/{id}/redirect");

    let resp = control.clone().oneshot(post_json(&uri, r#"{"destination":"https://evil.example/"}"#, None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let resp = control.clone().oneshot(post_json(&uri, r#"{"destination":"/exit?via=operator"}"#, None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app.clone().oneshot(bot_request("/archive/x")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(resp.headers()[LOCATION], "/exit?via=operator");

    let resp = app.clone().oneshot(bot_request("/archive/x")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "the operator redirect fires once");
    let _ = body_text(resp).await;
}

#[tokio::test]
async fn killswitch_disarms_and_rearms_the_trap() {
    let (app, state) = build(test_config()).await;
    let control = control_router(state.clone());

    let resp = control.clone().oneshot(post_json("/killswitch", r#"{"engaged":true}"#, None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = app.clone().oneshot(bot_request("/archive/x")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    let resp = control.clone().oneshot(post_json("/killswitch", r#"{"engaged":false}"#, None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = app.clone().oneshot(bot_request("/archive/x")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let _ = body_text(resp).await;
}

#[tokio::test]
async fn control_plane_token_and_block() {
    let mut cfg = test_config();
    cfg.control.token = Some("s3cret".into());
    let (app, state) = build(cfg).await;
    let control = control_router(state.clone());
    let _ = body_text(app.clone().oneshot(bot_request("/")).await.unwrap()).await;
    let id = state.sessions.list(None, 1)[0].id;
    let uri = format!("/sessions/{id}/block");

    let resp = control.clone().oneshot(Request::post(&uri).body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = control.clone().oneshot(post_json(&uri, "{}", Some("wrong"))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = control.clone().oneshot(post_json(&uri, "{}", Some("s3cret"))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = app.clone().oneshot(bot_request("/archive/x")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = control.clone().oneshot(post_json(&uri, "{}", Some("s3cret"))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT, "blocked -> blocked is not a legal transition");
}
