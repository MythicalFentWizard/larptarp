//! Reverse proxy for normal traffic: legitimate visitors are forwarded to the
//! real site, so the tarpit can sit in front of it.

use std::net::IpAddr;
use std::time::Duration;

use anyhow::Result;
use axum::body::{to_bytes, Body};
use axum::extract::Request;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

/// Request bodies larger than this are refused (they are buffered).
const MAX_REQUEST_BODY: usize = 16 * 1024 * 1024;

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

pub fn build_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(300))
        .pool_idle_timeout(Duration::from_secs(90))
        .build()?)
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    HOP_BY_HOP.contains(&name.as_str())
}

pub fn bad_gateway() -> Response {
    (StatusCode::BAD_GATEWAY, "Bad Gateway\n").into_response()
}

/// Forward `req` to `upstream`. With `identity`, the upstream is asked for an
/// uncompressed body (so the browser checks can be injected into HTML).
/// Returns the response and whether the upstream answered at all.
pub async fn forward(
    client: &reqwest::Client,
    upstream: &str,
    req: Request,
    client_ip: IpAddr,
    identity: bool,
) -> (Response, bool) {
    let path_and_query = req.uri().path_and_query().map(|p| p.as_str().to_owned()).unwrap_or_else(|| "/".into());
    let url = format!("{}{}", upstream.trim_end_matches('/'), path_and_query);
    let (parts, body) = req.into_parts();
    let Ok(body) = to_bytes(body, MAX_REQUEST_BODY).await else {
        return ((StatusCode::PAYLOAD_TOO_LARGE, "Payload Too Large\n").into_response(), true);
    };

    let mut headers = HeaderMap::new();
    for (name, value) in parts.headers.iter() {
        if is_hop_by_hop(name)
            || name == header::HOST
            || name == header::CONTENT_LENGTH
            || (identity && name == header::ACCEPT_ENCODING)
        {
            continue;
        }
        headers.append(name.clone(), value.clone());
    }
    let forwarded_for = match parts.headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        Some(prev) => format!("{prev}, {client_ip}"),
        None => client_ip.to_string(),
    };
    if let Ok(v) = HeaderValue::from_str(&forwarded_for) {
        headers.insert("x-forwarded-for", v);
    }
    if let Some(host) = parts.headers.get(header::HOST) {
        headers.insert("x-forwarded-host", host.clone());
    }
    headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));

    let mut request = client.request(parts.method.clone(), &url).headers(headers);
    if !body.is_empty() {
        request = request.body(body);
    }
    match request.send().await {
        Ok(resp) => {
            let mut builder = Response::builder().status(resp.status());
            if let Some(h) = builder.headers_mut() {
                for (name, value) in resp.headers().iter() {
                    if !is_hop_by_hop(name) {
                        h.append(name.clone(), value.clone());
                    }
                }
            }
            match builder.body(Body::from_stream(resp.bytes_stream())) {
                Ok(r) => (r, true),
                Err(_) => (bad_gateway(), false),
            }
        }
        Err(err) => {
            tracing::warn!(error = %err, %url, "upstream site request failed");
            (bad_gateway(), false)
        }
    }
}

/// Fetch the upstream site's robots.txt, if it has one.
pub async fn upstream_robots(client: &reqwest::Client, upstream: &str) -> Option<String> {
    let resp = client.get(format!("{}/robots.txt", upstream.trim_end_matches('/'))).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.text().await.ok()
}
