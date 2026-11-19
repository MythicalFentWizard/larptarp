//! Tower/axum middleware for the data plane, outermost first:
//! `request_trace` -> `rate_limit` -> `classifier` -> handlers.

pub mod classifier;
pub mod rate_limit;
pub mod request_trace;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::extract::{ConnectInfo, Request};

use request_trace::ClientIp;

/// Client IP for a request: resolved once by `request_trace`, recomputed if absent.
pub fn client_ip(req: &Request, trust_forwarded_for: bool) -> IpAddr {
    match req.extensions().get::<ClientIp>() {
        Some(ClientIp(ip)) => *ip,
        None => resolve_ip(req, trust_forwarded_for),
    }
}

pub(crate) fn resolve_ip(req: &Request, trust_forwarded_for: bool) -> IpAddr {
    if trust_forwarded_for {
        let forwarded = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse::<IpAddr>().ok());
        if let Some(ip) = forwarded {
            return ip;
        }
    }
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}
