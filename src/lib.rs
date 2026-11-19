//! Nepenthes: an asynchronous HTTP crawler tarpit with a separate control plane.
//!
//! Request life cycle (data plane):
//!
//! ```text
//! receive -> inspect (cookies, headers, history, nav patterns, browser checks)
//!         -> classify (confidence score)
//!         -> contain (route matching sessions into an isolated, bounded maze)
//!         -> track (session state, timeline, loops, give-up detection)
//!         -> redirect (bounded hops inside the maze, allowlisted exit when done)
//!         -> record (session time, request count, outcome / "enemy downtime")
//! ```
//!
//! The control plane listens on its own address and manages sessions,
//! redirects, the killswitch and telemetry, with a live dashboard.

pub mod config;
pub mod control;
pub mod engine;
pub mod middleware;
pub mod proxy;
pub mod routes;
pub mod server;
pub mod storage;
pub mod telemetry;

pub use server::AppState;
