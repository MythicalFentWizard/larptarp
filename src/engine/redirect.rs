//! Redirect controller: allowlisted destinations, bounded hop chains.
//!
//! Destinations are either local paths or absolute http(s) URLs, and must
//! match an allowlist entry. Protocol-relative URLs, backslashes, userinfo,
//! control characters and dot segments are refused, so the controller can't
//! be turned into an open redirect.

use axum::body::Body;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use url::Url;

use crate::config::RedirectConfig;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RedirectError {
    #[error("redirect destination is empty")]
    Empty,
    #[error("redirect destination `{0}` is malformed or uses a forbidden form")]
    Malformed(String),
    #[error("redirect destination `{0}` is not on the allowlist")]
    NotAllowed(String),
    #[error("allowlist entry `{0}` is invalid (use \"/path\", \"/path/*\" or \"https://host\")")]
    BadRule(String),
}

#[derive(Debug, Clone)]
enum Rule {
    LocalExact(String),
    LocalPrefix(String),
    Remote { scheme: String, host: String, port: Option<u16>, path_prefix: String },
}

impl Rule {
    fn parse(entry: &str) -> Result<Self, RedirectError> {
        let e = entry.trim();
        let bad = || RedirectError::BadRule(e.to_string());
        if e.starts_with('/') {
            if e.starts_with("//") {
                return Err(bad());
            }
            return Ok(match e.strip_suffix('*') {
                Some(prefix) => Rule::LocalPrefix(prefix.to_string()),
                None => Rule::LocalExact(e.to_string()),
            });
        }
        let url = Url::parse(e).map_err(|_| bad())?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(bad());
        }
        let host = url.host_str().ok_or_else(bad)?.to_ascii_lowercase();
        Ok(Rule::Remote {
            scheme: url.scheme().to_string(),
            host,
            port: url.port_or_known_default(),
            path_prefix: url.path().to_string(),
        })
    }

    fn matches_local(&self, path: &str) -> bool {
        match self {
            Rule::LocalExact(p) => p == path,
            Rule::LocalPrefix(p) => path.starts_with(p.as_str()),
            Rule::Remote { .. } => false,
        }
    }

    fn matches_remote(&self, url: &Url) -> bool {
        match self {
            Rule::Remote { scheme, host, port, path_prefix } => {
                url.scheme() == scheme
                    && url.host_str().is_some_and(|h| h.eq_ignore_ascii_case(host))
                    && url.port_or_known_default() == *port
                    && url.path().starts_with(path_prefix.as_str())
            }
            _ => false,
        }
    }
}

enum Target {
    Local(String),
    Remote(Url),
}

fn parse_target(dest: &str) -> Result<Target, RedirectError> {
    let d = dest.trim();
    if d.is_empty() {
        return Err(RedirectError::Empty);
    }
    let bad = || RedirectError::Malformed(d.to_string());
    if !d.is_ascii() || d.chars().any(|c| c.is_ascii_control() || c == '\\' || c == ' ') {
        return Err(bad());
    }
    if let Some(rest) = d.strip_prefix('/') {
        if rest.starts_with('/') {
            return Err(bad()); // protocol-relative: //evil.example
        }
        let path = d.split(['?', '#']).next().unwrap_or(d);
        let lower = path.to_ascii_lowercase();
        if path.split('/').any(|seg| seg == "." || seg == "..")
            || lower.contains("%2e")
            || lower.contains("%2f")
            || lower.contains("%5c")
        {
            return Err(bad());
        }
        return Ok(Target::Local(d.to_string()));
    }
    let url = Url::parse(d).map_err(|_| bad())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(bad());
    }
    Ok(Target::Remote(url))
}

#[derive(Debug, Clone)]
pub struct RedirectController {
    rules: Vec<Rule>,
    exit: String,
    exit_local_path: Option<String>,
    max_depth: u32,
    hop_probability: f64,
}

impl RedirectController {
    pub fn new(cfg: &RedirectConfig) -> Result<Self, RedirectError> {
        let rules = cfg.allowlist.iter().map(|e| Rule::parse(e)).collect::<Result<Vec<_>, _>>()?;
        let mut this = Self {
            rules,
            exit: String::new(),
            exit_local_path: None,
            max_depth: cfg.max_redirect_depth,
            hop_probability: cfg.hop_probability.clamp(0.0, 1.0),
        };
        let exit = this.validate(&cfg.exit_destination)?;
        this.exit_local_path = exit.starts_with('/').then(|| exit.split(['?', '#']).next().unwrap_or("/").to_string());
        this.exit = exit;
        Ok(this)
    }

    /// Check a destination against the allowlist and return its canonical form.
    pub fn validate(&self, dest: &str) -> Result<String, RedirectError> {
        match parse_target(dest)? {
            Target::Local(full) => {
                let path = full.split(['?', '#']).next().unwrap_or("");
                if self.rules.iter().any(|r| r.matches_local(path)) {
                    Ok(full)
                } else {
                    Err(RedirectError::NotAllowed(full))
                }
            }
            Target::Remote(url) => {
                if self.rules.iter().any(|r| r.matches_remote(&url)) {
                    Ok(url.to_string())
                } else {
                    Err(RedirectError::NotAllowed(url.to_string()))
                }
            }
        }
    }

    pub fn is_allowed(&self, dest: &str) -> bool {
        self.validate(dest).is_ok()
    }

    pub fn exit_destination(&self) -> &str {
        &self.exit
    }

    /// True when `path` is the local exit page itself (must never redirect again).
    pub fn is_exit_path(&self, path: &str) -> bool {
        self.exit_local_path.as_deref() == Some(path)
    }

    pub fn max_depth(&self) -> u32 {
        self.max_depth
    }

    /// Answer this maze request with a hop instead of a page? `roll` is uniform in [0, 1).
    pub fn should_hop(&self, chain: u32, roll: f64) -> bool {
        chain < self.max_depth && roll < self.hop_probability
    }
}

/// `302 Found` to `location`.
pub fn redirect_response(location: &str) -> Response {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::FOUND;
    if let Ok(v) = HeaderValue::from_str(location) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}
