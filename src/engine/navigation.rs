//! Navigation tracking and loop detection.

use std::collections::{HashSet, VecDeque};

use serde::Serialize;

/// Per-session cap on remembered distinct pages (memory guard).
const MAX_TRACKED_PAGES: usize = 4_096;

/// 64-bit FNV-1a. Stable across runs and Rust versions, which keeps the maze
/// deterministic (`DefaultHasher` makes no such promise).
pub fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// `/archive/a/` and `/archive/a` are the same page.
pub fn normalize_path(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/"
    } else {
        trimmed
    }
}

pub fn path_hash(path: &str) -> u64 {
    fnv1a(normalize_path(path).as_bytes())
}

/// Number of path segments below `prefix` (0 when `path` is outside the maze).
pub fn path_depth(path: &str, prefix: &str) -> u32 {
    match path.strip_prefix(prefix) {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => {
            rest.split('/').filter(|s| !s.is_empty()).count() as u32
        }
        _ => 0,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NavOutcome {
    /// First visit to this page.
    Fresh,
    /// Seen before, below the loop threshold.
    Revisit { hits: u32 },
    /// The page was visited `hits` times inside the window: the client is circling.
    Loop { hits: u32 },
}

#[derive(Debug, Clone, Default)]
pub struct NavState {
    recent: VecDeque<u64>,
    seen: HashSet<u64>,
    pub loops_detected: u32,
    pub max_path_depth: u32,
}

impl NavState {
    /// Record a page visit and report whether the client is going in circles.
    /// A loop fires once each time the in-window count crosses `threshold`.
    pub fn record(&mut self, hash: u64, window: usize, threshold: u32) -> NavOutcome {
        let hits = 1 + self.recent.iter().filter(|h| **h == hash).count() as u32;
        self.recent.push_back(hash);
        while self.recent.len() > window.max(1) {
            self.recent.pop_front();
        }
        let new_page = if self.seen.len() < MAX_TRACKED_PAGES {
            self.seen.insert(hash)
        } else {
            !self.seen.contains(&hash)
        };

        if threshold >= 2 && hits == threshold {
            self.loops_detected += 1;
            NavOutcome::Loop { hits }
        } else if hits > 1 || !new_page {
            NavOutcome::Revisit { hits }
        } else {
            NavOutcome::Fresh
        }
    }

    pub fn unique_pages(&self) -> usize {
        self.seen.len()
    }
}
