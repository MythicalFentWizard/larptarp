//! Configuration, loaded from `config/server.toml`.
//!
//! Every field has a default, so a partial (or missing) file works. Unknown
//! keys are rejected so typos do not silently fall back to defaults.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub control: ControlConfig,
    pub classifier: ClassifierConfig,
    pub session: SessionConfig,
    pub redirect: RedirectConfig,
    pub tarpit: TarpitConfig,
    pub limits: LimitsConfig,
    pub rate_limit: RateLimitConfig,
    pub storage: StorageConfig,
    pub telemetry: TelemetryConfig,
    pub normal: NormalConfig,
}

impl Config {
    pub fn from_toml(text: &str) -> Result<Self> {
        let mut cfg: Config = toml::from_str(text).context("invalid config")?;
        cfg.normalize();
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        Self::from_toml(&text).with_context(|| format!("loading config {}", path.display()))
    }

    /// Canonicalise values that have several equivalent spellings.
    pub fn normalize(&mut self) {
        let prefix = self.tarpit.prefix.trim().trim_end_matches('/').to_string();
        self.tarpit.prefix = if prefix.starts_with('/') { prefix } else { format!("/{prefix}") };

        let c = &mut self.classifier;
        for list in [
            &mut c.bot_user_agents,
            &mut c.always_contain_user_agents,
            &mut c.never_contain_user_agents,
        ] {
            for s in list.iter_mut() {
                *s = s.trim().to_ascii_lowercase();
            }
            list.retain(|s| !s.is_empty());
        }
        if let Some(url) = &mut self.normal.upstream_url {
            *url = url.trim().trim_end_matches('/').to_string();
        }
        if self.normal.upstream_url.as_deref() == Some("") {
            self.normal.upstream_url = None;
        }
    }

    pub fn validate(&self) -> Result<()> {
        let t = &self.tarpit;
        if t.prefix.len() < 2 {
            bail!("tarpit.prefix must be a sub-path such as \"/archive\" (\"/\" would trap the whole site)");
        }
        if t.prefix.contains(|c: char| c.is_whitespace() || "?#{}*\\".contains(c)) {
            bail!("tarpit.prefix contains characters that are not allowed in a path prefix");
        }
        if t.prefix.starts_with("/_np") {
            bail!("tarpit.prefix must not start with /_np (reserved for the browser checks)");
        }
        if t.min_delay_ms > t.max_delay_ms {
            bail!("tarpit.min_delay_ms must be <= tarpit.max_delay_ms");
        }
        if t.min_links == 0 || t.min_links > t.max_links {
            bail!("tarpit.min_links must be >= 1 and <= tarpit.max_links");
        }
        if t.min_paragraphs == 0 || t.min_paragraphs > t.max_paragraphs {
            bail!("tarpit.min_paragraphs must be >= 1 and <= tarpit.max_paragraphs");
        }
        if t.drip_chunk_bytes < 16 {
            bail!("tarpit.drip_chunk_bytes must be at least 16");
        }
        if t.backend == TarpitBackend::Upstream {
            url::Url::parse(&t.upstream_url).context("tarpit.upstream_url is not a valid URL")?;
        }
        if let Some(up) = &self.normal.upstream_url {
            let url = url::Url::parse(up).context("normal.upstream_url is not a valid URL")?;
            if !matches!(url.scheme(), "http" | "https") {
                bail!("normal.upstream_url must be an http(s) URL");
            }
        }
        if !(0.0..=1.0).contains(&self.classifier.threshold) {
            bail!("classifier.threshold must be between 0.0 and 1.0");
        }
        if !(0.0..=1.0).contains(&self.redirect.hop_probability) {
            bail!("redirect.hop_probability must be between 0.0 and 1.0");
        }
        if self.rate_limit.enabled && (self.rate_limit.per_ip_rps <= 0.0 || self.rate_limit.burst < 1.0) {
            bail!("rate_limit.per_ip_rps must be > 0 and rate_limit.burst >= 1");
        }
        if self.session.max_concurrent_sessions == 0 {
            bail!("session.max_concurrent_sessions must be >= 1");
        }
        let l = &self.limits;
        if l.max_inflight_requests == 0 || l.max_concurrent_streams == 0 || l.max_concurrent_generations == 0 {
            bail!("limits.max_inflight_requests, max_concurrent_streams and max_concurrent_generations must be >= 1");
        }
        if self.storage.batch_size == 0 || self.storage.channel_capacity == 0 {
            bail!("storage.batch_size and storage.channel_capacity must be >= 1");
        }
        if self.control.enabled && self.control.bind == self.server.bind {
            bail!("control.bind must differ from server.bind (the control plane is a separate listener)");
        }
        Ok(())
    }

    /// Copy that is safe to expose on the control plane.
    pub fn redacted(&self) -> Config {
        let mut c = self.clone();
        c.server.secret = "<redacted>".into();
        if c.control.token.is_some() {
            c.control.token = Some("<redacted>".into());
        }
        c
    }
}

// ---------------------------------------------------------------- [server]

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// Address crawlers and agents connect to (the data plane).
    pub bind: SocketAddr,
    /// Take the client IP from the first `X-Forwarded-For` entry. Only enable
    /// this behind a reverse proxy you control.
    pub trust_forwarded_for: bool,
    /// Cookie used to tag sessions.
    pub cookie_name: String,
    /// Seed mixed into page generation so the maze is unique per deployment.
    pub secret: String,
    /// Seconds to wait for open maze streams when shutting down.
    pub shutdown_grace_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
            trust_forwarded_for: false,
            cookie_name: "np_sid".into(),
            secret: "change-me".into(),
            shutdown_grace_secs: 10,
        }
    }
}

// --------------------------------------------------------------- [control]

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ControlConfig {
    pub enabled: bool,
    /// Separate listener for the control plane and dashboard. Keep it on loopback.
    pub bind: SocketAddr,
    /// When set, every control request needs `Authorization: Bearer <token>`
    /// (or `?token=` for the dashboard in a browser).
    pub token: Option<String>,
}

impl Default for ControlConfig {
    fn default() -> Self {
        Self { enabled: true, bind: SocketAddr::from(([127, 0, 0, 1], 9100)), token: None }
    }
}

// ------------------------------------------------------------ [classifier]

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassifierMode {
    /// Score every request and contain sessions above the threshold.
    #[default]
    Auto,
    /// Contain every session that is not explicitly exempt (handy for testing an agent).
    ContainAll,
    /// Never contain anybody; the maze answers 404.
    Off,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClassifierConfig {
    pub mode: ClassifierMode,
    /// Confidence (0.0 - 1.0) at which a session is contained.
    pub threshold: f32,
    /// Sustained requests/second of a single session that counts as a signal.
    pub high_rate_rps: f64,
    /// Opening the next page sooner than this after the previous one counts as fast.
    pub min_human_dwell_ms: u64,
    /// Put the browser checks (stylesheet, pixel, JS beacon) on every HTML page.
    pub beacon: bool,
    /// Case-insensitive User-Agent fragments of crawlers, HTTP libraries and agents.
    pub bot_user_agents: Vec<String>,
    /// User-Agent fragments that are always contained (e.g. your local agent).
    pub always_contain_user_agents: Vec<String>,
    /// User-Agent fragments that are never contained.
    pub never_contain_user_agents: Vec<String>,
    /// Client IPs that are never contained.
    pub never_contain_ips: Vec<IpAddr>,
    pub weights: ClassifierWeights,
}

impl Default for ClassifierConfig {
    fn default() -> Self {
        let bots = [
            "bot", "crawl", "spider", "scrapy", "python-requests", "python-urllib", "python-httpx",
            "httpx", "aiohttp", "curl/", "wget/", "go-http-client", "node-fetch", "axios", "undici",
            "okhttp", "java/", "libwww", "headlesschrome", "phantomjs", "playwright", "puppeteer",
            "selenium", "gptbot", "chatgpt", "oai-searchbot", "claudebot", "claude-web",
            "anthropic", "ccbot", "perplexity", "bytespider", "amazonbot", "cohere", "diffbot",
            "meta-externalagent", "langchain", "llama", "ollama", "openai", "agent",
        ];
        let search_engines =
            ["googlebot", "bingbot", "duckduckbot", "applebot", "yandexbot", "baiduspider"];
        Self {
            mode: ClassifierMode::Auto,
            threshold: 0.6,
            high_rate_rps: 4.0,
            min_human_dwell_ms: 800,
            beacon: true,
            bot_user_agents: bots.iter().map(|s| s.to_string()).collect(),
            always_contain_user_agents: Vec::new(),
            never_contain_user_agents: search_engines.iter().map(|s| s.to_string()).collect(),
            never_contain_ips: Vec::new(),
            weights: ClassifierWeights::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClassifierWeights {
    // Per-request header signals.
    pub known_bot_user_agent: f32,
    pub empty_user_agent: f32,
    pub missing_accept_language: f32,
    pub wildcard_accept: f32,
    pub missing_sec_fetch: f32,
    /// Requesting anything under the maze prefix.
    pub honeypot: f32,
    // Session behaviour signals.
    pub ignores_cookies: f32,
    pub high_rate: f32,
    /// Two or more pages viewed without loading their stylesheet or pixel.
    pub no_subresources: f32,
    /// Two or more pages viewed without the JS beacon ever firing.
    pub no_javascript: f32,
    /// The JS beacon reported `navigator.webdriver` (Playwright, Selenium, Puppeteer...).
    pub webdriver: f32,
    /// The JS beacon reported a headless browser.
    pub headless_browser: f32,
    /// Several pages with JavaScript running but no mouse, touch, scroll or key events.
    pub no_interaction: f32,
    /// Three or more page-to-page navigations faster than `min_human_dwell_ms`.
    pub fast_navigation: f32,
    /// Three or more in-site navigations without a Referer header.
    pub missing_referer: f32,
}

impl Default for ClassifierWeights {
    fn default() -> Self {
        Self {
            known_bot_user_agent: 0.6,
            empty_user_agent: 0.6,
            missing_accept_language: 0.15,
            wildcard_accept: 0.1,
            missing_sec_fetch: 0.1,
            honeypot: 1.0,
            ignores_cookies: 0.2,
            high_rate: 0.25,
            no_subresources: 0.3,
            no_javascript: 0.15,
            webdriver: 0.6,
            headless_browser: 0.4,
            no_interaction: 0.15,
            fast_navigation: 0.2,
            missing_referer: 0.1,
        }
    }
}

// --------------------------------------------------------------- [session]

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SessionConfig {
    /// Hard cap on tracked sessions (memory guard).
    pub max_concurrent_sessions: usize,
    /// After this many requests a contained session is sent to the exit. 0 = unlimited.
    pub max_requests_per_session: u64,
    /// Sessions idle for this long expire.
    pub idle_timeout_secs: u64,
    /// Sessions older than this expire regardless of activity.
    pub max_lifetime_secs: u64,
    pub cleanup_interval_secs: u64,
    /// How many recent page visits are kept for loop detection.
    pub loop_window: usize,
    /// Visiting the same page this many times inside the window is a loop (< 2 disables).
    pub loop_threshold: u32,
    /// A contained session that is quiet for this long has given up. 0 disables.
    pub abandon_after_secs: u64,
    /// Timeline entries kept in memory per session. 0 disables the timeline.
    pub timeline_max_entries: usize,
    /// Contained or blocked fingerprints are remembered (also across restarts)
    /// for this long, so a returning client is trapped on its first request.
    pub remember_secs: u64,
    pub max_remembered: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_concurrent_sessions: 10_000,
            max_requests_per_session: 10_000,
            idle_timeout_secs: 900,
            max_lifetime_secs: 86_400,
            cleanup_interval_secs: 10,
            loop_window: 64,
            loop_threshold: 3,
            abandon_after_secs: 120,
            timeline_max_entries: 500,
            remember_secs: 7 * 86_400,
            max_remembered: 100_000,
        }
    }
}

// -------------------------------------------------------------- [redirect]

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RedirectConfig {
    /// Where a session goes when it is finished (budget spent or released).
    pub exit_destination: String,
    /// Allowed redirect destinations: local paths (`/exit`, `/done/*`) or
    /// origins (`https://example.org`, optionally with a path prefix).
    pub allowlist: Vec<String>,
    /// Maximum consecutive redirect hops inside the maze before a page is served.
    pub max_redirect_depth: u32,
    /// Chance that a maze request is answered with a hop instead of a page.
    pub hop_probability: f64,
}

impl Default for RedirectConfig {
    fn default() -> Self {
        Self {
            exit_destination: "/exit".into(),
            allowlist: vec!["/exit".into()],
            max_redirect_depth: 4,
            hop_probability: 0.15,
        }
    }
}

// ---------------------------------------------------------------- [tarpit]

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TarpitBackend {
    /// Generate maze pages in-process (Rust port of the Nepenthes idea).
    #[default]
    Builtin,
    /// Proxy maze requests to a running nepenthes-py instance, falling back to
    /// the builtin generator if it is unreachable.
    Upstream,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TarpitConfig {
    /// Path prefix of the maze.
    pub prefix: String,
    pub backend: TarpitBackend,
    pub upstream_url: String,
    /// Text used to train the babble generator. Uses a built-in corpus when unset.
    pub corpus_path: Option<PathBuf>,
    /// Each page takes between min and max milliseconds to finish dripping.
    pub min_delay_ms: u64,
    pub max_delay_ms: u64,
    pub drip_chunk_bytes: usize,
    pub min_links: usize,
    pub max_links: usize,
    pub min_paragraphs: usize,
    pub max_paragraphs: usize,
    /// Links stop nesting deeper than this many path segments.
    pub max_url_depth: u32,
}

impl Default for TarpitConfig {
    fn default() -> Self {
        Self {
            prefix: "/archive".into(),
            backend: TarpitBackend::Builtin,
            upstream_url: "http://127.0.0.1:8893".into(),
            corpus_path: None,
            min_delay_ms: 1_500,
            max_delay_ms: 8_000,
            drip_chunk_bytes: 192,
            min_links: 5,
            max_links: 12,
            min_paragraphs: 3,
            max_paragraphs: 7,
            max_url_depth: 10,
        }
    }
}

// ---------------------------------------------------------------- [limits]

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    /// Start with the trap disarmed. Can be toggled at runtime on the control plane.
    pub killswitch: bool,
    /// Global cap on requests being processed (time to response headers).
    pub max_inflight_requests: usize,
    /// Global cap on maze pages being dripped at the same time.
    pub max_concurrent_streams: usize,
    /// Global cap on pages being generated at the same time (CPU limit).
    pub max_concurrent_generations: usize,
    /// Global maze bandwidth in bytes/second. 0 = unlimited.
    pub bandwidth_bytes_per_sec: u64,
    pub bandwidth_burst_bytes: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            killswitch: false,
            max_inflight_requests: 2_048,
            max_concurrent_streams: 512,
            max_concurrent_generations: 4,
            bandwidth_bytes_per_sec: 2 * 1024 * 1024,
            bandwidth_burst_bytes: 256 * 1024,
        }
    }
}

// ------------------------------------------------------------ [rate_limit]

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitConfig {
    pub enabled: bool,
    /// Sustained requests per second allowed per client IP.
    pub per_ip_rps: f64,
    pub burst: f64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self { enabled: true, per_ip_rps: 25.0, burst: 50.0 }
    }
}

// --------------------------------------------------------------- [storage]

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    pub enabled: bool,
    pub database_url: String,
    /// Records queued for the writer; when full, new records are dropped (and counted).
    pub channel_capacity: usize,
    pub batch_size: usize,
    pub flush_interval_ms: u64,
    /// How often changed in-memory sessions are written to the database.
    pub persist_interval_secs: u64,
    /// Store one row per request (can get large under heavy crawling).
    pub log_requests: bool,
    /// Delete stored rows older than this many days. 0 keeps everything.
    pub retention_days: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            database_url: "sqlite://data/nepenthes.db".into(),
            channel_capacity: 16_384,
            batch_size: 256,
            flush_interval_ms: 500,
            persist_interval_secs: 15,
            log_requests: true,
            retention_days: 30,
        }
    }
}

// ------------------------------------------------------------- [telemetry]

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    #[default]
    Pretty,
    Json,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    /// `tracing` filter, e.g. "info" or "nepenthes=debug". `RUST_LOG` overrides it.
    pub log_level: String,
    pub log_format: LogFormat,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self { log_level: "info".into(), log_format: LogFormat::Pretty }
    }
}

// ---------------------------------------------------------------- [normal]

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NormalConfig {
    pub site_name: String,
    /// Reverse-proxy legitimate traffic to your real site (takes precedence over `static_dir`).
    pub upstream_url: Option<String>,
    /// Serve legitimate traffic from this directory instead of the built-in pages.
    pub static_dir: Option<PathBuf>,
    /// Show a visible "Archive" link and a search box on the built-in pages.
    /// Catches agents that only read what is on screen, but humans who click
    /// them are trapped too, so keep it off on a public site.
    pub visible_entry_link: bool,
    /// Largest HTML page (bytes) that gets the browser checks injected.
    pub max_inject_bytes: usize,
}

impl Default for NormalConfig {
    fn default() -> Self {
        Self {
            site_name: "Field Notes".into(),
            upstream_url: None,
            static_dir: None,
            visible_entry_link: false,
            max_inject_bytes: 2 * 1024 * 1024,
        }
    }
}
