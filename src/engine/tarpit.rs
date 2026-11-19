//! The maze: deterministic Markov-babble pages whose links only lead deeper
//! into the maze, drip-fed slowly to the client.
//!
//! This is a Rust port of the Nepenthes idea, tuned for LLM agents as well
//! as crawlers:
//!
//! - **Topic echo**: the words the client asked for (search text, or the path
//!   it requested) become the page topic, carried through every link, so each
//!   page looks relevant to the agent's task.
//! - **Endless pagination**: "Part 7 of 31" with a Next link that always
//!   exists, plus a contents list and "continued in part N" hooks.
//! - **Fake search**: `<prefix>/search?q=...` returns pages of plausible results.
//!
//! Each URL always renders the same page (seeded by the URL and the server
//! secret), so the maze looks like a static site. Pages are generated on the
//! blocking pool under a semaphore (CPU guard), streamed out under a global
//! bandwidth limiter, and every stream holds a permit from a global stream
//! semaphore, so the trap can't take the host down with it.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use axum::body::Body;
use axum::http::{header, HeaderValue};
use axum::response::Response;
use bytes::Bytes;
use futures::{stream, Stream, StreamExt};
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::beacon;
use super::navigation::{fnv1a, normalize_path, path_depth};
use crate::config::{LimitsConfig, TarpitBackend, TarpitConfig};

const BUILTIN_CORPUS: &str = include_str!("corpus.txt");

/// Words that make poor URL segments and titles.
const STOPWORDS: &[&str] = &[
    "about", "after", "also", "although", "another", "because", "been", "before", "between",
    "could", "each", "even", "every", "from", "have", "however", "into", "itself", "many", "might",
    "more", "most", "much", "never", "nobody", "once", "only", "other", "over", "rather", "same",
    "should", "some", "such", "than", "that", "their", "them", "then", "there", "these", "they",
    "this", "those", "through", "under", "very", "were", "what", "when", "where", "whether",
    "which", "while", "whole", "with", "within", "without", "would", "your",
];

/// Words dropped when turning a requested path into a topic.
const TOPIC_NOISE: &[&str] = &["html", "htm", "php", "asp", "aspx", "jsp", "index", "www"];

/// Opening lines for topic pages. `{topic}`, `{page}`, `{total}`, `{from}`,
/// `{to}`, `{count}` and `{per}` are filled in.
const HOOKS: &[&str] = &[
    "This entry collects the {topic} records held in the archive. Part {page} of {total} is shown below; the remaining parts follow in order.",
    "The {topic} material is catalogued across {total} parts. This part covers entries {from} to {to}; the summary table continues in the next part.",
    "Part {page} of the {topic} series. Cross references for {topic} are listed under Contents and resolved in the later parts.",
    "The index lists {count} records under {topic}. They are presented here in catalogue order, {per} to a part.",
];

// ------------------------------------------------------------------ Markov

/// Order-2 word chain with an order-1 fallback for extra variety.
pub struct Markov {
    vocab: Vec<String>,
    order2: HashMap<(u32, u32), Vec<u32>>,
    order1: HashMap<u32, Vec<u32>>,
    starts: Vec<(u32, u32)>,
    link_words: Vec<String>,
}

impl Markov {
    pub fn from_text(text: &str) -> Result<Self> {
        let tokens: Vec<&str> = text.split_whitespace().collect();
        if tokens.len() < 50 {
            bail!("corpus is too small ({} words); provide at least a few paragraphs", tokens.len());
        }

        let mut index: HashMap<&str, u32> = HashMap::new();
        let mut vocab: Vec<String> = Vec::new();
        let ids: Vec<u32> = tokens
            .iter()
            .map(|t| {
                *index.entry(*t).or_insert_with(|| {
                    vocab.push((*t).to_string());
                    (vocab.len() - 1) as u32
                })
            })
            .collect();

        let mut order2: HashMap<(u32, u32), Vec<u32>> = HashMap::new();
        for w in ids.windows(3) {
            order2.entry((w[0], w[1])).or_default().push(w[2]);
        }
        let mut order1: HashMap<u32, Vec<u32>> = HashMap::new();
        for w in ids.windows(2) {
            order1.entry(w[0]).or_default().push(w[1]);
        }

        let mut starts = Vec::new();
        for i in 0..ids.len().saturating_sub(1) {
            let boundary = i == 0 || ends_sentence(tokens[i - 1]);
            if boundary && tokens[i].chars().next().is_some_and(char::is_uppercase) {
                starts.push((ids[i], ids[i + 1]));
            }
        }
        if starts.is_empty() {
            starts.push((ids[0], ids[1]));
        }

        let mut seen = HashSet::new();
        let link_words: Vec<String> = vocab
            .iter()
            .filter_map(|w| {
                let clean = w.trim_matches(|c: char| !c.is_alphanumeric()).to_lowercase();
                let ok = (4..=14).contains(&clean.len())
                    && clean.chars().all(|c| c.is_ascii_lowercase())
                    && !STOPWORDS.contains(&clean.as_str())
                    && seen.insert(clean.clone());
                ok.then_some(clean)
            })
            .collect();
        if link_words.len() < 16 {
            bail!("corpus needs more distinct words to build maze URLs (found {})", link_words.len());
        }

        Ok(Self { vocab, order2, order1, starts, link_words })
    }

    fn next_word(&self, rng: &mut ChaCha8Rng, a: u32, b: u32) -> Option<u32> {
        match self.order2.get(&(a, b)) {
            Some(next) if next.len() > 1 || !rng.gen_bool(0.35) => next.choose(rng).copied(),
            _ => self.order1.get(&b).and_then(|next| next.choose(rng).copied()),
        }
    }

    pub fn sentence(&self, rng: &mut ChaCha8Rng, max_words: usize) -> String {
        let (mut a, mut b) = *self.starts.choose(rng).expect("starts is never empty");
        let mut words: Vec<&str> = vec![&self.vocab[a as usize], &self.vocab[b as usize]];
        // Small corpora make short cycles ("then into streets, then into streets"),
        // so a trigram is never reused within one sentence.
        let mut used: HashSet<(u32, u32, u32)> = HashSet::new();
        while words.len() < max_words {
            if words.len() >= 6 && ends_sentence(words[words.len() - 1]) {
                break;
            }
            let next = (0..4).filter_map(|_| self.next_word(rng, a, b)).find(|c| !used.contains(&(a, b, *c)));
            match next {
                Some(c) => {
                    used.insert((a, b, c));
                    words.push(&self.vocab[c as usize]);
                    a = b;
                    b = c;
                }
                None => break,
            }
        }
        let mut s = words.join(" ");
        if !ends_sentence(&s) {
            let keep = s.trim_end_matches(|c: char| !c.is_alphanumeric()).len();
            s.truncate(keep);
            s.push('.');
        }
        capitalize(&s)
    }

    pub fn paragraph(&self, rng: &mut ChaCha8Rng, sentences: usize) -> String {
        (0..sentences).map(|_| self.sentence(rng, 32)).collect::<Vec<_>>().join(" ")
    }

    pub fn link_word(&self, rng: &mut ChaCha8Rng) -> &str {
        self.link_words.choose(rng).expect("link_words is never empty")
    }
}

fn ends_sentence(w: &str) -> bool {
    matches!(w.chars().last(), Some('.' | '!' | '?'))
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn title_case(text: &str) -> String {
    text.split(['-', '_', ' ']).filter(|w| !w.is_empty()).map(capitalize).collect::<Vec<_>>().join(" ")
}

pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn url_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                match (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                    (Some(h), Some(l)) => {
                        out.push(h * 16 + l);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// "Quarterly Revenue, 2024!" -> "quarterly-revenue-2024".
pub fn slugify(text: &str) -> Option<String> {
    let words: Vec<String> = text
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| w.to_ascii_lowercase())
        .filter(|w| !TOPIC_NOISE.contains(&w.as_str()))
        .take(6)
        .collect();
    let mut slug = words.join("-");
    if slug.len() > 60 {
        slug.truncate(60);
        slug = slug.trim_end_matches('-').to_string();
    }
    (!slug.is_empty()).then_some(slug)
}

fn is_page_segment(s: &str) -> bool {
    s.len() > 1 && s.starts_with('p') && s[1..].chars().all(|c| c.is_ascii_digit())
}

// -------------------------------------------------------------- MazeRequest

/// What a contained client asked for, reduced to what the maze needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MazeRequest {
    /// Normalized request path.
    pub path: String,
    /// Whether the path is under the maze prefix.
    pub in_maze: bool,
    /// Topic slug echoed back at the client, e.g. "quarterly-revenue".
    pub topic: Option<String>,
    /// Search text, when this is a search request.
    pub search: Option<String>,
    /// 1-based part / results page.
    pub page: u32,
}

impl MazeRequest {
    pub fn parse(path: &str, query: Option<&str>, prefix: &str) -> Self {
        let path = normalize_path(path).to_string();
        let params: Vec<(String, String)> = query
            .map(|q| url::form_urlencoded::parse(q.as_bytes()).into_owned().collect())
            .unwrap_or_default();
        let param = |names: &[&str]| {
            params
                .iter()
                .find(|(k, v)| names.contains(&k.as_str()) && !v.trim().is_empty())
                .map(|(_, v)| v.trim().chars().take(120).collect::<String>())
        };
        let q = param(&["q", "query", "search", "s", "keywords"]);

        let in_maze = path == prefix || path_depth(&path, prefix) > 0;
        let rest = if in_maze { &path[prefix.len()..] } else { path.as_str() };
        let segments: Vec<String> = rest.split('/').filter(|s| !s.is_empty()).map(percent_decode).collect();

        let is_search = q.is_some() && segments.last().is_some_and(|s| s == "search");
        let page = if is_search {
            param(&["page", "p"]).and_then(|p| p.parse::<u32>().ok())
        } else {
            segments.last().filter(|s| is_page_segment(s)).and_then(|s| s[1..].parse::<u32>().ok())
        }
        .unwrap_or(1)
        .clamp(1, 1_000_000);

        let topic = match &q {
            Some(q) => slugify(q),
            None if in_maze => segments.first().filter(|s| *s != "search" && !is_page_segment(s)).and_then(|s| slugify(s)),
            None => slugify(&segments.iter().filter(|s| !is_page_segment(s)).cloned().collect::<Vec<_>>().join(" ")),
        };

        Self { path, in_maze, topic, search: if is_search { q } else { None }, page }
    }

    /// What the page content is seeded from.
    fn seed_key(&self) -> String {
        match &self.search {
            Some(q) => format!("{}?q={}&page={}", self.path, q.to_lowercase(), self.page),
            None => self.path.clone(),
        }
    }

    /// The path without a trailing `/p{n}` segment.
    fn base(&self) -> &str {
        match self.path.rsplit_once('/') {
            Some((head, last)) if is_page_segment(last) => {
                if head.is_empty() {
                    "/"
                } else {
                    head
                }
            }
            _ => &self.path,
        }
    }
}

// --------------------------------------------------------------- Bandwidth

/// Global token bucket shared by every maze stream. Callers that overdraw it
/// sleep off their deficit, so total maze output converges on `rate`.
pub struct Bandwidth {
    rate: f64,
    burst: f64,
    state: Mutex<(f64, Instant)>,
}

impl Bandwidth {
    pub fn new(bytes_per_sec: u64, burst_bytes: u64) -> Self {
        let burst = burst_bytes.max(1) as f64;
        Self { rate: bytes_per_sec as f64, burst, state: Mutex::new((burst, Instant::now())) }
    }

    pub async fn take(&self, n: usize) {
        if self.rate <= 0.0 {
            return;
        }
        let wait = {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            let refill = now.saturating_duration_since(st.1).as_secs_f64() * self.rate;
            st.0 = (st.0 + refill).min(self.burst) - n as f64;
            st.1 = now;
            if st.0 < 0.0 {
                Duration::from_secs_f64(-st.0 / self.rate)
            } else {
                Duration::ZERO
            }
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

// ------------------------------------------------------------------ Tarpit

pub struct TrapPage {
    pub html: String,
    /// Total time the page should take to drip out.
    pub delay: Duration,
    pub links: Vec<String>,
}

impl TrapPage {
    fn fallback(prefix: &str) -> Self {
        Self {
            html: format!(
                "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>Archive</title></head>\
                 <body><p>This entry is being re-indexed.</p><p><a href=\"{prefix}/\">Return to the archive index</a></p></body></html>\n"
            ),
            delay: Duration::from_secs(2),
            links: vec![format!("{prefix}/")],
        }
    }
}

/// Outcome of one maze stream, reported when the stream ends or the client hangs up.
#[derive(Debug, Clone, Copy)]
pub struct TrapStats {
    pub bytes: u64,
    pub elapsed: Duration,
    pub completed: bool,
}

pub type OnDone = Box<dyn FnOnce(TrapStats) + Send + 'static>;

type UpstreamStream = Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send>>;

pub struct Tarpit {
    markov: Markov,
    cfg: TarpitConfig,
    seed: u64,
    beacon: bool,
    generations: Semaphore,
    streams: Arc<Semaphore>,
    max_streams: usize,
    bandwidth: Arc<Bandwidth>,
    upstream: Option<reqwest::Client>,
}

impl Tarpit {
    pub fn new(cfg: &TarpitConfig, limits: &LimitsConfig, secret: &str, beacon: bool) -> Result<Self> {
        let text = match &cfg.corpus_path {
            Some(path) => std::fs::read_to_string(path)
                .with_context(|| format!("reading tarpit corpus {}", path.display()))?,
            None => BUILTIN_CORPUS.to_string(),
        };
        let markov = Markov::from_text(&text)?;
        let upstream = match cfg.backend {
            TarpitBackend::Builtin => None,
            TarpitBackend::Upstream => Some(
                reqwest::Client::builder()
                    .connect_timeout(Duration::from_secs(3))
                    .timeout(Duration::from_secs(120))
                    .build()
                    .context("building upstream client")?,
            ),
        };
        Ok(Self {
            markov,
            cfg: cfg.clone(),
            seed: fnv1a(secret.as_bytes()),
            beacon,
            generations: Semaphore::new(limits.max_concurrent_generations),
            streams: Arc::new(Semaphore::new(limits.max_concurrent_streams)),
            max_streams: limits.max_concurrent_streams,
            bandwidth: Arc::new(Bandwidth::new(limits.bandwidth_bytes_per_sec, limits.bandwidth_burst_bytes)),
            upstream,
        })
    }

    pub fn prefix(&self) -> &str {
        &self.cfg.prefix
    }

    pub fn parse(&self, path: &str, query: Option<&str>) -> MazeRequest {
        MazeRequest::parse(path, query, &self.cfg.prefix)
    }

    fn rng_for(&self, key: &str, salt: u64) -> ChaCha8Rng {
        let seed = self.seed ^ fnv1a(key.as_bytes()) ^ salt.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        ChaCha8Rng::seed_from_u64(seed)
    }

    /// Where pagination and nested links of this page live.
    fn maze_base(&self, req: &MazeRequest) -> String {
        let prefix = &self.cfg.prefix;
        if req.in_maze {
            req.base().to_string()
        } else {
            match &req.topic {
                Some(t) => format!("{prefix}/{t}"),
                None => prefix.clone(),
            }
        }
    }

    fn beacon_nonce(&self, req: &MazeRequest) -> String {
        format!("{:016x}", fnv1a(req.seed_key().as_bytes()) ^ self.seed)
    }

    /// Render the page for a request. Same request, same secret, same page.
    pub fn render(&self, req: &MazeRequest) -> TrapPage {
        match &req.search {
            Some(q) => self.render_search(req, q),
            None => self.render_entry(req),
        }
    }

    fn head(&self, html: &mut String, title: &str, nonce: &str) {
        let _ = write!(
            html,
            "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
             <title>{t} &middot; Archive</title>\n\
             <style>body{{font-family:Georgia,serif;max-width:46rem;margin:2rem auto;padding:0 1rem;line-height:1.6;color:#222}}\
             a{{color:#1a4d8f}}nav,footer,.meta,.url{{font-size:.9rem;color:#555}}.lead{{font-size:1.05rem}}</style>\n",
            t = escape_html(title)
        );
        if self.beacon {
            html.push_str(&beacon::head_tags(nonce));
            html.push('\n');
        }
        html.push_str("</head>\n<body>\n");
    }

    fn foot(&self, html: &mut String, rng: &mut ChaCha8Rng, nonce: &str) {
        let _ = write!(
            html,
            "<footer><p><a href=\"{}/\">Archive index</a> &middot; {} entries catalogued</p></footer>\n",
            self.cfg.prefix,
            rng.gen_range(40_000..=900_000)
        );
        if self.beacon {
            html.push_str(&beacon::body_tags(nonce));
        }
        html.push_str("</body>\n</html>\n");
    }

    fn render_entry(&self, req: &MazeRequest) -> TrapPage {
        let cfg = &self.cfg;
        let prefix = cfg.prefix.as_str();
        let mut rng = self.rng_for(&req.seed_key(), 0);
        let nonce = self.beacon_nonce(req);
        let base = self.maze_base(req);
        let depth = path_depth(&base, prefix);
        let topic = req.topic.as_deref();
        let topic_title = topic.map(title_case);
        let topic_text = topic.map(|t| t.replace('-', " "));
        let page = req.page;

        let mut title = self.title(&mut rng);
        if let Some(tt) = &topic_title {
            title = format!("{tt}: {title}");
        }
        if page > 1 {
            title = format!("{title} (part {page})");
        }
        let total = page + 2 + rng.gen_range(0..=36);

        let n_links = rng.gen_range(cfg.min_links..=cfg.max_links);
        let links: Vec<(String, String)> = (0..n_links).map(|_| self.link(&mut rng, &base, depth, topic)).collect();
        let n_paragraphs = rng.gen_range(cfg.min_paragraphs..=cfg.max_paragraphs);

        let mut html = String::with_capacity(6_144 + n_paragraphs * 700);
        self.head(&mut html, &title, &nonce);

        // Breadcrumbs mirror the URL so the tree looks real.
        let _ = write!(html, "<nav class=\"crumbs\"><a href=\"/\">Home</a> &rsaquo; <a href=\"{prefix}/\">Archive</a>");
        let mut acc = String::from(prefix);
        let crumbs: Vec<&str> = if req.in_maze {
            req.path[prefix.len()..].split('/').filter(|s| !s.is_empty()).collect()
        } else {
            topic.into_iter().collect()
        };
        for seg in crumbs {
            acc.push('/');
            acc.push_str(seg);
            let _ = write!(html, " &rsaquo; <a href=\"{}\">{}</a>", escape_html(&acc), escape_html(&title_case(seg)));
        }
        html.push_str("</nav>\n<main>\n<article>\n");

        let _ = writeln!(html, "<h1>{}</h1>", escape_html(&title));
        let (year, month, day) = (rng.gen_range(2004..=2025), rng.gen_range(1..=12), rng.gen_range(1..=28));
        let entry: u32 = rng.gen_range(1_000..=99_999);
        let _ = writeln!(
            html,
            "<p class=\"meta\">Entry {entry} &middot; last revised {year}-{month:02}-{day:02} &middot; Part {page} of {total}</p>"
        );

        if let Some(tt) = &topic_text {
            let per = rng.gen_range(10..=40u32);
            let from = (page - 1).saturating_mul(per) + 1;
            let hook = HOOKS[rng.gen_range(0..HOOKS.len())]
                .replace("{topic}", tt)
                .replace("{page}", &page.to_string())
                .replace("{total}", &total.to_string())
                .replace("{from}", &from.to_string())
                .replace("{to}", &(from + per - 1).to_string())
                .replace("{count}", &(total.saturating_mul(per)).to_string())
                .replace("{per}", &per.to_string());
            let _ = writeln!(html, "<p class=\"lead\">{}</p>", escape_html(&hook));
        }

        // Contents: numbered sections that all lead deeper.
        html.push_str("<h2>Contents</h2>\n<ol>\n");
        for i in 1..=rng.gen_range(4..=7u32) {
            let word = self.markov.link_word(&mut rng).to_string();
            let label = format!("{page}.{i} {}", title_case(&format!("{word} {}", self.markov.link_word(&mut rng))));
            let _ = writeln!(html, "<li><a href=\"{}\">{}</a></li>", escape_html(&format!("{base}/{word}")), escape_html(&label));
        }
        html.push_str("</ol>\n");

        for i in 0..n_paragraphs {
            if i % 2 == 1 {
                let mut heading = self.title(&mut rng);
                if let Some(tt) = &topic_title {
                    if rng.gen_bool(0.5) {
                        heading = format!("{tt} {heading}");
                    }
                }
                let _ = writeln!(html, "<h2>{}</h2>", escape_html(&heading));
            }
            let sentences = rng.gen_range(3..=6);
            let text = self.markov.paragraph(&mut rng, sentences);
            html.push_str("<p>");
            html.push_str(&escape_html(&text));
            if rng.gen_bool(0.45) {
                let (href, label) = &links[rng.gen_range(0..links.len())];
                let _ = write!(html, " See also <a href=\"{}\">{}</a>.", escape_html(href), escape_html(label));
            }
            html.push_str("</p>\n");
        }

        html.push_str("<h2>Related entries</h2>\n<ul>\n");
        for (href, label) in &links {
            let _ = writeln!(html, "<li><a href=\"{}\">{}</a></li>", escape_html(href), escape_html(label));
        }
        html.push_str("</ul>\n");

        let next_title = self.title(&mut rng);
        let _ = writeln!(
            html,
            "<p class=\"continued\">Continued in part {}: <a href=\"{}\">{}</a></p>",
            page + 1,
            escape_html(&format!("{base}/p{}", page + 1)),
            escape_html(&next_title)
        );
        html.push_str(&pager(|n| format!("{base}/p{n}"), page, total));
        html.push_str("</article>\n</main>\n");
        self.foot(&mut html, &mut rng, &nonce);

        let delay = Duration::from_millis(rng.gen_range(cfg.min_delay_ms..=cfg.max_delay_ms));
        let mut hrefs: Vec<String> = links.into_iter().map(|(h, _)| h).collect();
        hrefs.push(format!("{base}/p{}", page + 1));
        TrapPage { html, delay, links: hrefs }
    }

    fn render_search(&self, req: &MazeRequest, q: &str) -> TrapPage {
        let cfg = &self.cfg;
        let prefix = cfg.prefix.as_str();
        let mut rng = self.rng_for(&req.seed_key(), 0);
        let nonce = self.beacon_nonce(req);
        let slug = req.topic.clone().unwrap_or_else(|| "results".to_string());
        let topic_title = title_case(&slug);
        let page = req.page;
        let total_pages = page + 3 + rng.gen_range(0..=20);
        let hits: u32 = rng.gen_range(1_200..=480_000);
        let search_url = |n: u32| format!("{prefix}/search?q={}&page={n}", url_encode(q));

        let mut title = format!("Search results for \"{q}\"");
        if page > 1 {
            title = format!("{title} - page {page}");
        }
        let mut html = String::with_capacity(8_192);
        self.head(&mut html, &title, &nonce);
        let _ = writeln!(
            html,
            "<nav class=\"crumbs\"><a href=\"/\">Home</a> &rsaquo; <a href=\"{prefix}/\">Archive</a> &rsaquo; Search</nav>\n<main>"
        );
        let _ = writeln!(html, "<h1>{}</h1>", escape_html(&title));
        let _ = writeln!(
            html,
            "<form action=\"{prefix}/search\" method=\"get\"><input name=\"q\" value=\"{}\" size=\"40\"> <button>Search</button></form>",
            escape_html(q)
        );
        let _ = writeln!(html, "<p class=\"meta\">About {hits} results (page {page} of {total_pages})</p>\n<ol>");

        let mut links = Vec::new();
        for _ in 0..10 {
            let n = rng.gen_range(1..=2);
            let words: Vec<&str> = (0..n).map(|_| self.markov.link_word(&mut rng)).collect();
            let href = format!("{prefix}/{slug}/{}", words.join("/"));
            let result_title = format!("{topic_title}: {}", self.title(&mut rng));
            let first = self.markov.sentence(&mut rng, 16);
            let second = self.markov.sentence(&mut rng, 12);
            let _ = writeln!(
                html,
                "<li><h3><a href=\"{h}\">{t}</a></h3><p class=\"url\">{h}</p><p>{a} &hellip; <b>{q}</b> {b}</p></li>",
                h = escape_html(&href),
                t = escape_html(&result_title),
                a = escape_html(&first),
                q = escape_html(q),
                b = escape_html(&second)
            );
            links.push(href);
        }
        html.push_str("</ol>\n<h2>Related searches</h2>\n<ul>\n");
        for _ in 0..4 {
            let related = format!("{q} {}", self.markov.link_word(&mut rng));
            let _ = writeln!(
                html,
                "<li><a href=\"{}\">{}</a></li>",
                escape_html(&format!("{prefix}/search?q={}", url_encode(&related))),
                escape_html(&related)
            );
        }
        html.push_str("</ul>\n");
        html.push_str(&pager(search_url, page, total_pages));
        html.push_str("</main>\n");
        self.foot(&mut html, &mut rng, &nonce);

        let delay = Duration::from_millis(rng.gen_range(cfg.min_delay_ms..=cfg.max_delay_ms));
        TrapPage { html, delay, links }
    }

    fn title(&self, rng: &mut ChaCha8Rng) -> String {
        let n = rng.gen_range(2..=5);
        (0..n).map(|_| title_case(self.markov.link_word(rng))).collect::<Vec<_>>().join(" ")
    }

    fn link(&self, rng: &mut ChaCha8Rng, base: &str, depth: u32, topic: Option<&str>) -> (String, String) {
        // Half the links nest under the current page, the rest jump elsewhere
        // in the maze (keeping the topic, so it follows the client around).
        let deeper = depth < self.cfg.max_url_depth && rng.gen_bool(0.5);
        let prefix = self.cfg.prefix.as_str();
        let n = if deeper { 1 } else { rng.gen_range(1..=2) };
        let words: Vec<&str> = (0..n).map(|_| self.markov.link_word(rng)).collect();
        let href = if deeper {
            format!("{}/{}", base.trim_end_matches('/'), words[0])
        } else {
            match topic {
                Some(t) => format!("{prefix}/{t}/{}", words.join("/")),
                None => format!("{prefix}/{}", words.join("/")),
            }
        };
        let mut label = words.iter().map(|w| title_case(w)).collect::<Vec<_>>().join(" ");
        if let Some(t) = topic {
            if rng.gen_bool(0.4) {
                label = format!("{}: {label}", title_case(t));
            }
        }
        (href, label)
    }

    /// A maze URL to bounce a client to instead of serving a page.
    pub fn hop_url(&self, req: &MazeRequest, salt: u64) -> String {
        let mut rng = self.rng_for(&req.seed_key(), salt | 1);
        let n = rng.gen_range(1..=2);
        let words: Vec<&str> = (0..n).map(|_| self.markov.link_word(&mut rng)).collect();
        match &req.topic {
            Some(t) => format!("{}/{}/{}", self.cfg.prefix, t, words.join("/")),
            None => format!("{}/{}", self.cfg.prefix, words.join("/")),
        }
    }

    /// Claim a stream slot; `None` means the global stream limit is reached.
    pub fn try_reserve_stream(&self) -> Option<OwnedSemaphorePermit> {
        self.streams.clone().try_acquire_owned().ok()
    }

    pub fn active_streams(&self) -> usize {
        self.max_streams.saturating_sub(self.streams.available_permits())
    }

    /// Serve the maze page for `req` as a slow drip. `on_done` runs when the
    /// stream finishes or the client disconnects.
    pub async fn serve(self: &Arc<Self>, req: MazeRequest, permit: OwnedSemaphorePermit, on_done: OnDone) -> Response {
        let guard = DripGuard { started: Instant::now(), bytes: 0, completed: false, on_done: Some(on_done), _permit: permit };

        if let (Some(client), None) = (&self.upstream, &req.search) {
            match self.upstream_stream(client, &req).await {
                Ok((content_type, upstream)) => {
                    return html_response(content_type, upstream_body(upstream, guard, self.bandwidth.clone()));
                }
                Err(err) => tracing::warn!(error = %err, "upstream tarpit unavailable; using builtin generator"),
            }
        }

        let page = self.render_limited(req).await;
        let chunks = split_chunks(page.html, self.cfg.drip_chunk_bytes);
        let per_chunk = page.delay / (chunks.len().max(1) as u32);
        html_response(
            HeaderValue::from_static("text/html; charset=utf-8"),
            drip_body(chunks, per_chunk, self.bandwidth.clone(), guard),
        )
    }

    /// Generate on the blocking pool, at most `max_concurrent_generations` at once.
    async fn render_limited(self: &Arc<Self>, req: MazeRequest) -> TrapPage {
        let _permit = self.generations.acquire().await;
        let this = Arc::clone(self);
        match tokio::task::spawn_blocking(move || this.render(&req)).await {
            Ok(page) => page,
            Err(err) => {
                tracing::error!(error = %err, "maze page generation failed");
                TrapPage::fallback(&self.cfg.prefix)
            }
        }
    }

    async fn upstream_stream(&self, client: &reqwest::Client, req: &MazeRequest) -> Result<(HeaderValue, UpstreamStream)> {
        // Contained clients can be anywhere on the site; upstream only knows the maze.
        let maze_path = if req.in_maze { req.path.clone() } else { format!("{}/", self.cfg.prefix) };
        let url = format!("{}{}", self.cfg.upstream_url.trim_end_matches('/'), maze_path);
        let resp = client.get(&url).send().await?.error_for_status()?;
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| HeaderValue::from_bytes(v.as_bytes()).ok())
            .unwrap_or_else(|| HeaderValue::from_static("text/html; charset=utf-8"));
        Ok((content_type, Box::pin(resp.bytes_stream())))
    }
}

/// « Previous 1 … 5 6 [7] 8 9 … 31 Next »
fn pager(link: impl Fn(u32) -> String, page: u32, total: u32) -> String {
    let mut out = String::from("<nav class=\"pager\">");
    if page > 1 {
        let _ = write!(out, "<a href=\"{}\" rel=\"prev\">&laquo; Previous</a> ", escape_html(&link(page - 1)));
    }
    let lo = page.saturating_sub(2).max(1);
    let hi = (page + 2).min(total);
    if lo > 1 {
        let _ = write!(out, "<a href=\"{}\">1</a> ", escape_html(&link(1)));
        if lo > 2 {
            out.push_str("&hellip; ");
        }
    }
    for n in lo..=hi {
        if n == page {
            let _ = write!(out, "<strong>{n}</strong> ");
        } else {
            let _ = write!(out, "<a href=\"{}\">{n}</a> ", escape_html(&link(n)));
        }
    }
    if hi < total {
        if hi + 1 < total {
            out.push_str("&hellip; ");
        }
        let _ = write!(out, "<a href=\"{}\">{total}</a> ", escape_html(&link(total)));
    }
    let _ = writeln!(out, "<a href=\"{}\" rel=\"next\">Next &raquo;</a></nav>", escape_html(&link(page + 1)));
    out
}

fn html_response(content_type: HeaderValue, body: Body) -> Response {
    let mut resp = Response::new(body);
    resp.headers_mut().insert(header::CONTENT_TYPE, content_type);
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    resp
}

fn split_chunks(html: String, chunk: usize) -> Vec<Bytes> {
    let bytes = Bytes::from(html);
    let chunk = chunk.max(1);
    let mut out = Vec::with_capacity(bytes.len() / chunk + 1);
    let mut start = 0;
    while start < bytes.len() {
        let end = (start + chunk).min(bytes.len());
        out.push(bytes.slice(start..end));
        start = end;
    }
    out
}

/// Lives inside the response stream. Dropping it (end of stream or client
/// hang-up) releases the stream permit and reports the stats.
struct DripGuard {
    started: Instant,
    bytes: u64,
    completed: bool,
    on_done: Option<OnDone>,
    _permit: OwnedSemaphorePermit,
}

impl DripGuard {
    /// Mark the stream as fully delivered; the stats are reported on drop.
    fn finish(mut self) {
        self.completed = true;
    }
}

impl Drop for DripGuard {
    fn drop(&mut self) {
        if let Some(done) = self.on_done.take() {
            done(TrapStats { bytes: self.bytes, elapsed: self.started.elapsed(), completed: self.completed });
        }
    }
}

fn drip_body(chunks: Vec<Bytes>, per_chunk: Duration, bandwidth: Arc<Bandwidth>, guard: DripGuard) -> Body {
    let s = stream::unfold((chunks.into_iter(), guard), move |(mut it, mut guard)| {
        let bandwidth = bandwidth.clone();
        async move {
            let Some(chunk) = it.next() else {
                guard.finish();
                return None;
            };
            if !per_chunk.is_zero() {
                tokio::time::sleep(per_chunk).await;
            }
            bandwidth.take(chunk.len()).await;
            guard.bytes += chunk.len() as u64;
            Some((Ok::<Bytes, std::io::Error>(chunk), (it, guard)))
        }
    });
    Body::from_stream(s)
}

fn upstream_body(upstream: UpstreamStream, guard: DripGuard, bandwidth: Arc<Bandwidth>) -> Body {
    let s = stream::unfold((upstream, guard, false), move |(mut up, mut guard, failed)| {
        let bandwidth = bandwidth.clone();
        async move {
            if failed {
                return None;
            }
            match up.next().await {
                Some(Ok(chunk)) => {
                    bandwidth.take(chunk.len()).await;
                    guard.bytes += chunk.len() as u64;
                    Some((Ok::<Bytes, std::io::Error>(chunk), (up, guard, false)))
                }
                Some(Err(err)) => Some((Err(std::io::Error::other(err)), (up, guard, true))),
                None => {
                    guard.finish();
                    None
                }
            }
        }
    });
    Body::from_stream(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maze_requests_parse_topics_pages_and_searches() {
        let r = MazeRequest::parse("/archive/harbour-ledger/p7", None, "/archive");
        assert_eq!((r.topic.as_deref(), r.page, r.in_maze), (Some("harbour-ledger"), 7, true));
        assert_eq!(r.base(), "/archive/harbour-ledger");

        let r = MazeRequest::parse("/archive/search", Some("q=Quarterly+Revenue%2C+2024&page=3"), "/archive");
        assert_eq!(r.search.as_deref(), Some("Quarterly Revenue, 2024"));
        assert_eq!((r.topic.as_deref(), r.page), (Some("quarterly-revenue-2024"), 3));

        let r = MazeRequest::parse("/docs/install%20guide.html", None, "/archive");
        assert_eq!((r.topic.as_deref(), r.in_maze), (Some("docs-install-guide"), false));

        assert_eq!(MazeRequest::parse("/", None, "/archive").topic, None);
        assert_eq!(slugify("  !!  "), None);
        assert_eq!(percent_decode("a%2Fb+c%zz%4"), "a/b c%zz%4");
    }
}
