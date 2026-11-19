# Nepenthes (Rust)
Basically an evil ass ddos tool using agents trapped in larptarp to throw their asses at a random domain you wish to fuck up
An asynchronous HTTP crawler tarpit with a separate control plane for managing
sessions, redirects and telemetry. Point an AI agent or crawler at it and the
backend:

- classifies the client from its headers, behaviour and in-browser checks;
- routes it into a deterministic, endless maze of babble pages tuned to keep
  agents reading;
- drips every page out slowly and tracks where it goes;
- detects when it circles or gives up;
- records how much time it lost.

Rust does not try to make the agent "believe" anything: it serves pages, tracks
navigation and enforces the trap rules.

## Quick start

```powershell
cargo run --release
```

- Tarpit (data plane): <http://127.0.0.1:8080/>
- Maze: <http://127.0.0.1:8080/archive/>
- **Dashboard**: <http://127.0.0.1:9100/> (live sessions, timelines, killswitch)
- Control API: <http://127.0.0.1:9100/metrics>

Then point your local agent at `http://127.0.0.1:8080/`.

If you already know your agent's User-Agent, putting a fragment of it in
`classifier.always_contain_user_agents` is the surest catch. While testing,
`classifier.mode = "contain_all"` traps everything.

```powershell
cargo test
```

## How agents get caught

Every session gets a confidence score from 0 to 1, and is contained at
`classifier.threshold` (default 0.6). The score only ratchets up, and
containment is sticky.

| Signal | Catches | Weight |
|---|---|---|
| Bot / HTTP-library User-Agent | python-requests, httpx, aiohttp, curl, node-fetch, LangChain loaders, HeadlessChrome... | 0.6 |
| Empty UA, no `Accept-Language`, `Accept: */*`, no `Sec-Fetch-*` | hand-rolled HTTP clients | 0.6 / 0.15 / 0.1 / 0.1 |
| Opens anything under `/archive` | anything following the hidden honeypot link, the visible entry link, or guessing URLs | 1.0 |
| Ignores the session cookie, high request rate | scrapers | 0.2 / 0.25 |
| `navigator.webdriver` reported by the JS beacon | Playwright, Selenium, Puppeteer browser agents | 0.6 |
| Headless browser reported by the beacon | headless Chrome/Firefox | 0.4 |
| 2+ pages without loading their stylesheet/pixel | text-only fetchers that pretend to be browsers | 0.3 |
| 2+ pages and the JS beacon never fired | clients that don't run JavaScript | 0.15 |
| Several pages with JS but no mouse/touch/scroll/keys | scripted browsers | 0.15 |
| 3+ page hops faster than `min_human_dwell_ms` | agents that don't read | 0.2 |
| 3+ in-site navigations without a `Referer` | agents that type URLs instead of clicking | 0.1 |

**The browser checks.** Every HTML page carries:

- a tiny stylesheet `/_np/s/<nonce>.css`;
- a pixel `/_np/p/<nonce>.gif`;
- a small script that `sendBeacon`s `/_np/b` on load and on page hide.

When the page comes from your real site (proxy mode), the same tags are
injected into it. A webdriver report contains the session at once, so the very
next click lands in the maze.

**Honest limits.** A browser agent driving a real, non-headless Chrome without
the webdriver flag, with full headers, and with synthetic mouse and scroll
events looks like a human at the header level. It is still caught by:

- the hidden honeypot link, if it reads the DOM rather than the screen;
- the visible "Archive" link and search box (`normal.visible_entry_link`), if it acts on what it sees;
- its pacing and Referer behaviour;
- or `always_contain_user_agents` / `contain_all`.

All the beacon fields can be forged by a client that knows they are there.

## Request life cycle

```
receive ─► inspect ─► classify ─► contain ─► track ─► redirect ─► record
           cookies    confidence   maze       nav,     hops /      session time,
           headers,   score 0..1   pages      loops,   exit        requests,
           checks                             give-up              outcome
```

| Stage | Where |
|---|---|
| HTTP entry point | `server.rs`, `routes.rs` |
| Request classifier (cookies, headers, patterns, rate, behaviour) | `middleware/classifier.rs`, `middleware/rate_limit.rs` |
| Browser checks (stylesheet, pixel, JS beacon) | `engine/beacon.rs` |
| Normal traffic vs tarpit manager | `routes.rs` (`dispatch`, `contained`, `normal_response`), `proxy.rs` |
| Session & redirect controller | `engine/session.rs`, `engine/redirect.rs`, `engine/navigation.rs` |
| Maze generator | `engine/tarpit.rs` (+ `engine/corpus.txt`) |
| Telemetry & storage | `telemetry/metrics.rs`, `storage/database.rs` |
| Control plane + dashboard (separate listener) | `control.rs`, `dashboard.html` |

### Session & redirect controller: which of the three options

This implements **options 1 and 3 together**: one centralized `SessionManager`
owns every live session and enforces an explicit state machine. Its
transitions are persisted as SQLx records asynchronously. Handlers stay thin
(option 2 was not used), so every trap rule lives in one place.

```
New ─► Classified ─► Normal ─► Contained ─► Completed
                └──────────────┘    │            │
            any live state ─► Blocked            ▼
            idle / max lifetime ──────────────► Expired
```

- Illegal edges are refused (`SessionState::can_transition_to`).
- Every check and mutation for a session happens under that session's lock
  (`SessionManager::with_session`), so concurrent requests can't corrupt state.
- Each session also carries an **outcome**: `trapped`, `abandoned` (gave up),
  `budget_exhausted`, `released` or `blocked`.

## The maze

A Rust port of the Nepenthes idea (nepenthes-py works too, see below). Each URL
renders the same page every time (seeded by `server.secret` + path), so the
maze looks like a static file tree. The text comes from an order-2 Markov chain
trained on `engine/corpus.txt`, or on any text file set in `tarpit.corpus_path`.

It is tuned for LLM agents, which follow promises of "more" better than random
links:

- **Topic echo.** The page title and headings echo the slug the agent asked
  for. If it opens `/archive/vector-memory-retrieval`, it gets an entry about
  vector memory retrieval.
- **Endless pagination.** Every entry has a "Part N of M" pager (`/p2`, `/p3`...),
  a table of contents, a teaser, and "Continued in part N+1" hooks.
- **Fake search.** `/archive/search?q=...` returns ten on-topic results per
  page, related searches, and more result pages.
- **Slow pages.** Each page drips out over 1.5 to 8 s in 192-byte chunks.
- **Wasted round trips.** Bounded 302 hops (`hop_probability`,
  `max_redirect_depth`) waste extra requests.
- **Loops.** Revisiting the same page `loop_threshold` times inside
  `loop_window` is recorded as a loop.

## Give-up detection, timelines, restart memory

- **Gave up.** A contained session with no request for `abandon_after_secs`
  (120 s) is marked `abandoned`. That is logged as "agent gave up", with how
  long it was trapped, how many pages it saw and where it stopped. If it comes
  back, it is `resumed`.
- **Timeline.** Each session keeps a timeline of its last
  `timeline_max_entries` events: page, maze page, search, hop, transition, and
  browser-check flag. Every entry has an offset, a duration and bytes. See
  `/sessions/{id}/timeline` or click a session in the dashboard.
- **Restart memory.** Contained and blocked fingerprints are remembered for
  `remember_secs` (7 days), including across restarts (loaded from SQLite), so
  a returning agent is trapped on its first request.

## Normal traffic

Legitimate visitors get, in order of preference:

1. `normal.upstream_url`: a reverse proxy to your real site. Bodies are
   streamed, and HTML pages get the browser checks injected; JSON, images and
   compressed bodies are passed through untouched. The upstream's `robots.txt`
   is merged with the maze's `Disallow`.
2. `normal.static_dir`: files from a directory, with the checks injected into HTML.
3. Built-in placeholder pages.

## Storage & retention

- **Session cache.** Active sessions live in an in-memory cache (`DashMap`),
  and the request path never waits on SQLite.
- **Write path.** Records go into a bounded channel. If it is full, the record
  is dropped and counted in `storage_dropped`. A single writer batches them
  into transactions.
- **Snapshots.** Changed sessions are snapshotted every
  `persist_interval_secs`, when they expire, and on shutdown.
- **Retention.** An hourly job deletes rows older than
  `storage.retention_days` (30). You can also prune on demand with
  `POST /storage/prune`.

Tables: `sessions`, `requests`, `transitions`, `events`, `redirects`
(SQLite at `data/nepenthes.db` by default). The schema is migrated
automatically (`PRAGMA user_version`).

## Safety limits (keep your own infrastructure alive)

| Limit | Config |
|---|---|
| Maximum concurrent sessions | `session.max_concurrent_sessions` |
| Maximum requests per session (then 302 to the exit) | `session.max_requests_per_session` |
| Session expiration | `session.idle_timeout_secs`, `session.max_lifetime_secs` |
| Maximum redirect depth | `redirect.max_redirect_depth` |
| Allowlisted redirect destinations | `redirect.allowlist` (open redirects are refused) |
| Global bandwidth | `limits.bandwidth_bytes_per_sec` |
| CPU | `limits.max_concurrent_generations` (generation runs on the blocking pool) |
| Concurrent maze streams / in-flight requests | `limits.max_concurrent_streams`, `limits.max_inflight_requests` |
| Per-IP rate limit | `[rate_limit]` |
| Emergency killswitch | `limits.killswitch`, `POST /killswitch`, or the dashboard button |

Search-engine crawlers are exempt by default (`never_contain_user_agents`), so
your real pages keep their ranking. `robots.txt` disallows the maze, and the
honeypot link is `rel="nofollow"`, so polite crawlers never enter it.

### Load test

```powershell
cargo run --release --example loadtest -- --target http://127.0.0.1:8080 --control http://127.0.0.1:9100 --clients 300 --secs 20
```

Each client is a separate crawler that walks the maze as fast as the server
lets it. With 300 clients against `max_concurrent_streams = 100`,
`bandwidth_bytes_per_sec = 262144` and 1 to 3 s pages (rate limit off), one run
gave:

- **Stream cap held.** Open maze streams peaked at exactly 100.
- **Bandwidth cap held.** The maze sent 239 KiB/s against the 256 KiB/s cap.
- **Excess load was shed cheaply.** 15,002 requests were shed with a 503
  (p50 time to first byte 4 ms).
- **Downtime.** The crawlers lost 2,105 s of combined waiting time in 23 s.

## Control plane

It listens on `control.bind` (default `127.0.0.1:9100`). If `control.token` is
set, send `Authorization: Bearer <token>`, or open the dashboard as
`/?token=<token>`.

| Method | Path | |
|---|---|---|
| GET | `/` | live dashboard |
| GET | `/health` | status, uptime, killswitch |
| GET | `/metrics` | counters, gauges (incl. sessions by state/outcome), `enemy_downtime_secs` |
| GET | `/metrics/prometheus` | Prometheus text format |
| GET | `/sessions?state=contained&limit=50` | live sessions |
| GET | `/sessions/{id}` | one session (signals, behaviour, outcome) |
| GET | `/sessions/{id}/timeline` | the session's timeline + stats (time trapped, pages, searches, loops, dwell) |
| POST | `/sessions/{id}/release` | finish the session; every later request goes to the exit |
| POST | `/sessions/{id}/block` | 403 from now on |
| POST | `/sessions/{id}/contain` | force containment |
| POST | `/sessions/{id}/redirect` | `{"destination": "/exit"}`, one-shot, allowlist enforced |
| GET/POST | `/killswitch` | `{"engaged": true}` disarms the trap |
| GET | `/config` | effective config (secrets redacted) |
| GET | `/history/sessions`, `/history/sessions/{id}/requests`, `/history/events`, `/history/summary` | from SQLite |
| POST | `/storage/prune` | apply the retention policy now |

```powershell
Invoke-RestMethod http://127.0.0.1:9100/metrics
```

```powershell
Invoke-RestMethod "http://127.0.0.1:9100/sessions?state=contained"
```

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:9100/killswitch -ContentType application/json -Body '{"engaged": true}'
```

## Using nepenthes-py instead of the built-in generator

Run nepenthes-py with the same prefix as `tarpit.prefix`, then set:

```toml
[tarpit]
backend = "upstream"
upstream_url = "http://127.0.0.1:8893"
```

Classification, sessions, limits, redirects and telemetry stay in Rust. If the
upstream is unreachable, the built-in generator takes over. The agent-tuned
features (topic echo, pagination, search) only exist in the built-in
generator.

## Layout

```
config/server.toml        every option, commented
src/main.rs               CLI (--config, --print-default-config)
src/lib.rs
src/config.rs             typed config + validation
src/server.rs             AppState, maintenance (expiry, give-up, retention), both listeners, graceful shutdown
src/routes.rs             data-plane routing: normal site vs tarpit manager, HTML check injection
src/proxy.rs              reverse proxy to the real site
src/control.rs            control plane API
src/dashboard.html        the dashboard (embedded into the binary)
src/middleware/           classifier.rs, rate_limit.rs, request_trace.rs
src/engine/               session.rs, tarpit.rs, beacon.rs, navigation.rs, redirect.rs, corpus.txt
src/storage/database.rs   SQLx/SQLite schema + migrations, batch writer, history queries, pruning
src/telemetry/metrics.rs  counters, Prometheus, tracing setup
tests/                    session_tests.rs, redirect_tests.rs, detection_tests.rs
examples/loadtest.rs      concurrent crawler load test
```

The layout follows the original plan, with some additions:

- `lib.rs`, so the integration tests can use the crate.
- `config.rs`, `control.rs`, `proxy.rs` and `beacon.rs`.
- The dashboard and the corpus file.

Hyper is not a direct dependency because axum already runs on hyper and
tokio.

## License

MIT. See [LICENSE](LICENSE).
