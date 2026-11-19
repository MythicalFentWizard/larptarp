//! Load test for the tarpit's safety limits.
//!
//! ```text
//! cargo run --release --example loadtest -- --target http://127.0.0.1:8080 \
//!     --control http://127.0.0.1:9100 --clients 300 --secs 20
//! ```
//!
//! Every client is a distinct crawler (own User-Agent, so its own session)
//! that walks the maze as fast as the server lets it. The report shows how the
//! limits held: the status mix (503 = the stream cap shedding load), received
//! throughput against the bandwidth cap, and the peak number of open maze
//! streams sampled from the control plane.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};

struct Args {
    target: String,
    control: String,
    token: Option<String>,
    clients: usize,
    secs: u64,
}

fn parse_args() -> Result<Args> {
    let mut args = Args {
        target: "http://127.0.0.1:8080".into(),
        control: "http://127.0.0.1:9100".into(),
        token: None,
        clients: 200,
        secs: 20,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| anyhow::anyhow!("{flag} needs a value"));
        match flag.as_str() {
            "--target" => args.target = value()?.trim_end_matches('/').to_string(),
            "--control" => args.control = value()?.trim_end_matches('/').to_string(),
            "--token" => args.token = Some(value()?),
            "--clients" => args.clients = value()?.parse()?,
            "--secs" => args.secs = value()?.parse()?,
            other => bail!("unknown flag {other} (use --target, --control, --token, --clients, --secs)"),
        }
    }
    Ok(args)
}

#[derive(Default)]
struct Stats {
    requests: AtomicU64,
    bytes: AtomicU64,
    errors: AtomicU64,
    statuses: Mutex<BTreeMap<u16, u64>>,
    ttfb_ms: Mutex<Vec<u64>>,
    page_ms: Mutex<Vec<u64>>,
}

fn percentile(values: &mut [u64], p: f64) -> u64 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    let idx = ((values.len() - 1) as f64 * p).round() as usize;
    values[idx]
}

fn maze_links(body: &str) -> Vec<String> {
    body.split("href=\"")
        .skip(1)
        .filter_map(|s| s.split('"').next())
        .filter(|h| h.starts_with("/archive/"))
        .map(|h| h.replace("&amp;", "&"))
        .collect()
}

async fn worker(id: usize, client: reqwest::Client, target: String, stats: Arc<Stats>, deadline: Instant) {
    let ua = format!("loadtest-crawler/{id}");
    let mut path = "/archive/".to_string();
    let mut step = id;
    while Instant::now() < deadline {
        let started = Instant::now();
        let sent = client.get(format!("{target}{path}")).header(reqwest::header::USER_AGENT, &ua).send().await;
        match sent {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let ttfb = started.elapsed().as_millis() as u64;
                let body = resp.bytes().await.unwrap_or_default();
                let total = started.elapsed().as_millis() as u64;
                stats.requests.fetch_add(1, Ordering::Relaxed);
                stats.bytes.fetch_add(body.len() as u64, Ordering::Relaxed);
                *stats.statuses.lock().unwrap().entry(status).or_insert(0) += 1;
                if status == 200 {
                    stats.ttfb_ms.lock().unwrap().push(ttfb);
                    stats.page_ms.lock().unwrap().push(total);
                    let links = maze_links(&String::from_utf8_lossy(&body));
                    step += 1;
                    path = if links.is_empty() { "/archive/".into() } else { links[step % links.len()].clone() };
                } else {
                    // Back off a little, like a real crawler would on 503/429.
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
            Err(_) => {
                stats.errors.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
}

async fn control_metrics(client: &reqwest::Client, args: &Args) -> Option<serde_json::Value> {
    let mut req = client.get(format!("{}/metrics", args.control));
    if let Some(t) = &args.token {
        req = req.bearer_auth(t);
    }
    let body = req.send().await.ok()?.bytes().await.ok()?;
    serde_json::from_slice(&body).ok()
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(10))
        .timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(args.clients)
        .build()?;
    let control_client = reqwest::Client::builder().timeout(Duration::from_secs(5)).build()?;
    let before = control_metrics(&control_client, &args).await;
    if before.is_none() {
        eprintln!("warning: control plane at {} not reachable; peak stream sampling disabled", args.control);
    }

    println!("load test: {} clients for {}s against {}", args.clients, args.secs, args.target);
    let stats = Arc::new(Stats::default());
    let started = Instant::now();
    let deadline = started + Duration::from_secs(args.secs);

    let peak_streams = Arc::new(AtomicU64::new(0));
    let sampler = {
        let peak = peak_streams.clone();
        let client = control_client.clone();
        let args = Args { target: args.target.clone(), control: args.control.clone(), token: args.token.clone(), clients: 0, secs: 0 };
        tokio::spawn(async move {
            while Instant::now() < deadline + Duration::from_secs(5) {
                if let Some(m) = control_metrics(&client, &args).await {
                    let open = m["gauges"]["active_trap_streams"].as_u64().unwrap_or(0);
                    peak.fetch_max(open, Ordering::Relaxed);
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
    };

    let workers: Vec<_> = (0..args.clients)
        .map(|i| tokio::spawn(worker(i, client.clone(), args.target.clone(), stats.clone(), deadline)))
        .collect();
    for w in workers {
        let _ = w.await;
    }
    let elapsed = started.elapsed().as_secs_f64();
    let _ = sampler.await;
    let after = control_metrics(&control_client, &args).await;

    let requests = stats.requests.load(Ordering::Relaxed);
    let bytes = stats.bytes.load(Ordering::Relaxed);
    let mut ttfb = stats.ttfb_ms.lock().unwrap().clone();
    let mut page = stats.page_ms.lock().unwrap().clone();
    println!("\n== client side ==");
    println!("elapsed            {elapsed:.1}s");
    println!("requests           {requests} ({:.1}/s), transport errors {}", requests as f64 / elapsed, stats.errors.load(Ordering::Relaxed));
    let statuses = stats.statuses.lock().unwrap();
    println!("status mix         {}", statuses.iter().map(|(s, n)| format!("{s} x{n}")).collect::<Vec<_>>().join(", "));
    println!("received           {:.1} KiB total, {:.1} KiB/s", bytes as f64 / 1024.0, bytes as f64 / 1024.0 / elapsed);
    println!("first byte p50/p95 {} / {} ms", percentile(&mut ttfb, 0.5), percentile(&mut ttfb, 0.95));
    println!("full page p50/p95  {} / {} ms", percentile(&mut page, 0.5), percentile(&mut page, 0.95));

    if let (Some(b), Some(a)) = (before, after) {
        let delta = |k: &str| a["counters"][k].as_u64().unwrap_or(0).saturating_sub(b["counters"][k].as_u64().unwrap_or(0));
        println!("\n== server side (control plane) ==");
        println!("peak open streams  {}", peak_streams.load(Ordering::Relaxed));
        println!("maze pages started {}", delta("trap_pages_served"));
        println!("maze bytes sent    {:.1} KiB ({:.1} KiB/s)", delta("trap_bytes_sent") as f64 / 1024.0, delta("trap_bytes_sent") as f64 / 1024.0 / elapsed);
        println!("shed (503)         {}", delta("overload_rejections"));
        println!("redirect hops      {}", delta("redirects_hop"));
        println!("enemy downtime     {:.1}s", delta("trapped_ms_total") as f64 / 1000.0);
        println!("sessions now       {}", a["gauges"]["active_sessions"]);
    }
    Ok(())
}
