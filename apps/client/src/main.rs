//! Chaos endpoint agent.
//!
//! Two input modes share one detection pipeline:
//!
//! * `--etw <seconds>` opens a real-time ETW session. It needs an elevated
//!   prompt, and it reports sensor-level numbers (provider mix, event ids,
//!   drops) because payload decoding via TDH is not wired to the pipeline yet.
//! * `--replay <n>` feeds a deterministic synthetic stream through the same
//!   `pipeline::Engine`. It needs no privileges, which is what makes the
//!   detection behaviour reproducible and reviewable on any machine.
//!
//! The split is deliberate. The part of this product that must be right —
//! evidence, thresholds, governance, minimisation — has no business depending
//! on whether the person running it holds an admin token.

mod synth;

use mimalloc::MiMalloc;
use model::HostId;
use pipeline::{Config, Engine};
use std::time::{Duration, Instant};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// How many per-event latencies to keep for the percentile report. A reservoir
/// rather than every sample, so a five-million-event run does not allocate
/// forty megabytes of timings.
const LATENCY_SAMPLES: u64 = 200_000;

fn main() {
    let args = Args::parse();

    let host = HostId::new(hostname()).expect("hostname is never empty");
    println!("chaos agent on {host:?}");

    if let Some(seconds) = args.etw_seconds {
        if let Err(e) = run_etw(seconds) {
            eprintln!("etw: {e}");
            std::process::exit(2);
        }
        return;
    }

    run_replay(&args, host);
}

// ---------------------------------------------------------------------------
// replay mode
// ---------------------------------------------------------------------------

fn run_replay(args: &Args, host: HostId) {
    let mut engine = Engine::new(Config::new(host.clone()));
    let mut generator = synth::Generator::new(host, args.seed, args.evil);

    println!(
        "replay: {} events, seed {}, {}% malicious-shaped, prior {:.3}",
        args.replay,
        args.seed,
        args.evil,
        engine.prior()
    );

    let stride = (args.replay / LATENCY_SAMPLES).max(1);
    let mut latencies: Vec<u64> = Vec::with_capacity(LATENCY_SAMPLES.min(args.replay) as usize);
    let mut alert_count = 0u64;

    let wall_start = Instant::now();
    for index in 0..args.replay {
        let event = generator.next();

        let tick = Instant::now();
        let alert = engine.ingest(&event);
        if index % stride == 0 {
            latencies.push(tick.elapsed().as_nanos() as u64);
        }

        if let Some(alert) = alert {
            alert_count += 1;
            if args.verbose {
                println!(
                    "  ALERT [{:>5}] {} | {}",
                    alert_count, alert.severity, alert.title
                );
                println!("          {}", alert.description);
            }
        }
    }
    let wall = wall_start.elapsed();

    print_report(
        &engine,
        &latencies,
        wall,
        args.replay,
        alert_count,
        "synthetic replay",
    );
}

// ---------------------------------------------------------------------------
// etw mode
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn run_etw(seconds: u64) -> Result<(), String> {
    use etw::{EtwSession, SessionConfig};
    use model::ProviderId;
    use std::collections::HashMap;

    let config = SessionConfig {
        name: format!("chaos-{}", std::process::id()),
        providers: etw::provider::default_providers(),
        ..Default::default()
    };

    let (mut session, reports) = EtwSession::start(config).map_err(|e| e.to_string())?;

    for report in &reports {
        match report.result {
            Ok(()) => println!("  enable    {:<38} ok", report.name),
            Err(code) => println!(
                "  enable    {:<38} failed {code} ({})",
                report.name,
                etw::hint(code)
            ),
        }
    }
    if reports.iter().all(|r| r.result.is_err()) {
        return Err("no provider could be enabled".into());
    }

    println!("\ncollecting for {seconds}s ...");

    let mut names: HashMap<ProviderId, u64> = HashMap::new();
    let mut event_ids: HashMap<(ProviderId, u16), u64> = HashMap::new();
    let mut batch = Vec::new();
    let mut total = 0u64;

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut next_tick = Instant::now() + Duration::from_secs(1);

    while Instant::now() < deadline {
        session.drain(&mut batch, 4096, Duration::from_millis(250));
        for raw in batch.drain(..) {
            total += 1;
            *names.entry(raw.wire.provider.clone()).or_default() += 1;
            *event_ids
                .entry((raw.wire.provider.clone(), raw.wire.event_id))
                .or_default() += 1;
        }

        if Instant::now() >= next_tick {
            let stats = session.stats();
            println!(
                "  live      events {:>9}  delivered {:>9}  ch_drop {:>6}  coverage {:.4}",
                stats.received,
                stats.delivered,
                stats.dropped,
                stats.coverage()
            );
            next_tick += Duration::from_secs(1);
        }
    }

    let stats = session.stats();
    session.shutdown().map_err(|e| e.to_string())?;
    let (events_lost, buffers_lost) = session.kernel_lost();

    println!("\n=== sensor report ====================================");
    println!("  events received        {:>12}", stats.received);
    println!("  delivered              {:>12}", stats.delivered);
    println!("  filtered by level      {:>12}", stats.filtered);
    println!("  classic headers        {:>12}", stats.classic);
    println!("  dropped (channel full) {:>12}", stats.dropped);
    println!(
        "  dropped (kernel)       {:>12}",
        u64::from(events_lost) + u64::from(buffers_lost)
    );
    println!("  coverage               {:>12.6}", stats.coverage());
    println!(
        "  mean payload bytes     {:>12.1}",
        stats.mean_payload_bytes()
    );

    let mut providers: Vec<_> = names.into_iter().collect();
    providers.sort_by(|a, b| b.1.cmp(&a.1));
    println!("\n  provider mix");
    for (provider, count) in providers.iter().take(10) {
        println!("    {:<38} {:>10}", provider.as_str(), count);
    }

    let mut ids: Vec<_> = event_ids.into_iter().collect();
    ids.sort_by(|a, b| b.1.cmp(&a.1));
    println!("\n  top event ids");
    for ((provider, id), count) in ids.iter().take(12) {
        let name = etw::provider::event_name(provider.as_str(), *id).unwrap_or("");
        println!(
            "    {:<38} id={:<5} {:>10}  {}",
            provider.as_str(),
            id,
            count,
            name
        );
    }

    println!("\n  note: payload decoding via TDH is not wired to the pipeline yet,");
    println!("        so these events are counted rather than scored.");
    let _ = total;
    Ok(())
}

#[cfg(not(windows))]
fn run_etw(_seconds: u64) -> Result<(), String> {
    Err("ETW is only available on Windows".into())
}

// ---------------------------------------------------------------------------
// reporting
// ---------------------------------------------------------------------------

fn print_report(
    engine: &Engine,
    latencies: &[u64],
    wall: Duration,
    events: u64,
    alerts: u64,
    mode: &str,
) {
    let metrics = engine.metrics();
    let observation = engine.observation(
        events as f64 / wall.as_secs_f64().max(1e-9),
        events as f64 / wall.as_secs_f64().max(1e-9),
    );

    println!("\n=== run report =======================================");
    println!("  mode                   {mode:>12}");
    println!("  events                 {:>12}", metrics.events);
    println!("  process starts         {:>12}", metrics.process_starts);
    println!("  rule findings          {:>12}", metrics.findings);
    println!("  alerts                 {:>12}", alerts);
    println!("  abstained              {:>12}", metrics.abstained);
    println!(
        "  withheld by policy     {:>12}",
        metrics.withheld_by_policy
    );
    println!("  redaction candidates   {:>12}", metrics.redacted_fields);

    println!("\n  decision boundary (A8/A25)");
    println!("    cost ratio             C_fp 1.00 : C_fn 20.00");
    println!("    derived threshold      {:.6}", engine.threshold());
    println!("    autonomy               {:?}", engine.autonomy());
    println!("    audit entries          {:>12}", engine.audit().len());

    println!("\n  rules by information value (A15)");
    let rules = metrics.rules_by_capacity();
    if rules.is_empty() {
        println!("    (no rule fired)");
    }
    for (name, firing) in rules.iter().take(12) {
        println!(
            "    {:<36} {:.4} bits  fires {:>8}",
            name,
            firing.capacity_bits(),
            firing.firings
        );
    }
    println!(
        "    {:<36} {:.4} bits",
        "aggregate", observation.channel_capacity_bits
    );

    println!("\n  state projection (A1)");
    println!("    entities               {:>12}", observation.entities);
    println!(
        "    distinct images (A22)  {:>12}",
        observation.distinct_images
    );
    println!("    structural edges (A23) {:>12}", observation.known_edges);

    println!("\n  observation ledger (A3 / A11)");
    println!(
        "    coverage               {:>12.6}",
        observation.coverage()
    );
    println!(
        "    blind spot             {:>12.6}",
        observation.blind_spot
    );
    println!(
        "    load factor            {:>12.4}",
        observation.load_factor
    );

    println!("\n  throughput");
    println!("    wall time              {:>12.3} s", wall.as_secs_f64());
    println!(
        "    event rate             {:>12.0} /s",
        events as f64 / wall.as_secs_f64().max(1e-9)
    );
    if !latencies.is_empty() {
        let mut sorted = latencies.to_vec();
        sorted.sort_unstable();
        println!(
            "    per-event p50          {:>12} ns",
            percentile(&sorted, 0.50)
        );
        println!(
            "    per-event p99          {:>12} ns",
            percentile(&sorted, 0.99)
        );
        println!(
            "    per-event max          {:>12} ns",
            sorted.last().copied().unwrap_or(0)
        );
        println!("    samples kept           {:>12}", sorted.len());
    }
    println!("======================================================");
}

fn percentile(sorted: &[u64], q: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let index = (((sorted.len() - 1) as f64) * q).round() as usize;
    sorted[index]
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".to_string())
}

// ---------------------------------------------------------------------------
// arguments
// ---------------------------------------------------------------------------

struct Args {
    replay: u64,
    seed: u64,
    evil: u32,
    verbose: bool,
    etw_seconds: Option<u64>,
}

impl Args {
    fn parse() -> Self {
        let mut args = Args {
            replay: 200_000,
            seed: 0xC0FFEE,
            evil: synth::DEFAULT_MALICIOUS_PERCENT,
            verbose: true,
            etw_seconds: None,
        };

        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            match flag.as_str() {
                "--replay" => {
                    args.replay = it.next().and_then(|v| v.parse().ok()).unwrap_or(200_000)
                }
                "--seed" => args.seed = it.next().and_then(|v| v.parse().ok()).unwrap_or(0xC0FFEE),
                "--evil" => {
                    args.evil = it.next().and_then(|v| v.parse().ok()).unwrap_or(2).min(100)
                }
                "--quiet" => args.verbose = false,
                "--etw" => {
                    args.etw_seconds = Some(it.next().and_then(|v| v.parse().ok()).unwrap_or(10))
                }
                "--help" | "-h" => {
                    println!(
                        "chaos agent\n\
                         \n\
                         usage: client [--replay N] [--seed S] [--evil PCT] [--quiet] [--etw SECONDS]\n\
                         \n\
                         --replay N      score N synthetic events through the pipeline (default 200000)\n\
                         --seed S        PRNG seed; the same seed replays identically\n\
                         --evil PCT      share of malicious-shaped events, 0-100 (default 2)\n\
                         --quiet         print the report only, not each alert\n\
                         --etw SECONDS   collect from a real-time ETW session (needs elevation)"
                    );
                    std::process::exit(0);
                }
                other => eprintln!("ignoring unknown argument `{other}`"),
            }
        }
        args
    }
}
