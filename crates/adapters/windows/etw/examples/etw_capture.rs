//! Measure EPS and decode cost under a real load.
//!
//! Run: cargo run --release --example etw_bench -p etw -- 60
//!
//! Release mode matters: TDH is 10–30× slower in debug builds, and a debug
//! run will report decode costs that look like the sensor is broken when it
//! is only unoptimised.

use etw::{EtwSession, SessionConfig, Translator};
use model::HostId;
use std::time::{Duration, Instant};

fn main() {
    let secs: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    let config = SessionConfig {
        name: "chaos-etw-bench".into(),
        capacity: 512 * 1024,
        providers: etw::provider::default_providers(),
        max_level: 5,
        buffers: etw::Buffers {
            size_kb: 64,
            minimum: 32,
            maximum: 128,
            flush_seconds: 1,
        },
    };

    let (mut session, reports) = match EtwSession::start(config) {
        Ok(started) => started,
        Err(e) => {
            eprintln!("{e}");
            if let Some(remedy) = etw::remedy(&e) {
                eprintln!("\n{remedy}");
            }
            std::process::exit(2);
        }
    };
    for r in &reports {
        eprintln!("  enable {:<40} {:?}", r.name, r.result);
    }

    let host = HostId::new("bench-host").expect("valid");
    let mut translator = Translator::new(host);

    println!("collecting for {secs}s ...");
    let started = Instant::now();
    let deadline = started + Duration::from_secs(secs);
    let mut raw_batch: Vec<etw::EtwRaw> = Vec::with_capacity(8192);

    while Instant::now() < deadline {
        session.drain(&mut raw_batch, 8192, Duration::from_millis(250));
        for raw in raw_batch.drain(..) {
            let _ = translator.translate(&raw);
        }
    }

    let wall = started.elapsed();
    let stats = session.stats();
    session.shutdown().ok();
    let (events_lost, buffers_lost) = session.kernel_lost();

    let scored = translator.mapped();
    let undecodable = translator.undecodable();
    let unrecognised = translator.counts().unrecognised();
    let eps = stats.received as f64 / wall.as_secs_f64();

    println!("\n=== benchmark =======================================");
    println!("  wall                {:.2} s", wall.as_secs_f64());
    println!("  raw received        {:>12}", stats.received);
    println!("  raw delivered       {:>12}", stats.delivered);
    println!("  raw dropped         {:>12}", stats.dropped);
    println!("  kernel lost         {:>12}", events_lost + buffers_lost);
    println!("  throughput          {:>12.0} /s", eps);
    println!();
    println!("  translator mapped   {:>12}", scored);
    println!("  translator undecodable {:>8}", undecodable);
    println!("  translator unrecognised {:>7}", unrecognised);

    println!("\n  Per-shape (mapped / attempted):");
    for (shape, attempted, mapped) in translator.counts().by_shape() {
        println!("    {:<20} {}/{}", shape.as_str(), mapped, attempted);
    }

    let kcb = translator.kcb_stats();
    println!("\n  KCB correlation:");
    println!("    learned                {:>12}", kcb.learned);
    println!("    hits on SetValueKey    {:>12}", kcb.hits);
    println!("    misses on SetValueKey  {:>12}", kcb.misses);
    println!(
        "    hit rate               {:>12.1}%",
        kcb.hit_rate() * 100.0
    );
    println!(
        "    cache                  {:>12} / {}",
        kcb.cache_size, kcb.cache_capacity
    );

    println!("\n  Top unrecognised:");
    for (provider, id, n) in translator.histogram().top(15) {
        println!("    {provider:<45} id={id:<6} {n}");
    }

    if !translator.failures().is_empty() {
        println!("\n  First decode failures:");
        for f in translator.failures() {
            println!("    {f}");
        }
    }
    println!("======================================================");
}
