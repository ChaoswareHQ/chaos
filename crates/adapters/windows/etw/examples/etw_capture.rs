//! Live ETW capture example.
//!
//! Starts a real-time ETW session, enables the default providers, and prints
//! every event the translator decodes for a bounded duration.
//!
//! # Requirements
//!
//! - Windows, elevated. `StartTraceW` requires `SeSystemProfilePrivilege`.
//! - Script Block Logging enabled on the host, if you want PowerShell events.
//!
//! # Run
//!
//! ```text
//! cargo run --example etw_capture -p etw -- 30
//! ```

use etw::provider;
use etw::session::{EtwSession, SessionConfig};
use etw::translate::Translator;
use model::{EventKind, HostId, TelemetryEvent};
use std::env;
use std::time::{Duration, Instant};

const SESSION_NAME: &str = "chaos-etw-capture-example";

fn main() {
    if !cfg!(windows) {
        eprintln!("This example requires Windows.");
        return;
    }

    let seconds: u64 = env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    println!("=== ETW Capture Example ===\n");
    println!("Session:   {SESSION_NAME}");
    println!("Duration:  {seconds}s");
    println!("Providers: {}\n", provider::default_providers().len());

    // The device-path mapping is built once and cached. Printing it here
    // means a translation that does not happen is visible immediately. The
    // character count alongside each device string is a check on the trim:
    // a trailing NUL that survived would make the count one greater than
    // the visible text.
    println!("--- Device path mappings ---");
    etw::DevicePaths::global().debug_print();
    println!();

    let config = SessionConfig {
        name: SESSION_NAME.to_string(),
        capacity: 8192,
        providers: provider::default_providers(),
        max_level: provider::LEVEL_INFORMATIONAL,
        buffers: Default::default(),
    };

    let (mut session, reports) = match EtwSession::start(config) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("[error] could not start session: {e}");
            if let Some(remedy) = etw::error::remedy(&e) {
                eprintln!("[remedy] {remedy}");
            }
            std::process::exit(1);
        }
    };

    println!("--- Enable reports ---");
    let mut enabled = 0;
    for report in &reports {
        match report.result {
            Ok(()) => {
                enabled += 1;
                println!("  {:40} ENABLED", report.name);
            }
            Err(code) => {
                println!(
                    "  {:40} FAILED ({code}: {})",
                    report.name,
                    etw::error::hint(code)
                );
            }
        }
    }
    println!("\n  {enabled} of {} providers enabled\n", reports.len());

    let host = HostId::new("etw-capture-example").expect("valid host id");
    let mut translator = Translator::new(host);

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut total = 0usize;
    let mut batch = Vec::new();

    println!("--- Live events ---");
    println!("(do something that generates events while this runs)\n");

    // The live loop. Bounded by the deadline, not by an empty channel: the
    // host may be producing a steady stream and the loop has to stop on
    // schedule regardless.
    while Instant::now() < deadline {
        batch.clear();
        let n = session.drain(&mut batch, 256, Duration::from_millis(500));
        if n == 0 {
            continue;
        }

        for raw in &batch {
            if let Some(event) = translator.translate(raw) {
                total += 1;
                print_event(&event);
            }
        }
    }

    // Security self-check while the session is still alive. After shutdown
    // the session genuinely does not exist, and `session_health` would
    // correctly report "not running" — which is true but misleading in a
    // report that is supposed to describe the state during the run.
    println!("\n=== Security self-check (while the session is live) ===");
    let report = etw::full_report(SESSION_NAME);
    let problems = report.problems();
    if problems.is_empty() {
        println!("  No problems detected.");
    } else {
        for p in &problems {
            println!("  - {p}");
        }
    }

    // Shut the session down **before** the final drain.
    //
    // The callback counts an event as `delivered` the moment `try_send`
    // returns `Ok`, and those events sit in the channel until something
    // reads them. `shutdown` calls `CloseTrace` and then joins the
    // consumer thread, so once it returns no callback can run and no new
    // event can enter the channel. A drain loop that runs after this
    // therefore terminates on its own, and every event the callback
    // counted as `delivered` reaches the translator.
    //
    // Draining before shutdown, by contrast, races the callback: the loop
    // exits with whatever is in the channel, and any event pushed
    // afterwards is counted as `delivered` but never pulled. That is what
    // produced the `2122` gap in the previous run.
    println!("\n--- Shutting down ---");
    if let Err(e) = session.shutdown() {
        eprintln!("[error] shutdown: {e}");
    }

    // Drain whatever was in the channel when the deadline hit. No
    // callback can run now, so the channel only shrinks.
    let mut residual = 0usize;
    loop {
        batch.clear();
        let n = session.drain(&mut batch, 4096, Duration::from_millis(50));
        if n == 0 {
            break;
        }
        residual += n;
        for raw in &batch {
            if let Some(event) = translator.translate(raw) {
                total += 1;
                print_event(&event);
            }
        }
    }

    // Read the counters after the drain. `kernel_lost` returns the values
    // the kernel reports at the stop, and `shutdown` already queried them;
    // the stats from `ctx.stats` are atomic and unaffected by order.
    let stats = session.stats();
    let (kernel_events_lost, kernel_buffers_lost) = session.kernel_lost();

    println!("\n=== Summary ===\n");
    println!("  Events translated:      {total}");
    println!("  Residual after stop:    {residual}");
    println!("  Raw events seen:        {}", stats.received);
    println!("  Raw events delivered:   {}", stats.delivered);
    println!("  Raw events dropped:     {}", stats.dropped);
    println!("  Raw events filtered:    {}", stats.filtered);
    println!("  Raw events classic:     {}", stats.classic);
    println!("  Kernel events lost:     {kernel_events_lost}");
    println!("  Kernel buffers lost:    {kernel_buffers_lost}");
    println!();
    println!("  Translator mapped:      {}", translator.mapped());
    println!("  Translator undecodable: {}", translator.undecodable());
    println!(
        "  Translator unrecognised: {}",
        translator.counts().unrecognised()
    );
    println!();
    println!("  Per-shape counts (mapped / attempted):");
    for (shape, attempted, mapped) in translator.counts().by_shape() {
        println!("    {:<20} {}/{}", shape.as_str(), mapped, attempted);
    }

    println!();
    println!("  Callback buckets:");
    println!("    string_only:      {}", stats.string_only);
    println!("    trace_message:    {}", stats.trace_message);

    let callback_accounted = stats.classic
        + stats.string_only
        + stats.trace_message
        + stats.filtered
        + stats.delivered
        + stats.dropped;
    println!();
    println!(
        "  Callback accounting: received={} accounted={} {}",
        stats.received,
        callback_accounted,
        if stats.callback_accounting_closes() {
            "CLOSES"
        } else {
            "BROKEN"
        }
    );

    let translator_accounted =
        translator.mapped() + translator.undecodable() + translator.counts().unrecognised();
    println!(
        "  Translator accounting: delivered={} accounted={} {}",
        stats.delivered,
        translator_accounted,
        if stats.delivered == translator_accounted {
            "CLOSES"
        } else {
            "BROKEN"
        }
    );

    let gaps = translator.detect_gaps();
    if gaps.is_empty() {
        println!("\n  No telemetry gaps detected.");
    } else {
        println!("\n  Telemetry gaps:");
        for gap in &gaps {
            println!("    {}", gap.describe());
        }
    }

    let failures = translator.failures();
    if !failures.is_empty() {
        println!("\n  First decode failures:");
        for failure in failures {
            println!("    - {failure}");
        }
    }

    println!("\n=== Done ===");
}

fn print_event(event: &TelemetryEvent) {
    let line = match &event.kind {
        EventKind::ProcessStart(p) => format!(
            "process_start       pid={:<6} ppid={:<6} image={}",
            p.pid.as_u32(),
            p.parent_pid
                .map(|p| p.as_u32().to_string())
                .unwrap_or_else(|| "-".into()),
            &*p.executable,
        ),
        EventKind::RegistrySet(r) => format!(
            "registry_set        pid={:<6} key={} value={}",
            r.pid.as_u32(),
            &*r.key_path,
            r.value_name.as_deref().unwrap_or("-"),
        ),
        EventKind::DnsQuery(d) => format!(
            "dns_query           pid={:<6} name={} type={}",
            d.pid.as_u32(),
            &*d.query_name,
            &*d.query_type,
        ),
        EventKind::ScriptBlock(s) => {
            let preview: String = s.text.chars().take(60).collect();
            let ellipsis = if s.text.chars().count() > 60 { "…" } else { "" };
            format!(
                "script_block        pid={:<6} text={:?}{}",
                s.pid.as_u32(),
                preview,
                ellipsis,
            )
        }
        EventKind::Unclassified => "unclassified".to_string(),
        other => format!("other               kind={}", other.as_str()),
    };

    println!("  {line}");
}
