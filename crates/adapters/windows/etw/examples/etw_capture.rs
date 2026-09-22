//! Live ETW capture — every scored shape, readable, with a health check.
//!
//! Run: cargo run --release --example etw_capture -p etw -- 30
//!      cargo run --release --example etw_capture -p etw -- 30 --quiet
//!
//! Release mode matters: TDH is 10–30× slower in debug builds.
//!
//! `--quiet` skips the per-event line and prints only the reports. That is not
//! cosmetic: the default mode formats and writes every mapped event to stdout,
//! which means the wire rate it reports is bounded partly by the console. In
//! `--quiet` mode the only remaining cost between the channel and the counter is
//! TDH decode, so the wire rate it reports is the decoder's actual throughput
//! and not the terminal's.
//!
//! # What it does that the benchmark does not
//!
//! * Prints each scored event as a line, in the shape's own vocabulary:
//!   `process_start` shows the command line, `file_create` shows the
//!   path, `network_connect` shows the destination.
//! * Checks the audit policy at startup and says, up front, whether
//!   `Security-Auditing` will produce anything. The `auditpol` call
//!   takes ten milliseconds; discovering the same fact from a `0/0` at
//!   the end of a 30-second run is slower.
//! * Ends with a report that names, for every shape, whether it fired
//!   and what to check if it did not. The report is the same
//!   information the benchmark prints, arranged so that a shape that
//!   should be firing and is not is obvious in a glance.
//! * Separates the two rates that get conflated when someone asks "how many
//!   EPS is this": the **capture** rate (raw, kernel → callback) and the
//!   **analysed/wire** rate (raw → typed event). Only the second is a SIEM
//!   sizing number, and they differ by one to two orders of magnitude.
//! * Reports what the run *cost*, not just what it collected: process CPU
//!   time, CPU per raw and per wire event, and how much of the consumer's
//!   time the wire measurement itself took. A rate with no cost next to it
//!   cannot tell you whether the sensor has headroom or is at its ceiling.
//!
//! # What it deliberately does not do
//!
//! It does not write to the registry, change the audit policy, or
//! otherwise configure the host. It reads, and it reports what it saw.
//! The operator changes the policy, because a tool that silently
//! rewrites `HKLM` is a tool nobody should trust.

use etw::{EtwRaw, EtwSession, SessionConfig, Shape, Translator};
use mimalloc::MiMalloc;
use model::{EventKind, HostId};
use std::io::{BufWriter, Write};
use std::process::Command;
use std::time::{Duration, Instant};

/// The allocator the examples use, matching `apps/client`.
///
/// The capture path allocates on one thread (the ETW callback, one payload
/// per event) and frees on another (the consumer, when the event is dropped
/// or translated). That is the pattern the Windows heap is worst at — a
/// cross-thread free takes a heap lock — and the one mimalloc is built for.
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// Depth of the callback → consumer queue, in events.
///
/// `crossbeam-channel`'s bounded channel allocates every slot up front, and
/// an `EtwRaw` is 144 bytes, so this number is multiplied by 144 to get the
/// sensor's fixed memory cost, whether or not a single event arrives. Three
/// readings of it:
///
/// * 64K slots is 9 MiB, and absorbs 1.3 seconds of a 50,000 event/second
///   burst.
/// * The default the crate ships (64K) is this number.
/// * 512K slots — the value this example used to pass — is 72 MiB, to absorb
///   ten seconds of a burst that a desktop has never produced.
///
/// A queue that fills does not lose the run: `on_event` counts the drop and
/// returns, and the report shows it. A sensor that reserves 72 MiB on a
/// laptop to cover a burst that never comes is the worse trade.
const QUEUE_SLOTS: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let secs: u64 = args
        .iter()
        .skip(1)
        .find_map(|s| s.parse().ok())
        .unwrap_or(30);
    // `--quiet` measures the decoder instead of the terminal. See the module doc.
    let quiet = args.iter().any(|a| a == "--quiet" || a == "-q");

    print_banner(secs, quiet);

    // Before starting the session: does this host actually produce the
    // events we are about to look for? The check is cheap and it moves
    // a 30-second diagnosis to a 1-second one.
    check_audit_policy();

    let config = SessionConfig {
        name: format!("chaos-etw-capture-{}", std::process::id()),
        capacity: QUEUE_SLOTS,
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
            eprintln!("\n  {e}");
            if let Some(remedy) = etw::remedy(&e) {
                eprintln!("  {remedy}");
            }
            std::process::exit(2);
        }
    };

    print_providers(&reports);

    let host = HostId::new(hostname()).expect("hostname is never empty");
    let mut translator = Translator::new(host);

    println!("  collecting for {secs}s ...\n");

    // The consumer loop. `drain_each` blocks for up to 250ms awaiting the
    // first event and hands each one straight to this closure — no batch
    // vector in between, so an event moves into the channel and then into
    // the translator, and never anywhere else. Anything that is not a scored
    // shape is counted by the translator and never reaches here.
    let started = Instant::now();
    let deadline = started + Duration::from_secs(secs);
    let mut mapped: u64 = 0;
    let mut wire_bytes: u64 = 0;
    // The consumer thread's own CPU, from `GetThreadTimes`. This thread and the
    // ETW callback thread are the two halves of the sensor, and the split says
    // which one a change moved: the callback copies and hands off, this one
    // decodes. `measuring` is the wall-clock part of this thread's time spent
    // sizing events, i.e. the tool measuring itself rather than the sensor
    // working.
    let mut measuring = Duration::ZERO;
    let mut last_tick = Instant::now();

    let stdout = std::io::stdout();
    let mut out = BufWriter::with_capacity(64 * 1024, stdout.lock());
    let mut since_flush = 0usize;

    while Instant::now() < deadline {
        session.drain_each(8192, Duration::from_millis(250), |raw| {
            let Some(event) = translator.translate(&raw) else {
                return;
            };
            mapped += 1;
            // Measure what would actually go on the wire. Two rates come out
            // of this run and only one of them is a SIEM sizing number:
            //
            //   * `stats.received` is the CAPTURE rate — every event the
            //     kernel handed the callback, most of which is counted and
            //     dropped because no rule reads it;
            //   * this is the ANALYSED rate — the wire events a pipeline or
            //     a SIEM would actually be asked to ingest.
            let measure_started = Instant::now();
            wire_bytes += serialized_len(&event);
            measuring += measure_started.elapsed();
            if !quiet {
                let _ = writeln!(out, "  {}", format_event(&event));
                since_flush += 1;
                if since_flush >= 200 {
                    let _ = out.flush();
                    since_flush = 0;
                }
            }
        });
        // A live tally every second, so a quiet host is distinguishable
        // from a stalled sensor. One line, overwritten in place.
        if last_tick.elapsed() >= Duration::from_secs(1) {
            last_tick = Instant::now();
            let _ = out.flush();
            print!("  [{:>4}s] {mapped} events\r", started.elapsed().as_secs());
            let _ = std::io::stdout().flush();
        }
    }
    let _ = out.flush();
    println!();

    let wall = started.elapsed();
    // Read the cost before the shutdown, so what is reported is the cost of
    // collecting rather than of tearing the session down.
    let cpu = process_cpu_time();
    let consumer_cpu = thread_cpu_time();
    let stats = session.stats();
    session.shutdown().ok();
    let (events_lost, buffers_lost) = session.kernel_lost();

    print_sensor_report(
        &translator,
        &stats,
        events_lost,
        buffers_lost,
        wall,
        wire_bytes,
    );
    print_cost_report(
        &stats,
        &translator,
        cpu,
        consumer_cpu,
        wall,
        measuring,
    );
    print_shape_report(&translator);
    print_histogram(&translator);
    print_failures(&translator);
    print_advice(&translator);
}

/// The serialised size of one wire event, as it would be sent.
///
/// `TelemetryEvent` is what the transport serialises, so measuring its JSON is
/// measuring the shipped bytes instead of guessing at them. The bytes are
/// counted as they are written and then thrown away: building a `Vec` per event
/// to read its length is the same number for a `malloc` and a copy per event on
/// the consumer's thread, which on a loaded host is the single largest cost in
/// this example.
///
/// A serialisation failure counts as zero, which understates the total rather
/// than overstating it.
fn serialized_len(event: &model::TelemetryEvent) -> u64 {
    let mut counter = ByteCounter(0);
    serde_json::to_writer(&mut counter, event)
        .map(|()| counter.0)
        .unwrap_or(0)
}

/// A writer that counts what it is given and stores none of it.
struct ByteCounter(u64);

impl Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// This process's CPU time, user plus kernel, across every thread.
///
/// Wall-clock rates say how fast events arrived; this says what it cost to
/// handle them, and the two answer different questions. A sensor at 0.9 us per
/// raw event has headroom at 200,000 events/second; one at 4 us does not.
fn process_cpu_time() -> Duration {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();

    // SAFETY: the pseudo-handle from `GetCurrentProcess` needs no closing, and
    // the four `FILETIME` out-parameters are stack locals.
    let ok = unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    };
    if ok.is_err() {
        return Duration::ZERO;
    }

    Duration::from_secs_f64(filetime_seconds(kernel) + filetime_seconds(user))
}

/// CPU time of the calling thread, which is the consumer.
///
/// `GetThreadTimes` on the `GetCurrentThread` pseudo-handle needs no open or
/// close, and reports this thread's own user and kernel time rather than the
/// process's. The ETW callback runs on the thread `ProcessTrace` owns, so this
/// is the half of the work that decoding is responsible for.
fn thread_cpu_time() -> Duration {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::{GetCurrentThread, GetThreadTimes};

    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();

    // SAFETY: the pseudo-handle from `GetCurrentThread` needs no closing, and
    // the four `FILETIME` out-parameters are stack locals.
    let ok = unsafe {
        GetThreadTimes(
            GetCurrentThread(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    };
    if ok.is_err() {
        return Duration::ZERO;
    }

    Duration::from_secs_f64(filetime_seconds(kernel) + filetime_seconds(user))
}

/// One `FILETIME` as seconds. The unit is 100 nanoseconds.
fn filetime_seconds(t: windows::Win32::Foundation::FILETIME) -> f64 {
    let ticks = (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime);
    ticks as f64 / 10_000_000.0
}

// ---------------------------------------------------------------------------
// Startup: banner, provider table, audit policy
// ---------------------------------------------------------------------------

fn print_banner(secs: u64, quiet: bool) {
    println!("=== ETW capture ===");
    println!();
    println!("  Duration:  {secs}s");
    println!(
        "  mode:      {}",
        if quiet {
            "quiet (decode throughput; no per-event output)"
        } else {
            "verbose (one line per event)"
        }
    );
    // The provider list is printed from `default_providers()` by
    // `print_providers`, so it cannot drift from the code the way a
    // hand-written banner does.
    println!();
}

fn print_providers(reports: &[etw::EnableReport]) {
    println!("--- Providers ---");
    let mut enabled = 0;
    for r in reports {
        match r.result {
            Ok(()) => {
                enabled += 1;
                println!("  {:<42} enabled", r.name);
            }
            Err(code) => {
                println!("  {:<42} FAILED {code} ({})", r.name, etw::hint(code));
            }
        }
    }
    println!("  {enabled} of {} enabled", reports.len());
    println!();
}

/// Read the audit policy and say whether `Security-Auditing` 4688 will
/// fire.
///
/// `auditpol /get` is a local call and needs no elevation to read. The
/// output is parsed by substring because `auditpol` writes a fixed
/// table and the two substrings that matter — `Process Creation` and
/// `Success and Failure` — do not change between Windows versions.
///
/// If the policy is off, the operator gets the exact two commands to run
/// before the run starts, not after.
fn check_audit_policy() {
    println!("--- Host check ---");

    match Command::new("auditpol")
        .args(["/get", "/subcategory:Process Creation"])
        .output()
    {
        Ok(output) => {
            let text = String::from_utf8_lossy(&output.stdout);
            if text.contains("Process Creation") && text.contains("Success and Failure") {
                println!("  audit policy           Process Creation: Success and Failure");
            } else if text.contains("Process Creation") && text.contains("No Auditing") {
                println!("  audit policy           Process Creation: NOT AUDITED");
                println!();
                println!("  Security-Auditing will stay silent. To fix, run as Administrator:");
                println!(
                    "    auditpol /set /subcategory:\"Process Creation\" /success:enable /failure:enable"
                );
            } else {
                println!("  audit policy           could not parse `auditpol` output");
            }
        }
        Err(e) => {
            println!("  audit policy           could not run auditpol: {e}");
        }
    }

    // The command-line inclusion flag. Off by default; without it, 4688
    // fires but `CommandLine` is empty.
    match Command::new("reg")
        .args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
            "/v",
            "ProcessCreationIncludeCmdLine_Enabled",
        ])
        .output()
    {
        Ok(output) => {
            let text = String::from_utf8_lossy(&output.stdout);
            if text.contains("0x1") {
                println!("  command line in 4688   enabled");
            } else {
                println!("  command line in 4688   NOT ENABLED");
                println!();
                println!(
                    "  4688 will fire but `CommandLine` will be empty. To fix, run as Administrator:"
                );
                println!(
                    "    reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit\" ^"
                );
                println!("        /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f");
            }
        }
        Err(_) => {
            println!("  command line in 4688   not set (key absent)");
        }
    }

    println!();
}

// ---------------------------------------------------------------------------
// Per-event formatting
// ---------------------------------------------------------------------------

/// Format one event in the shape's own vocabulary.
///
/// The point is that a reader should not have to know the shape's
/// `Debug` impl to read the line. Each variant prints what a human would
/// ask for: the process a file operation belongs to, the destination of
/// a network connect, the script text of a block.
fn format_event(event: &model::TelemetryEvent) -> String {
    match &event.kind {
        EventKind::ProcessStart(p) => {
            // The audit variant carries a command line; the kernel
            // variant does not. The command line is what makes the
            // event useful, so when it is present it goes first.
            match p.command_line.as_deref() {
                Some(cmd) if !cmd.is_empty() => format!(
                    "process_start  pid={:<6} ppid={:<6} {}",
                    p.pid.as_u32(),
                    p.parent_pid.map(|x| x.as_u32()).unwrap_or(0),
                    truncate(cmd, 120),
                ),
                _ => format!(
                    "process_start  pid={:<6} ppid={:<6} {}",
                    p.pid.as_u32(),
                    p.parent_pid.map(|x| x.as_u32()).unwrap_or(0),
                    p.executable,
                ),
            }
        }
        EventKind::ProcessExit(p) => format!(
            "process_exit   pid={:<6} code={}",
            p.pid.as_u32(),
            p.exit_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".into()),
        ),
        EventKind::ImageLoad(p) => {
            // Signature status is what makes the event actionable. The
            // three states are named distinctly so a rule author reading
            // a screen of these can see which ones are odd.
            let sig = match p.signed {
                Some(true) => "signed",
                Some(false) => "UNSIGNED",
                None => "sig?",
            };
            format!(
                "image_load     pid={:<6} {:<8} {}",
                p.pid.as_u32(),
                sig,
                p.image_path,
            )
        }
        EventKind::RegistrySet(r) => format!(
            "registry_set   pid={:<6} {} = {}",
            r.pid.as_u32(),
            r.key_path,
            r.value_name.as_deref().unwrap_or("(default)"),
        ),
        EventKind::FileCreate(f) => format!("file_create    pid={:<6} {}", f.pid.as_u32(), f.path,),
        EventKind::FileRename(f) => format!(
            "file_rename    pid={:<6} {} -> {}",
            f.pid.as_u32(),
            f.old_path,
            f.new_path,
        ),
        EventKind::FileDelete(f) => format!("file_delete    pid={:<6} {}", f.pid.as_u32(), f.path,),
        EventKind::NetworkConnect(n) => format!(
            "net_connect    pid={:<6} {}:{} -> {}:{}",
            n.pid.as_u32(),
            n.source_ip,
            n.source_port,
            n.destination_ip,
            n.destination_port,
        ),
        EventKind::NetworkDisconnect(n) => format!(
            "net_disconnect pid={:<6} {}:{} -> {}:{} bytes={}",
            n.pid.as_u32(),
            n.source_ip,
            n.source_port,
            n.destination_ip,
            n.destination_port,
            n.bytes_sent
                .map(|b| b.to_string())
                .unwrap_or_else(|| "?".into()),
        ),
        EventKind::DnsQuery(d) => format!(
            "dns_query      pid={:<6} {} type={}",
            d.pid.as_u32(),
            d.query_name,
            d.query_type,
        ),
        EventKind::ScriptBlock(s) => format!(
            "script_block   pid={:<6} {}",
            s.pid.as_u32(),
            truncate(&s.text.replace('\n', " "), 120),
        ),
        // The WMI shapes print the caller, because "WMI created a process" is
        // only actionable next to "and it came from off-box".
        EventKind::WmiProcess(w) => format!(
            "wmi_process    pid={:<6} client={:<6} {:>6} {}",
            w.pid.as_u32(),
            w.client_pid.map(|p| p.as_u32()).unwrap_or(0),
            match w.is_local {
                Some(true) => "local",
                Some(false) => "REMOTE",
                None => "?",
            },
            truncate(&w.command_line, 100),
        ),
        EventKind::WmiSubscription(s) => format!(
            "wmi_sub        {} consumer={}",
            s.namespace,
            s.consumer.as_deref().unwrap_or("(none)"),
        ),
        EventKind::TaskRegistered(t) => format!(
            "task_registered user={} {}",
            t.user.as_deref().unwrap_or("?"),
            t.task_name,
        ),
        other => format!("unclassified   {:?}", other),
    }
}

/// Truncate a string at a character boundary, adding `…` when cut.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

// ---------------------------------------------------------------------------
// End-of-run reports
// ---------------------------------------------------------------------------

fn print_sensor_report(
    translator: &Translator,
    stats: &etw::StatsSnapshot,
    events_lost: u32,
    buffers_lost: u32,
    wall: Duration,
    wire_bytes: u64,
) {
    let secs = wall.as_secs_f64().max(1e-9);
    let capture_eps = stats.received as f64 / secs;
    let wire_eps = translator.mapped() as f64 / secs;

    println!("=== Sensor report ======================================");
    println!("  wall                {:>12.2} s", wall.as_secs_f64());
    println!("  raw received        {:>12}", stats.received);
    println!("  raw delivered       {:>12}", stats.delivered);
    println!("  raw dropped         {:>12}", stats.dropped);
    println!("  kernel lost         {:>12}", events_lost + buffers_lost);
    println!();
    println!("  translator mapped   {:>12}", translator.mapped());
    println!("  translator undecodable {:>8}", translator.undecodable());
    println!(
        "  translator unrecognised {:>7}",
        translator.counts().unrecognised()
    );
    println!();

    // The two rates, side by side and labelled, because conflating them is the
    // easiest way to size a SIEM wrongly by an order of magnitude. The capture
    // rate is what the kernel handed over; the wire rate is what a pipeline or a
    // SIEM would be asked to ingest, and the gap between them is the whole point
    // of the shape table.
    println!("=== Rates ==============================================");
    println!(
        "  capture             {:>12.0} /s   (raw, kernel -> callback)",
        capture_eps
    );
    println!(
        "  analysed (wire)     {:>12.0} /s   (raw -> typed event)",
        wire_eps
    );
    if stats.received > 0 {
        println!(
            "  wire / capture      {:>12.1} %",
            wire_eps / capture_eps * 100.0
        );
    }
    println!();

    // Splunk licenses on volume, not on event count, so bytes/day is the number
    // that predicts cost. Wazuh's limiter is EPS-shaped, so both are printed.
    if translator.mapped() > 0 {
        let mean = wire_bytes as f64 / translator.mapped() as f64;
        let gb_per_day = wire_bytes as f64 / secs * 86_400.0 / 1e9;
        println!("=== Wire volume (what a SIEM would ingest) =============");
        println!("  mean event size     {:>12.0} bytes", mean);
        println!("  wire bytes          {:>12}", wire_bytes);
        println!("  at this rate        {:>12.2} GB/day", gb_per_day);
        println!(
            "  at 1k events/s      {:>12.2} GB/day (for comparison)",
            1000.0 * mean * 86_400.0 / 1e9
        );
        println!();
        println!(
            "  note: this is the wire rate, not the capture rate. {:.0}% of raw \
             events were counted and dropped.",
            (1.0 - wire_eps / capture_eps.max(1e-9)) * 100.0
        );
        println!();
    }
}

/// What the run cost, next to what it produced.
///
/// The rates above say how fast events arrived and how many became wire
/// events. This says what handling them took, in the only unit that answers
/// "is there headroom": CPU seconds, and CPU seconds per event. A rate with no
/// cost beside it cannot tell a sensor that is keeping up from one that is
/// already at its ceiling on a quiet host.
///
/// The process total and the consumer thread are reported separately because
/// the sensor is two threads. The difference between them is the ETW callback
/// and the tracing machinery behind it, which no amount of decode work moves;
/// the consumer line is the half that decoding changes.
fn print_cost_report(
    stats: &etw::StatsSnapshot,
    translator: &Translator,
    cpu: Duration,
    consumer_cpu: Duration,
    wall: Duration,
    measuring: Duration,
) {
    let cpu = cpu.as_secs_f64();
    let consumer_cpu = consumer_cpu.as_secs_f64();
    let secs = wall.as_secs_f64().max(1e-9);
    let raw = stats.received.max(1) as f64;
    let mapped = translator.mapped().max(1) as f64;
    let slot = std::mem::size_of::<EtwRaw>();

    println!("=== Cost (what the run took) ===========================");
    println!(
        "  cpu, process        {:>12.3} s   (user + kernel, both threads)",
        cpu
    );
    println!(
        "  cpu, consumer       {:>12.3} s   (drain + decode + the wire measurement)",
        consumer_cpu
    );
    println!("  cpu / raw event     {:>12.3} us", cpu / raw * 1e6);
    println!("  cpu / wire event    {:>12.3} us", cpu / mapped * 1e6);
    println!(
        "  cpu of one core     {:>12.1} %   (over {secs:.2} s wall)",
        cpu / secs * 100.0
    );
    println!(
        "  wire measurement    {:>12.3} s   (serde_json, to size each event)",
        measuring.as_secs_f64()
    );
    println!();
    println!(
        "  queue               {:>12.1} MiB   ({QUEUE_SLOTS} slots x {slot} bytes, allocated up front)",
        QUEUE_SLOTS as f64 * slot as f64 / (1024.0 * 1024.0)
    );
    println!();
}

/// The shape table, with a note per shape about whether it fired and
/// what to check if it did not.
///
/// The `expected` column is what makes this more than the benchmark
/// report: a shape with `0/0` on a busy host is not the same as a shape
/// with `0/0` on a host where the source is silent for a policy reason,
/// and the column says which is which.
fn print_shape_report(translator: &Translator) {
    println!("=== Per-shape ==========================================");
    println!(
        "  {:<22} {:>10} {:>10}  {:<20}",
        "shape", "mapped", "attempted", "note"
    );
    for (shape, attempted, mapped) in translator.counts().by_shape() {
        let note = if attempted == 0 {
            match expected_to_fire(shape) {
                Some(reason) => format!("silent: {reason}"),
                None => "quiet host".to_string(),
            }
        } else if mapped < attempted {
            let failures = attempted - mapped;
            format!("{failures} undecodable")
        } else {
            "ok".to_string()
        };
        println!(
            "  {:<22} {:>10} {:>10}  {:<20}",
            shape.as_str(),
            mapped,
            attempted,
            note
        );
    }
    println!();
}

/// Whether a shape is expected to fire on a default host, and why not
/// when it is not.
///
/// `ProcessStartAudit` is named as "audit policy + system logger" rather
/// than as a policy issue alone, because the failure mode the sensor
/// actually hit was the session not being a system logger — a
/// configuration the operator cannot see from `auditpol` output. The
/// message says both parts so an operator checking the policy does not
/// stop there when the policy is already correct.
fn expected_to_fire(shape: Shape) -> Option<&'static str> {
    match shape {
        Shape::ScriptBlock => Some("needs Script Block Logging (policy)"),
        Shape::ProcessStartAudit => Some("needs audit policy + system logger mode"),
        _ => None,
    }
}
/// The unrecognised-traffic breakdown, top 15.
fn print_histogram(translator: &Translator) {
    let histogram = translator.histogram();
    if histogram.total() == 0 {
        return;
    }
    println!("=== Unrecognised (top 15) ==============================");
    for (provider, id, n) in histogram.top(15) {
        println!("  {provider:<45} id={id:<6} {n}");
    }
    if histogram.folded() > 0 {
        println!("  (+ {} folded into catch-all)", histogram.folded());
    }
    println!();
}

fn print_failures(translator: &Translator) {
    if translator.failures().is_empty() {
        return;
    }
    println!("=== First decode failures ==============================");
    for f in translator.failures() {
        println!("  {f}");
    }
    println!();
}

/// Recommendations, based on what the run actually produced.
///
/// Deliberately short and specific. Every line names a thing the
/// operator can do in the next five minutes, or says nothing.
fn print_advice(translator: &Translator) {
    let counts = translator.counts();
    let mut advice: Vec<&str> = Vec::new();

    if counts.attempted(Shape::ScriptBlock) == 0 {
        advice.push(
            "script_block is silent: enable Script Block Logging on this host \
             (EnableScriptBlockLogging in Group Policy, or run the sensor's \
             script_block rule against a PowerShell script to test the path)",
        );
    }
    if counts.attempted(Shape::ProcessStartAudit) == 0 {
        advice.push(
            "process_start_audit is silent. Two possible causes, check in order:\n\
             \x20   1. the audit policy is off: run\n\
             \x20        auditpol /set /subcategory:\"Process Creation\" /success:enable /failure:enable\n\
             \x20        reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\\n\
             \x20        Policies\\System\\Audit\" /v ProcessCreationIncludeCmdLine_Enabled \\\n\
             \x20        /t REG_DWORD /d 1 /f\n\
             \x20   2. the session is not a system logger: this is the crate's job, and\n\
             \x20      if the audit policy is confirmed on and this shape is still silent,\n\
             \x20      the LogFileMode is missing EVENT_TRACE_SYSTEM_LOGGER_MODE (0x02000000)",
        );
    }
    if counts.undecodable(Shape::FileRename) > 0 {
        advice.push(
            "some file_rename events carried no name at all (43% of them in one live \
             run on the reference host). This is NOT a missing field spelling: \
             `Microsoft-Windows-Kernel-File` id 20 declares exactly one name field \
             (`FileName`) and no old/new pair, so FILE_NEW_NAME / FILE_OLD_NAME have \
             nothing left to add. The field is also a name *fragment*, not a path, so \
             old_path and new_path will read the same. Reading the event as \
             \"a rename happened on this name fragment\" is correct; reading it as \
             \"this file moved from A to B\" is not. Confirm with: \
             tools/dump-fields.ps1 -Provider Microsoft-Windows-Kernel-File -Id \"20\"",
        );
    }
    if translator.undecodable() == 0 && counts.unrecognised() > 0 {
        advice.push(
            "no decode failures; the unrecognised traffic is shapes the sensor \
             does not score, which is the design (see `shape.rs`)",
        );
    }

    if advice.is_empty() {
        println!("=== Advice =============================================");
        println!("  nothing to fix; every scored shape is behaving as expected");
        return;
    }

    println!("=== Advice =============================================");
    for line in advice {
        println!("  - {line}");
    }
    println!();
}

// ---------------------------------------------------------------------------
// Host identity
// ---------------------------------------------------------------------------

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".to_string())
}
