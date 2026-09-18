//! Chaos endpoint agent.
//!
//! One source: a live ETW session on this machine, decoded through TDH into the
//! wire events the detection pipeline scores. There is no synthetic mode — the
//! agent reads the host it is running on, which is also why it needs an elevated
//! token: that is what a trace session requires, and pretending otherwise would
//! mean shipping a fallback path that never touches the machine it claims to
//! monitor.
//!
//! * `--enroll URL` exchanges the bootstrap secret for this host's credential
//!   and stores it. Run once, by whatever provisions the machine.
//! * `--ship URL` collects, scores and ships. With no duration the agent runs
//!   until it is stopped, which is how it is meant to be deployed; `--etw
//!   SECONDS` bounds the run and prints a full report, which is how it is meant
//!   to be diagnosed.

mod credential;

use mimalloc::MiMalloc;
use model::{Alert, HostId, TelemetryEvent};
use pipeline::{AutonomyLevel, Config, Engine, Response};
use ports::{ActionError, Actuator};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use transport::{CleartextTransport, Endpoint, IngestSink};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// How many per-event scoring latencies the report keeps.
///
/// Only a bounded run prints a report, and a bounded run is a diagnostic rather
/// than a soak, so this fills without truncating at the rates a single host
/// produces. Nothing depends on the number being complete: it is a sample, and
/// the report says so.
const LATENCY_SAMPLES: usize = 20_000;

/// Events per shipped batch. Small enough that the batching path is exercised
/// early, large enough not to make delivery one request per event.
const SHIP_BATCH: usize = 500;

fn main() {
    let args = Args::parse();

    let host = HostId::new(hostname()).expect("hostname is never empty");
    println!("chaos agent on {host:?}");

    if let Some(url) = args.enroll_url.clone() {
        if let Err(e) = run_enroll(&url, &args) {
            eprintln!("enroll: {e}");
            std::process::exit(2);
        }
        return;
    }

    if let Err(e) = run_etw(&args, host) {
        eprintln!("etw: {e}");
        std::process::exit(2);
    }
}

// ---------------------------------------------------------------------------
// enrollment
// ---------------------------------------------------------------------------

fn run_enroll(url: &str, args: &Args) -> Result<(), String> {
    let endpoint = Endpoint::parse(url).map_err(|e| e.to_string())?;
    let mut transport = CleartextTransport::new();

    let request = protocol::EnrollRequest {
        hostname: hostname(),
        os: std::env::consts::OS.to_string(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    println!("enrolling with {url}");
    let credential = transport::enroll(&mut transport, &endpoint, &args.enrollment_token, &request)
        .map_err(|e| e.to_string())?;

    credential::save(&args.token_file, &credential).map_err(|e| e.to_string())?;

    println!("  host id        {}", credential.host_id);
    println!("  credential     {}", args.token_file.display());
    println!("  the token is a bearer credential: anyone who reads that file can");
    println!("  submit telemetry as this host, which is why it is written 0600");
    println!("  (or owner-only via icacls on Windows).");
    Ok(())
}

// ---------------------------------------------------------------------------
// scoring and shipping
// ---------------------------------------------------------------------------

/// A run, as far as the pipeline is concerned.
///
/// Both sources differ only in where a [`TelemetryEvent`] comes from. Everything
/// after that is identical — score it, queue the wire copy, keep the server's
/// view of the coalesced counts current — and writing it once is what makes
/// `--follow` a flag rather than a second implementation of the same run.
struct Shipper {
    engine: Engine,
    sink: Option<IngestSink>,
    /// Present only when this run was allowed to act. Absent means every proposal
    /// is surfaced and nothing is touched, which is the default: an agent that
    /// changes the machine because someone started it is not a thing anyone
    /// should get by accident.
    actuator: Option<Box<dyn Actuator>>,
    /// What this run did, in the order it did it, so that it can be undone in
    /// reverse. Only the reversible actions are here, which is why the type
    /// carries an inverse in the first place.
    applied: Vec<Response>,
    /// Proposals surfaced and not carried out, because governance withheld them
    /// or because this run may not act.
    proposed: u64,
    actioned: u64,
    refused: u64,
    failed: u64,
    alerts: u64,
    ship_errors: u64,
    /// When the queued batch and the restated alerts were last pushed.
    last_push: Instant,
    last_report: Instant,
    interval: Duration,
    verbose: bool,
}

impl Shipper {
    fn new(
        config: Config,
        sink: Option<IngestSink>,
        actuator: Option<Box<dyn Actuator>>,
        interval: Duration,
        verbose: bool,
    ) -> Self {
        let now = Instant::now();
        Self {
            engine: Engine::new(config),
            sink,
            actuator,
            applied: Vec::new(),
            proposed: 0,
            actioned: 0,
            refused: 0,
            failed: 0,
            alerts: 0,
            ship_errors: 0,
            last_push: now,
            last_report: now,
            interval,
            verbose,
        }
    }

    /// Score one event and queue its wire copy.
    ///
    /// Returns how long scoring took, so a caller can sample it without reaching
    /// inside.
    fn feed(&mut self, event: TelemetryEvent) -> u64 {
        let tick = Instant::now();
        let alert = self.engine.ingest(&event);
        let scored_ns = tick.elapsed().as_nanos() as u64;

        // Outside the timed region on purpose: acting on a process costs a syscall
        // and a guard check, and folding that into the scoring latency would make
        // the detector look slower than it is.
        self.act_on_responses();

        if let Some(sink) = self.sink.as_mut() {
            // The event is moved, not cloned: it has already been scored, and the
            // wire copy is the only one still needed.
            if let Err(e) = sink.enqueue(event) {
                self.ship_errors += 1;
                if self.ship_errors <= 3 {
                    eprintln!("  ship error: {e}");
                }
            }
        }

        if let Some(alert) = alert {
            self.alerts += 1;
            if let Some(sink) = self.sink.as_mut() {
                sink.enqueue_alert(alert.clone());
            }
            if self.verbose {
                print_alert(self.alerts, &alert);
            }
        }

        scored_ns
    }

    /// Push what is queued, and restate every alert that coalescing has added to
    /// since the last push.
    ///
    /// A restatement repeats the original alert id, so the server merges it into
    /// the row it already holds rather than adding a row beside it. That is what
    /// makes pushing on a timer safe, and it is what keeps the console's counts
    /// current: firings folded since the last push are in no row at all until
    /// something restates them, and waiting for the five-minute suppression
    /// window to lapse would leave the queue showing a stale count for five
    /// minutes.
    fn push(&mut self) {
        self.last_push = Instant::now();
        let Some(sink) = self.sink.as_mut() else {
            return;
        };
        for alert in self.engine.flush_suppressed() {
            sink.enqueue_alert(alert);
        }
        if let Err(e) = sink.submit() {
            self.ship_errors += 1;
            if self.ship_errors <= 3 {
                eprintln!("  ship error: {e}");
            }
        }
    }

    /// Push if the interval has elapsed.
    fn tick(&mut self) {
        if self.last_push.elapsed() >= self.interval {
            self.push();
        }
    }

    /// A one-line progress report, printed on the same interval.
    ///
    /// A run that never ends cannot print a report at the end, so it prints one
    /// as it goes. `folded` is the number that matters: it is what coalescing
    /// swallowed, and it is the count the server would be missing if the agent
    /// stopped without restating.
    fn report_live(&mut self, events: u64, started: Instant) {
        if self.last_report.elapsed() < self.interval {
            return;
        }
        self.last_report = Instant::now();

        let rate = events as f64 / started.elapsed().as_secs_f64().max(1e-9);
        let metrics = self.engine.metrics();
        print!(
            "  live   events {events:>10}  {rate:>8.0}/s  alerts {:>5}  folded {:>7}  \
             abstained {:>7}",
            self.alerts, metrics.suppressed, metrics.abstained
        );
        if let Some(sink) = self.sink.as_ref() {
            print!(
                "  shipped {:>10}  pending {:>6}",
                sink.shipped(),
                sink.pending()
            );
        }
        if self.actuator.is_some() {
            print!(
                "  actions {:>5}  refused {:>4}",
                self.actioned, self.refused
            );
        }
        println!();
    }

    // -----------------------------------------------------------------------
    // response
    // -----------------------------------------------------------------------

    /// Carry out what the pipeline proposed, to the extent this run is allowed.
    ///
    /// Two gates have already spoken by the time a proposal arrives: governance
    /// decided it may run unattended, which is what `automatic` means, and the
    /// operator decided by starting this agent with `--respond` that this process
    /// may act at all. A third sits in the actuator, and it is the only one no
    /// configuration can open.
    ///
    /// Every proposal is printed whether or not it was carried out. A run that
    /// silently swallows "would have frozen powershell.exe" is a run whose
    /// operator cannot tell a policy that is too strict from a detector that sees
    /// nothing.
    fn act_on_responses(&mut self) {
        for proposal in self.engine.take_responses() {
            let (outcome, detail) = self.carry_out(proposal.response, proposal.automatic);
            println!(
                "  ACTION [{outcome}] {} (alert {})",
                proposal.response.describe(),
                proposal.alert_id.as_str()
            );
            if let Some(detail) = detail {
                println!("         {detail}");
            }
        }
    }

    /// Apply one response if the gates allow it, and say what happened.
    ///
    /// The word that comes back is the audit trail an operator reads, so each one
    /// means something different and none of them is decoration:
    ///
    /// - `proposed` — surfaced and not attempted. Governance withheld it, or this
    ///   run was started without `--respond`. This is the expected outcome.
    /// - `dry run` — cleared, and withheld anyway because the actuator was told to
    ///   resolve and refuse without touching anything.
    /// - `applied` — the operating system accepted it.
    /// - `refused` — a guard said no. That is the guard working, not a failure: a
    ///   protected process is supposed to come back this way.
    /// - `failed` — the operating system declined. That is a race or a bug, and
    ///   the operator should see it as one.
    fn carry_out(&mut self, response: Response, automatic: bool) -> (&'static str, Option<String>) {
        if !automatic {
            self.proposed += 1;
            return ("proposed", None);
        }
        let Some(actuator) = self.actuator.as_mut() else {
            self.proposed += 1;
            return ("proposed", None);
        };

        let dry = actuator.is_dry_run();
        match actuator.apply(response) {
            Ok(()) => {
                self.actioned += 1;
                // Remembered so it can be undone. A response with no inverse is
                // the type saying there is no way back from it, which is exactly
                // why a terminate is not wired up yet.
                if response.is_reversible() {
                    self.applied.push(response);
                }
                if dry {
                    ("dry run", None)
                } else {
                    ("applied", None)
                }
            }
            Err(ActionError::Refused(reason)) => {
                self.refused += 1;
                ("refused", Some(reason))
            }
            Err(e) => {
                self.failed += 1;
                ("failed", Some(e.to_string()))
            }
        }
    }

    /// Undo everything this run did, newest first.
    ///
    /// A suspended process is released when the agent stops, and that is the whole
    /// reason suspend was chosen over terminate: once the agent is gone there is
    /// nobody watching what it froze, and a machine left holding a frozen process
    /// with no one accountable for it is worse than the freeze was worth.
    ///
    /// Reverse order, because that is the only order that undoes a sequence
    /// correctly. It costs nothing today — two actions on one pid would be a bug —
    /// and writing it the wrong way round would be a latent one.
    fn revert(&mut self) {
        let actions = std::mem::take(&mut self.applied);
        if actions.is_empty() {
            return;
        }
        let Some(actuator) = self.actuator.as_mut() else {
            return;
        };

        println!(
            "\n  releasing {} process(es) held by this run",
            actions.len()
        );
        for response in actions.into_iter().rev() {
            let Some(inverse) = response.inverse() else {
                continue;
            };
            match actuator.apply(inverse) {
                Ok(()) => println!("    released   {}", response.describe()),
                Err(e) => eprintln!("    still held {}: {e}", response.describe()),
            }
        }
    }

    /// What this run did to the machine, as a section of the report.
    ///
    /// Printed even when every number is zero, because "nothing was acted on" is
    /// the fact an operator most wants confirmed after a run they did not watch.
    fn print_response_report(&self) {
        println!("\n  response (A6 / A12)");
        println!(
            "    this run               {:>12}",
            match self.actuator.as_ref() {
                None => "propose only",
                Some(a) if a.is_dry_run() => "dry run",
                Some(_) => "acting",
            }
        );
        println!("    proposals surfaced     {:>12}", self.proposed);
        println!("    carried out            {:>12}", self.actioned);
        println!("    refused by a guard     {:>12}", self.refused);
        println!("    failed at the os       {:>12}", self.failed);
    }
}

/// Build the shipping sink, if the caller asked for one.
fn open_sink(args: &Args) -> Result<Option<IngestSink>, String> {
    let Some(url) = &args.ship_url else {
        return Ok(None);
    };

    let credential = credential::load(&args.token_file)
        .map_err(|e| format!("cannot read {}: {e}", args.token_file.display()))?
        .ok_or_else(|| {
            format!(
                "no credential at {}; run --enroll first",
                args.token_file.display()
            )
        })?;
    let endpoint = Endpoint::parse(url).map_err(|e| e.to_string())?;

    println!("shipping to {url} as host {}", credential.host_id);
    Ok(Some(IngestSink::new(
        endpoint,
        Box::new(CleartextTransport::new()),
        &credential,
        SHIP_BATCH,
    )))
}

/// Close a bounded run: release what was held, push the last batch, then report.
fn finish(
    mut shipper: Shipper,
    latencies: &[u64],
    wall: Duration,
    events: u64,
    mode: &str,
) -> Result<(), String> {
    // Release before the batch goes out, so that the alert rows the server keeps
    // describe a machine that is no longer in the state the run left it in.
    shipper.revert();
    shipper.push();

    print_report(
        &shipper.engine,
        latencies,
        wall,
        events,
        shipper.alerts,
        mode,
    );
    shipper.print_response_report();

    if let Some(sink) = shipper.sink.as_ref() {
        println!("  shipping (A19-minimised batch ingest)");
        println!("    host id                {:>12}", sink.host_id());
        println!("    events accepted        {:>12}", sink.shipped());
        println!("    batches failed         {:>12}", sink.failed());
        println!("    ship errors            {:>12}", shipper.ship_errors);
        println!("    still pending          {:>12}", sink.pending());
        if let Some(error) = sink.last_error() {
            println!("    last error             {error}");
        }
        if sink.shipped() == 0 && shipper.ship_errors > 0 {
            eprintln!("\nthe server rejected everything; is it running and is this host enrolled?");
            return Err("no events were accepted".to_string());
        }
    }

    Ok(())
}

fn print_alert(count: u64, alert: &Alert) {
    println!("  ALERT [{count:>5}] {} | {}", alert.severity, alert.title);
    println!("          {}", alert.description);
}

/// Say, before collection starts, which of the three response gates are open.
///
/// They are independent, and a run that is open at two and shut at the third
/// reads exactly like a run that is open at none. Saying it out loud is cheaper
/// than an operator assuming, and the assumption that matters — "of course it
/// will not touch my processes" — is the one the default configuration makes
/// true.
/// Say, before collection starts, which of the three response gates are open.
///
/// They are independent, and a run that is open at two and shut at the third
/// reads exactly like a run that is open at none. Saying it out loud is cheaper
/// than an operator assuming, and the assumption that matters — "of course it
/// will not touch my processes" — is the one the default configuration makes
/// true.
#[cfg(windows)]
fn print_gates(args: &Args, actuator: Option<&dyn Actuator>) {
    print!(
        "{}",
        gate_report(args.autonomy, args.max_auto, args.respond, actuator)
    );
}

/// The three gates as text.
///
/// Separate from the printing so that what the agent claims about its own
/// authority can be asserted on rather than eyeballed. This is the paragraph an
/// operator reads instead of checking, and the one claim in it that may never be
/// wrong is "it will not touch anything".
#[cfg(windows)]
fn gate_report(
    autonomy: AutonomyLevel,
    max_auto: model::Severity,
    respond: bool,
    actuator: Option<&dyn Actuator>,
) -> String {
    // The ceiling only matters at `Auto`, and it is the number that decides whether
    // a freeze can ever run unattended: a freeze is High and the default ceiling is
    // Medium. Printing it beside the level is what stops an operator concluding the
    // agent is broken because nothing ever runs.
    let mut report = String::from("\n");
    let governance = match autonomy {
        AutonomyLevel::Observe => "observe only; disruptive actions are denied".to_string(),
        AutonomyLevel::Alert => "alert only; disruptive actions are denied".to_string(),
        AutonomyLevel::Approve => "propose; disruptive actions need a human".to_string(),
        AutonomyLevel::Auto => format!("automatic up to {max_auto:?}"),
    };
    report.push_str(&format!("  gate 1 governance  {governance}\n"));
    if autonomy == AutonomyLevel::Auto && max_auto != model::Severity::Critical {
        report.push_str(
            "                     a freeze is high, so it is still proposed rather than run\n",
        );
    }
    report.push_str(&format!(
        "  gate 2 operator    {}\n",
        if respond {
            "acting permitted (--respond)"
        } else {
            "propose only (--respond to act)"
        }
    ));
    report.push_str(&format!(
        "  gate 3 guards      {}\n",
        match actuator {
            Some(a) if a.is_dry_run() => "dry run; resolved and refused, nothing touched",
            Some(_) => "armed",
            None => "not consulted",
        }
    ));
    report
}

// ---------------------------------------------------------------------------
// etw
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn run_etw(args: &Args, host: HostId) -> Result<(), String> {
    use etw::{EtwSession, SessionConfig};

    let session_config = SessionConfig {
        name: format!("chaos-{}", std::process::id()),
        providers: etw::provider::default_providers(),
        ..Default::default()
    };

    // The failure an operator actually hits, so it gets a real explanation
    // rather than a bare OS code. `EtwSession::start` is the only place we still
    // hold the typed error; by the time it is a `String` the code is gone.
    let (mut session, reports) = match EtwSession::start(session_config) {
        Ok(started) => started,
        Err(e) => {
            eprintln!("  {e}");
            if let Some(remedy) = etw::remedy(&e) {
                eprintln!("  {remedy}");
            }
            return Err("could not start a trace session".into());
        }
    };

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

    let mut config = Config::new(host.clone());
    config.min_row_severity = args.min_row_severity;
    config.autonomy = args.autonomy;
    // From the default rather than spelled out, so that whatever else the default
    // policy says stays true and this flag names exactly one thing.
    config.policy = pipeline::GovernancePolicy {
        max_auto: pipeline::policy_severity(args.max_auto),
        ..config.policy
    };

    let actuator: Option<Box<dyn Actuator>> = if args.respond {
        Some(Box::new(respond::WindowsActuator::new(args.dry_run)))
    } else {
        None
    };
    print_gates(args, actuator.as_deref());

    // Without this, a stop ends the process in the kernel and no Rust code runs
    // afterwards, which would leave every process this run suspended held by an
    // agent that no longer exists. Installed only when this run can act: with no
    // actuator there is nothing to release, and letting the default handler have
    // the signal is the behaviour an operator already expects.
    if args.respond && !respond::install_stop_handler() {
        eprintln!("  warning: could not catch a stop signal; a hard stop would leave");
        eprintln!("  anything this run suspends suspended. Consider --dry-run first.");
    }

    let mut shipper = Shipper::new(
        config,
        open_sink(args)?,
        actuator,
        args.interval(),
        args.verbose,
    );
    let mut translator = etw::Translator::new(host);

    let deadline = args
        .duration
        .map(|seconds| Instant::now() + Duration::from_secs(seconds));
    match args.duration {
        Some(seconds) => println!("\ncollecting for {seconds}s ..."),
        None => println!("\ncollecting until stopped ..."),
    }

    let started = Instant::now();
    let mut raw_batch: Vec<etw::EtwRaw> = Vec::new();
    let mut latencies: Vec<u64> = Vec::with_capacity(LATENCY_SAMPLES);
    let mut events = 0u64;

    loop {
        if let Some(deadline) = deadline {
            if Instant::now() >= deadline {
                break;
            }
        }
        // Polled rather than awaited: the stop arrives on a thread that may not
        // print, allocate or wait, so the loop is what notices it and unwinds.
        if respond::stop_requested() {
            println!("\nstop requested");
            break;
        }

        session.drain(&mut raw_batch, 4096, Duration::from_millis(250));
        for raw in raw_batch.drain(..) {
            if let Some(event) = translator.translate(&raw) {
                let scored_ns = shipper.feed(event);
                events += 1;
                if latencies.len() < LATENCY_SAMPLES {
                    latencies.push(scored_ns);
                }
            }
        }

        shipper.tick();
        shipper.report_live(events, started);
    }

    let stats = session.stats();
    session.shutdown().map_err(|e| e.to_string())?;
    let (events_lost, buffers_lost) = session.kernel_lost();

    // Sensor first, then what the pipeline made of it, then what left the host.
    // A gap anywhere in that chain should read in the order it happened.
    println!("\n=== sensor report ======================================");
    println!("  events received        {:>12}", stats.received);
    println!("  delivered              {:>12}", stats.delivered);
    println!("  filtered by level      {:>12}", stats.filtered);
    println!("  dropped (channel full) {:>12}", stats.dropped);
    println!(
        "  dropped (kernel)       {:>12}",
        u64::from(events_lost) + u64::from(buffers_lost)
    );
    println!("  coverage               {:>12.6}", stats.coverage());
    println!("  scored                 {:>12}", translator.mapped());
    println!("  undecodable            {:>12}", translator.undecodable());

    if translator.undecodable() > 0 {
        println!("\n  Events arrived in a shape this sensor scores but could not be decoded.");
        println!("  That means a property name in etw::translate is wrong for this build of");
        println!("  Windows, not that the machine was quiet:");
        for failure in translator.failures() {
            println!("    {failure}");
        }
    }

    finish(shipper, &latencies, started.elapsed(), events, "live etw")
}

#[cfg(not(windows))]
fn run_etw(_args: &Args, _host: HostId) -> Result<(), String> {
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
    let rate = events as f64 / wall.as_secs_f64().max(1e-9);
    let observation = engine.observation(rate, rate);

    println!("\n=== run report =======================================");
    println!("  mode                   {mode:>12}");
    println!("  events                 {:>12}", metrics.events);
    println!("  process starts         {:>12}", metrics.process_starts);
    println!("  rule findings          {:>12}", metrics.findings);
    println!("  alerts                 {:>12}", alerts);
    println!("  abstained              {:>12}", metrics.abstained);
    println!("  suppressed (coalesced) {:>12}", metrics.suppressed);
    println!("  below severity floor   {:>12}", metrics.below_floor);
    println!(
        "  withheld by policy     {:>12}",
        metrics.withheld_by_policy
    );

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
    println!("    event rate             {rate:>12.0} /s");
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
    }
    println!("======================================================");
}

fn percentile(sorted: &[u64], q: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    sorted[(((sorted.len() - 1) as f64) * q).round() as usize]
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
    /// `None` runs until the process is stopped, which is how the agent is
    /// deployed. `Some(seconds)` bounds the run and prints a full report, which
    /// is how it is diagnosed.
    duration: Option<u64>,
    verbose: bool,
    interval_secs: u64,
    enroll_url: Option<String>,
    ship_url: Option<String>,
    enrollment_token: String,
    token_file: PathBuf,
    /// The lowest severity that earns its own row. Everything below it is
    /// counted and held.
    min_row_severity: model::Severity,
    /// Who may act without a human (A12). `Approve` by default, which means
    /// disruptive actions are proposed and never taken.
    autonomy: AutonomyLevel,
    /// Whether this run may act on what governance clears. Off by default.
    respond: bool,
    /// Resolve and guard, then stop short of the call. The first run on any
    /// machine should be this one.
    dry_run: bool,
    /// The highest severity the `Auto` level may act on unattended.
    ///
    /// This is the ceiling that decides whether a freeze can run without a human
    /// at all: a freeze is High, and the default ceiling is Medium, so opening
    /// `--autonomy auto` on its own still proposes and waits. Naming this
    /// separately means the operator who wants an unattended freeze has to say
    /// so, rather than getting it by turning up the autonomy dial.
    max_auto: model::Severity,
}

impl Args {
    /// How often the agent pushes, and how often it reports.
    ///
    /// This is also the bound on what a hard stop can cost: everything already
    /// pushed is on the server, and the restatement that goes out on the next
    /// tick is what makes the counts whole again.
    fn interval(&self) -> Duration {
        Duration::from_secs(self.interval_secs.max(1))
    }
}

/// Parse the `--min-severity` value.
fn parse_severity(value: &str) -> Option<model::Severity> {
    match value.to_ascii_lowercase().as_str() {
        "info" => Some(model::Severity::Info),
        "low" => Some(model::Severity::Low),
        "medium" => Some(model::Severity::Medium),
        "high" => Some(model::Severity::High),
        "critical" => Some(model::Severity::Critical),
        _ => None,
    }
}

/// Parse the `--autonomy` value, which names the A12 ladder from least to most
/// authority.
fn parse_autonomy(value: &str) -> Option<AutonomyLevel> {
    match value.to_ascii_lowercase().as_str() {
        "observe" => Some(AutonomyLevel::Observe),
        "alert" => Some(AutonomyLevel::Alert),
        "approve" => Some(AutonomyLevel::Approve),
        "auto" => Some(AutonomyLevel::Auto),
        _ => None,
    }
}

impl Args {
    fn parse() -> Self {
        let mut args = Args {
            duration: None,
            verbose: true,
            interval_secs: 2,
            enroll_url: None,
            ship_url: None,
            enrollment_token: std::env::var("CHAOS_ENROLLMENT_TOKEN").unwrap_or_default(),
            token_file: credential::default_path(),
            min_row_severity: model::Severity::Medium,
            autonomy: AutonomyLevel::Approve,
            respond: false,
            dry_run: false,
            max_auto: model::Severity::Medium,
        };

        // Peekable, because `--etw` takes an optional value: the next token being
        // a flag is how "no duration" reads.
        let mut it = std::env::args().skip(1).peekable();
        while let Some(flag) = it.next() {
            match flag.as_str() {
                "--quiet" => args.verbose = false,
                "--interval" => {
                    if let Some(seconds) = it.next().and_then(|v| v.parse().ok()) {
                        args.interval_secs = seconds;
                    }
                }
                "--etw" => {
                    // The value is optional. A bare `--etw` means "listen", which
                    // is the same as not passing the flag at all, so the agent has
                    // one way to say "run" rather than two.
                    let seconds = match it.peek() {
                        Some(value) if !value.starts_with('-') => {
                            let value = it.next().unwrap_or_default();
                            match value.parse() {
                                Ok(seconds) => Some(seconds),
                                Err(_) => {
                                    eprintln!(
                                        "--etw SECONDS takes a number of seconds; got `{value}`"
                                    );
                                    std::process::exit(2);
                                }
                            }
                        }
                        _ => None,
                    };
                    args.duration = seconds;
                }
                "--enroll" => args.enroll_url = Some(it.next().unwrap_or_default()),
                "--ship" => args.ship_url = Some(it.next().unwrap_or_default()),
                "--enrollment-token" => {
                    args.enrollment_token = it.next().unwrap_or_default();
                }
                "--token-file" => {
                    if let Some(path) = it.next() {
                        args.token_file = PathBuf::from(path);
                    }
                }
                "--min-severity" => match it.next().as_deref().and_then(parse_severity) {
                    Some(severity) => args.min_row_severity = severity,
                    None => {
                        eprintln!("--min-severity needs one of: info, low, medium, high, critical");
                        std::process::exit(2);
                    }
                },
                "--autonomy" => match it.next().as_deref().and_then(parse_autonomy) {
                    Some(level) => args.autonomy = level,
                    None => {
                        eprintln!("--autonomy needs one of: observe, alert, approve, auto");
                        std::process::exit(2);
                    }
                },
                "--respond" => args.respond = true,
                "--dry-run" => args.dry_run = true,
                "--max-auto" => match it.next().as_deref().and_then(parse_severity) {
                    Some(severity) => args.max_auto = severity,
                    None => {
                        eprintln!("--max-auto needs one of: info, low, medium, high, critical");
                        std::process::exit(2);
                    }
                },
                "--help" | "-h" => {
                    // `concat!` rather than `\`-continued literals: a continuation
                    // strips the next line's leading whitespace, which silently
                    // un-aligns every wrapped description.
                    println!(
                        "{}",
                        concat!(
                            "chaos agent\n",
                            "\n",
                            "usage: client [--etw [SECONDS]] [--interval SECS] [--min-severity SEV]\n",
                            "              [--ship URL] [--enroll URL] [--enrollment-token T]\n",
                            "              [--token-file P] [--respond [--dry-run]]\n",
                            "              [--autonomy LEVEL] [--max-auto SEV] [--quiet]\n",
                            "\n",
                            "the agent reads this machine's ETW stream, so it needs an elevated\n",
                            "token. With no SECONDS it runs until stopped.\n",
                            "\n",
                            "--etw [SECONDS]       how long to collect for; without it, until\n",
                            "                      stopped\n",
                            "--interval SECS       how often to push and report, default 2\n",
                            "--min-severity SEV    lowest severity that earns a row, default\n",
                            "                      medium; below it firings are counted and held\n",
                            "                      until the evidence justifies them\n",
                            "--ship URL            ship telemetry and alerts to the server\n",
                            "--enroll URL          enroll and store this host's credential\n",
                            "--enrollment-token T  bootstrap secret (env: CHAOS_ENROLLMENT_TOKEN)\n",
                            "--token-file PATH     credential location\n",
                            "--quiet               print the report only, not each alert\n",
                            "\n",
                            "response, off unless asked for twice over:\n",
                            "  --respond           allow this run to act on what governance\n",
                            "                      clears. Governance must clear it as well, and\n",
                            "                      --autonomy approve (the default) clears nothing\n",
                            "                      for a disruptive action.\n",
                            "  --dry-run           with --respond: resolve the target and run\n",
                            "                      every guard, then stop short of the call. The\n",
                            "                      first run on any machine should be this one.\n",
                            "  --autonomy LEVEL    observe | alert | approve | auto, default\n",
                            "                      approve. `auto` lets a cleared action run with\n",
                            "                      no human, within the policy's severity ceiling.\n",
                            "  --max-auto SEV      highest severity `auto` may act on unattended,\n",
                            "                      default medium. A freeze is high, so raising the\n",
                            "                      autonomy level alone still proposes and waits.\n",
                            "\n",
                            "a suspend is released when the agent stops, including on Ctrl-C, so\n",
                            "a stopped agent never leaves a process frozen.\n"
                        )
                    );
                    std::process::exit(0);
                }
                // Fatal, not a warning. A mistyped `--min-severity` would
                // otherwise run with the default threshold and quietly detect a
                // different set of things than the operator asked for, which is
                // the kind of difference nobody notices until an incident.
                other => {
                    eprintln!("unknown argument `{other}`; try --help");
                    std::process::exit(2);
                }
            }
        }
        args
    }
}

/// The gates, without a machine to state them against.
///
/// `Shipper` is where the three gates meet, so this is the only place a mistake
/// would show up as an agent acting on something it should not have. A recording
/// actuator makes that observable: the test asserts on the calls, not on the
/// wording of a log line.
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// An actuator that writes down what it was asked to do.
    struct Recording {
        calls: Arc<Mutex<Vec<Response>>>,
        dry: bool,
        refusal: Option<&'static str>,
    }

    impl Recording {
        fn new(dry: bool) -> (Self, Arc<Mutex<Vec<Response>>>) {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let recorder = Self {
                calls: Arc::clone(&calls),
                dry,
                refusal: None,
            };
            (recorder, calls)
        }
    }

    impl Actuator for Recording {
        fn apply(&mut self, response: Response) -> Result<(), ActionError> {
            self.calls.lock().expect("not poisoned").push(response);
            match self.refusal {
                Some(reason) => Err(ActionError::Refused(reason.to_string())),
                None => Ok(()),
            }
        }

        fn is_dry_run(&self) -> bool {
            self.dry
        }
    }

    fn shipper(actuator: Option<Box<dyn Actuator>>) -> Shipper {
        Shipper::new(
            Config::new(HostId::new("host-a").expect("valid host")),
            None,
            actuator,
            Duration::from_secs(1),
            false,
        )
    }

    #[test]
    fn a_cleared_proposal_does_nothing_without_an_actuator() {
        // The default deployment. Governance clearing something is not the same
        // as this agent being allowed to do it, and the agent must not read the
        // first as the second.
        let mut s = shipper(None);
        let (outcome, detail) = s.carry_out(Response::Suspend { pid: 7 }, true);
        assert_eq!(outcome, "proposed");
        assert!(detail.is_none());
        assert_eq!(s.actioned, 0);
        assert_eq!(s.proposed, 1);
    }

    #[test]
    fn a_proposal_governance_did_not_clear_is_never_applied() {
        // The case that matters most: an armed agent, a freeze the policy
        // withheld. Nothing may reach the machine.
        let (recorder, calls) = Recording::new(false);
        let mut s = shipper(Some(Box::new(recorder)));
        let (outcome, _) = s.carry_out(Response::Suspend { pid: 7 }, false);
        assert_eq!(outcome, "proposed");
        assert!(calls.lock().expect("not poisoned").is_empty());
    }

    #[test]
    fn a_cleared_proposal_is_applied_and_then_released() {
        let (recorder, calls) = Recording::new(false);
        let mut s = shipper(Some(Box::new(recorder)));
        let (outcome, _) = s.carry_out(Response::Suspend { pid: 7 }, true);
        assert_eq!(outcome, "applied");
        assert_eq!(
            *calls.lock().expect("not poisoned"),
            vec![Response::Suspend { pid: 7 }]
        );

        // Stopping the agent has to undo it, or "reversible" is a claim the
        // product cannot keep.
        s.revert();
        assert_eq!(
            *calls.lock().expect("not poisoned"),
            vec![Response::Suspend { pid: 7 }, Response::Resume { pid: 7 }]
        );

        // And reverting twice must not release a process that has been reused.
        s.revert();
        assert_eq!(calls.lock().expect("not poisoned").len(), 2);
    }

    #[test]
    fn an_irreversible_response_is_not_remembered_for_undo() {
        // There is nothing to go back to, so recording one would invite a revert
        // that does something else entirely to whatever holds that pid next.
        let (recorder, calls) = Recording::new(false);
        let mut s = shipper(Some(Box::new(recorder)));
        let (outcome, _) = s.carry_out(Response::Terminate { pid: 9 }, true);
        assert_eq!(outcome, "applied");
        s.revert();
        assert_eq!(calls.lock().expect("not poisoned").len(), 1);
    }

    #[test]
    fn a_dry_run_does_not_claim_to_have_acted() {
        // The word is the only thing an operator reads, so it has to be true.
        let (recorder, _) = Recording::new(true);
        let mut s = shipper(Some(Box::new(recorder)));
        assert_eq!(s.carry_out(Response::Suspend { pid: 7 }, true).0, "dry run");
    }

    #[test]
    fn a_refusal_is_reported_as_a_refusal_and_not_as_a_failure() {
        // A protected process is the guard working. An operator reading "failed"
        // would go looking for a bug that is not there.
        let (mut recorder, calls) = Recording::new(false);
        recorder.refusal = Some("lsass.exe is protected");
        let mut s = shipper(Some(Box::new(recorder)));
        let (outcome, detail) = s.carry_out(Response::Suspend { pid: 700 }, true);
        assert_eq!(outcome, "refused");
        assert_eq!(detail.as_deref(), Some("lsass.exe is protected"));
        assert_eq!(s.refused, 1);
        assert_eq!(s.failed, 0);
        // A refused action did not happen, so there is nothing to undo.
        s.revert();
        assert_eq!(calls.lock().expect("not poisoned").len(), 1);
    }

    #[test]
    fn what_is_queued_for_the_server_does_not_depend_on_acting() {
        // With no sink there is nothing to push, and this is here to keep it that
        // way: response must not become a reason to ship, or a host that cannot
        // reach the server would stop responding.
        let mut s = shipper(None);
        s.push();
        assert_eq!(s.ship_errors, 0);
    }

    #[cfg(windows)]
    #[test]
    fn the_default_gates_say_nothing_will_be_touched() {
        let report = gate_report(AutonomyLevel::Approve, model::Severity::Medium, false, None);
        assert!(report.contains("propose; disruptive actions need a human"));
        assert!(report.contains("propose only (--respond to act)"));
        assert!(report.contains("not consulted"));
        assert!(!report.contains("armed"), "nothing may read as armed here");
    }

    #[cfg(windows)]
    #[test]
    fn raising_the_autonomy_alone_does_not_arm_a_freeze() {
        // The trap this line exists for: `auto` sounds like permission to freeze,
        // and the ceiling is what actually decides. Saying so is cheaper than an
        // operator concluding the detector sees nothing.
        let (recorder, _) = Recording::new(false);
        let report = gate_report(
            AutonomyLevel::Auto,
            model::Severity::Medium,
            true,
            Some(&recorder),
        );
        assert!(report.contains("automatic up to Medium"));
        assert!(report.contains("still proposed rather than run"));
    }

    #[cfg(windows)]
    #[test]
    fn the_armed_report_names_all_three_gates_as_open() {
        let (recorder, _) = Recording::new(false);
        let report = gate_report(
            AutonomyLevel::Auto,
            model::Severity::Critical,
            true,
            Some(&recorder),
        );
        assert!(report.contains("automatic up to Critical"));
        assert!(report.contains("acting permitted (--respond)"));
        assert!(report.contains("armed"));
        assert!(
            !report.contains("still proposed"),
            "a freeze is inside this ceiling"
        );
    }
}
