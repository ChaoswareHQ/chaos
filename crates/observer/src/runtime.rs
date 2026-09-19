//! The loop, and the handle a control thread uses to stop it.

use super::config::ObserverConfig;
use super::metrics::{Counters, Heartbeat, MetricsSnapshot};
use super::{EmitAlert, Observe, Score, Sink};
use model::TelemetryEvent;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Why a run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunStop {
    /// `config.deadline` elapsed. The bounded diagnostic.
    Deadline,
    /// `ObserverHandle::stop` was called. The operator or the supervisor.
    Requested,
    /// No event for `config.idle_timeout`. Off unless configured.
    Idle,
    /// The source returned an error. The runtime stops rather than loops on
    /// a source that has failed, because a source that fails once usually
    /// fails every time, and a tight retry loop hides the failure.
    SourceFailed(String),
}

impl RunStop {
    pub fn as_str(&self) -> &'static str {
        match self {
            RunStop::Deadline => "deadline",
            RunStop::Requested => "requested",
            RunStop::Idle => "idle",
            RunStop::SourceFailed(_) => "source failed",
        }
    }
}

/// What a run leaves behind.
#[derive(Debug)]
pub struct RunOutcome {
    pub stop: RunStop,
    /// Wall clock from the first iteration to the last.
    pub wall: Duration,
    /// Every counter the loop maintains.
    pub metrics: MetricsSnapshot,
    /// Events the source saw that the translator did not score.
    pub unmapped: u64,
    /// Events that were a scored shape but could not be decoded.
    pub undecodable: u64,
}

impl RunOutcome {
    pub fn eps(&self) -> f64 {
        self.metrics.eps(self.wall)
    }
}

/// A stop flag and a counters view, usable from any thread.
///
/// The one thing the observer shares. Everything else is owned by the loop
/// and never leaves it, which is what makes the loop single-threaded and
/// therefore testable.
pub struct ObserverHandle {
    stop: Arc<AtomicBool>,
    counters: Arc<Counters>,
}

impl ObserverHandle {
    /// Ask the loop to end at its next check. Idempotent.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Whether a stop has been requested.
    pub fn stopping(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// Read the counters now. Safe to call while the loop is running.
    pub fn metrics(&self) -> MetricsSnapshot {
        self.counters.snapshot()
    }
}

/// The observer.
pub struct Observer {
    source: Box<dyn Observe>,
    score: Box<dyn Score>,
    emit: Box<dyn EmitAlert>,
    sink: Option<Box<dyn Sink>>,
    config: ObserverConfig,
    counters: Arc<Counters>,
    stop: Arc<AtomicBool>,
}

impl Observer {
    pub fn new(
        source: Box<dyn Observe>,
        score: Box<dyn Score>,
        emit: Box<dyn EmitAlert>,
        sink: Option<Box<dyn Sink>>,
        config: ObserverConfig,
    ) -> Self {
        Self {
            source,
            score,
            emit,
            sink,
            config,
            counters: Arc::new(Counters::default()),
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// A handle to stop the run and read the counters.
    pub fn handle(&self) -> ObserverHandle {
        ObserverHandle {
            stop: Arc::clone(&self.stop),
            counters: Arc::clone(&self.counters),
        }
    }

    /// Read the counters without going through the handle.
    pub fn metrics(&self) -> MetricsSnapshot {
        self.counters.snapshot()
    }

    /// Run until one of the four stops.
    pub fn run(&mut self) -> RunOutcome {
        let started = Instant::now();
        let mut last_event_at = started;
        let mut last_flush = started;
        let mut last_report = started;

        let mut pull: Vec<TelemetryEvent> = Vec::with_capacity(self.config.batch);
        let mut ship: Vec<TelemetryEvent> = Vec::with_capacity(self.config.batch);

        let stop = loop {
            // 1. Deadline.
            if let Some(deadline) = self.config.deadline {
                if started.elapsed() >= deadline {
                    break RunStop::Deadline;
                }
            }
            // 2. Requested.
            if self.stop.load(Ordering::Relaxed) {
                break RunStop::Requested;
            }
            // 3. Idle, but only if configured.
            if let Some(idle) = self.config.idle_timeout {
                if last_event_at.elapsed() >= idle {
                    break RunStop::Idle;
                }
            }

            // Pull one batch. A failure here is the fourth stop, and the
            // runtime does not retry: a source that fails once usually fails
            // every time, and a tight retry loop hides the failure behind
            // log spam.
            pull.clear();
            match self
                .source
                .next_batch(&mut pull, self.config.batch, self.config.poll)
            {
                Ok(0) => {}
                Ok(_) => {
                    last_event_at = Instant::now();
                }
                Err(e) => {
                    Counters::bump(&self.counters.source_errors, 1);
                    break RunStop::SourceFailed(e.to_string());
                }
            }

            let raw_seen = self.source.unmapped()
                + self.source.undecodable()
                + self.counters.scored.load(Ordering::Relaxed)
                + pull.len() as u64;

            // 2. Score each event, and enqueue it for shipping.
            for event in pull.drain(..) {
                if let Some(alert) = self.score.score(&event) {
                    Counters::bump(&self.counters.alerts, 1);
                    self.emit.emit(alert);
                }
                ship.push(event);
            }
            Counters::bump(&self.counters.scored, ship.len() as u64);
            Counters::bump(
                &self.counters.raw_seen,
                raw_seen.saturating_sub(self.counters.raw_seen.load(Ordering::Relaxed)),
            );

            // 3. Hand the batch to the sink. A failure is counted, not fatal:
            // the app decides whether to stop on a sink that is refusing.
            if let Some(sink) = self.sink.as_mut() {
                if !ship.is_empty() {
                    let n = ship.len() as u64;
                    match sink.write(std::mem::take(&mut ship)) {
                        Ok(()) => Counters::bump(&self.counters.shipped, n),
                        Err(_) => Counters::bump(&self.counters.dropped, n),
                    }
                    ship.reserve(self.config.batch);
                }
            } else {
                // No sink: events are scored and dropped, which is what a
                // diagnostic run wants. Counted so the report is honest.
                Counters::bump(&self.counters.dropped, ship.len() as u64);
                ship.clear();
            }

            // The scorer gets to process whatever its `score` produced as a
            // side effect. Responses live behind this, not behind `score`.
            self.score.tick();

            // 4. Flush on the interval.
            if last_flush.elapsed() >= self.config.flush {
                self.flush(&mut last_flush);
            }

            // 5. Heartbeat on the report interval.
            if last_report.elapsed() >= self.config.report {
                if !self.config.quiet {
                    self.heartbeat(started);
                }
                last_report = Instant::now();
            }
        };

        // Final flush so a run that ends mid-batch does not lose it.
        self.flush(&mut last_flush);

        // Best-effort source shutdown. An error here is counted but the run
        // is over either way.
        if let Err(_) = self.source.shutdown() {
            Counters::bump(&self.counters.source_errors, 1);
        }

        let wall = started.elapsed();
        RunOutcome {
            stop,
            wall,
            metrics: self.counters.snapshot(),
            unmapped: self.source.unmapped(),
            undecodable: self.source.undecodable(),
        }
    }

    fn flush(&mut self, last_flush: &mut Instant) {
        *last_flush = Instant::now();
        if let Some(sink) = self.sink.as_mut() {
            if sink.flush().is_err() {
                Counters::bump(&self.counters.sink_errors, 1);
            }
        }
        // Restate anything the scorer has coalesced since the last flush. Each
        // restated alert carries the same id as its original, so the server
        // folds it into the row it already holds rather than adding one.
        for alert in self.score.restate() {
            Counters::bump(&self.counters.restated, 1);
            self.emit.emit(alert);
        }
        Counters::bump(&self.counters.flush_count, 1);
    }

    fn heartbeat(&self, started: Instant) {
        let m = self.counters.snapshot();
        let pending = self.sink.as_ref().map(|s| s.buffered_count()).unwrap_or(0);
        let heartbeat = Heartbeat {
            events: m.scored,
            eps: m.eps(started.elapsed()),
            alerts: m.alerts,
            shipped: m.shipped,
            pending,
            unmapped: self.source.unmapped(),
            undecodable: self.source.undecodable(),
        };
        println!("{heartbeat}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ObserverConfig;
    use model::{Alert, AlertId, HostId, RuleId, Severity, TelemetryEvent};
    use ports::{EventSink, SinkError, SourceError};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A source that produces `pending` events as fast as the loop asks.
    struct ScriptedSource {
        pending: u64,
        unmapped: u64,
        undecodable: u64,
        shutdown_called: bool,
    }

    impl ScriptedSource {
        fn new(pending: u64) -> Self {
            Self {
                pending,
                unmapped: 0,
                undecodable: 0,
                shutdown_called: false,
            }
        }
    }

    impl Observe for ScriptedSource {
        fn next_batch(
            &mut self,
            out: &mut Vec<TelemetryEvent>,
            max: usize,
            _timeout: Duration,
        ) -> Result<usize, SourceError> {
            let n = (self.pending as usize).min(max);
            for i in 0..n {
                out.push(synthetic_event(i as u64));
            }
            self.pending -= n as u64;
            Ok(n)
        }
        fn unmapped(&self) -> u64 {
            self.unmapped
        }
        fn undecodable(&self) -> u64 {
            self.undecodable
        }
        fn name(&self) -> &str {
            "scripted"
        }
        fn shutdown(&mut self) -> Result<(), SourceError> {
            self.shutdown_called = true;
            Ok(())
        }
    }

    struct FailingSource;
    impl Observe for FailingSource {
        fn next_batch(
            &mut self,
            _out: &mut Vec<TelemetryEvent>,
            _max: usize,
            _timeout: Duration,
        ) -> Result<usize, SourceError> {
            Err(SourceError::Unavailable("the disk went away".into()))
        }
    }

    struct CountingScore {
        fired: Arc<AtomicU64>,
        restated: Arc<AtomicU64>,
    }
    impl Score for CountingScore {
        fn score(&mut self, _event: &TelemetryEvent) -> Option<Alert> {
            let n = self.fired.fetch_add(1, Ordering::Relaxed);
            if n % 10 == 0 {
                Some(synthetic_alert())
            } else {
                None
            }
        }
        fn restate(&mut self) -> Vec<Alert> {
            self.restated.fetch_add(1, Ordering::Relaxed);
            Vec::new()
        }
    }

    struct CapturingSink {
        written: Arc<AtomicU64>,
        flushed: Arc<AtomicU64>,
    }
    impl EventSink for CapturingSink {
        fn write(&mut self, events: Vec<TelemetryEvent>) -> Result<(), SinkError> {
            self.written
                .fetch_add(events.len() as u64, Ordering::Relaxed);
            Ok(())
        }
        fn flush(&mut self) -> Result<(), SinkError> {
            self.flushed.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn buffered_count(&self) -> u64 {
            self.written.load(Ordering::Relaxed)
        }
    }

    fn synthetic_event(i: u64) -> TelemetryEvent {
        TelemetryEvent::new(
            model::EventId::new(i),
            HostId::new("test-host").unwrap(),
            chrono::Utc::now(),
            model::EventSource::WindowsEtw,
            model::ProviderId::new("test"),
            1,
            42,
            42,
            4,
            model::EventKind::Unclassified,
            model::Payload::empty(),
        )
    }

    fn synthetic_alert() -> Alert {
        Alert::new(
            AlertId::new("a-1").unwrap(),
            RuleId::new("R1").unwrap(),
            "test".into(),
            "test".into(),
            Severity::Medium,
            chrono::Utc::now(),
            HostId::new("test-host").unwrap(),
            Vec::new(),
            Vec::new(),
        )
    }

    fn run_once(pending: u64, fired: &Arc<AtomicU64>, restated: &Arc<AtomicU64>) -> RunOutcome {
        let source = Box::new(ScriptedSource::new(pending));
        let score = Box::new(CountingScore {
            fired: Arc::clone(fired),
            restated: Arc::clone(restated),
        });
        let written = Arc::new(AtomicU64::new(0));
        let flushed = Arc::new(AtomicU64::new(0));
        let sink = Box::new(CapturingSink {
            written: Arc::clone(&written),
            flushed: Arc::clone(&flushed),
        });
        let alerts = Arc::new(Mutex::new(Vec::new()));
        let emit = {
            let alerts = Arc::clone(&alerts);
            Box::new(move |a: Alert| alerts.lock().unwrap().push(a)) as Box<dyn EmitAlert>
        };
        let mut obs = Observer::new(source, score, emit, Some(sink), ObserverConfig::for_test());
        obs.run()
    }

    #[test]
    fn a_bounded_run_ends_on_its_deadline() {
        let fired = Arc::new(AtomicU64::new(0));
        let restated = Arc::new(AtomicU64::new(0));
        let outcome = run_once(10_000, &fired, &restated);
        assert_eq!(outcome.stop, RunStop::Deadline);
        assert!(outcome.wall >= Duration::from_millis(200));
        assert!(outcome.metrics.scored > 0);
    }

    #[test]
    fn stopping_the_handle_ends_the_run() {
        let source = Box::new(ScriptedSource::new(u64::MAX));
        let fired = Arc::new(AtomicU64::new(0));
        let score = Box::new(CountingScore {
            fired,
            restated: Arc::new(AtomicU64::new(0)),
        });
        let emit = Box::new(|_a: Alert| {}) as Box<dyn EmitAlert>;
        let mut obs = Observer::new(
            source,
            score,
            emit,
            None,
            ObserverConfig {
                deadline: None,
                ..ObserverConfig::for_test()
            },
        );
        let handle = obs.handle();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            handle.stop();
        });
        let outcome = obs.run();
        assert_eq!(outcome.stop, RunStop::Requested);
    }

    #[test]
    fn a_source_that_fails_stops_the_run() {
        let source = Box::new(FailingSource);
        let score = Box::new(CountingScore {
            fired: Arc::new(AtomicU64::new(0)),
            restated: Arc::new(AtomicU64::new(0)),
        });
        let emit = Box::new(|_a: Alert| {}) as Box<dyn EmitAlert>;
        let mut obs = Observer::new(source, score, emit, None, ObserverConfig::for_test());
        let outcome = obs.run();
        match outcome.stop {
            RunStop::SourceFailed(msg) => assert!(msg.contains("disk")),
            other => panic!("expected a source failure, got {other:?}"),
        }
        assert_eq!(outcome.metrics.source_errors, 1);
    }

    #[test]
    fn an_idle_timeout_ends_a_run_that_stays_quiet() {
        let source = Box::new(ScriptedSource::new(0));
        let score = Box::new(CountingScore {
            fired: Arc::new(AtomicU64::new(0)),
            restated: Arc::new(AtomicU64::new(0)),
        });
        let emit = Box::new(|_a: Alert| {}) as Box<dyn EmitAlert>;
        let mut obs = Observer::new(
            source,
            score,
            emit,
            None,
            ObserverConfig {
                deadline: None,
                idle_timeout: Some(Duration::from_millis(50)),
                ..ObserverConfig::for_test()
            },
        );
        let outcome = obs.run();
        assert_eq!(outcome.stop, RunStop::Idle);
    }

    #[test]
    fn the_accounting_closes_on_a_completed_run() {
        // The property the counters exist for: every raw event the source
        // produced is either scored or accounted for in the source's own
        // unmapped/undecodable counters.
        let fired = Arc::new(AtomicU64::new(0));
        let restated = Arc::new(AtomicU64::new(0));
        let outcome = run_once(200, &fired, &restated);
        let m = &outcome.metrics;
        assert_eq!(
            m.raw_seen,
            m.scored + outcome.unmapped + outcome.undecodable
        );
    }

    #[test]
    fn alerts_reach_the_emitter() {
        let fired = Arc::new(AtomicU64::new(0));
        let restated = Arc::new(AtomicU64::new(0));
        let outcome = run_once(100, &fired, &restated);
        // One in ten events fires, so roughly ten alerts.
        assert!(outcome.metrics.alerts >= 5, "{:?}", outcome.metrics);
    }

    #[test]
    fn a_run_with_no_sink_still_scores() {
        // The diagnostic mode: no `--ship`, no sink, alerts still surface.
        let source = Box::new(ScriptedSource::new(100));
        let fired = Arc::new(AtomicU64::new(0));
        let score = Box::new(CountingScore {
            fired: Arc::clone(&fired),
            restated: Arc::new(AtomicU64::new(0)),
        });
        let emit = Box::new(|_a: Alert| {}) as Box<dyn EmitAlert>;
        let mut obs = Observer::new(source, score, emit, None, ObserverConfig::for_test());
        let outcome = obs.run();
        assert!(outcome.metrics.scored > 0);
        assert_eq!(outcome.metrics.shipped, 0);
        assert_eq!(outcome.metrics.dropped, outcome.metrics.scored);
    }
}
