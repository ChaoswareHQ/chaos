//! The observation runtime.
//!
//! The sensor's run loop, extracted from `apps/client/src/main.rs` so it can
//! be tested with mock sources and reused by anything that observes a host.
//!
//! # What it drives
//!
//! Four things, in order, every iteration:
//!
//! 1. An [`Observe`] — the platform source, already translated to the wire
//!    format. On Windows this wraps an `etw::EtwSession` and an
//!    `etw::Translator`; the trait does not know that, which is the point.
//! 2. A [`Score`] — the detection engine. Takes a wire event, returns an
//!    alert when something fires. On Windows this wraps `pipeline::Engine`.
//! 3. An [`EmitAlert`] — where alerts go. Usually the same sink that carries
//!    telemetry, but a trait because tests want to capture them.
//! 4. A [`Sink`] — where wire events go. Optional: a run with no sink is a
//!    diagnostic, not a deployment.
//!
//! # What it emits
//!
//! * telemetry events to the sink, in batches;
//! * alerts to the emitter, one at a time as they fire;
//! * a one-line heartbeat to stdout on the report interval, unless quiet.
//!
//! # The four ways a run ends
//!
//! [`RunStop::Deadline`] when `config.deadline` elapses;
//! [`RunStop::Requested`] when the handle's `stop()` is called;
//! [`RunStop::Idle`] when no event arrives for `config.idle_timeout`;
//! [`RunStop::SourceFailed`] when the source returns an error.
//!
//! A source returning zero events is *not* an ending. A quiet host is not a
//! dead one, and a sensor that treats silence as failure is a sensor that
//! restarts on every quiet afternoon.
//!
//! # What it does not do
//!
//! It does not parse arguments, load credentials, enrol, handle actuator
//! responses, print a report, or decide which providers to enable. Those are
//! the app's job: it knows which source to build, which rules to load, and
//! what the user asked for on the command line.

mod config;
mod metrics;
mod runtime;

pub use config::ObserverConfig;
pub use metrics::{Counters, Heartbeat, MetricsSnapshot};
pub use runtime::{Observer, ObserverHandle, RunOutcome, RunStop};

use model::{Alert, TelemetryEvent};
use ports::SourceError;
use std::time::Duration;

/// A platform source that has already translated to the wire format.
///
/// Higher-level than [`ports::EventSource`], which yields raw events: a
/// platform adapter that can translate its own raw format into
/// [`TelemetryEvent`] implements this, and the runtime never sees a raw byte.
///
/// The Windows implementation wraps `etw::EtwSession` and `etw::Translator`
/// and lives in the `etw` crate as `etw::EtwObservation`; the shape is:
///
/// ```ignore
/// struct EtwObservation { session: etw::EtwSession, translator: etw::Translator }
///
/// impl observer::Observe for EtwObservation {
///     fn next_batch(&mut self, out: &mut Vec<TelemetryEvent>, max: usize, timeout: Duration)
///         -> Result<usize, SourceError>
///     {
///         let mut raw = Vec::new();
///         self.session.drain(&mut raw, max, timeout);
///         for r in raw {
///             if let Some(e) = self.translator.translate(&r) { out.push(e); }
///         }
///         Ok(out.len())
///     }
///     fn unmapped(&self) -> u64 { self.translator.counts().unrecognised() }
///     fn undecodable(&self) -> u64 { self.translator.undecodable() }
///     fn name(&self) -> &str { self.session.name() }
///     fn shutdown(&mut self) -> Result<(), SourceError> {
///         self.session.shutdown().map_err(|e| SourceError::Unavailable(e.to_string()))
///     }
/// }
/// ```
pub trait Observe: Send {
    /// Fill `out` with up to `max` wire events, waiting no longer than
    /// `timeout` for the first. Return how many were appended.
    fn next_batch(
        &mut self,
        out: &mut Vec<TelemetryEvent>,
        max: usize,
        timeout: Duration,
    ) -> Result<usize, SourceError>;

    /// Events the source saw that were not a shape the translator scores.
    /// The number that answers "what are we not looking at".
    fn unmapped(&self) -> u64 {
        0
    }

    /// Events that *were* a scored shape but could not be decoded.
    /// A non-zero value here is a bug in the field table, not a quiet host.
    fn undecodable(&self) -> u64 {
        0
    }

    /// A short name, used in heartbeats and the run report.
    fn name(&self) -> &str {
        "source"
    }

    /// Stop and release. Called once at the end of a run.
    fn shutdown(&mut self) -> Result<(), SourceError> {
        Ok(())
    }
}

/// Where a wire event is scored.
pub trait Score: Send {
    /// Score one event. `Some` when a rule fired.
    fn score(&mut self, event: &TelemetryEvent) -> Option<Alert>;

    /// Called after every batch, before the flush. The hook an app uses to
    /// process actuator responses: `engine.take_responses()` lives behind
    /// this, not behind `score`, because a response that changes the machine
    /// is not a side effect of scoring one event.
    fn tick(&mut self) {}

    /// Called on the flush interval. Returns alerts that need restating — a
    /// coalesced alert carries the same id as the original, so the server
    /// folds it into the row it already holds instead of adding one.
    fn restate(&mut self) -> Vec<Alert> {
        Vec::new()
    }
}

/// Where alerts go.
pub trait EmitAlert: Send {
    fn emit(&mut self, alert: Alert);
}

impl<F: FnMut(Alert) + Send> EmitAlert for F {
    fn emit(&mut self, alert: Alert) {
        self(alert);
    }
}

/// Where wire events go.
pub use ports::EventSink as Sink;
