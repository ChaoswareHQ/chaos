use crate::SourceError;
use model::RawEvent;
use std::time::Duration;

/// A source of raw telemetry.
///
/// Deliberately synchronous and batched.
///
/// Sensors like ETW and eBPF are driven by a kernel callback that already hands
/// batches to a bounded channel; an `async fn next()` per event would box a
/// future and force a round trip for every single event, at the exact point in
/// the system where throughput matters most. `next_batch` moves a whole batch
/// per call and lets the caller own its own deadline.
pub trait EventSource: Send {
    /// Append up to `max` events to `out`, blocking no longer than `timeout`.
    ///
    /// Returns the number appended. `Ok(0)` means the timeout elapsed with
    /// nothing available — that is normal, not an error.
    fn next_batch(
        &mut self,
        out: &mut Vec<RawEvent>,
        max: usize,
        timeout: Duration,
    ) -> Result<usize, SourceError>;

    /// Events the source itself threw away: channel overflow, or buffers lost
    /// in the kernel.
    ///
    /// This is not a diagnostic. It is the empirical input to the observation
    /// gap (A3): a pipeline that assumes zero drops cannot claim to know what
    /// fraction of the state space it actually saw.
    fn dropped_count(&self) -> u64;

    fn name(&self) -> &str;

    fn stop(&mut self) -> Result<(), SourceError>;
}
