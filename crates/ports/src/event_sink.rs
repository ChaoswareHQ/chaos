use crate::SinkError;
use model::TelemetryEvent;

/// A destination for telemetry.
///
/// Takes `&mut self` and owned events, because the sinks that matter buffer.
/// Shipping to a server means accumulating a batch and sending it once, not
/// making one request per event, and a `&self` signature cannot hold a batch
/// without interior mutability for no benefit.
///
/// `Send` and not `Sync`, for the same reason as [`crate::EventSource`]: a sink
/// is driven by the thread that owns it, and demanding `Sync` would force every
/// implementation to be shared-safe for no caller's benefit.
pub trait EventSink: Send {
    /// Queue events for delivery.
    ///
    /// Returning `Ok` means the events were accepted, *not* that they arrived:
    /// an implementation is free to buffer. [`EventSink::flush`] is what
    /// promises delivery.
    fn write(&mut self, events: Vec<TelemetryEvent>) -> Result<(), SinkError>;

    /// Deliver everything queued.
    fn flush(&mut self) -> Result<(), SinkError>;

    /// How many events are held but not yet delivered.
    fn buffered_count(&self) -> u64 {
        0
    }
}
