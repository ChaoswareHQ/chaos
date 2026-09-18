use crate::SinkError;
use model::TelemetryEvent;

pub trait EventSink: Send + Sync {
    fn write(&self, events: &[TelemetryEvent]) -> Result<(), SinkError>;

    fn flush(&self) -> Result<(), SinkError>;

    fn buffered_count(&self) -> u64 {
        0
    }
}
