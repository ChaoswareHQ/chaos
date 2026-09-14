use crate::SinkError;
use async_trait::async_trait;
use model::TelemetryEvent;

#[async_trait]
pub trait EventSink: Send + Sync {
    async fn write(&self, events: &[TelemetryEvent]) -> Result<(), SinkError>;

    async fn flush(&self) -> Result<(), SinkError>;

    fn buffered_count(&self) -> u64 {
        0
    }
}
