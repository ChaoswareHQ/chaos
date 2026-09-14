use crate::AlertError;
use async_trait::async_trait;
use model::Alert;

#[async_trait]
pub trait AlertSink: Send + Sync {
    async fn emit(&self, alert: &Alert) -> Result<(), AlertError>;
    fn emitted_count(&self) -> u64 {
        0
    }
}
