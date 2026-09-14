use crate::SourceError;
use async_trait::async_trait;
use model::RawEvent;

#[async_trait]
pub trait EventSource: Send + Sync {
    async fn next(&mut self) -> Result<Option<RawEvent>, SourceError>;
    fn name(&self) -> &str;
    fn dropped_count(&self) -> u64;
    async fn stop(&mut self) -> Result<(), SourceError>;
}
