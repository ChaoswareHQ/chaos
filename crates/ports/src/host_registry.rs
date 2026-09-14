use crate::HostError;
use async_trait::async_trait;
use model::{Host, HostId};

#[async_trait]
pub trait HostRegistry: Send + Sync {
    async fn upsert(&self, host: &Host) -> Result<(), HostError>;
    async fn get(&self, id: &HostId) -> Result<Option<Host>, HostError>;
    async fn list(&self) -> Result<Vec<Host>, HostError>;
    async fn mark_inactive(&self, id: &HostId) -> Result<(), HostError>;
}
