use crate::HostError;
use model::{Host, HostId};

pub trait HostRegistry: Send + Sync {
    fn upsert(&self, host: &Host) -> Result<(), HostError>;
    fn get(&self, id: &HostId) -> Result<Option<Host>, HostError>;
    fn list(&self) -> Result<Vec<Host>, HostError>;
    fn mark_inactive(&self, id: &HostId) -> Result<(), HostError>;
}
