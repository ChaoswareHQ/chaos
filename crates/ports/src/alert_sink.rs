use crate::AlertError;
use model::Alert;

pub trait AlertSink: Send + Sync {
    fn emit(&self, alert: &Alert) -> Result<(), AlertError>;

    fn emitted_count(&self) -> u64 {
        0
    }
}
