use crate::AlertError;
use model::Alert;

/// A destination for alerts.
///
/// `&mut self` for the same reason as [`crate::EventSink`]: a sink that batches
/// has to be able to accumulate, and pretending otherwise pushes every
/// implementation toward interior mutability it does not want.
pub trait AlertSink: Send {
    fn emit(&mut self, alert: &Alert) -> Result<(), AlertError>;

    fn emitted_count(&self) -> u64 {
        0
    }
}
