//! Response actuation: the only component in this product that changes the host.
//!
//! Everything else observes. This acts, which is why it is a separate crate with
//! its own guards, and why it refuses more than it accepts.
//!
//! # Three gates, in order
//!
//! Nothing gets touched unless all three say yes, and the crate only implements
//! the last one:
//!
//! 1. **Governance** decides whether an action may run without a human. That is
//!    the pipeline's autonomy level, and at the default — `Approve` — every
//!    response is proposed and none is carried out.
//! 2. **The operator** decides which classes of action this run permits at all.
//!    The agent holds that, because it is a deployment decision.
//! 3. **The guards** here decide whether *this* process may be acted on, whatever
//!    the first two said. A protected process is refused even when the pipeline
//!    and the operator both asked for it.
//!
//! The order matters. A guard is not a suggestion from the component with the
//! least context; it is the last word, and it is the one gate that no
//! configuration can open.
//!
//! # What is not here
//!
//! No host isolation, no file quarantine, no registry write. Each is a real XDR
//! capability and each can strand a machine, so they arrive one at a time with
//! their own inverse and their own guards. An action that is not implemented
//! returns [`ports::ActionError::Unsupported`] rather than quietly doing
//! something adjacent.
//!
//! # Reversible is a promise the agent has to keep
//!
//! A suspend is only safe because it can be undone, and it is the agent that
//! undoes it. That means it is only safe while the agent is running: the normal
//! way an agent stops is Ctrl-C, which ends the process in the kernel and runs no
//! further code, so without [`install_stop_handler`] every suspended process
//! would stay suspended — held by something that no longer exists and
//! accountable to nobody. The handler is the other half of the response, not a
//! nicety on top of it.

mod guard;

#[cfg(windows)]
mod console;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use console::{install_stop_handler, stop_requested};

#[cfg(windows)]
pub use windows::WindowsActuator;

/// The actuator on a platform with no implementation.
///
/// Present, and refusing, rather than absent: a build for a platform this
/// product does not support yet should report that when asked, not fail to
/// compile for whoever is reading the code.
#[cfg(not(windows))]
pub struct UnsupportedActuator;

#[cfg(not(windows))]
impl ports::Actuator for UnsupportedActuator {
    fn apply(&mut self, _response: ports::Response) -> Result<(), ports::ActionError> {
        Err(ports::ActionError::Unsupported)
    }
}

pub use guard::{Context, Target, image_name, refusal_by_image, refusal_by_pid, under};
