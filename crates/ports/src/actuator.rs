//! The port through which a decided response reaches the machine.
//!
//! Everything else in this product observes. This is the only thing that acts,
//! and the split is deliberate: the pipeline decides, the agent does, and the
//! one irreversible capability in the system sits behind a trait with a small
//! vocabulary so it can be replaced, audited, or stubbed out in a test.
//!
//! # The vocabulary is deliberately tiny
//!
//! Three operations, all aimed at a *process*, because that is the largest blast
//! radius this agent is allowed to have right now. There is no isolate, no
//! quarantine, no registry write. Each of those is a real XDR capability and each
//! of them can strand a host, so they arrive one at a time with their own
//! inverse — see [`Response::inverse`], which exists so that "can this be undone"
//! is a question the type answers rather than a comment claiming it.
//!
//! # Why suspend before terminate
//!
//! [`Response::Suspend`] is the first action worth having because it is
//! reversible: a wrong guess costs a paused process, not a lost one. Suspending
//! a process also freezes the *attacker's* activity rather than only ending the
//! process they were driving, which for a live intrusion is usually the more
//! useful of the two.

/// Something the agent can do to a process in response to a detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Response {
    /// Hold a process's threads at their current instruction.
    Suspend { pid: u32 },
    /// Let a suspended process run again.
    Resume { pid: u32 },
    /// End a process. Not reversible in any sense that matters.
    Terminate { pid: u32 },
}

impl Response {
    /// The process this is aimed at.
    #[inline]
    pub const fn pid(self) -> u32 {
        match self {
            Response::Suspend { pid } | Response::Resume { pid } | Response::Terminate { pid } => {
                pid
            }
        }
    }

    /// What undoes this, when anything does.
    ///
    /// `None` is not a failure to implement: it is the answer. A terminate is
    /// the end of that process, and a caller that treats `None` as room to
    /// improvise is the reason this returns an `Option` rather than a `Response`.
    pub const fn inverse(self) -> Option<Response> {
        match self {
            Response::Suspend { pid } => Some(Response::Resume { pid }),
            Response::Resume { pid } => Some(Response::Suspend { pid }),
            Response::Terminate { .. } => None,
        }
    }

    /// Whether this can be undone.
    #[inline]
    pub const fn is_reversible(self) -> bool {
        self.inverse().is_some()
    }

    /// The imperative verb, for a log line or an alert body.
    #[inline]
    pub const fn verb(self) -> &'static str {
        match self {
            Response::Suspend { .. } => "suspend",
            Response::Resume { .. } => "resume",
            Response::Terminate { .. } => "terminate",
        }
    }

    /// A one-line description of what was or would be done.
    pub fn describe(self) -> String {
        format!("{} process {}", self.verb(), self.pid())
    }
}

/// Why an action did not happen.
///
/// [`ActionError::Refused`] is separate from [`ActionError::Os`] on purpose: one
/// is the product declining to act, the other is the machine failing to, and an
/// operator reading a log needs to know which. A refusal is a guard working; an
/// OS error is a bug or a race.
#[derive(Debug, thiserror::Error)]
pub enum ActionError {
    /// A guard said no. This is the expected outcome for a protected process.
    #[error("refused: {0}")]
    Refused(String),

    /// The operating system declined, or the target was already gone.
    #[error("the operating system declined: {0}")]
    Os(String),

    /// This build has no implementation for the platform it is running on.
    #[error("responding is not implemented on this platform")]
    Unsupported,
}

/// Carries out a decided response.
///
/// `&mut self` and not `&self`, matching [`crate::EventSink`]: an actuator that
/// records what it did, or holds a handle, cannot do it behind a shared
/// reference without interior mutability for no benefit.
pub trait Actuator: Send {
    /// Do it, or refuse and say why.
    ///
    /// An `Ok` means the operating system accepted the request. It does not mean
    /// the effect is observable yet — thread suspension is asynchronous — so
    /// callers should not treat a subsequent absence of activity as proof.
    fn apply(&mut self, response: Response) -> Result<(), ActionError>;

    /// Whether this actuator resolves and guards but never actually acts.
    ///
    /// The trait cannot report that a response took effect — `Ok` says only that
    /// the operating system accepted it — but a dry run is a property of the
    /// actuator itself, and a log line claiming something was done when nothing
    /// was is the kind of lie the rest of this product goes out of its way to
    /// avoid. Defaults to `false`: an actuator is assumed real unless it says
    /// otherwise.
    fn is_dry_run(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suspend_is_reversible_and_terminate_is_not() {
        assert_eq!(
            Response::Suspend { pid: 10 }.inverse(),
            Some(Response::Resume { pid: 10 })
        );
        assert_eq!(
            Response::Resume { pid: 10 }.inverse(),
            Some(Response::Suspend { pid: 10 })
        );
        assert_eq!(Response::Terminate { pid: 10 }.inverse(), None);

        assert!(Response::Suspend { pid: 10 }.is_reversible());
        assert!(!Response::Terminate { pid: 10 }.is_reversible());
    }

    #[test]
    fn an_inverse_is_its_own_inverse() {
        // Otherwise a revert-of-a-revert would do something nobody asked for.
        for response in [Response::Suspend { pid: 1 }, Response::Resume { pid: 1 }] {
            let back = response.inverse().expect("reversible").inverse();
            assert_eq!(back, Some(response));
        }
    }

    #[test]
    fn every_response_names_its_target_and_its_verb() {
        assert_eq!(Response::Terminate { pid: 42 }.pid(), 42);
        assert_eq!(Response::Terminate { pid: 42 }.verb(), "terminate");
        assert_eq!(
            Response::Suspend { pid: 42 }.describe(),
            "suspend process 42"
        );
    }

    #[test]
    fn a_refusal_reads_differently_from_an_os_failure() {
        let refused = ActionError::Refused("lsass.exe is protected".into()).to_string();
        let failed = ActionError::Os("access denied".into()).to_string();
        assert!(refused.starts_with("refused:"));
        assert!(failed.starts_with("the operating system declined:"));
    }
}
