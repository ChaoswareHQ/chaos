//! Catching the stop, so that what was frozen can be let go.
//!
//! # Why an agent needs this at all
//!
//! A suspend is only safe because it can be undone. That promise is kept by the
//! agent, which means it is only kept if the agent gets to run code on the way
//! out — and the way an agent is normally stopped is Ctrl-C, which ends the
//! process inside the kernel with no Rust code running afterwards. Every process
//! the run had suspended would stay suspended, held by something that no longer
//! exists and accountable to nobody.
//!
//! So the console handler is not a nicety. It is the other half of the response:
//! without it, "reversible" is a claim the product cannot keep.
//!
//! # What it does and does not do
//!
//! The handler does one thing — record that a stop was asked for — because it
//! runs on a thread Windows injects and cannot allocate, print, or wait. The
//! collection loop is polling anyway, so it sees the flag within one drain
//! interval and unwinds on its own terms: release what it held, ship what is
//! queued, exit.
//!
//! Returning `TRUE` is what buys that. Returning `FALSE` would hand the event
//! back to the default handler, which terminates the process immediately — the
//! exact outcome this exists to prevent.

use std::sync::atomic::{AtomicBool, Ordering};
use windows::Win32::System::Console::SetConsoleCtrlHandler;
use windows::core::BOOL;

static STOP: AtomicBool = AtomicBool::new(false);

/// Whether a stop has been asked for: Ctrl-C, Ctrl-Break, a closed console, or a
/// sign-out.
///
/// Polled, not awaited. The alternative — blocking until the stop arrives —
/// would mean the collection loop could not ship on a timer, which is what keeps
/// the server's counts current while a run is in progress.
#[inline]
pub fn stop_requested() -> bool {
    STOP.load(Ordering::Relaxed)
}

/// Ask Windows to report a stop instead of provoking one.
///
/// Returns `false` if the handler could not be installed. The agent is expected
/// to say so plainly, because the consequence is real: after a hard stop, every
/// process this run suspended stays suspended.
pub fn install_stop_handler() -> bool {
    // SAFETY: the handler has the signature the API requires, reads and writes no
    // shared state beyond one atomic, and is installed once per process.
    unsafe { SetConsoleCtrlHandler(Some(handler), true).is_ok() }
}

/// Runs on a thread Windows creates, on every stop event.
///
/// One atomic store, and nothing else. Anything more — a log line, a lock, a
/// second thread — is not safe to do here.
unsafe extern "system" fn handler(_event: u32) -> BOOL {
    STOP.store(true, Ordering::SeqCst);
    // Handled: do not let the default handler kill the process before the
    // collection loop has released what it held.
    BOOL(1)
}
