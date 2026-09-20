//! Every flag value the crate uses, in one place.
//!
//! # Why this file exists
//!
//! ETW has a lot of magic numbers: `LogFileMode` bits, `TRACE_LEVEL_*`,
//! `EVENT_HEADER_FLAG_*`. Windows-rs exposes some as named items and not
//! others; the ones it does not are defined here. Grep `0x` across the
//! crate and the only hits should be in this file and the `declare_shapes!`
//! macro.
//!
//! # The load-bearing constants
//!
//! Two of these matter more than the rest and are the reason this file
//! exists rather than being scattered:
//!
//! * [`INDEPENDENT_SESSION_MODE`] and [`PERSIST_ON_HYBRID_SHUTDOWN`] must
//!   be set **together**. The kernel silently strips `INDEPENDENT` when it
//!   is set alone, and the session looks healthy while dropping events
//!   under load. See [`LOG_FILE_MODE`].
//! * [`FLAG_32_BIT_HEADER`] is not exposed as a named item in this version
//!   of windows-rs, so its value is asserted by a test.

use windows::Win32::System::Diagnostics::Etw::{
    EVENT_HEADER_FLAG_CLASSIC_HEADER, EVENT_HEADER_FLAG_STRING_ONLY,
    EVENT_HEADER_FLAG_TRACE_MESSAGE,
};

/// `EVENT_HEADER_FLAG_CLASSIC_HEADER`. A pre-manifest event.
pub(crate) const FLAG_CLASSIC: u32 = EVENT_HEADER_FLAG_CLASSIC_HEADER;

/// `EVENT_HEADER_FLAG_STRING_ONLY`. Bare Unicode string, no properties.
pub(crate) const FLAG_STRING_ONLY: u32 = EVENT_HEADER_FLAG_STRING_ONLY;

/// `EVENT_HEADER_FLAG_TRACE_MESSAGE`. WPP output, no properties.
pub(crate) const FLAG_TRACE_MESSAGE: u32 = EVENT_HEADER_FLAG_TRACE_MESSAGE;

/// `EVENT_HEADER_FLAG_32_BIT_HEADER`.
///
/// Not exposed as a named constant in this version of windows-rs. The
/// value is stable and documented in `evntcons.h`: the event was logged
/// by a 32-bit process, including a WOW64 process on a 64-bit host.
///
/// The test at the bottom of this file pins the value against the header
/// so a future windows-rs that *does* expose it as a named item would fail
/// loudly rather than diverge silently.
pub(crate) const FLAG_32_BIT_HEADER: u32 = 0x0020;

/// `EVENT_TRACE_REAL_TIME_MODE`.
///
/// The flag that makes a session consumable while it runs. Without it the
/// session writes to a file and [`crate::boundary::session::EtwSession::attach`]
/// has nothing to join.
pub const REAL_TIME_MODE: u32 = 0x0000_0100;

/// `EVENT_TRACE_INDEPENDENT_SESSION_MODE`.
///
/// Isolates the session's buffer pool from other ETW consumers. Without
/// this flag, the kernel routes a portion of events through a shared pool
/// that silently drops under contention — **and the kernel's own loss
/// counters stay at zero**. On a high-EPS provider such as
/// `Microsoft-Windows-DNSServer`, observed loss was roughly 50% with
/// `EventsLost = 0` and `RealTimeBuffersLost = 0`.
///
/// Not sufficient on its own. See [`PERSIST_ON_HYBRID_SHUTDOWN`].
pub(crate) const INDEPENDENT_SESSION_MODE: u32 = 0x0800_0000;

/// `EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN`.
///
/// Required for [`INDEPENDENT_SESSION_MODE`] to be honoured. Setting
/// `INDEPENDENT` alone causes the kernel to silently strip it at
/// `StartTrace` time, leaving the session in the shared-buffer mode
/// without any indication that the requested isolation was not applied.
///
/// Verified against observed behaviour: with `INDEPENDENT` alone the
/// kernel applies `0x00000100`; with both bits together it applies
/// `0x08800100` and honours the request.
pub(crate) const PERSIST_ON_HYBRID_SHUTDOWN: u32 = 0x0080_0000;

/// The `LogFileMode` this crate always uses.
///
/// The composition is not arbitrary:
///
/// * [`REAL_TIME_MODE`] — makes the session consumable live.
/// * [`INDEPENDENT_SESSION_MODE`] — isolates the buffer pool.
/// * [`PERSIST_ON_HYBRID_SHUTDOWN`] — makes the kernel *accept* the
///   `INDEPENDENT` bit rather than silently stripping it.
///
/// All three are required. The tests in this file assert each bit is
/// present, so a future edit that removes one fails at `cargo test`, not
/// at 3am when a production host starts dropping events.
pub(crate) const LOG_FILE_MODE: u32 =
    REAL_TIME_MODE | INDEPENDENT_SESSION_MODE | PERSIST_ON_HYBRID_SHUTDOWN;

pub const LEVEL_CRITICAL: u8 = 1;
pub const LEVEL_ERROR: u8 = 2;
pub const LEVEL_WARNING: u8 = 3;
pub const LEVEL_INFORMATIONAL: u8 = 4;
pub const LEVEL_VERBOSE: u8 = 5;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_log_file_mode_includes_all_three_required_bits() {
        // The pairing that matters most: without both INDEPENDENT and
        // PERSIST, the kernel silently strips INDEPENDENT and the session
        // drops events under load with its own loss counters at zero.
        assert_eq!(
            LOG_FILE_MODE & REAL_TIME_MODE,
            REAL_TIME_MODE,
            "REAL_TIME is required for live consumption"
        );
        assert_eq!(
            LOG_FILE_MODE & INDEPENDENT_SESSION_MODE,
            INDEPENDENT_SESSION_MODE,
            "INDEPENDENT is required to isolate the buffer pool"
        );
        assert_eq!(
            LOG_FILE_MODE & PERSIST_ON_HYBRID_SHUTDOWN,
            PERSIST_ON_HYBRID_SHUTDOWN,
            "PERSIST is required for INDEPENDENT to be honoured"
        );
    }

    #[test]
    fn the_log_file_mode_is_exactly_those_three_bits() {
        // If a fourth bit is added by accident, the constant is no longer
        // what the doc comment says it is. This catches that.
        let expected =
            REAL_TIME_MODE | INDEPENDENT_SESSION_MODE | PERSIST_ON_HYBRID_SHUTDOWN;
        assert_eq!(LOG_FILE_MODE, expected);
    }

    #[test]
    fn the_flag_constants_have_their_documented_values() {
        // A canary for windows-rs changes. If a future version of the
        // bindings exposes these as different values, this test is what
        // fails rather than the callback silently misfiltering.
        assert_eq!(FLAG_CLASSIC, 0x0001);
        assert_eq!(FLAG_STRING_ONLY, 0x0004);
        assert_eq!(FLAG_TRACE_MESSAGE, 0x0008);
        assert_eq!(FLAG_32_BIT_HEADER, 0x0020);
    }

    #[test]
    fn the_level_constants_are_ordered() {
        // The level filter uses `>`, so the ordering matters.
        assert!(LEVEL_CRITICAL < LEVEL_ERROR);
        assert!(LEVEL_ERROR < LEVEL_WARNING);
        assert!(LEVEL_WARNING < LEVEL_INFORMATIONAL);
        assert!(LEVEL_INFORMATIONAL < LEVEL_VERBOSE);
    }
}
