//! Every flag value the crate uses, in one place.
//!
//! # Why this file exists
//!
//! ETW has a lot of magic numbers: `LogFileMode` bits, `TRACE_LEVEL_*`,
//! `EVENT_HEADER_FLAG_*`. Windows-rs exposes some as named items and not
//! others; the ones it does not are defined here.
//!
//! # The load-bearing constants
//!
//! Three of these matter more than the rest and are the reason this file
//! exists rather than being scattered:
//!
//! * [`INDEPENDENT_SESSION_MODE`] and [`PERSIST_ON_HYBRID_SHUTDOWN`] must
//!   be set **together**. The kernel silently strips `INDEPENDENT` when it
//!   is set alone, and the session looks healthy while dropping events
//!   under load.
//! * [`SYSTEM_LOGGER_MODE`] is what makes `Security-Auditing` willing to
//!   deliver events at all. Without it, the enable call for that provider
//!   succeeds and the events never arrive.
//! * [`FLAG_32_BIT_HEADER`] is not exposed as a named item in this version
//!   of windows-rs, so its value is asserted by a test.

use windows::Win32::System::Diagnostics::Etw::{
    EVENT_HEADER_FLAG_CLASSIC_HEADER, EVENT_HEADER_FLAG_STRING_ONLY,
    EVENT_HEADER_FLAG_TRACE_MESSAGE,
};

// ---------------------------------------------------------------------------
// EVENT_HEADER_FLAG_*: the callback's filter
// ---------------------------------------------------------------------------

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
pub(crate) const FLAG_32_BIT_HEADER: u32 = 0x0020;

// ---------------------------------------------------------------------------
// LogFileMode bits
// ---------------------------------------------------------------------------

/// `EVENT_TRACE_REAL_TIME_MODE`.
///
/// The flag that makes a session consumable while it runs.
pub const REAL_TIME_MODE: u32 = 0x0000_0100;

/// `EVENT_TRACE_INDEPENDENT_SESSION_MODE`.
///
/// Isolates the session's buffer pool from other ETW consumers. Not
/// sufficient on its own — see [`PERSIST_ON_HYBRID_SHUTDOWN`].
pub(crate) const INDEPENDENT_SESSION_MODE: u32 = 0x0800_0000;

/// `EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN`.
///
/// Required for [`INDEPENDENT_SESSION_MODE`] to be honoured. Setting
/// `INDEPENDENT` alone causes the kernel to silently strip it at
/// `StartTrace` time.
pub(crate) const PERSIST_ON_HYBRID_SHUTDOWN: u32 = 0x0080_0000;

/// `EVENT_TRACE_SYSTEM_LOGGER_MODE`.
///
/// The flag that makes a trace session a **system logger**. A system
/// logger session is the only kind that the kernel will deliver
/// `Microsoft-Windows-Security-Auditing` events to — and, notably, a
/// session without this flag will still *accept* the enable call for
/// that provider and report `ERROR_SUCCESS`, then deliver nothing.
///
/// # The failure this closes
///
/// Without the flag, the sensor's `Security-Auditing` enable succeeds,
/// the provider registers on the session, and `Security-Auditing` 4688
/// never arrives. The shape that reads 4688 (`process_start_audit`)
/// shows `0/0` in the run report while the audit policy is confirmed
/// on and the `CommandLine` inclusion flag is set. Everything an
/// operator would think to check is correct, and the events are still
/// absent.
///
/// Setting this bit is the fix. The kernel then routes the audit
/// events to the session. The bit requires Administrator, which this
/// crate already needs to start a session at all.
///
/// Windows XP and later. No compatibility concern.
pub(crate) const SYSTEM_LOGGER_MODE: u32 = 0x0200_0000;

/// The `LogFileMode` this crate always uses.
///
/// The composition is not arbitrary:
///
/// * [`REAL_TIME_MODE`] — makes the session consumable live.
/// * [`INDEPENDENT_SESSION_MODE`] — isolates the buffer pool.
/// * [`PERSIST_ON_HYBRID_SHUTDOWN`] — makes the kernel *accept* the
///   `INDEPENDENT` bit rather than silently stripping it.
/// * [`SYSTEM_LOGGER_MODE`] — makes the session one that
///   `Security-Auditing` will deliver to.
///
/// All four are required for the seven-provider default set to work on
/// a host where the audit policy is on. Removing any of them makes an
/// entire class of events unreachable:
///
/// * without `SYSTEM_LOGGER_MODE`: `process_start_audit` never fires.
/// * without `INDEPENDENT_SESSION_MODE` (+ `PERSIST`): the kernel drops
///   events under load and its own loss counters stay at zero.
pub(crate) const LOG_FILE_MODE: u32 =
    REAL_TIME_MODE | INDEPENDENT_SESSION_MODE | PERSIST_ON_HYBRID_SHUTDOWN | SYSTEM_LOGGER_MODE;

// ---------------------------------------------------------------------------
// TRACE_LEVEL_*: the level filter
// ---------------------------------------------------------------------------

pub const LEVEL_CRITICAL: u8 = 1;
pub const LEVEL_ERROR: u8 = 2;
pub const LEVEL_WARNING: u8 = 3;
pub const LEVEL_INFORMATIONAL: u8 = 4;
pub const LEVEL_VERBOSE: u8 = 5;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_log_file_mode_includes_all_four_required_bits() {
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
        assert_eq!(
            LOG_FILE_MODE & SYSTEM_LOGGER_MODE,
            SYSTEM_LOGGER_MODE,
            "SYSTEM_LOGGER is required for Security-Auditing to deliver events"
        );
    }

    #[test]
    fn the_log_file_mode_is_exactly_those_four_bits() {
        // If a fifth bit is added by accident, the constant is no longer
        // what the doc comment says it is. This catches that.
        let expected = REAL_TIME_MODE
            | INDEPENDENT_SESSION_MODE
            | PERSIST_ON_HYBRID_SHUTDOWN
            | SYSTEM_LOGGER_MODE;
        assert_eq!(LOG_FILE_MODE, expected);
    }

    #[test]
    fn the_flag_constants_have_their_documented_values() {
        // A canary for windows-rs changes. The values are the
        // `EVENT_HEADER_FLAG_*` constants from `evntcons.h`:
        //
        // * `EVENT_HEADER_FLAG_EXTENDED_INFO` is `0x0001`
        // * `EVENT_HEADER_FLAG_STRING_ONLY` is `0x0004`
        // * `EVENT_HEADER_FLAG_TRACE_MESSAGE` is `0x0008`
        // * `EVENT_HEADER_FLAG_32_BIT_HEADER` is `0x0020`
        // * `EVENT_HEADER_FLAG_CLASSIC_HEADER` is `0x0100`
        //
        // `CLASSIC_HEADER` is the one that is easy to get wrong because
        // the name suggests it should be the first flag in the list.
        // It is not.
        assert_eq!(FLAG_CLASSIC, 0x0100);
        assert_eq!(FLAG_STRING_ONLY, 0x0004);
        assert_eq!(FLAG_TRACE_MESSAGE, 0x0008);
        assert_eq!(FLAG_32_BIT_HEADER, 0x0020);
    }

    #[test]
    fn the_level_constants_are_ordered() {
        assert!(LEVEL_CRITICAL < LEVEL_ERROR);
        assert!(LEVEL_ERROR < LEVEL_WARNING);
        assert!(LEVEL_WARNING < LEVEL_INFORMATIONAL);
        assert!(LEVEL_INFORMATIONAL < LEVEL_VERBOSE);
    }
}
