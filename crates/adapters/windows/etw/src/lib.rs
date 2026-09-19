//! Windows ETW real-time sensor.
//!
//! * [`session`] owns the kernel session and the thread that blocks in
//!   `ProcessTrace`. It is the only module that talks to the session API.
//! * [`callback`] runs per event on that thread. It copies the payload, reads
//!   the header, and hands off. It does no decoding, no allocation beyond the
//!   payload copy, and no blocking.
//! * [`decode`] runs on the consumer side, where being slow is affordable. It
//!   rebuilds a synthetic `EVENT_RECORD` over the copied bytes, fetches the
//!   schema TDH uses to name the fields, and reads each value by its declared
//!   type rather than guessing from the byte width.
//! * [`translate`] is where a decoded event becomes the wire format the
//!   detection pipeline scores. It is the only module that knows which events
//!   the product cares about.
//! * [`paths`] translates the kernel's `\Device\HarddiskVolumeN\...` paths to
//!   the DOS form (`C:\...`) that a rule author writes.
//! * [`security`] is the self-check layer: `ntdll` prologue inspection, the
//!   whole-`.text` comparison against disk, session health, and kernel
//!   integrity. It turns an attack on the sensor into evidence.
//! * [`stats`] counts what happened, including what was lost. Those counters
//!   are what let the pipeline state an observation gap instead of assuming
//!   one.
//!
//! [`error::remedy`] is the odd one out and earns its place: the two failures
//! an operator actually hits — no elevated token, a session name already taken
//! — have obvious answers that do not fit in the error's own line.
//!
//! The sensor emits [`EtwRaw`], not `RawEvent`, because local decoding needs
//! the provider GUID, the descriptor and the extended data, none of which
//! belong in the wire format. `EtwRaw::wire` is the part that ships.
#![cfg(windows)]

pub mod autologger;
pub mod callback;
pub mod decode;
pub mod error;
pub mod paths;
pub mod provider;
pub mod security;
pub mod session;
pub mod stats;
pub mod translate;

pub use autologger::{
    AUTOLOGGER_ROOT, AutologgerSpec, AutologgerState, REAL_TIME_MODE, format_guid,
};
pub use callback::{EtwRaw, ProcessIdentity};
pub use decode::{Decoder, FieldType, FieldValue, utf16_to_string};
pub use error::{EtwError, hint, remedy};
pub use paths::DevicePaths;
pub use provider::{DNS_CLIENT, KERNEL_FILE, KERNEL_NETWORK, KERNEL_PROCESS, KERNEL_REGISTRY};
pub use security::{
    ExportIntegrity, JumpScan, KernelIntegrityStatus, SecurityReport, SessionHealth, TextIntegrity,
    check_ntdll_exports, find_patch_in, full_report, query_kernel_integrity, scan_for_jumps,
    session_health, verify_text_section,
};
pub use session::{
    Buffers, EnableReport, EtwSession, ProviderSpec, SessionConfig, SessionState, is_running,
    session_state,
};
pub use stats::{Stats, StatsSnapshot};
pub use translate::{
    GapSeverity, KcbStats, KeyCache, Shape, ShapeCounts, TelemetryGap, Translator,
    UnrecognisedHistogram, render_registry_value,
};
