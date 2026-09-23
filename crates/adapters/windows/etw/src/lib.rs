//! Windows ETW real-time sensor.
//!
//! # Structure
//!
//! Five layers, in order of flow:
//!
//! ```text
//!   boundary/   ↔ Windows. Session, callback, counters.
//!   decode/     ↔ TDH. Raw bytes → named, typed fields.
//!   wire/       ↔ Wire format. Raw event → typed event.
//!   enrich/     ↔ Host facts the kernel does not emit.
//!   diagnostics/↔ Operator-facing checks. Never on the hot path.
//! ```
//!
//! [`observe`] is the sixth module and not a layer: it joins a session and a
//! translator into one [`observer::Observe`] source, which is what a runtime
//! drives. It sits on top of the five rather than between any of them.
//!
//! # Reading order
//!
//! 1. [`boundary::callback::on_event`] — the hot path.
//! 2. [`wire::shape`] — one `declare_shapes!` table.
//! 3. [`wire::decoders`] — one function per shape.
//! 4. [`decode`] — TDH.
//! 5. [`enrich`] — the four caches.
//!
//! # Rules
//!
//! * The callback never blocks and never panics.
//! * Every `unsafe` block is in a module whose name says why.
//! * The wire format is typed. No raw bytes, no offsets.
//! * A missing mandatory field is `undecodable`, never a guess.
//! * A quiet host is not a dead sensor.

#![cfg(windows)]

pub mod boundary;
pub mod decode;
pub mod diagnostics;
pub mod enrich;
pub mod error;
pub mod observe;
pub mod provider;
pub mod util;
pub mod wire;

pub use boundary::{
    callback::{EtwRaw, ProcessIdentity},
    constants::{
        LEVEL_CRITICAL, LEVEL_ERROR, LEVEL_INFORMATIONAL, LEVEL_VERBOSE, LEVEL_WARNING,
        REAL_TIME_MODE,
    },
    session::{
        Buffers, EnableReport, EtwSession, ProviderSpec, SessionConfig, SessionState, is_running,
        session_state,
    },
    stats::{Stats, StatsSnapshot},
};

pub use decode::{Decoder, FieldType, FieldValue, utf16_to_string};

pub use diagnostics::{
    autologger::{AUTOLOGGER_ROOT, AutologgerSpec, AutologgerState},
    security::{
        ExportIntegrity, JumpScan, KernelIntegrityStatus, SecurityReport, SessionHealth,
        TextIntegrity, check_ntdll_exports, find_patch_in, full_report, query_kernel_integrity,
        scan_for_jumps, session_health, verify_text_section,
    },
};

pub use enrich::{
    image::{ImageMeta, ImageMetaCache},
    kcb::KeyCache,
    paths::DevicePaths,
    registry::translate as translate_registry_path,
};

pub use error::{EtwError, hint, remedy};

pub use provider::{
    DNS_CLIENT, KERNEL_FILE, KERNEL_NETWORK, KERNEL_PROCESS, KERNEL_REGISTRY, default_providers,
};

pub use observe::EtwObservation;

pub use util::format_guid;

pub use wire::{
    GapSeverity, KcbStats, Shape, ShapeCounts, TelemetryGap, Translator, UnrecognisedHistogram,
    render_registry_value,
};
