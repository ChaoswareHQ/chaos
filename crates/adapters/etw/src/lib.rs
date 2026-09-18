//! Windows ETW real-time sensor.
//!
//! Shape of the thing, because the split matters more than any single file:
//!
//! * [`session`] owns the kernel session and the thread that blocks in
//!   `ProcessTrace`. It is the only module that talks to the session API.
//! * [`callback`] runs per event on that thread. It copies the payload, reads
//!   the header, and hands off. It does no decoding, no allocation beyond the
//!   payload copy, and no blocking.
//! * [`decode`] runs on the consumer side, where being slow is affordable. It
//!   rebuilds a synthetic `EVENT_RECORD` over the copied bytes so TDH can name
//!   the fields.
//! * [`stats`] counts what happened, including what was lost. Those counters
//!   are what let the pipeline state an observation gap instead of assuming
//!   one.
//!
//! The sensor emits [`EtwRaw`], not `RawEvent`, because local decoding needs
//! the provider GUID, the descriptor and the extended data, none of which
//! belong in the wire format. `EtwRaw::wire` is the part that ships.
#![cfg(windows)]

pub mod callback;
pub mod decode;
pub mod error;
pub mod provider;
pub mod session;
pub mod stats;

pub use callback::{EtwRaw, ProcessIdentity};
pub use decode::{Decoder, FieldValue, utf16_to_string};
pub use error::{EtwError, hint};
pub use provider::{DNS_CLIENT, KERNEL_FILE, KERNEL_NETWORK, KERNEL_PROCESS, KERNEL_REGISTRY};
pub use session::{EnableReport, EtwSession, ProviderSpec, SessionConfig};
pub use stats::{Stats, StatsSnapshot};
