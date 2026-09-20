//! Where this crate touches the Windows API.
//!
//! Every call to `StartTraceW`, `EnableTraceEx2`, `OpenTraceW`,
//! `ProcessTrace`, `CloseTrace`, `ControlTraceW`, and the console control
//! handler lives under this module. Nothing else in the crate talks to the
//! session API directly.
//!
//! # The four files
//!
//! * [`constants`] — every flag value the crate uses, in one place. Grep
//!   `0x` across the crate and you find only this file plus `declare_shapes!`.
//! * [`callback`] — the hot path. Runs once per event on the kernel's
//!   thread. Short, total, unsafe-scoped.
//! * [`session`] — the lifecycle. Everything about starting, attaching,
//!   stopping a trace session, and the consumer thread that blocks in
//!   `ProcessTrace`.
//! * [`stats`] — the atomic counters the callback writes and the report
//!   reads.
//!
//! # What this module does not do
//!
//! It does not decode events (that is [`crate::decode`]), does not
//! translate to the wire format (that is [`crate::wire`]), and does not
//! know about the pipeline. It moves bytes out of the kernel and into a
//! channel.

pub mod callback;
pub mod constants;
pub mod session;
pub mod stats;
