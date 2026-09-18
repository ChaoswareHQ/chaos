//! macOS telemetry source (EndpointSecurity). Placeholder.
//!
//! Nothing in the Windows build references this crate. This one is worth its
//! own crate because it is genuinely harder than the Windows path:
//!
//! * EndpointSecurity cannot be driven from pure Rust. It needs an
//!   entitlements-bearing, code-signed binary and an Objective-C block client,
//!   so the shape is a small `es-sys` FFI shim plus this adapter on top of it.
//! * The framework delivers an `es_message_t` whose `proc` and `event` unions
//!   are only valid for the duration of the callback — exactly like ETW's
//!   `EVENT_RECORD`. The same copy-then-decode split applies, for the same
//!   reason.
//! * macOS has no process start key either; identity comes from the audit
//!   token's pidversion, which is the closest analogue.
#![cfg(target_os = "macos")]
