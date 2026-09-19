//! Linux telemetry source (eBPF). Placeholder.
//!
//! Nothing in the Windows build references this crate; it exists so the port
//! has a home on Linux. What belongs here is not a copy of the ETW adapter:
//!
//! * Loading and attaching a CO-RE program set (aya or libbpf-rs) for the
//!   syscall, LSM and tracepoint families that map onto [`model::EventKind`].
//! * A ring buffer consumer. ETW calls you back on its own thread; eBPF gives
//!   you a memory-mapped ring you poll yourself. That difference is why the
//!   two sources share only `ports::EventSource`.
//! * A stable process identity. ETW supplies a kernel-generated process start
//!   key; on Linux the `(pid, start_time)` pair has to be assembled in the
//!   adapter, otherwise PID reuse silently corrupts A1 state projections.
//!
//! Until this exists, callers on Linux should report that they have no sensor
//! rather than quietly running with a partial one.
#![cfg(target_os = "linux")]
