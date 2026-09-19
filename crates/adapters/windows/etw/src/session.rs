//! Real-time ETW session lifecycle.
//!
//! The shape here is forced by the API, and most of the care is about
//! lifetimes:
//!
//! * `EVENT_TRACE_PROPERTIES` and its logger name share one allocation that must
//!   outlive the session, because `ControlTraceW` reads it back on stop. The
//!   logger name is copied into the tail of that same buffer.
//! * `ProcessTrace` blocks, so it owns a thread. `CloseTrace` from another
//!   thread is what makes it return — there is no other way to wake it.
//! * `EVENT_TRACE_LOGFILEW` must stay alive for the whole `ProcessTrace` call,
//!   including the `LoggerName` pointer that reaches back into our name buffer.
//!   It is owned by the session and never moved: the consumer thread only gets
//!   the handle.
//!
//! Real-time mode means `FlushTimer` is a latency floor, not a tuning knob: a
//! sparse provider's events are delivered on flush rather than on arrival, so
//! one second is the compromise between seeing quiet providers at all and
//! paying per-buffer overhead for nothing.
//!
//! # Why `INDEPENDENT_SESSION_MODE` is mandatory
//!
//! Without `EVENT_TRACE_INDEPENDENT_SESSION_MODE`, the kernel routes a portion
//! of events through a shared buffer pool that silently drops under
//! contention — **and the kernel's own loss counters stay at zero**. On a
//! high-EPS provider such as `Microsoft-Windows-DNSServer`, the observed loss
//! was roughly 50% with `EventsLost = 0` and `RealTimeBuffersLost = 0`[reference:3].
//!
//! A subtler requirement documented in the same report: the kernel silently
//! strips `INDEPENDENT` unless it is paired with
//! `EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN` (or its sibling). Setting
//! `INDEPENDENT` alone produces `Requested LogFileMode = 0x08000100` but
//! `Kernel-applied = 0x00000100` — the bit is gone, and the session looks
//! healthy[reference:4]. Both bits together are honored.

use crate::callback::{CallbackContext, EtwRaw, on_event};
use crate::error::{EtwError, hint};
use crate::stats::StatsSnapshot;
use crossbeam_channel::{Receiver, RecvTimeoutError, bounded};
use model::RawEvent;
use ports::{EventSource, SourceError};
use std::mem::size_of;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use windows::Win32::Foundation::{ERROR_SUCCESS, ERROR_WMI_INSTANCE_NOT_FOUND};
use windows::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE,
    ProcessTrace, StartTraceW, WNODE_FLAG_TRACED_GUID,
};
use windows::core::{GUID, PCWSTR, PWSTR};

/// `EVENT_TRACE_INDEPENDENT_SESSION_MODE` from `evntrace.h`.
///
/// Without this flag (and its required companion below), the kernel routes a
/// portion of events through a shared pool that silently drops under
/// contention. The kernel's loss counters do not increment; the only way to
/// detect the loss is to compare against an independent consumer[reference:5].
const EVENT_TRACE_INDEPENDENT_SESSION_MODE: u32 = 0x0800_0000;

/// `EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN` from `evntrace.h`.
///
/// Required for `INDEPENDENT_SESSION_MODE` to be honored. Setting `INDEPENDENT`
/// alone causes the kernel to silently strip it at `StartTrace` time, leaving
/// the session in the shared-buffer mode without any indication that the
/// requested isolation was not applied[reference:6].
const EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN: u32 = 0x0080_0000;

/// The `LogFileMode` this sensor always uses.
///
/// The composition is not arbitrary:
///
/// - `REAL_TIME_MODE` is what makes the session consumable live.
/// - `INDEPENDENT_SESSION_MODE` isolates the session's buffer pool from other
///   ETW consumers.
/// - `PERSIST_ON_HYBRID_SHUTDOWN` is what makes the kernel *accept* the
///   `INDEPENDENT` bit rather than silently stripping it.
const LOG_FILE_MODE: u32 =
    EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_INDEPENDENT_SESSION_MODE | EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN;

/// One provider to enable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderSpec {
    pub guid: GUID,
    /// Human name, used both for the wire format and for error messages.
    pub name: &'static str,
    /// `TRACE_LEVEL_*`: 5 is verbose, 4 informational, 2 error-only.
    pub level: u8,
    /// Keyword mask. `0` means "every keyword", which against a manifest
    /// provider is rarely what a production deployment wants.
    pub keywords: u64,
}

/// Kernel buffer sizing and flush cadence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Buffers {
    /// Size of one kernel buffer, in KB.
    pub size_kb: u32,
    /// Buffers allocated immediately. Held for the session's lifetime.
    pub minimum: u32,
    /// Ceiling the kernel may grow to under load.
    pub maximum: u32,
    /// Seconds between forced flushes.
    pub flush_seconds: u32,
}

impl Default for Buffers {
    fn default() -> Self {
        Self {
            size_kb: 128,
            minimum: 16,
            maximum: 64,
            flush_seconds: 1,
        }
    }
}

/// Session parameters.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub name: String,
    /// Bounded channel depth. When it fills, the callback drops rather than
    /// blocks, so this is a real ceiling on burst absorption.
    pub capacity: usize,
    pub providers: Vec<ProviderSpec>,
    /// Events above this level are counted and discarded before any allocation.
    pub max_level: u8,
    /// Kernel buffer sizing and flush cadence.
    pub buffers: Buffers,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            capacity: 64 * 1024,
            providers: Vec::new(),
            max_level: 5,
            buffers: Buffers::default(),
        }
    }
}

/// Outcome of enabling one provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnableReport {
    pub name: &'static str,
    pub result: Result<(), u32>,
}

/// Keeps `EVENT_TRACE_LOGFILEW` alive without letting its raw pointers escape.
#[allow(dead_code)]
struct LogFile(Box<EVENT_TRACE_LOGFILEW>);

unsafe impl Send for LogFile {}

/// A live real-time session.
pub struct EtwSession {
    display_name: String,
    /// Owned, NUL-terminated, and referenced by `LoggerName` for the whole run.
    name: Vec<u16>,
    /// `EVENT_TRACE_PROPERTIES` plus the logger name in its tail.
    props: Box<[u8]>,
    /// Held for its lifetime, never read after start.
    #[allow(dead_code)]
    logfile: LogFile,
    consumer: PROCESSTRACE_HANDLE,
    ctx: Arc<CallbackContext>,
    rx: Receiver<EtwRaw>,
    thread: Option<JoinHandle<()>>,
    /// `(EventsLost, RealTimeBuffersLost)` as reported by the kernel.
    lost: (u32, u32),
    /// Whether this process started the session.
    owns: bool,
}

fn props_ptr(buf: &mut [u8]) -> *mut EVENT_TRACE_PROPERTIES {
    buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES
}

/// Build the properties struct and its embedded logger name.
fn build_props(name: &[u16], buffers: Buffers) -> Box<[u8]> {
    let terminated = name.last() == Some(&0);
    let units = name.len() + usize::from(!terminated);
    let total = size_of::<EVENT_TRACE_PROPERTIES>() + units * size_of::<u16>();
    let mut buf = vec![0u8; total].into_boxed_slice();

    unsafe {
        let p = props_ptr(&mut buf);
        (*p).Wnode.BufferSize = total as u32;
        (*p).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*p).Wnode.ClientContext = 1;
        // The three bits that matter: real-time, independent, persist.
        // Setting only REAL_TIME is what causes the silent loss described in
        // the module docs.
        (*p).LogFileMode = LOG_FILE_MODE;
        (*p).FlushTimer = buffers.flush_seconds.max(1);
        (*p).BufferSize = buffers.size_kb;
        (*p).MinimumBuffers = buffers.minimum;
        (*p).MaximumBuffers = buffers.maximum.max(buffers.minimum);
        (*p).LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;

        let dst = buf.as_mut_ptr().add(size_of::<EVENT_TRACE_PROPERTIES>()) as *mut u16;
        for (i, unit) in name.iter().enumerate() {
            dst.add(i).write_unaligned(*unit);
        }
    }

    buf
}

/// What the kernel knows about a session, without starting or stopping it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionState {
    pub real_time: bool,
    pub log_file_mode: u32,
    pub events_lost: u32,
    pub buffers_lost: u32,
    pub buffers_written: u32,
    pub free_buffers: u32,
}

/// Ask the kernel what a session is doing.
pub fn session_state(name: &str) -> Result<Option<SessionState>, EtwError> {
    if name.is_empty() {
        return Err(EtwError::EmptySessionName);
    }

    let name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut props = build_props(&name, Buffers::default());

    let rc = unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            PCWSTR(name.as_ptr()),
            props_ptr(&mut props),
            EVENT_TRACE_CONTROL_QUERY,
        )
    };

    if rc == ERROR_WMI_INSTANCE_NOT_FOUND {
        return Ok(None);
    }
    if rc != ERROR_SUCCESS {
        return Err(EtwError::ControlTrace(rc.0));
    }

    let p = props_ptr(&mut props);
    Ok(Some(unsafe {
        SessionState {
            real_time: (*p).LogFileMode & EVENT_TRACE_REAL_TIME_MODE != 0,
            log_file_mode: (*p).LogFileMode,
            events_lost: (*p).EventsLost,
            buffers_lost: (*p).RealTimeBuffersLost,
            buffers_written: (*p).BuffersWritten,
            free_buffers: (*p).FreeBuffers,
        }
    }))
}

/// Whether a session by this name exists.
pub fn is_running(name: &str) -> Result<bool, EtwError> {
    Ok(session_state(name)?.is_some())
}

impl EtwSession {
    /// Start the session and its consumer thread.
    pub fn start(cfg: SessionConfig) -> Result<(Self, Vec<EnableReport>), EtwError> {
        if cfg.name.is_empty() {
            return Err(EtwError::EmptySessionName);
        }
        if cfg.capacity == 0 {
            return Err(EtwError::InvalidChannelCapacity);
        }

        let name: Vec<u16> = cfg.name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut props = build_props(&name, cfg.buffers);
        let pname = PCWSTR(name.as_ptr());
        let null_handle = CONTROLTRACE_HANDLE { Value: 0 };

        let _ = unsafe {
            ControlTraceW(
                null_handle,
                pname,
                props_ptr(&mut props),
                EVENT_TRACE_CONTROL_STOP,
            )
        };

        let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
        let rc = unsafe { StartTraceW(&mut handle, pname, props_ptr(&mut props)) };
        if rc != ERROR_SUCCESS {
            return Err(EtwError::StartTrace {
                code: rc.0,
                hint: hint(rc.0),
            });
        }

        let mut reports = Vec::with_capacity(cfg.providers.len());
        for spec in &cfg.providers {
            let rc = unsafe {
                EnableTraceEx2(
                    handle,
                    &spec.guid,
                    EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                    spec.level,
                    spec.keywords,
                    0,
                    0,
                    None,
                )
            };
            reports.push(EnableReport {
                name: spec.name,
                result: if rc == ERROR_SUCCESS {
                    Ok(())
                } else {
                    Err(rc.0)
                },
            });
        }

        let session = Self::consume(cfg, name, props, true)?;
        Ok((session, reports))
    }

    /// Attach to a session that is already running.
    pub fn attach(cfg: SessionConfig) -> Result<Self, EtwError> {
        if cfg.name.is_empty() {
            return Err(EtwError::EmptySessionName);
        }
        if cfg.capacity == 0 {
            return Err(EtwError::InvalidChannelCapacity);
        }

        let state = session_state(&cfg.name)?.ok_or_else(|| EtwError::NoSuchSession {
            name: cfg.name.clone(),
        })?;
        if !state.real_time {
            return Err(EtwError::NotRealTime {
                name: cfg.name.clone(),
                mode: state.log_file_mode,
            });
        }

        let name: Vec<u16> = cfg.name.encode_utf16().chain(std::iter::once(0)).collect();
        let props = build_props(&name, cfg.buffers);
        Self::consume(cfg, name, props, false)
    }

    /// The consumer half, shared by `start` and `attach`.
    fn consume(
        cfg: SessionConfig,
        name: Vec<u16>,
        props: Box<[u8]>,
        owns: bool,
    ) -> Result<Self, EtwError> {
        let providers = cfg
            .providers
            .iter()
            .map(|s| (s.guid, model::ProviderId::new(s.name)))
            .collect();

        let (tx, rx) = bounded(cfg.capacity);
        let ctx = Arc::new(CallbackContext {
            tx,
            stats: crate::stats::Stats::default(),
            providers,
            max_level: cfg.max_level,
        });

        let mut logfile = Box::new(EVENT_TRACE_LOGFILEW::default());
        logfile.LoggerName = PWSTR(name.as_ptr() as *mut u16);
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(on_event);
        logfile.Context = Arc::as_ptr(&ctx) as *mut core::ffi::c_void;

        let consumer = unsafe { OpenTraceW(&mut *logfile) };
        if consumer.Value == u64::MAX {
            if owns {
                let _ = unsafe {
                    ControlTraceW(
                        CONTROLTRACE_HANDLE { Value: 0 },
                        PCWSTR(name.as_ptr()),
                        props.as_ptr() as *mut EVENT_TRACE_PROPERTIES,
                        EVENT_TRACE_CONTROL_STOP,
                    )
                };
            }
            return Err(EtwError::OpenTrace);
        }

        let thread = match thread::Builder::new()
            .name("etw-consumer".into())
            .spawn(move || {
                let _ = unsafe { ProcessTrace(&[consumer], None, None) };
            }) {
            Ok(t) => t,
            Err(e) => {
                let _ = unsafe { CloseTrace(consumer) };
                if owns {
                    let _ = unsafe {
                        ControlTraceW(
                            CONTROLTRACE_HANDLE { Value: 0 },
                            PCWSTR(name.as_ptr()),
                            props.as_ptr() as *mut EVENT_TRACE_PROPERTIES,
                            EVENT_TRACE_CONTROL_STOP,
                        )
                    };
                }
                return Err(EtwError::Spawn(e.to_string()));
            }
        };

        Ok(Self {
            display_name: cfg.name,
            name,
            props,
            logfile: LogFile(logfile),
            consumer,
            ctx,
            rx,
            thread: Some(thread),
            lost: (0, 0),
            owns,
        })
    }

    /// Pull up to `max` events, waiting no longer than `timeout` for the first.
    pub fn drain(&mut self, out: &mut Vec<EtwRaw>, max: usize, timeout: Duration) -> usize {
        let mut count = 0;

        match self.rx.recv_timeout(timeout) {
            Ok(item) => {
                out.push(item);
                count += 1;
            }
            Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => return 0,
        }

        while count < max {
            match self.rx.try_recv() {
                Ok(item) => {
                    out.push(item);
                    count += 1;
                }
                Err(_) => break,
            }
        }
        count
    }

    pub fn stats(&self) -> StatsSnapshot {
        self.ctx.stats.snapshot()
    }

    /// Kernel-reported losses.
    pub fn kernel_lost(&self) -> (u32, u32) {
        self.lost
    }

    /// Stop consuming, release the session, and collect the final loss counts.
    pub fn shutdown(&mut self) -> Result<(), EtwError> {
        let _ = unsafe { CloseTrace(self.consumer) };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }

        let pname = PCWSTR(self.name.as_ptr());
        let null_handle = CONTROLTRACE_HANDLE { Value: 0 };

        let rc = unsafe {
            ControlTraceW(
                null_handle,
                pname,
                props_ptr(&mut self.props),
                EVENT_TRACE_CONTROL_QUERY,
            )
        };
        if rc == ERROR_SUCCESS {
            let p = props_ptr(&mut self.props);
            self.lost = unsafe { ((*p).EventsLost, (*p).RealTimeBuffersLost) };
        }

        let rc = unsafe {
            ControlTraceW(
                null_handle,
                pname,
                props_ptr(&mut self.props),
                EVENT_TRACE_CONTROL_STOP,
            )
        };
        if self.owns && rc != ERROR_SUCCESS {
            return Err(EtwError::ControlTrace(rc.0));
        }

        Ok(())
    }
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        if self.thread.is_some() {
            let _ = self.shutdown();
        }
    }
}

impl EventSource for EtwSession {
    fn next_batch(
        &mut self,
        out: &mut Vec<RawEvent>,
        max: usize,
        timeout: Duration,
    ) -> Result<usize, SourceError> {
        let mut batch = Vec::new();
        let n = self.drain(&mut batch, max, timeout);
        out.extend(batch.into_iter().map(|e| e.wire));
        Ok(n)
    }

    fn dropped_count(&self) -> u64 {
        let snap = self.stats();
        snap.lost() + u64::from(self.lost.0) + u64::from(self.lost.1)
    }

    fn name(&self) -> &str {
        &self.display_name
    }

    fn stop(&mut self) -> Result<(), SourceError> {
        self.shutdown()
            .map_err(|e| SourceError::Unavailable(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABSENT: &str = "chaos-no-such-session-9f3c1a";

    #[test]
    fn an_absent_session_is_reported_as_absent_and_not_as_a_failure() {
        match session_state(ABSENT) {
            Ok(None) => {}
            Ok(Some(state)) => panic!("a session that does not exist reported state: {state:?}"),
            Err(e) => panic!("asking about an absent session was refused: {e}"),
        }
    }

    #[test]
    fn is_running_never_turns_a_refusal_into_a_quiet_no() {
        assert_eq!(is_running(ABSENT).expect("query is permitted"), false);
    }

    #[test]
    fn an_empty_session_name_is_rejected_before_any_syscall() {
        assert!(matches!(session_state(""), Err(EtwError::EmptySessionName)));
        assert!(matches!(is_running(""), Err(EtwError::EmptySessionName)));
    }

    #[test]
    fn the_buffer_defaults_are_a_size_and_not_a_wish() {
        let b = Buffers::default();
        assert_eq!(b.size_kb, 128);
        assert_eq!(b.minimum, 16);
        assert_eq!(b.maximum, 64);
        assert_eq!(b.flush_seconds, 1);
    }

    #[test]
    fn the_log_file_mode_includes_independent_and_persist() {
        // The critical pairing. `INDEPENDENT` alone is silently stripped by the
        // kernel; `PERSIST_ON_HYBRID_SHUTDOWN` is what makes it stick.
        // Verified against the reported observed behavior: without both, the
        // kernel applies `0x00000100` and the session silently drops events
        // on high-EPS providers with no counter increment.
        assert_eq!(
            LOG_FILE_MODE & EVENT_TRACE_REAL_TIME_MODE,
            EVENT_TRACE_REAL_TIME_MODE,
            "REAL_TIME is required for live consumption"
        );
        assert_eq!(
            LOG_FILE_MODE & EVENT_TRACE_INDEPENDENT_SESSION_MODE,
            EVENT_TRACE_INDEPENDENT_SESSION_MODE,
            "INDEPENDENT is required to isolate the buffer pool"
        );
        assert_eq!(
            LOG_FILE_MODE & EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN,
            EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN,
            "PERSIST is required for INDEPENDENT to be honored"
        );
    }

    #[test]
    fn a_ceiling_below_the_floor_is_corrected_rather_than_written() {
        let name = wide("chaos-test");
        let buffers = Buffers {
            size_kb: 64,
            minimum: 32,
            maximum: 8,
            flush_seconds: 0,
        };
        let props = build_props(&name, buffers);
        let p = props_ptr(&mut { props });
        unsafe {
            assert_eq!((*p).MaximumBuffers, 32, "raised to the floor");
            assert_eq!((*p).MinimumBuffers, 32);
            assert_eq!((*p).FlushTimer, 1, "zero would never flush");
            assert_eq!((*p).BufferSize, 64);
            assert_eq!((*p).LogFileMode, LOG_FILE_MODE);
        }
    }

    #[test]
    fn the_logger_name_is_written_into_the_properties_tail() {
        let name = wide("chaos-test-session");
        let props = build_props(&name, Buffers::default());
        assert_eq!(
            props.len(),
            size_of::<EVENT_TRACE_PROPERTIES>() + name.len() * size_of::<u16>()
        );

        let p = props_ptr(&mut { props });
        let (recovered, terminator) = unsafe {
            let tail = (p as *const u8).add((*p).LoggerNameOffset as usize) as *const u16;
            let mut units = Vec::new();
            for i in 0..name.len() {
                units.push(tail.add(i).read_unaligned());
            }
            let terminator = units.last().copied();
            let text: Vec<u16> = units.into_iter().take_while(|u| *u != 0).collect();
            (String::from_utf16(&text).expect("valid UTF-16"), terminator)
        };
        assert_eq!(recovered, "chaos-test-session");
        assert_eq!(terminator, Some(0), "the tail must end in a terminated name");
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }
}
