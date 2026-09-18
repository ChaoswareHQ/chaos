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
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE,
    ProcessTrace, StartTraceW, WNODE_FLAG_TRACED_GUID,
};
use windows::core::{GUID, PCWSTR, PWSTR};

/// One provider to enable.
#[derive(Debug, Clone, Copy)]
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
    /// Kernel buffer size in KB.
    pub buffer_kb: u32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            capacity: 64 * 1024,
            providers: Vec::new(),
            max_level: 5,
            buffer_kb: 128,
        }
    }
}

/// Outcome of enabling one provider.
///
/// Partial success is the normal case: a deployment usually lacks the privilege
/// for at least one kernel provider, and the right response is to run with what
/// it was granted and say so, not to abort the sensor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnableReport {
    pub name: &'static str,
    pub result: Result<(), u32>,
}

/// Keeps `EVENT_TRACE_LOGFILEW` alive without letting its raw pointers escape.
///
/// The struct is `!Send` by construction because it holds `*mut c_void` and
/// `PWSTR`. Every pointer in ours aims at a buffer this session owns and which
/// lives exactly as long as the session does, and nothing outside the decoder
/// ever dereferences the logfile, so moving the session between threads cannot
/// create a dangling reference or a data race.
#[allow(dead_code)] // held purely for its lifetime, never read after start
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
}

fn props_ptr(buf: &mut [u8]) -> *mut EVENT_TRACE_PROPERTIES {
    buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES
}

/// Build the properties struct and its embedded logger name.
fn build_props(name: &[u16], buffer_kb: u32) -> Box<[u8]> {
    let tail = (name.len() + 1) * size_of::<u16>();
    let total = size_of::<EVENT_TRACE_PROPERTIES>() + tail;
    let mut buf = vec![0u8; total].into_boxed_slice();

    unsafe {
        let p = props_ptr(&mut buf);
        (*p).Wnode.BufferSize = total as u32;
        (*p).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        // 1 = query performance counter ticks: the only timestamp source with
        // enough resolution to order events inside a millisecond.
        (*p).Wnode.ClientContext = 1;
        (*p).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*p).FlushTimer = 1;
        (*p).BufferSize = buffer_kb;
        // Lost buffers are blind spots, and blind spots are what the gap
        // theorem measures, so these are sized deliberately rather than left at
        // the defaults.
        (*p).MinimumBuffers = 16;
        (*p).MaximumBuffers = 64;
        (*p).LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;

        let dst = buf.as_mut_ptr().add(size_of::<EVENT_TRACE_PROPERTIES>()) as *mut u16;
        for (i, unit) in name.iter().chain(std::iter::once(&0u16)).enumerate() {
            dst.add(i).write_unaligned(*unit);
        }
    }

    buf
}

impl EtwSession {
    /// Start the session and its consumer thread.
    ///
    /// Returns the session plus one report per requested provider, so a caller
    /// can tell "running with three of four providers" from "running".
    pub fn start(cfg: SessionConfig) -> Result<(Self, Vec<EnableReport>), EtwError> {
        if cfg.name.is_empty() {
            return Err(EtwError::EmptySessionName);
        }
        if cfg.capacity == 0 {
            return Err(EtwError::InvalidChannelCapacity);
        }

        let name: Vec<u16> = cfg.name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut props = build_props(&name, cfg.buffer_kb);
        let pname = PCWSTR(name.as_ptr());
        let null_handle = CONTROLTRACE_HANDLE { Value: 0 };

        // Reap a session left behind by an earlier crash. "Not found" is the
        // normal case and is not an error worth reporting.
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
        // Writing a union field is safe when its type is `Copy`; only reading one
        // is not. These are all writes, so this block needs no `unsafe`.
        logfile.LoggerName = PWSTR(name.as_ptr() as *mut u16);
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(on_event);
        logfile.Context = Arc::as_ptr(&ctx) as *mut core::ffi::c_void;

        let consumer = unsafe { OpenTraceW(&mut *logfile) };
        if consumer.Value == u64::MAX {
            let _ = unsafe {
                ControlTraceW(
                    null_handle,
                    pname,
                    props_ptr(&mut props),
                    EVENT_TRACE_CONTROL_STOP,
                )
            };
            return Err(EtwError::OpenTrace);
        }

        // The thread gets the handle only. `logfile` stays owned by the session,
        // which outlives the thread because `shutdown` joins it.
        let thread = thread::Builder::new()
            .name("etw-consumer".into())
            .spawn(move || {
                let _ = unsafe { ProcessTrace(&[consumer], None, None) };
            })
            .map_err(|e| EtwError::Spawn(e.to_string()))?;

        Ok((
            Self {
                display_name: cfg.name,
                name,
                props,
                logfile: LogFile(logfile),
                consumer,
                ctx,
                rx,
                thread: Some(thread),
                lost: (0, 0),
            },
            reports,
        ))
    }

    /// Pull up to `max` events, waiting no longer than `timeout` for the first.
    ///
    /// Returns how many were appended. `0` means the session was idle, which is
    /// routine: a quiet host produces bursts, not a steady rate.
    pub fn drain(&mut self, out: &mut Vec<EtwRaw>, max: usize, timeout: Duration) -> usize {
        let mut count = 0;

        match self.rx.recv_timeout(timeout) {
            Ok(item) => {
                out.push(item);
                count += 1;
            }
            Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => return 0,
        }

        // Everything already queued comes along for free: one round trip for a
        // batch instead of one per event.
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

    /// Kernel-reported losses: `(EventsLost, RealTimeBuffersLost)`.
    ///
    /// Distinct from, and worse than, the channel drop counter: these events
    /// never reached the process at all, so nothing downstream can even count
    /// them. Being unable to measure a loss is not the same as not having one.
    pub fn kernel_lost(&self) -> (u32, u32) {
        self.lost
    }

    /// Stop consuming, release the session, and collect the final loss counts.
    pub fn shutdown(&mut self) -> Result<(), EtwError> {
        // CloseTrace is what unblocks ProcessTrace; the join that follows is
        // how we know no callback is still running.
        let _ = unsafe { CloseTrace(self.consumer) };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }

        let pname = PCWSTR(self.name.as_ptr());
        let null_handle = CONTROLTRACE_HANDLE { Value: 0 };

        // Query before stopping: after STOP the counters are gone.
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
        if rc != ERROR_SUCCESS {
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

/// The sensor as the rest of the system sees it: a batch source of wire events.
///
/// The GUID, descriptor and extended data stay behind in this adapter, because
/// the local decoder needs them and the wire format deliberately does not carry
/// them.
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
