//! Real-time ETW session lifecycle.
//!
//! The shape here is forced by the API, and most of the care is about
//! lifetimes:
//!
//! * `EVENT_TRACE_PROPERTIES` and its logger name share one allocation
//!   that must outlive the session, because `ControlTraceW` reads it back
//!   on stop. The logger name is copied into the tail of that same buffer.
//! * `ProcessTrace` blocks, so it owns a thread. `CloseTrace` from another
//!   thread is what makes it return — there is no other way to wake it.
//! * `EVENT_TRACE_LOGFILEW` must stay alive for the whole `ProcessTrace`
//!   call, including the `LoggerName` pointer that reaches back into our
//!   name buffer. It is owned by the session and never moved.
//!
//! Real-time mode means `FlushTimer` is a latency floor, not a tuning
//! knob: a sparse provider's events are delivered on flush rather than on
//! arrival, so one second is the compromise between seeing quiet
//! providers at all and paying per-buffer overhead for nothing.
//!
//! # Why `INDEPENDENT_SESSION_MODE` is mandatory
//!
//! See [`crate::boundary::constants`]. The composition of `LOG_FILE_MODE`
//! is not a tuning choice; without both the `INDEPENDENT` and `PERSIST`
//! bits, the kernel silently drops events with its own loss counters at
//! zero.
//!
//! # Why some providers need `ENABLE_KEYWORD_0`
//!
//! `Microsoft-Windows-Security-Auditing` (and a handful of other system
//! providers) will accept an `EnableTraceEx2` call, report
//! `ERROR_SUCCESS`, register on the session — and then never emit a
//! single event. The provider is not broken and the session is not
//! broken; the enable call simply did not ask for keyword-0 events.
//!
//! `EVENT_ENABLE_PROPERTY_ENABLE_KEYWORD_0` is the property that says
//! "yes, deliver the events whose keyword mask includes bit 0." Without
//! it, a provider whose events carry the keyword-0 flag stays silent for
//! this session. The `ProviderSpec::enable_keyword_zero` flag controls
//! whether the property is set; it defaults to `false` so providers that
//! do not need it pay nothing for the option.

use crate::boundary::callback::{CallbackContext, EtwRaw, on_event};
use crate::boundary::constants::LOG_FILE_MODE;
use crate::boundary::stats::StatsSnapshot;
use crate::error::{EtwError, hint};
use crossbeam_channel::{Receiver, RecvTimeoutError, bounded};
use model::RawEvent;
use ports::{EventSource, SourceError};
use std::mem::size_of;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_PARAMETER, ERROR_MORE_DATA, ERROR_SUCCESS,
    ERROR_WMI_INSTANCE_NOT_FOUND,
};
use windows::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, ENABLE_TRACE_PARAMETERS,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_CONTROL_STOP,
    EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2,
    OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE,
    ProcessTrace, QueryAllTracesW, StartTraceW, WNODE_FLAG_TRACED_GUID,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
use windows::core::{GUID, HRESULT, PCWSTR, PWSTR};

/// `EVENT_ENABLE_PROPERTY_ENABLE_KEYWORD_0` from `evntrace.h`.
///
/// The property that tells the kernel "yes, deliver keyword-0 events to
/// this session." Without it, a provider whose events carry the
/// keyword-0 flag — Security-Auditing among them — registers
/// successfully and stays silent.
///
/// Not exposed as a named constant in this version of windows-rs. The
/// value is stable.
const EVENT_ENABLE_PROPERTY_ENABLE_KEYWORD_0: u32 = 0x40;

/// `ENABLE_TRACE_PARAMETERS_VERSION_2`, the version the parameters
/// struct uses when it carries a filter descriptor.
const ENABLE_TRACE_PARAMETERS_VERSION_2: u32 = 2;

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
    /// Whether to set `EVENT_ENABLE_PROPERTY_ENABLE_KEYWORD_0` in the
    /// `EnableTraceEx2` call.
    ///
    /// Most providers do not care. A few system providers —
    /// `Microsoft-Windows-Security-Auditing` is the one this crate has
    /// hit — will accept the enable call, register on the session, and
    /// then never emit a single event unless this property is set.
    ///
    /// The symptom is subtle: `EnableTraceEx2` returns
    /// `ERROR_SUCCESS`, the run report shows the provider as enabled,
    /// and the shape that reads its events has a `0/0` count. Without
    /// this property the provider is registered but silent.
    ///
    /// Defaults to `false`.
    pub enable_keyword_zero: bool,
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
    /// Bounded channel depth. When it fills, the callback drops rather
    /// than blocks, so this is a real ceiling on burst absorption.
    pub capacity: usize,
    pub providers: Vec<ProviderSpec>,
    /// Events above this level are counted and discarded before any
    /// allocation.
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

/// Keeps `EVENT_TRACE_LOGFILEW` alive without letting its raw pointers
/// escape.
#[allow(dead_code)]
struct LogFile(Box<EVENT_TRACE_LOGFILEW>);

// SAFETY: the pointers inside `EVENT_TRACE_LOGFILEW` point into buffers
// owned by the session (`name`), and the session owns this struct. Moving
// it to the consumer thread moves only the box, not the buffers the
// pointers refer to.
unsafe impl Send for LogFile {}

/// A live real-time session.
pub struct EtwSession {
    display_name: String,
    /// Owned, NUL-terminated, and referenced by `LoggerName` for the whole
    /// run.
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

    // SAFETY: `buf` is a fresh allocation large enough for
    // `EVENT_TRACE_PROPERTIES` plus `units` UTF-16 code units; the
    // arithmetic above computed `total` from exactly those.
    unsafe {
        let p = props_ptr(&mut buf);
        (*p).Wnode.BufferSize = total as u32;
        (*p).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*p).Wnode.ClientContext = 1;
        // The three bits that matter. See `boundary::constants` for why
        // INDEPENDENT alone is not enough.
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
    // SAFETY: `ControlTraceW` with `QUERY` filled `props` in place and
    // returned `ERROR_SUCCESS`, so the fields it reads are valid.
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

/// Stop a running session by name.
///
/// `Ok(false)` means nothing was running under that name, which is an answer
/// rather than a failure: it is what "it is already gone" looks like.
pub fn stop_session(name: &str) -> Result<bool, EtwError> {
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
            EVENT_TRACE_CONTROL_STOP,
        )
    };

    match rc {
        ERROR_SUCCESS => Ok(true),
        ERROR_WMI_INSTANCE_NOT_FOUND => Ok(false),
        other => Err(EtwError::ControlTrace(other.0)),
    }
}

/// The names of every session the kernel is running.
///
/// `QueryAllTracesW` cannot be asked how many sessions exist, so it is handed a
/// fixed array and told how many did not fit. The array grows and the call is
/// retried, which needs a bound: a retry whose stop condition is decided by
/// another process on the machine is a way to spin forever.
pub fn running_sessions() -> Result<Vec<String>, EtwError> {
    let mut capacity = 64usize;
    for _ in 0..4 {
        let mut buffers: Vec<Box<PropertiesBuffer>> =
            (0..capacity).map(|_| Box::new(query_buffer())).collect();
        let mut pointers: Vec<*mut EVENT_TRACE_PROPERTIES> =
            buffers.iter_mut().map(|b| props_ptr(&mut b.0)).collect();
        let mut written = 0u32;

        let rc = unsafe { QueryAllTracesW(pointers.as_mut_slice(), &mut written) };
        if rc == ERROR_MORE_DATA {
            // `written` is now the number of sessions that exist, so the next
            // pass is sized for them. The slack covers sessions that appear
            // while this is running, rather than requiring another pass.
            capacity = (written as usize).saturating_add(8).max(capacity + 1);
            continue;
        }
        if rc != ERROR_SUCCESS {
            return Err(EtwError::ControlTrace(rc.0));
        }

        let found = (written as usize).min(buffers.len());
        return Ok(buffers[..found]
            .iter()
            .filter_map(|buf| logger_name_of(&buf.0))
            .collect());
    }

    Err(EtwError::ControlTrace(ERROR_MORE_DATA.0))
}

/// One session's properties, as `QueryAllTracesW` fills it in.
///
/// Aligned, because the API writes an `EVENT_TRACE_PROPERTIES` into it and is
/// entitled to assume the memory it was handed can hold one. This crate only
/// ever reads a single field of it, byte-wise.
#[repr(align(8))]
struct PropertiesBuffer([u8; Self::BYTES]);

impl PropertiesBuffer {
    /// Windows writes each logger name into the tail of its own buffer and does
    /// not say how long it will be. The sample code for this API uses 1024 bytes
    /// per session, which is far past the longest name a host runs.
    const BYTES: usize = 1024;
}

/// A properties buffer empty except for the two fields `QueryAllTracesW` reads.
///
/// `Wnode.BufferSize` is not decoration. It is how the API knows how much room
/// each buffer has for the logger name it writes into the tail, and a zeroed
/// `EVENT_TRACE_PROPERTIES` does not fail — it returns success and reports *no
/// sessions at all*, which is a machine with forty of them reporting none.
fn query_buffer() -> PropertiesBuffer {
    let mut buffer = PropertiesBuffer([0u8; PropertiesBuffer::BYTES]);
    let p = props_ptr(&mut buffer.0);
    // SAFETY: `buffer` is `BYTES` bytes and `EVENT_TRACE_PROPERTIES` is far
    // smaller than that, so both fields written here are in bounds.
    unsafe {
        (*p).Wnode.BufferSize = PropertiesBuffer::BYTES as u32;
        (*p).LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    }
    buffer
}

/// The logger name the kernel wrote into a session's properties buffer.
///
/// Reads the offset field byte-wise rather than casting the buffer to
/// `EVENT_TRACE_PROPERTIES`: the buffer is a byte array whose alignment is only
/// as good as its type says, and a dereference there is undefined behaviour the
/// compiler is entitled to reject — which it does.
///
/// Reading through `LoggerNameOffset`, which is relative to the start of the
/// buffer, rather than assuming the name sits immediately after the struct, is
/// what makes this work for buffers the kernel filled in and not just for the
/// ones this crate builds.
fn logger_name_of(buf: &[u8]) -> Option<String> {
    const FIELD: usize = std::mem::offset_of!(EVENT_TRACE_PROPERTIES, LoggerNameOffset);

    if buf.len() < size_of::<EVENT_TRACE_PROPERTIES>() {
        return None;
    }
    let offset = u32::from_ne_bytes(buf[FIELD..FIELD + 4].try_into().ok()?) as usize;
    if offset == 0 || offset + 2 > buf.len() {
        return None;
    }

    let mut units = Vec::new();
    for at in (offset..buf.len().saturating_sub(1)).step_by(2) {
        let unit = u16::from_ne_bytes([buf[at], buf[at + 1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    let name = String::from_utf16(&units).ok()?;
    (!name.is_empty()).then_some(name)
}

/// Stop the sessions a previous run of this program left behind.
///
/// A session survives the process that created it: kill an agent and its
/// session stays registered, holding its buffers and one of the finite number
/// of session slots the kernel has. Enough runs of a program that crashes or is
/// interrupted — which is every run during development — and the machine runs
/// out of sessions and every later run fails to start.
///
/// The name is what makes the orphans findable. Every session this crate starts
/// under `prefix` ends in `-<pid>`, so a trailing number naming a process that
/// no longer exists is a run that ended without cleaning up. A live pid is left
/// alone, so a second agent on the same host is never disturbed — the test is
/// deliberately one-sided, because stopping a working sensor is far worse than
/// leaving a dead session behind.
///
pub fn retire_orphaned_sessions(prefix: &str) -> Result<Vec<String>, EtwError> {
    let mut retired = Vec::new();
    for name in running_sessions()? {
        let Some(pid) = orphan_pid(&name, prefix) else {
            continue;
        };
        if process_is_alive(pid) {
            continue;
        }
        if stop_session(&name)? {
            retired.push(name);
        }
    }
    Ok(retired)
}

/// The pid a session name encodes, when the name has this program's shape:
/// `prefix-<pid>`, or `prefix-<something>-<pid>`.
///
/// Strict about the shape so an unrelated session can never be mistaken for one
/// of ours: `prefix` must match, the last `-`-separated field must be all digits
/// and must parse.
fn orphan_pid(name: &str, prefix: &str) -> Option<u32> {
    let rest = name.strip_prefix(prefix)?.strip_prefix('-')?;
    let last = rest.rsplit('-').next().unwrap_or(rest);
    if last.is_empty() || !last.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    last.parse().ok()
}

/// Whether a process is still running.
///
/// `OpenProcess` is the only check available without a handle of our own, and it
/// is the *failure* that carries the answer: `ERROR_INVALID_PARAMETER` is the
/// documented "no such process", while `ERROR_ACCESS_DENIED` means the process
/// exists and belongs to someone else. Only a definite "no such process" counts
/// as gone; everything else, including an error nobody anticipated, errs towards
/// leaving the session alone.
fn process_is_alive(pid: u32) -> bool {
    match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(handle) => {
            // SAFETY: the handle came from `OpenProcess` and is ours to close.
            let _ = unsafe { CloseHandle(handle) };
            true
        }
        Err(e) => e.code() != HRESULT::from_win32(ERROR_INVALID_PARAMETER.0),
    }
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

        // Stop any session that already exists under this name. We do this
        // before `StartTraceW` because `StartTraceW` returns
        // `ERROR_ALREADY_EXISTS` if the name is taken — even if the
        // previous owner is a dead process whose session was never
        // cleanly stopped.
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
            // The enable call itself. Most providers work with the
            // default behavior — no parameter block, "enable everything
            // the keyword mask asks for." Security-Auditing is the
            // notable exception: without `ENABLE_KEYWORD_0` set, the
            // call succeeds and the provider stays silent.
            let params = if spec.enable_keyword_zero {
                Some(ENABLE_TRACE_PARAMETERS {
                    Version: ENABLE_TRACE_PARAMETERS_VERSION_2,
                    EnableProperty: EVENT_ENABLE_PROPERTY_ENABLE_KEYWORD_0,
                    ControlFlags: 0,
                    SourceId: GUID::from_u128(0),
                    EnableFilterDesc: std::ptr::null_mut(),
                    FilterDescCount: 0,
                })
            } else {
                None
            };

            let rc = unsafe {
                EnableTraceEx2(
                    handle,
                    &spec.guid,
                    EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                    spec.level,
                    spec.keywords,
                    0,
                    0,
                    params.as_ref().map(|p| p as *const ENABLE_TRACE_PARAMETERS),
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
            stats: crate::boundary::stats::Stats::default(),
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

    /// Pull up to `max` events, waiting no longer than `timeout` for the
    /// first.
    pub fn drain(&mut self, out: &mut Vec<EtwRaw>, max: usize, timeout: Duration) -> usize {
        self.drain_each(max, timeout, |event| out.push(event))
    }

    /// Pull up to `max` events, waiting no longer than `timeout` for the
    /// first, and hand each one to `f` as it arrives.
    ///
    /// This is [`Self::drain`] without the batch. An `EtwRaw` is 144 bytes
    /// — the payload's `Vec` header, the GUID, both activity ids, the
    /// descriptor fields — and every hop between the kernel and the
    /// decoder moves all of it: into the channel, out of the channel, into
    /// the batch vector, and out of the batch vector again. A consumer that
    /// translates in place makes the last two of those hops disappear, and
    /// on a host producing 200,000 events a second that is 200,000
    /// 144-byte pairs of copies the process does not make.
    ///
    /// `f` runs on the caller's thread and may block: it is not the ETW
    /// callback, which is a different thread with different rules (see
    /// [`crate::boundary::callback`]).
    pub fn drain_each<F>(&mut self, max: usize, timeout: Duration, mut f: F) -> usize
    where
        F: FnMut(EtwRaw),
    {
        let mut count = 0;

        match self.rx.recv_timeout(timeout) {
            Ok(item) => {
                f(item);
                count += 1;
            }
            Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => return 0,
        }

        while count < max {
            match self.rx.try_recv() {
                Ok(item) => {
                    f(item);
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

    /// Stop consuming, release the session, and collect the final loss
    /// counts.
    pub fn shutdown(&mut self) -> Result<(), EtwError> {
        // `CloseTrace` from this thread is what makes the blocked
        // `ProcessTrace` return. There is no other way to wake it.
        let _ = unsafe { CloseTrace(self.consumer) };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }

        let pname = PCWSTR(self.name.as_ptr());
        let null_handle = CONTROLTRACE_HANDLE { Value: 0 };

        // Query first, while the session still exists, so the final loss
        // counts are read before the session is destroyed.
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
            // SAFETY: `QUERY` filled `props`, so these reads are valid.
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
        // If shutdown was not called explicitly, do it now. A session left
        // running under this process's name is a session that a future
        // `start` will refuse to create.
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
        // Straight from the channel into the caller's vector. The obvious
        // shape — drain into a local `Vec<EtwRaw>`, then move each event's
        // `wire` field into `out` — allocates a batch vector per call and
        // moves every event twice.
        Ok(self.drain_each(max, timeout, |event| out.push(event.wire)))
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
    fn a_ceiling_below_the_floor_is_corrected_rather_than_written() {
        let name = wide("chaos-test");
        let buffers = Buffers {
            size_kb: 64,
            minimum: 32,
            maximum: 8,
            flush_seconds: 0,
        };
        let props = build_props(&name, buffers);
        let mut boxed = props;
        let p = props_ptr(&mut boxed);
        // SAFETY: `boxed` is a fresh allocation that `build_props` sized
        // for exactly this struct.
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

        let mut boxed = props;
        let p = props_ptr(&mut boxed);
        // SAFETY: `boxed` was sized by `build_props` for exactly this
        // layout.
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
        assert_eq!(
            terminator,
            Some(0),
            "the tail must end in a terminated name"
        );
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Enumerating sessions needs rights on sessions this process did not
    /// create, so an unelevated run cannot have the answer. Returning `None`
    /// skips; returning an empty list would be a lie, because an empty list
    /// means "there are no orphans" and a refusal means "no answer at all".
    fn sessions_or_none() -> Option<Vec<String>> {
        match running_sessions() {
            Ok(names) => Some(names),
            Err(EtwError::ControlTrace(5)) => None,
            Err(e) => panic!("enumeration failed for a reason that is not access: {e:?}"),
        }
    }

    #[test]
    fn the_logger_name_reader_matches_the_writer() {
        // `logger_name_of` reads through `LoggerNameOffset` so it also works on
        // buffers Windows filled in; this pins it against the one buffer this
        // crate builds, where the offset and the layout are both known.
        let props = build_props(&wide("chaos-reader-test"), Buffers::default());
        assert_eq!(logger_name_of(&props).as_deref(), Some("chaos-reader-test"));
    }

    #[test]
    fn a_buffer_too_short_to_hold_a_name_yields_none_rather_than_a_panic() {
        assert_eq!(logger_name_of(&[]), None);
        assert_eq!(logger_name_of(&[0u8; 4]), None);
    }

    #[test]
    fn only_this_programs_session_names_carry_an_orphan_pid() {
        // The accepted shape.
        assert_eq!(orphan_pid("chaos-12108", "chaos"), Some(12108));
        assert_eq!(orphan_pid("chaos-etw-capture-26592", "chaos"), Some(26592));
        // Everything else, including another product's session, a name with no
        // pid, and a near-miss on the prefix.
        assert_eq!(orphan_pid("NT Kernel Logger", "chaos"), None);
        assert_eq!(orphan_pid("chaos", "chaos"), None);
        assert_eq!(orphan_pid("chaos-", "chaos"), None);
        assert_eq!(orphan_pid("chaos-sensor", "chaos"), None);
        assert_eq!(orphan_pid("chaosx-1234", "chaos"), None);
        assert_eq!(orphan_pid("rechaos-1234", "chaos"), None);
        assert_eq!(orphan_pid("chaos-1234a", "chaos"), None);
        assert_eq!(
            orphan_pid("chaos-99999999999999", "chaos"),
            None,
            "not a pid"
        );
    }

    #[test]
    fn a_live_process_is_alive_and_an_impossible_pid_is_not() {
        // The whole safety of reclamation rests on this: only a definite "no
        // such process" may be treated as gone, or a second agent's session
        // gets stopped underneath it.
        assert!(process_is_alive(std::process::id()));
        assert!(!process_is_alive(0xFFFF_FFFC));
    }

    #[test]
    fn an_unknown_prefix_retires_nothing() {
        // The safety property in one call. A prefix no session on this machine
        // is named with must never stop anything; if this ever returns a name,
        // the shape check matched a session that is not ours.
        match retire_orphaned_sessions("chaos-no-such-agent-9f3c1a") {
            Ok(retired) => assert!(retired.is_empty(), "{retired:?}"),
            Err(EtwError::ControlTrace(5)) => {}
            Err(e) => panic!("{e:?}"),
        }
    }

    #[test]
    fn stopping_an_absent_session_is_an_answer_and_not_a_failure() {
        assert_eq!(stop_session(ABSENT).expect("stop is permitted"), false);
        assert!(matches!(stop_session(""), Err(EtwError::EmptySessionName)));
    }

    #[test]
    fn enumeration_finds_the_sessions_this_machine_is_running() {
        let Some(names) = sessions_or_none() else {
            return;
        };
        // A Windows host runs trace sessions the moment it boots, so an empty
        // answer means the reader failed rather than that the machine is idle.
        // That is not hypothetical: this returned zero sessions for a machine
        // running forty-four of them, because the query buffers were not stamped
        // with `Wnode.BufferSize`.
        assert!(!names.is_empty(), "enumeration found no sessions at all");
        for name in &names {
            assert!(!name.is_empty(), "a session with no name: {names:?}");
            assert!(
                !name.contains('\0'),
                "the reader ran past the terminator: {name:?}"
            );
        }
    }

    #[test]
    fn an_orphan_shaped_session_is_recognised_in_a_real_enumeration() {
        // The join between the shape check and the machine: whatever this host is
        // running, the names the kernel reports must round-trip through the
        // parser, and reclamation must not name a session whose pid is alive.
        //
        // This test stops real sessions. That is deliberate and it is the only
        // way to test the thing that matters — the check is that it stops
        // *nothing but* orphans, and an orphan is by definition a session whose
        // owner died and which nobody will ever stop. It is also why this is
        // worth running: the machine that ran it had thirty-seven leaked
        // sessions on it.
        let Some(names) = sessions_or_none() else {
            return;
        };
        let matched: Vec<&String> = names
            .iter()
            .filter(|name| orphan_pid(name, "chaos").is_some())
            .collect();
        for name in &matched {
            assert!(
                name.starts_with("chaos-"),
                "the parser matched a name outside the prefix: {name}"
            );
        }
        if let Ok(retired) = retire_orphaned_sessions("chaos") {
            for name in &retired {
                let pid = orphan_pid(name, "chaos").expect("a retired name has a pid");
                assert!(!process_is_alive(pid), "retired a live session: {name}");
            }
        }
    }
}
