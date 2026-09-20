//! The ETW callback: the hottest code in the product.
//!
//! # The two rules
//!
//! 1. **Never block.** A callback that waits on a full channel stalls
//!    `ProcessTrace`, and the kernel responds by dropping events in bulk.
//!    Losing one event to `try_send` is strictly cheaper than losing a
//!    buffer.
//! 2. **Never panic.** Unwinding out of an `extern "system"` frame aborts
//!    the process. Every operation below is total: checked lengths,
//!    saturating arithmetic, no indexing that can go out of range.
//!
//! # The recipe
//!
//! 1. Validate the record and its context (one `unsafe` helper).
//! 2. Reject the three formats TDH cannot decode.
//! 3. Reject events above the level ceiling.
//! 4. Copy `UserData` — the only allocation this function makes.
//! 5. Read the two extended items worth the walk.
//! 6. `try_send`, counting a drop if the channel is full.
//!
//! Everything unsafe is in [`prepare`] and [`extended_data`]. The body of
//! the callback itself is safe code operating on references those two
//! helpers produced.

use crate::boundary::constants::*;
use crate::boundary::stats::Stats;
use crossbeam_channel::Sender;
use model::{EventSource, ProviderId, RawEvent};
use std::slice;
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY, EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID,
    EVENT_RECORD,
};
use windows::core::GUID;

/// An ETW event, paired with the routing detail the wire format does not
/// carry.
///
/// `wire` is the part that ships. Everything else is decode-time context:
/// the GUID that TDH keys schemas on, the descriptor fields that select
/// one, the two extended items, and the WOW64 flag.
#[derive(Debug, Clone)]
pub struct EtwRaw {
    pub wire: RawEvent,
    pub guid: GUID,
    pub version: u8,
    pub opcode: u8,
    pub keyword: u64,
    /// ETW's own correlation identifier. The kernel already computed a
    /// causal graph here; downstream analysis starts from it rather than
    /// reconstructing one.
    pub activity_id: [u8; 16],
    pub related_activity_id: Option<[u8; 16]>,
    /// A kernel-generated process identity that survives PID reuse.
    pub process_start_key: Option<u64>,
    /// Whether the provider was a 32-bit image (including WOW64).
    ///
    /// From `EVENT_HEADER_FLAG_32_BIT_HEADER`. The header's `ProcessId` is
    /// always a 32-bit PID; this flag is what distinguishes a native
    /// 64-bit process from a WOW64 one that happens to share the PID
    /// space.
    pub is_wow64: bool,
}

impl EtwRaw {
    /// Stable identity for the process that emitted this event.
    pub fn process_identity(&self) -> ProcessIdentity {
        ProcessIdentity {
            pid: self.wire.pid,
            start_key: self.process_start_key,
        }
    }
}

/// A process reference that is safe to key state on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_key: Option<u64>,
}

/// Shared state the callback reaches through `EVENT_RECORD::UserContext`.
///
/// Installed by [`crate::boundary::session::EtwSession::consume`], which
/// holds the `Arc` for the session's lifetime. The callback borrows it,
/// never owns it.
pub(crate) struct CallbackContext {
    pub(crate) tx: Sender<EtwRaw>,
    pub(crate) stats: Stats,
    /// `(GUID, name)` for every enabled provider. A linear scan is fine:
    /// the list is under a dozen entries and this is the hot path.
    pub(crate) providers: Vec<(GUID, ProviderId)>,
    /// Events above this level are counted and discarded.
    pub(crate) max_level: u8,
}

/// The callback.
///
/// # Safety
///
/// ETW calls this with a valid `EVENT_RECORD` whose `UserContext` is the
/// `Arc<CallbackContext>` kept alive by
/// [`crate::boundary::session::EtwSession`].
pub(crate) unsafe extern "system" fn on_event(record: *mut EVENT_RECORD) {
    // All unsafe is in `prepare`; from here on this is safe code.
    let (rec, ctx) = match unsafe { prepare(record) } {
        Some(pair) => pair,
        None => return,
    };

    let header = &rec.EventHeader;
    let descriptor = &header.EventDescriptor;
    let flags = u32::from(header.Flags);

    // Reject formats TDH cannot decode. Counted, not dropped silently.
    if flags & FLAG_CLASSIC != 0 {
        ctx.stats.classic();
        return;
    }
    if flags & FLAG_STRING_ONLY != 0 {
        ctx.stats.string_only();
        return;
    }
    if flags & FLAG_TRACE_MESSAGE != 0 {
        ctx.stats.trace_message();
        return;
    }

    // Level filter, before any allocation.
    if descriptor.Level > ctx.max_level {
        ctx.stats.filtered();
        return;
    }

    // Provider name: from the enabled list, or the GUID's canonical
    // spelling if the event came from a provider we did not enable.
    let provider = ctx
        .providers
        .iter()
        .find(|(guid, _)| *guid == header.ProviderId)
        .map(|(_, name)| name.clone())
        .unwrap_or_else(|| ProviderId::new(crate::util::format_guid(&header.ProviderId)));

    // The one allocation in the callback. `UserData` is valid only for the
    // duration of this call, so it must be copied before we return.
    let len = (rec.UserDataLength as usize).min(model::MAX_PAYLOAD_SIZE);
    let data = if len == 0 || rec.UserData.is_null() {
        Vec::new()
    } else {
        // SAFETY: `UserData` points at `UserDataLength` bytes valid for
        // the duration of this call. The `min` above bounds it.
        unsafe { slice::from_raw_parts(rec.UserData as *const u8, len) }.to_vec()
    };

    let (related_activity_id, process_start_key) = unsafe { extended_data(rec) };

    let raw = EtwRaw {
        wire: RawEvent {
            source: EventSource::WindowsEtw,
            provider,
            event_id: descriptor.Id,
            timestamp_raw: header.TimeStamp,
            pid: header.ProcessId,
            tid: header.ThreadId,
            level: descriptor.Level,
            data,
        },
        guid: header.ProviderId,
        version: descriptor.Version,
        opcode: descriptor.Opcode,
        keyword: descriptor.Keyword,
        activity_id: guid_bytes(&header.ActivityId),
        related_activity_id,
        process_start_key,
        is_wow64: flags & FLAG_32_BIT_HEADER != 0,
    };

    ctx.stats.received(raw.wire.data.len());
    match ctx.tx.try_send(raw) {
        Ok(()) => ctx.stats.delivered(),
        Err(_) => ctx.stats.dropped(),
    }
}

/// Validate the record and its context, then hand back references with a
/// `'static` lifetime bounded by this scope.
///
/// # Safety
///
/// `record` must either be null or point at a valid `EVENT_RECORD` whose
/// `UserContext` is a `*const CallbackContext` kept alive for the duration
/// of the call.
unsafe fn prepare(
    record: *mut EVENT_RECORD,
) -> Option<(&'static EVENT_RECORD, &'static CallbackContext)> {
    if record.is_null() {
        return None;
    }
    let rec = unsafe { &*record };
    let ctx_ptr = rec.UserContext as *const CallbackContext;
    if ctx_ptr.is_null() {
        return None;
    }
    let ctx = unsafe { &*ctx_ptr };
    // SAFETY: both references outlive this call. `rec` is stack-local to
    // the caller; `ctx` is installed by `EtwSession` and outlives the
    // session. The `transmute` is how we tell the borrow checker that,
    // without lying about either pointer's real lifetime.
    Some((
        unsafe { std::mem::transmute(rec) },
        unsafe { std::mem::transmute(ctx) },
    ))
}

/// Pull the two extended items worth the walk: the causal parent, and the
/// process start key.
///
/// # Safety
///
/// `rec.ExtendedData` must be either null or point at `ExtendedDataCount`
/// valid `EVENT_HEADER_EXTENDED_DATA_ITEM`s.
unsafe fn extended_data(rec: &EVENT_RECORD) -> (Option<[u8; 16]>, Option<u64>) {
    if rec.ExtendedData.is_null() || rec.ExtendedDataCount == 0 {
        return (None, None);
    }
    let items = unsafe { slice::from_raw_parts(rec.ExtendedData, rec.ExtendedDataCount as usize) };
    let mut related = None;
    let mut start_key = None;
    for item in items {
        if item.DataPtr == 0 {
            continue;
        }
        match u32::from(item.ExtType) {
            EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID if item.DataSize >= 16 => {
                let mut buf = [0u8; 16];
                // SAFETY: `DataPtr` is non-null and `DataSize` is at least
                // 16, so the range is valid.
                unsafe {
                    std::ptr::copy_nonoverlapping(item.DataPtr as *const u8, buf.as_mut_ptr(), 16)
                };
                related = Some(buf);
            }
            EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY if item.DataSize >= 8 => {
                let mut buf = [0u8; 8];
                // SAFETY: same as above.
                unsafe {
                    std::ptr::copy_nonoverlapping(item.DataPtr as *const u8, buf.as_mut_ptr(), 8)
                };
                start_key = Some(u64::from_le_bytes(buf));
            }
            _ => {}
        }
    }
    (related, start_key)
}

/// GUID as raw bytes, in the canonical Windows layout.
///
/// `data1`, `data2`, and `data3` are little-endian integers; `data4` is
/// big-endian bytes as stored. This is what the causal identifiers use to
/// stay opaque but stable.
fn guid_bytes(guid: &GUID) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&guid.data1.to_le_bytes());
    out[4..6].copy_from_slice(&guid.data2.to_le_bytes());
    out[6..8].copy_from_slice(&guid.data3.to_le_bytes());
    out[8..16].copy_from_slice(&guid.data4);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_bytes_use_the_canonical_windows_layout() {
        let g = GUID::from_u128(0x0011_2233_4455_6677_8899_aabb_ccdd_eeff);
        let b = guid_bytes(&g);

        assert_eq!(b[0..4], 0x0011_2233u32.to_le_bytes());
        assert_eq!(b[4..6], 0x4455u16.to_le_bytes());
        assert_eq!(b[6..8], 0x6677u16.to_le_bytes());
        assert_eq!(b[8..16], [0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        assert_eq!(
            b,
            [
                0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]
        );
        // The byte order is not the same as a big-endian u128.
        assert_ne!(
            u128::from_le_bytes(b),
            0x0011_2233_4455_6677_8899_aabb_ccdd_eeff
        );
    }

    #[test]
    fn process_identity_distinguishes_reused_pids() {
        let base = EtwRaw {
            wire: RawEvent {
                source: EventSource::WindowsEtw,
                provider: ProviderId::new("p"),
                event_id: 1,
                timestamp_raw: 0,
                pid: 4242,
                tid: 1,
                level: 4,
                data: Vec::new(),
            },
            guid: GUID::from_u128(1),
            version: 0,
            opcode: 0,
            keyword: 0,
            activity_id: [0; 16],
            related_activity_id: None,
            process_start_key: Some(100),
            is_wow64: false,
        };

        let first = base.process_identity();
        let mut recycled = base.clone();
        recycled.process_start_key = Some(200);
        let second = recycled.process_identity();

        assert_eq!(first.pid, second.pid, "same PID...");
        assert_ne!(first, second, "...different process");
        assert_eq!(first.start_key, Some(100));
    }

    #[test]
    fn a_missing_start_key_still_yields_an_identity() {
        let id = ProcessIdentity {
            pid: 7,
            start_key: None,
        };
        assert_eq!(id.pid, 7);
        assert!(id.start_key.is_none());
    }

    #[test]
    fn prepare_rejects_null_records() {
        let result = unsafe { prepare(std::ptr::null_mut()) };
        assert!(result.is_none());
    }
}
