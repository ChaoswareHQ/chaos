//! The ETW callback: the hottest code in the product.
//!
//! Everything here runs on the consumer thread, once per event, with the whole
//! session waiting on it. Two rules follow, and both are load-bearing:
//!
//! * **Never block.** A callback that waits on a full channel stalls
//!   `ProcessTrace`, and the kernel responds by dropping events in bulk. Losing
//!   one event to `try_send` is strictly cheaper than losing the buffer.
//! * **Never panic.** Unwinding out of an `extern "system"` frame aborts the
//!   process. Every operation below is total: checked lengths, saturating
//!   arithmetic, no indexing that can go out of range.
//!
//! The callback does exactly one piece of real work: copy `UserData`. That
//! pointer is only valid for the duration of the call, and the *copy* is what
//! makes deferred decoding possible at all — TDH can rebuild a synthetic
//! `EVENT_RECORD` over our own buffer later, but it can never survive the
//! kernel recycling the original.
//!
//! # Legacy formats the callback filters before the decoder sees them
//!
//! Three event-header flags mark formats that TDH cannot decode:
//!
//! * `EVENT_HEADER_FLAG_CLASSIC_HEADER` (`0x0001`) — a pre-manifest event whose
//!   descriptor is a legacy `EVENT_CLASSIC_HEADER` rather than an
//!   `EVENT_DESCRIPTOR`. Counted as `classic`.
//! * `EVENT_HEADER_FLAG_STRING_ONLY` (`0x0004`) — the event data is a bare
//!   null-terminated Unicode string with no properties. TDH has no field names
//!   to resolve, so an event like this counted as `undecodable` would be a
//!   false positive in the failure counter. Counted as `string_only`.
//! * `EVENT_HEADER_FLAG_TRACE_MESSAGE` (`0x0008`) — the provider used the WPP
//!   trace-message function rather than a manifest. Also no named properties.
//!   Counted as `trace_message`.
//!
//! Before this filter, the two legacy formats silently inflated `undecodable`
//! on any host that still runs WPP providers — which is most of them.

use crate::stats::Stats;
use crossbeam_channel::Sender;
use model::{EventSource, ProviderId, RawEvent};
use std::slice;
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY, EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID,
    EVENT_HEADER_FLAG_CLASSIC_HEADER, EVENT_HEADER_FLAG_STRING_ONLY,
    EVENT_HEADER_FLAG_TRACE_MESSAGE, EVENT_RECORD,
};
use windows::core::GUID;

/// `EVENT_HEADER_FLAG_STRING_ONLY` from `evntcons.h`.
///
/// The windows-rs binding declares these flags as `u32` while the header
/// field is `u16`. The alias is `u32` and the header field is widened at
/// the read site, so the two sides of the comparison are the same width
/// without a second cast.
const FLAG_STRING_ONLY: u32 = EVENT_HEADER_FLAG_STRING_ONLY;

/// `EVENT_HEADER_FLAG_TRACE_MESSAGE` from `evntcons.h`.
const FLAG_TRACE_MESSAGE: u32 = EVENT_HEADER_FLAG_TRACE_MESSAGE;

/// `EVENT_HEADER_FLAG_32_BIT_HEADER` from `evntcons.h`.
///
/// Not exposed as a named constant in this version of windows-rs. The value
/// is stable: the event was logged by a 32-bit process (including a WOW64
/// process on a 64-bit host).
const FLAG_32_BIT_HEADER: u32 = 0x0020;

/// An ETW event, paired with the routing detail the wire format deliberately
/// does not carry.
#[derive(Debug, Clone)]
pub struct EtwRaw {
    pub wire: RawEvent,
    pub guid: GUID,
    pub version: u8,
    pub opcode: u8,
    pub keyword: u64,
    /// ETW's own correlation identifier. The kernel already computed a causal
    /// graph here; A4 gets to start from it rather than reconstructing one.
    pub activity_id: [u8; 16],
    pub related_activity_id: Option<[u8; 16]>,
    /// A kernel-generated process identity that survives PID reuse.
    pub process_start_key: Option<u64>,
    /// Whether the provider was 32-bit or a WOW64 process.
    ///
    /// From `EVENT_HEADER_FLAG_32_BIT_HEADER`. The header's ProcessId is
    /// always a 32-bit PID; this flag is what distinguishes a native 64-bit
    /// process from a WOW64 one that happens to share the PID space.
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
pub(crate) struct CallbackContext {
    pub(crate) tx: Sender<EtwRaw>,
    pub(crate) stats: Stats,
    pub(crate) providers: Vec<(GUID, ProviderId)>,
    pub(crate) max_level: u8,
}

/// The callback itself.
///
/// # Safety
/// Called by ETW with a valid `EVENT_RECORD` whose `UserContext` is the
/// `Arc<CallbackContext>` kept alive by `EtwSession`.
pub(crate) unsafe extern "system" fn on_event(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let ctx = unsafe { (*record).UserContext as *const CallbackContext };
    if ctx.is_null() {
        return;
    }
    let (rec, ctx) = (unsafe { &*record }, unsafe { &*ctx });
    let header = &rec.EventHeader;

    // The SDK declares the flag constants as `u32` while the header field is
    // `u16`. Widening once here means every subsequent comparison is against
    // `u32` and the width mismatch lives in exactly one place.
    let flags = u32::from(header.Flags);

    // Classic header: pre-manifest, cannot be decoded.
    if flags & EVENT_HEADER_FLAG_CLASSIC_HEADER != 0 {
        ctx.stats.classic();
        return;
    }

    // String-only: bare Unicode string, no properties. Previously fell
    // through to the decoder and inflated `undecodable`.
    if flags & FLAG_STRING_ONLY != 0 {
        ctx.stats.string_only();
        return;
    }

    // Trace message: WPP output, no properties. Same as above.
    if flags & FLAG_TRACE_MESSAGE != 0 {
        ctx.stats.trace_message();
        return;
    }

    let descriptor = &header.EventDescriptor;
    if descriptor.Level > ctx.max_level {
        ctx.stats.filtered();
        return;
    }

    let provider = match ctx
        .providers
        .iter()
        .find(|(guid, _)| *guid == header.ProviderId)
    {
        Some((_, name)) => name.clone(),
        None => ProviderId::new(crate::autologger::format_guid(&header.ProviderId)),
    };

    let len = (rec.UserDataLength as usize).min(model::MAX_PAYLOAD_SIZE);
    let data = if len == 0 || rec.UserData.is_null() {
        Vec::new()
    } else {
        unsafe { slice::from_raw_parts(rec.UserData as *const u8, len) }.to_vec()
    };

    let (related_activity_id, process_start_key) = unsafe { extended_data(rec) };

    let is_wow64 = flags & FLAG_32_BIT_HEADER != 0;

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
        is_wow64,
    };

    ctx.stats.received(raw.wire.data.len());
    match ctx.tx.try_send(raw) {
        Ok(()) => ctx.stats.delivered(),
        Err(_) => ctx.stats.dropped(),
    }
}

/// Pull the two extended items worth the walk: the causal parent, and the
/// process start key.
unsafe fn extended_data(rec: &EVENT_RECORD) -> (Option<[u8; 16]>, Option<u64>) {
    let mut related = None;
    let mut start_key = None;

    if rec.ExtendedData.is_null() || rec.ExtendedDataCount == 0 {
        return (related, start_key);
    }

    let items = unsafe { slice::from_raw_parts(rec.ExtendedData, rec.ExtendedDataCount as usize) };

    for item in items {
        if item.DataPtr == 0 {
            continue;
        }
        match u32::from(item.ExtType) {
            EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID if item.DataSize >= 16 => {
                let mut buf = [0u8; 16];
                unsafe {
                    std::ptr::copy_nonoverlapping(item.DataPtr as *const u8, buf.as_mut_ptr(), 16)
                };
                related = Some(buf);
            }
            EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY if item.DataSize >= 8 => {
                let mut buf = [0u8; 8];
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

/// GUID as raw bytes, for the causal identifiers we keep opaquely.
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
    use windows::core::GUID;

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
}
