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

use crate::stats::Stats;
use crossbeam_channel::Sender;
use model::{EventSource, ProviderId, RawEvent};
use std::slice;
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY, EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID,
    EVENT_HEADER_FLAG_CLASSIC_HEADER, EVENT_RECORD,
};
use windows::core::GUID;

/// An ETW event, paired with the routing detail the wire format deliberately
/// does not carry.
///
/// `wire` is what ships to a server: provider *name*, opaque payload, no GUID.
/// The rest exists because local decoding needs it — TDH resolves a schema from
/// the provider GUID plus the descriptor, and a name is not enough to rebuild
/// that. Keeping both means the shipping path and the detection path read the
/// same bytes without either one dictating the other's shape.
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
}

impl EtwRaw {
    /// Stable identity for the process that emitted this event, when the
    /// provider supplies a start key. Without one, a PID is only valid for as
    /// long as nothing recycles it.
    pub fn process_identity(&self) -> ProcessIdentity {
        match self.process_start_key {
            Some(key) => ProcessIdentity {
                pid: self.wire.pid,
                start_key: Some(key),
            },
            None => ProcessIdentity {
                pid: self.wire.pid,
                start_key: None,
            },
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
    /// The enabled providers, as `(guid, name)`.
    ///
    /// A `Vec` scanned linearly rather than a `HashMap`: the list is the four
    /// providers the session was configured with, so four `GUID` comparisons beat
    /// hashing a sixteen-byte key on every event, and there is one less
    /// collection to reason about on the hottest path in the product.
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

    // The SDK declares this flag as `u32` while the header field is `u16`; the
    // cast keeps that width mismatch in one place.
    if u32::from(header.Flags) & EVENT_HEADER_FLAG_CLASSIC_HEADER != 0 {
        ctx.stats.classic();
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
        // Cloning the name is an `Arc` increment, not an allocation.
        Some((_, name)) => name.clone(),
        // A provider we did not ask for still arrives when another session
        // enables it. Paying one format per unknown provider beats dropping
        // evidence we cannot attribute.
        None => ProviderId::new(format!("{:?}", header.ProviderId)),
    };

    let len = (rec.UserDataLength as usize).min(model::MAX_PAYLOAD_SIZE);
    let data = if len == 0 || rec.UserData.is_null() {
        Vec::new()
    } else {
        // The one irreplaceable operation: UserData dies with this call.
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
        // 00112233-4455-6677-8899-aabbccddeeff
        let g = GUID::from_u128(0x0011_2233_4455_6677_8899_aabb_ccdd_eeff);
        let b = guid_bytes(&g);

        assert_eq!(b[0..4], 0x0011_2233u32.to_le_bytes());
        assert_eq!(b[4..6], 0x4455u16.to_le_bytes());
        assert_eq!(b[6..8], 0x6677u16.to_le_bytes());
        assert_eq!(b[8..16], [0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        // The first three fields are little-endian and the trailing eight bytes
        // are not, so this is NOT a little-endian encoding of the 128-bit value.
        // Getting it wrong silently byte-swaps every activity id we keep, which
        // turns A4 correlation into noise.
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
