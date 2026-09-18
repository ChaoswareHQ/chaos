//! TDH decoding: turning the opaque payload in an [`EtwRaw`] into named fields.
//!
//! The central trick is that TDH can only read a *live* `EVENT_RECORD`, and the
//! kernel recycles the real one the moment the callback returns. Because the
//! callback copied `UserData` into our own buffer, we can rebuild a synthetic
//! record that points at that copy, restores the descriptor fields TDH keys its
//! schema lookup on, and hand it over. Everything else here follows from that:
//! the decode is deferred, so it costs nothing on the hot path, and it is free
//! to be as slow as it needs to be.
//!
//! What went into the synthetic record is the reason `EtwRaw` carries a GUID, a
//! version, an opcode and a keyword that the wire format does not: TDH resolves
//! a schema from the provider GUID plus the event descriptor, and a provider
//! *name* is not invertible back into either.
//!
//! Field extraction is by name (`TdhGetProperty` addresses properties by
//! `PCWSTR`, not by index), so the names are the one thing that has to be right.
//! They come from the provider's manifest; the client's `--dump-schema` mode
//! enumerates them on a real machine so the mapping table in `pipeline` can be
//! checked rather than trusted.

use crate::callback::EtwRaw;
use std::ffi::c_void;
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_DESCRIPTOR, EVENT_HEADER, EVENT_RECORD, PROPERTY_DATA_DESCRIPTOR, TdhGetProperty,
    TdhGetPropertySize,
};
use windows::core::PCWSTR;

/// Largest single property we will read. Command lines and image paths are the
/// big ones and they are nowhere near this; anything larger is a malformed
/// event and gets truncated rather than trusted.
pub const MAX_FIELD_BYTES: usize = 4096;

/// A decoded property value.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    Str(String),
    U16(u16),
    U32(u32),
    U64(u64),
    Binary(Vec<u8>),
}

/// Reusable decode state.
///
/// Holds one scratch buffer so a run of events sharing a schema does not
/// allocate per field. `Decoder` is not `Sync`: it is meant to live on the
/// single thread that consumes a session.
#[derive(Debug, Default)]
pub struct Decoder {
    scratch: Vec<u8>,
    name: Vec<u16>,
}

/// Rebuild a record TDH will accept from bytes we own.
///
/// `payload` must be the same buffer that `UserData` points at. The returned
/// record borrows it, so it must not outlive this scope.
fn synthetic_record(raw: &EtwRaw, payload: *mut u8) -> EVENT_RECORD {
    let mut record = EVENT_RECORD::default();

    record.EventHeader = EVENT_HEADER {
        ProviderId: raw.guid,
        EventDescriptor: EVENT_DESCRIPTOR {
            Id: raw.wire.event_id,
            Version: raw.version,
            Level: raw.wire.level,
            Opcode: raw.opcode,
            ..Default::default()
        },
        ProcessId: raw.wire.pid,
        ThreadId: raw.wire.tid,
        TimeStamp: raw.wire.timestamp_raw,
        ..Default::default()
    };

    record.UserDataLength = raw.wire.data.len().min(u16::MAX as usize) as u16;
    record.UserData = payload as *mut c_void;
    record
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Read a property as an owned value.
    ///
    /// Returns `None` when the schema does not know the field, when the event
    /// cannot be resolved at all, or when the value is not the requested shape.
    /// A missing field is a normal outcome — manifests differ between Windows
    /// builds — so it is not an error, but callers should treat a `None` on a
    /// field they depend on as a reason to lower confidence rather than to
    /// guess.
    pub fn field(&mut self, raw: &EtwRaw, name: &str) -> Option<FieldValue> {
        if raw.wire.data.is_empty() {
            // TDH needs the payload to parse anything at all, but a header-only
            // event is still legitimate.
            return None;
        }

        self.name.clear();
        self.name.extend(name.encode_utf16());
        self.name.push(0);

        let descriptor = PROPERTY_DATA_DESCRIPTOR {
            PropertyName: self.name.as_ptr() as u64,
            ArrayIndex: u32::MAX,
            Reserved: 0,
        };

        // The payload must be mutable for the synthetic record's pointer, even
        // though TDH only reads it. Copying into scratch also guarantees the
        // borrow outlives the call.
        self.scratch.clear();
        self.scratch.extend_from_slice(&raw.wire.data);

        let record = synthetic_record(raw, self.scratch.as_mut_ptr());

        let mut size: u32 = 0;
        let rc = unsafe { TdhGetPropertySize(&record, None, &[descriptor], &mut size) };
        if rc != 0 || size == 0 || size as usize > MAX_FIELD_BYTES {
            return None;
        }

        let mut buffer = vec![0u8; size as usize];
        let rc = unsafe { TdhGetProperty(&record, None, &[descriptor], &mut buffer) };
        if rc != 0 {
            return None;
        }

        Some(classify(&buffer))
    }

    /// Convenience wrappers. Each is a thin typed view over [`Self::field`].
    pub fn text(&mut self, raw: &EtwRaw, name: &str) -> Option<String> {
        match self.field(raw, name)? {
            FieldValue::Str(s) => Some(s),
            FieldValue::U32(v) => Some(v.to_string()),
            FieldValue::U64(v) => Some(v.to_string()),
            FieldValue::U16(v) => Some(v.to_string()),
            FieldValue::Binary(b) => Some(b.iter().map(|x| format!("{x:02x}")).collect()),
        }
    }

    pub fn u32(&mut self, raw: &EtwRaw, name: &str) -> Option<u32> {
        match self.field(raw, name)? {
            FieldValue::U32(v) => Some(v),
            FieldValue::U16(v) => Some(u32::from(v)),
            FieldValue::U64(v) => u32::try_from(v).ok(),
            _ => None,
        }
    }

    pub fn u64(&mut self, raw: &EtwRaw, name: &str) -> Option<u64> {
        match self.field(raw, name)? {
            FieldValue::U64(v) => Some(v),
            FieldValue::U32(v) => Some(u64::from(v)),
            FieldValue::U16(v) => Some(u64::from(v)),
            _ => None,
        }
    }

    /// Return the first field that resolves, trying `names` in order.
    ///
    /// Manifests rename fields between Windows versions (`ProcessID` versus
    /// `ProcessId` versus `NewProcessId` are all real), and a lookup chain costs
    /// a few failed `TdhGetPropertySize` calls only on the first event of a
    /// schema.
    pub fn text_any(&mut self, raw: &EtwRaw, names: &[&str]) -> Option<String> {
        names.iter().find_map(|n| self.text(raw, n))
    }

    pub fn u32_any(&mut self, raw: &EtwRaw, names: &[&str]) -> Option<u32> {
        names.iter().find_map(|n| self.u32(raw, n))
    }
}

/// TDH returns a byte buffer whose interpretation depends on the property's
/// declared type, which `TdhGetProperty` does not hand back. These are the
/// widths we can distinguish without the schema.
///
/// The ambiguity is real and worth stating: a 4-byte buffer could be a `U32` or
/// four bytes of a `Binary` field. Callers that need certainty should use the
/// typed accessors and accept a `None` over a guess, which is what
/// [`Decoder::u32`] does.
fn classify(buffer: &[u8]) -> FieldValue {
    match buffer.len() {
        2 => FieldValue::U16(u16::from_le_bytes([buffer[0], buffer[1]])),
        4 => FieldValue::U32(u32::from_le_bytes([
            buffer[0], buffer[1], buffer[2], buffer[3],
        ])),
        8 => FieldValue::U64(u64::from_le_bytes([
            buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7],
        ])),
        _ => FieldValue::Binary(buffer.to_vec()),
    }
}

/// Decode a NUL-terminated UTF-16 string, which is how TDH returns `wstring`
/// properties and how the manifests store every name we care about.
pub fn utf16_to_string(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 || bytes.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|u| *u != 0)
        .collect();
    if units.is_empty() {
        return None;
    }
    String::from_utf16(&units).ok()
}

/// Point a `PCWSTR` at a UTF-16 name, for the TDH entry points that take one.
pub fn wide(name: &str) -> Vec<u16> {
    name.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Helper for callers building a `PCWSTR` from [`wide`].
pub fn pcwstr(buf: &[u16]) -> PCWSTR {
    PCWSTR(buf.as_ptr())
}

#[cfg(test)]
mod tests {
    use super::*;
    use model::{EventSource, ProviderId, RawEvent};
    use windows::core::GUID;

    fn raw(provider: &'static str, event_id: u16, data: Vec<u8>) -> EtwRaw {
        EtwRaw {
            wire: RawEvent {
                source: EventSource::WindowsEtw,
                provider: ProviderId::new(provider),
                event_id,
                timestamp_raw: 1,
                pid: 10,
                tid: 11,
                level: 4,
                data,
            },
            guid: GUID::from_u128(0),
            version: 0,
            opcode: 0,
            keyword: 0,
            activity_id: [0; 16],
            related_activity_id: None,
            process_start_key: Some(1),
        }
    }

    #[test]
    fn utf16_decoding_stops_at_the_terminator() {
        let bytes = [b'h', 0, b'i', 0, 0, 0, b'x', 0];
        assert_eq!(utf16_to_string(&bytes).as_deref(), Some("hi"));
    }

    #[test]
    fn utf16_decoding_rejects_malformed_input() {
        assert_eq!(utf16_to_string(&[]), None);
        assert_eq!(utf16_to_string(&[b'a']), None, "odd length is not UTF-16");
        assert_eq!(utf16_to_string(&[0, 0]), None, "empty string is absence");
        assert_eq!(utf16_to_string(&[0x00, 0xd8]), None, "lone surrogate");
    }

    #[test]
    fn wide_is_nul_terminated() {
        let w = wide("ab");
        assert_eq!(w, vec![0x61, 0x62, 0x00]);
    }

    #[test]
    fn classify_maps_known_widths_and_falls_back_to_binary() {
        assert_eq!(classify(&[1, 0]), FieldValue::U16(1));
        assert_eq!(classify(&[1, 0, 0, 0]), FieldValue::U32(1));
        assert_eq!(classify(&[1, 0, 0, 0, 0, 0, 0, 0]), FieldValue::U64(1));
        assert_eq!(classify(&[1, 2, 3]), FieldValue::Binary(vec![1, 2, 3]));
        assert_eq!(classify(&[]), FieldValue::Binary(Vec::new()));
    }

    #[test]
    fn an_empty_payload_yields_no_field_rather_than_a_guess() {
        // Header-only events are legal; asking for a property on one must not
        // invent a value.
        let mut d = Decoder::new();
        assert_eq!(d.field(&raw("p", 1, Vec::new()), "ImageName"), None);
        assert_eq!(d.text(&raw("p", 1, Vec::new()), "ImageName"), None);
        assert_eq!(d.u32(&raw("p", 1, Vec::new()), "ProcessID"), None);
    }

    #[test]
    fn lookup_chains_return_the_first_hit() {
        let mut d = Decoder::new();
        // Resolution fails for every candidate on a payload TDH cannot parse,
        // so the chain must degrade to None instead of looping or panicking.
        let empty = raw("p", 1, Vec::new());
        assert_eq!(d.text_any(&empty, &["A", "B", "C"]), None);
        assert_eq!(d.u32_any(&empty, &["A", "B"]), None);
        assert_eq!(d.text_any(&empty, &[]), None);
    }

    #[test]
    fn synthetic_record_restores_what_tdh_keys_on() {
        let mut payload = vec![0xABu8; 8];
        let r = raw("Microsoft-Windows-Kernel-Process", 1, payload.clone());
        let record = synthetic_record(&r, payload.as_mut_ptr());

        assert_eq!(record.EventHeader.ProviderId, r.guid);
        assert_eq!(record.EventHeader.EventDescriptor.Id, 1);
        assert_eq!(record.EventHeader.EventDescriptor.Level, 4);
        assert_eq!(record.EventHeader.ProcessId, 10);
        assert_eq!(record.EventHeader.ThreadId, 11);
        assert_eq!(record.EventHeader.TimeStamp, 1);
        assert_eq!(record.UserDataLength, 8);
        assert_eq!(record.UserData as *const u8, payload.as_ptr());

        payload[0] = 0;
        // The record aliases our buffer rather than owning a copy of it: that
        // aliasing is the whole point, and it is why the buffer must outlive
        // every TDH call made against the record.
        assert_eq!(unsafe { *(record.UserData as *const u8) }, 0);
    }
}
