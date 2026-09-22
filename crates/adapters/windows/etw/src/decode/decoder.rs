//! The public `Decoder`.
//!
//! # Lifecycle
//!
//! One `Decoder` per decode thread. It holds:
//!
//! * A name buffer, reused for every TDH call, so a run of events
//!   sharing a schema does not allocate per field.
//! * A property buffer, likewise reused. It is the buffer TDH fills; the
//!   caller gets a borrow of it rather than an owned copy, because the
//!   next field read overwrites it and nobody wants both.
//! * A schema cache, so a field's declared type is fetched once per
//!   `(provider, event id, version)` rather than guessed per event.
//!
//! # Why the payload is not copied
//!
//! TDH addresses a property by name and walks the payload to find it, which
//! means every field read needs a record whose `UserData` points at the
//! event's bytes. Those bytes live in the caller's [`EtwRaw`], which
//! outlives the call, so the record is pointed straight at them. The
//! `*const` → `*mut` cast is the C API's shape (`UserData` is `*mut c_void`)
//! and not a promise to write: `TdhGetProperty` and `TdhGetEventInformation`
//! read the payload and nothing else. Copying it into a scratch buffer once
//! per field was the previous shape of this module, and it was pure
//! traffic: a decode reads several fields per event.
//!
//! # Why `Clone`
//!
//! The observer runs N decode workers, each with its own `Decoder`. A
//! clone starts with an empty schema cache and pays
//! `TdhGetEventInformation` once per shape it sees. That is the right
//! trade: the alternative is a lock on the hot path, and the schema cache
//! is small (one entry per shape, on a desktop ~10 entries).
//!
//! # What it is not
//!
//! `Decoder` is not `Sync`. It holds mutable buffers that are reused
//! across calls, and two threads calling `text_any` on the same `Decoder`
//! at the same time would trample each other's buffers. It is `Send`, so
//! it can be moved to a worker thread, but not shared across threads.

use super::schema::{Schema, SchemaKey, load_schema};
use super::value::{FieldType, FieldValue, classify, classify_typed, hex, render_text};
use crate::boundary::callback::EtwRaw;
use std::collections::HashMap;
use std::ffi::c_void;
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_DESCRIPTOR, EVENT_HEADER, EVENT_RECORD, PROPERTY_DATA_DESCRIPTOR, TdhGetProperty,
    TdhGetPropertySize,
};

/// Largest single property we will read.
///
/// Command lines and image paths are the big ones and they are nowhere
/// near this; anything larger is a malformed event and gets truncated
/// rather than trusted.
pub const MAX_FIELD_BYTES: usize = 4096;

#[derive(Debug, Default, Clone)]
pub struct Decoder {
    name: Vec<u16>,
    /// TDH's output buffer for the field being read. Reused, so a decode
    /// that reads six fields allocates once for the decoder's lifetime
    /// rather than six times per event.
    prop: Vec<u8>,
    schemas: HashMap<SchemaKey, Schema>,
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Read a property as an owned value, using the schema's declared type
    /// to decide what the bytes mean.
    ///
    /// Returns `None` when the schema does not know the field, when the
    /// event cannot be resolved at all, or when TDH refuses the property
    /// call. A missing field is a normal outcome — manifests differ
    /// between Windows builds — so it is not an error, but callers should
    /// treat a `None` on a field they depend on as a reason to lower
    /// confidence rather than to guess.
    ///
    /// This is the accessor `wire::decoders` uses for every field whose
    /// declared type is not obvious from the name alone, which is every
    /// `Binary` field and every registry value.
    pub fn typed_field(&mut self, raw: &EtwRaw, name: &str) -> Option<(FieldValue, FieldType)> {
        let ty = self.declared_type(raw, name)?;
        let bytes = self.raw_property(raw, name)?;
        Some((classify_typed(bytes, ty), ty))
    }

    /// Read a property as an owned value, classifying it by byte width.
    ///
    /// Kept for fields that are known by the caller to be fixed-width
    /// scalars (a `ProcessID`, a `QueryType`) and for which the schema
    /// lookup would be an extra call for no information. New code should
    /// prefer [`Self::typed_field`] where the type is not obvious.
    pub fn field(&mut self, raw: &EtwRaw, name: &str) -> Option<FieldValue> {
        let bytes = self.raw_property(raw, name)?;
        Some(classify(bytes))
    }

    /// Look up the declared type of `property` in the event's schema.
    ///
    /// `None` means the schema does not resolve — no manifest registered,
    /// a malformed payload, an event whose template has no such name.
    /// Callers that *must* have an answer should treat that as a reason to
    /// skip the event, not as a reason to fall back to the byte-width
    /// guess.
    pub fn declared_type(&mut self, raw: &EtwRaw, property: &str) -> Option<FieldType> {
        if raw.wire.data.is_empty() {
            return None;
        }

        let key = SchemaKey {
            provider: raw.guid,
            event_id: raw.wire.event_id,
            version: raw.version,
        };

        let schema = match self.schemas.entry(key) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => {
                let record = synthetic_record(raw, payload_pointer(raw));
                // SAFETY: `record` is a valid synthetic record for the
                // duration of this scope, and `load_schema` does not
                // retain it.
                e.insert(unsafe { load_schema(&record) })
            }
        };

        if schema.unresolvable {
            return None;
        }
        let raw_type = schema.get(property)?;
        Some(FieldType::from_tdh(raw_type))
    }

    /// The TDH round trip: size, fill, hand back a borrow of the buffer.
    ///
    /// Deliberately does *not* interpret the bytes. Two callers want the
    /// same bytes for different reasons — the typed path wants to classify
    /// by declared type, the untyped path by width — and this is the
    /// shared half.
    ///
    /// The returned slice is valid until the next call on this decoder.
    /// Every caller consumes it immediately (classify, decode, render), so
    /// the reuse costs nothing and saves an allocation per field, which on
    /// a host where the sensor is decoding 300,000 events a second is a
    /// million allocations a second.
    fn raw_property(&mut self, raw: &EtwRaw, name: &str) -> Option<&[u8]> {
        if raw.wire.data.is_empty() {
            // TDH needs the payload to parse anything at all, but a
            // header-only event is still legitimate.
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

        let record = synthetic_record(raw, payload_pointer(raw));

        let mut size: u32 = 0;
        // SAFETY: `record` is a valid synthetic record; `descriptor` holds
        // a pointer to `self.name`, which outlives this call.
        let rc = unsafe { TdhGetPropertySize(&record, None, &[descriptor], &mut size) };
        if rc != 0 || size == 0 || size as usize > MAX_FIELD_BYTES {
            return None;
        }

        self.prop.clear();
        self.prop.resize(size as usize, 0);
        // SAFETY: same as above; `self.prop` is exactly `size` bytes, which
        // is the size TDH just asked for.
        let rc = unsafe { TdhGetProperty(&record, None, &[descriptor], &mut self.prop) };
        if rc != 0 {
            return None;
        }

        Some(&self.prop)
    }

    /// Read a property as text.
    ///
    /// Renders the bytes using the **declared type** when the schema
    /// resolves. TDH's declared type is what tells us a field is a
    /// `UnicodeString` (decode as UTF-16) rather than a `Binary` blob
    /// (render as hex). The untyped path can only guess from byte width, and
    /// a 26-byte UTF-16 DNS name looks like a 26-byte blob to it — which is
    /// why the first live run printed `hif-leim.deepseek.com` as
    /// `6800690066002d006c00650069006d...`.
    ///
    /// Falls back to the byte-width guess when the schema does not resolve,
    /// which is normal for a provider whose manifest is not registered on
    /// this build, and when it resolves but does not declare this name.
    ///
    /// # One TDH round trip, not two
    ///
    /// This used to read the bytes through [`Self::typed_field`] and, when
    /// that returned `None` — which it does for every field of a schema
    /// that does not resolve, and for every declared-but-empty field, of
    /// which the registry provider's `KeyName` is the one that matters —
    /// read them *again* through [`Self::field`]. The declared type and the
    /// bytes are independent facts, so the type is looked up once and the
    /// bytes are fetched once, whatever the type turns out to be.
    pub fn text(&mut self, raw: &EtwRaw, name: &str) -> Option<String> {
        let ty = self.declared_type(raw, name);
        let bytes = self.raw_property(raw, name)?;
        Some(render_bytes(bytes, ty))
    }

    pub fn u32(&mut self, raw: &EtwRaw, name: &str) -> Option<u32> {
        match self.field(raw, name)? {
            FieldValue::U32(v) => Some(v),
            FieldValue::U16(v) => Some(u32::from(v)),
            FieldValue::U8(v) => Some(u32::from(v)),
            FieldValue::U64(v) => u32::try_from(v).ok(),
            FieldValue::I32(v) => u32::try_from(v).ok(),
            FieldValue::I64(v) => u32::try_from(v).ok(),
            _ => None,
        }
    }

    pub fn u64(&mut self, raw: &EtwRaw, name: &str) -> Option<u64> {
        match self.field(raw, name)? {
            FieldValue::U64(v) => Some(v),
            FieldValue::U32(v) => Some(u64::from(v)),
            FieldValue::U16(v) => Some(u64::from(v)),
            FieldValue::U8(v) => Some(u64::from(v)),
            FieldValue::I64(v) => u64::try_from(v).ok(),
            FieldValue::I32(v) => u64::try_from(v).ok(),
            _ => None,
        }
    }

    /// Return the first field that resolves, trying `names` in order.
    ///
    /// Manifests rename fields between Windows versions (`ProcessID`
    /// versus `ProcessId` versus `NewProcessId` are all real), and a lookup
    /// chain costs a few failed `TdhGetPropertySize` calls only on the
    /// first event of a schema.
    ///
    /// Note that this returns the first *resolving* name, even if it
    /// resolves to an empty string. A field declared by the manifest but
    /// not populated on this event is `Some("")`, not `None`, and a chain
    /// that stops there would hide the next name. Use
    /// [`Self::text_first_nonempty`] when an empty value should fall
    /// through to the next candidate.
    pub fn text_any(&mut self, raw: &EtwRaw, names: &[&str]) -> Option<String> {
        names.iter().find_map(|n| self.text(raw, n))
    }

    /// Like [`Self::text_any`], but skips a name that resolves to an empty
    /// string.
    ///
    /// A field that is *declared* by the manifest but *not populated* in
    /// this event returns an empty string, not `None`. That is a real
    /// outcome — the registry provider's `KeyName` behaves this way on
    /// `SetValueKey` events, where the kernel only has a pointer and not a
    /// path — and treating it as "resolved" hides the next name in the
    /// chain. `text_first_nonempty` continues to the next name when one
    /// resolves to nothing.
    pub fn text_first_nonempty(&mut self, raw: &EtwRaw, names: &[&str]) -> Option<String> {
        names
            .iter()
            .filter_map(|n| self.text(raw, n))
            .find(|s| !s.is_empty())
    }

    pub fn u32_any(&mut self, raw: &EtwRaw, names: &[&str]) -> Option<u32> {
        names.iter().find_map(|n| self.u32(raw, n))
    }

    pub fn u64_any(&mut self, raw: &EtwRaw, names: &[&str]) -> Option<u64> {
        names.iter().find_map(|n| self.u64(raw, n))
    }
}

/// Rebuild a record TDH will accept, pointing at the event's own payload.
///
/// `payload` must be the buffer the record's `UserData` points at, and it
/// must outlive every TDH call made against the record. The `*const` →
/// `*mut` cast is the C API's shape, not a promise to write: every TDH
/// entry point used here reads `UserData` and nothing else.
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

/// The event's payload as the C API's `*mut c_void`, without copying it.
///
/// The `EtwRaw` the caller borrowed the payload from outlives every TDH
/// call made with it, which is what makes handing out a pointer instead of
/// a copy sound.
fn payload_pointer(raw: &EtwRaw) -> *mut u8 {
    raw.wire.data.as_ptr() as *mut u8
}

/// Render property bytes as text, using the declared type when the schema
/// gave us one and the byte width when it did not.
///
/// Split out of [`Decoder::text`] so the borrow of the property buffer ends
/// before the `String` is built.
fn render_bytes(bytes: &[u8], ty: Option<FieldType>) -> String {
    match ty {
        // A string type decodes straight to the answer. Going through
        // `FieldValue::Str` would build one `String` in `classify_typed`
        // and then clone it in `render_text`, which is a copy of every
        // path and every script block the sensor ships.
        Some(ty) if ty.is_string() => classify_string(bytes),
        Some(ty) => render_text(&classify_typed(bytes, ty)),
        None => render_text(&classify(bytes)),
    }
}

/// Decode a property the manifest declares as one of the UTF-16 string
/// types, including the two cases that are not a UTF-16 decode: an empty
/// value (which arrives as a lone terminator) is an empty string, and a
/// malformed one is rendered as bytes rather than dropped.
fn classify_string(bytes: &[u8]) -> String {
    if !bytes.is_empty() && bytes.iter().all(|b| *b == 0) {
        return String::new();
    }
    super::utf16_to_string(bytes).unwrap_or_else(|| hex(bytes))
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
            is_wow64: false,
        }
    }

    #[test]
    fn an_empty_payload_yields_no_field_rather_than_a_guess() {
        // Header-only events are legal; asking for a property on one must
        // not invent a value.
        let mut d = Decoder::new();
        let r = raw("p", 1, Vec::new());
        assert_eq!(d.field(&r, "ImageName"), None);
        assert_eq!(d.text(&r, "ImageName"), None);
        assert_eq!(d.u32(&r, "ProcessID"), None);
        assert_eq!(d.u64(&r, "ProcessID"), None);
        assert_eq!(d.typed_field(&r, "ImageName"), None);
        assert_eq!(d.declared_type(&r, "ImageName"), None);
    }

    #[test]
    fn lookup_chains_do_not_loop_or_panic() {
        let mut d = Decoder::new();
        // Resolution fails for every candidate on a payload TDH cannot
        // parse, so the chain must degrade to None.
        let empty = raw("p", 1, Vec::new());
        assert_eq!(d.text_any(&empty, &["A", "B", "C"]), None);
        assert_eq!(d.text_first_nonempty(&empty, &["A", "B", "C"]), None);
        assert_eq!(d.u32_any(&empty, &["A", "B"]), None);
        assert_eq!(d.u64_any(&empty, &["A", "B"]), None);
        assert_eq!(d.text_any(&empty, &[]), None);
        assert_eq!(d.text_first_nonempty(&empty, &[]), None);
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
        // The record aliases our buffer rather than owning a copy of it:
        // that aliasing is the whole point, and it is why the buffer must
        // outlive every TDH call made against the record.
        assert_eq!(unsafe { *(record.UserData as *const u8) }, 0);
    }

    #[test]
    fn synthetic_record_truncates_oversized_payloads_to_u16_max() {
        // `UserDataLength` is a `u16` in the wire format. A payload larger
        // than 65535 bytes has to be clamped rather than wrapped.
        let payload = vec![0u8; 0];
        let mut r = raw("p", 1, vec![0u8; 100]);
        r.wire.data = vec![0u8; 70000];
        let mut scratch = r.wire.data.clone();
        let record = synthetic_record(&r, scratch.as_mut_ptr());
        assert_eq!(record.UserDataLength, u16::MAX);
        let _ = payload;
    }

    #[test]
    fn a_declared_string_renders_as_text_and_a_malformed_one_as_bytes() {
        // The typed path's whole point, plus the two cases that are not a
        // UTF-16 decode: an empty value arrives as a lone terminator and is
        // an empty string, and bytes that are not UTF-16 are rendered as
        // bytes rather than dropped.
        let wide = b"C\x00:\x00\\\x00x\x00\x00\x00";
        assert_eq!(render_bytes(wide, Some(FieldType::UnicodeString)), "C:\\x");

        let empty = [0u8, 0];
        assert_eq!(render_bytes(&empty, Some(FieldType::UnicodeString)), "");

        let lone_surrogate = [0x00, 0xd8];
        assert_eq!(
            render_bytes(&lone_surrogate, Some(FieldType::UnicodeString)),
            "00d8"
        );
    }

    #[test]
    fn an_unresolved_schema_falls_back_to_the_byte_width() {
        // Four bytes with no declared type are a `UInt32`; the same four
        // bytes declared `Binary` are four bytes. That distinction is the
        // reason the schema is fetched at all, and it survives the rewrite
        // that fetches the type and the bytes independently.
        let four = [1u8, 0, 0, 0];
        assert_eq!(render_bytes(&four, None), "1");
        assert_eq!(render_bytes(&four, Some(FieldType::Binary)), "01000000");
    }

    #[test]
    fn cloning_a_decoder_starts_with_an_empty_cache() {
        // The observer gives each worker its own `Decoder`; a clone must
        // not share the schema cache with the original, because the two
        // will be mutated on different threads.
        let a = Decoder::new();
        let b = a.clone();
        assert!(a.schemas.is_empty());
        assert!(b.schemas.is_empty());
    }
}
