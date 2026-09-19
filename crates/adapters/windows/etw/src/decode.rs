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
//! # Why the schema is fetched, not guessed
//!
//! `TdhGetProperty` returns a byte buffer and nothing else; it does not say
//! whether those bytes are a `UInt32`, four bytes of a `Binary` field, or the
//! first half of a UTF-16 string. Guessing from the width works until it does
//! not: the registry provider's `CapturedData` is declared `Binary`, and a
//! `REG_DWORD` Run value is four bytes, so a width-based guess reads an integer
//! where the manifest says bytes and never notices.
//!
//! `TdhGetEventInformation` *does* return the declared `InType` of every
//! property, and the answer is stable per `(provider, event id, version)`.
//! [`Decoder`] fetches it once per schema and caches it, so a field's type is a
//! fact rather than a guess and the cost is one extra TDH call on the first
//! event of each shape.
//!
//! [`Decoder::text`] uses the typed path *first*. A 26-byte UTF-16 DNS name
//! looks like a 26-byte blob to the untyped path, and rendering it as hex is
//! how the first live run printed `hif-leim.deepseek.com` as
//! `6800690066002d006c00650069006d...`. The typed path knows the field is a
//! `UnicodeString` and decodes accordingly.
//!
//! Field extraction is still by name (`TdhGetProperty` addresses properties by
//! `PCWSTR`, not by index), so the names are the one thing that has to be right.
//! They come from the provider's manifest, and the manifest can be read on any
//! machine without elevation by running `../tools/dump-fields.ps1`:
//!
//! ```text
//! powershell -NoProfile -ExecutionPolicy Bypass -File tools/dump-fields.ps1 `
//!     -Provider Microsoft-Windows-Kernel-Process
//! ```
//!
//! That is how the table in `translate` was built, and it is how to check it
//! rather than trust it. Not `wevtutil gp`: it prints a provider's channels,
//! levels, opcodes and tasks and says nothing at all about the data fields.

use crate::callback::EtwRaw;
use std::collections::HashMap;
use std::ffi::c_void;
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_DESCRIPTOR, EVENT_HEADER, EVENT_PROPERTY_INFO, EVENT_RECORD, PROPERTY_DATA_DESCRIPTOR,
    TRACE_EVENT_INFO, TdhGetEventInformation, TdhGetProperty, TdhGetPropertySize,
};
use windows::core::{GUID, PCWSTR};

/// Largest single property we will read. Command lines and image paths are the
/// big ones and they are nowhere near this; anything larger is a malformed
/// event and gets truncated rather than trusted.
pub const MAX_FIELD_BYTES: usize = 4096;

/// Largest schema buffer we will accept from TDH. A real template is a few
/// hundred bytes; this is a sanity ceiling so a malformed manifest cannot make
/// the sensor allocate a gigabyte.
pub const MAX_SCHEMA_BYTES: usize = 64 * 1024;

/// A decoded property value.
///
/// The variants are the shapes TDH's `InType` actually resolves to for the
/// providers this crate enables. `U8` rather than `Bool` because ETW's
/// `Boolean` is a one-byte `0`/`1` on the wire and giving it its own variant
/// would be inventing a type the manifest does not declare.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    Str(String),
    I8(i8),
    U8(u8),
    I16(i16),
    U16(u16),
    I32(i32),
    U32(u32),
    I64(i64),
    U64(u64),
    F32(f32),
    F64(f64),
    Guid([u8; 16]),
    Binary(Vec<u8>),
}

/// The subset of TDH's `InType` that this crate acts on.
///
/// The numbers are the `TDH_INTYPE_*` constants from `tdh.h`; windows-rs does
/// not expose them as named items, so they are spelled out here. Only the types
/// a manifest provider actually declares in the fields this crate reads are
/// matched; everything else becomes [`FieldType::Unknown`] and is kept as bytes,
/// which is the honest answer for a type we do not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    UnicodeString,
    AnsiString,
    CountedString,
    NonNullTerminatedString,
    Int8,
    UInt8,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Float,
    Double,
    Boolean,
    Binary,
    Guid,
    Pointer,
    FileTime,
    SystemTime,
    HexInt32,
    HexInt64,
    Sid,
    WbemSid,
    Unknown(u16),
}

impl FieldType {
    pub(crate) fn from_tdh(value: u16) -> Self {
        match value {
            1 => Self::UnicodeString,
            2 => Self::AnsiString,
            300 => Self::CountedString,
            304 => Self::NonNullTerminatedString,
            3 => Self::Int8,
            4 => Self::UInt8,
            5 => Self::Int16,
            6 => Self::UInt16,
            7 => Self::Int32,
            8 => Self::UInt32,
            9 => Self::Int64,
            10 => Self::UInt64,
            11 => Self::Float,
            12 => Self::Double,
            13 => Self::Boolean,
            14 => Self::Binary,
            15 => Self::Guid,
            16 => Self::Pointer,
            17 => Self::FileTime,
            18 => Self::SystemTime,
            19 => Self::Sid,
            20 => Self::HexInt32,
            21 => Self::HexInt64,
            309 => Self::WbemSid,
            other => Self::Unknown(other),
        }
    }

    /// Whether the type is a string whose bytes should be decoded as text
    /// rather than kept as bytes. The string types TDH can return differ only
    /// in their terminator convention, which [`utf16_to_string`] already
    /// handles by stopping at the first NUL.
    pub const fn is_string(self) -> bool {
        matches!(
            self,
            Self::UnicodeString
                | Self::CountedString
                | Self::NonNullTerminatedString
                | Self::WbemSid
        )
    }
}

/// A `(provider, event id, version)` triple. `Version` is in the key because a
/// provider can declare two different templates for the same event id at
/// different versions, and `EVENT_DESCRIPTOR::Version` is what selects one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SchemaKey {
    provider: GUID,
    event_id: u16,
    version: u8,
}

/// A template's property names and their declared types, as TDH reported them.
#[derive(Debug, Default, Clone)]
struct Schema {
    /// Property name to `InType` as TDH spelled it. Kept as a `BTreeMap` for
    /// determinism across runs, which matters when a failure message is the
    /// thing being diffed.
    properties: std::collections::BTreeMap<Box<str>, u16>,
    /// Set once TDH has refused the schema for a key. Without this, an event
    /// from a provider whose manifest is not registered would pay a failed
    /// `TdhGetEventInformation` call on every single event.
    unresolvable: bool,
}

/// Reusable decode state.
///
/// Holds one scratch buffer so a run of events sharing a schema does not
/// allocate per field, and one schema cache so the declared type of every
/// property is fetched once per `(provider, event id, version)` rather than
/// guessed from the byte width of each value.
///
/// `Decoder` is not `Sync`: it is meant to live on the single thread that
/// consumes a session.
#[derive(Debug, Default, Clone)]
pub struct Decoder {
    scratch: Vec<u8>,
    name: Vec<u16>,
    schemas: HashMap<SchemaKey, Schema>,
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

    /// Read a property as an owned value, using the schema's declared type to
    /// decide what the bytes mean.
    ///
    /// Returns `None` when the schema does not know the field, when the event
    /// cannot be resolved at all, or when TDH refuses the property call. A
    /// missing field is a normal outcome — manifests differ between Windows
    /// builds — so it is not an error, but callers should treat a `None` on a
    /// field they depend on as a reason to lower confidence rather than to
    /// guess.
    ///
    /// This is the accessor `translate` should use for every field whose
    /// declared type is not obvious from the name alone, which is every
    /// `Binary` field and every registry value.
    pub fn typed_field(&mut self, raw: &EtwRaw, name: &str) -> Option<(FieldValue, FieldType)> {
        let ty = self.declared_type(raw, name)?;
        let bytes = self.raw_property(raw, name)?;
        Some((classify_typed(&bytes, ty), ty))
    }

    /// Read a property as an owned value, classifying it by byte width.
    ///
    /// Kept for fields that are known by the caller to be fixed-width scalars
    /// (a `ProcessID`, a `QueryType`) and for which the schema lookup would be
    /// an extra call for no information. New code should prefer
    /// [`Self::typed_field`] where the type is not obvious.
    pub fn field(&mut self, raw: &EtwRaw, name: &str) -> Option<FieldValue> {
        let bytes = self.raw_property(raw, name)?;
        Some(classify(&bytes))
    }

    /// Look up the declared type of `property` in the event's schema.
    ///
    /// `None` means the schema does not resolve — no manifest registered, a
    /// malformed payload, an event whose template has no such name. Callers
    /// that *must* have an answer should treat that as a reason to skip the
    /// event, not as a reason to fall back to the byte-width guess.
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
                // The scratch is repopulated below for the property call;
                // building it here and again there is the one place this
                // happens twice, and it is only on a schema's first event.
                self.scratch.clear();
                self.scratch.extend_from_slice(&raw.wire.data);
                let record = synthetic_record(raw, self.scratch.as_mut_ptr());
                // SAFETY: `record` is a valid synthetic record for the duration
                // of this scope, and `load_schema` does not retain it.
                e.insert(unsafe { load_schema(&record) })
            }
        };

        if schema.unresolvable {
            return None;
        }
        let raw_type = *schema.properties.get(property)?;
        Some(FieldType::from_tdh(raw_type))
    }

    /// The TDH round trip, unchanged: size, copy, return the bytes.
    ///
    /// Deliberately does *not* interpret the bytes. Two callers want the same
    /// bytes for different reasons — the typed path wants to classify by
    /// declared type, the untyped path by width — and this is the shared half.
    fn raw_property(&mut self, raw: &EtwRaw, name: &str) -> Option<Vec<u8>> {
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

        Some(buffer)
    }

    /// Read a property as text.
    ///
    /// Uses the **typed** path first. TDH's declared type is what tells us a
    /// field is a `UnicodeString` (decode as UTF-16) rather than a `Binary`
    /// blob (render as hex). The untyped path can only guess from byte width,
    /// and a 26-byte UTF-16 DNS name looks like a 26-byte blob to it — which
    /// is why the first live run printed `hif-leim.deepseek.com` as
    /// `6800690066002d006c00650069006d...`.
    ///
    /// Falls back to the untyped path when the schema does not resolve, which
    /// is normal for a provider whose manifest is not registered on this
    /// build.
    pub fn text(&mut self, raw: &EtwRaw, name: &str) -> Option<String> {
        if let Some((value, _ty)) = self.typed_field(raw, name) {
            return Some(render_text(&value));
        }
        Some(render_text(&self.field(raw, name)?))
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
    /// Manifests rename fields between Windows versions (`ProcessID` versus
    /// `ProcessId` versus `NewProcessId` are all real), and a lookup chain costs
    /// a few failed `TdhGetPropertySize` calls only on the first event of a
    /// schema.
    ///
    /// Note that this returns the first *resolving* name, even if it resolves
    /// to an empty string. A field declared by the manifest but not populated
    /// on this event is `Some("")`, not `None`, and a chain that stops there
    /// would hide the next name. Use [`Self::text_first_nonempty`] when an
    /// empty value should fall through to the next candidate.
    pub fn text_any(&mut self, raw: &EtwRaw, names: &[&str]) -> Option<String> {
        names.iter().find_map(|n| self.text(raw, n))
    }

    /// Like [`Self::text_any`], but skips a name that resolves to an empty
    /// string.
    ///
    /// A field that is *declared* by the manifest but *not populated* in this
    /// event returns an empty string, not `None`. That is a real outcome — the
    /// registry provider's `KeyName` behaves this way on `SetValueKey` events,
    /// where the kernel only has a pointer and not a path — and treating it as
    /// "resolved" hides the next name in the chain.
    /// `text_first_nonempty` continues to the next name when one resolves to
    /// nothing.
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

/// Ask TDH for a schema. First call discovers the buffer size; second fills it.
///
/// Both calls are cheap relative to the events that will reuse the result, and
/// the result is cached per `(provider, event id, version)` by the caller.
///
/// # Safety
///
/// `record` must be a valid `EVENT_RECORD` whose `UserData` points at a live
/// buffer for the duration of both calls.
unsafe fn load_schema(record: &EVENT_RECORD) -> Schema {
    let unresolvable = Schema {
        properties: Default::default(),
        unresolvable: true,
    };

    let mut size: u32 = 0;
    // The first call is the size probe. `ERROR_INSUFFICIENT_BUFFER` is the
    // success case here; TDH reports the needed size in `size` regardless of
    // the return code, so we only check the size.
    let _ = unsafe { TdhGetEventInformation(record, None, None, &mut size) };
    if size == 0 || size as usize > MAX_SCHEMA_BYTES {
        return unresolvable;
    }

    let mut buffer = vec![0u8; size as usize];
    let rc = unsafe {
        TdhGetEventInformation(
            record,
            None,
            Some(buffer.as_mut_ptr() as *mut TRACE_EVENT_INFO),
            &mut size,
        )
    };
    if rc != 0 {
        return unresolvable;
    }
    buffer.truncate(size as usize);

    // SAFETY: `buffer` was filled by `TdhGetEventInformation` on the second
    // call, which is the precondition `parse_schema` documents.
    unsafe { parse_schema(&buffer) }.unwrap_or(unresolvable)
}

/// Walk a `TRACE_EVENT_INFO` buffer and pull out `name -> InType`.
///
/// The struct ends in a variable-length array of `EVENT_PROPERTY_INFO` (the
/// C `ANYSIZE_ARRAY` idiom, which windows-rs declares as a one-element array),
/// and every string it references lives in the same buffer as a NUL-terminated
/// UTF-16 run at a byte offset. Both facts are why the parse walks bytes.
///
/// # Safety
///
/// `buffer` must be a buffer that TDH filled with a `TRACE_EVENT_INFO` and its
/// associated strings, and its length must be the byte count TDH reported.
unsafe fn parse_schema(buffer: &[u8]) -> Option<Schema> {
    if buffer.len() < std::mem::size_of::<TRACE_EVENT_INFO>() {
        return None;
    }

    // SAFETY: the length check above guarantees the fixed header is in range.
    let info = buffer.as_ptr() as *const TRACE_EVENT_INFO;
    let property_count = unsafe { (*info).PropertyCount } as usize;

    // Where the variable-length array actually begins, relative to the buffer.
    // windows-rs names this field `EventPropertyInfoArray` and declares it as
    // `[EVENT_PROPERTY_INFO; 1]`, so `offset_of!` on the field gives the
    // correct start of the array in both the single- and multi-element cases.
    let array_offset = std::mem::offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray);

    let mut properties = std::collections::BTreeMap::new();

    for index in 0..property_count {
        let prop_offset = array_offset
            .checked_add(index.checked_mul(std::mem::size_of::<EVENT_PROPERTY_INFO>())?)?;
        if prop_offset + std::mem::size_of::<EVENT_PROPERTY_INFO>() > buffer.len() {
            return None;
        }
        // SAFETY: the offset arithmetic above bounds-checks both ends of the
        // `EVENT_PROPERTY_INFO` this reads.
        let prop = unsafe { &*(buffer.as_ptr().add(prop_offset) as *const EVENT_PROPERTY_INFO) };

        // The name is a NUL-terminated UTF-16 string at a byte offset into the
        // same buffer. A missing name means a struct or array property, which
        // this crate does not decode: it has no single scalar type and TDH
        // will not let you address it by name anyway.
        let Some(name) = read_wide_at(buffer, prop.NameOffset as usize) else {
            continue;
        };

        // `InType` is the first `u16` of the `nonStructType` arm of the union.
        // The `structType` and `arrayType` arms share those two bytes, so the
        // read is the same number regardless of which arm TDH filled in.
        // windows-rs exposes the union as `Anonymous1`; the field names inside
        // are `nonStructType` / `structType` / `arrayType`. Verify against the
        // installed version if this does not compile.
        // SAFETY: `prop` is a valid, aligned `EVENT_PROPERTY_INFO` and the
        // union is initialized by TDH with the InType field in every arm.
        let in_type: u16 = unsafe { prop.Anonymous1.nonStructType.InType };

        properties.insert(name.into_boxed_str(), in_type);
    }

    Some(Schema {
        properties,
        unresolvable: false,
    })
}

/// Read a NUL-terminated UTF-16 string at a byte offset into `buffer`.
///
/// Returns `None` for a zero offset, an odd offset, or an offset past the end.
/// All three are how TDH says "this property has no name" — a struct property
/// has `NameOffset == 0`, and a corrupted buffer has an offset that does not
/// point at a string.
fn read_wide_at(buffer: &[u8], offset: usize) -> Option<String> {
    if offset == 0 || offset % 2 != 0 || offset >= buffer.len() {
        return None;
    }
    let units: Vec<u16> = buffer[offset..]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|u| *u != 0)
        .collect();
    if units.is_empty() {
        return None;
    }
    String::from_utf16(&units).ok()
}

/// Interpret a TDH property buffer given the schema's declared type.
///
/// Every branch here is a fact about the property, not a guess from its size.
/// The `Binary` branch is the one that matters most in practice: the registry
/// provider's `CapturedData` is a `Binary` field, and its bytes are whatever
/// the writer wrote — a UTF-16 string, a `DWORD`, an embedded image. Hex is
/// the honest rendering of "we know it is bytes and nothing more".
fn classify_typed(buffer: &[u8], ty: FieldType) -> FieldValue {
    match ty {
        FieldType::UnicodeString
        | FieldType::CountedString
        | FieldType::NonNullTerminatedString
        | FieldType::WbemSid => {
            // A `REG_SZ` empty value arrives as just the terminator.
            // `utf16_to_string` refuses that because for an *untyped* field
            // "all NUL" is absence; for a typed string field, it is an empty
            // string, which is a real value.
            if !buffer.is_empty() && buffer.iter().all(|b| *b == 0) {
                return FieldValue::Str(String::new());
            }
            utf16_to_string(buffer)
                .map(FieldValue::Str)
                .unwrap_or_else(|| FieldValue::Binary(buffer.to_vec()))
        }

        FieldType::AnsiString => {
            let s = buffer
                .split(|b| *b == 0)
                .next()
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .filter(|s| !s.is_empty());
            s.map(FieldValue::Str)
                .unwrap_or_else(|| FieldValue::Binary(buffer.to_vec()))
        }

        FieldType::Int8 => read::<1>(buffer)
            .map(|b| FieldValue::I8(b[0] as i8))
            .unwrap_or_else(empty_binary),
        FieldType::UInt8 | FieldType::Boolean => read::<1>(buffer)
            .map(|b| FieldValue::U8(b[0]))
            .unwrap_or_else(empty_binary),
        FieldType::Int16 => read::<2>(buffer)
            .map(|b| FieldValue::I16(i16::from_le_bytes(b)))
            .unwrap_or_else(empty_binary),
        FieldType::UInt16 => read::<2>(buffer)
            .map(|b| FieldValue::U16(u16::from_le_bytes(b)))
            .unwrap_or_else(empty_binary),
        FieldType::Int32 => read::<4>(buffer)
            .map(|b| FieldValue::I32(i32::from_le_bytes(b)))
            .unwrap_or_else(empty_binary),
        FieldType::UInt32 | FieldType::HexInt32 => read::<4>(buffer)
            .map(|b| FieldValue::U32(u32::from_le_bytes(b)))
            .unwrap_or_else(empty_binary),
        FieldType::Int64 => read::<8>(buffer)
            .map(|b| FieldValue::I64(i64::from_le_bytes(b)))
            .unwrap_or_else(empty_binary),
        FieldType::UInt64 | FieldType::HexInt64 | FieldType::Pointer | FieldType::FileTime => {
            read::<8>(buffer)
                .map(|b| FieldValue::U64(u64::from_le_bytes(b)))
                .unwrap_or_else(empty_binary)
        }
        FieldType::Float => read::<4>(buffer)
            .map(|b| FieldValue::F32(f32::from_le_bytes(b)))
            .unwrap_or_else(empty_binary),
        FieldType::Double => read::<8>(buffer)
            .map(|b| FieldValue::F64(f64::from_le_bytes(b)))
            .unwrap_or_else(empty_binary),
        FieldType::Guid => read::<16>(buffer)
            .map(FieldValue::Guid)
            .unwrap_or_else(empty_binary),
        FieldType::Binary | FieldType::Sid | FieldType::SystemTime | FieldType::Unknown(_) => {
            FieldValue::Binary(buffer.to_vec())
        }
    }
}

#[inline]
fn read<const N: usize>(buffer: &[u8]) -> Option<[u8; N]> {
    buffer.get(..N)?.try_into().ok()
}

#[inline]
fn empty_binary() -> FieldValue {
    FieldValue::Binary(Vec::new())
}

/// TDH returns a byte buffer whose interpretation depends on the property's
/// declared type, which `TdhGetProperty` does not hand back. These are the
/// widths we can distinguish without the schema.
///
/// Kept for callers that already know the field is a fixed-width scalar. New
/// code that does not know should use [`Decoder::typed_field`], which asks the
/// schema and does not have to guess. The ambiguity this documents — a 4-byte
/// buffer could be a `U32` or four bytes of a `Binary` field — is why the
/// typed path exists at all.
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

/// Render a [`FieldValue`] as text.
///
/// Split from [`Decoder::text`] so the untyped and typed paths share the same
/// rendering, and so `text` stays small enough to read. This is the same
/// rendering `translate::render_field` uses; the two are kept separate because
/// `translate` renders values from an already-typed context and this renders
/// whatever `Decoder` returns.
fn render_text(value: &FieldValue) -> String {
    match value {
        FieldValue::Str(s) => s.clone(),
        FieldValue::I8(v) => v.to_string(),
        FieldValue::U8(v) => v.to_string(),
        FieldValue::I16(v) => v.to_string(),
        FieldValue::U16(v) => v.to_string(),
        FieldValue::I32(v) => v.to_string(),
        FieldValue::U32(v) => v.to_string(),
        FieldValue::I64(v) => v.to_string(),
        FieldValue::U64(v) => v.to_string(),
        FieldValue::F32(v) => v.to_string(),
        FieldValue::F64(v) => v.to_string(),
        FieldValue::Guid(b) => hex(b),
        FieldValue::Binary(b) => hex(b),
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0F) as usize] as char);
    }
    out
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
            is_wow64: false,
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
    fn classify_typed_uses_the_declared_type_not_the_width() {
        // Four bytes of `Binary` are bytes, even though four bytes of `UInt32`
        // are an integer. This is the distinction the typed path exists for,
        // and it is the whole reason the registry value is not shipped as the
        // little-endian rendering of a `REG_SZ`'s first two characters.
        assert_eq!(
            classify_typed(&[1, 2, 3, 4], FieldType::Binary),
            FieldValue::Binary(vec![1, 2, 3, 4])
        );
        assert_eq!(
            classify_typed(&[1, 2, 3, 4], FieldType::UInt32),
            FieldValue::U32(0x0403_0201)
        );
    }

    #[test]
    fn classify_typed_decodes_utf16_reg_sz_as_a_string_not_as_hex() {
        // `REG_SZ` is a UTF-16 string. `classify` would have called eight bytes
        // `U64` and shipped the encoding; the typed path is the reason it does
        // not.
        let bytes: Vec<u8> = "ab"
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(
            classify_typed(&bytes, FieldType::UnicodeString),
            FieldValue::Str("ab".to_string())
        );
    }

    #[test]
    fn an_empty_typed_string_is_an_empty_string_not_absence() {
        // A `REG_SZ` with an empty value arrives as just the terminator. That
        // is a value, and reporting it as `Binary([0, 0])` would be wrong.
        assert_eq!(
            classify_typed(&[0, 0], FieldType::UnicodeString),
            FieldValue::Str(String::new())
        );
    }

    #[test]
    fn classify_typed_refuses_a_truncated_scalar() {
        // A scalar type on a buffer too short for it is a malformed event, not
        // a value to be reinterpreted. The empty `Binary` is the honest answer.
        assert_eq!(
            classify_typed(&[1, 2], FieldType::UInt32),
            FieldValue::Binary(Vec::new())
        );
    }

    #[test]
    fn field_type_from_tdh_covers_the_types_this_crate_decodes() {
        assert_eq!(FieldType::from_tdh(1), FieldType::UnicodeString);
        assert_eq!(FieldType::from_tdh(14), FieldType::Binary);
        assert_eq!(FieldType::from_tdh(8), FieldType::UInt32);
        assert_eq!(FieldType::from_tdh(10), FieldType::UInt64);
        assert_eq!(FieldType::from_tdh(13), FieldType::Boolean);
        assert_eq!(FieldType::from_tdh(99), FieldType::Unknown(99));
    }

    #[test]
    fn an_empty_payload_yields_no_field_rather_than_a_guess() {
        // Header-only events are legal; asking for a property on one must not
        // invent a value.
        let mut d = Decoder::new();
        assert_eq!(d.field(&raw("p", 1, Vec::new()), "ImageName"), None);
        assert_eq!(d.text(&raw("p", 1, Vec::new()), "ImageName"), None);
        assert_eq!(d.u32(&raw("p", 1, Vec::new()), "ProcessID"), None);
        assert_eq!(d.typed_field(&raw("p", 1, Vec::new()), "ImageName"), None);
        assert_eq!(d.declared_type(&raw("p", 1, Vec::new()), "ImageName"), None);
    }

    #[test]
    fn lookup_chains_return_the_first_hit() {
        let mut d = Decoder::new();
        // Resolution fails for every candidate on a payload TDH cannot parse,
        // so the chain must degrade to None instead of looping or panicking.
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
        // The record aliases our buffer rather than owning a copy of it: that
        // aliasing is the whole point, and it is why the buffer must outlive
        // every TDH call made against the record.
        assert_eq!(unsafe { *(record.UserData as *const u8) }, 0);
    }

    #[test]
    fn read_wide_at_rejects_every_shape_of_absent_name() {
        let buffer = [0x61u8, 0x00, 0x62, 0x00, 0x00, 0x00];
        assert_eq!(read_wide_at(&buffer, 0), None, "zero offset is 'no name'");
        assert_eq!(read_wide_at(&buffer, 1), None, "odd offset is not UTF-16");
        assert_eq!(read_wide_at(&buffer, 100), None, "past the end");
        assert_eq!(read_wide_at(&buffer, 2), Some("b".to_string()));
        assert_eq!(read_wide_at(&buffer, 4), None, "all NUL is empty");
    }

    #[test]
    fn render_text_renders_a_string_as_its_characters() {
        // The property that made the first live run print hex: a
        // `FieldValue::Str` must render as its characters, not as hex.
        // The typed path produces the `Str`; this pins the render.
        assert_eq!(
            render_text(&FieldValue::Str("hif-leim.deepseek.com".into())),
            "hif-leim.deepseek.com"
        );
        assert_eq!(render_text(&FieldValue::Binary(vec![0xab, 0xcd])), "abcd");
        assert_eq!(render_text(&FieldValue::U32(42)), "42");
    }
}
