//! The `TRACE_EVENT_INFO` parse and the schema cache key.
//!
//! # What a schema is
//!
//! `TdhGetEventInformation` returns a `TRACE_EVENT_INFO` buffer. It
//! contains, for one `(provider, event id, version)`:
//!
//! * A fixed header (provider GUID, event id, version, property count).
//! * A variable-length array of `EVENT_PROPERTY_INFO`, one per property.
//! * A block of NUL-terminated UTF-16 strings, referenced by byte offset
//!   from the array entries.
//!
//! The strings are what we want: the *names* of the properties. The array
//! entries carry the declared `InType` of each.
//!
//! # Why this walks bytes
//!
//! The struct ends in the C `ANYSIZE_ARRAY` idiom, which windows-rs
//! declares as a one-element array (`[EVENT_PROPERTY_INFO; 1]`). The actual
//! array begins at that field's offset, and its length is
//! `TRACE_EVENT_INFO::PropertyCount`. Every string reference is a byte
//! offset into the same buffer. Both facts are why the parse walks raw
//! bytes rather than using the declared struct shape directly.

use std::collections::BTreeMap;
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_PROPERTY_INFO, EVENT_RECORD, TRACE_EVENT_INFO, TdhGetEventInformation,
};
use windows::core::GUID;

/// Largest schema buffer we will accept from TDH.
///
/// A real template is a few hundred bytes; this is a sanity ceiling so a
/// malformed manifest cannot make the sensor allocate a gigabyte.
pub(crate) const MAX_SCHEMA_BYTES: usize = 64 * 1024;

/// A `(provider, event id, version)` triple.
///
/// `Version` is in the key because a provider can declare two different
/// templates for the same event id at different versions, and
/// `EVENT_DESCRIPTOR::Version` is what selects one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SchemaKey {
    pub provider: GUID,
    pub event_id: u16,
    pub version: u8,
}

/// A template's property names and their declared types.
///
/// `properties` maps a name to the raw `InType` value TDH reported;
/// [`crate::decode::FieldType::from_tdh`] converts it to the typed enum.
/// Kept as a `BTreeMap` for determinism across runs, which matters when a
/// failure message is the thing being diffed.
#[derive(Debug, Default, Clone)]
pub(crate) struct Schema {
    pub(crate) properties: BTreeMap<Box<str>, u16>,
    /// Set once TDH has refused the schema for a key. Without this, an
    /// event from a provider whose manifest is not registered would pay a
    /// failed `TdhGetEventInformation` call on every single event.
    pub(crate) unresolvable: bool,
}

impl Schema {
    /// The schema for a `(provider, id, version)` TDH does not know.
    ///
    /// Storing this instead of retrying means the cost of an unresolvable
    /// schema is paid exactly once per key, not per event.
    pub(crate) fn unresolvable() -> Self {
        Self {
            properties: BTreeMap::new(),
            unresolvable: true,
        }
    }

    /// The declared `InType` of `name`, or `None` when the template has no
    /// such property.
    ///
    /// A `None` here is a fact and not a failure: the field tables in
    /// [`crate::wire::shape`] carry alternative spellings precisely because
    /// manifests differ between builds, and a name that does not resolve is
    /// how the chain moves on to the next one.
    pub(crate) fn get(&self, name: &str) -> Option<u16> {
        self.properties.get(name).copied()
    }
}

/// Ask TDH for a schema.
///
/// First call discovers the buffer size; second fills it. Both calls are
/// cheap relative to the events that will reuse the result, and the result
/// is cached per key by [`crate::decode::Decoder`].
///
/// # Safety
///
/// `record` must be a valid `EVENT_RECORD` whose `UserData` points at a
/// live buffer for the duration of both calls.
pub(crate) unsafe fn load_schema(record: &EVENT_RECORD) -> Schema {
    let mut size: u32 = 0;
    // The first call is the size probe. `ERROR_INSUFFICIENT_BUFFER` is the
    // success case here; TDH reports the needed size in `size` regardless
    // of the return code, so we only check the size.
    let _ = unsafe { TdhGetEventInformation(record, None, None, &mut size) };
    if size == 0 || size as usize > MAX_SCHEMA_BYTES {
        return Schema::unresolvable();
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
        return Schema::unresolvable();
    }
    buffer.truncate(size as usize);

    // SAFETY: `buffer` was filled by `TdhGetEventInformation` on the
    // second call, which is the precondition `parse_schema` documents.
    unsafe { parse_schema(&buffer) }.unwrap_or_else(Schema::unresolvable)
}

/// Walk a `TRACE_EVENT_INFO` buffer and pull out `name -> InType`.
///
/// # Safety
///
/// `buffer` must be a buffer that TDH filled with a `TRACE_EVENT_INFO` and
/// its associated strings, and its length must be the byte count TDH
/// reported.
unsafe fn parse_schema(buffer: &[u8]) -> Option<Schema> {
    if buffer.len() < std::mem::size_of::<TRACE_EVENT_INFO>() {
        return None;
    }

    // SAFETY: the length check above guarantees the fixed header is in
    // range.
    let info = buffer.as_ptr() as *const TRACE_EVENT_INFO;
    let property_count: usize = unsafe { (*info).PropertyCount as usize };

    // Where the variable-length array actually begins, relative to the
    // buffer. windows-rs names this field `EventPropertyInfoArray` and
    // declares it as `[EVENT_PROPERTY_INFO; 1]`, so `offset_of!` on the
    // field gives the correct start of the array in both the single- and
    // multi-element cases.
    let array_offset = std::mem::offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray);

    let mut properties = BTreeMap::new();

    for index in 0..property_count {
        let prop_offset = array_offset
            .checked_add(index.checked_mul(std::mem::size_of::<EVENT_PROPERTY_INFO>())?)?;
        if prop_offset + std::mem::size_of::<EVENT_PROPERTY_INFO>() > buffer.len() {
            return None;
        }
        // SAFETY: the offset arithmetic above bounds-checks both ends of
        // the `EVENT_PROPERTY_INFO` this reads.
        let prop = unsafe { &*(buffer.as_ptr().add(prop_offset) as *const EVENT_PROPERTY_INFO) };

        // The name is a NUL-terminated UTF-16 string at a byte offset
        // into the same buffer. A missing name means a struct or array
        // property, which this crate does not decode: it has no single
        // scalar type and TDH will not let you address it by name anyway.
        let Some(name) = read_wide_at(buffer, prop.NameOffset as usize) else {
            continue;
        };

        // `InType` is the first `u16` of the `nonStructType` arm of the
        // union. The `structType` and `arrayType` arms share those two
        // bytes, so the read is the same number regardless of which arm
        // TDH filled in. windows-rs exposes the union as `Anonymous1`; the
        // field names inside are `nonStructType` / `structType` /
        // `arrayType`.
        //
        // SAFETY: `prop` is a valid, aligned `EVENT_PROPERTY_INFO` and the
        // union is initialized by TDH with the `InType` field in every
        // arm.
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
/// Returns `None` for a zero offset, an odd offset, or an offset past the
/// end. All three are how TDH says "this property has no name" — a struct
/// property has `NameOffset == 0`, and a corrupted buffer has an offset
/// that does not point at a string.
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn an_unresolvable_schema_is_empty_and_flagged() {
        let s = Schema::unresolvable();
        assert!(s.unresolvable);
        assert!(s.properties.is_empty());
    }

    #[test]
    fn schema_keys_hash_on_all_three_fields() {
        use std::collections::HashSet;
        let provider = GUID::from_u128(0);
        let mut set = HashSet::new();
        set.insert(SchemaKey {
            provider,
            event_id: 1,
            version: 0,
        });
        // Same everything: not a new key.
        assert!(!set.insert(SchemaKey {
            provider,
            event_id: 1,
            version: 0,
        }));
        // Different event id: new key.
        assert!(set.insert(SchemaKey {
            provider,
            event_id: 2,
            version: 0,
        }));
        // Different version: new key.
        assert!(set.insert(SchemaKey {
            provider,
            event_id: 1,
            version: 1,
        }));
    }

    #[test]
    fn parse_schema_refuses_a_buffer_smaller_than_the_header() {
        // SAFETY: the buffer is not a real TRACE_EVENT_INFO, but the
        // function checks the length first and returns None before
        // reading anything.
        assert!(unsafe { parse_schema(&[]) }.is_none());
        assert!(unsafe { parse_schema(&[0u8; 8]) }.is_none());
    }
}
