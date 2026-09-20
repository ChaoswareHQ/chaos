//! TDH decoding: turning the opaque payload in an [`EtwRaw`] into named
//! fields.
//!
//! # The central trick
//!
//! TDH can only read a *live* `EVENT_RECORD`, and the kernel recycles the
//! real one the moment the callback returns. Because the callback copied
//! `UserData` into our own buffer, we rebuild a synthetic record that
//! points at that copy, restores the descriptor fields TDH keys its
//! schema lookup on, and hand it over. Everything else here follows from
//! that: the decode is deferred, so it costs nothing on the hot path, and
//! it is free to be as slow as it needs to be.
//!
//! # Why the schema is fetched, not guessed
//!
//! `TdhGetProperty` returns a byte buffer and nothing else; it does not
//! say whether those bytes are a `UInt32`, four bytes of a `Binary` field,
//! or the first half of a UTF-16 string. Guessing from the width works
//! until it does not: the registry provider's `CapturedData` is declared
//! `Binary`, and a `REG_DWORD` Run value is four bytes, so a width-based
//! guess reads an integer where the manifest says bytes and never notices.
//!
//! `TdhGetEventInformation` *does* return the declared `InType` of every
//! property, and the answer is stable per `(provider, event id, version)`.
//! [`Decoder`] fetches it once per schema and caches it, so a field's type
//! is a fact rather than a guess and the cost is one extra TDH call on the
//! first event of each shape.
//!
//! [`Decoder::text`] uses the typed path *first*. A 26-byte UTF-16 DNS
//! name looks like a 26-byte blob to the untyped path, and rendering it as
//! hex is how the first live run printed `hif-leim.deepseek.com` as
//! `6800690066002d006c00650069006d...`. The typed path knows the field is
//! a `UnicodeString` and decodes accordingly.
//!
//! # What is in each file
//!
//! * [`decoder`] — the `Decoder` type. Holds the scratch buffer, the name
//!   buffer, and the schema cache. The `typed_field` / `text_any` /
//!   `u32_any` surface lives here.
//! * [`schema`] — the `TRACE_EVENT_INFO` parse and the schema cache key.
//! * [`value`] — `FieldValue`, `FieldType`, and the two classification
//!   paths (`classify` by width, `classify_typed` by declared type).
//!
//! # Field names come from the manifest
//!
//! Field extraction is still by name (`TdhGetProperty` addresses
//! properties by `PCWSTR`, not by index), so the names are the one thing
//! that has to be right. They come from the provider's manifest, and the
//! manifest can be read on any machine without elevation by running
//! `tools/dump-fields.ps1`:
//!
//! ```text
//! powershell -NoProfile -ExecutionPolicy Bypass -File tools/dump-fields.ps1 `
//!     -Provider Microsoft-Windows-Kernel-Process
//! ```
//!
//! That is how the field tables in [`crate::wire::shape`] were built, and
//! it is how to check them rather than trust them.

mod decoder;
mod schema;
mod value;

pub use decoder::{Decoder, MAX_FIELD_BYTES};
pub use schema::SchemaKey;
pub use value::{FieldType, FieldValue};

/// Decode a NUL-terminated UTF-16 string.
///
/// This is how TDH returns `wstring` properties and how the manifests
/// store every name the crate cares about. Rejects odd-length input and
/// empty strings; the first of those is malformed, the second is absence.
///
/// Public because `render_registry_value` in [`crate::wire::render`] uses
/// it, and because the KCB cache's consumers may want to decode a stored
/// path back from raw bytes.
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

/// Point a `PCWSTR` at a UTF-16 name, for the TDH entry points that take
/// one.
pub fn wide(name: &str) -> Vec<u16> {
    name.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn wide_handles_the_empty_string() {
        let w = wide("");
        assert_eq!(w, vec![0x00]);
    }
}
