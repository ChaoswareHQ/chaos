//! Typed property values, and the two classification paths.
//!
//! # Why two classifiers
//!
//! [`classify_typed`] interprets bytes according to the schema's declared
//! `InType`. It is the honest answer: a field declared `Binary` is bytes,
//! even when four of those bytes happen to look like a `UInt32`.
//!
//! [`classify`] interprets bytes by *width*. It exists for the case where
//! the schema does not resolve — a provider whose manifest is not
//! registered on this build — and the caller already knows the field is a
//! fixed-width scalar (`ProcessID`, `QueryType`). It is a guess, and the
//! crate treats it as one.
//!
//! Everywhere the declared type is available, use the typed path.

/// A decoded property value.
///
/// The variants are the shapes TDH's `InType` actually resolves to for the
/// providers this crate enables. `U8` rather than `Bool` because ETW's
/// `Boolean` is a one-byte `0`/`1` on the wire and giving it its own
/// variant would be inventing a type the manifest does not declare.
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
/// The numbers are the `TDH_INTYPE_*` constants from `tdh.h`; windows-rs
/// does not expose them as named items, so they are spelled out in
/// [`FieldType::from_tdh`]. Only the types a manifest provider actually
/// declares in the fields this crate reads are matched; everything else
/// becomes [`FieldType::Unknown`] and is kept as bytes, which is the
/// honest answer for a type we do not decode.
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
    /// rather than kept as bytes. The string types TDH can return differ
    /// only in their terminator convention, which
    /// [`crate::decode::utf16_to_string`] already handles by stopping at
    /// the first NUL.
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

/// Interpret a TDH property buffer given the schema's declared type.
///
/// Every branch is a fact about the property, not a guess from its size.
/// The `Binary` branch is the one that matters most in practice: the
/// registry provider's `CapturedData` is a `Binary` field, and its bytes
/// are whatever the writer wrote — a UTF-16 string, a `DWORD`, an embedded
/// image. Hex is the honest rendering of "we know it is bytes and nothing
/// more".
pub(crate) fn classify_typed(buffer: &[u8], ty: FieldType) -> FieldValue {
    use super::utf16_to_string;
    match ty {
        FieldType::UnicodeString
        | FieldType::CountedString
        | FieldType::NonNullTerminatedString
        | FieldType::WbemSid => {
            // A `REG_SZ` empty value arrives as just the terminator.
            // `utf16_to_string` refuses that because for an *untyped*
            // field "all NUL" is absence; for a typed string field, it is
            // an empty string, which is a real value.
            if !buffer.is_empty() && buffer.iter().all(|b| *b == 0) {
                return FieldValue::Str(String::new());
            }
            utf16_to_string(buffer)
                .map(FieldValue::Str)
                .unwrap_or_else(|| FieldValue::Binary(buffer.to_vec()))
        }

        FieldType::AnsiString => buffer
            .split(|b| *b == 0)
            .next()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .filter(|s| !s.is_empty())
            .map(FieldValue::Str)
            .unwrap_or_else(|| FieldValue::Binary(buffer.to_vec())),

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

/// Classify by byte width.
///
/// Used when the schema does not resolve and the caller already knows the
/// field is a fixed-width scalar. The ambiguity this documents — a 4-byte
/// buffer could be a `U32` or four bytes of a `Binary` field — is why the
/// typed path exists at all.
pub(crate) fn classify(buffer: &[u8]) -> FieldValue {
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
/// Split from the fetch path so the typed and untyped paths share the
/// rendering, and so `text` stays small enough to read.
pub(crate) fn render_text(value: &FieldValue) -> String {
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

#[inline]
fn read<const N: usize>(buffer: &[u8]) -> Option<[u8; N]> {
    buffer.get(..N)?.try_into().ok()
}

#[inline]
fn empty_binary() -> FieldValue {
    FieldValue::Binary(Vec::new())
}

/// Lowercase hex. Used for GUID and binary renderings.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_classification_uses_the_declared_type_not_the_width() {
        // Four bytes of `Binary` are bytes, even though four bytes of
        // `UInt32` are an integer. This is the distinction the typed path
        // exists for, and it is the whole reason the registry value is not
        // shipped as the little-endian rendering of a `REG_SZ`'s first two
        // characters.
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
    fn typed_classification_decodes_utf16_reg_sz_as_a_string() {
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
        // A `REG_SZ` with an empty value arrives as just the terminator.
        // That is a value, and reporting it as `Binary([0, 0])` would be
        // wrong.
        assert_eq!(
            classify_typed(&[0, 0], FieldType::UnicodeString),
            FieldValue::Str(String::new())
        );
    }

    #[test]
    fn typed_classification_refuses_a_truncated_scalar() {
        // A scalar type on a buffer too short for it is a malformed event,
        // not a value to be reinterpreted. The empty `Binary` is the
        // honest answer.
        assert_eq!(
            classify_typed(&[1, 2], FieldType::UInt32),
            FieldValue::Binary(Vec::new())
        );
    }

    #[test]
    fn width_classification_maps_known_sizes_and_falls_back_to_binary() {
        assert_eq!(classify(&[1, 0]), FieldValue::U16(1));
        assert_eq!(classify(&[1, 0, 0, 0]), FieldValue::U32(1));
        assert_eq!(classify(&[1, 0, 0, 0, 0, 0, 0, 0]), FieldValue::U64(1));
        assert_eq!(classify(&[1, 2, 3]), FieldValue::Binary(vec![1, 2, 3]));
        assert_eq!(classify(&[]), FieldValue::Binary(Vec::new()));
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
    fn string_types_are_recognised() {
        assert!(FieldType::UnicodeString.is_string());
        assert!(FieldType::CountedString.is_string());
        assert!(!FieldType::Binary.is_string());
        assert!(!FieldType::UInt32.is_string());
    }

    #[test]
    fn render_text_renders_a_string_as_its_characters() {
        // The property that made the first live run print hex: a
        // `FieldValue::Str` must render as its characters, not as hex.
        assert_eq!(
            render_text(&FieldValue::Str("hif-leim.deepseek.com".into())),
            "hif-leim.deepseek.com"
        );
        assert_eq!(render_text(&FieldValue::Binary(vec![0xab, 0xcd])), "abcd");
        assert_eq!(render_text(&FieldValue::U32(42)), "42");
    }

    #[test]
    fn hex_is_lowercase() {
        assert_eq!(hex(&[0xab, 0xcd, 0xef]), "abcdef");
        assert_eq!(hex(&[]), "");
    }
}
