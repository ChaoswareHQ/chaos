//! Value rendering: FILETIME, registry types, DNS mnemonics, script capping.
//!
//! Everything here is pure — no TDH, no decoder state — so the code that
//! formats a value is separable from the code that fetches it. That matters
//! when a value renders wrong and the bug is either in TDH or in the
//! formatter; this file is the second one.

use chrono::{DateTime, Utc};

/// ETW's `TimeStamp` is a FILETIME: 100-nanosecond intervals since 1601-01-01.
const FILETIME_EPOCH_DELTA: i64 = 116_444_736_000_000_000;
const FILETIME_TICKS_PER_SEC: i64 = 10_000_000;

pub fn from_filetime(filetime: i64) -> Option<DateTime<Utc>> {
    let since_epoch = filetime.checked_sub(FILETIME_EPOCH_DELTA)?;
    if since_epoch < 0 {
        return None;
    }
    DateTime::from_timestamp(
        since_epoch / FILETIME_TICKS_PER_SEC,
        ((since_epoch % FILETIME_TICKS_PER_SEC) * 100) as u32,
    )
}

/// How much script text we will ship, in bytes.
pub const MAX_SCRIPT_TEXT: usize = 8 * 1024;

pub fn cap_script_text(text: &str) -> &str {
    if text.len() <= MAX_SCRIPT_TEXT {
        return text;
    }
    let mut end = MAX_SCRIPT_TEXT;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

pub fn query_type_name(value: u32) -> String {
    let known = match value {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        43 => "DS",
        65 => "HTTPS",
        255 => "ANY",
        other => return other.to_string(),
    };
    known.to_string()
}

pub mod reg_type {
    pub const SZ: u32 = 1;
    pub const EXPAND_SZ: u32 = 2;
    pub const BINARY: u32 = 3;
    pub const DWORD: u32 = 4;
    pub const DWORD_BIG_ENDIAN: u32 = 5;
    pub const MULTI_SZ: u32 = 7;
    pub const QWORD: u32 = 11;
}

/// Render a registry value according to its declared `REG_*` type.
pub fn render_registry_value(reg_type: u32, bytes: &[u8]) -> String {
    use crate::decode::utf16_to_string;
    match reg_type {
        reg_type::SZ | reg_type::EXPAND_SZ | reg_type::MULTI_SZ => {
            utf16_to_string(bytes).unwrap_or_else(|| hex(bytes))
        }
        reg_type::DWORD | reg_type::DWORD_BIG_ENDIAN => bytes
            .get(..4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .map(|v| v.to_string())
            .unwrap_or_else(|| hex(bytes)),
        reg_type::QWORD => bytes
            .get(..8)
            .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8])))
            .map(|v| v.to_string())
            .unwrap_or_else(|| hex(bytes)),
        reg_type::BINARY => hex(bytes),
        _ => hex(bytes),
    }
}

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

    const KNOWN_FILETIME: i64 = 133_444_736_000_000_000;

    #[test]
    fn filetime_converts_to_the_right_instant() {
        let at = from_filetime(KNOWN_FILETIME).expect("valid filetime");
        assert_eq!(at.to_rfc3339(), "2023-11-14T22:13:20+00:00");
    }

    #[test]
    fn sub_second_filetime_precision_survives() {
        let at = from_filetime(KNOWN_FILETIME + 1_234_567).expect("valid");
        assert_eq!(at.timestamp_subsec_nanos(), 123_456_700);
    }

    #[test]
    fn a_filetime_before_the_unix_epoch_is_refused() {
        assert_eq!(from_filetime(0), None);
        assert_eq!(from_filetime(FILETIME_EPOCH_DELTA - 1), None);
    }

    #[test]
    fn script_cap_respects_char_boundaries() {
        let long = "e".repeat(MAX_SCRIPT_TEXT * 2);
        assert_eq!(cap_script_text(&long).len(), MAX_SCRIPT_TEXT);

        let mut text = "a".repeat(MAX_SCRIPT_TEXT - 1);
        text.push('\u{20ac}');
        text.push_str(&"b".repeat(100));
        assert_eq!(cap_script_text(&text).len(), MAX_SCRIPT_TEXT - 1);
    }

    #[test]
    fn registry_values_render_by_declared_type() {
        let sz: Vec<u8> = "C:\\x"
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(render_registry_value(reg_type::SZ, &sz), "C:\\x");
        assert_eq!(render_registry_value(reg_type::DWORD, &[1, 0, 0, 0]), "1");
        assert_eq!(
            render_registry_value(reg_type::BINARY, &[1, 2, 3]),
            "010203"
        );
        assert_eq!(render_registry_value(0xdead, &[1, 2, 3]), "010203");
    }

    #[test]
    fn unknown_dns_types_fall_back_to_numbers() {
        assert_eq!(query_type_name(1), "A");
        assert_eq!(query_type_name(28), "AAAA");
        assert_eq!(query_type_name(99), "99");
    }
}
