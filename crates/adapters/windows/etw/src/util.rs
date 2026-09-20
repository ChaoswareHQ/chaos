//! Shared helpers.

use windows::core::GUID;

/// A GUID in the canonical `{8-4-4-4-12}` spelling.
pub fn format_guid(guid: &GUID) -> String {
    let b = guid.data4;
    format!(
        "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        guid.data1, guid.data2, guid.data3,
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guids_use_canonical_windows_layout() {
        let g = GUID::from_u128(0x0011_2233_4455_6677_8899_aabb_ccdd_eeff);
        assert_eq!(format_guid(&g), "{00112233-4455-6677-8899-aabbccddeeff}");
    }
}
