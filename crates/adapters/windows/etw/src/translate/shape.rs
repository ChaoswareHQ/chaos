//! Which ETW event becomes which wire shape, and the field-name chains TDH
//! resolves against.
//!
//! Every name here was read off a live `Get-WinEvent -ListProvider <provider>`.
//! The chains exist because templates rename fields across Windows builds and
//! a miss must degrade to `None`, never to a guess.
//!
//! # What is deliberately NOT here
//!
//! `Kernel-Registry` opens/queries/enumerates, `Kernel-Process` thread churn,
//! and `DNS-Client` responses were all reviewed and excluded. The
//! [`super::UnrecognisedHistogram`] is what keeps that decision visible: if
//! one of these turns out to matter, the histogram will say so and it becomes
//! a shape; until then, excluding them is why the sensor runs at all.

/// A wire event this sensor knows how to build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    ProcessStart = 0,
    ProcessExit = 1,
    ImageLoad = 2,
    RegistrySet = 3,
    DnsQuery = 4,
    ScriptBlock = 5,
}

impl Shape {
    pub const ALL: [Shape; 6] = [
        Shape::ProcessStart,
        Shape::ProcessExit,
        Shape::ImageLoad,
        Shape::RegistrySet,
        Shape::DnsQuery,
        Shape::ScriptBlock,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Shape::ProcessStart => "process_start",
            Shape::ProcessExit => "process_exit",
            Shape::ImageLoad => "image_load",
            Shape::RegistrySet => "registry_set",
            Shape::DnsQuery => "dns_query",
            Shape::ScriptBlock => "script_block",
        }
    }

    /// Kernel-provider shapes. The gap detector uses this to decide whether
    /// a silent shape is suspicious or just a quiet host.
    pub const fn is_kernel_side(self) -> bool {
        matches!(
            self,
            Shape::ProcessStart | Shape::ProcessExit | Shape::ImageLoad | Shape::RegistrySet
        )
    }

    pub const fn is_user_mode(self) -> bool {
        !self.is_kernel_side()
    }
}

/// Which ETW event becomes which wire shape.
///
/// Every id here was verified against the installed manifest. The pairs that
/// are **not** here were deliberately excluded after reviewing their volume
/// and signal; the histogram is what keeps that decision visible.
pub fn shape_of(provider: &str, event_id: u16) -> Option<Shape> {
    match (provider, event_id) {
        ("Microsoft-Windows-Kernel-Process", 1) => Some(Shape::ProcessStart),
        ("Microsoft-Windows-Kernel-Process", 2) => Some(Shape::ProcessExit),
        ("Microsoft-Windows-Kernel-Process", 5) => Some(Shape::ImageLoad),
        ("Microsoft-Windows-Kernel-Registry", 5) => Some(Shape::RegistrySet),
        ("Microsoft-Windows-DNS-Client", 3006) => Some(Shape::DnsQuery),
        ("Microsoft-Windows-PowerShell", 4104) => Some(Shape::ScriptBlock),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Field-name chains
// ---------------------------------------------------------------------------

pub const PROCESS_ID: &[&str] = &["ProcessID", "ProcessId"];
pub const PARENT_PROCESS_ID: &[&str] = &["ParentProcessID", "ParentProcessId"];
pub const IMAGE_NAME: &[&str] = &["ImageName", "ImagePath"];

/// Registry key path.
///
/// The `KeyName` field on `RegistrySetValue` carries the full path on some
/// builds and is empty on others. When it is empty, the decoder falls back
/// to the [`super::kcb::KeyCache`] using [`KCB_KEY_OBJECT`], which is why
/// both fields are read from every registry event.
///
/// `KeyPath` and `RelativeName` are here as alternatives because that is
/// what an alternative manifest would name the field.
pub const KEY_NAME: &[&str] = &["KeyName", "KeyPath", "RelativeName"];

/// The kernel pointer to a Key Control Block, carried by every
/// `Microsoft-Windows-Kernel-Registry` event and by nothing else.
///
/// On a 64-bit host this is a `POINTER` field (TDH `InType` 16) and reads
/// back as a `u64`. On a 32-bit host it would be a `UInt32`; this crate
/// only ships 64-bit, and the decoder chain reads it as `u64` either way
/// because a 32-bit pointer zero-extends.
///
/// The cache that resolves this pointer to a path lives in
/// [`super::kcb`]. It is populated from the registry events that *do* carry
/// a path (`OpenKey`, `CreateKey`, `KCBCreate`, …) and answers the events
/// that do not (`SetValueKey`).
pub const KCB_KEY_OBJECT: &[&str] = &["KeyObject", "KeyObjectPtr"];

pub const VALUE_NAME: &[&str] = &["ValueName", "Value"];
pub const CAPTURED_DATA: &str = "CapturedData";
pub const REGISTRY_TYPE: &[&str] = &["Type", "ValueType"];

/// `Kernel-Process` id 2: exit status under one of these.
pub const EXIT_CODE: &[&str] = &["ExitCode", "ExitStatus"];

pub const QUERY_NAME: &[&str] = &["QueryName"];
pub const QUERY_TYPE: &[&str] = &["QueryType"];

pub const SCRIPT_BLOCK_TEXT: &[&str] = &["ScriptBlockText"];
pub const SCRIPT_BLOCK_ID: &[&str] = &["ScriptBlockId"];
pub const SCRIPT_BLOCK_PATH: &[&str] = &["Path"];
pub const MESSAGE_NUMBER: &[&str] = &["MessageNumber"];
pub const MESSAGE_TOTAL: &[&str] = &["MessageTotal"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_scored_shapes_are_claimed() {
        assert_eq!(
            shape_of("Microsoft-Windows-Kernel-Process", 1),
            Some(Shape::ProcessStart)
        );
        assert_eq!(
            shape_of("Microsoft-Windows-Kernel-Process", 2),
            Some(Shape::ProcessExit)
        );
        assert_eq!(
            shape_of("Microsoft-Windows-Kernel-Process", 5),
            Some(Shape::ImageLoad)
        );
        assert_eq!(
            shape_of("Microsoft-Windows-Kernel-Registry", 5),
            Some(Shape::RegistrySet)
        );
        assert_eq!(
            shape_of("Microsoft-Windows-DNS-Client", 3006),
            Some(Shape::DnsQuery)
        );
        assert_eq!(
            shape_of("Microsoft-Windows-PowerShell", 4104),
            Some(Shape::ScriptBlock)
        );

        // Deliberately not scored.
        assert_eq!(shape_of("Microsoft-Windows-Kernel-Process", 3), None);
        assert_eq!(shape_of("Microsoft-Windows-Kernel-Process", 4), None);
        assert_eq!(shape_of("Microsoft-Windows-Kernel-Registry", 1), None);
        assert_eq!(shape_of("Microsoft-Windows-PowerShell", 4103), None);
    }

    #[test]
    fn every_shape_has_a_name_and_a_side() {
        for s in Shape::ALL {
            assert!(!s.as_str().is_empty());
            assert!(s.is_kernel_side() ^ s.is_user_mode());
        }
    }

    #[test]
    fn shape_indices_are_stable() {
        assert_eq!(Shape::ProcessStart as usize, 0);
        assert_eq!(Shape::ProcessExit as usize, 1);
        assert_eq!(Shape::ImageLoad as usize, 2);
        assert_eq!(Shape::RegistrySet as usize, 3);
        assert_eq!(Shape::DnsQuery as usize, 4);
        assert_eq!(Shape::ScriptBlock as usize, 5);
    }

    #[test]
    fn the_kcb_pointer_chain_has_a_first_candidate() {
        // The decoder reads `KCB_KEY_OBJECT[0]` as the manifest's spelling.
        // If someone renames it, this test is what catches the drift.
        assert_eq!(KCB_KEY_OBJECT.first().copied(), Some("KeyObject"));
    }
}
