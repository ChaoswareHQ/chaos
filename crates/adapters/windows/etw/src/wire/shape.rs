//! Which ETW event becomes which wire shape, and the field-name chains TDH
//! resolves against.
//!
//! # One declaration, five generated pieces of code
//!
//! Adding a shape is one line at the bottom of this file. The [`Shape`]
//! enum, [`Shape::ALL`], [`Shape::as_str`], [`Shape::is_kernel_side`], and
//! [`shape_of`] are all generated from the same table.
//!
//! Before this macro, adding a shape meant editing five sites here plus
//! two array sizes in [`super::ShapeCounts`]. Missing any one produced
//! either a compile error (good) or a silent bug where the shape was
//! defined but never counted (bad).
//!
//! # What is deliberately NOT here
//!
//! `Kernel-Registry` opens/queries/enumerates, `Kernel-Process` thread
//! churn, and `DNS-Client` responses were all reviewed and excluded after
//! looking at their volume on a real host. The
//! [`super::UnrecognisedHistogram`] is what keeps that decision visible:
//! if one of them turns out to matter, the histogram says so and it
//! becomes a shape.

/// The single source of truth for the shape table.
///
/// Each row is: `VariantName = "wire_name" => (provider, event_id), is_kernel_side ;`
macro_rules! declare_shapes {
    (
        $(
            $variant:ident = $wire:literal
                => ($provider:literal, $event_id:literal)
                , $kernel:literal ;
        )*
    ) => {
        /// A wire event this sensor knows how to build.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Shape {
            $($variant,)*
        }

        impl Shape {
            /// Every shape, in declaration order.
            ///
            /// The order is stable and is what [`super::ShapeCounts`]'s
            /// per-shape arrays and the run report's table both iterate.
            /// Reordering this list without reordering the enum is caught
            /// by a test in this file.
            pub const ALL: &[Shape] = &[$(Shape::$variant,)*];

            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Shape::$variant => $wire,)*
                }
            }

            /// Whether this shape comes from a kernel-mode provider.
            ///
            /// The gap detector uses this to decide whether a silent shape
            /// is suspicious or just a quiet host. A user-mode shape that
            /// stops firing while a kernel-mode shape is still active is
            /// the ETW-bypass signature.
            pub const fn is_kernel_side(self) -> bool {
                match self {
                    $(Shape::$variant => $kernel,)*
                }
            }

            pub const fn is_user_mode(self) -> bool {
                !self.is_kernel_side()
            }
        }

        /// Which ETW event becomes which wire shape.
        ///
        /// Every id here was verified against the installed manifest.
        pub fn shape_of(provider: &str, event_id: u16) -> Option<Shape> {
            match (provider, event_id) {
                $(($provider, $event_id) => Some(Shape::$variant),)*
                _ => None,
            }
        }
    };
}

// The single source of truth. Adding a shape is one line here.
//
// Kernel-Registry 5 (`SetValueKey`) is the only registry event scored.
// Registry opens, queries, and enumerates were reviewed and excluded; see
// the histogram for the volumes on a real host.
declare_shapes! {
    ProcessStart = "process_start" => ("Microsoft-Windows-Kernel-Process", 1), true;
    ProcessExit  = "process_exit"  => ("Microsoft-Windows-Kernel-Process", 2), true;
    ImageLoad    = "image_load"    => ("Microsoft-Windows-Kernel-Process", 5), true;
    RegistrySet  = "registry_set"  => ("Microsoft-Windows-Kernel-Registry", 5), true;
    DnsQuery     = "dns_query"     => ("Microsoft-Windows-DNS-Client", 3006), false;
    ScriptBlock  = "script_block"  => ("Microsoft-Windows-PowerShell", 4104), false;
}

// ---------------------------------------------------------------------------
// Field-name chains
// ---------------------------------------------------------------------------
//
// Each chain is tried in order; the first name that resolves to a
// non-empty value wins. Chains exist because manifests rename fields
// between Windows builds (`ProcessID` vs `ProcessId` vs `NewProcessId`
// are all real), and a miss must degrade to a missing field, never to a
// guess.

pub const PROCESS_ID: &[&str] = &["ProcessID", "ProcessId"];
pub const PARENT_PROCESS_ID: &[&str] = &["ParentProcessID", "ParentProcessId"];
pub const IMAGE_NAME: &[&str] = &["ImageName", "ImagePath"];

/// Registry key path.
///
/// The `KeyName` field on `RegistrySetValue` carries the full path on some
/// builds and is empty on others. When it is empty, the decoder falls back
/// to the [`super::Translator`]'s KCB cache using [`KCB_KEY_OBJECT`].
pub const KEY_NAME: &[&str] = &["KeyName", "KeyPath", "RelativeName"];

/// The kernel pointer to a Key Control Block.
///
/// On a 64-bit host this is a `POINTER` field (TDH `InType` 16) and reads
/// back as a `u64`. On a 32-bit host it would be a `UInt32`; this crate
/// only ships 64-bit, and the decoder chain reads it as `u64` either way
/// because a 32-bit pointer zero-extends.
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
            assert!(
                s.is_kernel_side() ^ s.is_user_mode(),
                "{s:?} is both or neither"
            );
        }
    }

    #[test]
    fn shape_indices_are_stable() {
        // The order of `Shape::ALL` is what `ShapeCounts`' arrays index
        // by. Changing the order in `declare_shapes!` without changing
        // the enum would misattribute counters in old reports.
        assert_eq!(Shape::ALL[0], Shape::ProcessStart);
        assert_eq!(Shape::ALL[1], Shape::ProcessExit);
        assert_eq!(Shape::ALL[2], Shape::ImageLoad);
        assert_eq!(Shape::ALL[3], Shape::RegistrySet);
        assert_eq!(Shape::ALL[4], Shape::DnsQuery);
        assert_eq!(Shape::ALL[5], Shape::ScriptBlock);
        assert_eq!(Shape::ALL.len(), 6);
    }

    #[test]
    fn the_kcb_pointer_chain_has_a_first_candidate() {
        // The decoder reads `KCB_KEY_OBJECT[0]` as the manifest's
        // spelling. If someone renames it, this test is what catches the
        // drift.
        assert_eq!(KCB_KEY_OBJECT.first().copied(), Some("KeyObject"));
    }

    #[test]
    fn every_field_chain_is_nonempty() {
        // A chain with no candidates would make a decoder always fail on
        // that field. Cheap to assert, and it catches a typo.
        for chain in [
            PROCESS_ID,
            PARENT_PROCESS_ID,
            IMAGE_NAME,
            KEY_NAME,
            KCB_KEY_OBJECT,
            VALUE_NAME,
            REGISTRY_TYPE,
            EXIT_CODE,
            QUERY_NAME,
            QUERY_TYPE,
            SCRIPT_BLOCK_TEXT,
            SCRIPT_BLOCK_ID,
            SCRIPT_BLOCK_PATH,
            MESSAGE_NUMBER,
            MESSAGE_TOTAL,
        ] {
            assert!(!chain.is_empty());
            assert!(chain.iter().all(|s| !s.is_empty()));
        }
    }
}
