//! `\REGISTRY\MACHINE\...` → `HKLM\...`.
//!
//! # Why two spellings
//!
//! The Windows registry has three namespaces layered on each other:
//!
//! * The **object manager** namespace, which is what the kernel sees:
//!   `\REGISTRY\MACHINE\SOFTWARE\...`. Every kernel structure that names
//!   a registry object uses this form. `SetValueKey` events carry it when
//!   they carry a path at all.
//!
//! * The **predefined root keys** — `HKEY_LOCAL_MACHINE`,
//!   `HKEY_USERS`, etc. These are not paths; they are handles, and they
//!   are the constants the Win32 API takes.
//!
//! * The **documentation spelling** — `HKLM`, `HKU`, `HKCR`, `HKCU`,
//!   `HKCC`, `HKPD`. These are names for the predefined handles that
//!   appear in every registry editor, every Sysinternals tool, and every
//!   ATT&CK rule anyone has written.
//!
//! `HKLM` is not a path. It is the name of a handle. The kernel has never
//! heard of it — no `StartTrace` code path parses the string `"HKLM"`,
//! and the object manager does not maintain an alias table. The
//! translation from `HKLM` to `\REGISTRY\MACHINE` happens in user mode,
//! in `advapi32.dll`, before any kernel call is made.
//!
//! The sensor is a kernel-side observer. Every registry path it emits
//! from TDH comes from walking the KCB, which produces the object-manager
//! form. Every rule author, on the other hand, writes rules in the
//! documentation form. This module translates one to the other at the
//! wire boundary — the same principle as `paths.rs`, applied to a fixed
//! prefix table instead of a machine-specific one.
//!
//! # Why `HKU` and not `HKCU`
//!
//! `HKCU` means "the current user's hive", and the sensor does not know
//! which user a given registry event belongs to — the SID in the path is
//! the fact, and a rule that wants to say "the current user" has to spell
//! out the SID or match any SID under `HKU`. Sysmon resolves it; the
//! sensor has less context, so `HKU\<sid>` is the honest answer.

use std::borrow::Cow;

/// Translate a kernel registry path to its user-facing form.
///
/// Covers the three mount points that appear in practice. Anything else —
/// a path that is already in `HKLM\...` form, or an unrecognised mount
/// point — is returned unchanged, which is what makes this safe to call
/// on every path regardless of origin.
pub fn translate(path: &str) -> Cow<'_, str> {
    if let Some(rest) = path.strip_prefix(r"\REGISTRY\MACHINE") {
        return Cow::Owned(format!("HKLM{rest}"));
    }
    if let Some(rest) = path.strip_prefix(r"\REGISTRY\USER") {
        return Cow::Owned(format!("HKU{rest}"));
    }
    if let Some(rest) = path.strip_prefix(r"\REGISTRY\WC") {
        return Cow::Owned(format!("HKWC{rest}"));
    }
    Cow::Borrowed(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_machine_hive_becomes_hklm() {
        assert_eq!(
            translate(r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        );
    }

    #[test]
    fn the_user_hive_becomes_hku_and_keeps_the_sid() {
        assert_eq!(
            translate(
                r"\REGISTRY\USER\S-1-5-21-1111111111-2222222222-3333333333-1001\Software\Foo"
            ),
            r"HKU\S-1-5-21-1111111111-2222222222-3333333333-1001\Software\Foo"
        );
    }

    #[test]
    fn the_container_hive_becomes_hkwc() {
        assert_eq!(
            translate(r"\REGISTRY\WC\Silo123\Software\Foo"),
            r"HKWC\Silo123\Software\Foo"
        );
    }

    #[test]
    fn an_already_translated_path_is_unchanged() {
        assert_eq!(translate(r"HKLM\SOFTWARE\Foo"), r"HKLM\SOFTWARE\Foo");
        assert_eq!(translate(r"C:\some\file"), r"C:\some\file");
        assert_eq!(translate(""), "");
    }

    #[test]
    fn an_unknown_mount_point_is_unchanged() {
        // Only the three we know about are translated. A future Windows
        // build that adds a fourth mount point returns through this path
        // and produces a path that is still usable, just not the
        // documentation spelling.
        assert_eq!(
            translate(r"\REGISTRY\UNKNOWN\Foo"),
            r"\REGISTRY\UNKNOWN\Foo"
        );
    }

    #[test]
    fn the_prefix_must_match_at_a_boundary() {
        // `\REGISTRY\MACHINERY` is not `\REGISTRY\MACHINE` + `RY`. The
        // `strip_prefix` is exact, so this is a test that it does not
        // over-match. It would if the check were `starts_with` + slicing.
        assert_eq!(
            translate(r"\REGISTRY\MACHINERY\Foo"),
            r"\REGISTRY\MACHINERY\Foo"
        );
    }

    #[test]
    fn the_machine_prefix_without_a_trailing_backslash_is_translated() {
        // A path that is *exactly* `\REGISTRY\MACHINE` — no subkey. Rare
        // but legal: someone can write to the root of HKLM.
        assert_eq!(translate(r"\REGISTRY\MACHINE"), r"HKLM");
    }
}
