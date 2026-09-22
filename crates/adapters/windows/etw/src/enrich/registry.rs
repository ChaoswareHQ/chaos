//! `\REGISTRY\MACHINE\...` → `HKLM\...`.
//!
//! # Why two spellings
//!
//! The Windows registry has three namespaces layered on each other:
//!
//! * The **object manager** namespace, which is what the kernel sees:
//!   `\REGISTRY\MACHINE\SOFTWARE\...`.
//! * The **predefined root keys** — `HKEY_LOCAL_MACHINE`,
//!   `HKEY_USERS`, etc. Handles, not paths.
//! * The **documentation spelling** — `HKLM`, `HKU`, `HKCR`, `HKCU`,
//!   `HKCC`, `HKPD`.
//!
//! `HKLM` is not a path. It is the name of a handle. This module
//! translates the kernel's form to the documentation form so a rule
//! author never has to know the difference.
//!
//! # The boundary check
//!
//! `\REGISTRY\MACHINE` is a prefix of `\REGISTRY\MACHINERY`, and a bare
//! `strip_prefix` matches both. The two are different mount points and
//! translating the second as if it were the first produces a path that
//! looks like `HKLMRY\Foo` — syntactically valid-looking, semantically
//! wrong, and impossible to notice without seeing the input.
//!
//! [`strip_prefix_at_boundary`] is what stops the match: the prefix
//! must be followed by a `\` separator or the end of the string.

use std::borrow::Cow;

/// Translate a kernel registry path to its user-facing form.
///
/// Covers the three mount points that appear in practice. Anything else
/// — a path already in `HKLM\...` form, or an unrecognised mount point —
/// is returned unchanged, which is what makes this safe to call on
/// every path regardless of origin.
pub fn translate(path: &str) -> Cow<'_, str> {
    if let Some(rest) = strip_prefix_at_boundary(path, r"\REGISTRY\MACHINE") {
        return Cow::Owned(format!("HKLM{rest}"));
    }
    if let Some(rest) = strip_prefix_at_boundary(path, r"\REGISTRY\USER") {
        return Cow::Owned(format!("HKU{rest}"));
    }
    if let Some(rest) = strip_prefix_at_boundary(path, r"\REGISTRY\WC") {
        return Cow::Owned(format!("HKWC{rest}"));
    }
    Cow::Borrowed(path)
}

/// Strip `prefix` from `path` only when the prefix is followed by a path
/// separator or the end of the string.
///
/// A bare `strip_prefix` matches `\REGISTRY\MACHINERY` against
/// `\REGISTRY\MACHINE`, which is wrong. The boundary check is what makes
/// the match be the prefix and not a longer name that happens to start
/// with it.
fn strip_prefix_at_boundary<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = path.strip_prefix(prefix)?;
    match rest.as_bytes().first() {
        // Exact match — the path is *only* the prefix.
        None => Some(rest),
        // A separator follows — the prefix is a complete component.
        Some(b'\\') => Some(rest),
        // Something else follows — the prefix is part of a longer
        // component and this is not the mount point we are looking for.
        Some(_) => None,
    }
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
        assert_eq!(
            translate(r"\REGISTRY\UNKNOWN\Foo"),
            r"\REGISTRY\UNKNOWN\Foo"
        );
    }

    #[test]
    fn the_prefix_must_match_at_a_boundary() {
        // `\REGISTRY\MACHINERY` is not `\REGISTRY\MACHINE` + `RY`. The
        // boundary check is what stops the match.
        assert_eq!(
            translate(r"\REGISTRY\MACHINERY\Foo"),
            r"\REGISTRY\MACHINERY\Foo"
        );
        assert_eq!(
            translate(r"\REGISTRY\USERS\Foo"),
            r"\REGISTRY\USERS\Foo",
            "`USERS` is not `USER`"
        );
        assert_eq!(
            translate(r"\REGISTRY\WCRT\Foo"),
            r"\REGISTRY\WCRT\Foo",
            "`WCRT` is not `WC`"
        );
    }

    #[test]
    fn the_machine_prefix_without_a_trailing_backslash_is_translated() {
        // A path that is *exactly* `\REGISTRY\MACHINE` — no subkey.
        assert_eq!(translate(r"\REGISTRY\MACHINE"), r"HKLM");
    }
}
