//! NT device path translation.
//!
//! The kernel reports paths as `\Device\HarddiskVolumeN\...` because that
//! is what the kernel sees. Drive letters are a user-mode concept — the
//! mount manager maintains the mapping, and the kernel's ETW providers do
//! not consult it.
//!
//! Every tool that reads those events — Process Explorer, Sysmon,
//! Defender — translates them to the DOS form (`C:\...`) before
//! presenting them, because the DOS form is what a rule author writes.
//! This module does that.
//!
//! # What it does not do
//!
//! The translation covers mounted volumes only. A path on a volume with
//! no drive letter — a hidden recovery partition, a Windows Store app's
//! package volume, a mounted VHD — is returned unchanged. That is the
//! honest answer for a path the user's view of the filesystem does not
//! include, and it keeps the caller from inventing a translation that
//! would not resolve.
//!
//! # Two details that are load-bearing
//!
//! **The device string ends at its NUL.** `QueryDosDeviceW` reports the
//! number of TCHARs written, and on this build that count includes the
//! terminating NUL. Reading the whole reported length produces a device
//! string ending in an invisible `\0`, which `strip_prefix` then fails to
//! match against a path that has no NUL after the volume name. The string
//! is therefore truncated at the first NUL, not at the reported length.
//!
//! **The root has no trailing backslash.** The suffix that `strip_prefix`
//! returns already begins with a `\`, so the replacement root must not
//! end with one. If both have it, the result is `C:\\Windows\...` — a
//! path no user-mode API will resolve.

use std::borrow::Cow;
use std::sync::OnceLock;
use windows::Win32::Storage::FileSystem::{GetLogicalDriveStringsW, QueryDosDeviceW};
use windows::core::PCWSTR;

/// A mapping from NT device paths to DOS drive roots.
#[derive(Debug)]
pub struct DevicePaths {
    /// Device path to DOS drive root, sorted longest-first so a longer
    /// prefix wins over a shorter one. `\Device\HarddiskVolume10` must be
    /// checked before `\Device\HarddiskVolume1`.
    ///
    /// The root is stored **without** a trailing backslash.
    mappings: Vec<(String, String)>,
}

impl DevicePaths {
    /// The process-wide mapping.
    ///
    /// Built once, on first call. The mount table does not change during
    /// a process's lifetime often enough to warrant rebuilding it; a
    /// volume mounted after this crate starts is a rare case, and
    /// returning the unmapped path is the honest fallback.
    pub fn global() -> &'static DevicePaths {
        static INSTANCE: OnceLock<DevicePaths> = OnceLock::new();
        INSTANCE.get_or_init(DevicePaths::build)
    }

    /// Build the mapping from the current drive table.
    fn build() -> Self {
        let mut mappings = Vec::new();

        // `GetLogicalDriveStringsW` writes a sequence of NUL-terminated
        // drive roots ("C:\\\0D:\\\0\0") into the buffer and returns the
        // number of UTF-16 units written, not including the final NUL.
        let mut buffer = vec![0u16; 1024];
        let len = unsafe { GetLogicalDriveStringsW(Some(&mut buffer)) };
        if len == 0 {
            return Self { mappings };
        }

        let mut start = 0usize;
        let end_of_buffer = len as usize;
        while start < end_of_buffer {
            let end = buffer[start..end_of_buffer]
                .iter()
                .position(|c| *c == 0)
                .map(|i| start + i)
                .unwrap_or(end_of_buffer);
            if end == start {
                break;
            }
            let drive = String::from_utf16_lossy(&buffer[start..end]);
            start = end + 1;

            // `QueryDosDeviceW("C:")` returns `\Device\HarddiskVolume3`
            // for the system volume, or the appropriate device for
            // removable media, network shares, and so on.
            let drive_query: Vec<u16> = drive
                .trim_end_matches('\\')
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let mut device_buffer = vec![0u16; 1024];
            let device_len =
                unsafe { QueryDosDeviceW(PCWSTR(drive_query.as_ptr()), Some(&mut device_buffer)) };
            if device_len == 0 {
                continue;
            }

            // The reported length can include the terminating NUL. The
            // device string is what comes before it, so the units are
            // read up to the first NUL rather than to `device_len`. A
            // device string with a trailing `\0` would never match a path
            // in `translate`, and the symptom is a silent failure to
            // translate every image path.
            let units: Vec<u16> = device_buffer
                .iter()
                .take(device_len as usize)
                .take_while(|u| **u != 0)
                .copied()
                .collect();
            if units.is_empty() {
                continue;
            }
            let device = String::from_utf16_lossy(&units);

            // `root` is `C:`, not `C:\`. The suffix from `strip_prefix`
            // already starts with a backslash.
            let root = drive.trim_end_matches('\\').to_string();
            mappings.push((device, root));
        }

        // Longest device path first: `\Device\HarddiskVolume10` must win
        // over `\Device\HarddiskVolume1` when both are prefixes of the
        // path.
        mappings.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        Self { mappings }
    }

    /// Translate an NT device path to its DOS form.
    pub fn translate<'a>(&self, path: &'a str) -> Cow<'a, str> {
        for (device, root) in &self.mappings {
            if let Some(rest) = path.strip_prefix(device.as_str()) {
                return Cow::Owned(format!("{root}{rest}"));
            }
        }
        Cow::Borrowed(path)
    }

    /// Print the current mappings.
    ///
    /// Each line ends with `\` so a reader can see the exact boundary of
    /// the stored root. A NUL in the device string does not render — this
    /// is why the diagnostic prints the byte length alongside the text, so
    /// a trailing NUL that survived the trim would be visible as a length
    /// one greater than the number of characters shown.
    pub fn debug_print(&self) {
        if self.mappings.is_empty() {
            println!("  (no mappings — GetLogicalDriveStringsW or QueryDosDeviceW failed)");
            return;
        }
        for (device, root) in &self.mappings {
            println!(
                "  {device} ({} chars)  ->  {root}\\",
                device.chars().count()
            );
        }
    }

    /// How many mappings were built.
    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    /// Whether the mapping is empty.
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translating_a_path_on_a_mounted_volume_produces_a_dos_form() {
        let paths = DevicePaths::global();
        let raw = r"\Device\HarddiskVolume3\Windows\System32\notepad.exe";
        let translated = paths.translate(raw);
        if translated != raw {
            assert!(
                translated.starts_with(|c: char| c.is_ascii_alphabetic()),
                "a translated path starts with a drive letter: {translated}"
            );
            assert!(translated.contains(":\\"), "{translated}");
            assert!(
                !translated.contains("\\\\"),
                "a translated path has a double backslash: {translated}"
            );
        }
    }

    #[test]
    fn an_unmapped_path_is_returned_unchanged() {
        let paths = DevicePaths::global();
        let raw = r"\Device\SomeUnmappedVolume\foo\bar";
        assert_eq!(paths.translate(raw), raw);
    }

    #[test]
    fn a_dos_path_is_returned_unchanged() {
        let paths = DevicePaths::global();
        let raw = r"C:\Windows\System32\notepad.exe";
        assert_eq!(paths.translate(raw), raw);
    }

    #[test]
    fn a_longer_device_prefix_wins_over_a_shorter_one() {
        let mut mappings = vec![
            (r"\Device\HarddiskVolume1".to_string(), "C:".to_string()),
            (r"\Device\HarddiskVolume10".to_string(), "D:".to_string()),
        ];
        mappings.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        let paths = DevicePaths { mappings };
        assert_eq!(paths.translate(r"\Device\HarddiskVolume10\foo"), r"D:\foo");
        assert_eq!(paths.translate(r"\Device\HarddiskVolume1\foo"), r"C:\foo");
    }

    #[test]
    fn a_synthetic_mapping_translates_as_expected() {
        // The property every caller depends on: a device string and a
        // path that begins with it produce a DOS path with exactly one
        // backslash between the root and the suffix. This test builds the
        // mapping by hand so it does not depend on the host's drive
        // configuration.
        let paths = DevicePaths {
            mappings: vec![(r"\Device\HarddiskVolume3".to_string(), "C:".to_string())],
        };

        assert_eq!(
            paths.translate(r"\Device\HarddiskVolume3\Windows\System32\notepad.exe"),
            r"C:\Windows\System32\notepad.exe"
        );
        assert_eq!(paths.translate(r"\Device\HarddiskVolume3"), r"C:");
    }

    #[test]
    fn an_empty_path_is_returned_unchanged() {
        let paths = DevicePaths::global();
        assert_eq!(paths.translate(""), "");
    }
}
