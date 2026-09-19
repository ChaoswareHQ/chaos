//! ETW security self-checks.
//!
//! Five layers of detection, each assuming the one below it may have failed:
//!
//! 1. **ntdll export prologues** — matches the first 16 bytes of the ETW
//!    exports against known patch patterns. Fast, and it *names* the
//!    technique, but bypassed by a patch whose first byte lands past the scan
//!    window. The whole-`.text` comparison below is the check that catches
//!    those.
//! 2. **ntdll `.text` comparison** — compares the entire code section of
//!    `ntdll.dll` against the on-disk copy. Catches any byte modification
//!    anywhere in the section, regardless of pattern.
//! 3. **Jump scan** — flags trampolines in the prologue. The scan is
//!    byte-level, not instruction-level, so it can false-positive on a jump
//!    opcode that appears as part of a longer instruction. The `.text`
//!    comparison is the check that has no false positives; the jump scan is a
//!    *naming* convenience that surfaces trampolines for an operator.
//! 4. **Session health** — detects a stopped or reconfigured trace session.
//! 5. **Kernel integrity** — reports whether VBS/HVCI is constraining
//!    kernel-level tampering.
//!
//! None of these *prevent* an attack. They make it **visible**. The goal is
//! that a bypass requires privilege, is deliberate, and leaves evidence.
//!
//! # The residual gap
//!
//! Three bypasses are not caught by any check in this module:
//!
//! - **IAT hooks** — modifying the import table of a *calling* module so the
//!   call never reaches `ntdll`. The bytes in `ntdll` are untouched.
//! - **Hardware breakpoints** — setting `DR0`–`DR3` via a vectored exception
//!   handler. No bytes change, so no byte comparison can see it.
//! - **Detector self-patching** — patching the code of `check_ntdll_exports`
//!   itself. This is the "who watches the watchmen" problem and cannot be
//!   solved from inside the same process.
//!
//! Closing these requires either a separate process reading this one's
//! memory, or kernel-level monitoring. That is the correct architecture for
//! a high-assurance deployment and is documented in the README.

use crate::error::EtwError;
use std::path::PathBuf;
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{MEM_PRIVATE, MEMORY_BASIC_INFORMATION, VirtualQuery};
use windows::core::{PCSTR, PCWSTR};

/// The ETW export functions a user-mode attacker patches.
const ETW_EXPORTS: &[&str] = &[
    "EtwEventWrite",
    "EtwEventWriteFull",
    "EtwEventWriteEx",
    "NtTraceEvent",
];

/// Known patch patterns, as byte sequences.
///
/// **Order matters.** `starts_with` checks a prefix, so a longer pattern must
/// come before any shorter pattern that it begins with. This list is a *hint*
/// — the `.text` comparison catches everything a pattern list would, and
/// more — but it names the technique, which a byte diff alone cannot.
const PATCH_PATTERNS: &[(&str, &[u8])] = &[
    ("xor eax, eax; ret", &[0x31, 0xC0, 0xC3]),
    ("xor eax, eax; ret (alt)", &[0x33, 0xC0, 0xC3]),
    ("mov eax, 0; ret", &[0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3]),
    ("sub eax, eax; ret", &[0x2B, 0xC0, 0xC3]),
    ("ret", &[0xC3]),
    ("int3", &[0xCC]),
    ("jmp short", &[0xEB]),
    ("jmp rel32", &[0xE9]),
];

/// How many bytes of each export to read for the pattern match.
///
/// The matcher sees every 8-byte window that starts within these bytes, so a
/// pattern whose first byte lands at offset `PROLOGUE_SCAN_BYTES - 8 + 1` or
/// later is outside the scan window. The `.text` comparison in
/// [`verify_text_section`] is the check that catches it. The scan is a
/// *naming* convenience, not the load-bearing check.
const PROLOGUE_SCAN_BYTES: usize = 16;

/// A jump instruction found in a function's prologue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpScan {
    /// Byte offset within the scanned range.
    pub offset: usize,
    /// The opcode byte.
    pub opcode: u8,
    /// A short description of the instruction.
    pub description: &'static str,
}

/// The result of checking one export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportIntegrity {
    pub name: &'static str,
    /// The first [`PROLOGUE_SCAN_BYTES`] bytes of the function.
    pub memory_bytes: [u8; PROLOGUE_SCAN_BYTES],
    /// Whether any known patch pattern matches *anywhere* in the scanned
    /// bytes, not just at offset 0.
    pub known_patch: Option<&'static str>,
    /// The offset at which the pattern matched, when it did.
    pub patch_offset: Option<usize>,
    /// Jumps found in the prologue. A real function's prologue does not
    /// begin with a jump; a trampoline does.
    pub jumps: Vec<JumpScan>,
    /// Whether the memory page is private (not file-backed).
    pub private_page: bool,
}

impl ExportIntegrity {
    /// Whether this export appears to have been tampered with.
    pub fn is_suspicious(&self) -> bool {
        self.known_patch.is_some() || !self.jumps.is_empty() || self.private_page
    }

    /// A human-readable reason, when suspicious.
    pub fn reason(&self) -> Option<String> {
        if let Some(patch) = self.known_patch {
            let at = self.patch_offset.unwrap_or(0);
            return Some(format!("patched at offset {at}: {patch}"));
        }
        if let Some(jump) = self.jumps.first() {
            return Some(format!(
                "jump at offset {}: {}",
                jump.offset, jump.description
            ));
        }
        if self.private_page {
            return Some("on a private page (possible tamper)".into());
        }
        None
    }
}

/// Find a known patch pattern in a byte slice.
///
/// Returns the label of the first pattern found and the offset at which it
/// starts. The pattern matches only at the *start* of an 8-byte window, so
/// the search effectively covers offsets `0..=(len - 8)`.
///
/// This is the matcher the prologue check uses, exposed so tests can call
/// it directly and so a caller diagnosing a false positive can see what the
/// matcher found.
pub fn find_patch_in(bytes: &[u8]) -> Option<(&'static str, usize)> {
    if bytes.len() < 8 {
        return None;
    }
    for (offset, window) in bytes.windows(8).enumerate() {
        for (label, pattern) in PATCH_PATTERNS {
            if window.starts_with(pattern) {
                return Some((label, offset));
            }
        }
    }
    None
}

/// The result of comparing `ntdll`'s `.text` section against the on-disk copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextIntegrity {
    /// The path the on-disk copy was read from.
    pub module_path: String,
    /// How many bytes were compared.
    pub text_size: usize,
    /// How many bytes differed.
    pub bytes_differing: usize,
    /// The first offset where a difference was found.
    pub first_difference: Option<usize>,
    /// The first 16 bytes at the first difference, from memory.
    pub first_difference_memory: [u8; 16],
    /// The first 16 bytes at the first difference, from disk.
    pub first_difference_disk: [u8; 16],
}

impl TextIntegrity {
    pub fn is_clean(&self) -> bool {
        self.bytes_differing == 0
    }

    pub fn reason(&self) -> Option<String> {
        if self.is_clean() {
            return None;
        }
        let offset = self.first_difference.unwrap_or(0);
        Some(format!(
            "{} bytes differ from disk, first at offset {offset:#x}",
            self.bytes_differing
        ))
    }
}

/// Check every ETW export in the current process.
pub fn check_ntdll_exports() -> Vec<ExportIntegrity> {
    let Some(ntdll) = load_ntdll() else {
        return Vec::new();
    };

    let mut results = Vec::with_capacity(ETW_EXPORTS.len());

    for name in ETW_EXPORTS {
        let Some(ptr) = resolve_export(ntdll, name) else {
            continue;
        };

        // SAFETY: `ptr` is a valid function address returned by GetProcAddress.
        // Every exported function is at least `PROLOGUE_SCAN_BYTES` long.
        let mut memory_bytes = [0u8; PROLOGUE_SCAN_BYTES];
        unsafe {
            std::ptr::copy_nonoverlapping(
                ptr as *const u8,
                memory_bytes.as_mut_ptr(),
                PROLOGUE_SCAN_BYTES,
            );
        }

        let (known_patch, patch_offset) = match find_patch_in(&memory_bytes) {
            Some((label, offset)) => (Some(label), Some(offset)),
            None => (None, None),
        };

        // Scan for jumps in the prologue. A function whose first bytes are a
        // jump is a trampoline.
        let jumps = scan_for_jumps(&memory_bytes);

        let private_page = page_is_private(ptr);

        results.push(ExportIntegrity {
            name,
            memory_bytes,
            known_patch,
            patch_offset,
            jumps,
            private_page,
        });
    }

    results
}

/// Scan a byte slice for jump instructions.
///
/// A normal function prologue does not begin with a jump. A trampoline does.
/// The scanner is deliberately naive — it walks byte-by-byte and looks for
/// jump opcodes rather than decoding x86 — because a false positive (a `jmp`
/// that happens to be part of an instruction operand) is safer than a false
/// negative.
///
/// Only a jump at offset 0 is reported. A jump later in the prologue is
/// usually part of a legitimate instruction; the `.text` comparison catches
/// those when they are not.
pub fn scan_for_jumps(bytes: &[u8]) -> Vec<JumpScan> {
    let mut jumps = Vec::new();
    for (offset, byte) in bytes.iter().enumerate() {
        let description = match *byte {
            0xE9 => "jmp rel32",
            0xEB => "jmp rel8",
            0xE8 => "call rel32",
            0xCC => "int3",
            _ => continue,
        };
        jumps.push(JumpScan {
            offset,
            opcode: *byte,
            description,
        });
    }
    // A `ret` at offset 0 is a patch, not a trampoline; it is already covered
    // by the pattern list. A jump at offset 0 is the trampoline signal.
    jumps.retain(|j| j.offset == 0);
    jumps
}

/// Compare `ntdll`'s `.text` section in memory against the on-disk copy.
///
/// This is the strongest user-mode check available. It catches any byte
/// modification anywhere in the code section — a patch at offset 32, an
/// unknown return pattern, a trampoline written over the entry point — and
/// it does not depend on a pattern list knowing what the patch looks like.
///
/// It does **not** catch:
/// - IAT hooks (another module's import table is modified, not `ntdll`).
/// - Hardware breakpoints (no bytes change).
/// - A patch that is applied and reverted between two calls to this function.
pub fn verify_text_section() -> Option<TextIntegrity> {
    let ntdll = load_ntdll()?;
    let path = module_path(ntdll)?;
    let (virtual_address, virtual_size, raw_offset) = find_text_section(ntdll)?;

    let disk = std::fs::read(&path).ok()?;
    let disk_start = raw_offset as usize;
    let disk_end = disk_start.checked_add(virtual_size)?;
    let disk_bytes = disk.get(disk_start..disk_end)?;

    // SAFETY: `virtual_address` and `virtual_size` come from the PE header
    // of a loaded module, so the resulting slice is within the module's
    // mapped image.
    let base = ntdll.0 as *const u8;
    let memory_bytes =
        unsafe { std::slice::from_raw_parts(base.add(virtual_address), virtual_size) };

    let mut bytes_differing = 0usize;
    let mut first_difference = None;
    let mut first_difference_memory = [0u8; 16];
    let mut first_difference_disk = [0u8; 16];

    for (i, (m, d)) in memory_bytes.iter().zip(disk_bytes.iter()).enumerate() {
        if m != d {
            bytes_differing += 1;
            if first_difference.is_none() {
                first_difference = Some(i);
                let take = (virtual_size - i).min(16);
                first_difference_memory[..take].copy_from_slice(&memory_bytes[i..i + take]);
                first_difference_disk[..take].copy_from_slice(&disk_bytes[i..i + take]);
            }
        }
    }

    Some(TextIntegrity {
        module_path: path.to_string_lossy().into_owned(),
        text_size: virtual_size,
        bytes_differing,
        first_difference,
        first_difference_memory,
        first_difference_disk,
    })
}

/// Load `ntdll.dll` in the current process.
fn load_ntdll() -> Option<HMODULE> {
    let name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
    unsafe { GetModuleHandleW(PCWSTR(name.as_ptr())) }.ok()
}

/// Resolve an export by name.
fn resolve_export(module: HMODULE, name: &str) -> Option<*const core::ffi::c_void> {
    let name: Vec<u8> = name.bytes().chain(std::iter::once(0)).collect();
    unsafe { GetProcAddress(module, PCSTR(name.as_ptr())) }
        .map(|f| f as usize as *const core::ffi::c_void)
}

/// The full path of a loaded module.
fn module_path(module: HMODULE) -> Option<PathBuf> {
    let mut buf = vec![0u16; 1024];
    let len = unsafe { GetModuleFileNameW(Some(module), &mut buf) };
    if len == 0 {
        return None;
    }
    buf.truncate(len as usize);
    Some(PathBuf::from(String::from_utf16_lossy(&buf)))
}

/// Find the `.text` section of a PE module.
///
/// Returns `(virtual_address, virtual_size, raw_file_offset)`.
fn find_text_section(module: HMODULE) -> Option<(usize, usize, u64)> {
    // SAFETY: the offsets below are the documented PE layout. Each read is
    // guarded by the check that the previous one produced a plausible value.
    unsafe {
        let base = module.0 as *const u8;

        // DOS header: `e_lfanew` at offset 0x3C points to the PE header.
        let e_lfanew = *(base.add(0x3C) as *const i32);
        if e_lfanew < 0 || e_lfanew > 0x1000 {
            return None;
        }
        let nt = base.add(e_lfanew as usize);

        // PE signature "PE\0\0".
        if *(nt as *const u32) != 0x0000_4550 {
            return None;
        }

        // COFF file header follows the signature (20 bytes).
        let coff = nt.add(4);
        let num_sections = *(coff.add(2) as *const u16) as usize;
        let optional_size = *(coff.add(16) as *const u16) as usize;

        // Section headers follow the optional header.
        let sections = coff.add(20 + optional_size);

        for i in 0..num_sections {
            let s = sections.add(i * 40);
            let name = std::slice::from_raw_parts(s, 8);
            if name.starts_with(b".text") {
                let virtual_size = *(s.add(8) as *const u32) as usize;
                let virtual_address = *(s.add(12) as *const u32) as usize;
                let raw_offset = *(s.add(20) as *const u32) as u64;
                if virtual_size == 0 {
                    return None;
                }
                return Some((virtual_address, virtual_size, raw_offset));
            }
        }
    }
    None
}

/// Whether the page containing `addr` is private (not file-backed).
fn page_is_private(addr: *const core::ffi::c_void) -> bool {
    let mut info = MEMORY_BASIC_INFORMATION::default();
    let result = unsafe {
        VirtualQuery(
            Some(addr),
            &mut info,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if result == 0 {
        return false;
    }
    info.Type == MEM_PRIVATE
}

// ---------------------------------------------------------------------------
// Session health
// ---------------------------------------------------------------------------

/// The health of the trace session, as reported by the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionHealth {
    pub running: bool,
    pub real_time: bool,
    pub events_lost: u32,
    pub buffers_lost: u32,
    pub buffers_written: u32,
    /// The session exists but `LogFileMode` no longer includes
    /// `EVENT_TRACE_REAL_TIME_MODE`. Someone reconfigured it.
    pub reconfigured: bool,
}

impl SessionHealth {
    pub fn is_healthy(&self) -> bool {
        self.running && self.real_time && !self.reconfigured
    }

    pub fn problem(&self) -> Option<String> {
        if !self.running {
            return Some("session is not running".into());
        }
        if self.reconfigured {
            return Some("session is no longer real-time (LogFileMode was changed)".into());
        }
        if !self.real_time {
            return Some("session is not real-time".into());
        }
        if self.events_lost > 0 || self.buffers_lost > 0 {
            return Some(format!(
                "{} events lost, {} buffers lost",
                self.events_lost, self.buffers_lost
            ));
        }
        None
    }
}

/// Query the kernel for the session's state.
pub fn session_health(name: &str) -> Result<SessionHealth, EtwError> {
    match crate::session::session_state(name)? {
        Some(state) => Ok(SessionHealth {
            running: true,
            real_time: state.real_time,
            events_lost: state.events_lost,
            buffers_lost: state.buffers_lost,
            buffers_written: state.buffers_written,
            reconfigured: !state.real_time,
        }),
        None => Ok(SessionHealth {
            running: false,
            real_time: false,
            events_lost: 0,
            buffers_lost: 0,
            buffers_written: 0,
            reconfigured: false,
        }),
    }
}

// ---------------------------------------------------------------------------
// Kernel integrity (VBS / HVCI)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelIntegrityStatus {
    pub secure_kernel_running: bool,
    pub hvci_enabled: bool,
    pub hvci_strict: bool,
    pub firmware_page_protection: bool,
}

// NtQuerySystemInformation is exported by ntdll.dll but is not in the
// windows crate's safe bindings, so it is declared here. Rustdoc does not
// generate documentation for extern blocks, which is why these are plain
// `//` comments rather than `///`.
//
// SAFETY: the caller must pass a buffer of at least `len` bytes, and `class`
// must be a valid information class. Only class 0xA5
// (SystemIsolatedUserModeInformation) is used by this module.
unsafe extern "system" {
    fn NtQuerySystemInformation(class: u32, info: *mut u8, len: u32, returned: *mut u32) -> i32;
}

pub fn query_kernel_integrity() -> Option<KernelIntegrityStatus> {
    const SYSTEM_ISOLATED_USER_MODE_INFORMATION: u32 = 0xA5;

    let mut info = [0u8; 16];
    let mut returned: u32 = 0;

    let status = unsafe {
        NtQuerySystemInformation(
            SYSTEM_ISOLATED_USER_MODE_INFORMATION,
            info.as_mut_ptr(),
            info.len() as u32,
            &mut returned,
        )
    };

    if status != 0 {
        return None;
    }

    let byte0 = info[0];
    Some(KernelIntegrityStatus {
        secure_kernel_running: (byte0 & 0x01) != 0,
        hvci_enabled: (byte0 & 0x02) != 0,
        hvci_strict: (byte0 & 0x04) != 0,
        firmware_page_protection: (byte0 & 0x20) != 0,
    })
}

// ---------------------------------------------------------------------------
// Combined report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SecurityReport {
    pub exports: Vec<ExportIntegrity>,
    pub text: Option<TextIntegrity>,
    pub session: SessionHealth,
    pub kernel: Option<KernelIntegrityStatus>,
}

impl SecurityReport {
    pub fn is_healthy(&self) -> bool {
        self.exports.iter().all(|e| !e.is_suspicious())
            && self.text.as_ref().map(|t| t.is_clean()).unwrap_or(false)
            && self.session.is_healthy()
            && self.kernel.map(|k| k.hvci_enabled).unwrap_or(false)
    }

    pub fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();

        for export in &self.exports {
            if let Some(reason) = export.reason() {
                problems.push(format!("{}: {reason}", export.name));
            }
        }

        if let Some(text) = &self.text {
            if let Some(reason) = text.reason() {
                problems.push(format!("ntdll .text: {reason}"));
            }
        }

        if let Some(problem) = self.session.problem() {
            problems.push(format!("session: {problem}"));
        }

        if let Some(kernel) = &self.kernel {
            if !kernel.hvci_enabled {
                problems.push("HVCI is not enabled; kernel tampering is unconstrained".into());
            }
            if !kernel.secure_kernel_running {
                problems.push("VBS secure kernel is not running".into());
            }
        }

        problems
    }
}

pub fn full_report(session_name: &str) -> SecurityReport {
    SecurityReport {
        exports: check_ntdll_exports(),
        text: verify_text_section(),
        session: session_health(session_name).unwrap_or(SessionHealth {
            running: false,
            real_time: false,
            events_lost: 0,
            buffers_lost: 0,
            buffers_written: 0,
            reconfigured: false,
        }),
        kernel: query_kernel_integrity(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntdll_exports_resolve_on_this_machine() {
        let results = check_ntdll_exports();
        assert!(!results.is_empty(), "ntdll.dll should have ETW exports");
    }

    #[test]
    fn a_clean_ntdll_has_no_known_patch() {
        for result in check_ntdll_exports() {
            assert!(result.known_patch.is_none(), "{result:?}");
        }
    }

    #[test]
    fn a_clean_text_section_matches_disk() {
        let integrity = verify_text_section().expect("ntdll .text is readable");
        assert!(
            integrity.is_clean(),
            "ntdll .text should match disk on a clean host: {:?}",
            integrity.reason()
        );
        assert!(integrity.text_size > 0, "the section must have a size");
    }

    #[test]
    fn the_pattern_matcher_only_sees_the_scan_window() {
        // The matcher sees every 8-byte window that starts within
        // `PROLOGUE_SCAN_BYTES`. A 3-byte pattern at position `j` is
        // visible only if a window starts at `j`, i.e. `j` is at most
        // `PROLOGUE_SCAN_BYTES - 8`. A patch that lands past that is
        // invisible to this check — and that is what the `.text`
        // comparison is for.

        // Patch at offset 0: caught.
        let mut at_zero = [0u8; PROLOGUE_SCAN_BYTES];
        at_zero[0..3].copy_from_slice(&[0x31, 0xC0, 0xC3]);
        assert_eq!(find_patch_in(&at_zero), Some(("xor eax, eax; ret", 0)));

        // Patch at offset 8, the last window start: caught.
        let mut at_eight = [0u8; PROLOGUE_SCAN_BYTES];
        at_eight[8..11].copy_from_slice(&[0x31, 0xC0, 0xC3]);
        assert_eq!(find_patch_in(&at_eight), Some(("xor eax, eax; ret", 8)));

        // Patch at offset 9, past the last window start: not caught by
        // this matcher. The `.text` comparison catches it, and that is
        // why both checks exist.
        let mut at_nine = [0u8; PROLOGUE_SCAN_BYTES];
        at_nine[9..12].copy_from_slice(&[0x31, 0xC0, 0xC3]);
        assert_eq!(find_patch_in(&at_nine), None);
    }

    #[test]
    fn find_patch_in_refuses_short_slices() {
        // A slice shorter than the window size cannot contain a match,
        // and returning `None` rather than panicking is the contract.
        assert_eq!(find_patch_in(&[]), None);
        assert_eq!(find_patch_in(&[0x31, 0xC0, 0xC3]), None);
        assert_eq!(find_patch_in(&[0u8; 7]), None);
    }

    #[test]
    fn a_jump_at_offset_zero_is_reported() {
        // A trampoline's first byte is a jump. A normal prologue's is not.
        let mut trampoline = [0u8; PROLOGUE_SCAN_BYTES];
        trampoline[0] = 0xE9;
        let jumps = scan_for_jumps(&trampoline);
        assert_eq!(jumps.len(), 1);
        assert_eq!(jumps[0].offset, 0);
        assert_eq!(jumps[0].description, "jmp rel32");
    }

    #[test]
    fn a_jump_after_offset_zero_is_not_reported() {
        // A jump later in the prologue is usually part of a legitimate
        // instruction. The `.text` comparison is the check for those.
        let mut normal = [0u8; PROLOGUE_SCAN_BYTES];
        normal[0] = 0x40;
        normal[1] = 0x55;
        normal[8] = 0xE9;
        assert!(scan_for_jumps(&normal).is_empty());
    }

    #[test]
    fn a_normal_prologue_has_no_jumps_at_offset_zero() {
        // The real prologue of `EtwEventWrite` is `40 55 57 41 ...`.
        let mut normal = [0u8; PROLOGUE_SCAN_BYTES];
        normal[0] = 0x40;
        normal[1] = 0x55;
        normal[2] = 0x57;
        normal[3] = 0x41;
        assert!(scan_for_jumps(&normal).is_empty());
    }
}
