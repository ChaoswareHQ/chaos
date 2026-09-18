//! The guards, as pure functions.
//!
//! Isolated from the operating system calls on purpose. These are the rules that
//! decide what the agent must never touch, and they are the part most worth
//! reading carefully — so they are the part with no `unsafe`, no handles, and
//! tests that run anywhere.
//!
//! # The hard case
//!
//! `svchost.exe` is protected. `svchost.exe` running from `%TEMP%` is not.
//!
//! A deny-list keyed on the name would protect the thing this product exists to
//! find, because masquerading is the technique of *naming* a binary after a
//! system process. So a name only protects a process when the process is also
//! running from where the operating system actually keeps its files, and
//! [`Context::windows_dir`] is read from the machine rather than assumed to be
//! `C:\Windows` — an install on another drive is not a rare enough case to guess
//! about when the guess is what stands between a response and `lsass.exe`.

/// Images that must never be suspended or killed **when they are the real
/// thing**, i.e. running from the operating system's own directory.
///
/// Two groups. The first are declared critical processes: killing one bugchecks
/// the machine immediately. The second are the session's own furniture — the
/// shell, the desktop compositor — where killing is survivable but freezing
/// ruins the session, which for a remote operator is indistinguishable.
const CRITICAL_IMAGES: &[&str] = &[
    // Kernel pseudo-processes. pid 0 and 4 are caught before this list is
    // consulted, but naming them keeps the intent explicit.
    "system",
    "registry",
    "memory compression",
    "idle",
    // Declared critical: `TerminateProcess` on any of these is a bugcheck.
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
    // Session furniture. Freezing these does not crash the machine; it removes
    // the operator's desktop, which is the same thing from where they sit.
    "explorer.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    // The host process for services. Some instances are load-bearing, and the
    // ones that are not survive being left alone. Malware masquerading as this
    // name is caught by the directory check, not by this list.
    "svchost.exe",
];

/// What the guards need to know that only the machine can say.
pub struct Context<'a> {
    /// The agent's own process id, which it must never act against.
    pub self_pid: u32,
    /// The agent's own image path, for the same reason — a pid can be recycled.
    pub self_image: &'a str,
    /// The operating system's directory, as reported by the machine.
    pub windows_dir: &'a str,
}

/// A process the agent is considering acting on.
pub struct Target<'a> {
    pub pid: u32,
    pub image: &'a str,
}

/// Guards that need no lookup.
///
/// Checked before the image is resolved so that a refusal on a pseudo-process
/// reads as a refusal, rather than as the access-denied the kernel would return
/// for a handle it will never grant.
pub fn refusal_by_pid(pid: u32, self_pid: u32) -> Option<String> {
    if pid <= 4 {
        return Some(format!(
            "pid {pid} is the idle or system pseudo-process, which has no image to act on"
        ));
    }
    if pid == self_pid {
        return Some("that is this agent; suspending it would end the monitoring".to_string());
    }
    None
}

/// Guards that need to know what the process actually is.
///
/// The image must be known. An empty path means it could not be resolved, and
/// acting on a process whose identity is unknown is the one guess this code is
/// not allowed to make: it would mean the checks below never ran.
pub fn refusal_by_image(target: &Target<'_>, context: &Context<'_>) -> Option<String> {
    let image = target.image.trim();
    if image.is_empty() {
        return Some(format!(
            "pid {} has no resolvable image, so it cannot be checked against the protected set",
            target.pid
        ));
    }

    if same_path(image, context.self_image) {
        return Some("that is this agent's own image".to_string());
    }

    let name = image_name(image);
    let critical = CRITICAL_IMAGES.contains(&name.as_str());
    if critical && under(image, context.windows_dir) {
        return Some(format!(
            "{name} running from {} is a protected system process",
            context.windows_dir
        ));
    }

    None
}

/// The final path component, lowercased.
pub fn image_name(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .trim()
        .to_ascii_lowercase()
}

/// Whether `path` is inside `directory`.
///
/// Requires a separator after the prefix, so `C:\WindowsApps\x.exe` is not inside
/// `C:\Windows`. A prefix match without that boundary is exactly the bug that
/// would let a directory named after the system directory defeat the guard.
///
/// The only caller refuses when this is true, so the direction a mistake can take
/// is the safe one: an over-match protects a process that did not need it. An
/// under-match would let a target walk past the check, which is why both
/// separators are folded first.
pub fn under(path: &str, directory: &str) -> bool {
    let path = normalise(path);
    let directory = normalise(directory);
    if directory.is_empty() {
        // No directory means no protection. The caller treats an unresolvable
        // windows directory as fatal rather than relying on this returning true.
        return false;
    }
    match path.strip_prefix(&directory) {
        Some(rest) => rest.starts_with('\\'),
        None => false,
    }
}

/// Lower-cased, forward slashes folded to back, trailing separators removed.
///
/// Win32 accepts either separator, so `C:/Windows/System32` and
/// `C:\Windows\System32` name the same file. A comparison that treated them as
/// different paths would let a target spelled the other way past the
/// protected-process check, and the whole job of this function is to not do that.
fn normalise(path: &str) -> String {
    path.trim()
        .trim_end_matches(['\\', '/'])
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn same_path(a: &str, b: &str) -> bool {
    !a.is_empty() && !b.is_empty() && a.trim().eq_ignore_ascii_case(b.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> Context<'static> {
        Context {
            self_pid: 1000,
            self_image: "C:\\Program Files\\Chaos\\client.exe",
            windows_dir: "C:\\Windows",
        }
    }

    fn target(pid: u32, image: &'static str) -> Target<'static> {
        Target { pid, image }
    }

    #[test]
    fn the_kernel_pseudo_processes_are_refused() {
        // pid 4 has no image to resolve, so this has to be caught before the
        // lookup or it surfaces as an access-denied from the kernel.
        assert!(refusal_by_pid(0, 1000).is_some());
        assert!(refusal_by_pid(4, 1000).is_some());
        assert!(refusal_by_pid(100, 1000).is_none());
    }

    #[test]
    fn the_agent_will_not_act_on_itself() {
        assert!(refusal_by_pid(1000, 1000).is_some());
        let refusal = refusal_by_image(
            &target(999, "C:\\Program Files\\Chaos\\client.exe"),
            &context(),
        );
        assert!(refusal.is_some(), "same image, recycled pid");
    }

    #[test]
    fn the_real_system_processes_are_protected() {
        for (pid, image) in [
            (700, "C:\\Windows\\System32\\lsass.exe"),
            (712, "C:\\Windows\\System32\\services.exe"),
            (800, "C:\\Windows\\System32\\svchost.exe"),
            (900, "C:\\Windows\\explorer.exe"),
            (901, "C:\\Windows\\System32\\csrss.exe"),
        ] {
            assert!(
                refusal_by_image(&target(pid, image), &context()).is_some(),
                "{image} must be protected"
            );
        }
    }

    #[test]
    fn masquerading_system_processes_are_not_protected() {
        // The whole point. A name-only deny-list would protect the malware.
        for (pid, image) in [
            (2000, "C:\\Users\\user\\AppData\\Local\\Temp\\svchost.exe"),
            (2001, "C:\\Users\\user\\AppData\\Local\\Temp\\lsass.exe"),
            (2002, "C:\\ProgramData\\dropper\\csrss.exe"),
            (2003, "C:\\Users\\user\\Downloads\\explorer.exe"),
        ] {
            assert!(
                refusal_by_image(&target(pid, image), &context()).is_none(),
                "{image} is masquerading and must be actionable"
            );
        }
    }

    #[test]
    fn ordinary_system_binaries_are_actionable() {
        // These live in System32 and are exactly what a response should be able
        // to freeze: `certutil.exe` and `powershell.exe` are the tools.
        for image in [
            "C:\\Windows\\System32\\certutil.exe",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\System32\\rundll32.exe",
        ] {
            assert!(
                refusal_by_image(&target(5000, image), &context()).is_none(),
                "{image} must be actionable"
            );
        }
    }

    #[test]
    fn an_unknown_image_is_refused_rather_than_assumed_safe() {
        // If we cannot say what it is, the checks above did not run, and acting
        // anyway is the one guess this code may not make.
        for image in ["", "   "] {
            assert!(
                refusal_by_image(&target(700, image), &context()).is_some(),
                "an unresolved image must fail closed"
            );
        }
    }

    #[test]
    fn the_directory_boundary_cannot_be_defeated_by_a_prefix() {
        // `C:\WindowsApps` is not inside `C:\Windows`.
        assert!(under("C:\\Windows\\System32\\lsass.exe", "C:\\Windows"));
        assert!(!under("C:\\WindowsApps\\lsass.exe", "C:\\Windows"));
        assert!(!under("C:\\Windows2\\lsass.exe", "C:\\Windows"));
        // Case and trailing separators should not matter.
        assert!(under("c:\\windows\\explorer.exe", "C:\\Windows\\"));
        assert!(under("C:/Windows/System32/lsass.exe", "C:\\Windows"));
        // A directory the machine could not report protects nothing.
        assert!(!under("C:\\Windows\\System32\\lsass.exe", ""));
    }

    #[test]
    fn a_windows_install_on_another_drive_still_protects() {
        // The reason the directory comes from the machine: this must not depend
        // on the operating system being on C:.
        let elsewhere = Context {
            windows_dir: "D:\\Win",
            ..context()
        };
        assert!(
            refusal_by_image(&target(700, "D:\\Win\\System32\\lsass.exe"), &elsewhere).is_some()
        );
        assert!(
            refusal_by_image(&target(700, "C:\\Windows\\System32\\lsass.exe"), &elsewhere)
                .is_none(),
            "the other path is not where this machine keeps its system"
        );
    }

    #[test]
    fn image_names_are_taken_from_the_final_component() {
        assert_eq!(image_name("C:\\Windows\\System32\\lsass.exe"), "lsass.exe");
        assert_eq!(image_name("System"), "system");
        assert_eq!(image_name("lsass.exe"), "lsass.exe");
        assert_eq!(image_name(""), "");
    }
}
