//! The operating system calls, and the only `unsafe` code in the agent.
//!
//! # Why `NtSuspendProcess` and not `SuspendThread`
//!
//! The documented way to freeze a process is to walk its thread list and suspend
//! each thread. That has a hole: any thread the target spawns *during* the walk is
//! missed, so the process keeps running. A "frozen" process that is still making
//! progress is worse than one you never claimed to freeze, because the operator
//! stops looking at it.
//!
//! `NtSuspendProcess` is one call that stops all of them, and it has been an
//! opaque but stable ntdll export since Windows XP because that is how every
//! debugger and every EDR suspends a process. It is loaded by name rather than
//! linked, because it is not part of the documented surface this crate binds to.

use crate::guard::{self, Context, Target};
use ports::{ActionError, Actuator, Response};
use std::ffi::c_void;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::SystemInformation::GetWindowsDirectoryW;
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE,
    QueryFullProcessImageNameW, TerminateProcess,
};
use windows::core::{PCWSTR, PWSTR, s, w};

/// Largest image path we will read. `MAX_PATH` is not the limit on modern
/// Windows, and a truncated path would silently become a different file.
const IMAGE_PATH_LEN: usize = 512;

/// Response actuation on Windows.
///
/// Every call goes through the guards first. Nothing in this type decides
/// *whether* to act — that is the pipeline's governance step — so the only
/// judgment here is whether the target is something the agent is allowed to
/// touch at all.
pub struct WindowsActuator {
    self_pid: u32,
    self_image: String,
    /// Read from the machine, and an empty string if that failed, which makes
    /// every protected-process check fail closed.
    windows_dir: String,
    /// Resolve and guard, then stop short of the call. The first run on any
    /// machine should be this one.
    dry_run: bool,
}

impl WindowsActuator {
    /// Build an actuator for the current process.
    ///
    /// Falls back to a dry run if the machine will not say where Windows lives,
    /// because that is the input which decides whether `lsass.exe` is protected.
    pub fn new(dry_run: bool) -> Self {
        let windows_dir = windows_directory().unwrap_or_default();
        let dry_run = dry_run || windows_dir.is_empty();
        Self {
            self_pid: std::process::id(),
            self_image: current_image().unwrap_or_default(),
            windows_dir,
            dry_run,
        }
    }

    /// Whether the actuator is resolving and refusing but not acting.
    pub fn is_dry_run(&self) -> bool {
        self.dry_run
    }

    fn context(&self) -> Context<'_> {
        Context {
            self_pid: self.self_pid,
            self_image: &self.self_image,
            windows_dir: &self.windows_dir,
        }
    }
}

impl Actuator for WindowsActuator {
    fn is_dry_run(&self) -> bool {
        self.dry_run
    }

    fn apply(&mut self, response: Response) -> Result<(), ActionError> {
        let pid = response.pid();

        // The cheap refusals first, so pid 4 reads as a refusal rather than as the
        // access-denied the kernel would give us for a handle it never grants.
        if let Some(reason) = guard::refusal_by_pid(pid, self.self_pid) {
            return Err(ActionError::Refused(reason));
        }

        let image = process_image(pid)?;
        let target = Target { pid, image: &image };
        if let Some(reason) = guard::refusal_by_image(&target, &self.context()) {
            return Err(ActionError::Refused(reason));
        }

        if self.dry_run {
            return Ok(());
        }

        match response {
            Response::Suspend { .. } => nt_process_control("NtSuspendProcess", pid),
            Response::Resume { .. } => nt_process_control("NtResumeProcess", pid),
            Response::Terminate { .. } => terminate(pid),
        }
    }
}

/// The image path of a process, or an error if the machine will not say.
fn process_image(pid: u32) -> Result<String, ActionError> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .map_err(|e| ActionError::Os(format!("cannot open pid {pid}: {e}")))?;
        let _guard = HandleGuard(handle);

        let mut buffer = [0u16; IMAGE_PATH_LEN];
        let mut len = buffer.len() as u32;
        QueryFullProcessImageNameW(
            handle,
            windows::Win32::System::Threading::PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut len,
        )
        .map_err(|e| ActionError::Os(format!("cannot read the image of pid {pid}: {e}")))?;

        Ok(String::from_utf16_lossy(&buffer[..len as usize]))
    }
}

/// `NtSuspendProcess` / `NtResumeProcess`, resolved from ntdll at call time.
fn nt_process_control(export: &str, pid: u32) -> Result<(), ActionError> {
    type NtProcessControl = unsafe extern "system" fn(HANDLE) -> i32;

    unsafe {
        let ntdll = windows::Win32::System::LibraryLoader::GetModuleHandleW(w!("ntdll.dll"))
            .map_err(|e| ActionError::Os(format!("ntdll is not loaded: {e}")))?;

        let name = std::ffi::CString::new(export)
            .map_err(|_| ActionError::Os(format!("bad export name {export}")))?;
        let address = windows::Win32::System::LibraryLoader::GetProcAddress(
            ntdll,
            windows::core::PCSTR(name.as_ptr() as *const u8),
        )
        .ok_or_else(|| ActionError::Os(format!("ntdll has no {export} on this build")))?;

        // SAFETY: the signature is the documented one for these exports — a
        // process handle in, an NTSTATUS out — and the export is checked to
        // exist before the cast.
        let control: NtProcessControl = std::mem::transmute(address);

        let handle = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid)
            .map_err(|e| ActionError::Os(format!("cannot open pid {pid}: {e}")))?;
        let _guard = HandleGuard(handle);

        let status = control(handle);
        if status < 0 {
            return Err(ActionError::Os(format!(
                "{export} on pid {pid} returned {status:#010x}"
            )));
        }
    }
    Ok(())
}

fn terminate(pid: u32) -> Result<(), ActionError> {
    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, false, pid)
            .map_err(|e| ActionError::Os(format!("cannot open pid {pid}: {e}")))?;
        let _guard = HandleGuard(handle);
        TerminateProcess(handle, 1)
            .map_err(|e| ActionError::Os(format!("cannot end pid {pid}: {e}")))
    }
}

/// The operating system's directory, as the machine reports it.
///
/// Not `C:\Windows` and not `%SystemRoot%`: the first is wrong on an install
/// elsewhere, and the second is an environment variable anything running as the
/// user could have rewritten before launching us.
fn windows_directory() -> Option<String> {
    unsafe {
        let mut buffer = [0u16; IMAGE_PATH_LEN];
        let len = GetWindowsDirectoryW(Some(&mut buffer));
        if len == 0 || len as usize >= buffer.len() {
            return None;
        }
        Some(String::from_utf16_lossy(&buffer[..len as usize]))
    }
}

fn current_image() -> Option<String> {
    process_image(std::process::id()).ok()
}

/// Closes a handle on the way out of a scope, including an early return.
struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Keeps `PCWSTR` in scope for the bindings that take one.
#[allow(dead_code)]
fn _assert_imports(_: PCWSTR, _: *const c_void) {
    let _ = s!("");
}

/// These call the real bindings on the machine running them, which is the point:
/// a guard test with a hand-written path proves the comparison, not the lookup.
/// Every one is a dry run, so nothing is touched even if a guard were to allow it.
#[cfg(test)]
mod tests {
    use super::*;

    fn dry() -> WindowsActuator {
        WindowsActuator::new(true)
    }

    #[test]
    fn the_windows_directory_is_read_from_the_machine() {
        // The guard's most important input, and the one the fallback exists for:
        // an unresolvable directory forces a dry run rather than leaving system
        // processes unprotected.
        let actuator = WindowsActuator::new(false);
        assert!(
            !actuator.is_dry_run(),
            "this machine should be able to say where Windows lives"
        );
        assert!(
            actuator.windows_dir.contains(':'),
            "expected a drive-qualified path, got {:?}",
            actuator.windows_dir
        );
    }

    #[test]
    fn a_protected_target_is_refused_before_any_handle_is_opened() {
        let mut actuator = dry();
        // pid 4 has no image to resolve, so this must be answered from the pid
        // alone or it surfaces as an access-denied from the kernel.
        assert!(matches!(
            actuator.apply(Response::Suspend { pid: 4 }),
            Err(ActionError::Refused(_))
        ));
        // And the agent will not act on itself.
        assert!(matches!(
            actuator.apply(Response::Suspend {
                pid: std::process::id()
            }),
            Err(ActionError::Refused(_))
        ));
    }

    #[test]
    fn a_target_that_does_not_exist_is_an_os_failure_not_a_refusal() {
        // The two are different things to an operator: a refusal is a guard
        // working, this is the machine reporting there is nothing there.
        let mut actuator = dry();
        assert!(matches!(
            actuator.apply(Response::Resume { pid: 0x7FFF_FFF0 }),
            Err(ActionError::Os(_))
        ));
    }

    #[test]
    fn the_current_process_resolves_to_its_own_image() {
        // What the self-image guard depends on, proven against a real process
        // rather than a string.
        let image = process_image(std::process::id()).expect("our own image must resolve");
        assert!(
            image.to_ascii_lowercase().ends_with(".exe"),
            "expected an executable path, got {image:?}"
        );
    }
}
