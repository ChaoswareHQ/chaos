//! Boot-time sessions: reading what is configured, and saying what to
//! write.
//!
//! A session created by [`crate::boundary::session::EtwSession::start`]
//! begins when the agent does. Everything before that — the services that
//! started, the logon, the Run key that fired during it — happened before
//! there was anything listening, and no amount of care in the consumer
//! recovers it.
//!
//! Windows has a mechanism for exactly this. A subkey under
//! `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger` describes a
//! session, and the kernel starts it during boot, before any user-mode
//! code is in a position to interfere. That is what "system-managed
//! session" means, and it is a real difference rather than a
//! configuration preference:
//!
//! * the session exists from boot, so early-boot activity is captured;
//! * it is not owned by the agent, so an agent restart does not interrupt
//!   it;
//! * its buffers are sized by the registry, at boot, not by whatever
//!   process happens to start first.
//!
//! # What this module does and does not do
//!
//! It **reads** the configuration and reports what is missing, and it
//! **renders** the commands that would create it. It does not write:
//! creating the key needs an elevated token, and a library that quietly
//! rewrites `HKLM` at startup is a library nobody should trust. The
//! operator gets the commands, the exact values they came from, and a
//! verification that says whether they took effect.
//!
//! # The limit of the idea
//!
//! An autologger is not tamper-proof. It is started by the kernel, but it
//! is *configured* by a registry key, and an administrator can stop the
//! session (`logman stop -ets`) or edit the key and reboot. What it buys
//! is that the tampering has to be done deliberately, with privilege, and
//! leaves a trace — which is why [`AutologgerSpec::problems`] exists, so
//! a host can be asked whether its own telemetry is still configured the
//! way it was.

use crate::boundary::session::Buffers;
use crate::error::EtwError;
use crate::util::format_guid;
use std::collections::BTreeMap;
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD, REG_EXPAND_SZ, REG_QWORD, REG_SZ,
    REG_VALUE_TYPE, RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW,
};
use windows::core::{PCWSTR, PWSTR};

/// Where autologger sessions live, under `HKEY_LOCAL_MACHINE`.
pub const AUTOLOGGER_ROOT: &str = r"SYSTEM\CurrentControlSet\Control\WMI\Autologger";

/// `EVENT_TRACE_REAL_TIME_MODE`.
///
/// The flag that makes a session consumable while it runs. Without it the
/// session writes to a file and
/// [`crate::boundary::session::EtwSession::attach`] has nothing to join.
pub const REAL_TIME_MODE: u32 = 0x0000_0100;

/// One provider under a session key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProviderEntry {
    pub enabled: Option<u32>,
    pub level: Option<u32>,
    pub match_any_keyword: Option<u64>,
}

/// What the registry says about a session, as read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AutologgerState {
    /// Whether the session key exists at all.
    pub present: bool,
    /// `Start`: `1` means the session is started at boot.
    pub start: Option<u32>,
    /// The session's GUID, as a string.
    pub guid: Option<String>,
    pub log_file_mode: Option<u32>,
    pub buffer_size_kb: Option<u32>,
    pub minimum_buffers: Option<u32>,
    pub maximum_buffers: Option<u32>,
    pub flush_seconds: Option<u32>,
    /// Provider subkeys, keyed by the subkey name (a `{guid}` string).
    /// Ordered so that rendering it twice produces the same bytes.
    pub providers: BTreeMap<String, ProviderEntry>,
}

impl AutologgerState {
    /// Read the configuration for one session.
    ///
    /// A session that does not exist is `Ok` with `present == false`: an
    /// unconfigured host is a fact to report, not a failure. A refusal is
    /// an error, because "there is nothing here" and "I was not allowed
    /// to look" are different answers.
    pub fn read(session: &str) -> Result<Self, EtwError> {
        let path = format!("{AUTOLOGGER_ROOT}\\{session}");
        let Some(key) = open_key(&path)? else {
            return Ok(Self::default());
        };
        let guard = KeyGuard(key);

        let mut state = Self {
            present: true,
            start: read_u32(guard.0, "Start"),
            guid: read_string(guard.0, "Guid"),
            log_file_mode: read_u32(guard.0, "LogFileMode"),
            buffer_size_kb: read_u32(guard.0, "BufferSize"),
            minimum_buffers: read_u32(guard.0, "MinimumBuffers"),
            maximum_buffers: read_u32(guard.0, "MaximumBuffers"),
            flush_seconds: read_u32(guard.0, "FlushTimer"),
            providers: BTreeMap::new(),
        };

        for name in subkey_names(guard.0) {
            if let Some(sub) = open_key(&format!("{path}\\{name}"))? {
                let sub_guard = KeyGuard(sub);
                state.providers.insert(
                    name,
                    ProviderEntry {
                        enabled: read_u32(sub_guard.0, "Enabled"),
                        level: read_u32(sub_guard.0, "EnableLevel"),
                        match_any_keyword: read_u64(sub_guard.0, "MatchAnyKeyword"),
                    },
                );
            }
        }

        Ok(state)
    }

    /// Whether this session is started at boot.
    pub fn starts_at_boot(&self) -> bool {
        self.start == Some(1)
    }

    /// Whether a live consumer could attach to it.
    pub fn real_time(&self) -> bool {
        self.log_file_mode
            .is_some_and(|mode| mode & REAL_TIME_MODE != 0)
    }
}

/// The session this deployment wants, and the commands that create it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutologgerSpec {
    pub session: String,
    /// The session's GUID as Windows will know it.
    ///
    /// Provided by the caller rather than derived, because a consumer
    /// attaches by *name*: the GUID only has to be stable and unique, and
    /// inventing one by hashing the name would be a guess about an
    /// implementation detail that nothing here depends on.
    pub guid: String,
    pub buffers: Buffers,
    /// `START` is always 1: a session that is not started at boot is not
    /// an autologger.
    pub providers: Vec<crate::boundary::session::ProviderSpec>,
}

impl AutologgerSpec {
    pub fn new(session: impl Into<String>, guid: impl Into<String>) -> Self {
        Self {
            session: session.into(),
            guid: guid.into(),
            buffers: Buffers::default(),
            providers: Vec::new(),
        }
    }

    pub fn with_providers(
        mut self,
        providers: Vec<crate::boundary::session::ProviderSpec>,
    ) -> Self {
        self.providers = providers;
        self
    }

    pub fn with_buffers(mut self, buffers: Buffers) -> Self {
        self.buffers = buffers;
        self
    }

    /// The registry path of the session key.
    pub fn key_path(&self) -> String {
        format!("{AUTOLOGGER_ROOT}\\{}", self.session)
    }

    /// Every command needed to create the session, in order, for an
    /// elevated prompt.
    ///
    /// Rendered rather than applied: see the module docs. The values come
    /// from this struct, so a change to the buffer sizing or the provider
    /// list cannot drift away from the instructions an operator was
    /// given.
    pub fn reg_commands(&self) -> String {
        let key = format!("HKLM\\{}", self.key_path());
        let mut out = String::new();

        let mut add = |path: &str, name: &str, kind: &str, value: String| {
            out.push_str(&format!(
                "reg add \"{path}\" /v {name} /t {kind} /d {value} /f\n"
            ));
        };

        add(&key, "Start", "REG_DWORD", "1".into());
        add(&key, "Guid", "REG_SZ", self.guid.clone());
        add(
            &key,
            "LogFileMode",
            "REG_DWORD",
            format!("0x{:08x}", REAL_TIME_MODE),
        );
        add(
            &key,
            "BufferSize",
            "REG_DWORD",
            format!("0x{:x}", self.buffers.size_kb),
        );
        add(
            &key,
            "MinimumBuffers",
            "REG_DWORD",
            format!("0x{:x}", self.buffers.minimum),
        );
        add(
            &key,
            "MaximumBuffers",
            "REG_DWORD",
            format!("0x{:x}", self.buffers.maximum.max(self.buffers.minimum)),
        );
        add(
            &key,
            "FlushTimer",
            "REG_DWORD",
            format!("0x{:x}", self.buffers.flush_seconds.max(1)),
        );

        for spec in &self.providers {
            let sub = format!("{key}\\{}", format_guid(&spec.guid));
            add(&sub, "Enabled", "REG_DWORD", "1".into());
            add(
                &sub,
                "EnableLevel",
                "REG_DWORD",
                format!("0x{:x}", spec.level),
            );
            add(
                &sub,
                "MatchAnyKeyword",
                "REG_QWORD",
                format!("0x{:016x}", spec.keywords),
            );
        }

        out
    }

    /// What is wrong with a session that was read back, as sentences.
    ///
    /// Empty means the host telemetry is configured as this deployment
    /// expects. Each string is a fact about a specific value, because "the
    /// autologger is broken" is not something an operator can act on.
    pub fn problems(&self, state: &AutologgerState) -> Vec<String> {
        let mut problems = Vec::new();

        if !state.present {
            problems.push(format!(
                "no autologger session named `{}`; the host has no boot-time telemetry",
                self.session
            ));
            return problems;
        }
        if !state.starts_at_boot() {
            problems.push(format!(
                "`Start` is {:?}, so the session is not started at boot",
                state.start
            ));
        }
        if !state.real_time() {
            problems.push(format!(
                "`LogFileMode` is {:?} and does not include EVENT_TRACE_REAL_TIME_MODE \
                 ({REAL_TIME_MODE:#x}), so no consumer can attach",
                state.log_file_mode
            ));
        }
        if state.buffer_size_kb != Some(self.buffers.size_kb) {
            problems.push(format!(
                "`BufferSize` is {:?}, expected {}",
                state.buffer_size_kb, self.buffers.size_kb
            ));
        }
        if state.maximum_buffers != Some(self.buffers.maximum) {
            problems.push(format!(
                "`MaximumBuffers` is {:?}, expected {}",
                state.maximum_buffers, self.buffers.maximum
            ));
        }
        if state.flush_seconds != Some(self.buffers.flush_seconds) {
            problems.push(format!(
                "`FlushTimer` is {:?}, expected {}",
                state.flush_seconds, self.buffers.flush_seconds
            ));
        }

        for spec in &self.providers {
            let name = format_guid(&spec.guid);
            match state.providers.get(&name) {
                None => problems.push(format!(
                    "provider {name} ({}) is not in the session, so nothing it emits is \
                     collected",
                    spec.name
                )),
                Some(entry) if entry.enabled != Some(1) => problems.push(format!(
                    "provider {name} ({}) has `Enabled` = {:?}, expected 1",
                    spec.name, entry.enabled
                )),
                Some(entry) => match entry.match_any_keyword {
                    None => problems.push(format!(
                        "provider {name} ({}) has no `MatchAnyKeyword`, so it is \
                         subscribed to every keyword ({:#x} intended)",
                        spec.name, spec.keywords
                    )),
                    // The check that was missing: an altered mask is a
                    // tamper, and the whole module exists to notice one.
                    // Absent is the only case that used to fire, and absent
                    // is not the shape a tamper actually takes — the
                    // tamper narrows the mask, which silently drops a
                    // subset of the traffic while the check reports
                    // nothing.
                    Some(actual) if spec.keywords != 0 && actual != spec.keywords => {
                        problems.push(format!(
                            "provider {name} ({}) has `MatchAnyKeyword` = {actual:#x}, \
                             expected {:#x}; the session is dropping the difference",
                            spec.name, spec.keywords
                        ));
                    }
                    Some(_) => {}
                },
            }
        }

        problems
    }
}

// ---------------------------------------------------------------------------
// Registry plumbing
// ---------------------------------------------------------------------------

/// Closes a key on every path out of the scope that opened it.
struct KeyGuard(HKEY);

impl Drop for KeyGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Open a key under `HKLM`, or `None` when it does not exist.
fn open_key(path: &str) -> Result<Option<HKEY>, EtwError> {
    let path = wide(path);
    let mut key = HKEY::default();

    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path.as_ptr()),
            None,
            KEY_READ,
            &mut key,
        )
    };
    match rc {
        ERROR_SUCCESS => Ok(Some(key)),
        ERROR_FILE_NOT_FOUND => Ok(None),
        other => Err(EtwError::Registry {
            path: path_to_string(&path),
            code: other.0,
        }),
    }
}

fn path_to_string(units: &[u16]) -> String {
    let trimmed = units.split(|u| *u == 0).next().unwrap_or(units);
    String::from_utf16_lossy(trimmed)
}

/// Read a value's raw bytes and type.
fn read_raw(key: HKEY, name: &str) -> Option<(Vec<u8>, REG_VALUE_TYPE)> {
    let name = wide(name);
    let mut kind = REG_VALUE_TYPE::default();
    let mut size = 0u32;

    // Size first: the values here are small and fixed, but a registry is
    // not a place to assume, and `RegQueryValueExW` writes the needed size
    // back.
    let rc = unsafe {
        RegQueryValueExW(
            key,
            PCWSTR(name.as_ptr()),
            None,
            Some(&mut kind),
            None,
            Some(&mut size),
        )
    };
    if rc != ERROR_SUCCESS || size == 0 {
        return None;
    }

    let mut buf = vec![0u8; size as usize];
    let mut size2 = size;
    let rc = unsafe {
        RegQueryValueExW(
            key,
            PCWSTR(name.as_ptr()),
            None,
            Some(&mut kind),
            Some(buf.as_mut_ptr()),
            Some(&mut size2),
        )
    };
    if rc != ERROR_SUCCESS {
        return None;
    }
    buf.truncate(size2 as usize);
    Some((buf, kind))
}

fn read_u32(key: HKEY, name: &str) -> Option<u32> {
    let (bytes, kind) = read_raw(key, name)?;
    match kind {
        REG_DWORD => bytes
            .get(..4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
        // Windows is happy to store a small number as a QWORD, and a
        // reader that insists on exactly four bytes reports "not set" on a
        // value that is set.
        REG_QWORD => bytes
            .get(..8)
            .map(|b| u32::try_from(u64::from_le_bytes(b[..8].try_into().ok()?)).ok())
            .unwrap_or(None),
        _ => None,
    }
}

fn read_u64(key: HKEY, name: &str) -> Option<u64> {
    let (bytes, kind) = read_raw(key, name)?;
    match kind {
        REG_QWORD => bytes
            .get(..8)
            .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]))),
        REG_DWORD => bytes
            .get(..4)
            .map(|b| u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))),
        _ => None,
    }
}

fn read_string(key: HKEY, name: &str) -> Option<String> {
    let (bytes, kind) = read_raw(key, name)?;
    if kind != REG_SZ && kind != REG_EXPAND_SZ {
        return None;
    }
    // A `wstring` value: UTF-16, normally NUL-terminated, and with or
    // without the terminator in the returned length depending on who
    // wrote it.
    let mut units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    while units.last() == Some(&0) {
        units.pop();
    }
    if units.is_empty() {
        None
    } else {
        Some(String::from_utf16_lossy(&units))
    }
}

fn subkey_names(key: HKEY) -> Vec<String> {
    let mut names = Vec::new();
    let mut index = 0u32;

    loop {
        let mut buf = [0u16; 128];
        let mut len = buf.len() as u32;
        let rc = unsafe {
            RegEnumKeyExW(
                key,
                index,
                Some(PWSTR(buf.as_mut_ptr())),
                &mut len,
                None,
                None,
                None,
                None,
            )
        };
        if rc != ERROR_SUCCESS {
            // `ERROR_NO_MORE_ITEMS` and anything else end the walk: a
            // partial list of subkeys is reported as what it is, not as a
            // complete one.
            break;
        }
        names.push(String::from_utf16_lossy(&buf[..len as usize]));
        index += 1;
    }

    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::session::ProviderSpec;
    use crate::provider;
    use windows::core::GUID;

    /// A session name nothing should be using.
    const ABSENT: &str = "chaos-no-such-autologger-7c41";

    #[test]
    fn an_unconfigured_session_is_reported_as_absent_not_as_an_error() {
        // The distinction the whole self-check rests on.
        let state = AutologgerState::read(ABSENT).expect("a missing key is not a failure");
        assert!(!state.present);
        assert!(!state.starts_at_boot());
        assert!(!state.real_time());
        assert!(state.providers.is_empty());
    }

    #[test]
    fn a_boot_session_can_be_read_off_a_real_machine() {
        // `EventLog-System` is an autologger that ships with Windows, so
        // this exercises the whole read path against a key that exists —
        // the only way to test registry plumbing without writing to the
        // registry. Skips rather than fails on a host that does not have
        // it, because that is a fact about the host and not about this
        // code.
        let Ok(state) = AutologgerState::read("EventLog-System") else {
            return; // a refusal is a host fact; the absent-name test covers the API
        };
        if !state.present {
            return;
        }

        assert_eq!(state.start, Some(1), "a shipping autologger starts at boot");
        assert!(state.guid.is_some(), "a session key carries its GUID");
        assert!(
            !state.providers.is_empty(),
            "a session with no providers could not be logging anything"
        );
        // Every subkey is a provider GUID, and they are readable as such.
        for name in state.providers.keys() {
            assert!(name.starts_with('{') && name.ends_with('}'), "{name}");
        }
    }

    #[test]
    fn an_absent_session_names_every_value_it_is_missing() {
        let spec = AutologgerSpec::new("chaos-sensor", "{11111111-2222-3333-4444-555555555555}")
            .with_providers(provider::default_providers());
        let problems = spec.problems(&AutologgerState::default());

        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains("no autologger session"),
            "{problems:?}"
        );
    }

    #[test]
    fn a_configured_session_reports_no_problems_and_then_its_deviations() {
        let spec = AutologgerSpec::new("chaos-sensor", "{11111111-2222-3333-4444-555555555555}")
            .with_providers(vec![ProviderSpec {
                guid: provider::KERNEL_PROCESS,
                name: "Microsoft-Windows-Kernel-Process",
                level: provider::LEVEL_INFORMATIONAL,
                keywords: provider::KERNEL_PROCESS_KEYWORD_PROCESS
                    | provider::KERNEL_PROCESS_KEYWORD_IMAGE,
            }]);

        let good = AutologgerState {
            present: true,
            start: Some(1),
            guid: Some(spec.guid.clone()),
            log_file_mode: Some(REAL_TIME_MODE),
            buffer_size_kb: Some(spec.buffers.size_kb),
            minimum_buffers: Some(spec.buffers.minimum),
            maximum_buffers: Some(spec.buffers.maximum),
            flush_seconds: Some(spec.buffers.flush_seconds),
            providers: BTreeMap::from([(
                format_guid(&provider::KERNEL_PROCESS),
                ProviderEntry {
                    enabled: Some(1),
                    level: Some(u32::from(provider::LEVEL_INFORMATIONAL)),
                    match_any_keyword: Some(
                        provider::KERNEL_PROCESS_KEYWORD_PROCESS
                            | provider::KERNEL_PROCESS_KEYWORD_IMAGE,
                    ),
                },
            )]),
        };
        assert_eq!(spec.problems(&good), Vec::<String>::new());

        // Now take it apart one value at a time. Each deviation has to be
        // named separately: "the autologger is broken" is not actionable.
        let disabled = AutologgerState {
            start: Some(0),
            ..good.clone()
        };
        assert!(
            spec.problems(&disabled)[0].contains("not started at boot"),
            "{:?}",
            spec.problems(&disabled)
        );

        let to_a_file = AutologgerState {
            log_file_mode: Some(0x0000_0001),
            ..good.clone()
        };
        assert!(
            spec.problems(&to_a_file)[0].contains("EVENT_TRACE_REAL_TIME_MODE"),
            "{:?}",
            spec.problems(&to_a_file)
        );

        let provider_gone = AutologgerState {
            providers: BTreeMap::new(),
            ..good.clone()
        };
        assert!(
            spec.problems(&provider_gone)[0].contains("not in the session"),
            "{:?}",
            spec.problems(&provider_gone)
        );

        let provider_off = AutologgerState {
            providers: BTreeMap::from([(
                format_guid(&provider::KERNEL_PROCESS),
                ProviderEntry {
                    enabled: Some(0),
                    ..Default::default()
                },
            )]),
            ..good
        };
        assert!(
            spec.problems(&provider_off)[0].contains("expected 1"),
            "{:?}",
            spec.problems(&provider_off)
        );
    }

    #[test]
    fn a_narrowed_keyword_mask_is_reported_even_though_the_value_is_present() {
        // The tamper that used to slip through: `MatchAnyKeyword` present,
        // `Enabled` 1, level correct — and the mask quietly narrowed so
        // image loads stop arriving. An absent-value check cannot see
        // this, and it is exactly the shape a tamper takes: nothing is
        // missing, something is smaller.
        let spec = AutologgerSpec::new("chaos-sensor", "{11111111-2222-3333-4444-555555555555}")
            .with_providers(vec![ProviderSpec {
                guid: provider::KERNEL_PROCESS,
                name: "Microsoft-Windows-Kernel-Process",
                level: provider::LEVEL_INFORMATIONAL,
                keywords: provider::KERNEL_PROCESS_KEYWORD_PROCESS
                    | provider::KERNEL_PROCESS_KEYWORD_IMAGE,
            }]);

        let narrowed = AutologgerState {
            present: true,
            start: Some(1),
            guid: Some(spec.guid.clone()),
            log_file_mode: Some(REAL_TIME_MODE),
            buffer_size_kb: Some(spec.buffers.size_kb),
            minimum_buffers: Some(spec.buffers.minimum),
            maximum_buffers: Some(spec.buffers.maximum),
            flush_seconds: Some(spec.buffers.flush_seconds),
            providers: BTreeMap::from([(
                format_guid(&provider::KERNEL_PROCESS),
                ProviderEntry {
                    enabled: Some(1),
                    level: Some(u32::from(provider::LEVEL_INFORMATIONAL)),
                    // Process only: image dropped.
                    match_any_keyword: Some(provider::KERNEL_PROCESS_KEYWORD_PROCESS),
                },
            )]),
        };

        let problems = spec.problems(&narrowed);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains("MatchAnyKeyword"),
            "the message must name the value: {problems:?}"
        );
        assert!(
            problems[0].contains("0x50"),
            "and the expected mask: {problems:?}"
        );
    }

    #[test]
    fn the_rendered_commands_carry_the_values_they_came_from() {
        let spec = AutologgerSpec::new("chaos-sensor", "{11111111-2222-3333-4444-555555555555}")
            .with_providers(vec![ProviderSpec {
                guid: provider::KERNEL_PROCESS,
                name: "Microsoft-Windows-Kernel-Process",
                level: provider::LEVEL_INFORMATIONAL,
                keywords: 0x50,
            }]);
        let commands = spec.reg_commands();

        assert!(commands
            .contains(r"HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\chaos-sensor"));
        assert!(
            commands.contains("/v Start /t REG_DWORD /d 1 /f"),
            "{commands}"
        );
        assert!(commands.contains("0x00000100"), "real time: {commands}");
        assert!(
            commands.contains("/v BufferSize /t REG_DWORD /d 0x80"),
            "{commands}"
        );
        // The provider is a *subkey* of the session, so its GUID follows
        // the separator rather than ending the path.
        assert!(
            commands.contains(r"chaos-sensor\{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}"),
            "the provider subkey is its GUID: {commands}"
        );
        assert!(commands.contains("/v MatchAnyKeyword /t REG_QWORD /d 0x0000000000000050"));

        // One line per value, no blank lines, and nothing that runs by
        // itself: seven session values plus three for the one provider.
        assert_eq!(commands.lines().count(), 7 + 3, "{commands}");
        assert!(commands.lines().all(|l| l.starts_with("reg add \"")));
    }

    #[test]
    fn guids_are_spelled_the_way_windows_spells_them() {
        let guid = GUID::from_u128(0x0011_2233_4455_6677_8899_aabb_ccdd_eeff);
        assert_eq!(format_guid(&guid), "{00112233-4455-6677-8899-aabbccddeeff}");
        assert_eq!(
            format_guid(&provider::KERNEL_PROCESS),
            "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}"
        );
    }
}
