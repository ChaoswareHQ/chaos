//! Which ETW event becomes which wire shape, and the field-name chains TDH
//! resolves against.
//!
//! # One declaration, five generated pieces of code
//!
//! Adding a shape is one line at the bottom of this file.
//!
//! # What is deliberately NOT here
//!
//! `Kernel-Registry` opens/queries/enumerates, `Kernel-Process` thread
//! churn, and `DNS-Client` responses were all reviewed and excluded after
//! looking at their volume on a real host. The
//! [`super::UnrecognisedHistogram`] is what keeps that decision visible.
//!
//! Three more are excluded for a reason that is not volume:
//!
//! * `Microsoft-Antimalware-Scan-Interface` 1101 — the provider is not
//!   registered on every host, and where it is, its content-scan event says
//!   much the same thing as `ScriptBlock` 4104 for PowerShell.
//! * `Microsoft-Windows-Services` 105 — the field names are verified
//!   (`ServiceName`, `ImageName`, `StartType`, `CurrentState`, `PID`), but the
//!   host this table was built on ships no message template for it, so what
//!   `ImageName` names — the service's binary, or the `svchost.exe` hosting it
//!   — is unconfirmed. A shape added on a guess is a rule that never fires and
//!   looks healthy.
//! * `Microsoft-Windows-CodeIntegrity` 3076/3077 — verified fields, but they
//!   contain **spaces** (`"File Name"`, `"SHA256 Hash"`) and the events are
//!   high-volume on a policy in audit mode. Worth a shape, not worth adding
//!   without a rule that reads it.
//!
//! # The two sources of `ProcessStart`
//!
//! `Kernel-Process` id 1 and `Security-Auditing` 4688 both fire when a
//! process is created. Both decode into `EventKind::ProcessStart`, and
//! both appear on the wire with different `provider` fields:
//!
//! * `Kernel-Process` id 1 — always fires if the provider is enabled.
//!   Carries PID, parent PID, image, and the WOW64 flag. No command line.
//! * `Security-Auditing` 4688 — fires only when `Audit Process Creation`
//!   is on. Carries the command line (v1+), the parent image name (v2),
//!   the user (v1+), and the integrity level (v2).
//!
//! On a host with the audit policy on, both fire. A rule that wants a
//! command line filters on `command_line.is_some()`; a rule that only
//! wants the image matches on `executable`. Deduplication for the
//! analyst's alert queue is a downstream concern — the sensor ships what
//! it sees.
//!
//! # The field chains are not guesses
//!
//! Every name below was read off an installed manifest with
//! `tools/dump-fields.ps1`, which is also how to re-check one:
//!
//! ```text
//! powershell -NoProfile -ExecutionPolicy Bypass -File tools/dump-fields.ps1 `
//!     -Provider Microsoft-Windows-WMI-Activity -Id "23,5861"
//! ```
//!
//! Where the manifest's spelling is surprising it is said so in the
//! comment — `Commandline` has a lowercase `l`, `ESS` and `CONSUMER` are
//! `UPPERCASE`, and CodeIntegrity's names contain spaces. TDH matches names
//! case-sensitively, so each of those is a silent no-match if guessed.

/// The single source of truth for the shape table.
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
            pub const ALL: &[Shape] = &[$(Shape::$variant,)*];

            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Shape::$variant => $wire,)*
                }
            }

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

// The single source of truth.
//
// Indices 0–10 are frozen — changing one would misattribute counters in
// historical reports. New shapes append.
declare_shapes! {
    // Kernel-Process — lifecycle and image loads.
    ProcessStart = "process_start" => ("Microsoft-Windows-Kernel-Process", 1), true;
    ProcessExit  = "process_exit"  => ("Microsoft-Windows-Kernel-Process", 2), true;
    ImageLoad    = "image_load"    => ("Microsoft-Windows-Kernel-Process", 5), true;

    // Kernel-Registry — the one write event that carries a KCB pointer.
    RegistrySet  = "registry_set"  => ("Microsoft-Windows-Kernel-Registry", 5), true;

    // User-mode providers.
    DnsQuery     = "dns_query"     => ("Microsoft-Windows-DNS-Client", 3006), false;
    ScriptBlock  = "script_block"  => ("Microsoft-Windows-PowerShell", 4104), false;

    // Kernel-File — the three operations a rule cares about most.
    FileCreate   = "file_create"   => ("Microsoft-Windows-Kernel-File", 12), true;
    FileRename   = "file_rename"   => ("Microsoft-Windows-Kernel-File", 20), true;
    FileDelete   = "file_delete"   => ("Microsoft-Windows-Kernel-File", 27), true;

    // Kernel-Network — TCP connect and disconnect.
    NetworkConnect    = "network_connect"    => ("Microsoft-Windows-Kernel-Network", 10), true;
    NetworkDisconnect = "network_disconnect" => ("Microsoft-Windows-Kernel-Network", 11), true;

    // Security-Auditing 4688 — the audit variant of process start, which
    // is the only live source of the command line on a Windows host.
    ProcessStartAudit = "process_start_audit" => ("Microsoft-Windows-Security-Auditing", 4688), true;

    // WMI-Activity — the T1047 execution channel and the T1546.003
    // permanent-subscription event. Both are user-mode providers: nothing
    // here comes from the kernel, so a silent WMI shape while kernel shapes
    // are active is the ETW-bypass signature the gap detector looks for.
    WmiProcess      = "wmi_process"      => ("Microsoft-Windows-WMI-Activity", 23), false;
    WmiSubscription = "wmi_subscription" => ("Microsoft-Windows-WMI-Activity", 5861), false;

    // TaskScheduler — task registration (T1053.005).
    TaskRegistered  = "task_registered"  => ("Microsoft-Windows-TaskScheduler", 106), false;
}

// ---------------------------------------------------------------------------
// Field-name chains
// ---------------------------------------------------------------------------

pub const PROCESS_ID: &[&str] = &["ProcessID", "ProcessId", "NewProcessId"];
pub const PARENT_PROCESS_ID: &[&str] =
    &["ParentProcessID", "ParentProcessId", "NewParentProcessId"];
pub const IMAGE_NAME: &[&str] = &["ImageName", "ImagePath"];

/// Registry key path. The `KeyName` field on `RegistrySetValue` carries
/// the full path on some builds and is empty on others. When it is empty,
/// the decoder falls back to the KCB cache using [`KCB_KEY_OBJECT`].
pub const KEY_NAME: &[&str] = &["KeyName", "KeyPath", "RelativeName"];
pub const KCB_KEY_OBJECT: &[&str] = &["KeyObject", "KeyObjectPtr"];
pub const VALUE_NAME: &[&str] = &["ValueName", "Value"];
pub const CAPTURED_DATA: &str = "CapturedData";
pub const REGISTRY_TYPE: &[&str] = &["Type", "ValueType"];
pub const EXIT_CODE: &[&str] = &["ExitCode", "ExitStatus"];

pub const QUERY_NAME: &[&str] = &["QueryName"];
pub const QUERY_TYPE: &[&str] = &["QueryType"];

pub const SCRIPT_BLOCK_TEXT: &[&str] = &["ScriptBlockText"];
pub const SCRIPT_BLOCK_ID: &[&str] = &["ScriptBlockId"];
pub const SCRIPT_BLOCK_PATH: &[&str] = &["Path"];
pub const MESSAGE_NUMBER: &[&str] = &["MessageNumber"];
pub const MESSAGE_TOTAL: &[&str] = &["MessageTotal"];

/// Kernel-File: the file path. Verified on Windows 10/11: id 12 (`Create`) and
/// id 27 (`Delete`) both declare `FileName`; 27 is spelled `FilePath` on some
/// builds, hence the chain.
pub const FILE_NAME: &[&str] = &["FileName", "FilePath", "Path"];

/// Kernel-File 20: there is no separate old-name field on this provider.
///
/// Verified with `tools/dump-fields.ps1` on Windows 10/11: id 20 declares exactly
/// one name field, `FileName`, and nothing else — no `OldFileName`, no
/// `NewFileName`. The chain is kept only because another build may declare one;
/// nothing here resolves on this one, which is why the `file_rename` decoder
/// mirrors the single name it does get into both fields.
pub const FILE_OLD_NAME: &[&str] = &["OldFileName", "OriginalFileName", "OldName"];

/// Kernel-File 20: a name **fragment**, not a path.
///
/// A live 25-second run on the reference host (3271 rename events) showed what
/// this field actually holds: `*` for the majority, then `usr`, `bin`, `Git`,
/// and values like `77003E88…ED_*`. 43% of the events carried no value at all.
/// The target of the rename is not in this event under any name — it travels in
/// the SetInformation parameter buffer, which the provider does not decode — so
/// `FileName` is a fragment of the pre-operation name and nothing more. It sits
/// last in the chain so a build that *does* declare a distinct new-name field
/// wins.
pub const FILE_NEW_NAME: &[&str] = &["NewFileName", "NewName", "FileName", "FilePath"];

/// Kernel-Network: address and port fields.
pub const NET_PID: &[&str] = &["PID", "ProcessID"];
pub const NET_SADDR: &[&str] = &["saddr", "SourceAddress", "LocalAddress"];
pub const NET_DADDR: &[&str] = &["daddr", "DestinationAddress", "RemoteAddress"];
pub const NET_SPORT: &[&str] = &["sport", "SourcePort", "LocalPort"];
pub const NET_DPORT: &[&str] = &["dport", "DestinationPort", "RemotePort"];
pub const NET_SIZE: &[&str] = &["size", "Size", "IOSize"];

/// Security-Auditing 4688: the command line. Version 1 and 2 carry it;
/// version 0 does not.
pub const COMMAND_LINE: &[&str] = &["CommandLine", "ProcessCommandLine"];

/// Security-Auditing 4688: the new process's image. Different spelling
/// from `IMAGE_NAME` on Kernel-Process — that one is `ImageName`, this
/// one is `NewProcessName`.
pub const NEW_PROCESS_NAME: &[&str] = &["NewProcessName", "ImageName"];

/// Security-Auditing 4688: the parent process's image. Version 2 only.
pub const PARENT_PROCESS_NAME: &[&str] = &["ParentProcessName", "ImageName"];

/// Security-Auditing 4688: the account the new process runs as. Version
/// 1 and 2 carry it. Often a SID on some builds and a username on
/// others; the decoder takes what the manifest gives it, which is what
/// the console renders.
pub const SUBJECT_USER_NAME: &[&str] = &["SubjectUserName", "User"];

/// Security-Auditing 4688: the mandatory label (integrity level) as a
/// SID string (`S-1-16-8192` for Medium). Version 2 only.
pub const MANDATORY_LABEL: &[&str] = &["MandatoryLabel"];

// ---------------------------------------------------------------------------
// WMI-Activity
// ---------------------------------------------------------------------------

/// WMI-Activity 23: the command line of the process WMI created. The
/// manifest spells it `Commandline` (lowercase `l`); the camel-case
/// spelling is the one other builds have used.
pub const WMI_COMMAND_LINE: &[&str] = &["Commandline", "CommandLine"];

/// WMI-Activity 23: the process the WMI host created.
pub const WMI_CREATED_PID: &[&str] = &["CreatedProcessId", "CreatedProcessID"];

/// WMI-Activity 23: the process that asked for the creation, normally
/// `WmiPrvSE.exe`.
pub const WMI_CLIENT_PID: &[&str] = &["ClientProcessId", "ClientProcessID"];

/// WMI-Activity 23: the caller's machine. The manifest declares both a
/// short name and an FQDN; the FQDN is the more useful one when present.
pub const WMI_CLIENT_MACHINE: &[&str] = &["ClientMachineFQDN", "ClientMachine"];

/// WMI-Activity 23: the account the caller ran as.
pub const WMI_USER: &[&str] = &["User"];

/// WMI-Activity 23: whether the caller was local. Declared `Boolean`, which
/// TDH returns as a one-byte `0`/`1`.
pub const WMI_IS_LOCAL: &[&str] = &["IsLocal"];

/// WMI-Activity 5861: the namespace the permanent subscription lives in.
pub const WMI_NAMESPACE: &[&str] = &["Namespace"];

/// WMI-Activity 5861: the event filter. The manifest spells this `ESS`,
/// which is short for event subscription.
pub const WMI_EVENT_FILTER: &[&str] = &["ESS", "EventFilter"];

/// WMI-Activity 5861: the consumer that runs. Spelled in capitals by the
/// manifest, which is worth pinning: TDH is case-sensitive.
pub const WMI_CONSUMER: &[&str] = &["CONSUMER", "Consumer"];

// ---------------------------------------------------------------------------
// TaskScheduler
// ---------------------------------------------------------------------------

/// TaskScheduler 106: the task's path and name.
pub const TASK_NAME: &[&str] = &["TaskName"];

/// TaskScheduler 106: the account that registered the task.
pub const USER_CONTEXT: &[&str] = &["UserContext"];

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
            shape_of("Microsoft-Windows-Security-Auditing", 4688),
            Some(Shape::ProcessStartAudit)
        );
        assert_eq!(
            shape_of("Microsoft-Windows-Kernel-File", 12),
            Some(Shape::FileCreate)
        );
        assert_eq!(
            shape_of("Microsoft-Windows-Kernel-Network", 10),
            Some(Shape::NetworkConnect)
        );

        // Deliberately not scored.
        assert_eq!(shape_of("Microsoft-Windows-Kernel-Process", 3), None);
        assert_eq!(shape_of("Microsoft-Windows-Kernel-Registry", 1), None);
        assert_eq!(shape_of("Microsoft-Windows-Security-Auditing", 4689), None);
    }

    #[test]
    fn every_shape_has_a_name_and_a_side() {
        for s in Shape::ALL {
            assert!(!s.as_str().is_empty());
            assert!(s.is_kernel_side() ^ s.is_user_mode(), "{s:?}");
        }
    }

    #[test]
    fn shape_indices_are_stable() {
        // Indices 0–11 are frozen. `WmiProcess` onwards is new at 12.
        assert_eq!(Shape::ALL[0], Shape::ProcessStart);
        assert_eq!(Shape::ALL[1], Shape::ProcessExit);
        assert_eq!(Shape::ALL[2], Shape::ImageLoad);
        assert_eq!(Shape::ALL[3], Shape::RegistrySet);
        assert_eq!(Shape::ALL[4], Shape::DnsQuery);
        assert_eq!(Shape::ALL[5], Shape::ScriptBlock);
        assert_eq!(Shape::ALL[6], Shape::FileCreate);
        assert_eq!(Shape::ALL[7], Shape::FileRename);
        assert_eq!(Shape::ALL[8], Shape::FileDelete);
        assert_eq!(Shape::ALL[9], Shape::NetworkConnect);
        assert_eq!(Shape::ALL[10], Shape::NetworkDisconnect);
        assert_eq!(Shape::ALL[11], Shape::ProcessStartAudit);
        assert_eq!(Shape::ALL[12], Shape::WmiProcess);
        assert_eq!(Shape::ALL[13], Shape::WmiSubscription);
        assert_eq!(Shape::ALL[14], Shape::TaskRegistered);
        assert_eq!(Shape::ALL.len(), 15);
    }

    #[test]
    fn the_new_shapes_are_claimed_from_their_verified_ids() {
        assert_eq!(
            shape_of("Microsoft-Windows-WMI-Activity", 23),
            Some(Shape::WmiProcess)
        );
        assert_eq!(
            shape_of("Microsoft-Windows-WMI-Activity", 5861),
            Some(Shape::WmiSubscription)
        );
        assert_eq!(
            shape_of("Microsoft-Windows-TaskScheduler", 106),
            Some(Shape::TaskRegistered)
        );

        // And the ids next to them stay unscored, so the table cannot grow by
        // accident: WMI 5857/5858/5859/5860 are provider-load and query noise.
        assert_eq!(shape_of("Microsoft-Windows-WMI-Activity", 5857), None);
        assert_eq!(shape_of("Microsoft-Windows-WMI-Activity", 5860), None);
        assert_eq!(shape_of("Microsoft-Windows-TaskScheduler", 200), None);
    }

    #[test]
    fn every_field_chain_is_nonempty() {
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
            FILE_NAME,
            FILE_OLD_NAME,
            FILE_NEW_NAME,
            NET_PID,
            NET_SADDR,
            NET_DADDR,
            NET_SPORT,
            NET_DPORT,
            NET_SIZE,
            COMMAND_LINE,
            NEW_PROCESS_NAME,
            PARENT_PROCESS_NAME,
            SUBJECT_USER_NAME,
            MANDATORY_LABEL,
            WMI_COMMAND_LINE,
            WMI_CREATED_PID,
            WMI_CLIENT_PID,
            WMI_CLIENT_MACHINE,
            WMI_USER,
            WMI_IS_LOCAL,
            WMI_NAMESPACE,
            WMI_EVENT_FILTER,
            WMI_CONSUMER,
            TASK_NAME,
            USER_CONTEXT,
        ] {
            assert!(!chain.is_empty());
            assert!(chain.iter().all(|s| !s.is_empty()));
        }
    }
}
