use crate::process::ProcessId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    ProcessStart(ProcessStart),
    ProcessExit(ProcessExit),
    NetworkConnect(NetworkConnect),
    NetworkDisconnect(NetworkDisconnect),
    FileCreate(FileCreate),
    FileWrite(FileWrite),
    FileDelete(FileDelete),
    FileRename(FileRename),
    RegistrySet(RegistrySet),
    RegistryDelete(RegistryDelete),
    DnsQuery(DnsQueryPayload),
    ImageLoad(ImageLoad),
    ScriptBlock(ScriptBlock),
    WmiProcess(WmiProcess),
    WmiSubscription(WmiSubscription),
    TaskRegistered(TaskRegistered),
    #[serde(other)]
    Unclassified,
}

impl Default for EventKind {
    #[inline]
    fn default() -> Self {
        EventKind::Unclassified
    }
}

impl EventKind {
    #[inline]
    pub const fn as_str(&self) -> &'static str {
        match self {
            EventKind::ProcessStart(_) => "process_start",
            EventKind::ProcessExit(_) => "process_exit",
            EventKind::NetworkConnect(_) => "network_connect",
            EventKind::NetworkDisconnect(_) => "network_disconnect",
            EventKind::FileCreate(_) => "file_create",
            EventKind::FileWrite(_) => "file_write",
            EventKind::FileDelete(_) => "file_delete",
            EventKind::FileRename(_) => "file_rename",
            EventKind::RegistrySet(_) => "registry_set",
            EventKind::RegistryDelete(_) => "registry_delete",
            EventKind::DnsQuery(_) => "dns_query",
            EventKind::ImageLoad(_) => "image_load",
            EventKind::ScriptBlock(_) => "script_block",
            EventKind::WmiProcess(_) => "wmi_process",
            EventKind::WmiSubscription(_) => "wmi_subscription",
            EventKind::TaskRegistered(_) => "task_registered",
            EventKind::Unclassified => "unclassified",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityLevel {
    Untrusted,
    Low,
    Medium,
    MediumPlus,
    High,
    System,
    Protected,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessStart {
    pub pid: ProcessId,
    pub parent_pid: Option<ProcessId>,
    pub executable: Box<str>,
    pub command_line: Option<Box<str>>,
    pub user: Option<Box<str>>,
    pub working_directory: Option<Box<str>>,
    pub started_at: DateTime<Utc>,
    #[serde(default)]
    pub image_hash: Option<Box<str>>,
    #[serde(default)]
    pub integrity_level: Option<IntegrityLevel>,
    #[serde(default)]
    pub is_wow64: bool,
    /// The image name of the process that spawned this one.
    ///
    /// Populated from `Microsoft-Windows-Security-Auditing` event 4688
    /// version 2, which carries `ParentProcessName` directly. The
    /// `Kernel-Process` provider never carries it — only the parent
    /// PID — so a rule that wants the parent's image without a second
    /// lookup uses this field when it is present, and falls back to the
    /// parent PID otherwise.
    ///
    /// `#[serde(default)]` makes this backward-compatible: an old client
    /// that never sets it deserializes to `None` on the server, and an
    /// old server that never reads it accepts a new client's payload
    /// without complaint.
    #[serde(default)]
    pub parent_image: Option<Box<str>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessExit {
    pub pid: ProcessId,
    pub exit_code: Option<i32>,
    pub exited_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkConnect {
    pub pid: ProcessId,
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub destination_ip: IpAddr,
    pub destination_port: u16,
    pub protocol: NetworkProtocol,
    pub initiated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkDisconnect {
    pub pid: ProcessId,
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub destination_ip: IpAddr,
    pub destination_port: u16,
    pub protocol: NetworkProtocol,
    #[serde(default)]
    pub bytes_sent: Option<u64>,
    #[serde(default)]
    pub bytes_received: Option<u64>,
    pub ended_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileCreate {
    pub pid: ProcessId,
    pub path: Box<str>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileWrite {
    pub pid: ProcessId,
    pub path: Box<str>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub bytes_written: Option<u64>,
    pub written_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileDelete {
    pub pid: ProcessId,
    pub path: Box<str>,
    pub deleted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileRename {
    pub pid: ProcessId,
    /// The name the file was renamed from, as far as the provider says.
    ///
    /// On Windows 10/11 `Microsoft-Windows-Kernel-File` id 20 declares exactly
    /// one name field and no old/new pair, and it is often *empty* (43% of 3271
    /// events in one live run) or a fragment rather than a path (`*`, `usr`,
    /// `bin`). It holds the same value as [`Self::new_path`], and the event's
    /// honest reading is "a rename-class operation touched a file whose name
    /// fragment is this", not "the file moved from A to B".
    ///
    /// See the `file_rename` decoder for the verified template and the numbers.
    pub old_path: Box<str>,
    /// The name the file was renamed to, as far as the provider says.
    ///
    /// The rename *target* is not in the telemetry on any Windows build this
    /// crate has checked: it lives in the SetInformation parameter buffer, which
    /// the provider does not decode into a named field. This field exists so a
    /// provider that *can* distinguish the two sides populates them differently,
    /// and so a reader who sees them equal knows the manifest did not distinguish
    /// them rather than that the file was renamed to itself.
    pub new_path: Box<str>,
    pub renamed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistrySet {
    pub pid: ProcessId,
    pub key_path: Box<str>,
    #[serde(default)]
    pub value_name: Option<Box<str>>,
    #[serde(default)]
    pub value_data: Option<Box<str>>,
    pub set_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistryDelete {
    pub pid: ProcessId,
    pub key_path: Box<str>,
    pub deleted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsQueryPayload {
    pub pid: ProcessId,
    pub query_name: Box<str>,
    pub query_type: Box<str>,
    #[serde(default)]
    pub answers: Vec<Box<str>>,
    #[serde(default)]
    pub response_code: Option<Box<str>>,
    pub queried_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImageLoad {
    pub pid: ProcessId,
    pub image_path: Box<str>,
    #[serde(default)]
    pub image_hash: Option<Box<str>>,
    #[serde(default)]
    pub signed: Option<bool>,
    #[serde(default)]
    pub signer: Option<Box<str>>,
    pub loaded_at: DateTime<Utc>,
    #[serde(default)]
    pub is_wow64: bool,
}

/// A script block an interpreter was asked to run (`Microsoft-Windows-PowerShell`
/// id 4104).
///
/// This is what the interpreter was told to *execute*, which is a different and
/// usually more useful thing than what was on its command line: an encoded
/// command, a download cradle, or a whole script. It only exists when Script
/// Block Logging is enabled on the host, so its absence proves nothing.
///
/// # Two honest caveats
///
/// A long script arrives in fragments sharing a [`ScriptBlock::script_block_id`],
/// one per event, with `message_number` counting them and `message_total` saying
/// how many there are. Nothing here reassembles them: a rule reading one fragment
/// sees one fragment, and `message_total > 1` is how a reader can tell that the
/// text in hand is a piece rather than the whole.
///
/// The sensor caps `text`, so a very long block is truncated. The cap is a
/// property of what we ship, not of what the host ran.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScriptBlock {
    pub pid: ProcessId,
    /// The script text, capped by the sensor.
    pub text: Box<str>,
    /// Groups the fragments of one script, when the host supplies it.
    #[serde(default)]
    pub script_block_id: Option<Box<str>>,
    /// The file the block came from, when it came from one. Absent for a block
    /// typed at a prompt or built in memory.
    #[serde(default)]
    pub path: Option<Box<str>>,
    #[serde(default)]
    pub message_number: Option<u32>,
    #[serde(default)]
    pub message_total: Option<u32>,
    pub recorded_at: DateTime<Utc>,
}

/// A process created through WMI (`Microsoft-Windows-WMI-Activity` id 23).
///
/// This is the `T1047` observable. WMI is a living-off-the-land execution
/// channel: a remote or local caller asks `Win32_Process::Create` for a
/// process, and `WmiPrvSE.exe` — a signed Windows binary that is already
/// running — creates it. The attacker never touches a shell on the target, which
/// is why this event is worth its own shape rather than being folded into
/// `ProcessStart`.
///
/// The message template on the reference host reads
/// `CorrelationId = %1; GroupOperationId = %2; OperationId = %3;
/// Commandline= %4; CreatedProcessId = %5; ClientMachine = %6; User = %8;
/// ClientProcessId = %9`, which is where every field below comes from. Note
/// what it does **not** carry: the image path. The command line is the whole
/// story, so it is mandatory here — an id-23 event without one is
/// `undecodable` rather than a `WmiProcess` with nothing to read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WmiProcess {
    /// The process WMI created, not the WMI host that created it.
    pub pid: ProcessId,
    /// The full command line of the created process. Mandatory.
    pub command_line: Box<str>,
    /// The account the caller ran as, as WMI spells it.
    #[serde(default)]
    pub user: Option<Box<str>>,
    /// The process that asked for the creation (normally `WmiPrvSE.exe`).
    #[serde(default)]
    pub client_pid: Option<ProcessId>,
    /// The machine the request came from. Empty or absent for a local caller,
    /// which is the distinction [`Self::is_local`] states directly.
    #[serde(default)]
    pub client_machine: Option<Box<str>>,
    /// `true` when WMI reported the caller as local.
    #[serde(default)]
    pub is_local: Option<bool>,
    pub created_at: DateTime<Utc>,
}

/// A WMI **permanent event subscription** (`Microsoft-Windows-WMI-Activity` id
/// 5861).
///
/// This is `T1546.003`, and it is the highest-signal single event this sensor
/// ships. A permanent subscription is a pair — an event filter and a consumer —
/// that WMI stores in its repository and re-evaluates after every reboot without
/// any process running to trigger it. That is the whole point of it, and it is
/// why the event, not the task or the service, is the one to alert on: there is
/// no binary to find later.
///
/// The message template reads
/// `Namespace = %1; Eventfilter = %2 (refer to its activate eventid:5859);
/// Consumer = %3; PossibleCause = %4`, which is the source of every field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WmiSubscription {
    /// The WMI namespace the subscription lives in (`root\subscription` for
    /// anything that runs a command).
    pub namespace: Box<str>,
    /// The event filter (`ESS`), spelled as WMI spells it.
    pub event_filter: Box<str>,
    /// The consumer that runs when the filter matches. This is where the
    /// payload lives — a `CommandLineEventConsumer` names a command, an
    /// `ActiveScriptEventConsumer` names a script — so a rule that wants to
    /// judge the subscription reads this and not the filter.
    #[serde(default)]
    pub consumer: Option<Box<str>>,
    pub recorded_at: DateTime<Utc>,
}

/// A scheduled task registration (`Microsoft-Windows-TaskScheduler` id 106).
///
/// This is `T1053.005`. The message template reads
/// `User "%2" registered Task Scheduler task "%1"`, and that really is the
/// whole event: a task name and a user context.
///
/// # What this event cannot tell you
///
/// It does not carry the task's action. The command a task will run is in the
/// task's XML, which this provider does not emit; `TaskScheduler` id 129 carries
/// `Path` and `ProcessID` when the task *launches*, and id 200/201 carry
/// `ActionName` when an action runs. So a rule reading id 106 can judge the task
/// name and the account that registered it, and nothing else. Shipping the field
/// that is available, rather than pretending to the one that is not, is why the
/// type has only two fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskRegistered {
    /// The task path and name, as Task Scheduler spells it (for example
    /// `\Microsoft\Windows\UpdateOrchestrator\Schedule Scan`).
    pub task_name: Box<str>,
    /// The account the registration ran as, when the host supplies it.
    #[serde(default)]
    pub user: Option<Box<str>>,
    pub recorded_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProcessId;

    /// One instance of every kind the ETW adapter can currently emit.
    fn emitted_kinds() -> Vec<(EventKind, &'static str)> {
        let now = DateTime::from_timestamp(1_700_000_000, 0).expect("valid instant");
        vec![
            (
                EventKind::WmiProcess(WmiProcess {
                    pid: ProcessId::new(4242),
                    command_line: "cmd.exe /c whoami".into(),
                    user: Some("CORP\\alice".into()),
                    client_pid: Some(ProcessId::new(900)),
                    client_machine: Some("ws-042.corp.example".into()),
                    is_local: Some(false),
                    created_at: now,
                }),
                "wmi_process",
            ),
            (
                EventKind::WmiSubscription(WmiSubscription {
                    namespace: "root\\subscription".into(),
                    event_filter: "SELECT * FROM __InstanceModificationEvent".into(),
                    consumer: Some("CommandLineEventConsumer.Name=\"Updater\"".into()),
                    recorded_at: now,
                }),
                "wmi_subscription",
            ),
            (
                EventKind::TaskRegistered(TaskRegistered {
                    task_name: "\\MicrosoftEdgeUpdate\\MicrosoftUpdate".into(),
                    user: Some("SYSTEM".into()),
                    recorded_at: now,
                }),
                "task_registered",
            ),
        ]
    }

    #[test]
    fn every_emitted_kind_announces_itself_by_name_on_the_wire() {
        // The tag is the whole contract. `EventKind` carries
        // `#[serde(other)]` on `Unclassified`, so a misspelled or renamed tag
        // does not fail to parse — it arrives, counts, and means nothing.
        // Silently. A tag assertion per kind is what makes that loud.
        for (kind, tag) in emitted_kinds() {
            assert_eq!(kind.as_str(), tag, "as_str and the serde tag must agree");

            let json = serde_json::to_string(&kind).expect("serializes");
            assert!(json.contains(&format!("\"kind\":\"{tag}\"")), "{json}");

            let back: EventKind = serde_json::from_str(&json).expect("parses");
            assert_eq!(
                back.as_str(),
                tag,
                "a tag that does not resolve arrives as `unclassified`"
            );
        }
    }

    #[test]
    fn a_wmi_process_is_not_a_process_start_on_the_wire() {
        // Both describe a process being created, and folding them together
        // would lose the one fact T1047 turns on: that WMI — and not a parent
        // process — is what ran it. This pins the separation.
        let kinds = emitted_kinds();
        let (wmi, _) = kinds
            .iter()
            .find(|(kind, _)| matches!(kind, EventKind::WmiProcess(_)))
            .expect("a WmiProcess case");

        assert!(!matches!(wmi, EventKind::ProcessStart(_)));
        assert_ne!(wmi.as_str(), "process_start");
    }

    #[test]
    fn optional_fields_are_omitted_rather_than_faked() {
        // `#[serde(default)]` on an `Option` means an absent fact stays absent
        // in both directions. A `null` that round-trips as `Some("")` is the
        // bug the sensor's "empty string is missing" rule exists to prevent,
        // and it is worth pinning at the model boundary too.
        let subscription = WmiSubscription {
            namespace: "root\\subscription".into(),
            event_filter: "SELECT *".into(),
            consumer: None,
            recorded_at: DateTime::from_timestamp(1_700_000_000, 0).expect("valid"),
        };
        let json = serde_json::to_string(&subscription).expect("serializes");
        assert!(json.contains("\"consumer\":null"), "{json}");
        let back: WmiSubscription = serde_json::from_str(&json).expect("parses");
        assert!(back.consumer.is_none());
    }
}
