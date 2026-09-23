//! The bridge between our typed events and the field names a SIGMA rule reads.
//!
//! # Why this exists, and why it is the whole risk
//!
//! SIGMA rules are written against a *log schema*, not against our wire format.
//! A Windows rule says `Image: C:\Windows\Temp\*`, meaning Sysmon's `Image`
//! field; our `EventKind::ProcessStart` calls the same thing `executable`. Every
//! rule therefore needs a translation, and the translation is where this feature
//! is won or lost: a field name we spell differently is a rule that loads, looks
//! healthy, and can never fire.
//!
//! That failure mode is the reason [`Rule::unmapped_fields`] exists. A rule
//! whose detection names a field this module never emits is reported at load
//! rather than discovered by an operator wondering why their ruleset is quiet.
//!
//! [`Rule::unmapped_fields`]: crate::Rule::unmapped_fields
//!
//! # What is mapped, and what is not
//!
//! Only the shapes with an unambiguous SIGMA category are mapped. That is
//! deliberate: inventing a field name for a shape SIGMA has no category for
//! would produce rules that never fire and look healthy, which is the failure
//! this module exists to prevent. WMI and scheduled-task shapes are therefore
//! **not** exposed to SIGMA in this version — their native rules are the only
//! readers — and [`EventView::of`] returns `None` for them.

use model::{EventKind, TelemetryEvent};
use std::collections::BTreeMap;

/// The product every view claims. This sensor is Windows-only.
pub const PRODUCT: &str = "windows";

/// A field's value, in the three shapes a SIGMA comparison needs.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Text(String),
    Int(i64),
    Bool(bool),
}

impl Value {
    /// The value as text, for the string comparisons SIGMA is mostly made of.
    pub fn as_text(&self) -> String {
        match self {
            Value::Text(s) => s.clone(),
            Value::Int(i) => i.to_string(),
            Value::Bool(b) => b.to_string(),
        }
    }

    /// The value as an integer, for the numeric modifiers.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            // SIGMA writes numbers as strings when the log source typed them as
            // strings, so a decimal in a text field is still a number.
            Value::Text(s) => s.trim().parse().ok(),
            Value::Bool(_) => None,
        }
    }
}

/// One event, as a SIGMA rule sees it: a category and a bag of named fields.
#[derive(Debug, Clone)]
pub struct EventView {
    /// The SIGMA `category`, e.g. `process_creation`.
    pub category: &'static str,
    /// The SIGMA `service`, when the category does not already name one.
    pub service: Option<&'static str>,
    fields: BTreeMap<&'static str, Value>,
}

impl EventView {
    /// Build a view, or `None` for a shape with no SIGMA category mapping.
    pub fn of(event: &TelemetryEvent) -> Option<Self> {
        let mut fields: BTreeMap<&'static str, Value> = BTreeMap::new();
        // Every view carries the fields any log line would: the provider, the
        // event id, and the channel. Rules that key on `EventID` (a large share
        // of the Windows ruleset) work through these alone.
        fields.insert("EventID", Value::Int(i64::from(event.event_id)));
        fields.insert(
            "Provider_Name",
            Value::Text(event.provider.as_str().to_string()),
        );
        fields.insert("Channel", Value::Text(event.provider.as_str().to_string()));

        let category = match &event.kind {
            EventKind::ProcessStart(p) => {
                fields.insert("Image", Value::Text(p.executable.to_string()));
                if let Some(cmd) = &p.command_line {
                    fields.insert("CommandLine", Value::Text(cmd.to_string()));
                }
                if let Some(parent) = &p.parent_image {
                    fields.insert("ParentImage", Value::Text(parent.to_string()));
                }
                if let Some(parent) = p.parent_pid {
                    fields.insert("ParentProcessId", Value::Int(i64::from(parent.as_u32())));
                }
                fields.insert("ProcessId", Value::Int(i64::from(p.pid.as_u32())));
                if let Some(user) = &p.user {
                    fields.insert("User", Value::Text(user.to_string()));
                }
                "process_creation"
            }

            EventKind::ProcessExit(e) => {
                fields.insert("ProcessId", Value::Int(i64::from(e.pid.as_u32())));
                if let Some(code) = e.exit_code {
                    // `ExitCode` is written here as the unsigned `NTSTATUS` a
                    // crash carries, because that is the number a rule compares
                    // against (`0xC0000005`), and the model stores it signed.
                    fields.insert("ExitCode", Value::Int(i64::from(code as u32)));
                }
                "process_termination"
            }

            EventKind::ImageLoad(i) => {
                fields.insert("ImageLoaded", Value::Text(i.image_path.to_string()));
                if let Some(signed) = i.signed {
                    fields.insert("Signed", Value::Bool(signed));
                }
                if let Some(signer) = &i.signer {
                    fields.insert("Signature", Value::Text(signer.to_string()));
                }
                fields.insert("ProcessId", Value::Int(i64::from(i.pid.as_u32())));
                "image_load"
            }

            EventKind::RegistrySet(r) => {
                // SIGMA's `TargetObject` is the full registry path including the
                // value name, which is how a rule writes
                // `TargetObject|endswith: '\Run\Updater'`.
                let target = match &r.value_name {
                    Some(name) => format!("{}\\{name}", r.key_path),
                    None => r.key_path.to_string(),
                };
                fields.insert("TargetObject", Value::Text(target));
                if let Some(data) = &r.value_data {
                    fields.insert("Details", Value::Text(data.to_string()));
                }
                fields.insert("ProcessId", Value::Int(i64::from(r.pid.as_u32())));
                "registry_set"
            }

            EventKind::FileCreate(f) => {
                fields.insert("TargetFilename", Value::Text(f.path.to_string()));
                fields.insert("ProcessId", Value::Int(i64::from(f.pid.as_u32())));
                "file_event"
            }

            EventKind::FileDelete(f) => {
                fields.insert("TargetFilename", Value::Text(f.path.to_string()));
                fields.insert("ProcessId", Value::Int(i64::from(f.pid.as_u32())));
                "file_delete"
            }

            EventKind::FileRename(r) => {
                // Both sides hold the same name fragment on Windows 10/11 — see
                // the `file_rename` decoder. Publishing them as if they differed
                // would let a `SourceFilename|endswith` rule match a value that
                // is not a source name.
                fields.insert("TargetFilename", Value::Text(r.new_path.to_string()));
                fields.insert("SourceFilename", Value::Text(r.old_path.to_string()));
                fields.insert("ProcessId", Value::Int(i64::from(r.pid.as_u32())));
                "file_rename"
            }

            EventKind::DnsQuery(d) => {
                fields.insert("QueryName", Value::Text(d.query_name.to_string()));
                if !d.answers.is_empty() {
                    fields.insert("QueryResults", Value::Text(d.answers.join(",")));
                }
                fields.insert("ProcessId", Value::Int(i64::from(d.pid.as_u32())));
                "dns_query"
            }

            EventKind::NetworkConnect(n) => {
                fields.insert("SourceIp", Value::Text(n.source_ip.to_string()));
                fields.insert("SourcePort", Value::Int(i64::from(n.source_port)));
                fields.insert("DestinationIp", Value::Text(n.destination_ip.to_string()));
                fields.insert("DestinationPort", Value::Int(i64::from(n.destination_port)));
                fields.insert(
                    "Protocol",
                    Value::Text(format!("{:?}", n.protocol).to_lowercase()),
                );
                fields.insert("ProcessId", Value::Int(i64::from(n.pid.as_u32())));
                "network_connection"
            }

            EventKind::ScriptBlock(s) => {
                fields.insert("ScriptBlockText", Value::Text(s.text.to_string()));
                if let Some(id) = &s.script_block_id {
                    fields.insert("ScriptBlockId", Value::Text(id.to_string()));
                }
                if let Some(path) = &s.path {
                    fields.insert("Path", Value::Text(path.to_string()));
                }
                fields.insert("ProcessId", Value::Int(i64::from(s.pid.as_u32())));
                "ps_script"
            }

            // No SIGMA category is claimed for these. See the module docs: a
            // guessed field name is a rule that looks healthy and never fires.
            // `network_disconnect` is here with them: SIGMA models a
            // `network_connection` and has no category for the teardown.
            EventKind::WmiProcess(_)
            | EventKind::WmiSubscription(_)
            | EventKind::TaskRegistered(_)
            | EventKind::NetworkDisconnect(_)
            | EventKind::FileWrite(_)
            | EventKind::RegistryDelete(_)
            | EventKind::Unclassified => return None,
        };

        Some(EventView {
            category,
            service: None,
            fields,
        })
    }

    /// One field, by the exact name SIGMA would write.
    pub fn get(&self, field: &str) -> Option<&Value> {
        self.fields.get(field)
    }

    /// Every field name that appears in this view.
    ///
    /// Used by the load-time check that separates a rule that *can* fire from
    /// one that names a field nothing here ever produces.
    pub fn field_names(&self) -> impl Iterator<Item = &&'static str> {
        self.fields.keys()
    }
}

/// The SIGMA category of an event, from its shape alone.
///
/// [`EventView::of`] derives the same string, but it does so while building a
/// `BTreeMap` and a `String` per field. A caller that only needs to know *which*
/// rules could apply — [`crate::RuleSet::evaluate`], before it decides whether a
/// view is worth building at all — should not pay for that, so this reads the
/// kind directly and allocates nothing.
pub fn category_of(event: &TelemetryEvent) -> Option<&'static str> {
    Some(match &event.kind {
        EventKind::ProcessStart(_) => "process_creation",
        EventKind::ProcessExit(_) => "process_termination",
        EventKind::ImageLoad(_) => "image_load",
        EventKind::RegistrySet(_) => "registry_set",
        EventKind::FileCreate(_) => "file_event",
        EventKind::FileDelete(_) => "file_delete",
        EventKind::FileRename(_) => "file_rename",
        EventKind::DnsQuery(_) => "dns_query",
        EventKind::NetworkConnect(_) => "network_connection",
        EventKind::ScriptBlock(_) => "ps_script",
        // No SIGMA category is claimed for these. See the module docs: a guessed
        // field name is a rule that looks healthy and never fires.
        EventKind::WmiProcess(_)
        | EventKind::WmiSubscription(_)
        | EventKind::TaskRegistered(_)
        | EventKind::NetworkDisconnect(_)
        | EventKind::FileWrite(_)
        | EventKind::RegistryDelete(_)
        | EventKind::Unclassified => return None,
    })
}

/// The fields a view of `category` can *ever* carry.
///
/// The union of this and [`UNIVERSAL_FIELDS`] is what a rule is checked against
/// at load. A rule naming anything outside it is reported as unable to fire
/// rather than left to be discovered by its silence.
pub fn known_fields(category: &str) -> &'static [&'static str] {
    match category {
        "process_creation" => &[
            "Image",
            "CommandLine",
            "ParentImage",
            "ParentProcessId",
            "ProcessId",
            "User",
        ],
        "process_termination" => &["ProcessId", "ExitCode"],
        "image_load" => &["ImageLoaded", "Signed", "Signature", "ProcessId"],
        "registry_set" => &["TargetObject", "Details", "ProcessId"],
        "file_event" | "file_delete" => &["TargetFilename", "ProcessId"],
        "file_rename" => &["TargetFilename", "SourceFilename", "ProcessId"],
        "dns_query" => &["QueryName", "QueryResults", "ProcessId"],
        "network_connection" => &[
            "SourceIp",
            "SourcePort",
            "DestinationIp",
            "DestinationPort",
            "Protocol",
            "ProcessId",
        ],
        "ps_script" => &["ScriptBlockText", "ScriptBlockId", "Path", "ProcessId"],
        _ => &[],
    }
}

/// Fields present on every view, whatever the category.
pub const UNIVERSAL_FIELDS: &[&str] = &["EventID", "Provider_Name", "Channel"];

/// Whether a field name could ever appear on a view of `category`.
pub fn field_is_mappable(category: &str, field: &str) -> bool {
    UNIVERSAL_FIELDS.contains(&field) || known_fields(category).contains(&field)
}

/// Every category this module can produce a view for.
pub const CATEGORIES: &[&str] = &[
    "process_creation",
    "process_termination",
    "image_load",
    "registry_set",
    "file_event",
    "file_delete",
    "file_rename",
    "dns_query",
    "network_connection",
    "ps_script",
];

#[cfg(test)]
mod tests {
    use super::*;
    use model::{
        DnsQueryPayload, EventId, EventSource, FileCreate, FileDelete, FileRename, FileWrite,
        HostId, ImageLoad, NetworkConnect, NetworkProtocol, Payload, ProcessExit, ProcessId,
        ProcessStart, ProviderId, RegistrySet, ScriptBlock, Value as ModelValue, WmiProcess,
    };

    fn start(cmd: Option<&str>) -> TelemetryEvent {
        TelemetryEvent::new(
            EventId::new(1),
            HostId::new("host-a").unwrap(),
            chrono::Utc::now(),
            EventSource::WindowsEtw,
            ProviderId::new("Microsoft-Windows-Kernel-Process"),
            1,
            42,
            42,
            4,
            EventKind::ProcessStart(ProcessStart {
                pid: ProcessId::new(42),
                parent_pid: Some(ProcessId::new(4)),
                executable: "C:\\Windows\\Temp\\dropper.exe".into(),
                command_line: cmd.map(Into::into),
                user: None,
                working_directory: None,
                started_at: chrono::Utc::now(),
                image_hash: None,
                integrity_level: None,
                is_wow64: false,
                parent_image: Some("C:\\Windows\\explorer.exe".into()),
            }),
            Payload::empty(),
        )
    }

    #[test]
    fn a_process_start_is_process_creation_with_sysmon_field_names() {
        let event = start(Some("powershell -enc AAAA"));
        let view = EventView::of(&event).expect("mapped");
        assert_eq!(view.category, "process_creation");
        assert_eq!(
            view.get("Image").unwrap().as_text(),
            "C:\\Windows\\Temp\\dropper.exe"
        );
        assert_eq!(
            view.get("CommandLine").unwrap().as_text(),
            "powershell -enc AAAA"
        );
        assert_eq!(
            view.get("ParentImage").unwrap().as_text(),
            "C:\\Windows\\explorer.exe"
        );
        assert_eq!(view.get("ProcessId").unwrap().as_int(), Some(42));
        // The universal fields are on every view.
        assert_eq!(view.get("EventID").unwrap().as_int(), Some(1));
        assert!(view.get("Provider_Name").is_some());
    }

    #[test]
    fn an_absent_field_is_absent_rather_than_empty() {
        // The distinction a `field: null` rule depends on. A command line that
        // was not collected must not read as a command line that was empty.
        let view = EventView::of(&start(None)).expect("mapped");
        assert!(view.get("CommandLine").is_none());
    }

    #[test]
    fn a_shape_with_no_sigma_category_is_not_offered_one() {
        // WMI has no unambiguous SIGMA category, and inventing a field name for
        // it would produce rules that load and never fire.
        let event = TelemetryEvent::new(
            EventId::new(2),
            HostId::new("host-a").unwrap(),
            chrono::Utc::now(),
            EventSource::WindowsEtw,
            ProviderId::new("Microsoft-Windows-Kernel-File"),
            27,
            42,
            42,
            4,
            EventKind::FileDelete(FileDelete {
                pid: ProcessId::new(42),
                path: "C:\\Temp\\a.exe".into(),
                deleted_at: chrono::Utc::now(),
            }),
            Payload::new(ModelValue::Null).unwrap(),
        );
        // file_delete *is* mapped; the universal fields come with it.
        let view = EventView::of(&event).expect("file_delete is mapped");
        assert_eq!(view.category, "file_delete");
        assert_eq!(
            view.get("TargetFilename").unwrap().as_text(),
            "C:\\Temp\\a.exe"
        );
    }

    #[test]
    fn every_claimed_category_has_a_field_list() {
        for category in CATEGORIES {
            assert!(
                !known_fields(category).is_empty(),
                "{category} is claimed but names no fields"
            );
        }
    }

    /// An event of the given shape, with the identity fields filled but nothing
    /// else, so a `kind` can be exercised on its own.
    fn event(kind: EventKind) -> TelemetryEvent {
        TelemetryEvent::new(
            EventId::new(1),
            HostId::new("host-a").unwrap(),
            chrono::Utc::now(),
            EventSource::WindowsEtw,
            ProviderId::new("Microsoft-Windows-Kernel-Process"),
            1,
            42,
            42,
            4,
            kind,
            Payload::empty(),
        )
    }

    #[test]
    fn category_of_agrees_with_the_view_for_every_mapped_kind() {
        // The index in `RuleSet` is keyed on `category_of`; the rules themselves
        // are keyed on the view's category. If the two ever disagree, a rule is
        // silently evaluated for the wrong shape or not at all, so this pins them
        // to each other for every kind either one claims.
        let now = chrono::Utc::now();
        let pid = ProcessId::new(42);
        let cases: Vec<(EventKind, Option<&'static str>)> = vec![
            (
                EventKind::ProcessStart(ProcessStart {
                    pid,
                    parent_pid: Some(ProcessId::new(4)),
                    executable: "C:\\Windows\\Temp\\dropper.exe".into(),
                    command_line: None,
                    user: None,
                    working_directory: None,
                    started_at: now,
                    image_hash: None,
                    integrity_level: None,
                    is_wow64: false,
                    parent_image: None,
                }),
                Some("process_creation"),
            ),
            (
                EventKind::ProcessExit(ProcessExit {
                    pid,
                    exit_code: Some(0),
                    exited_at: now,
                }),
                Some("process_termination"),
            ),
            (
                EventKind::ImageLoad(ImageLoad {
                    pid,
                    image_path: "C:\\Windows\\System32\\ntdll.dll".into(),
                    image_hash: None,
                    signed: Some(true),
                    signer: None,
                    loaded_at: now,
                    is_wow64: false,
                }),
                Some("image_load"),
            ),
            (
                EventKind::RegistrySet(RegistrySet {
                    pid,
                    key_path: "HKLM\\Software\\Run".into(),
                    value_name: Some("Updater".into()),
                    value_data: None,
                    set_at: now,
                }),
                Some("registry_set"),
            ),
            (
                EventKind::FileCreate(FileCreate {
                    pid,
                    path: "C:\\Temp\\a.exe".into(),
                    created_at: now,
                }),
                Some("file_event"),
            ),
            (
                EventKind::FileDelete(FileDelete {
                    pid,
                    path: "C:\\Temp\\a.exe".into(),
                    deleted_at: now,
                }),
                Some("file_delete"),
            ),
            (
                EventKind::FileRename(FileRename {
                    pid,
                    old_path: "C:\\a.tmp".into(),
                    new_path: "C:\\a.exe".into(),
                    renamed_at: now,
                }),
                Some("file_rename"),
            ),
            (
                EventKind::DnsQuery(DnsQueryPayload {
                    pid,
                    query_name: "example.test".into(),
                    query_type: "A".into(),
                    answers: Vec::new(),
                    response_code: None,
                    queried_at: now,
                }),
                Some("dns_query"),
            ),
            (
                EventKind::NetworkConnect(NetworkConnect {
                    pid,
                    source_ip: "10.0.0.1".parse().unwrap(),
                    source_port: 1234,
                    destination_ip: "10.0.0.2".parse().unwrap(),
                    destination_port: 443,
                    protocol: NetworkProtocol::Tcp,
                    initiated_at: now,
                }),
                Some("network_connection"),
            ),
            (
                EventKind::ScriptBlock(ScriptBlock {
                    pid,
                    text: "Invoke-Expression $x".into(),
                    script_block_id: None,
                    path: None,
                    message_number: None,
                    message_total: None,
                    recorded_at: now,
                }),
                Some("ps_script"),
            ),
            // The shapes with no SIGMA category, and the ones a mis-mapped
            // category would otherwise sneak through.
            (
                EventKind::FileWrite(FileWrite {
                    pid,
                    path: "C:\\Temp\\a.log".into(),
                    size: None,
                    bytes_written: None,
                    written_at: now,
                }),
                None,
            ),
            (
                EventKind::WmiProcess(WmiProcess {
                    pid,
                    command_line: "cmd /c whoami".into(),
                    user: None,
                    client_pid: None,
                    client_machine: None,
                    is_local: Some(true),
                    created_at: now,
                }),
                None,
            ),
        ];

        for (kind, expected) in cases {
            let event = event(kind);
            assert_eq!(category_of(&event), expected);
            assert_eq!(EventView::of(&event).map(|v| v.category), expected);
        }
    }
}
