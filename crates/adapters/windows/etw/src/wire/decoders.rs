//! Per-shape decoders.
//!
//! Each returns `Result<EventKind, String>` where the `Err` string names
//! the field that was missing or empty. Callers log it via
//! [`super::Translator`]'s failure log and increment `undecodable`; the
//! reason must be specific enough that an operator can act on it, which
//! is why "no ImageName" is not "decode failed".
//!
//! # Two rules this module holds to
//!
//! * **Empty string is missing.** A field that resolves to `""` is treated
//!   the same as a field that did not resolve. The registry-key bug that
//!   produced `key=` in production was exactly this: TDH returned an
//!   empty string and the old decoder accepted it as a value.
//! * **A shape is not `mapped` until its mandatory fields are present.**
//!   `note_mapped` fires only after the decoder returns `Ok`.
//!
//! # Enrichments over the raw event
//!
//! * `registry_set` reads the path from the KCB cache when the manifest's
//!   `KeyName` is empty, then translates it to the documentation spelling
//!   (`\REGISTRY\MACHINE\...` → `HKLM\...`).
//! * `image_load` fills `image_hash`, `signed`, and `signer` from the
//!   image-metadata cache.
//! * `file_*` translate `\Device\HarddiskVolumeN\...` to DOS form.
//! * `network_*` decode the `UInt32` `saddr`/`daddr` fields the kernel
//!   provider emits into `IpAddr`, with a fallback for builds that
//!   declare them `Binary`.
//! * `process_start_audit` reads the audit variant of process start,
//!   which is the only live source of the command line.
//! * `wmi_process` and `wmi_subscription` read the two WMI-Activity shapes:
//!   the `T1047` execution channel and the `T1546.003` permanent
//!   subscription.
//! * `task_registered` reads a Task Scheduler registration.

use super::Translator;
use super::shape::*;
use crate::boundary::callback::EtwRaw;
use crate::decode::FieldValue;
use crate::enrich::{image::ImageMeta, paths::DevicePaths, registry};
use chrono::{DateTime, Utc};
use model::{
    DnsQueryPayload, EventKind, FileCreate, FileDelete, FileRename, ImageLoad, IntegrityLevel,
    NetworkConnect, NetworkDisconnect, NetworkProtocol, ProcessExit, ProcessId, ProcessStart,
    RegistrySet, ScriptBlock, TaskRegistered, WmiProcess, WmiSubscription,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

impl Translator {
    // ---------------------------------------------------------------------
    // Kernel-Process
    // ---------------------------------------------------------------------

    /// Decode `Microsoft-Windows-Kernel-Process` id 1.
    ///
    /// The kernel provider's process-start event. It always fires when the
    /// provider is enabled, carries the image name and both PIDs, and
    /// carries **no command line** — that field does not exist in the
    /// manifest on any Windows build. The `command_line: None` below is
    /// not a decode failure; it is the manifest being honest.
    ///
    /// The command-line field is populated by [`Self::process_start_audit`]
    /// when the Security-Auditing provider is enabled and the audit policy
    /// is on.
    pub(super) fn process_start(
        &mut self,
        raw: &EtwRaw,
        at: DateTime<Utc>,
    ) -> Result<EventKind, String> {
        let image = self
            .decoder
            .text_first_nonempty(raw, IMAGE_NAME)
            .ok_or("no ImageName; cannot attribute the process")?;
        let image = DevicePaths::global().translate(&image).into_owned();

        let pid = self
            .decoder
            .u32_any(raw, PROCESS_ID)
            .unwrap_or(raw.wire.pid);

        Ok(EventKind::ProcessStart(ProcessStart {
            pid: ProcessId::new(pid),
            parent_pid: self
                .decoder
                .u32_any(raw, PARENT_PROCESS_ID)
                .map(ProcessId::new),
            executable: image.into(),
            command_line: None,
            user: None,
            working_directory: None,
            started_at: at,
            image_hash: None,
            integrity_level: None,
            is_wow64: raw.is_wow64,
            parent_image: None,
        }))
    }

    /// Decode `Microsoft-Windows-Security-Auditing` 4688.
    ///
    /// The audit variant of process start, which is the **only** live
    /// source of the command line on a Windows host. Same
    /// `EventKind::ProcessStart` as the kernel provider's id 1, with the
    /// fields the kernel provider cannot supply:
    ///
    /// * `command_line` — the argument vector, which is what every
    ///   `T1059.*` and `T1218.*` rule reads.
    /// * `user` — the account the process runs as.
    /// * `parent_image` — the parent's image path.
    /// * `integrity_level` — from `MandatoryLabel`, decoded from the
    ///   `S-1-16-*` SID.
    ///
    /// A version-0 event has none of these; a version-1 event has all
    /// but the parent image and integrity level; a version-2 event has
    /// everything. The decoder is indifferent to the version — it reads
    /// whatever the manifest declares and leaves the rest `None`. A
    /// version-0 event is still a legitimate `ProcessStart`.
    ///
    /// # Requires a policy, not just a provider
    ///
    /// The provider registering successfully does not mean events will
    /// arrive. On a stock host, 4688 is silent until **both** of these
    /// are set:
    ///
    /// ```text
    /// auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
    /// reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" ^
    ///     /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
    /// ```
    ///
    /// Without the first, no 4688 fires. Without the second, 4688 fires
    /// but `CommandLine` is empty, and this decoder will produce a
    /// `ProcessStart` with `command_line: None` — which is the honest
    /// answer for a host where the flag is off.
    pub(super) fn process_start_audit(
        &mut self,
        raw: &EtwRaw,
        at: DateTime<Utc>,
    ) -> Result<EventKind, String> {
        let image = self
            .decoder
            .text_first_nonempty(raw, NEW_PROCESS_NAME)
            .ok_or("no NewProcessName; cannot attribute the process")?;
        let image = DevicePaths::global().translate(&image).into_owned();

        let pid = self
            .decoder
            .u32_any(raw, PROCESS_ID)
            .unwrap_or(raw.wire.pid);

        let command_line = self
            .decoder
            .text_first_nonempty(raw, COMMAND_LINE)
            .map(Into::into);

        let user = self
            .decoder
            .text_first_nonempty(raw, SUBJECT_USER_NAME)
            .map(Into::into);

        let parent_image = self
            .decoder
            .text_first_nonempty(raw, PARENT_PROCESS_NAME)
            .map(|p| DevicePaths::global().translate(&p).into_owned().into());

        let integrity_level = self
            .decoder
            .text_first_nonempty(raw, MANDATORY_LABEL)
            .and_then(|sid| parse_integrity_sid(&sid));

        Ok(EventKind::ProcessStart(ProcessStart {
            pid: ProcessId::new(pid),
            parent_pid: self
                .decoder
                .u32_any(raw, PARENT_PROCESS_ID)
                .map(ProcessId::new),
            executable: image.into(),
            command_line,
            user,
            working_directory: None,
            started_at: at,
            image_hash: None,
            integrity_level,
            is_wow64: raw.is_wow64,
            parent_image,
        }))
    }

    pub(super) fn process_exit(
        &mut self,
        raw: &EtwRaw,
        at: DateTime<Utc>,
    ) -> Result<EventKind, String> {
        // The exit event's `ProcessID` is the process that exited; the
        // header's `ProcessId` is the same value on this provider, but
        // reading the field directly keeps the two paths honest.
        let pid = self
            .decoder
            .u32_any(raw, PROCESS_ID)
            .unwrap_or(raw.wire.pid);
        let exit_code = self.decoder.u32_any(raw, EXIT_CODE).map(|v| v as i32);

        Ok(EventKind::ProcessExit(ProcessExit {
            pid: ProcessId::new(pid),
            exit_code,
            exited_at: at,
        }))
    }

    pub(super) fn image_load(
        &mut self,
        raw: &EtwRaw,
        at: DateTime<Utc>,
    ) -> Result<EventKind, String> {
        let image = self
            .decoder
            .text_first_nonempty(raw, IMAGE_NAME)
            .ok_or("no ImageName; cannot attribute the loaded module")?;
        let image = DevicePaths::global().translate(&image).into_owned();

        let pid = self
            .decoder
            .u32_any(raw, PROCESS_ID)
            .unwrap_or(raw.wire.pid);

        // Metadata (hash + signature) is looked up per path, cached on
        // (path, mtime, size). The cache is shared across workers so a
        // module loaded twice in the same process is hashed once.
        let meta: ImageMeta = self.image_meta.get(&image);

        Ok(EventKind::ImageLoad(ImageLoad {
            pid: ProcessId::new(pid),
            image_path: image.into(),
            image_hash: meta.hash,
            signed: meta.signed,
            signer: meta.signer,
            loaded_at: at,
            is_wow64: raw.is_wow64,
        }))
    }

    // ---------------------------------------------------------------------
    // Kernel-Registry
    // ---------------------------------------------------------------------

    pub(super) fn registry_set(
        &mut self,
        raw: &EtwRaw,
        at: DateTime<Utc>,
    ) -> Result<EventKind, String> {
        // Read the path, in one of two ways, in order of preference:
        //
        // 1. `KeyName` (or an alternative spelling) is present and
        //    non-empty — use it directly.
        // 2. `KeyName` is empty but the KCB cache knows the pointer.
        //
        // A miss from both goes to `undecodable` with a reason that names
        // the pointer — the operator sees a specific fact, not a generic
        // failure.
        let kernel_path = match self.decoder.text_first_nonempty(raw, KEY_NAME) {
            Some(path) => path,
            None => {
                let key_object = self.decoder.u64_any(raw, KCB_KEY_OBJECT).unwrap_or(0);
                match self.key_cache.lookup(key_object) {
                    Some(path) => {
                        self.kcb_hits += 1;
                        path
                    }
                    None => {
                        self.kcb_misses += 1;
                        return Err(format!(
                            "KeyName empty and KeyObject {key_object:#018x} unknown to the \
                             KCB cache (learned {} so far, cache holds {}/{})",
                            self.kcb_learned,
                            self.key_cache.len(),
                            self.key_cache.capacity(),
                        ));
                    }
                }
            }
        };

        // Translate `\REGISTRY\MACHINE\...` to `HKLM\...` so a rule author
        // never has to know the kernel's spelling.
        let key_path = registry::translate(&kernel_path).into_owned();

        let value_data = match self.decoder.typed_field(raw, CAPTURED_DATA) {
            Some((FieldValue::Binary(bytes), _)) => {
                let declared = self.decoder.u32_any(raw, REGISTRY_TYPE).unwrap_or(0);
                Some(super::render::render_registry_value(declared, &bytes).into())
            }
            Some((other, _)) => Some(render_field(&other).into()),
            None => None,
        };

        Ok(EventKind::RegistrySet(RegistrySet {
            pid: ProcessId::new(raw.wire.pid),
            key_path: key_path.into(),
            value_name: self
                .decoder
                .text_first_nonempty(raw, VALUE_NAME)
                .map(Into::into),
            value_data,
            set_at: at,
        }))
    }

    // ---------------------------------------------------------------------
    // Kernel-File
    // ---------------------------------------------------------------------

    pub(super) fn file_create(
        &mut self,
        raw: &EtwRaw,
        at: DateTime<Utc>,
    ) -> Result<EventKind, String> {
        let path = self
            .decoder
            .text_first_nonempty(raw, FILE_NAME)
            .ok_or("no FileName; cannot tell which file was created")?;
        let path = DevicePaths::global().translate(&path).into_owned();

        Ok(EventKind::FileCreate(FileCreate {
            pid: ProcessId::new(raw.wire.pid),
            path: path.into(),
            created_at: at,
        }))
    }

    /// Decode `Microsoft-Windows-Kernel-File` id 20, a rename-class
    /// set-information operation.
    ///
    /// # What this event actually contains (verified, not assumed)
    ///
    /// `tools/dump-fields.ps1 -Provider Microsoft-Windows-Kernel-File -Id 20`
    /// on Windows 10/11 prints one name field and no more:
    ///
    /// ```text
    /// id=20  Irp, ThreadId, FileObject, FileKey, Length, InfoClass, FileIndex, FileName
    /// ```
    ///
    /// There is **no** old-name field and **no** new-name field. The target of
    /// the rename lives in the SetInformation parameter buffer, which the
    /// provider does not decode, so a rename's two sides are simply not in the
    /// telemetry. A live 25-second run on the reference host (3271 rename
    /// events) also showed what `FileName` *is*: name fragments, not paths —
    /// `*` for the majority, then `usr`, `bin`, `Git`, and `77003E88…ED_*` —
    /// with 43% of the events carrying no value at all.
    ///
    /// So a `FileRename { old_path, new_path }` cannot be populated truthfully
    /// from this provider, and an earlier version of this comment claimed
    /// otherwise ("some rename events carry only the new name"). That was
    /// wrong, and a live run is what showed it.
    ///
    /// # What this decoder does about it
    ///
    /// The least-wrong thing available: read whichever name resolves
    /// (`FILE_NEW_NAME` first, then `FILE_OLD_NAME`, so a build that does
    /// declare a target name uses it) and mirror it into `old_path` when no
    /// separate old name was found. Both fields therefore hold the same
    /// fragment, and the honest reading of the event is "a rename-class
    /// operation touched a file whose name fragment is this" — *not* "the file
    /// moved from A to B".
    ///
    /// An event with no name at all is counted as `undecodable` rather than
    /// silently dropped, and that is a large fraction rather than a rare edge:
    /// 1414 of 3271 in the run above. It is **not** a missing field spelling;
    /// there is no other spelling to add, which is what the old advice told
    /// operators to go looking for.
    ///
    /// The shape is kept rather than removed because a *burst* of rename-class
    /// operations is real ransomware signal even when an individual fragment is
    /// uninformative, and the per-shape counter is what makes a burst countable.
    /// Representing that honestly in the wire format — a `name_fragment` field
    /// rather than two paths that are equal and wrong — is a model change with
    /// a schema-version bump, and is deliberately not done here.
    pub(super) fn file_rename(
        &mut self,
        raw: &EtwRaw,
        at: DateTime<Utc>,
    ) -> Result<EventKind, String> {
        // Try new-name spellings first, then old-name spellings as a
        // fallback. Neither resolves to the rename target on Windows 10/11 —
        // see the doc comment above — so what this really reads is the single
        // `FileName` fragment. Keeping the two-name shape means a build that
        // does declare both sides uses them without a second code path.
        let primary = self
            .decoder
            .text_first_nonempty(raw, FILE_NEW_NAME)
            .or_else(|| self.decoder.text_first_nonempty(raw, FILE_OLD_NAME))
            .ok_or("no FileName in either field; cannot tell what was renamed")?;
        let primary = DevicePaths::global().translate(&primary).into_owned();

        // The old path, when it is named separately. When it is not, the
        // primary value is used — see the doc comment.
        let old_path = self
            .decoder
            .text_first_nonempty(raw, FILE_OLD_NAME)
            .map(|p| DevicePaths::global().translate(&p).into_owned())
            .unwrap_or_else(|| primary.clone());

        Ok(EventKind::FileRename(FileRename {
            pid: ProcessId::new(raw.wire.pid),
            old_path: old_path.into(),
            new_path: primary.into(),
            renamed_at: at,
        }))
    }

    pub(super) fn file_delete(
        &mut self,
        raw: &EtwRaw,
        at: DateTime<Utc>,
    ) -> Result<EventKind, String> {
        let path = self
            .decoder
            .text_first_nonempty(raw, FILE_NAME)
            .ok_or("no FileName; cannot tell which file was deleted")?;
        let path = DevicePaths::global().translate(&path).into_owned();

        Ok(EventKind::FileDelete(FileDelete {
            pid: ProcessId::new(raw.wire.pid),
            path: path.into(),
            deleted_at: at,
        }))
    }

    // ---------------------------------------------------------------------
    // Kernel-Network
    // ---------------------------------------------------------------------

    pub(super) fn network_connect(
        &mut self,
        raw: &EtwRaw,
        at: DateTime<Utc>,
    ) -> Result<EventKind, String> {
        let pid = self.decoder.u32_any(raw, NET_PID).unwrap_or(raw.wire.pid);

        // The addresses are the mandatory fields: a connect with no
        // address is not scoreable. Ports default to zero when absent.
        let source_ip = self
            .read_ip(raw, NET_SADDR)
            .ok_or("no saddr; cannot tell who the connection came from")?;
        let destination_ip = self
            .read_ip(raw, NET_DADDR)
            .ok_or("no daddr; cannot tell where the connection went")?;

        let source_port = self.decoder.u32_any(raw, NET_SPORT).unwrap_or(0) as u16;
        let destination_port = self.decoder.u32_any(raw, NET_DPORT).unwrap_or(0) as u16;

        Ok(EventKind::NetworkConnect(NetworkConnect {
            pid: ProcessId::new(pid),
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            protocol: NetworkProtocol::Tcp,
            initiated_at: at,
        }))
    }

    pub(super) fn network_disconnect(
        &mut self,
        raw: &EtwRaw,
        at: DateTime<Utc>,
    ) -> Result<EventKind, String> {
        let pid = self.decoder.u32_any(raw, NET_PID).unwrap_or(raw.wire.pid);

        let source_ip = self
            .read_ip(raw, NET_SADDR)
            .ok_or("no saddr; cannot tell who the connection came from")?;
        let destination_ip = self
            .read_ip(raw, NET_DADDR)
            .ok_or("no daddr; cannot tell where the connection went")?;

        let source_port = self.decoder.u32_any(raw, NET_SPORT).unwrap_or(0) as u16;
        let destination_port = self.decoder.u32_any(raw, NET_DPORT).unwrap_or(0) as u16;

        // `size` is the total bytes transferred over the connection. It
        // is one number, not two, so it is reported as `bytes_sent` and
        // `bytes_received` is left absent. Splitting it would be a lie.
        let bytes = self.decoder.u64_any(raw, NET_SIZE);

        Ok(EventKind::NetworkDisconnect(NetworkDisconnect {
            pid: ProcessId::new(pid),
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            protocol: NetworkProtocol::Tcp,
            bytes_sent: bytes,
            bytes_received: None,
            ended_at: at,
        }))
    }

    /// Read an IP-address field and decode it.
    ///
    /// # The `UInt32` case is the common one
    ///
    /// The Kernel-Network manifest declares `saddr` and `daddr` as
    /// `UInt32`, not `Binary`. This was learned by running the sensor:
    /// the first version of this function only handled `Binary` and every
    /// network event failed with "no saddr".
    ///
    /// An `IN_ADDR.S_addr` is a `u32` whose in-memory bytes are the
    /// network-order octets. For `192.168.1.1` the bytes are
    /// `C0 A8 01 01`, which read as a little-endian `u32` is
    /// `0x0101A8C0`. The inverse is `to_le_bytes()`, which gives back
    /// `C0 A8 01 01`, which is what `Ipv4Addr::from([u8; 4])` expects.
    ///
    /// The `Binary` path is preserved because some builds — or a future
    /// manifest change — declare the field that way, and the code should
    /// work on either without a second source of truth.
    fn read_ip(&mut self, raw: &EtwRaw, names: &[&str]) -> Option<IpAddr> {
        for name in names {
            if let Some((value, _ty)) = self.decoder.typed_field(raw, name) {
                match value {
                    FieldValue::U32(v) => {
                        // The common case. See the doc comment.
                        return Some(IpAddr::V4(Ipv4Addr::from(v.to_le_bytes())));
                    }
                    FieldValue::U64(v) => {
                        // Some builds declare the address as `UInt64`.
                        // An IPv4 address uses only the low 32 bits.
                        return Some(IpAddr::V4(Ipv4Addr::from((v as u32).to_le_bytes())));
                    }
                    FieldValue::Binary(bytes) => {
                        // The `sockaddr_*` form some builds produce. The
                        // length tells the family; see `parse_ip_bytes`.
                        if let Some(ip) = parse_ip_bytes(&bytes) {
                            return Some(ip);
                        }
                    }
                    _ => {
                        // Wrong type. Try the next spelling; the loop
                        // continues rather than aborting the whole
                        // lookup, because a name chain is exactly the
                        // case where one spelling resolves to the wrong
                        // type and the next is the right one.
                    }
                }
            }
        }
        None
    }

    // ---------------------------------------------------------------------
    // User-mode providers
    // ---------------------------------------------------------------------

    pub(super) fn dns_query(
        &mut self,
        raw: &EtwRaw,
        at: DateTime<Utc>,
    ) -> Result<EventKind, String> {
        let name = self
            .decoder
            .text_first_nonempty(raw, QUERY_NAME)
            .ok_or("no QueryName; cannot tell what was looked up")?;

        Ok(EventKind::DnsQuery(DnsQueryPayload {
            pid: ProcessId::new(raw.wire.pid),
            query_name: name.into(),
            query_type: self
                .decoder
                .u32_any(raw, QUERY_TYPE)
                .map(super::render::query_type_name)
                .unwrap_or_else(|| "A".to_string())
                .into(),
            answers: Vec::new(),
            response_code: None,
            queried_at: at,
        }))
    }

    pub(super) fn script_block(
        &mut self,
        raw: &EtwRaw,
        at: DateTime<Utc>,
    ) -> Result<EventKind, String> {
        let text = self
            .decoder
            .text_first_nonempty(raw, SCRIPT_BLOCK_TEXT)
            .ok_or("no ScriptBlockText; cannot tell what was run")?;

        let path = self
            .decoder
            .text_first_nonempty(raw, SCRIPT_BLOCK_PATH)
            .map(|p| DevicePaths::global().translate(&p).into_owned());

        Ok(EventKind::ScriptBlock(ScriptBlock {
            pid: ProcessId::new(raw.wire.pid),
            text: super::render::cap_script_text(&text).into(),
            script_block_id: self
                .decoder
                .text_first_nonempty(raw, SCRIPT_BLOCK_ID)
                .map(Into::into),
            path: path.map(Into::into),
            message_number: self.decoder.u32_any(raw, MESSAGE_NUMBER),
            message_total: self.decoder.u32_any(raw, MESSAGE_TOTAL),
            recorded_at: at,
        }))
    }

    // ---------------------------------------------------------------------
    // WMI-Activity
    // ---------------------------------------------------------------------

    /// Decode `Microsoft-Windows-WMI-Activity` id 23 — a process WMI created.
    ///
    /// The `Commandline` field is **mandatory**: it is the entire reason this
    /// event has its own shape, so an id-23 event without one is a decode
    /// failure that names the field, not a `WmiProcess` with nothing in it.
    /// `CreatedProcessId` falls back to the header PID, which for this event is
    /// `WmiPrvSE.exe` — the wrong process, but a better answer than no process
    /// at all, and the fallback is visible because `client_pid` is separate.
    pub(super) fn wmi_process(
        &mut self,
        raw: &EtwRaw,
        at: DateTime<Utc>,
    ) -> Result<EventKind, String> {
        let command_line = self
            .decoder
            .text_first_nonempty(raw, WMI_COMMAND_LINE)
            .ok_or("no Commandline; the command is the whole point of a WMI process")?;

        let pid = self
            .decoder
            .u32_any(raw, WMI_CREATED_PID)
            .unwrap_or(raw.wire.pid);

        // `IsLocal` is declared `Boolean`, which TDH returns as one byte. A
        // missing field stays `None` rather than becoming `false`: "the
        // manifest did not say" and "WMI said the caller is remote" are
        // different facts and a rule keys on the difference.
        let is_local = self.decoder.u32_any(raw, WMI_IS_LOCAL).map(|v| v != 0);

        Ok(EventKind::WmiProcess(WmiProcess {
            pid: ProcessId::new(pid),
            command_line: command_line.into(),
            user: self
                .decoder
                .text_first_nonempty(raw, WMI_USER)
                .map(Into::into),
            client_pid: self
                .decoder
                .u32_any(raw, WMI_CLIENT_PID)
                .map(ProcessId::new),
            client_machine: self
                .decoder
                .text_first_nonempty(raw, WMI_CLIENT_MACHINE)
                .map(Into::into),
            is_local,
            created_at: at,
        }))
    }

    /// Decode `Microsoft-Windows-WMI-Activity` id 5861 — a permanent WMI event
    /// subscription (`T1546.003`).
    ///
    /// The namespace is mandatory; the filter is required too, because a
    /// subscription with no filter is not a subscription. The consumer is left
    /// optional and is the field a rule actually judges, since that is where a
    /// `CommandLineEventConsumer` or an `ActiveScriptEventConsumer` is named.
    pub(super) fn wmi_subscription(
        &mut self,
        raw: &EtwRaw,
        at: DateTime<Utc>,
    ) -> Result<EventKind, String> {
        let namespace = self
            .decoder
            .text_first_nonempty(raw, WMI_NAMESPACE)
            .ok_or("no Namespace; cannot place the subscription")?;
        let event_filter = self
            .decoder
            .text_first_nonempty(raw, WMI_EVENT_FILTER)
            .ok_or("no ESS (event filter); cannot tell what triggers it")?;

        Ok(EventKind::WmiSubscription(WmiSubscription {
            namespace: namespace.into(),
            event_filter: event_filter.into(),
            consumer: self
                .decoder
                .text_first_nonempty(raw, WMI_CONSUMER)
                .map(Into::into),
            recorded_at: at,
        }))
    }

    // ---------------------------------------------------------------------
    // TaskScheduler
    // ---------------------------------------------------------------------

    /// Decode `Microsoft-Windows-TaskScheduler` id 106 — a task registration.
    ///
    /// Two fields is not an oversight; it is the whole event. What the task
    /// will run is in the task's XML, which this provider does not emit. See
    /// [`model::TaskRegistered`] for what that leaves a rule able to judge.
    pub(super) fn task_registered(
        &mut self,
        raw: &EtwRaw,
        at: DateTime<Utc>,
    ) -> Result<EventKind, String> {
        let task_name = self
            .decoder
            .text_first_nonempty(raw, TASK_NAME)
            .ok_or("no TaskName; cannot tell which task was registered")?;

        Ok(EventKind::TaskRegistered(TaskRegistered {
            task_name: task_name.into(),
            user: self
                .decoder
                .text_first_nonempty(raw, USER_CONTEXT)
                .map(Into::into),
            recorded_at: at,
        }))
    }
}

// ---------------------------------------------------------------------------
// Address parsing
// ---------------------------------------------------------------------------

/// Decode a `saddr`/`daddr` blob into an `IpAddr`.
///
/// Reached only when the manifest declares the address field as
/// `Binary` — the common case for `Kernel-Network` on the builds this
/// crate has been tested against is `UInt32`, and that path is handled
/// inline in [`Translator::read_ip`].
///
/// When the field *is* `Binary`, the bytes are one of three shapes
/// depending on the address family and the Windows build:
///
/// * **4 bytes** — a bare `in_addr` (IPv4).
/// * **16 bytes** — a bare `in6_addr` (IPv6), or a `sockaddr_in` for IPv4
///   with padding. The family field at offset 0 distinguishes them.
/// * **28 bytes** — a `sockaddr_in6`.
///
/// Every case is tried; `None` means the bytes did not match any of them,
/// and the caller treats that as a decode failure with a clear reason.
/// The alternative — inventing `0.0.0.0` — is what this refuses to do.
pub(crate) fn parse_ip_bytes(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        16 => {
            // Disambiguate: is this a bare IPv6 address, or a
            // `sockaddr_in` with padding?
            let family = u16::from_le_bytes([bytes[0], bytes[1]]);
            if family == 2 {
                // AF_INET: sockaddr_in layout, address at offset 4.
                Some(IpAddr::V4(Ipv4Addr::new(
                    bytes[4], bytes[5], bytes[6], bytes[7],
                )))
            } else if family == 23 {
                // AF_INET6 without the trailing scope_id (unusual). The
                // address starts at offset 8.
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&bytes[8..24]);
                Some(IpAddr::V6(Ipv6Addr::from(arr)))
            } else {
                // Bare in6_addr.
                let mut arr = [0u8; 16];
                arr.copy_from_slice(bytes);
                Some(IpAddr::V6(Ipv6Addr::from(arr)))
            }
        }
        28 => {
            // sockaddr_in6: family (2) + port (2) + flowinfo (4) + address
            // (16) + scope_id (4).
            let family = u16::from_le_bytes([bytes[0], bytes[1]]);
            if family == 23 {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&bytes[8..24]);
                Some(IpAddr::V6(Ipv6Addr::from(arr)))
            } else if family == 2 {
                // A `sockaddr_in` declared at 28 bytes: family, port,
                // address, zero padding. Address at offset 4.
                Some(IpAddr::V4(Ipv4Addr::new(
                    bytes[4], bytes[5], bytes[6], bytes[7],
                )))
            } else {
                None
            }
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// SID parsing
// ---------------------------------------------------------------------------

/// Decode a Windows mandatory-label SID into the integrity level it
/// denotes.
///
/// The well-known mandatory SIDs are:
///
/// | SID | Level |
/// |---|---|
/// | `S-1-16-0`     | Untrusted |
/// | `S-1-16-4096`  | Low |
/// | `S-1-16-8192`  | Medium |
/// | `S-1-16-8448`  | MediumPlus |
/// | `S-1-16-12288` | High |
/// | `S-1-16-16384` | System |
/// | `S-1-16-20480` | Protected |
///
/// An unrecognised SID returns `None` rather than guessing at a level.
/// Some builds deliver the label as a SID string and others as a
/// rendered name; only the SID form is decoded, because that is the form
/// that carries the numeric level unambiguously.
fn parse_integrity_sid(sid: &str) -> Option<IntegrityLevel> {
    match sid.trim() {
        "S-1-16-0" => Some(IntegrityLevel::Untrusted),
        "S-1-16-4096" => Some(IntegrityLevel::Low),
        "S-1-16-8192" => Some(IntegrityLevel::Medium),
        "S-1-16-8448" => Some(IntegrityLevel::MediumPlus),
        "S-1-16-12288" => Some(IntegrityLevel::High),
        "S-1-16-16384" => Some(IntegrityLevel::System),
        "S-1-16-20480" => Some(IntegrityLevel::Protected),
        _ => None,
    }
}

/// Render a non-binary `FieldValue` as text.
///
/// Kept separate from `decode::value::render_text` because that one is
/// `pub(crate)` inside `decode` and this is used by decoders that receive
/// a value from `typed_field` and want its string form. The two render
/// identically; the split is about where each is called from.
pub(crate) fn render_field(value: &FieldValue) -> String {
    match value {
        FieldValue::Str(s) => s.clone(),
        FieldValue::I8(v) => v.to_string(),
        FieldValue::U8(v) => v.to_string(),
        FieldValue::I16(v) => v.to_string(),
        FieldValue::U16(v) => v.to_string(),
        FieldValue::I32(v) => v.to_string(),
        FieldValue::U32(v) => v.to_string(),
        FieldValue::I64(v) => v.to_string(),
        FieldValue::U64(v) => v.to_string(),
        FieldValue::F32(v) => v.to_string(),
        FieldValue::F64(v) => v.to_string(),
        FieldValue::Guid(b) => super::render::hex(b),
        FieldValue::Binary(b) => super::render::hex(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_field_renders_every_variant() {
        assert_eq!(render_field(&FieldValue::Str("x".into())), "x");
        assert_eq!(render_field(&FieldValue::I32(-1)), "-1");
        assert_eq!(render_field(&FieldValue::U32(42)), "42");
        assert_eq!(
            render_field(&FieldValue::U64(u64::MAX)),
            u64::MAX.to_string()
        );
        assert_eq!(render_field(&FieldValue::Binary(vec![0xab])), "ab");
        assert_eq!(render_field(&FieldValue::Guid([0u8; 16])), "0".repeat(32));
    }

    #[test]
    fn ipv4_bare_address_parses() {
        let bytes = [192, 168, 1, 1];
        assert_eq!(
            parse_ip_bytes(&bytes),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
    }

    #[test]
    fn ipv4_sockaddr_in_parses() {
        // family=AF_INET (2), port=0x5000 (big-endian = 80), addr=10.0.0.1,
        // 8 bytes of zero padding.
        let mut bytes = [0u8; 16];
        bytes[0] = 2;
        bytes[1] = 0;
        bytes[2] = 0x50;
        bytes[3] = 0x00;
        bytes[4] = 10;
        bytes[5] = 0;
        bytes[6] = 0;
        bytes[7] = 1;
        assert_eq!(
            parse_ip_bytes(&bytes),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
    }

    #[test]
    fn ipv6_bare_address_parses() {
        // 2001:db8::1
        let bytes = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(
            parse_ip_bytes(&bytes),
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)))
        );
    }

    #[test]
    fn ipv6_sockaddr_in6_parses() {
        let mut bytes = [0u8; 28];
        bytes[0] = 23; // AF_INET6
        bytes[1] = 0;
        // bytes 2..4 = port
        // bytes 4..8 = flowinfo
        // bytes 8..24 = address
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        bytes[8..24].copy_from_slice(&addr);
        assert_eq!(
            parse_ip_bytes(&bytes),
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)))
        );
    }

    #[test]
    fn a_short_blob_is_refused_not_invented() {
        // Anything that is not 4, 16, or 28 bytes is not an address on
        // this provider. The honest answer is `None`.
        assert_eq!(parse_ip_bytes(&[]), None);
        assert_eq!(parse_ip_bytes(&[1, 2, 3]), None);
        assert_eq!(parse_ip_bytes(&[1; 8]), None);
        assert_eq!(parse_ip_bytes(&[1; 100]), None);
    }

    #[test]
    fn a_u32_address_decodes_as_ipv4() {
        // The common case on Kernel-Network: the manifest declares
        // `saddr`/`daddr` as `UInt32`. 192.168.1.1 in memory as
        // `IN_ADDR.S_addr` is the bytes [0xC0, 0xA8, 0x01, 0x01], which
        // read as a little-endian u32 is 0x0101A8C0. The inverse is
        // `to_le_bytes()`.
        let v: u32 = 0x0101_A8C0;
        assert_eq!(
            IpAddr::V4(Ipv4Addr::from(v.to_le_bytes())),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        );

        // A second case, to catch a byte-swap that would still round-trip
        // through one value but not another.
        let v: u32 = 0x0100_007F; // 127.0.0.1
        assert_eq!(
            IpAddr::V4(Ipv4Addr::from(v.to_le_bytes())),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
        );
    }

    #[test]
    fn integrity_sids_decode_to_their_levels() {
        assert_eq!(
            parse_integrity_sid("S-1-16-0"),
            Some(IntegrityLevel::Untrusted)
        );
        assert_eq!(
            parse_integrity_sid("S-1-16-4096"),
            Some(IntegrityLevel::Low)
        );
        assert_eq!(
            parse_integrity_sid("S-1-16-8192"),
            Some(IntegrityLevel::Medium)
        );
        assert_eq!(
            parse_integrity_sid("S-1-16-8448"),
            Some(IntegrityLevel::MediumPlus)
        );
        assert_eq!(
            parse_integrity_sid("S-1-16-12288"),
            Some(IntegrityLevel::High)
        );
        assert_eq!(
            parse_integrity_sid("S-1-16-16384"),
            Some(IntegrityLevel::System)
        );
        assert_eq!(
            parse_integrity_sid("S-1-16-20480"),
            Some(IntegrityLevel::Protected)
        );
        // Whitespace is tolerated because the manifest sometimes pads.
        assert_eq!(
            parse_integrity_sid(" S-1-16-8192 "),
            Some(IntegrityLevel::Medium)
        );
        // Unknown SIDs are not guessed at.
        assert_eq!(parse_integrity_sid("S-1-5-18"), None);
        assert_eq!(parse_integrity_sid(""), None);
    }
}
