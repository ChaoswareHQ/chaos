//! Turning raw ETW events into the pipeline's wire format.
//!
//! The sensor hands over an [`EtwRaw`] — a copied payload plus the descriptor
//! TDH needs to name its fields. This module is where that becomes a
//! [`TelemetryEvent`] the detection engine can score.
//!
//! # The field names come from this machine's manifests, not from memory
//!
//! TDH addresses properties by name, and the name has to match the provider's
//! manifest exactly. Every name below was read off the shipped templates with
//! `Get-WinEvent -ListProvider <provider>`, which needs no elevation. The
//! chains exist because templates are not identical across Windows builds, and
//! a miss has to degrade to `None` rather than to a guess.
//!
//! Two of those templates are worth stating outright, because both are
//! surprises that cost detections silently:
//!
//! * `Microsoft-Windows-Kernel-Process` `ProcessStart` carries `ProcessID`,
//!   `ParentProcessID`, `ImageName` and the token elevation — and **no command
//!   line field at all**. Every rule that reads a command line is therefore
//!   unreachable from this provider alone.
//! * `Microsoft-Windows-Kernel-Registry` `RegistrySetValue` carries `KeyName`
//!   and `ValueName`, but the value written is `CapturedData`, a `Binary`
//!   field sized by `CapturedDataSize`. Its *shape* is decided by the companion
//!   `Type` field, which is a `REG_*` constant.
//!
//! # NT device paths
//!
//! The kernel reports paths as `\Device\HarddiskVolumeN\...`, not `C:\...`.
//! Drive letters are a user-mode concept, and the kernel does not consult the
//! mount manager. Every path this module ships is translated to the DOS form
//! with [`crate::paths::DevicePaths`], because the DOS form is what a rule
//! author writes.
//!
//! # Why the failure counters matter
//!
//! A property name that does not resolve on a given machine is a silent hole.
//! [`Translator::counts`] and [`Translator::failures`] exist so that cannot
//! happen quietly — a non-zero `undecodable` means this table is wrong, not
//! that the machine is idle.
//!
//! A shape whose event id is not in [`shape_of`] is also a silent hole, unless
//! it is counted. [`ShapeCounts::unrecognised`] closes that hole: an event
//! whose id is not a shape the sensor scores is counted as `unrecognised`, so
//! that `delivered == mapped + undecodable + unrecognised` and every event the
//! callback delivered is accounted for.
//!
//! # Gap correlation
//!
//! [`Translator::detect_gaps`] is the security layer. A process that patches
//! `ntdll!EtwEventWrite` still generates **kernel** events but its **user-mode**
//! events stop arriving. A shape that *was* firing and has stopped while other
//! shapes are active is the signal. A shape that has never fired is
//! **untested**, not silent.

use crate::callback::EtwRaw;
use crate::decode::{Decoder, FieldValue, utf16_to_string};
use crate::paths::DevicePaths;
use chrono::{DateTime, Utc};
use model::{
    DnsQueryPayload, EventId, EventKind, EventSource, HostId, Payload, ProcessId, ProcessStart,
    RegistrySet, ScriptBlock, TelemetryEvent,
};

/// ETW's `TimeStamp` is a `FILETIME`: 100-nanosecond intervals since 1601-01-01.
const FILETIME_EPOCH_DELTA: i64 = 116_444_736_000_000_000;
const FILETIME_TICKS_PER_SEC: i64 = 10_000_000;

/// Convert an ETW timestamp to UTC.
fn from_filetime(filetime: i64) -> Option<DateTime<Utc>> {
    let since_epoch = filetime.checked_sub(FILETIME_EPOCH_DELTA)?;
    if since_epoch < 0 {
        return None;
    }
    DateTime::from_timestamp(
        since_epoch / FILETIME_TICKS_PER_SEC,
        ((since_epoch % FILETIME_TICKS_PER_SEC) * 100) as u32,
    )
}

/// A wire event this sensor knows how to build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    ProcessStart = 0,
    RegistrySet = 1,
    DnsQuery = 2,
    ScriptBlock = 3,
}

impl Shape {
    pub const ALL: [Shape; 4] = [
        Shape::ProcessStart,
        Shape::RegistrySet,
        Shape::DnsQuery,
        Shape::ScriptBlock,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Shape::ProcessStart => "process_start",
            Shape::RegistrySet => "registry_set",
            Shape::DnsQuery => "dns_query",
            Shape::ScriptBlock => "script_block",
        }
    }

    pub const fn is_kernel_side(self) -> bool {
        matches!(self, Shape::ProcessStart | Shape::RegistrySet)
    }

    pub const fn is_user_mode(self) -> bool {
        !self.is_kernel_side()
    }
}

/// What the sensor could and could not decode, per shape.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShapeCounts {
    attempted: [u64; 4],
    mapped: [u64; 4],
    ever_fired: [bool; 4],
    /// Events the callback delivered that `shape_of` did not recognise.
    ///
    /// Every provider the session enables emits event ids the translator does
    /// not score. Before this counter, those events were silently dropped at
    /// the shape match: the callback counted `delivered`, the translator
    /// returned early without incrementing anything, and the accounting
    /// broke. With this counter, `delivered == mapped + undecodable +
    /// unrecognised` holds and every event is accounted for.
    unrecognised: u64,
}

impl ShapeCounts {
    pub(crate) fn note_attempt(&mut self, shape: Shape) {
        self.attempted[shape as usize] += 1;
        self.ever_fired[shape as usize] = true;
    }

    pub(crate) fn note_mapped(&mut self, shape: Shape) {
        self.mapped[shape as usize] += 1;
    }

    /// An event the callback delivered that `shape_of` did not recognise.
    pub(crate) fn note_unrecognised(&mut self) {
        self.unrecognised += 1;
    }

    /// Events of this shape the sensor saw and could not decode.
    pub fn undecodable(&self, shape: Shape) -> u64 {
        self.attempted(shape).saturating_sub(self.mapped(shape))
    }

    pub fn attempted(&self, shape: Shape) -> u64 {
        self.attempted[shape as usize]
    }

    pub fn mapped(&self, shape: Shape) -> u64 {
        self.mapped[shape as usize]
    }

    pub fn ever_fired(&self, shape: Shape) -> bool {
        self.ever_fired[shape as usize]
    }

    /// Events delivered but not recognised as any shape.
    pub fn unrecognised(&self) -> u64 {
        self.unrecognised
    }

    pub fn by_shape(&self) -> impl Iterator<Item = (Shape, u64, u64)> + '_ {
        Shape::ALL
            .iter()
            .copied()
            .map(|s| (s, self.attempted(s), self.mapped(s)))
    }

    pub fn total_attempted(&self) -> u64 {
        self.attempted.iter().sum()
    }

    pub fn total_mapped(&self) -> u64 {
        self.mapped.iter().sum()
    }

    /// Whether any kernel-side shape has seen events.
    pub fn kernel_side_active(&self) -> bool {
        Shape::ALL
            .iter()
            .copied()
            .filter(|s| s.is_kernel_side())
            .any(|s| self.attempted(s) > 0)
    }

    /// Whether any user-mode shape has seen events.
    pub fn user_mode_active(&self) -> bool {
        Shape::ALL
            .iter()
            .copied()
            .filter(|s| s.is_user_mode())
            .any(|s| self.attempted(s) > 0)
    }
}

/// A detected gap: a shape that should be producing events but is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryGap {
    pub shape: Shape,
    pub attempted: u64,
    pub mapped: u64,
    pub severity: GapSeverity,
}

impl TelemetryGap {
    pub fn describe(&self) -> String {
        match self.severity {
            GapSeverity::Healthy => format!("{}: healthy", self.shape.as_str()),
            GapSeverity::DecodeFailure => format!(
                "{}: {} of {} events failed to decode (table problem, not an attack)",
                self.shape.as_str(),
                self.attempted - self.mapped,
                self.attempted
            ),
            GapSeverity::Silent => format!(
                "{}: silent while other shapes are active (possible ETW bypass)",
                self.shape.as_str()
            ),
        }
    }
}

/// How serious a gap is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GapSeverity {
    Healthy,
    DecodeFailure,
    Silent,
}

/// Which ETW event becomes which wire event.
fn shape_of(provider: &str, event_id: u16) -> Option<Shape> {
    match (provider, event_id) {
        ("Microsoft-Windows-Kernel-Process", 1) => Some(Shape::ProcessStart),
        ("Microsoft-Windows-Kernel-Registry", 5) => Some(Shape::RegistrySet),
        ("Microsoft-Windows-DNS-Client", 3006) => Some(Shape::DnsQuery),
        ("Microsoft-Windows-PowerShell", 4104) => Some(Shape::ScriptBlock),
        _ => None,
    }
}

const PROCESS_ID: &[&str] = &["ProcessID", "ProcessId"];
const PARENT_PROCESS_ID: &[&str] = &["ParentProcessID", "ParentProcessId"];
const IMAGE_NAME: &[&str] = &["ImageName"];
const KEY_NAME: &[&str] = &["KeyName"];
const VALUE_NAME: &[&str] = &["ValueName"];
const CAPTURED_DATA: &str = "CapturedData";
const REGISTRY_TYPE: &[&str] = &["Type"];
const QUERY_NAME: &[&str] = &["QueryName"];
const QUERY_TYPE: &[&str] = &["QueryType"];
const SCRIPT_BLOCK_TEXT: &[&str] = &["ScriptBlockText"];
const SCRIPT_BLOCK_ID: &[&str] = &["ScriptBlockId"];
const SCRIPT_BLOCK_PATH: &[&str] = &["Path"];
const MESSAGE_NUMBER: &[&str] = &["MessageNumber"];
const MESSAGE_TOTAL: &[&str] = &["MessageTotal"];

/// How much script text we will ship, in bytes.
const MAX_SCRIPT_TEXT: usize = 8 * 1024;

fn cap_script_text(text: &str) -> &str {
    if text.len() <= MAX_SCRIPT_TEXT {
        return text;
    }
    let mut end = MAX_SCRIPT_TEXT;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

const KEPT_FAILURES: usize = 8;

fn query_type_name(value: u32) -> String {
    let known = match value {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        43 => "DS",
        65 => "HTTPS",
        255 => "ANY",
        other => return other.to_string(),
    };
    known.to_string()
}

mod reg_type {
    pub const SZ: u32 = 1;
    pub const EXPAND_SZ: u32 = 2;
    pub const BINARY: u32 = 3;
    pub const DWORD: u32 = 4;
    pub const DWORD_BIG_ENDIAN: u32 = 5;
    pub const MULTI_SZ: u32 = 7;
    pub const QWORD: u32 = 11;
}

pub fn render_registry_value(reg_type: u32, bytes: &[u8]) -> String {
    match reg_type {
        reg_type::SZ | reg_type::EXPAND_SZ | reg_type::MULTI_SZ => {
            utf16_to_string(bytes).unwrap_or_else(|| hex(bytes))
        }
        reg_type::DWORD | reg_type::DWORD_BIG_ENDIAN => bytes
            .get(..4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .map(|v| v.to_string())
            .unwrap_or_else(|| hex(bytes)),
        reg_type::QWORD => bytes
            .get(..8)
            .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8])))
            .map(|v| v.to_string())
            .unwrap_or_else(|| hex(bytes)),
        reg_type::BINARY => hex(bytes),
        _ => hex(bytes),
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0F) as usize] as char);
    }
    out
}

/// Translates raw ETW events, and reports what it could not translate.
pub struct Translator {
    host: HostId,
    decoder: Decoder,
    next_event_id: u64,
    counts: ShapeCounts,
    failures: Vec<String>,
}

impl Translator {
    pub fn new(host: HostId) -> Self {
        Self {
            host,
            decoder: Decoder::new(),
            next_event_id: 0,
            counts: ShapeCounts::default(),
            failures: Vec::new(),
        }
    }

    pub fn mapped(&self) -> u64 {
        self.counts.total_mapped()
    }

    pub fn undecodable(&self) -> u64 {
        self.counts
            .total_attempted()
            .saturating_sub(self.counts.total_mapped())
    }

    pub fn counts(&self) -> ShapeCounts {
        self.counts
    }

    pub fn failures(&self) -> &[String] {
        &self.failures
    }

    fn note_failure(&mut self, reason: String) {
        if self.failures.len() < KEPT_FAILURES {
            self.failures.push(reason);
        }
    }

    /// Detect shapes that are silent while the sensor is otherwise active.
    pub fn detect_gaps(&self) -> Vec<TelemetryGap> {
        let total_attempted = self.counts.total_attempted();
        if total_attempted == 0 {
            return Vec::new();
        }

        let kernel_active = self.counts.kernel_side_active();
        let user_active = self.counts.user_mode_active();

        let mut gaps = Vec::new();

        for shape in Shape::ALL {
            let attempted = self.counts.attempted(shape);
            let mapped = self.counts.mapped(shape);

            let severity = if attempted == 0 {
                if !self.counts.ever_fired(shape) {
                    GapSeverity::Healthy
                } else if shape.is_user_mode() && kernel_active {
                    GapSeverity::Silent
                } else if shape.is_kernel_side() && user_active {
                    GapSeverity::Silent
                } else {
                    GapSeverity::Healthy
                }
            } else if attempted > mapped {
                GapSeverity::DecodeFailure
            } else {
                GapSeverity::Healthy
            };

            if severity != GapSeverity::Healthy {
                gaps.push(TelemetryGap {
                    shape,
                    attempted,
                    mapped,
                    severity,
                });
            }
        }

        gaps.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.shape.as_str().cmp(b.shape.as_str()))
        });

        gaps
    }

    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        for (shape, attempted, mapped) in self.counts.by_shape() {
            parts.push(format!("{}: {}/{}", shape.as_str(), mapped, attempted));
        }
        if self.counts.unrecognised() > 0 {
            parts.push(format!("unrecognised: {}", self.counts.unrecognised()));
        }
        parts.join(", ")
    }

    /// Translate one event, or return `None` if it is not something this sensor
    /// scores or not something it could decode.
    pub fn translate(&mut self, raw: &EtwRaw) -> Option<TelemetryEvent> {
        let Some(shape) = shape_of(raw.wire.provider.as_str(), raw.wire.event_id) else {
            // Not a shape we score. Counted so the totals add up: without
            // this, the event was silently dropped at the shape match and
            // the accounting broke between `delivered` and `mapped`.
            self.counts.note_unrecognised();
            return None;
        };
        self.counts.note_attempt(shape);

        let Some(timestamp) = from_filetime(raw.wire.timestamp_raw) else {
            self.note_failure(format!(
                "{} id={}: timestamp {} is not a valid FILETIME",
                raw.wire.provider.as_str(),
                raw.wire.event_id,
                raw.wire.timestamp_raw
            ));
            return None;
        };

        let kind = match shape {
            Shape::ProcessStart => self.process_start(raw, timestamp),
            Shape::RegistrySet => self.registry_set(raw, timestamp),
            Shape::DnsQuery => self.dns_query(raw, timestamp),
            Shape::ScriptBlock => self.script_block(raw, timestamp),
        };

        let kind = match kind {
            Ok(kind) => kind,
            Err(reason) => {
                self.note_failure(format!(
                    "{} id={}: {reason}",
                    raw.wire.provider.as_str(),
                    raw.wire.event_id
                ));
                return None;
            }
        };

        self.counts.note_mapped(shape);
        self.next_event_id += 1;

        Some(TelemetryEvent::new(
            EventId::new(self.next_event_id),
            self.host.clone(),
            timestamp,
            EventSource::WindowsEtw,
            raw.wire.provider.clone(),
            raw.wire.event_id,
            raw.wire.pid,
            raw.wire.tid,
            raw.wire.level,
            kind,
            Payload::empty(),
        ))
    }

    fn process_start(&mut self, raw: &EtwRaw, at: DateTime<Utc>) -> Result<EventKind, String> {
        let image = self
            .decoder
            .text_any(raw, IMAGE_NAME)
            .ok_or("no ImageName; cannot attribute the process")?;

        // The kernel reports paths as `\Device\HarddiskVolumeN\...`. Translate
        // to the DOS form (`C:\...`) that a rule author writes.
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
        }))
    }

    fn registry_set(&mut self, raw: &EtwRaw, at: DateTime<Utc>) -> Result<EventKind, String> {
        let key = self
            .decoder
            .text_any(raw, KEY_NAME)
            .ok_or("no KeyName; cannot tell which key was written")?;

        let value_data = match self.decoder.typed_field(raw, CAPTURED_DATA) {
            Some((FieldValue::Binary(bytes), _)) => {
                let declared = self.decoder.u32_any(raw, REGISTRY_TYPE).unwrap_or(0);
                Some(render_registry_value(declared, &bytes).into())
            }
            Some((other, _)) => Some(render_field(&other).into()),
            None => None,
        };

        Ok(EventKind::RegistrySet(RegistrySet {
            pid: ProcessId::new(raw.wire.pid),
            key_path: key.into(),
            value_name: self.decoder.text_any(raw, VALUE_NAME).map(Into::into),
            value_data,
            set_at: at,
        }))
    }

    fn dns_query(&mut self, raw: &EtwRaw, at: DateTime<Utc>) -> Result<EventKind, String> {
        let name = self
            .decoder
            .text_any(raw, QUERY_NAME)
            .ok_or("no QueryName; cannot tell what was looked up")?;

        Ok(EventKind::DnsQuery(DnsQueryPayload {
            pid: ProcessId::new(raw.wire.pid),
            query_name: name.into(),
            query_type: self
                .decoder
                .u32_any(raw, QUERY_TYPE)
                .map(query_type_name)
                .unwrap_or_else(|| "A".to_string())
                .into(),
            answers: Vec::new(),
            response_code: None,
            queried_at: at,
        }))
    }

    fn script_block(&mut self, raw: &EtwRaw, at: DateTime<Utc>) -> Result<EventKind, String> {
        let text = self
            .decoder
            .text_any(raw, SCRIPT_BLOCK_TEXT)
            .ok_or("no ScriptBlockText; cannot tell what was run")?;

        let path = self
            .decoder
            .text_any(raw, SCRIPT_BLOCK_PATH)
            .map(|p| DevicePaths::global().translate(&p).into_owned());

        Ok(EventKind::ScriptBlock(ScriptBlock {
            pid: ProcessId::new(raw.wire.pid),
            text: cap_script_text(&text).into(),
            script_block_id: self.decoder.text_any(raw, SCRIPT_BLOCK_ID).map(Into::into),
            path: path.map(Into::into),
            message_number: self.decoder.u32_any(raw, MESSAGE_NUMBER),
            message_total: self.decoder.u32_any(raw, MESSAGE_TOTAL),
            recorded_at: at,
        }))
    }
}

fn render_field(value: &FieldValue) -> String {
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
        FieldValue::Guid(b) => hex(b),
        FieldValue::Binary(b) => hex(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use model::{ProviderId, RawEvent};
    use windows::core::GUID;

    const KNOWN_FILETIME: i64 = 133_444_736_000_000_000;

    fn raw(provider: &'static str, event_id: u16, data: Vec<u8>) -> EtwRaw {
        EtwRaw {
            wire: RawEvent {
                source: EventSource::WindowsEtw,
                provider: ProviderId::new(provider),
                event_id,
                timestamp_raw: KNOWN_FILETIME,
                pid: 4242,
                tid: 4243,
                level: 4,
                data,
            },
            guid: GUID::from_u128(0),
            version: 0,
            opcode: 0,
            keyword: 0,
            activity_id: [0; 16],
            related_activity_id: None,
            process_start_key: Some(1),
            is_wow64: false,
        }
    }

    fn translator() -> Translator {
        Translator::new(HostId::new("host-a").unwrap())
    }

    #[test]
    fn filetime_converts_to_the_right_instant() {
        let at = from_filetime(KNOWN_FILETIME).expect("valid filetime");
        assert_eq!(at.to_rfc3339(), "2023-11-14T22:13:20+00:00");
    }

    #[test]
    fn sub_second_filetime_precision_survives() {
        let at = from_filetime(KNOWN_FILETIME + 1_234_567).expect("valid filetime");
        assert_eq!(at.timestamp_subsec_nanos(), 123_456_700);
    }

    #[test]
    fn a_filetime_before_the_unix_epoch_is_refused() {
        assert_eq!(from_filetime(0), None);
        assert_eq!(from_filetime(FILETIME_EPOCH_DELTA - 1), None);
    }

    #[test]
    fn only_the_scored_shapes_are_claimed() {
        assert_eq!(
            shape_of("Microsoft-Windows-Kernel-Process", 1),
            Some(Shape::ProcessStart)
        );
        assert_eq!(
            shape_of("Microsoft-Windows-Kernel-Registry", 5),
            Some(Shape::RegistrySet)
        );
        assert_eq!(
            shape_of("Microsoft-Windows-DNS-Client", 3006),
            Some(Shape::DnsQuery)
        );
        assert_eq!(
            shape_of("Microsoft-Windows-PowerShell", 4104),
            Some(Shape::ScriptBlock)
        );
        assert_eq!(shape_of("Microsoft-Windows-Kernel-Process", 3), None);
        assert_eq!(shape_of("Microsoft-Windows-Kernel-Process", 5), None);
        assert_eq!(shape_of("Some-Third-Party-Provider", 1), None);
        assert_eq!(shape_of("Microsoft-Windows-PowerShell", 4103), None);
        assert_eq!(shape_of("Microsoft-Windows-PowerShell", 4097), None);
    }

    #[test]
    fn kernel_side_classification_is_correct() {
        assert!(Shape::ProcessStart.is_kernel_side());
        assert!(Shape::RegistrySet.is_kernel_side());
        assert!(!Shape::DnsQuery.is_kernel_side());
        assert!(!Shape::ScriptBlock.is_kernel_side());

        assert!(Shape::DnsQuery.is_user_mode());
        assert!(Shape::ScriptBlock.is_user_mode());
        assert!(!Shape::ProcessStart.is_user_mode());
    }

    #[test]
    fn a_script_block_without_the_machine_schema_is_not_invented() {
        let raw = raw("Microsoft-Windows-PowerShell", 4104, vec![1, 2, 3, 4]);
        let mut t = translator();
        assert!(t.translate(&raw).is_none());
        assert_eq!(t.mapped(), 0);
        assert_eq!(t.undecodable(), 1);
        assert_eq!(t.counts().attempted(Shape::ScriptBlock), 1);
        assert_eq!(t.counts().mapped(Shape::ScriptBlock), 0);
    }

    #[test]
    fn a_long_script_is_capped_at_a_character_boundary() {
        let long = "e".repeat(MAX_SCRIPT_TEXT * 2);
        assert_eq!(cap_script_text(&long).len(), MAX_SCRIPT_TEXT);

        let mut text = "a".repeat(MAX_SCRIPT_TEXT - 1);
        text.push('\u{20ac}');
        text.push_str(&"b".repeat(100));
        let capped = cap_script_text(&text);
        assert_eq!(
            capped.len(),
            MAX_SCRIPT_TEXT - 1,
            "the euro sign is dropped"
        );
        assert!(text.starts_with(capped));

        assert_eq!(cap_script_text("short"), "short");
    }

    #[test]
    fn query_types_map_to_mnemonics_and_fall_back_to_numbers() {
        assert_eq!(query_type_name(1), "A");
        assert_eq!(query_type_name(28), "AAAA");
        assert_eq!(query_type_name(65), "HTTPS");
        assert_eq!(
            query_type_name(99),
            "99",
            "an unknown type is reported as itself, not as a wrong mnemonic"
        );
    }

    #[test]
    fn registry_values_render_by_their_declared_reg_type() {
        let sz: Vec<u8> = "C:\\x"
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(render_registry_value(reg_type::SZ, &sz), "C:\\x");
        assert_eq!(render_registry_value(reg_type::EXPAND_SZ, &sz), "C:\\x");
        assert_eq!(
            render_registry_value(reg_type::DWORD, &[0x01, 0, 0, 0]),
            "1"
        );
        assert_eq!(
            render_registry_value(reg_type::QWORD, &[1, 0, 0, 0, 0, 0, 0, 0]),
            "1"
        );
        assert_eq!(
            render_registry_value(reg_type::BINARY, &[1, 2, 3]),
            "010203"
        );
        assert_eq!(render_registry_value(0xdead, &[1, 2, 3]), "010203");
    }

    #[test]
    fn unscored_traffic_is_counted_as_unrecognised_not_as_undecodable() {
        // The distinction the counters rest on: a busy machine is not a
        // broken sensor. Thread events must move `unrecognised`, not
        // `undecodable`, and the totals must add up.
        let mut t = translator();
        for id in [2u16, 3, 4, 5, 6] {
            assert!(
                t.translate(&raw("Microsoft-Windows-Kernel-Process", id, vec![1, 2, 3]))
                    .is_none()
            );
        }
        assert!(
            t.translate(&raw("Some-Other-Provider", 1, vec![1]))
                .is_none()
        );
        assert_eq!(t.undecodable(), 0);
        assert_eq!(t.mapped(), 0);
        assert_eq!(t.counts().unrecognised(), 6);
        assert_eq!(t.counts().total_attempted(), 0);
    }

    #[test]
    fn the_translator_accounting_closes() {
        // Every event the translator received is either mapped, undecodable,
        // or unrecognised. Before the `unrecognised` counter, the shape
        // match silently dropped events and the accounting broke.
        let mut t = translator();
        t.translate(&raw("Microsoft-Windows-Kernel-Process", 1, Vec::new())); // undecodable
        t.translate(&raw("Microsoft-Windows-Kernel-Process", 3, Vec::new())); // unrecognised
        t.translate(&raw("Some-Other-Provider", 1, Vec::new())); // unrecognised

        let total = t.mapped() + t.undecodable() + t.counts().unrecognised();
        assert_eq!(total, 3, "three events were delivered, three are accounted for");
    }

    #[test]
    fn a_header_only_process_start_is_undecodable_rather_than_invented() {
        let mut t = translator();
        assert!(
            t.translate(&raw("Microsoft-Windows-Kernel-Process", 1, Vec::new()))
                .is_none()
        );
        assert_eq!(t.mapped(), 0);
        assert_eq!(t.undecodable(), 1);
        assert!(
            t.failures()[0].contains("ImageName"),
            "the reason must name the field that failed: {:?}",
            t.failures()
        );
    }

    #[test]
    fn each_shape_names_its_own_missing_field() {
        let mut t = translator();
        t.translate(&raw("Microsoft-Windows-Kernel-Process", 1, Vec::new()));
        t.translate(&raw("Microsoft-Windows-Kernel-Registry", 5, Vec::new()));
        t.translate(&raw("Microsoft-Windows-DNS-Client", 3006, Vec::new()));
        t.translate(&raw("Microsoft-Windows-PowerShell", 4104, Vec::new()));
        assert_eq!(t.undecodable(), 4);
        assert!(t.failures()[0].contains("ImageName"), "{:?}", t.failures());
        assert!(t.failures()[1].contains("KeyName"), "{:?}", t.failures());
        assert!(t.failures()[2].contains("QueryName"), "{:?}", t.failures());
        assert!(
            t.failures()[3].contains("ScriptBlockText"),
            "{:?}",
            t.failures()
        );
    }

    #[test]
    fn an_unusable_timestamp_is_reported_and_not_scored() {
        let mut t = translator();
        let mut bad = raw("Microsoft-Windows-Kernel-Process", 1, vec![0; 8]);
        bad.wire.timestamp_raw = 0;
        assert!(t.translate(&bad).is_none());
        assert_eq!(t.undecodable(), 1);
        assert!(t.failures()[0].contains("FILETIME"), "{:?}", t.failures());
    }

    #[test]
    fn the_failure_log_is_bounded() {
        let mut t = translator();
        for _ in 0..500 {
            t.translate(&raw("Microsoft-Windows-Kernel-Process", 1, Vec::new()));
        }
        assert_eq!(t.undecodable(), 500);
        assert_eq!(t.failures().len(), KEPT_FAILURES);
    }

    #[test]
    fn per_shape_counts_separate_a_quiet_shape_from_a_broken_one() {
        let mut t = translator();
        t.translate(&raw("Microsoft-Windows-Kernel-Process", 1, Vec::new()));
        t.translate(&raw("Microsoft-Windows-DNS-Client", 3006, Vec::new()));
        t.translate(&raw("Microsoft-Windows-DNS-Client", 3006, Vec::new()));

        assert_eq!(t.counts().attempted(Shape::ProcessStart), 1);
        assert_eq!(t.counts().mapped(Shape::ProcessStart), 0);
        assert_eq!(t.counts().attempted(Shape::DnsQuery), 2);
        assert_eq!(t.counts().mapped(Shape::DnsQuery), 0);
        assert_eq!(t.counts().attempted(Shape::RegistrySet), 0);
        assert_eq!(t.counts().attempted(Shape::ScriptBlock), 0);
        assert_eq!(t.undecodable(), 3);
        assert_eq!(t.counts().total_attempted(), 3);
    }

    #[test]
    fn by_shape_iterates_in_a_stable_order() {
        let mut t = translator();
        t.translate(&raw("Microsoft-Windows-DNS-Client", 3006, Vec::new()));
        let seen: Vec<Shape> = t.counts().by_shape().map(|(s, _, _)| s).collect();
        assert_eq!(
            seen,
            vec![
                Shape::ProcessStart,
                Shape::RegistrySet,
                Shape::DnsQuery,
                Shape::ScriptBlock
            ]
        );
    }

    #[test]
    fn an_idle_sensor_reports_no_gaps() {
        let t = translator();
        assert!(t.detect_gaps().is_empty());
    }

    #[test]
    fn a_shape_that_never_fired_is_untested_not_silent() {
        let mut t = translator();
        t.translate(&raw("Microsoft-Windows-DNS-Client", 3006, Vec::new()));

        let gaps = t.detect_gaps();
        assert_eq!(gaps.len(), 1, "{gaps:?}");
        assert_eq!(gaps[0].shape, Shape::DnsQuery);
        assert_eq!(gaps[0].severity, GapSeverity::DecodeFailure);

        assert!(!t.counts().ever_fired(Shape::ProcessStart));
        assert!(!t.counts().ever_fired(Shape::ScriptBlock));
    }

    #[test]
    fn a_shape_that_stopped_firing_is_silent() {
        let mut t = translator();
        t.translate(&raw("Microsoft-Windows-DNS-Client", 3006, Vec::new()));
        assert!(t.counts().ever_fired(Shape::DnsQuery));

        for _ in 0..3 {
            t.translate(&raw("Microsoft-Windows-Kernel-Registry", 5, Vec::new()));
        }

        let gaps = t.detect_gaps();
        let dns_gap = gaps
            .iter()
            .find(|g| g.shape == Shape::DnsQuery)
            .expect("DNS gap should be present");
        assert_eq!(dns_gap.severity, GapSeverity::Silent);

        assert!(gaps.iter().all(|g| g.shape != Shape::ScriptBlock));
    }

    #[test]
    fn a_decode_failure_is_not_a_silent_gap() {
        let mut t = translator();
        for _ in 0..3 {
            t.translate(&raw("Microsoft-Windows-Kernel-Registry", 5, Vec::new()));
        }
        t.translate(&raw("Microsoft-Windows-Kernel-Process", 1, Vec::new()));

        let gaps = t.detect_gaps();
        let registry_gap = gaps
            .iter()
            .find(|g| g.shape == Shape::RegistrySet)
            .expect("registry gap");
        assert_eq!(registry_gap.severity, GapSeverity::DecodeFailure);
        assert_eq!(registry_gap.attempted, 3);
        assert_eq!(registry_gap.mapped, 0);
    }

    #[test]
    fn silent_gaps_sort_before_decode_failures() {
        let mut t = translator();
        t.translate(&raw("Microsoft-Windows-DNS-Client", 3006, Vec::new()));
        for _ in 0..2 {
            t.translate(&raw("Microsoft-Windows-Kernel-Registry", 5, Vec::new()));
        }

        let gaps = t.detect_gaps();
        assert!(gaps.len() >= 2, "{gaps:?}");
        assert_eq!(gaps[0].severity, GapSeverity::Silent);
    }

    #[test]
    fn a_gap_describes_itself_usefully() {
        let gap = TelemetryGap {
            shape: Shape::ScriptBlock,
            attempted: 0,
            mapped: 0,
            severity: GapSeverity::Silent,
        };
        let text = gap.describe();
        assert!(text.contains("script_block"));
        assert!(text.contains("silent"));

        let decode_gap = TelemetryGap {
            shape: Shape::RegistrySet,
            attempted: 10,
            mapped: 3,
            severity: GapSeverity::DecodeFailure,
        };
        let text = decode_gap.describe();
        assert!(text.contains("registry_set"));
        assert!(text.contains("7 of 10"));
    }

    #[test]
    fn summary_reports_every_shape_and_unrecognised() {
        let mut t = translator();
        t.translate(&raw("Microsoft-Windows-Kernel-Process", 1, Vec::new()));
        t.translate(&raw("Microsoft-Windows-Kernel-Process", 3, Vec::new())); // unrecognised
        let s = t.summary();
        assert!(s.contains("process_start: 0/1"), "{s}");
        assert!(s.contains("registry_set: 0/0"), "{s}");
        assert!(s.contains("dns_query: 0/0"), "{s}");
        assert!(s.contains("script_block: 0/0"), "{s}");
        assert!(s.contains("unrecognised: 1"), "{s}");
    }
}
