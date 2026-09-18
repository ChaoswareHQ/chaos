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
//!   field sized by `CapturedDataSize`. There is no `Data` or `ValueData`
//!   string.
//!
//! # Why the failure counters matter
//!
//! A property name that does not resolve on a given machine is a silent hole:
//! events arrive, map to nothing, and the console reports a calm host rather
//! than a broken sensor. [`Translator::undecodable`] and
//! [`Translator::first_failures`] exist so that cannot happen quietly — a
//! non-zero `undecodable` means this table is wrong, not that the machine is
//! idle.

use crate::callback::EtwRaw;
use crate::decode::Decoder;
use chrono::{DateTime, Utc};
use model::{
    DnsQueryPayload, EventId, EventKind, EventSource, HostId, Payload, ProcessId, ProcessStart,
    RegistrySet, TelemetryEvent,
};

/// ETW's `TimeStamp` is a `FILETIME`: 100-nanosecond intervals since 1601-01-01.
/// The offset to the Unix epoch is a constant, not something to derive at
/// runtime and get subtly wrong.
const FILETIME_EPOCH_DELTA: i64 = 116_444_736_000_000_000;
const FILETIME_TICKS_PER_SEC: i64 = 10_000_000;

/// Convert an ETW timestamp to UTC.
///
/// Returns `None` for anything that cannot be a real instant, because a wrong
/// timestamp is worse than a missing event: the engine builds a causal order
/// from these, and a plausible-looking wrong one would corrupt it silently.
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
enum Shape {
    ProcessStart,
    RegistrySet,
    DnsQuery,
}

/// Which ETW event becomes which wire event.
///
/// Keyed on provider and event id rather than on the event's name: a name has
/// to be looked up and can be absent, while the ids are what the manifests
/// declare and what the callback already carries.
fn shape_of(provider: &str, event_id: u16) -> Option<Shape> {
    match (provider, event_id) {
        ("Microsoft-Windows-Kernel-Process", 1) => Some(Shape::ProcessStart),
        ("Microsoft-Windows-Kernel-Registry", 5) => Some(Shape::RegistrySet),
        ("Microsoft-Windows-DNS-Client", 3006) => Some(Shape::DnsQuery),
        _ => None,
    }
}

// Property names, most specific first. See the module docs for where these came
// from and why each is a chain.
const PROCESS_ID: &[&str] = &["ProcessID", "ProcessId"];
const PARENT_PROCESS_ID: &[&str] = &["ParentProcessID", "ParentProcessId"];
const IMAGE_NAME: &[&str] = &["ImageName"];
const KEY_NAME: &[&str] = &["KeyName"];
const VALUE_NAME: &[&str] = &["ValueName"];
const VALUE_DATA: &[&str] = &["CapturedData"];
const QUERY_NAME: &[&str] = &["QueryName"];
const QUERY_TYPE: &[&str] = &["QueryType"];

/// How many decode failures to keep the reason for.
const KEPT_FAILURES: usize = 8;

/// A DNS query type number as the mnemonic an analyst recognises.
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
        // Better a number than a wrong mnemonic.
        other => return other.to_string(),
    };
    known.to_string()
}

/// Translates raw ETW events, and reports what it could not translate.
pub struct Translator {
    host: HostId,
    decoder: Decoder,
    next_event_id: u64,
    /// Events that became a wire event.
    mapped: u64,
    /// Events of a shape we want whose essential field did not resolve. This is
    /// the number that matters: it means the tables above are wrong for this
    /// machine rather than that nothing happened.
    undecodable: u64,
    /// The first few reasons, so a failure is diagnosable from the console
    /// rather than from a debugger.
    failures: Vec<String>,
}

impl Translator {
    pub fn new(host: HostId) -> Self {
        Self {
            host,
            decoder: Decoder::new(),
            next_event_id: 0,
            mapped: 0,
            undecodable: 0,
            failures: Vec::new(),
        }
    }

    pub fn mapped(&self) -> u64 {
        self.mapped
    }

    pub fn undecodable(&self) -> u64 {
        self.undecodable
    }

    pub fn failures(&self) -> &[String] {
        &self.failures
    }

    fn note_failure(&mut self, reason: String) {
        self.undecodable += 1;
        if self.failures.len() < KEPT_FAILURES {
            self.failures.push(reason);
        }
    }

    /// Translate one event, or return `None` if it is not something this sensor
    /// scores or not something it could decode.
    pub fn translate(&mut self, raw: &EtwRaw) -> Option<TelemetryEvent> {
        // Most ETW traffic is not a shape we score, and that is not a failure:
        // returning early here keeps `undecodable` meaning "broken", not "busy".
        let shape = shape_of(raw.wire.provider.as_str(), raw.wire.event_id)?;

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

        self.mapped += 1;
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
            // The decoded fields are what the rules read and they are already in
            // the kind, so shipping the raw provider payload as well would put
            // every string on the wire twice for no detection benefit.
            Payload::empty(),
        ))
    }

    fn process_start(&mut self, raw: &EtwRaw, at: DateTime<Utc>) -> Result<EventKind, String> {
        let image = self
            .decoder
            .text_any(raw, IMAGE_NAME)
            .ok_or("no ImageName; cannot attribute the process")?;

        // The header pid is the process that was started, so it is a correct
        // fallback rather than a guess.
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
            // Not omitted by choice: this provider has no command-line field.
            // See the module docs.
            command_line: None,
            // The user is a property of the token, not of this event; the
            // kernel provider does not carry it.
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

        Ok(EventKind::RegistrySet(RegistrySet {
            pid: ProcessId::new(raw.wire.pid),
            key_path: key.into(),
            value_name: self.decoder.text_any(raw, VALUE_NAME).map(Into::into),
            // Binary, so `text` renders it as hex. The run-key rule reads the
            // key path, so this is carried for the analyst rather than the
            // detector.
            value_data: self.decoder.text_any(raw, VALUE_DATA).map(Into::into),
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
            // Answers arrive on the companion response event, 3008.
            answers: Vec::new(),
            response_code: None,
            queried_at: at,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use model::{ProviderId, RawEvent};
    use windows::core::GUID;

    /// 2023-11-14T22:13:20Z, which is Unix 1700000000, as a FILETIME.
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
        }
    }

    fn translator() -> Translator {
        Translator::new(HostId::new("host-a").unwrap())
    }

    #[test]
    fn filetime_converts_to_the_right_instant() {
        // 133446000000000000 ticks = 2023-11-14T22:13:20Z.
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
        // Not "1970 or later" pedantry: a zero timestamp is what a malformed
        // header produces, and accepting it would place evidence in 1601.
        assert_eq!(from_filetime(0), None);
        assert_eq!(from_filetime(FILETIME_EPOCH_DELTA - 1), None);
    }

    #[test]
    fn only_the_three_scored_shapes_are_claimed() {
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
        // Thread churn and image loads arrive constantly and are not scored.
        assert_eq!(shape_of("Microsoft-Windows-Kernel-Process", 3), None);
        assert_eq!(shape_of("Microsoft-Windows-Kernel-Process", 5), None);
        assert_eq!(shape_of("Some-Third-Party-Provider", 1), None);
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
    fn unscored_traffic_is_not_counted_as_undecodable() {
        // The distinction the counters rest on: a busy machine is not a broken
        // sensor, so thread events must not move `undecodable`.
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
    }

    #[test]
    fn a_header_only_process_start_is_undecodable_rather_than_invented() {
        // TDH cannot name a field on an empty payload, so the image is absent.
        // Emitting the event anyway would create a process with no image, and
        // every path-based rule would then be reasoning about a fiction.
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
        t.translate(&raw("Microsoft-Windows-Kernel-Registry", 5, Vec::new()));
        t.translate(&raw("Microsoft-Windows-DNS-Client", 3006, Vec::new()));
        assert_eq!(t.undecodable(), 2);
        assert!(t.failures()[0].contains("KeyName"), "{:?}", t.failures());
        assert!(t.failures()[1].contains("QueryName"), "{:?}", t.failures());
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
        // A broken field table must not turn into unbounded memory on a machine
        // producing tens of thousands of events a second.
        let mut t = translator();
        for _ in 0..500 {
            t.translate(&raw("Microsoft-Windows-Kernel-Process", 1, Vec::new()));
        }
        assert_eq!(t.undecodable(), 500);
        assert_eq!(t.failures().len(), KEPT_FAILURES);
    }
}
