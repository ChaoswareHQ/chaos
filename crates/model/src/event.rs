use crate::{HostId, ModelError, Value};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::sync::Arc;

/// The schema version every event carries.
///
/// Bumped to 2 when [`Payload`] stopped being two fields on the wire. It is one
/// field now, so a `1` event and a `2` event are not interchangeable, and a
/// number that says so is worth more than a comment nobody reads.
pub const CURRENT_SCHEMA_VERSION: u16 = 2;
pub const MAX_PAYLOAD_SIZE: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProviderId(Arc<str>);

impl ProviderId {
    #[inline]
    pub fn new(s: impl AsRef<str>) -> Self {
        Self(Arc::from(s.as_ref()))
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EventId(u64);

impl EventId {
    #[inline]
    pub const fn new(n: u64) -> Self {
        Self(n)
    }

    #[inline]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

struct LimitedCounter {
    written: usize,
    limit: usize,
}

impl Write for LimitedCounter {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written += buf.len();
        if self.written > self.limit {
            return Err(io::Error::other("payload exceeds maximum size"));
        }
        Ok(buf.len())
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The provider's own fields, as they came off the wire.
///
/// # Why this is transparent on the wire
///
/// It used to serialize as `{"value":...,"value_size":N}`, and the size was
/// written and read by nobody: the measurement exists to *enforce* the ceiling,
/// not to be stored. Carrying it cost about fifteen bytes on every event and
/// bought nothing, so the struct is transparent and the JSON is just the value.
///
/// # Why the ceiling is measured while writing
///
/// The serialised size is the thing with a limit, and counting as the writer
/// runs means an oversized payload is rejected without ever building the
/// oversized buffer — which matters, because the input is attacker influenced.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Payload {
    value: Value,
}

impl Payload {
    pub fn new(value: Value) -> Result<Self, ModelError> {
        let mut counter = LimitedCounter {
            written: 0,
            limit: MAX_PAYLOAD_SIZE,
        };
        serde_json::to_writer(&mut counter, &value).map_err(|e| {
            if counter.written > MAX_PAYLOAD_SIZE {
                ModelError::PayloadTooLarge {
                    size: counter.written,
                    max: MAX_PAYLOAD_SIZE,
                }
            } else {
                ModelError::InvalidValue {
                    field: "payload",
                    value: e.to_string().into_boxed_str(),
                }
            }
        })?;
        Ok(Self { value })
    }

    /// A payload with nothing in it.
    ///
    /// The ETW path ships no raw payload — the decoded fields *are* the event —
    /// so this is the common case, and it should not pay for a serialisation
    /// pass per event to rediscover that `null` fits in 64 KiB. The ceiling is
    /// not being skipped, it is being answered: four bytes against sixty-five
    /// thousand is not a measured thing.
    #[inline]
    pub const fn empty() -> Self {
        Self { value: Value::Null }
    }

    #[inline]
    pub fn value(&self) -> &Value {
        &self.value
    }

    #[inline]
    pub fn into_value(self) -> Value {
        self.value
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventSource {
    WindowsEtw,
    LinuxEbpf,
    MacOsEs,
}

#[derive(Debug, Clone)]
pub struct RawEvent {
    pub source: EventSource,
    pub provider: ProviderId,
    pub event_id: u16,
    pub timestamp_raw: i64,
    pub pid: u32,
    pub tid: u32,
    pub level: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub id: EventId,
    pub host: HostId,
    pub timestamp: DateTime<Utc>,
    #[serde(default)]
    pub received_at: Option<DateTime<Utc>>,
    #[serde(default = "default_schema_version")]
    pub schema_version: u16,
    pub source: EventSource,
    pub provider: ProviderId,
    pub event_id: u16,
    pub pid: u32,
    pub tid: u32,
    pub level: u8,
    pub kind: crate::kind::EventKind,
    pub payload: Payload,
}

impl TelemetryEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: EventId,
        host: HostId,
        timestamp: DateTime<Utc>,
        source: EventSource,
        provider: ProviderId,
        event_id: u16,
        pid: u32,
        tid: u32,
        level: u8,
        kind: crate::kind::EventKind,
        payload: Payload,
    ) -> Self {
        Self {
            id,
            host,
            timestamp,
            received_at: None,
            schema_version: CURRENT_SCHEMA_VERSION,
            source,
            provider,
            event_id,
            pid,
            tid,
            level,
            kind,
            payload,
        }
    }

    #[inline]
    pub fn with_received_at(mut self, ts: DateTime<Utc>) -> Self {
        self.received_at = Some(ts);
        self
    }

    #[inline]
    pub fn with_schema_version(mut self, v: u16) -> Self {
        self.schema_version = v;
        self
    }
}

#[inline]
fn default_schema_version() -> u16 {
    CURRENT_SCHEMA_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Map;

    #[test]
    fn a_payload_is_the_value_and_nothing_else_on_the_wire() {
        // It used to be `{"value":...,"value_size":N}`. The size is a ceiling
        // being enforced, not a fact worth shipping, and a wrapper that came back
        // would put fifteen bytes on every event for nothing. This test is the
        // only thing that would notice.
        let payload = Payload::new(Value::Int(7)).expect("small enough");
        assert_eq!(serde_json::to_string(&payload).expect("serializes"), "7");

        let mut map = Map::new();
        map.insert("ImageName".into(), Value::String("x".into()));
        let payload = Payload::new(Value::Object(map)).expect("small enough");
        assert_eq!(
            serde_json::to_string(&payload).expect("serializes"),
            r#"{"ImageName":"x"}"#
        );
        assert_eq!(
            serde_json::from_str::<Payload>(r#"{"ImageName":"x"}"#).expect("parses"),
            payload
        );
    }

    #[test]
    fn a_positive_integer_is_canonicalised_to_unsigned_by_a_round_trip() {
        // Not a property anyone would guess, and it used to be invisible. JSON
        // has one number type, so the deserialiser picks a variant from the value
        // alone: anything non-negative arrives as `visit_u64`, so `Int(7)` and
        // `Uint(7)` are the same event on the wire and only the second one comes
        // back. Worth pinning rather than discovering while comparing a decoded
        // payload against a hand-built one.
        assert_eq!(
            serde_json::from_str::<Payload>("7")
                .expect("parses")
                .value(),
            &Value::Uint(7),
            "a non-negative integer is canonicalised to Uint"
        );
        // Negative values have only one representation, so they survive exactly.
        let negative = Payload::new(Value::Int(-7)).expect("small enough");
        assert_eq!(
            serde_json::from_str::<Payload>("-7").expect("parses"),
            negative
        );
        // And above i64::MAX only Uint can hold it.
        let wide = Payload::new(Value::Uint(u64::MAX)).expect("small enough");
        assert_eq!(
            serde_json::from_str::<Payload>(&u64::MAX.to_string())
                .expect("parses")
                .value(),
            wide.value()
        );
        assert_eq!(wide.value().as_u64(), Some(u64::MAX));
    }

    #[test]
    fn an_empty_payload_is_null_and_costs_nothing_to_build() {
        let payload = Payload::empty();
        assert!(payload.value().is_null());
        assert_eq!(serde_json::to_string(&payload).expect("serializes"), "null");
        assert_eq!(
            serde_json::from_str::<Payload>("null").expect("parses"),
            payload
        );
    }

    #[test]
    fn the_ceiling_is_still_enforced() {
        // The reason `Payload::new` measures at all, and the one property that
        // must survive making the struct transparent.
        let huge = Value::String("x".repeat(MAX_PAYLOAD_SIZE + 1).into());
        assert!(matches!(
            Payload::new(huge),
            Err(ModelError::PayloadTooLarge { .. })
        ));

        let fits = Value::String("x".repeat(1024).into());
        assert!(Payload::new(fits).is_ok());
    }

    #[test]
    fn a_script_block_announces_itself_by_name_on_the_wire() {
        // The tag is the whole contract. Misspell it and the far end does not
        // complain: `#[serde(other)]` turns an unknown tag into `Unclassified`,
        // so the event arrives, counts, and means nothing. Silently.
        let event = TelemetryEvent::new(
            EventId::new(11),
            HostId::new("host-a").expect("valid"),
            DateTime::from_timestamp(1_700_000_000, 0).expect("valid instant"),
            EventSource::WindowsEtw,
            ProviderId::new("Microsoft-Windows-PowerShell"),
            4104,
            42,
            42,
            4,
            crate::EventKind::ScriptBlock(crate::ScriptBlock {
                pid: crate::ProcessId::new(42),
                text: "Invoke-Expression $x".into(),
                script_block_id: Some("{abc}".into()),
                path: None,
                message_number: Some(1),
                message_total: Some(1),
                recorded_at: DateTime::from_timestamp(1_700_000_000, 0).expect("valid instant"),
            }),
            Payload::empty(),
        );

        let json = serde_json::to_string(&event).expect("serializes");
        assert!(json.contains(r#""kind":"script_block""#), "{json}");

        let reparsed = serde_json::from_str::<TelemetryEvent>(&json).expect("parses");
        match &reparsed.kind {
            crate::EventKind::ScriptBlock(block) => {
                assert_eq!(block.text.as_ref(), "Invoke-Expression $x");
                assert_eq!(block.pid.as_u32(), 42);
                // Absent optionals must stay absent rather than becoming empty.
                assert!(block.path.is_none());
            }
            other => panic!("the tag did not survive: {other:?}"),
        }
        assert_eq!(serde_json::to_string(&reparsed).expect("serializes"), json);
    }

    #[test]
    fn an_event_from_a_newer_agent_is_unclassified_rather_than_a_parse_failure() {
        // The forward-compatibility promise `#[serde(other)]` makes, and the
        // reason adding a variant is additive.
        let json = r#"{"kind":"something_from_the_future","pid":1}"#;
        let parsed = serde_json::from_str::<crate::EventKind>(json).expect("parses");
        assert_eq!(parsed, crate::EventKind::Unclassified);
    }

    #[test]
    fn a_payload_round_trips_through_a_whole_event() {
        // The transparent attribute is on the type, but the field it lives in is
        // what actually has to keep working.
        let event = TelemetryEvent::new(
            EventId::new(9),
            HostId::new("host-a").expect("valid"),
            DateTime::from_timestamp(1_700_000_000, 0).expect("valid instant"),
            EventSource::WindowsEtw,
            ProviderId::new("Microsoft-Windows-Kernel-Process"),
            1,
            42,
            42,
            4,
            crate::EventKind::Unclassified,
            Payload::empty(),
        );

        let json = serde_json::to_string(&event).expect("serializes");
        assert!(json.contains(r#""payload":null"#), "{json}");
        assert!(json.contains(r#""schema_version":2"#), "{json}");

        // Compared as JSON rather than as values: `TelemetryEvent` deliberately
        // does not derive `PartialEq`, and adding it for a test would be the tail
        // wagging the dog.
        let reparsed = serde_json::from_str::<TelemetryEvent>(&json).expect("parses");
        assert_eq!(serde_json::to_string(&reparsed).expect("serializes"), json);
    }
}
