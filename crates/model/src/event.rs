use crate::{HostId, ModelError, Value};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::sync::Arc;

pub const CURRENT_SCHEMA_VERSION: u16 = 1;
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
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "payload exceeds maximum size",
            ));
        }
        Ok(buf.len())
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Payload {
    value: Value,
    value_size: usize,
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
        Ok(Self {
            value,
            value_size: counter.written,
        })
    }

    #[inline]
    pub fn value(&self) -> &Value {
        &self.value
    }

    #[inline]
    pub fn into_value(self) -> Value {
        self.value
    }

    #[inline]
    pub fn value_size(&self) -> usize {
        self.value_size
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
