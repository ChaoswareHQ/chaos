use crate::HostId;
use crate::ModelError;
use crate::Value;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProviderId(String);

impl ProviderId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EventId(u64);

impl EventId {
    pub fn new(n: u64) -> Self {
        Self(n)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

pub const MAX_PAYLOAD_SIZE: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Payload {
    value: Value,
    size: usize,
}

impl Payload {
    pub fn new(value: Value) -> Result<Self, ModelError> {
        let size = serde_json::to_vec(&value)
            .map_err(|e| ModelError::InvalidValue {
                field: "payload",
                value: e.to_string(),
            })?
            .len();
        if size > MAX_PAYLOAD_SIZE {
            return Err(ModelError::PayloadTooLarge {
                size,
                max: MAX_PAYLOAD_SIZE,
            });
        }
        Ok(Self { value, size })
    }

    pub fn value(&self) -> &Value {
        &self.value
    }

    pub fn size(&self) -> usize {
        self.size
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    pub source: EventSource,
    pub provider: ProviderId,
    pub event_id: u16,
    pub pid: u32,
    pub tid: u32,
    pub level: u8,
    pub payload: Payload,
}
