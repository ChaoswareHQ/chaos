use crate::HostId;
use crate::ModelError;
use crate::Value;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::sync::Arc;

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
    pub fn new(n: u64) -> Self {
        Self(n)
    }

    #[inline]
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

pub const MAX_PAYLOAD_SIZE: usize = 65_536;

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
    size: usize,
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
            size: counter.written,
        })
    }

    #[inline]
    pub fn value(&self) -> &Value {
        &self.value
    }

    #[inline]
    pub fn size(&self) -> usize {
        self.size
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
    pub source: EventSource,
    pub provider: ProviderId,
    pub event_id: u16,
    pub pid: u32,
    pub tid: u32,
    pub level: u8,
    pub payload: Payload,
}
