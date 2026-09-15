use crate::ModelError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HostId(Box<str>);

impl HostId {
    pub fn new(s: impl Into<Box<str>>) -> Result<Self, ModelError> {
        let s = s.into();
        if s.is_empty() {
            return Err(ModelError::EmptyField { field: "host_id" });
        }
        Ok(Self(s))
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub id: HostId,
    pub hostname: Box<str>,
    pub os: OperatingSystem,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub labels: crate::value::Map,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperatingSystem {
    Windows,
    Linux,
    MacOs,
    Unknown,
}
