use crate::ModelError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// A host's identity, cheap to clone.
///
/// `Arc<str>` rather than `Box<str>` because this travels on every event and the
/// sensor clones it once per event. A `Box` would make that a malloc and a copy
/// per event, on the hot path, for a string that never changes; an `Arc` makes it
/// an atomic increment. It is also what [`crate::ProviderId`] already does, and
/// two identifiers on the same event behaving differently was the surprise worth
/// removing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HostId(Arc<str>);

impl HostId {
    pub fn new(s: impl AsRef<str>) -> Result<Self, ModelError> {
        let s = s.as_ref();
        if s.is_empty() {
            return Err(ModelError::EmptyField { field: "host_id" });
        }
        Ok(Self(Arc::from(s)))
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

impl Host {
    pub fn new(id: HostId, hostname: Box<str>, os: OperatingSystem, now: DateTime<Utc>) -> Self {
        Self {
            id,
            hostname,
            os,
            first_seen: now,
            last_seen: now,
            labels: crate::value::Map::new(),
        }
    }

    #[inline]
    pub fn touch(&mut self, now: DateTime<Utc>) {
        self.last_seen = now;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperatingSystem {
    Windows,
    Linux,
    MacOs,
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_id_cannot_be_empty() {
        assert!(HostId::new("").is_err());
        assert_eq!(HostId::new("host-a").expect("valid").as_str(), "host-a");
        assert_eq!(
            HostId::new(String::from("host-b")).expect("valid").as_str(),
            "host-b"
        );
    }

    #[test]
    fn cloning_a_host_id_shares_the_name_instead_of_copying_it() {
        // The reason this is an `Arc` and not a `Box`: the sensor clones a
        // `HostId` once per event, and an allocation there would be on the hot
        // path for a string that never changes. Pointer identity is the only way
        // to see that from outside, and it is exactly the property that matters.
        let id = HostId::new("host-a").expect("valid");
        let copy = id.clone();
        assert_eq!(copy, id);
        assert_eq!(
            copy.as_str().as_ptr(),
            id.as_str().as_ptr(),
            "a clone must not allocate a second copy of the name"
        );
    }

    #[test]
    fn a_host_id_round_trips_through_json_as_a_plain_string() {
        // The wire format must not learn that the in-memory type changed.
        let id = HostId::new("host-a").expect("valid");
        let json = serde_json::to_string(&id).expect("serializes");
        assert_eq!(json, "\"host-a\"");
        assert_eq!(serde_json::from_str::<HostId>(&json).expect("parses"), id);
    }
}
