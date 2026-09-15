use crate::EventId;
use crate::HostId;
use crate::ModelError;
use crate::RuleId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AlertId(Box<str>);

impl AlertId {
    pub fn new(s: impl Into<Box<str>>) -> Result<Self, ModelError> {
        let s = s.into();
        if s.is_empty() {
            return Err(ModelError::EmptyField { field: "alert_id" });
        }
        Ok(Self(s))
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: AlertId,
    pub rule_id: RuleId,
    pub title: Box<str>,
    pub description: Box<str>,
    pub severity: Severity,
    pub timestamp: DateTime<Utc>,
    pub host: HostId,
    pub events: Vec<EventId>,
    pub mitre_techniques: Vec<Box<str>>,
}
