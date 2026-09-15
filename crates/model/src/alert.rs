use crate::{EventId, HostId, ModelError, RuleId, Severity};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertStatus {
    New,
    Investigating,
    Closed,
    FalsePositive,
}

impl Default for AlertStatus {
    #[inline]
    fn default() -> Self {
        AlertStatus::New
    }
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
    #[serde(default)]
    pub status: AlertStatus,
}

impl Alert {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: AlertId,
        rule_id: RuleId,
        title: Box<str>,
        description: Box<str>,
        severity: Severity,
        timestamp: DateTime<Utc>,
        host: HostId,
        events: Vec<EventId>,
        mitre_techniques: Vec<Box<str>>,
    ) -> Self {
        Self {
            id,
            rule_id,
            title,
            description,
            severity,
            timestamp,
            host,
            events,
            mitre_techniques,
            status: AlertStatus::New,
        }
    }

    #[inline]
    pub fn with_status(mut self, status: AlertStatus) -> Self {
        self.status = status;
        self
    }
}
