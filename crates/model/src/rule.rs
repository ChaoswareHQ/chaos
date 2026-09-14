use crate::ModelError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RuleId(String);

impl RuleId {
    pub fn new(s: impl Into<String>) -> Result<Self, ModelError> {
        let s = s.into();
        if s.is_empty() {
            return Err(ModelError::EmptyField { field: "rule_id" });
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: RuleId,
    pub title: String,
    pub description: String,
    pub severity: super::alert::Severity,
    pub mitre_techniques: Vec<String>,
    pub sigma_yaml: Option<String>,
    pub enabled: bool,
}
