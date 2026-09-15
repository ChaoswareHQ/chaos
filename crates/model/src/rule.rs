use crate::ModelError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuleId(Box<str>);

impl RuleId {
    pub fn new(s: impl Into<Box<str>>) -> Result<Self, ModelError> {
        let s = s.into();
        if s.is_empty() {
            return Err(ModelError::EmptyField { field: "rule_id" });
        }
        Ok(Self(s))
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: RuleId,
    pub title: Box<str>,
    pub description: Box<str>,
    pub severity: super::alert::Severity,
    pub mitre_techniques: Vec<Box<str>>,
    pub sigma_yaml: Option<Box<str>>,
    pub enabled: bool,
}
