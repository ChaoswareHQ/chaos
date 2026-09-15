use crate::process::Process;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryAction {
    CreateKey,
    DeleteKey,
    OpenKey,
    QueryValue,
    SetValue,
    DeleteValue,
    EnumerateKey,
    EnumerateValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEvent {
    pub action: RegistryAction,
    pub key_path: Box<str>,
    pub value_name: Option<Box<str>>,
    pub value_data: Option<Box<str>>,
    pub process: Option<Arc<Process>>,
}
