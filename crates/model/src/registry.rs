use serde::{Deserialize, Serialize};

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
    pub key_path: String,
    pub value_name: Option<String>,
    pub value_data: Option<String>,
    pub process: Option<super::process::Process>,
}
