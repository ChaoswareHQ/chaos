use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileAction {
    Create,
    Read,
    Write,
    Delete,
    Rename,
    Execute,
    Open,
    Close,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub action: FileAction,
    pub path: String,
    pub new_path: Option<String>,
    pub process: Option<super::process::Process>,
    pub size: Option<u64>,
    pub hash: Option<String>,
}
