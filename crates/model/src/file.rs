use crate::process::Process;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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
    pub path: Box<str>,
    pub new_path: Option<Box<str>>,
    pub process: Option<Arc<Process>>,
    pub size: Option<u64>,
    pub hash: Option<Box<str>>,
}
