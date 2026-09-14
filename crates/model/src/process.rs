use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProcessId(u32);

impl ProcessId {
    pub fn new(n: u32) -> Self {
        Self(n)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Process {
    pub pid: ProcessId,
    pub parent_pid: Option<ProcessId>,
    pub executable: Option<String>,
    pub command_line: Option<String>,
    pub user: Option<String>,
    pub working_directory: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
}
