use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProcessId(u32);

impl ProcessId {
    #[inline]
    pub fn new(n: u32) -> Self {
        Self(n)
    }

    #[inline]
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Process {
    pub pid: ProcessId,
    pub parent_pid: Option<ProcessId>,
    pub executable: Option<Box<str>>,
    pub command_line: Option<Box<str>>,
    pub user: Option<Box<str>>,
    pub working_directory: Option<Box<str>>,
    pub started_at: Option<DateTime<Utc>>,
}
