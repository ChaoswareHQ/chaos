use crate::process::Process;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub query_name: Box<str>,
    pub query_type: Box<str>,
    pub answers: Vec<Box<str>>,
    pub process: Option<Arc<Process>>,
    pub response_code: Option<Box<str>>,
}
