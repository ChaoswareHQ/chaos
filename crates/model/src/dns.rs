use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub query_name: String,
    pub query_type: String,
    pub answers: Vec<String>,
    pub process: Option<super::process::Process>,
    pub response_code: Option<String>,
}
