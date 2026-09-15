use crate::process::Process;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub source_ip: Box<str>,
    pub source_port: u16,
    pub destination_ip: Box<str>,
    pub destination_port: u16,
    pub protocol: NetworkProtocol,
    pub process: Option<Arc<Process>>,
    pub bytes_sent: Option<u64>,
    pub bytes_received: Option<u64>,
}
