use crate::process::ProcessId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    ProcessStart(ProcessStart),
    ProcessExit(ProcessExit),
    NetworkConnect(NetworkConnect),
    NetworkDisconnect(NetworkDisconnect),
    FileCreate(FileCreate),
    FileWrite(FileWrite),
    FileDelete(FileDelete),
    FileRename(FileRename),
    RegistrySet(RegistrySet),
    RegistryDelete(RegistryDelete),
    DnsQuery(DnsQueryPayload),
    ImageLoad(ImageLoad),
    #[serde(other)]
    Unclassified,
}

impl Default for EventKind {
    #[inline]
    fn default() -> Self {
        EventKind::Unclassified
    }
}

impl EventKind {
    #[inline]
    pub const fn as_str(&self) -> &'static str {
        match self {
            EventKind::ProcessStart(_) => "process_start",
            EventKind::ProcessExit(_) => "process_exit",
            EventKind::NetworkConnect(_) => "network_connect",
            EventKind::NetworkDisconnect(_) => "network_disconnect",
            EventKind::FileCreate(_) => "file_create",
            EventKind::FileWrite(_) => "file_write",
            EventKind::FileDelete(_) => "file_delete",
            EventKind::FileRename(_) => "file_rename",
            EventKind::RegistrySet(_) => "registry_set",
            EventKind::RegistryDelete(_) => "registry_delete",
            EventKind::DnsQuery(_) => "dns_query",
            EventKind::ImageLoad(_) => "image_load",
            EventKind::Unclassified => "unclassified",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityLevel {
    Untrusted,
    Low,
    Medium,
    MediumPlus,
    High,
    System,
    Protected,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessStart {
    pub pid: ProcessId,
    pub parent_pid: Option<ProcessId>,
    pub executable: Box<str>,
    pub command_line: Option<Box<str>>,
    pub user: Option<Box<str>>,
    pub working_directory: Option<Box<str>>,
    pub started_at: DateTime<Utc>,
    #[serde(default)]
    pub image_hash: Option<Box<str>>,
    #[serde(default)]
    pub integrity_level: Option<IntegrityLevel>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessExit {
    pub pid: ProcessId,
    pub exit_code: Option<i32>,
    pub exited_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkConnect {
    pub pid: ProcessId,
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub destination_ip: IpAddr,
    pub destination_port: u16,
    pub protocol: NetworkProtocol,
    pub initiated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkDisconnect {
    pub pid: ProcessId,
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub destination_ip: IpAddr,
    pub destination_port: u16,
    pub protocol: NetworkProtocol,
    #[serde(default)]
    pub bytes_sent: Option<u64>,
    #[serde(default)]
    pub bytes_received: Option<u64>,
    pub ended_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileCreate {
    pub pid: ProcessId,
    pub path: Box<str>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileWrite {
    pub pid: ProcessId,
    pub path: Box<str>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub bytes_written: Option<u64>,
    pub written_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileDelete {
    pub pid: ProcessId,
    pub path: Box<str>,
    pub deleted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileRename {
    pub pid: ProcessId,
    pub old_path: Box<str>,
    pub new_path: Box<str>,
    pub renamed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistrySet {
    pub pid: ProcessId,
    pub key_path: Box<str>,
    #[serde(default)]
    pub value_name: Option<Box<str>>,
    #[serde(default)]
    pub value_data: Option<Box<str>>,
    pub set_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistryDelete {
    pub pid: ProcessId,
    pub key_path: Box<str>,
    pub deleted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsQueryPayload {
    pub pid: ProcessId,
    pub query_name: Box<str>,
    pub query_type: Box<str>,
    #[serde(default)]
    pub answers: Vec<Box<str>>,
    #[serde(default)]
    pub response_code: Option<Box<str>>,
    pub queried_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImageLoad {
    pub pid: ProcessId,
    pub image_path: Box<str>,
    #[serde(default)]
    pub image_hash: Option<Box<str>>,
    #[serde(default)]
    pub signed: Option<bool>,
    #[serde(default)]
    pub signer: Option<Box<str>>,
    pub loaded_at: DateTime<Utc>,
}
