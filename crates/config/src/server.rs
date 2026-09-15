use crate::ConfigError;
use crate::TlsConfig;
use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub ingest: IngestConfig,

    pub storage: StorageConfig,

    #[serde(default)]
    pub api: ApiConfig,

    #[serde(default)]
    pub detection: DetectionConfig,

    #[serde(default)]
    pub retention: RetentionConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestConfig {
    pub bind: String,

    pub tls: TlsConfig,

    #[serde(default = "default_max_batch")]
    pub max_batch_size: usize,

    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
}

fn default_max_batch() -> usize {
    10_000
}
fn default_max_connections() -> usize {
    10_000
}
fn default_idle_timeout() -> u64 {
    300
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    pub backend: String,

    pub url: String,

    #[serde(default = "default_pool_size")]
    pub pool_size: u32,

    #[serde(default = "default_write_batch")]
    pub write_batch: usize,

    #[serde(default = "default_flush_interval")]
    pub flush_interval_ms: u64,
}

fn default_pool_size() -> u32 {
    8
}
fn default_write_batch() -> usize {
    500
}
fn default_flush_interval() -> u64 {
    1000
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    #[serde(default = "default_api_bind")]
    pub bind: String,

    #[serde(default = "default_jwt_env")]
    pub jwt_secret_env: String,

    #[serde(default = "default_jwt_ttl")]
    pub jwt_ttl_secs: u64,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            bind: default_api_bind(),
            jwt_secret_env: default_jwt_env(),
            jwt_ttl_secs: default_jwt_ttl(),
        }
    }
}

fn default_api_bind() -> String {
    "127.0.0.1:8080".to_string()
}
fn default_jwt_env() -> String {
    "CHAOS_JWT_SECRET".to_string()
}
fn default_jwt_ttl() -> u64 {
    3600
}

/// Detection engine configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionConfig {
    #[serde(default = "default_rule_dir")]
    pub rule_dir: String,

    #[serde(default = "default_reload_interval")]
    pub reload_interval_secs: u64,

    #[serde(default)]
    pub workers: usize,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            rule_dir: default_rule_dir(),
            reload_interval_secs: default_reload_interval(),
            workers: 0,
        }
    }
}

fn default_rule_dir() -> String {
    if cfg!(windows) {
        r"C:\ProgramData\Chaos\rules".to_string()
    } else {
        "/etc/chaos/rules".to_string()
    }
}

fn default_reload_interval() -> u64 {
    60
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionConfig {
    #[serde(default = "default_hot_days")]
    pub hot_days: u32,

    #[serde(default = "default_warm_days")]
    pub warm_days: u32,

    #[serde(default = "default_cold_days")]
    pub cold_days: u32,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            hot_days: default_hot_days(),
            warm_days: default_warm_days(),
            cold_days: default_cold_days(),
        }
    }
}

fn default_hot_days() -> u32 {
    30
}
fn default_warm_days() -> u32 {
    90
}
fn default_cold_days() -> u32 {
    365
}

impl ServerConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.ingest
            .bind
            .parse::<SocketAddr>()
            .map_err(|e| ConfigError::InvalidValue {
                field: "ingest.bind",
                reason: e.to_string(),
            })?;
        self.api
            .bind
            .parse::<SocketAddr>()
            .map_err(|e| ConfigError::InvalidValue {
                field: "api.bind",
                reason: e.to_string(),
            })?;

        match self.storage.backend.as_str() {
            "sqlite" | "clickhouse" => {}
            other => {
                return Err(ConfigError::InvalidValue {
                    field: "storage.backend",
                    reason: format!("unknown backend `{other}`; expected `sqlite` or `clickhouse`"),
                });
            }
        }

        if self.storage.pool_size == 0 {
            return Err(ConfigError::InvalidValue {
                field: "storage.pool_size",
                reason: "must be greater than zero".to_string(),
            });
        }

        if self.ingest.max_batch_size == 0 {
            return Err(ConfigError::InvalidValue {
                field: "ingest.max_batch_size",
                reason: "must be greater than zero".to_string(),
            });
        }

        if self.retention.hot_days == 0 {
            return Err(ConfigError::InvalidValue {
                field: "retention.hot_days",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.retention.warm_days < self.retention.hot_days {
            return Err(ConfigError::InvalidValue {
                field: "retention.warm_days",
                reason: "must be >= hot_days".to_string(),
            });
        }
        if self.retention.cold_days < self.retention.warm_days {
            return Err(ConfigError::InvalidValue {
                field: "retention.cold_days",
                reason: "must be >= warm_days".to_string(),
            });
        }

        self.ingest.tls.validate()?;

        Ok(())
    }
}
