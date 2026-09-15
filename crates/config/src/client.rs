use crate::ConfigError;
use crate::TlsConfig;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub session_name: String,

    #[serde(default)]
    pub providers: Vec<ProviderConfig>,

    pub server_url: String,
    pub tls: TlsConfig,

    #[serde(default)]
    pub batch: BatchConfig,

    #[serde(default)]
    pub buffer: BufferConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    pub name: String,

    #[serde(default)]
    pub events: Vec<String>,

    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchConfig {
    #[serde(default = "default_batch_size")]
    pub max_size: usize,

    #[serde(default = "default_batch_delay")]
    pub max_delay_ms: u64,

    #[serde(default = "default_channel_capacity")]
    pub channel_capacity: usize,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_size: default_batch_size(),
            max_delay_ms: default_batch_delay(),
            channel_capacity: default_channel_capacity(),
        }
    }
}

fn default_batch_size() -> usize {
    1000
}
fn default_batch_delay() -> u64 {
    500
}
fn default_channel_capacity() -> usize {
    1_000_000
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BufferConfig {
    #[serde(default = "default_buffer_path")]
    pub path: String,

    #[serde(default = "default_buffer_size_mb")]
    pub max_size_mb: u64,
}

impl Default for BufferConfig {
    fn default() -> Self {
        Self {
            path: default_buffer_path(),
            max_size_mb: default_buffer_size_mb(),
        }
    }
}

fn default_buffer_path() -> String {
    if cfg!(windows) {
        r"C:\ProgramData\Chaos\buffer.db".to_string()
    } else {
        "/var/lib/chaos/buffer.db".to_string()
    }
}

fn default_buffer_size_mb() -> u64 {
    1024
}

impl ClientConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.session_name.is_empty() {
            return Err(ConfigError::MissingField {
                field: "session_name",
            });
        }

        if !self.server_url.starts_with("https://") {
            return Err(ConfigError::InvalidValue {
                field: "server_url",
                reason: "must start with https://".to_string(),
            });
        }

        if self.batch.max_size == 0 {
            return Err(ConfigError::InvalidValue {
                field: "batch.max_size",
                reason: "must be greater than zero".to_string(),
            });
        }

        if self.batch.max_delay_ms == 0 {
            return Err(ConfigError::InvalidValue {
                field: "batch.max_delay_ms",
                reason: "must be greater than zero".to_string(),
            });
        }

        if self.batch.channel_capacity == 0 {
            return Err(ConfigError::InvalidValue {
                field: "batch.channel_capacity",
                reason: "must be greater than zero".to_string(),
            });
        }

        self.tls.validate()?;

        for (i, provider) in self.providers.iter().enumerate() {
            if provider.name.is_empty() {
                return Err(ConfigError::InvalidValue {
                    field: "providers[].name",
                    reason: format!("provider at index {i} has empty name"),
                });
            }
        }

        Ok(())
    }
}
