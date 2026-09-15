use serde::Deserialize;

use crate::ConfigError;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub ca_path: String,
    #[serde(default)]
    pub server_name: Option<String>,

    #[serde(default = "default_tls_version")]
    pub min_version: String,
}

fn default_tls_version() -> String {
    "1.3".to_string()
}

impl TlsConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        for (field, path) in [
            ("tls.cert_path", &self.cert_path),
            ("tls.key_path", &self.key_path),
            ("tls.ca_path", &self.ca_path),
        ] {
            if path.is_empty() {
                return Err(ConfigError::MissingField { field });
            }
            if !std::path::Path::new(path).exists() {
                return Err(ConfigError::InvalidValue {
                    field,
                    reason: format!("file does not exist: {path}"),
                });
            }
        }

        if self.min_version != "1.3" && self.min_version != "1.2" {
            return Err(ConfigError::InvalidValue {
                field: "tls.min_version",
                reason: format!("must be \"1.2\" or \"1.3\", got \"{}\"", self.min_version),
            });
        }

        Ok(())
    }
}
