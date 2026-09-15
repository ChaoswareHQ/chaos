use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid TOML in {path}: {source}")]
    ParseToml {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("missing required field `{field}`")]
    MissingField { field: &'static str },

    #[error("field `{field}` has invalid value: {reason}")]
    InvalidValue { field: &'static str, reason: String },

    #[error("environment variable `{var}` referenced by `{field}` is not set")]
    MissingEnvVar { field: &'static str, var: String },

    #[error("validation failed: {0}")]
    Validation(String),
}
