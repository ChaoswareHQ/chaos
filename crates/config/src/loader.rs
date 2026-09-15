use std::path::Path;

use crate::client::ClientConfig;
use crate::error::ConfigError;
use crate::server::ServerConfig;

pub fn load_client_from_file(path: impl AsRef<Path>) -> Result<ClientConfig, ConfigError> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path).map_err(|e| ConfigError::ReadFile {
        path: path.to_path_buf(),
        source: e,
    })?;

    let config: ClientConfig = toml::from_str(&content).map_err(|e| ConfigError::ParseToml {
        path: path.to_path_buf(),
        source: e,
    })?;

    config.validate()?;
    Ok(config)
}

pub fn load_server_from_file(path: impl AsRef<Path>) -> Result<ServerConfig, ConfigError> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path).map_err(|e| ConfigError::ReadFile {
        path: path.to_path_buf(),
        source: e,
    })?;

    let config: ServerConfig = toml::from_str(&content).map_err(|e| ConfigError::ParseToml {
        path: path.to_path_buf(),
        source: e,
    })?;

    config.validate()?;
    Ok(config)
}

pub fn load_from_file(path: impl AsRef<Path>) -> Result<ClientConfig, ConfigError> {
    load_client_from_file(path)
}
