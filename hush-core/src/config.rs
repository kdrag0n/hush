use anyhow::{Context, Result};
use serde::Deserialize;
use std::{fs, net::SocketAddr, path::Path};

pub const DEFAULT_MAX_CONNECTIONS: usize = 128;
pub const DEFAULT_MAX_SESSIONS_PER_CONNECTION: usize = 1;
pub const DEFAULT_MAX_FORWARDS_PER_CONNECTION: usize = 16;
pub const DEFAULT_MAX_FORWARD_STREAMS_PER_CONNECTION: usize = 64;

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfigFile {
    pub listen: Option<SocketAddr>,
    pub data_dir: Option<std::path::PathBuf>,
    pub host_cert_path: Option<std::path::PathBuf>,
    pub host_key_path: Option<std::path::PathBuf>,
    pub authorized_keys_path: Option<std::path::PathBuf>,
    pub allow_users: Option<Vec<String>>,
    pub allow_tcp_forwarding: Option<bool>,
    pub max_connections: Option<usize>,
    pub max_sessions_per_connection: Option<usize>,
    pub max_forwards_per_connection: Option<usize>,
    pub max_forward_streams_per_connection: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct ServerRuntimeConfig {
    pub authorized_keys_path: Option<std::path::PathBuf>,
    pub allow_users: Vec<String>,
    pub allow_tcp_forwarding: bool,
    pub max_connections: usize,
    pub max_sessions_per_connection: usize,
    pub max_forwards_per_connection: usize,
    pub max_forward_streams_per_connection: usize,
}

impl Default for ServerRuntimeConfig {
    fn default() -> Self {
        Self {
            authorized_keys_path: None,
            allow_users: Vec::new(),
            allow_tcp_forwarding: true,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_sessions_per_connection: DEFAULT_MAX_SESSIONS_PER_CONNECTION,
            max_forwards_per_connection: DEFAULT_MAX_FORWARDS_PER_CONNECTION,
            max_forward_streams_per_connection: DEFAULT_MAX_FORWARD_STREAMS_PER_CONNECTION,
        }
    }
}

pub fn read_server_config(path: &Path) -> Result<Option<ServerConfigFile>> {
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let cfg = toml::from_str(&data).with_context(|| format!("parse {}", path.display()))?;
    Ok(Some(cfg))
}

#[derive(Debug, Clone, Default)]
pub struct SshHostConfig {
    pub user: Option<String>,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub identity_file: Option<std::path::PathBuf>,
}

pub fn read_ssh_config(alias: &str) -> Result<SshHostConfig> {
    let path = crate::paths::current_home().join(".ssh/config");
    let Ok(data) = fs::read_to_string(&path) else {
        return Ok(SshHostConfig::default());
    };

    let mut active = false;
    let mut cfg = SshHostConfig::default();
    for raw in data.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let key = parts.next().unwrap_or_default().to_ascii_lowercase();
        let value = parts.next().unwrap_or_default().trim();
        if key == "host" {
            active = value
                .split_whitespace()
                .any(|pat| host_pattern_matches(pat, alias));
            continue;
        }
        if !active {
            continue;
        }
        match key.as_str() {
            "user" if cfg.user.is_none() => cfg.user = Some(value.to_owned()),
            "hostname" if cfg.hostname.is_none() => cfg.hostname = Some(value.to_owned()),
            "port" if cfg.port.is_none() => cfg.port = value.parse().ok(),
            "identityfile" if cfg.identity_file.is_none() => {
                cfg.identity_file = Some(expand_home(value))
            }
            _ => {}
        }
    }
    Ok(cfg)
}

fn expand_home(value: &str) -> std::path::PathBuf {
    if let Some(rest) = value.strip_prefix("~/") {
        crate::paths::current_home().join(rest)
    } else {
        std::path::PathBuf::from(value)
    }
}

fn host_pattern_matches(pattern: &str, host: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return host.starts_with(prefix);
    }
    pattern == host
}

#[cfg(test)]
mod tests {
    use super::ServerConfigFile;

    #[test]
    fn config_example_parses() {
        toml::from_str::<ServerConfigFile>(include_str!("../../config.example.toml"))
            .expect("config.example.toml should parse");
    }
}
