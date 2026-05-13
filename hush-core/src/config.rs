use crate::protocol::EnvVar;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::{
    fs,
    io::{ErrorKind, Write},
    net::SocketAddr,
    path::Path,
};

pub const DEFAULT_MAX_CONNECTIONS: usize = 128;
pub const DEFAULT_MAX_SESSIONS_PER_CONNECTION: usize = 1;
pub const DEFAULT_MAX_FORWARDS_PER_CONNECTION: usize = 16;
pub const DEFAULT_MAX_FORWARD_STREAMS_PER_CONNECTION: usize = 64;
pub const SERVER_CONFIG_EXAMPLE: &str = include_str!("../../config.example.toml");

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

pub fn write_server_config_example_if_missing(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut file) => file
            .write_all(SERVER_CONFIG_EXAMPLE.as_bytes())
            .with_context(|| format!("write {}", path.display())),
        Err(err) if err.kind() == ErrorKind::AlreadyExists => Ok(()),
        Err(err) => Err(err).with_context(|| format!("write {}", path.display())),
    }
}

#[derive(Debug, Clone, Default)]
pub struct SshHostConfig {
    pub user: Option<String>,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub identity_file: Option<std::path::PathBuf>,
    pub set_env: Vec<EnvVar>,
    pub local_forwards: Vec<SshForward>,
    pub remote_forwards: Vec<SshForward>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshForward {
    pub listen_host: String,
    pub listen_port: u16,
    pub target_host: String,
    pub target_port: u16,
}

pub fn read_ssh_config(alias: &str) -> Result<SshHostConfig> {
    let path = crate::paths::current_home().join(".ssh/config");
    let Ok(data) = fs::read_to_string(&path) else {
        return Ok(SshHostConfig::default());
    };

    parse_ssh_config(alias, &data)
}

fn parse_ssh_config(alias: &str, data: &str) -> Result<SshHostConfig> {
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
            "setenv" if cfg.set_env.is_empty() => {
                cfg.set_env = parse_set_env(value).context("parse SetEnv")?;
            }
            "localforward" => cfg.local_forwards.push(
                parse_ssh_forward(value)
                    .with_context(|| format!("parse LocalForward {value:?}"))?,
            ),
            "remoteforward" => cfg.remote_forwards.push(
                parse_ssh_forward(value)
                    .with_context(|| format!("parse RemoteForward {value:?}"))?,
            ),
            _ => {}
        }
    }
    Ok(cfg)
}

fn parse_set_env(value: &str) -> Result<Vec<EnvVar>> {
    let args = shell_words::split(value).context("split SetEnv directive")?;
    if args.is_empty() {
        anyhow::bail!("expected NAME=VALUE");
    }
    let mut env = Vec::new();
    for arg in args {
        let Some((key, value)) = arg.split_once('=') else {
            anyhow::bail!("expected NAME=VALUE, got {arg:?}");
        };
        if key.is_empty() {
            anyhow::bail!("environment variable name is empty");
        }
        if env.iter().any(|var: &EnvVar| var.key == key) {
            continue;
        }
        env.push(EnvVar {
            key: key.to_owned(),
            value: value.to_owned(),
        });
    }
    Ok(env)
}

fn parse_ssh_forward(value: &str) -> Result<SshForward> {
    let args = shell_words::split(value).context("split forward directive")?;
    match args.as_slice() {
        [combined] => parse_colon_forward(combined),
        [listen, target] => {
            let (listen_host, listen_port) = parse_listen_endpoint(listen)?;
            let (target_host, target_port) = parse_target_endpoint(target)?;
            Ok(SshForward {
                listen_host,
                listen_port,
                target_host,
                target_port,
            })
        }
        [listen, target_host, target_port] => {
            let (listen_host, listen_port) = parse_listen_endpoint(listen)?;
            Ok(SshForward {
                listen_host,
                listen_port,
                target_host: unbracket_host(target_host),
                target_port: target_port.parse().context("bad target port")?,
            })
        }
        _ => anyhow::bail!(
            "expected [listen_host:]listen_port target_host:target_port or [listen_host:]listen_port target_host target_port"
        ),
    }
}

fn parse_colon_forward(value: &str) -> Result<SshForward> {
    let parts = split_colon_bracketed(value);
    let (listen_host, listen_port, target_host, target_port) = match parts.as_slice() {
        [lp, th, tp] => (
            "127.0.0.1".to_owned(),
            lp.as_str(),
            th.as_str(),
            tp.as_str(),
        ),
        [lh, lp, th, tp] => (unbracket_host(lh), lp.as_str(), th.as_str(), tp.as_str()),
        _ => anyhow::bail!("expected [listen_host:]listen_port:target_host:target_port"),
    };
    Ok(SshForward {
        listen_host,
        listen_port: listen_port.parse().context("bad listen port")?,
        target_host: unbracket_host(target_host),
        target_port: target_port.parse().context("bad target port")?,
    })
}

fn parse_listen_endpoint(value: &str) -> Result<(String, u16)> {
    let parts = split_colon_bracketed(value);
    match parts.as_slice() {
        [port] => Ok((
            "127.0.0.1".to_owned(),
            port.parse().context("bad listen port")?,
        )),
        [host, port] => Ok((
            unbracket_host(host),
            port.parse().context("bad listen port")?,
        )),
        _ => anyhow::bail!("expected [listen_host:]listen_port"),
    }
}

fn parse_target_endpoint(value: &str) -> Result<(String, u16)> {
    let parts = split_colon_bracketed(value);
    match parts.as_slice() {
        [host, port] => Ok((
            unbracket_host(host),
            port.parse().context("bad target port")?,
        )),
        _ => anyhow::bail!("expected target_host:target_port"),
    }
}

fn split_colon_bracketed(input: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut bracket_depth = 0usize;
    for ch in input.chars() {
        match ch {
            '[' => {
                bracket_depth += 1;
                current.push(ch);
            }
            ']' => {
                bracket_depth = bracket_depth.saturating_sub(1);
                current.push(ch);
            }
            ':' if bracket_depth == 0 => {
                parts.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    parts.push(current);
    parts
}

fn unbracket_host(host: &str) -> String {
    host.strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host)
        .to_owned()
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
    use super::{
        SERVER_CONFIG_EXAMPLE, ServerConfigFile, SshForward, parse_ssh_forward,
        write_server_config_example_if_missing,
    };
    use crate::protocol::EnvVar;
    use std::fs;

    #[test]
    fn config_example_parses() {
        toml::from_str::<ServerConfigFile>(SERVER_CONFIG_EXAMPLE)
            .expect("config.example.toml should parse");
    }

    #[test]
    fn writes_config_example_if_missing() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("server/config.toml");

        write_server_config_example_if_missing(&path).unwrap();

        assert_eq!(fs::read_to_string(path).unwrap(), SERVER_CONFIG_EXAMPLE);
    }

    #[test]
    fn does_not_overwrite_existing_config() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.toml");
        fs::write(&path, "listen = \"127.0.0.1:22022\"\n").unwrap();

        write_server_config_example_if_missing(&path).unwrap();

        assert_eq!(
            fs::read_to_string(path).unwrap(),
            "listen = \"127.0.0.1:22022\"\n"
        );
    }

    #[test]
    fn ssh_forward_parses_openssh_two_argument_form() {
        let forward = parse_ssh_forward("8080 app.internal:443").unwrap();
        assert_eq!(
            forward,
            SshForward {
                listen_host: "127.0.0.1".to_owned(),
                listen_port: 8080,
                target_host: "app.internal".to_owned(),
                target_port: 443,
            }
        );
    }

    #[test]
    fn ssh_forward_parses_openssh_three_argument_form() {
        let forward = parse_ssh_forward("localhost:8080 db.internal 5432").unwrap();
        assert_eq!(
            forward,
            SshForward {
                listen_host: "localhost".to_owned(),
                listen_port: 8080,
                target_host: "db.internal".to_owned(),
                target_port: 5432,
            }
        );
    }

    #[test]
    fn ssh_forward_parses_colon_only_form() {
        let forward = parse_ssh_forward("127.0.0.1:8080:app.internal:443").unwrap();
        assert_eq!(
            forward,
            SshForward {
                listen_host: "127.0.0.1".to_owned(),
                listen_port: 8080,
                target_host: "app.internal".to_owned(),
                target_port: 443,
            }
        );
    }

    #[test]
    fn ssh_forward_parses_bracketed_ipv6_hosts() {
        let forward = parse_ssh_forward("[::1]:8080 [2001:db8::1]:443").unwrap();
        assert_eq!(
            forward,
            SshForward {
                listen_host: "::1".to_owned(),
                listen_port: 8080,
                target_host: "2001:db8::1".to_owned(),
                target_port: 443,
            }
        );
    }

    #[test]
    fn ssh_config_collects_local_and_remote_forwards() {
        let cfg = super::parse_ssh_config(
            "edge",
            r#"
Host other
    LocalForward 9000 ignored:9000

Host edge
    HostName edge.example
    LocalForward 8080 app.internal:443
    RemoteForward localhost:9090 db.internal 5432
    LocalForward [::1]:10000 [2001:db8::1]:443
"#,
        )
        .unwrap();

        assert_eq!(cfg.hostname.as_deref(), Some("edge.example"));
        assert_eq!(
            cfg.local_forwards,
            vec![
                SshForward {
                    listen_host: "127.0.0.1".to_owned(),
                    listen_port: 8080,
                    target_host: "app.internal".to_owned(),
                    target_port: 443,
                },
                SshForward {
                    listen_host: "::1".to_owned(),
                    listen_port: 10000,
                    target_host: "2001:db8::1".to_owned(),
                    target_port: 443,
                },
            ]
        );
        assert_eq!(
            cfg.remote_forwards,
            vec![SshForward {
                listen_host: "localhost".to_owned(),
                listen_port: 9090,
                target_host: "db.internal".to_owned(),
                target_port: 5432,
            }]
        );
    }

    #[test]
    fn ssh_config_parses_first_set_env_directive() {
        let cfg = super::parse_ssh_config(
            "edge",
            r#"
Host *
    SetEnv TERM=screen-256color LANG=C

Host edge
    SetEnv TERM=ignored
"#,
        )
        .unwrap();

        assert_eq!(
            cfg.set_env,
            vec![
                EnvVar {
                    key: "TERM".to_owned(),
                    value: "screen-256color".to_owned(),
                },
                EnvVar {
                    key: "LANG".to_owned(),
                    value: "C".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn ssh_config_set_env_splits_quoted_values_and_keeps_first_duplicate() {
        let cfg = super::parse_ssh_config(
            "edge",
            r#"
Host edge
    SetEnv TERM=xterm-256color LANG="en_US.UTF-8" TERM=ignored
"#,
        )
        .unwrap();

        assert_eq!(
            cfg.set_env,
            vec![
                EnvVar {
                    key: "TERM".to_owned(),
                    value: "xterm-256color".to_owned(),
                },
                EnvVar {
                    key: "LANG".to_owned(),
                    value: "en_US.UTF-8".to_owned(),
                },
            ]
        );
    }
}
