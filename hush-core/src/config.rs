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
pub const DEFAULT_MAX_FILE_COPY_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const DEFAULT_MAX_FILE_COPY_ENTRIES: u64 = 100_000;
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
    pub allow_agent_forwarding: Option<bool>,
    pub max_connections: Option<usize>,
    pub max_sessions_per_connection: Option<usize>,
    pub max_forwards_per_connection: Option<usize>,
    pub max_forward_streams_per_connection: Option<usize>,
    pub max_file_copy_bytes: Option<u64>,
    pub max_file_copy_entries: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ServerRuntimeConfig {
    pub authorized_keys_path: Option<std::path::PathBuf>,
    pub allow_users: Vec<String>,
    pub allow_tcp_forwarding: bool,
    pub allow_agent_forwarding: bool,
    /// Signs agent forwarding session identifiers with the host key; `None`
    /// disables `session-bind@openssh.com` but not forwarding itself.
    pub agent_signer: Option<std::sync::Arc<crate::agent::HostSigner>>,
    pub max_connections: usize,
    pub max_sessions_per_connection: usize,
    pub max_forwards_per_connection: usize,
    pub max_forward_streams_per_connection: usize,
    pub file_copy_limits: crate::filecopy::FileCopyLimits,
}

impl Default for ServerRuntimeConfig {
    fn default() -> Self {
        Self {
            authorized_keys_path: None,
            allow_users: Vec::new(),
            allow_tcp_forwarding: true,
            allow_agent_forwarding: true,
            agent_signer: None,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_sessions_per_connection: DEFAULT_MAX_SESSIONS_PER_CONNECTION,
            max_forwards_per_connection: DEFAULT_MAX_FORWARDS_PER_CONNECTION,
            max_forward_streams_per_connection: DEFAULT_MAX_FORWARD_STREAMS_PER_CONNECTION,
            file_copy_limits: crate::filecopy::FileCopyLimits::default(),
        }
    }
}

impl ServerRuntimeConfig {
    pub fn validate(&self, running_as_root: bool) -> Result<()> {
        if running_as_root && self.authorized_keys_path.is_some() && self.allow_users.is_empty() {
            anyhow::bail!(
                "a root server using authorized_keys_path must set allow_users (or --allow-user)"
            );
        }
        Ok(())
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
    pub identity_agent: Option<IdentityAgent>,
    pub forward_agent: Option<ForwardAgent>,
    pub set_env: Vec<EnvVar>,
    pub local_forwards: Vec<SshForward>,
    pub remote_forwards: Vec<SshForward>,
}

/// Resolved value of an `IdentityAgent` directive from ssh_config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityAgent {
    /// `IdentityAgent none` — do not use any agent.
    Disabled,
    /// An explicit agent socket path.
    Socket(std::path::PathBuf),
}

/// Resolved value of a `ForwardAgent` directive from ssh_config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardAgent {
    /// `ForwardAgent yes` — forward the default agent (`SSH_AUTH_SOCK`).
    Yes,
    /// `ForwardAgent no`.
    No,
    /// An explicit agent socket path (or environment variable) to forward.
    Socket(std::path::PathBuf),
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
            active = host_block_matches(value, alias);
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
            "identityagent" if cfg.identity_agent.is_none() => {
                cfg.identity_agent = parse_identity_agent(value);
            }
            "forwardagent" if cfg.forward_agent.is_none() => {
                cfg.forward_agent = parse_forward_agent(value);
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

/// Parse an `IdentityAgent` directive value. Returns `None` when the directive
/// just selects the default agent (an empty value or the literal
/// `SSH_AUTH_SOCK`), so the standard `SSH_AUTH_SOCK` lookup is used.
fn parse_identity_agent(value: &str) -> Option<IdentityAgent> {
    let value = unquote(value.trim());
    if value.is_empty() {
        return None;
    }
    if value.eq_ignore_ascii_case("none") {
        return Some(IdentityAgent::Disabled);
    }
    let expanded = expand_env(&value);
    // The literal `SSH_AUTH_SOCK` (or `$SSH_AUTH_SOCK`) means "use the default
    // agent", which is what an unset value already does.
    if value == "SSH_AUTH_SOCK" || expanded.is_empty() {
        return None;
    }
    Some(IdentityAgent::Socket(expand_home(&expanded)))
}

/// Parse a `ForwardAgent` directive value: `yes`/`no`, or an explicit agent
/// socket path or environment variable reference, following OpenSSH.
fn parse_forward_agent(value: &str) -> Option<ForwardAgent> {
    let value = unquote(value.trim());
    if value.is_empty() {
        return None;
    }
    if value.eq_ignore_ascii_case("yes") || value.eq_ignore_ascii_case("true") {
        return Some(ForwardAgent::Yes);
    }
    if value.eq_ignore_ascii_case("no") || value.eq_ignore_ascii_case("false") {
        return Some(ForwardAgent::No);
    }
    let expanded = expand_env(&value);
    if expanded.is_empty() {
        return None;
    }
    Some(ForwardAgent::Socket(expand_home(&expanded)))
}

fn unquote(value: &str) -> String {
    let bytes = value.as_bytes();
    if bytes.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value[1..value.len() - 1].to_owned()
    } else {
        value.to_owned()
    }
}

/// Expand `$VAR` and `${VAR}` environment variable references. Unknown
/// variables expand to an empty string, matching ssh's behaviour.
fn expand_env(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '$' {
            out.push(ch);
            continue;
        }
        let name = if chars.peek() == Some(&'{') {
            chars.next();
            let mut name = String::new();
            for c in chars.by_ref() {
                if c == '}' {
                    break;
                }
                name.push(c);
            }
            name
        } else {
            let mut name = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_ascii_alphanumeric() || c == '_' {
                    name.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            name
        };
        if name.is_empty() {
            out.push('$');
        } else if let Ok(val) = std::env::var(&name) {
            out.push_str(&val);
        }
    }
    out
}

fn host_block_matches(patterns: &str, host: &str) -> bool {
    let mut positive_match = false;
    for pattern in patterns.split_whitespace() {
        let (negated, pattern) = match pattern.strip_prefix('!') {
            Some(pattern) => (true, pattern),
            None => (false, pattern),
        };
        if pattern.is_empty() || !host_pattern_matches(pattern, host) {
            continue;
        }
        if negated {
            return false;
        }
        positive_match = true;
    }
    positive_match
}

fn host_pattern_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    let pattern = pattern.as_bytes();
    let host = host.as_bytes();
    let (mut p, mut h) = (0usize, 0usize);
    let (mut star, mut after_star) = (None, 0usize);
    while h < host.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == host[h]) {
            p += 1;
            h += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            after_star = h;
        } else if let Some(star_index) = star {
            p = star_index + 1;
            after_star += 1;
            h = after_star;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::{
        SERVER_CONFIG_EXAMPLE, ServerConfigFile, SshForward, parse_ssh_config, parse_ssh_forward,
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
    fn root_authorized_keys_override_requires_an_explicit_user_scope() {
        let mut cfg = super::ServerRuntimeConfig {
            authorized_keys_path: Some("/tmp/authorized_keys".into()),
            ..Default::default()
        };

        assert!(cfg.validate(true).is_err());
        cfg.allow_users.push("deploy".to_owned());
        cfg.validate(true).unwrap();
        cfg.allow_users.clear();
        cfg.validate(false).unwrap();
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
    fn ssh_config_host_globs_match_any_position_case_insensitively() {
        let cfg = parse_ssh_config(
            "API.Staging.Example.COM",
            r#"
Host api.*.example.?om
    User deploy
"#,
        )
        .unwrap();

        assert_eq!(cfg.user.as_deref(), Some("deploy"));
    }

    #[test]
    fn ssh_config_negated_host_pattern_excludes_a_broader_match() {
        let prod = parse_ssh_config(
            "prod.example.com",
            r#"
Host *.example.com !prod.example.com
    User broad
Host prod.example.com
    User production
"#,
        )
        .unwrap();
        let staging = parse_ssh_config(
            "staging.example.com",
            r#"
Host *.example.com !prod.example.com
    User broad
Host prod.example.com
    User production
"#,
        )
        .unwrap();

        assert_eq!(prod.user.as_deref(), Some("production"));
        assert_eq!(staging.user.as_deref(), Some("broad"));
    }

    #[test]
    fn ssh_config_negated_pattern_alone_never_activates_a_block() {
        let cfg = parse_ssh_config(
            "staging.example.com",
            r#"
Host !prod.example.com
    User should-not-match
"#,
        )
        .unwrap();

        assert_eq!(cfg.user, None);
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
    fn ssh_config_parses_quoted_identity_agent_socket() {
        let cfg = super::parse_ssh_config(
            "edge",
            "Host edge\n    IdentityAgent \"~/Library/Group Containers/agent.sock\"\n",
        )
        .unwrap();

        assert_eq!(
            cfg.identity_agent,
            Some(super::IdentityAgent::Socket(
                crate::paths::current_home().join("Library/Group Containers/agent.sock")
            ))
        );
    }

    #[test]
    fn ssh_config_parses_forward_agent_values() {
        let cfg = super::parse_ssh_config("edge", "Host edge\n    ForwardAgent yes\n").unwrap();
        assert_eq!(cfg.forward_agent, Some(super::ForwardAgent::Yes));

        let cfg = super::parse_ssh_config("edge", "Host edge\n    ForwardAgent no\n").unwrap();
        assert_eq!(cfg.forward_agent, Some(super::ForwardAgent::No));

        let cfg =
            super::parse_ssh_config("edge", "Host edge\n    ForwardAgent ~/agent.sock\n").unwrap();
        assert_eq!(
            cfg.forward_agent,
            Some(super::ForwardAgent::Socket(
                crate::paths::current_home().join("agent.sock")
            ))
        );

        let cfg = super::parse_ssh_config("edge", "Host edge\n").unwrap();
        assert_eq!(cfg.forward_agent, None);
    }

    #[test]
    fn ssh_config_identity_agent_none_disables_agent() {
        let cfg = super::parse_ssh_config("edge", "Host edge\n    IdentityAgent none\n").unwrap();
        assert_eq!(cfg.identity_agent, Some(super::IdentityAgent::Disabled));
    }

    #[test]
    fn ssh_config_identity_agent_ssh_auth_sock_uses_default() {
        let cfg = super::parse_ssh_config("edge", "Host edge\n    IdentityAgent SSH_AUTH_SOCK\n")
            .unwrap();
        assert_eq!(cfg.identity_agent, None);
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
