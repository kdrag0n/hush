use anyhow::{Result, bail};
use clap::Parser;
use std::path::PathBuf;

#[derive(Debug)]
pub(crate) enum Cli {
    Session(Args),
    Copy(crate::cp::CpArgs),
}

impl Cli {
    pub(crate) fn parse_from_env() -> Result<Self> {
        let mut args: Vec<std::ffi::OsString> = std::env::args_os().collect();
        let argv0 = args
            .first()
            .and_then(|arg| std::path::Path::new(arg).file_stem())
            .and_then(|arg| arg.to_str())
            .unwrap_or("hush");
        if argv0 == "hcp" {
            return Ok(Self::Copy(crate::cp::CpArgs::parse_from(args)));
        }
        if args.get(1).and_then(|arg| arg.to_str()) == Some("cp") {
            args.remove(1);
            return Ok(Self::Copy(crate::cp::CpArgs::parse_from(args)));
        }
        Ok(Self::Session(Args::parse_from(args)))
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "hush",
    version,
    about = "SSH-like remote command client over QUIC",
    long_about = "hush connects to a hush-server over QUIC, authenticates with an Ed25519 SSH key, and runs a remote shell or command.\n\nTarget syntax is [user@]host[:port]. IPv6 literals may be written as [::1]:22022.\n\nForward syntax for -L and -R is [listen_host:]listen_port:target_host:target_port."
)]
pub(crate) struct Args {
    /// Enable client logging. Without this, client logging is disabled.
    #[arg(short = 'v', long)]
    pub(crate) verbose: bool,

    /// Skip TOFU host certificate verification for this connection.
    #[arg(short = 'k', long, help_heading = "Host Trust")]
    pub(crate) insecure: bool,

    /// Connect to this remote port, overriding target and ssh_config ports.
    #[arg(short = 'p', value_name = "PORT")]
    pub(crate) port: Option<u16>,

    /// Force PTY allocation.
    #[arg(short = 't')]
    pub(crate) tty: bool,

    /// Disable PTY allocation and use stdin/stdout/stderr pipes.
    #[arg(short = 'T')]
    pub(crate) no_tty: bool,

    /// Data directory for known_hosts and client state.
    #[arg(long, value_name = "DIR", help_heading = "Files")]
    pub(crate) data_dir: Option<PathBuf>,

    /// SSH Ed25519 identity file. Agent use is preferred when it has this key.
    #[arg(short = 'i', value_name = "PATH", help_heading = "Authentication")]
    pub(crate) identity_file: Option<PathBuf>,

    /// Execute the command directly instead of through the user's shell.
    #[arg(short = 'S', long, help_heading = "Execution")]
    pub(crate) no_shell: bool,

    /// Forward a local TCP port to the remote side.
    #[arg(
        short = 'L',
        value_name = "[BIND:]PORT:TARGET_HOST:TARGET_PORT",
        help_heading = "Forwarding",
        value_parser = parse_forward
    )]
    pub(crate) local_forward: Vec<ForwardArg>,

    /// Forward a remote TCP port back to the client side.
    #[arg(
        short = 'R',
        value_name = "[BIND:]PORT:TARGET_HOST:TARGET_PORT",
        help_heading = "Forwarding",
        value_parser = parse_forward
    )]
    pub(crate) remote_forward: Vec<ForwardArg>,

    /// Remote target as [user@]host[:port].
    #[arg(value_name = "[USER@]HOST[:PORT]")]
    pub(crate) target: String,

    /// Remote command and arguments. Defaults to a login shell.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub(crate) command: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ForwardArg {
    pub(crate) listen_host: String,
    pub(crate) listen_port: u16,
    pub(crate) target_host: String,
    pub(crate) target_port: u16,
}

#[derive(Debug, Clone)]
pub(crate) struct Target {
    pub(crate) user: Option<String>,
    pub(crate) host: String,
    pub(crate) host_alias: String,
    pub(crate) port: Option<u16>,
}

impl Target {
    pub(crate) fn parse(input: &str, port_override: Option<u16>) -> Result<Self> {
        let (user, rest) = match input.rsplit_once('@') {
            Some((user, rest)) => (Some(user.to_owned()), rest),
            None => (None, input),
        };
        let (host, port) = parse_optional_host_port(rest)?;
        Ok(Self {
            user,
            host_alias: host.clone(),
            host,
            port: port_override.or(port),
        })
    }
}

fn parse_forward(s: &str) -> Result<ForwardArg, String> {
    let parts = split_colon_bracketed(s);
    let (listen_host, listen_port, target_host, target_port) = match parts.as_slice() {
        [lp, th, tp] => (
            "127.0.0.1".to_string(),
            lp.as_str(),
            th.as_str(),
            tp.as_str(),
        ),
        [lh, lp, th, tp] => (unbracket_host(lh), lp.as_str(), th.as_str(), tp.as_str()),
        _ => return Err("expected [listen_host:]listen_port:target_host:target_port".into()),
    };
    Ok(ForwardArg {
        listen_host,
        listen_port: listen_port.parse().map_err(|_| "bad listen port")?,
        target_host: unbracket_host(target_host),
        target_port: target_port.parse().map_err(|_| "bad target port")?,
    })
}

fn parse_optional_host_port(input: &str) -> Result<(String, Option<u16>)> {
    if let Some(rest) = input.strip_prefix('[') {
        let Some((host, suffix)) = rest.split_once(']') else {
            bail!("missing closing ']' in IPv6 host");
        };
        if suffix.is_empty() {
            return Ok((host.to_owned(), None));
        }
        let Some(port) = suffix.strip_prefix(':') else {
            bail!("unexpected text after bracketed host");
        };
        return Ok((host.to_owned(), Some(port.parse()?)));
    }
    match input.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !host.contains(':') => {
            Ok((host.to_owned(), Some(port.parse()?)))
        }
        _ => Ok((input.to_owned(), None)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Parser, error::ErrorKind};

    #[test]
    fn target_accepts_domain_names() {
        let target = Target::parse("alice@ssh.example.test:2222", None).unwrap();
        assert_eq!(target.user.as_deref(), Some("alice"));
        assert_eq!(target.host, "ssh.example.test");
        assert_eq!(target.host_alias, "ssh.example.test");
        assert_eq!(target.port, Some(2222));
    }

    #[test]
    fn forward_accepts_domain_names() {
        let forward = parse_forward("8080:app.internal.example:443").unwrap();
        assert_eq!(forward.listen_host, "127.0.0.1");
        assert_eq!(forward.listen_port, 8080);
        assert_eq!(forward.target_host, "app.internal.example");
        assert_eq!(forward.target_port, 443);
    }

    #[test]
    fn forward_accepts_domain_listen_hosts() {
        let forward = parse_forward("localhost:8080:db.internal.example:5432").unwrap();
        assert_eq!(forward.listen_host, "localhost");
        assert_eq!(forward.listen_port, 8080);
        assert_eq!(forward.target_host, "db.internal.example");
        assert_eq!(forward.target_port, 5432);
    }

    #[test]
    fn tty_short_flag_cannot_be_repeated() {
        let err = Args::try_parse_from(["hush", "-tt", "example.test"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }
}
