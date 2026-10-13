use anyhow::{Result, bail};
use std::{ffi::OsStr, path::PathBuf, str::FromStr};

/// Parse `words` (argv without the program name) with `$ty`, handling help, version, and
/// failures the way `parse()` does: help/version to stdout with exit 0, failures to stderr
/// with exit 2.
macro_rules! parse_or_exit {
    ($ty:ty, $words:expr) => {{
        let words: &[&::std::ffi::OsStr] = $words;
        match <$ty>::parse_from(words) {
            Ok(cli) => cli,
            Err(usage_rs::Error::Help { cmd, long }) => {
                if let Some(page) = <$ty>::render_help(cmd, long) {
                    print!("{page}");
                }
                ::std::process::exit(0);
            }
            Err(usage_rs::Error::Version { .. }) => {
                let bin = <$ty>::spec().bin.unwrap_or(env!("CARGO_PKG_NAME"));
                println!("{bin} {}", env!("CARGO_PKG_VERSION"));
                ::std::process::exit(0);
            }
            Err(err) => {
                eprint!("{}", <$ty>::render_failure(words, &err));
                ::std::process::exit(2);
            }
        }
    }};
}

#[derive(Debug)]
pub(crate) enum Cli {
    Session(Args),
    Copy(crate::cp::CpArgs),
    /// Print a shell completion script.
    Completions(&'static str),
    CompleteRemote(crate::complete::RemoteArgs),
}

impl Cli {
    pub(crate) fn parse_from_env() -> Result<Self> {
        let mut args: Vec<std::ffi::OsString> = std::env::args_os().collect();
        // Before the argv0 check, so completion can call whichever name it
        // is completing, `hcp` included.
        if args.get(1).and_then(|arg| arg.to_str()) == Some(crate::complete::COMPLETE_REMOTE) {
            let words: Vec<&OsStr> = args.iter().skip(2).map(OsStr::new).collect();
            return Ok(Self::CompleteRemote(parse_or_exit!(
                crate::complete::RemoteArgs,
                &words
            )));
        }
        let argv0 = args
            .first()
            .and_then(|arg| std::path::Path::new(arg).file_stem())
            .and_then(|arg| arg.to_str())
            .unwrap_or("hush");
        if argv0 == "hcp" {
            let words: Vec<&OsStr> = args.iter().skip(1).map(OsStr::new).collect();
            return Ok(Self::Copy(parse_or_exit!(crate::cp::CpArgs, &words)));
        }
        if args.get(1).and_then(|arg| arg.to_str()) == Some("cp") {
            args.remove(1);
            let words: Vec<&OsStr> = args.iter().skip(1).map(OsStr::new).collect();
            return Ok(Self::Copy(parse_or_exit!(crate::cp::CpArgs, &words)));
        }
        if args.get(1).and_then(|arg| arg.to_str()) == Some("--completions") {
            let script = match args.get(2).and_then(|arg| arg.to_str()) {
                Some("zsh") => crate::complete::ZSH,
                Some("bash") => crate::complete::BASH,
                _ => {
                    eprintln!("hush: --completions takes a shell: zsh or bash");
                    std::process::exit(2);
                }
            };
            return Ok(Self::Completions(script));
        }
        let words: Vec<&OsStr> = args.iter().skip(1).map(OsStr::new).collect();
        Ok(Self::Session(parse_or_exit!(Args, &words)))
    }
}

#[derive(Debug, usage_rs::Cli)]
#[usage(
    bin = "hush",
    version,
    unknown_flags = "error",
    args_override_self = false,
    about = "SSH-like remote command client over QUIC",
    long_about = "hush connects to a hush-server over QUIC, authenticates with an Ed25519 or ECDSA (P-256/384/521) SSH key, and runs a remote shell or command.\n\nTarget syntax is [user@]host[:port]. IPv6 literals may be written as [::1]:22022.\n\nForward syntax for -L and -R is [listen_host:]listen_port:target_host:target_port.\n\nPrint shell completions with `hush --completions zsh` or `hush --completions bash`."
)]
pub(crate) struct Args {
    /// Enable client logging. Without this, client logging is disabled.
    #[usage(short = 'v', long)]
    pub(crate) verbose: bool,

    /// Skip TOFU host certificate verification for this connection.
    #[usage(short = 'k', long, help_heading = "Host Trust")]
    pub(crate) insecure: bool,

    /// Connect to this remote port, overriding target and ssh_config ports.
    #[usage(short = 'p', value_name = "PORT")]
    pub(crate) port: Option<u16>,

    /// Force PTY allocation.
    #[usage(short = 't')]
    pub(crate) tty: bool,

    /// Disable PTY allocation and use stdin/stdout/stderr pipes.
    #[usage(short = 'T')]
    pub(crate) no_tty: bool,

    /// Data directory for known_hosts and client state.
    #[usage(long, value_name = "DIR", help_heading = "Files")]
    pub(crate) data_dir: Option<PathBuf>,

    /// SSH identity file (Ed25519 or ECDSA). Agent use is preferred when it has this key.
    #[usage(short = 'i', value_name = "PATH", help_heading = "Authentication")]
    pub(crate) identity_file: Option<PathBuf>,

    /// Execute the command directly instead of through the user's shell.
    #[usage(short = 'S', long, help_heading = "Execution")]
    pub(crate) no_shell: bool,

    /// Forward the local ssh-agent to the remote session.
    #[usage(short = 'A', help_heading = "Forwarding")]
    pub(crate) forward_agent: bool,

    /// Forward a local TCP port to the remote side.
    #[usage(
        short = 'L',
        value_name = "[BIND:]PORT:TARGET_HOST:TARGET_PORT",
        help_heading = "Forwarding"
    )]
    pub(crate) local_forward: Vec<ForwardArg>,

    /// Forward a remote TCP port back to the client side.
    #[usage(
        short = 'R',
        value_name = "[BIND:]PORT:TARGET_HOST:TARGET_PORT",
        help_heading = "Forwarding"
    )]
    pub(crate) remote_forward: Vec<ForwardArg>,

    /// Remote target as [user@]host[:port].
    #[usage(value_name = "[USER@]HOST[:PORT]")]
    pub(crate) target: String,

    /// Remote command and arguments. Defaults to a login shell.
    #[usage(value_name = "COMMAND", double_dash = "automatic")]
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

impl FromStr for ForwardArg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        parse_forward(s)
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
    fn remote_command_keeps_hyphenated_words() {
        let words = ["-L", "8080:app:443", "box", "ls", "-la", "--color"].map(OsStr::new);
        let args = Args::parse_from(&words).unwrap();
        assert_eq!(args.target, "box");
        assert_eq!(args.command, ["ls", "-la", "--color"]);
        assert_eq!(args.local_forward.len(), 1);
        assert_eq!(args.local_forward[0].target_port, 443);
    }

    #[test]
    fn tty_short_flag_cannot_be_repeated() {
        let words = ["-tt", "example.test"].map(OsStr::new);
        let err = Args::parse_from(&words).unwrap_err();
        assert!(matches!(err, usage_rs::Error::DuplicateFlag { .. }), "{err:?}");
    }
}
