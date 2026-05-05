use anyhow::{Context, Result, bail};
use clap::Parser;
use hush_core::{
    auth, config,
    forwarding::LocalForward,
    protocol::{
        ControlRequest, ControlResponse, OpenSession, RemoteForwardRequest, SessionMode,
        StreamOpen, TcpTarget, TermSize, read_frame, write_frame,
    },
};
use quinn::Endpoint;
use std::{
    io::IsTerminal,
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
};
use tokio::io::{self, AsyncWriteExt};

#[derive(Debug, Parser)]
#[command(name = "hush", version)]
struct Args {
    #[arg(short = 'v', long)]
    verbose: bool,
    #[arg(short = 'k', long)]
    insecure: bool,
    #[arg(short = 'p')]
    port: Option<u16>,
    #[arg(short = 't', action = clap::ArgAction::Count)]
    tty: u8,
    #[arg(short = 'T')]
    no_tty: bool,
    #[arg(long)]
    data_dir: Option<PathBuf>,
    #[arg(short = 'L', value_parser = parse_forward)]
    local_forward: Vec<ForwardArg>,
    #[arg(short = 'R', value_parser = parse_forward)]
    remote_forward: Vec<ForwardArg>,
    target: String,
    command: Vec<String>,
}

#[derive(Debug, Clone)]
struct ForwardArg {
    listen_host: String,
    listen_port: u16,
    target_host: String,
    target_port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_logging(args.verbose);
    let target = Target::parse(&args.target, args.port)?;
    let ssh_cfg = config::read_ssh_config(&target.host_alias)?;
    let user = target
        .user
        .or(ssh_cfg.user)
        .unwrap_or_else(auth::current_username);
    let host = ssh_cfg.hostname.unwrap_or(target.host);
    let port = target.port.or(ssh_cfg.port).unwrap_or(4433);
    let data_dir = args
        .data_dir
        .unwrap_or_else(hush_core::paths::default_data_dir);

    let identity = auth::load_identity()?;
    let mut endpoint = Endpoint::client("[::]:0".parse::<SocketAddr>()?)?;
    endpoint.set_default_client_config(hush_core::tls::make_client_config(
        &data_dir,
        hush_core::tls::host_key(&host, port),
        identity,
        args.insecure,
    )?);

    let remote_addr = resolve_one(&host, port)?;
    let conn = endpoint
        .connect(remote_addr, &host)?
        .await
        .with_context(|| format!("connect to {host}:{port}"))?;

    for spec in args.local_forward.iter().cloned() {
        let conn = conn.clone();
        tokio::spawn(async move {
            let local = LocalForward {
                listen_host: spec.listen_host,
                listen_port: spec.listen_port,
                target: TcpTarget {
                    host: spec.target_host,
                    port: spec.target_port,
                },
            };
            if let Err(err) = hush_core::forwarding::run_local_forward(conn, local).await {
                tracing::warn!(%err, "local forwarding stopped");
            }
        });
    }

    let conn_for_remote = conn.clone();
    tokio::spawn(async move {
        while let Ok((send, recv)) = conn_for_remote.accept_bi().await {
            tokio::spawn(async move {
                if let Err(err) =
                    hush_core::forwarding::serve_remote_forward_stream(send, recv).await
                {
                    tracing::warn!(%err, "remote forwarding stream failed");
                }
            });
        }
    });

    let (mut control_send, mut control_recv) = conn.open_bi().await?;
    for spec in args.remote_forward.iter().cloned() {
        write_frame(
            &mut control_send,
            &ControlRequest::OpenRemoteForward(RemoteForwardRequest {
                listen_host: spec.listen_host,
                listen_port: spec.listen_port,
                target: TcpTarget {
                    host: spec.target_host,
                    port: spec.target_port,
                },
            }),
        )
        .await?;
        expect_ok(&mut control_recv).await?;
    }

    let mode = choose_mode(args.tty, args.no_tty);
    let session = OpenSession {
        user,
        command: args.command,
        mode,
    };
    write_frame(
        &mut control_send,
        &ControlRequest::OpenSession(session.clone()),
    )
    .await?;
    match session.mode {
        SessionMode::Pty { .. } => run_pty(conn, control_recv).await,
        SessionMode::Pipes => run_pipes(conn, control_recv).await,
    }
}

async fn run_pty(conn: quinn::Connection, mut control_recv: quinn::RecvStream) -> Result<()> {
    let _raw = RawModeGuard::enable_if_terminal()?;
    let (mut send, recv) = conn.open_bi().await?;
    write_frame(&mut send, &StreamOpen::SessionPtyData).await?;
    expect_session_ready(&mut control_recv).await?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    let in_task = tokio::spawn(hush_core::net::copy_reader_to_quic(stdin, send));
    let out_task = tokio::spawn(hush_core::net::copy_quic_to_writer(recv, stdout));
    let status = read_exit_status(&mut control_recv).await?;
    in_task.abort();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), out_task).await;
    std::process::exit(status);
}

async fn run_pipes(conn: quinn::Connection, mut control_recv: quinn::RecvStream) -> Result<()> {
    let (mut send, recv) = conn.open_bi().await?;
    write_frame(&mut send, &StreamOpen::SessionStdIo).await?;
    expect_session_ready(&mut control_recv).await?;

    let mut stderr_recv = loop {
        let mut recv = conn.accept_uni().await?;
        let header: StreamOpen = read_frame(&mut recv).await?;
        if matches!(header, StreamOpen::SessionStderr) {
            break recv;
        }
    };

    let in_task = tokio::spawn(hush_core::net::copy_reader_to_quic(io::stdin(), send));
    let out_task = tokio::spawn(hush_core::net::copy_quic_to_writer(recv, io::stdout()));
    let err_task = tokio::spawn(async move {
        io::copy(&mut stderr_recv, &mut io::stderr()).await?;
        io::stderr().shutdown().await.ok();
        anyhow::Ok(())
    });
    let status = read_exit_status(&mut control_recv).await?;
    in_task.abort();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), out_task).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), err_task).await;
    std::process::exit(status);
}

fn choose_mode(force_tty: u8, no_tty: bool) -> SessionMode {
    if no_tty {
        return SessionMode::Pipes;
    }
    if force_tty > 0 || (std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
        return SessionMode::Pty {
            term: std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into()),
            size: terminal_size(),
        };
    }
    SessionMode::Pipes
}

fn terminal_size() -> TermSize {
    let mut ws = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe {
        libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws);
    }
    TermSize {
        rows: ws.ws_row.max(1),
        cols: ws.ws_col.max(1),
        width_px: ws.ws_xpixel,
        height_px: ws.ws_ypixel,
    }
}

async fn expect_ok(recv: &mut quinn::RecvStream) -> Result<()> {
    match read_frame::<ControlResponse>(recv).await? {
        ControlResponse::Ok => Ok(()),
        ControlResponse::Error(err) => bail!("{err}"),
        other => bail!("unexpected control response: {other:?}"),
    }
}

async fn expect_session_ready(recv: &mut quinn::RecvStream) -> Result<()> {
    match read_frame::<ControlResponse>(recv).await? {
        ControlResponse::SessionReady => Ok(()),
        ControlResponse::Error(err) => bail!("{err}"),
        other => bail!("unexpected control response: {other:?}"),
    }
}

async fn read_exit_status(recv: &mut quinn::RecvStream) -> Result<i32> {
    loop {
        match read_frame::<ControlResponse>(recv).await? {
            ControlResponse::ExitStatus(code) => return Ok(code),
            ControlResponse::Error(err) => bail!("{err}"),
            _ => {}
        }
    }
}

fn resolve_one(host: &str, port: u16) -> Result<SocketAddr> {
    (host, port)
        .to_socket_addrs()?
        .next()
        .with_context(|| format!("resolve {host}:{port}"))
}

#[derive(Debug)]
struct Target {
    user: Option<String>,
    host: String,
    host_alias: String,
    port: Option<u16>,
}

impl Target {
    fn parse(input: &str, port_override: Option<u16>) -> Result<Self> {
        let (user, rest) = match input.rsplit_once('@') {
            Some((user, rest)) => (Some(user.to_owned()), rest),
            None => (None, input),
        };
        let (host, port) = match rest.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() => (host.to_owned(), Some(port.parse()?)),
            _ => (rest.to_owned(), None),
        };
        Ok(Self {
            user,
            host_alias: host.clone(),
            host,
            port: port_override.or(port),
        })
    }
}

fn parse_forward(s: &str) -> Result<ForwardArg, String> {
    let parts: Vec<_> = s.split(':').collect();
    let (listen_host, listen_port, target_host, target_port) = match parts.as_slice() {
        [lp, th, tp] => ("127.0.0.1".to_string(), *lp, *th, *tp),
        [lh, lp, th, tp] => ((*lh).to_string(), *lp, *th, *tp),
        _ => return Err("expected [listen_host:]listen_port:target_host:target_port".into()),
    };
    Ok(ForwardArg {
        listen_host,
        listen_port: listen_port.parse().map_err(|_| "bad listen port")?,
        target_host: target_host.to_string(),
        target_port: target_port.parse().map_err(|_| "bad target port")?,
    })
}

fn init_logging(verbose: bool) {
    if verbose {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "hush=debug,hush_core=debug,quinn=info".into()),
            )
            .init();
    }
}

struct RawModeGuard {
    saved: libc::termios,
    active: bool,
}

impl RawModeGuard {
    fn enable_if_terminal() -> Result<Self> {
        if !std::io::stdin().is_terminal() {
            return Ok(Self {
                saved: unsafe { std::mem::zeroed() },
                active: false,
            });
        }
        let mut saved = unsafe { std::mem::zeroed::<libc::termios>() };
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut saved) } != 0 {
            bail!("tcgetattr failed: {}", std::io::Error::last_os_error());
        }
        let mut raw = saved;
        unsafe { libc::cfmakeraw(&mut raw) };
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) } != 0 {
            bail!("tcsetattr failed: {}", std::io::Error::last_os_error());
        }
        Ok(Self {
            saved,
            active: true,
        })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.saved);
            }
        }
    }
}
