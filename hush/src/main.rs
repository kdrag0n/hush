use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use hush_core::{
    auth, config,
    forwarding::LocalForward,
    protocol::{
        ControlRequest, ControlResponse, EnvVar, OpenSession, ProcessExit, RemoteForwardRequest,
        RemoteSignal, SessionMode, StreamOpen, TcpTarget, TermSize, read_frame, write_frame,
    },
};
use quinn::{Connection, Endpoint};
use std::{
    collections::VecDeque,
    io::IsTerminal,
    net::SocketAddr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    path::PathBuf,
    sync::Arc,
};
use tokio::{
    io::unix::AsyncFd,
    task::JoinSet,
    time::{Duration, Instant},
};

const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);

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
    #[arg(short = 'i')]
    identity_file: Option<PathBuf>,
    #[arg(short = 'S', long)]
    no_shell: bool,
    #[arg(short = 'L', value_parser = parse_forward)]
    local_forward: Vec<ForwardArg>,
    #[arg(short = 'R', value_parser = parse_forward)]
    remote_forward: Vec<ForwardArg>,
    target: String,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
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
    let identity_file = args.identity_file.or(ssh_cfg.identity_file);

    let identity = auth::load_identity_with_file(identity_file.as_deref())?;
    let mut endpoint = Endpoint::client("[::]:0".parse::<SocketAddr>()?)?;
    endpoint.set_default_client_config(hush_core::tls::make_client_config(
        &data_dir,
        hush_core::tls::host_key(&host, port),
        identity,
        args.insecure,
    )?);

    let conn = connect_any(&endpoint, &host, port).await?;

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
    let env = session_env(&mode);
    let session = OpenSession {
        user,
        command: args.command,
        use_shell: !args.no_shell,
        mode,
        env,
    };
    write_frame(
        &mut control_send,
        &ControlRequest::OpenSession(session.clone()),
    )
    .await?;
    let (control_tx, control_rx) = tokio::sync::mpsc::channel(32);
    tokio::spawn(control_writer(control_send, control_rx));
    match session.mode {
        SessionMode::Pty { .. } => run_pty(conn, control_recv, control_tx).await,
        SessionMode::Pipes => run_pipes(conn, control_recv, control_tx).await,
    }
}

async fn control_writer(
    mut control_send: quinn::SendStream,
    mut rx: tokio::sync::mpsc::Receiver<ControlRequest>,
) -> Result<()> {
    while let Some(request) = rx.recv().await {
        write_frame(&mut control_send, &request).await?;
    }
    let _ = control_send.finish();
    Ok(())
}

async fn run_pty(
    conn: quinn::Connection,
    mut control_recv: quinn::RecvStream,
    control_tx: tokio::sync::mpsc::Sender<ControlRequest>,
) -> Result<()> {
    let raw = RawModeGuard::enable_if_terminal()?;
    let (mut send, recv) = conn.open_bi().await?;
    write_frame(&mut send, &StreamOpen::SessionPtyData).await?;
    expect_session_ready(&mut control_recv).await?;
    let resize_task = tokio::spawn(watch_resize(control_tx.clone()));
    let in_task = tokio::spawn(stdio_to_quic(libc::STDIN_FILENO, send));
    let out_task = tokio::spawn(quic_to_stdio(recv, libc::STDOUT_FILENO));
    let status = read_exit_status(&mut control_recv).await?;
    resize_task.abort();
    in_task.abort();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), out_task).await;
    drop(raw);
    finish_process(status);
}

async fn run_pipes(
    conn: quinn::Connection,
    mut control_recv: quinn::RecvStream,
    control_tx: tokio::sync::mpsc::Sender<ControlRequest>,
) -> Result<()> {
    let (mut send, recv) = conn.open_bi().await?;
    write_frame(&mut send, &StreamOpen::SessionStdIo).await?;
    expect_session_ready(&mut control_recv).await?;

    let stderr_recv = loop {
        let mut recv = conn.accept_uni().await?;
        let header: StreamOpen = read_frame(&mut recv).await?;
        if matches!(header, StreamOpen::SessionStderr) {
            break recv;
        }
    };

    let in_task = tokio::spawn(stdio_to_quic(libc::STDIN_FILENO, send));
    let out_task = tokio::spawn(quic_to_stdio(recv, libc::STDOUT_FILENO));
    let err_task = tokio::spawn(quic_to_stdio(stderr_recv, libc::STDERR_FILENO));
    let (local_signal_tx, mut local_signal_rx) = tokio::sync::mpsc::channel(8);
    let signal_task = tokio::spawn(watch_signals(control_tx, local_signal_tx));
    let mut sigterm_watchdog = None;
    let status = loop {
        tokio::select! {
            status = read_exit_status(&mut control_recv) => break status?,
            Some(signal) = local_signal_rx.recv() => {
                if signal == RemoteSignal::SIGTERM && sigterm_watchdog.is_none() {
                    sigterm_watchdog = Some(tokio::spawn(async {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        self_terminate_with_signal(RemoteSignal::SIGTERM);
                    }));
                }
            }
        }
    };
    if let Some(watchdog) = sigterm_watchdog {
        watchdog.abort();
    }
    signal_task.abort();
    in_task.abort();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), out_task).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), err_task).await;
    finish_process(status);
}

#[cfg(unix)]
async fn watch_resize(tx: tokio::sync::mpsc::Sender<ControlRequest>) -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sigwinch = signal(SignalKind::window_change())?;
    while sigwinch.recv().await.is_some() {
        let _ = tx.send(ControlRequest::Resize(terminal_size())).await;
    }
    Ok(())
}

#[cfg(unix)]
async fn watch_signals(
    tx: tokio::sync::mpsc::Sender<ControlRequest>,
    local_tx: tokio::sync::mpsc::Sender<RemoteSignal>,
) -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sighup = signal(SignalKind::hangup())?;
    let mut sigquit = signal(SignalKind::quit())?;
    let mut sigusr1 = signal(SignalKind::user_defined1())?;
    let mut sigusr2 = signal(SignalKind::user_defined2())?;
    loop {
        let signal = tokio::select! {
            _ = sigint.recv() => RemoteSignal::SIGINT,
            _ = sigterm.recv() => RemoteSignal::SIGTERM,
            _ = sighup.recv() => RemoteSignal::SIGHUP,
            _ = sigquit.recv() => RemoteSignal::SIGQUIT,
            _ = sigusr1.recv() => RemoteSignal::SIGUSR1,
            _ = sigusr2.recv() => RemoteSignal::SIGUSR2,
        };
        let _ = tx.send(ControlRequest::Signal(signal)).await;
        let _ = local_tx.send(signal).await;
    }
}

async fn stdio_to_quic(fd: RawFd, mut send: quinn::SendStream) -> Result<()> {
    let fd = Arc::new(async_stdio_fd(fd)?);
    let mut buf = vec![0u8; 8192];
    loop {
        let mut guard = fd.readable().await?;
        match guard.try_io(|inner| read_fd(inner.get_ref().as_raw_fd(), &mut buf)) {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => send.write_all(&buf[..n]).await?,
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => continue,
        }
    }
    send.finish()?;
    let _ = send.stopped().await;
    Ok(())
}

async fn quic_to_stdio(mut recv: quinn::RecvStream, fd: RawFd) -> Result<()> {
    let fd = Arc::new(async_stdio_fd(fd)?);
    let mut buf = vec![0u8; 8192];
    loop {
        let n = recv.read(&mut buf).await?.unwrap_or(0);
        if n == 0 {
            return Ok(());
        }
        let mut written = 0;
        while written < n {
            let mut guard = fd.writable().await?;
            match guard.try_io(|inner| write_fd(inner.get_ref().as_raw_fd(), &buf[written..n])) {
                Ok(Ok(0)) => return Ok(()),
                Ok(Ok(m)) => written += m,
                Ok(Err(err)) => return Err(err.into()),
                Err(_) => continue,
            }
        }
    }
}

fn async_stdio_fd(fd: RawFd) -> Result<AsyncFd<OwnedFd>> {
    let dup = unsafe { libc::dup(fd) };
    if dup < 0 {
        bail!("dup stdio fd failed: {}", std::io::Error::last_os_error());
    }
    set_nonblocking(dup)?;
    Ok(AsyncFd::new(unsafe { OwnedFd::from_raw_fd(dup) })?)
}

fn set_nonblocking(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        bail!("fcntl(F_GETFL) failed: {}", std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        bail!("fcntl(F_SETFL) failed: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

fn read_fd(fd: RawFd, buf: &mut [u8]) -> std::io::Result<usize> {
    let rc = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if rc >= 0 {
        Ok(rc as usize)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn write_fd(fd: RawFd, buf: &[u8]) -> std::io::Result<usize> {
    let rc = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    if rc >= 0 {
        Ok(rc as usize)
    } else {
        Err(std::io::Error::last_os_error())
    }
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

async fn read_exit_status(recv: &mut quinn::RecvStream) -> Result<ProcessExit> {
    loop {
        match read_frame::<ControlResponse>(recv).await? {
            ControlResponse::ExitStatus(code) => return Ok(code),
            ControlResponse::Error(err) => bail!("{err}"),
            _ => {}
        }
    }
}

fn session_env(mode: &SessionMode) -> Vec<EnvVar> {
    let mut env = Vec::new();
    if let SessionMode::Pty { term, .. } = mode {
        env.push(EnvVar {
            key: "TERM".to_owned(),
            value: term.clone(),
        });
    }
    for (key, value) in std::env::vars() {
        if key == "LANG" || key.starts_with("LC_") {
            env.push(EnvVar { key, value });
        }
    }
    env
}

fn finish_process(status: ProcessExit) -> ! {
    match status {
        ProcessExit::Code(code) => std::process::exit(code),
        ProcessExit::Signal(signal) => self_terminate_with_signal(signal),
    }
}

fn self_terminate_with_signal(signal: RemoteSignal) -> ! {
    let signal = signal.as_raw();
    unsafe {
        let mut set = std::mem::zeroed::<libc::sigset_t>();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, signal);
        libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
        libc::_exit(128 + signal);
    }
}

async fn connect_any(endpoint: &Endpoint, host: &str, port: u16) -> Result<Connection> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolve {host}:{port}"))?
        .collect();
    if addrs.is_empty() {
        bail!("resolve {host}:{port}: no addresses");
    }

    let mut pending = VecDeque::from(happy_eyeballs_order(addrs));
    let mut attempts = JoinSet::<Result<Connection>>::new();
    let label = format!("{host}:{port}");

    if let Some(addr) = pending.pop_front() {
        spawn_connect_attempt(&mut attempts, endpoint, addr, host, &label);
    }

    let mut last_err = None;
    let mut next_attempt_at = (!pending.is_empty()).then(|| Instant::now() + HAPPY_EYEBALLS_DELAY);
    loop {
        if attempts.is_empty() && pending.is_empty() {
            break;
        }
        if attempts.is_empty() {
            if let Some(addr) = pending.pop_front() {
                spawn_connect_attempt(&mut attempts, endpoint, addr, host, &label);
                next_attempt_at =
                    (!pending.is_empty()).then(|| Instant::now() + HAPPY_EYEBALLS_DELAY);
                continue;
            }
        }

        match next_attempt_at {
            Some(deadline) => {
                tokio::select! {
                    result = attempts.join_next(), if !attempts.is_empty() => {
                        match result {
                            Some(Ok(Ok(conn))) => {
                                attempts.abort_all();
                                return Ok(conn);
                            }
                            Some(Ok(Err(err))) => last_err = Some(err),
                            Some(Err(err)) => last_err = Some(err.into()),
                            None => {}
                        }
                    }
                    _ = tokio::time::sleep_until(deadline) => {
                        if let Some(addr) = pending.pop_front() {
                            spawn_connect_attempt(&mut attempts, endpoint, addr, host, &label);
                        }
                        next_attempt_at =
                            (!pending.is_empty()).then(|| Instant::now() + HAPPY_EYEBALLS_DELAY);
                    }
                }
            }
            None => match attempts.join_next().await {
                Some(Ok(Ok(conn))) => return Ok(conn),
                Some(Ok(Err(err))) => last_err = Some(err),
                Some(Err(err)) => last_err = Some(err.into()),
                None => {}
            },
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("connect to {host}:{port}: no attempts completed")))
}

fn spawn_connect_attempt(
    attempts: &mut JoinSet<Result<Connection>>,
    endpoint: &Endpoint,
    addr: SocketAddr,
    server_name: &str,
    label: &str,
) {
    let endpoint = endpoint.clone();
    let server_name = server_name.to_owned();
    let label = label.to_owned();
    attempts.spawn(async move {
        endpoint
            .connect(addr, &server_name)
            .with_context(|| format!("start QUIC connect to {addr} for {label}"))?
            .await
            .with_context(|| format!("connect to {addr} for {label}"))
    });
}

fn happy_eyeballs_order(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    if addrs.is_empty() {
        return addrs;
    }
    let (v6, v4): (Vec<_>, Vec<_>) = addrs.into_iter().partition(SocketAddr::is_ipv6);
    let mut preferred = VecDeque::from(v6);
    let mut fallback = VecDeque::from(v4);
    let mut ordered = Vec::with_capacity(preferred.len() + fallback.len());

    while !preferred.is_empty() || !fallback.is_empty() {
        if let Some(addr) = preferred.pop_front() {
            ordered.push(addr);
        }
        if let Some(addr) = fallback.pop_front() {
            ordered.push(addr);
        }
    }
    ordered
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
    fn happy_eyeballs_prefers_ipv6_and_interleaves_ipv4() {
        let ordered = happy_eyeballs_order(vec![
            "192.0.2.1:443".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
            "192.0.2.2:443".parse().unwrap(),
            "[2001:db8::2]:443".parse().unwrap(),
        ]);
        assert_eq!(
            ordered,
            vec![
                "[2001:db8::1]:443".parse().unwrap(),
                "192.0.2.1:443".parse().unwrap(),
                "[2001:db8::2]:443".parse().unwrap(),
                "192.0.2.2:443".parse().unwrap(),
            ]
        );
    }
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
