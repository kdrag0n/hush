use anyhow::{Result, bail};
use hush_core::protocol::{
    ControlRequest, ControlResponse, EnvVar, ProcessExit, RemoteSignal, SessionMode, StreamOpen,
    TermSize, read_frame, write_frame,
};
use std::{
    io::IsTerminal,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::Arc,
};
use tokio::io::unix::AsyncFd;

pub(crate) async fn control_writer(
    mut control_send: quinn::SendStream,
    mut rx: tokio::sync::mpsc::Receiver<ControlRequest>,
) -> Result<()> {
    while let Some(request) = rx.recv().await {
        write_frame(&mut control_send, &request).await?;
    }
    let _ = control_send.finish();
    Ok(())
}

pub(crate) async fn run_pty(
    conn: quinn::Connection,
    mut control_recv: quinn::RecvStream,
    control_tx: tokio::sync::mpsc::Sender<ControlRequest>,
) -> Result<()> {
    let raw = RawModeGuard::enable_if_terminal()?;
    let (mut send, recv) = conn.open_bi().await?;
    write_frame(&mut send, &StreamOpen::SessionPtyData).await?;
    expect_session_ready(&mut control_recv).await?;
    let resize_task = tokio::spawn(watch_resize(control_tx.clone()));
    let mut status_task = tokio::spawn(async move { read_exit_status(&mut control_recv).await });
    let (in_task, mut escape_rx) = spawn_stdin_pump(send);
    let out_task = tokio::spawn(quic_to_stdio(recv, libc::STDOUT_FILENO));
    let end = loop {
        tokio::select! {
            status = &mut status_task => break SessionEnd::Remote(status??),
            Some(()) = escape_rx.recv() => {
                conn.close(0u32.into(), b"~.");
                break SessionEnd::Escape;
            }
        }
    };
    status_task.abort();
    resize_task.abort();
    in_task.abort();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), out_task).await;
    drop(raw);
    finish_session(end);
}

pub(crate) async fn run_pipes(
    conn: quinn::Connection,
    mut control_recv: quinn::RecvStream,
    control_tx: tokio::sync::mpsc::Sender<ControlRequest>,
) -> Result<()> {
    let (local_signal_tx, mut local_signal_rx) = tokio::sync::mpsc::channel(8);
    let signal_task = tokio::spawn(watch_signals(control_tx, local_signal_tx));
    let mut sigterm_watchdog: Option<tokio::task::JoinHandle<()>> = None;
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

    let (in_task, mut escape_rx) = spawn_stdin_pump(send);
    let out_task = tokio::spawn(quic_to_stdio(recv, libc::STDOUT_FILENO));
    let err_task = tokio::spawn(quic_to_stdio(stderr_recv, libc::STDERR_FILENO));
    let mut status_task = tokio::spawn(async move { read_exit_status(&mut control_recv).await });
    let end = loop {
        tokio::select! {
            status = &mut status_task => break SessionEnd::Remote(status??),
            Some(()) = escape_rx.recv() => {
                conn.close(0u32.into(), b"~.");
                break SessionEnd::Escape;
            }
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
    status_task.abort();
    if let Some(watchdog) = sigterm_watchdog {
        watchdog.abort();
    }
    signal_task.abort();
    in_task.abort();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), out_task).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), err_task).await;
    finish_session(end);
}

pub(crate) fn choose_mode(force_tty: u8, no_tty: bool) -> SessionMode {
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

pub(crate) fn session_env(mode: &SessionMode) -> Vec<EnvVar> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StdinPumpExit {
    Eof,
    Escape,
}

#[derive(Debug, Clone, Copy)]
enum SessionEnd {
    Remote(ProcessExit),
    Escape,
}

fn spawn_stdin_pump(
    send: quinn::SendStream,
) -> (tokio::task::JoinHandle<()>, tokio::sync::mpsc::Receiver<()>) {
    let (escape_tx, escape_rx) = tokio::sync::mpsc::channel(1);
    let task = tokio::spawn(async move {
        match stdio_to_quic(libc::STDIN_FILENO, send).await {
            Ok(StdinPumpExit::Escape) => {
                let _ = escape_tx.try_send(());
            }
            Ok(StdinPumpExit::Eof) => {}
            Err(err) => tracing::debug!(%err, "stdin pump stopped"),
        }
    });
    (task, escape_rx)
}

async fn stdio_to_quic(fd: RawFd, mut send: quinn::SendStream) -> Result<StdinPumpExit> {
    let enable_escape = fd == libc::STDIN_FILENO && std::io::stdin().is_terminal();
    let fd = Arc::new(async_stdio_fd(fd)?);
    let mut escape = EscapeFilter::new(enable_escape);
    let mut buf = vec![0u8; 8192];
    let mut out = Vec::with_capacity(buf.len());
    loop {
        let mut guard = fd.readable().await?;
        match guard.try_io(|inner| read_fd(inner.get_ref().as_raw_fd(), &mut buf)) {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                out.clear();
                if escape.push(&buf[..n], &mut out) {
                    return Ok(StdinPumpExit::Escape);
                }
                if !out.is_empty() {
                    send.write_all(&out).await?;
                }
            }
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => continue,
        }
    }
    out.clear();
    escape.finish(&mut out);
    if !out.is_empty() {
        send.write_all(&out).await?;
    }
    send.finish()?;
    let _ = send.stopped().await;
    Ok(StdinPumpExit::Eof)
}

#[derive(Debug)]
struct EscapeFilter {
    enabled: bool,
    at_line_start: bool,
    pending_tilde: bool,
}

impl EscapeFilter {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            at_line_start: true,
            pending_tilde: false,
        }
    }

    fn push(&mut self, input: &[u8], output: &mut Vec<u8>) -> bool {
        if !self.enabled {
            output.extend_from_slice(input);
            return false;
        }

        for &byte in input {
            if self.pending_tilde {
                self.pending_tilde = false;
                if byte == b'.' {
                    return true;
                }
                output.push(b'~');
                self.at_line_start = false;
            }

            if self.at_line_start && byte == b'~' {
                self.pending_tilde = true;
                continue;
            }

            output.push(byte);
            self.at_line_start = byte == b'\n' || byte == b'\r';
        }
        false
    }

    fn finish(&mut self, output: &mut Vec<u8>) {
        if self.pending_tilde {
            self.pending_tilde = false;
            output.push(b'~');
        }
    }
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

fn finish_session(end: SessionEnd) -> ! {
    match end {
        SessionEnd::Remote(ProcessExit::Code(code)) => std::process::exit(code),
        SessionEnd::Remote(ProcessExit::Signal(signal)) => self_terminate_with_signal(signal),
        SessionEnd::Escape => std::process::exit(255),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_filter_detects_tilde_dot_at_line_start() {
        let (escaped, output) = run_escape_filter(true, &[b"hello\n~."]);
        assert!(escaped);
        assert_eq!(output, b"hello\n");
    }

    #[test]
    fn escape_filter_carries_tilde_across_reads() {
        let (escaped, output) = run_escape_filter(true, &[b"hello\r", b"~", b"."]);
        assert!(escaped);
        assert_eq!(output, b"hello\r");
    }

    #[test]
    fn escape_filter_ignores_tilde_dot_away_from_line_start() {
        let (escaped, output) = run_escape_filter(true, &[b"echo ~.\n"]);
        assert!(!escaped);
        assert_eq!(output, b"echo ~.\n");
    }

    #[test]
    fn escape_filter_only_handles_tilde_dot() {
        let (escaped, output) = run_escape_filter(true, &[b"~~.\n~x\n~"]);
        assert!(!escaped);
        assert_eq!(output, b"~~.\n~x\n~");
    }

    #[test]
    fn escape_filter_can_be_disabled() {
        let (escaped, output) = run_escape_filter(false, &[b"~.\n"]);
        assert!(!escaped);
        assert_eq!(output, b"~.\n");
    }

    fn run_escape_filter(enabled: bool, chunks: &[&[u8]]) -> (bool, Vec<u8>) {
        let mut filter = EscapeFilter::new(enabled);
        let mut output = Vec::new();
        let mut escaped = false;
        for chunk in chunks {
            if filter.push(chunk, &mut output) {
                escaped = true;
                break;
            }
        }
        if !escaped {
            filter.finish(&mut output);
        }
        (escaped, output)
    }
}
