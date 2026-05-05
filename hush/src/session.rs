use crate::os;
use anyhow::{Result, anyhow, bail};
use hush_core::protocol::{
    EnvVar, OpenSession, ProcessExit, RemoteSignal, SessionMode, StreamOpen, StreamResponse,
    read_frame, write_frame,
};

const STDIO_BUFFER_LEN: usize = 8192;

async fn stream_open_writer(
    conn: quinn::Connection,
    mut rx: tokio::sync::mpsc::Receiver<StreamOpen>,
) -> Result<()> {
    while let Some(header) = rx.recv().await {
        let mut send = conn.open_uni().await?;
        write_frame(&mut send, &header).await?;
        send.finish()?;
    }
    Ok(())
}

pub(crate) async fn run_pty(conn: quinn::Connection, session: OpenSession) -> Result<()> {
    let raw = os::RawModeGuard::enable_if_terminal()?;
    let (mut send, recv) = conn.open_bi().await?;
    write_frame(&mut send, &StreamOpen::Session { request: session }).await?;
    let recv = expect_session_ready(recv).await?;
    let (stream_tx, stream_rx) = tokio::sync::mpsc::channel(32);
    let stream_writer_task = tokio::spawn(stream_open_writer(conn.clone(), stream_rx));
    let resize_task = tokio::spawn(os::watch_resize(stream_tx.clone()));
    let mut status_task = tokio::spawn(read_exit_status(conn.clone()));
    let (in_task, mut escape_rx) = spawn_stdin_pump(send);
    let out_task = tokio::spawn(quic_to_stdio(recv, os::STDOUT_FD));
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
    stream_writer_task.abort();
    resize_task.abort();
    in_task.abort();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), out_task).await;
    drop(raw);
    finish_session(end);
}

pub(crate) async fn run_pipes(conn: quinn::Connection, session: OpenSession) -> Result<()> {
    let (local_signal_tx, mut local_signal_rx) = tokio::sync::mpsc::channel(8);
    let (stream_tx, stream_rx) = tokio::sync::mpsc::channel(32);
    let stream_writer_task = tokio::spawn(stream_open_writer(conn.clone(), stream_rx));
    let signal_task = tokio::spawn(os::watch_signals(stream_tx, local_signal_tx));
    let mut sigterm_watchdog: Option<tokio::task::JoinHandle<()>> = None;
    let (mut send, recv) = conn.open_bi().await?;
    write_frame(&mut send, &StreamOpen::Session { request: session }).await?;
    let recv = expect_session_ready(recv).await?;

    let mut deferred_status = None;
    let stderr_recv = loop {
        let mut recv = conn.accept_uni().await?;
        let header: StreamOpen = read_frame(&mut recv).await?;
        match header {
            StreamOpen::SessionStderr => break recv,
            StreamOpen::SessionExitStatus(status) => {
                deferred_status = Some(Ok(status));
            }
            StreamOpen::SessionError(err) => {
                deferred_status = Some(Err(anyhow!(err)));
            }
            other => tracing::debug!(?other, "ignoring unexpected session side stream"),
        }
    };

    let (in_task, mut escape_rx) = spawn_stdin_pump(send);
    let out_task = tokio::spawn(quic_to_stdio(recv, os::STDOUT_FD));
    let err_task = tokio::spawn(quic_to_stdio(stderr_recv, os::STDERR_FD));
    let status_conn = conn.clone();
    let mut status_task = tokio::spawn(async move {
        match deferred_status {
            Some(result) => result,
            None => read_exit_status(status_conn).await,
        }
    });
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
                        os::self_terminate_with_signal(RemoteSignal::SIGTERM);
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
    stream_writer_task.abort();
    in_task.abort();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), out_task).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), err_task).await;
    finish_session(end);
}

pub(crate) fn choose_mode(force_tty: bool, no_tty: bool) -> SessionMode {
    if no_tty {
        return SessionMode::Pipes;
    }
    if force_tty || (os::stdin_is_terminal() && os::stdout_is_terminal()) {
        return SessionMode::Pty {
            term: std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into()),
            size: os::terminal_size(),
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
        match stdio_to_quic(send).await {
            Ok(StdinPumpExit::Escape) => {
                let _ = escape_tx.try_send(());
            }
            Ok(StdinPumpExit::Eof) => {}
            Err(err) => tracing::debug!(%err, "stdin pump stopped"),
        }
    });
    (task, escape_rx)
}

async fn stdio_to_quic(mut send: quinn::SendStream) -> Result<StdinPumpExit> {
    let enable_escape = os::stdin_is_terminal();
    let fd = os::AsyncStdioFd::duplicate(os::STDIN_FD)?;
    let mut escape = EscapeFilter::new(enable_escape);
    let mut buf = vec![0u8; STDIO_BUFFER_LEN];
    let mut out = Vec::with_capacity(buf.len());
    loop {
        match fd.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                out.clear();
                if escape.push(&buf[..n], &mut out) {
                    return Ok(StdinPumpExit::Escape);
                }
                if !out.is_empty() {
                    send.write_all(&out).await?;
                }
            }
            Err(err) => return Err(err),
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

async fn quic_to_stdio(mut recv: quinn::RecvStream, fd: i32) -> Result<()> {
    let fd = os::AsyncStdioFd::duplicate(fd)?;
    let mut buf = vec![0u8; STDIO_BUFFER_LEN];
    loop {
        let n = recv.read(&mut buf).await?.unwrap_or(0);
        if n == 0 {
            return Ok(());
        }
        fd.write_all(&buf[..n]).await?;
    }
}

async fn expect_session_ready(mut recv: quinn::RecvStream) -> Result<quinn::RecvStream> {
    match read_frame::<StreamResponse>(&mut recv).await? {
        StreamResponse::SessionReady => Ok(recv),
        StreamResponse::Error(err) => bail!("{err}"),
        other => bail!("unexpected control response: {other:?}"),
    }
}

async fn read_exit_status(conn: quinn::Connection) -> Result<ProcessExit> {
    loop {
        let mut recv = conn.accept_uni().await?;
        match read_frame::<StreamOpen>(&mut recv).await? {
            StreamOpen::SessionExitStatus(status) => return Ok(status),
            StreamOpen::SessionError(err) => bail!("{err}"),
            other => tracing::debug!(?other, "ignoring unexpected session side stream"),
        }
    }
}

fn finish_session(end: SessionEnd) -> ! {
    match end {
        SessionEnd::Remote(ProcessExit::Code(code)) => std::process::exit(code),
        SessionEnd::Remote(ProcessExit::Signal(signal)) => os::self_terminate_with_signal(signal),
        SessionEnd::Escape => std::process::exit(255),
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
