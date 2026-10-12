use crate::os;
use anyhow::{Result, anyhow, bail};
use hush_core::priority::{StreamPriority, set_stream_priority};
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
        set_stream_priority(&send, StreamPriority::Shell);
        write_frame(&mut send, &header).await?;
        send.finish()?;
    }
    Ok(())
}

pub(crate) async fn run_pty(conn: quinn::Connection, session: OpenSession) -> Result<()> {
    let raw = os::RawModeGuard::enable_if_terminal()?;
    let (mut send, recv) = conn.open_bi().await?;
    set_stream_priority(&send, StreamPriority::Shell);
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
    set_stream_priority(&send, StreamPriority::Shell);
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

pub(crate) fn choose_mode(
    force_tty: bool,
    no_tty: bool,
    term_override: Option<&str>,
) -> SessionMode {
    if no_tty {
        return SessionMode::Pipes;
    }
    if force_tty || (os::stdin_is_terminal() && os::stdout_is_terminal()) {
        return SessionMode::Pty {
            term: term_override
                .map(str::to_owned)
                .or_else(|| std::env::var("TERM").ok())
                .unwrap_or_else(|| "xterm-256color".into()),
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

/// Detects the `<Enter>~.` disconnect escape in terminal input, both as plain
/// bytes and as kitty keyboard protocol (`CSI … u`) key events, which remote
/// apps can enable so that every key arrives as an escape sequence.
#[derive(Debug)]
struct EscapeFilter {
    enabled: bool,
    at_line_start: bool,
    /// Input held back since a `~` at line start, until the next key press
    /// decides whether it is an escape. Empty when no `~` is pending.
    held: Vec<u8>,
    /// Incomplete CSI sequence carried over from the previous read.
    partial: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EscapeKey {
    Enter,
    Tilde,
    Dot,
    Other,
    /// Not a key press: releases, modifier keys alone, focus and mouse reports.
    Ignore,
}

/// Longest incomplete CSI sequence to carry across reads before passing it through.
const MAX_PARTIAL_CSI_LEN: usize = 256;

const KITTY_MOD_SHIFT: u32 = 1;
const KITTY_MOD_CAPS_LOCK: u32 = 64;
const KITTY_MOD_NUM_LOCK: u32 = 128;
const KITTY_EVENT_RELEASE: u32 = 3;
const KITTY_KEY_CAPS_LOCK: u32 = 57358;
const KITTY_KEY_NUM_LOCK: u32 = 57360;
const KITTY_KEY_KP_ENTER: u32 = 57414;
const KITTY_KEY_LEFT_SHIFT: u32 = 57441;
const KITTY_KEY_ISO_LEVEL5_SHIFT: u32 = 57454;

impl EscapeFilter {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            at_line_start: true,
            held: Vec::new(),
            partial: Vec::new(),
        }
    }

    fn push(&mut self, input: &[u8], output: &mut Vec<u8>) -> bool {
        if !self.enabled {
            output.extend_from_slice(input);
            return false;
        }

        let joined;
        let input = if self.partial.is_empty() {
            input
        } else {
            let mut buf = std::mem::take(&mut self.partial);
            buf.extend_from_slice(input);
            joined = buf;
            &joined[..]
        };

        let mut pos = 0;
        while pos < input.len() {
            let Some((len, key)) = next_escape_key(&input[pos..]) else {
                self.partial.extend_from_slice(&input[pos..]);
                break;
            };
            if self.handle(key, &input[pos..pos + len], output) {
                return true;
            }
            pos += len;
        }
        false
    }

    fn handle(&mut self, key: EscapeKey, bytes: &[u8], output: &mut Vec<u8>) -> bool {
        if !self.held.is_empty() {
            match key {
                EscapeKey::Dot => return true,
                EscapeKey::Ignore => {
                    self.held.extend_from_slice(bytes);
                    return false;
                }
                _ => {
                    output.append(&mut self.held);
                    self.at_line_start = false;
                }
            }
        }

        match key {
            EscapeKey::Tilde if self.at_line_start => self.held.extend_from_slice(bytes),
            EscapeKey::Ignore => output.extend_from_slice(bytes),
            _ => {
                output.extend_from_slice(bytes);
                self.at_line_start = key == EscapeKey::Enter;
            }
        }
        false
    }

    fn finish(&mut self, output: &mut Vec<u8>) {
        output.append(&mut self.held);
        output.append(&mut self.partial);
    }
}

/// Splits the next key off `input`, returning its length, or `None` if it is
/// an incomplete CSI sequence. A lone ESC is returned as is rather than held,
/// since terminals write each sequence whole and the Escape key must not stall.
fn next_escape_key(input: &[u8]) -> Option<(usize, EscapeKey)> {
    match input {
        [0x1b, b'[', rest @ ..] => {
            for (i, &byte) in rest.iter().enumerate() {
                match byte {
                    0x20..=0x3f => {}
                    0x40..=0x7e => return Some((i + 3, classify_csi(&rest[..i], byte))),
                    // Malformed: pass the bytes so far through and restart at this byte.
                    _ => return Some((i + 2, EscapeKey::Other)),
                }
            }
            (input.len() > MAX_PARTIAL_CSI_LEN).then_some((input.len(), EscapeKey::Other))
        }
        [b'\r' | b'\n', ..] => Some((1, EscapeKey::Enter)),
        [b'~', ..] => Some((1, EscapeKey::Tilde)),
        [b'.', ..] => Some((1, EscapeKey::Dot)),
        _ => Some((1, EscapeKey::Other)),
    }
}

fn classify_csi(params: &[u8], final_byte: u8) -> EscapeKey {
    match (params.first(), final_byte) {
        // Focus reports, and private-prefixed reports such as SGR mouse events
        // and mode query replies.
        (None, b'I' | b'O') | (Some(b'<' | b'=' | b'>' | b'?'), _) => EscapeKey::Ignore,
        (_, b'u') => classify_kitty_key(params).unwrap_or(EscapeKey::Other),
        _ => EscapeKey::Other,
    }
}

/// Classifies a kitty keyboard protocol key event:
/// `CSI key[:shifted[:base]] [; modifiers[:event] [; text]] u`.
fn classify_kitty_key(params: &[u8]) -> Option<EscapeKey> {
    fn number(field: Option<&str>, default: u32) -> Option<u32> {
        match field {
            None | Some("") => Some(default),
            Some(field) => field.parse().ok(),
        }
    }

    let mut fields = std::str::from_utf8(params).ok()?.split(';');
    let mut keys = fields.next()?.split(':');
    let key = number(keys.next(), 0)?;
    let shifted = keys.next().and_then(|field| field.parse::<u32>().ok());
    let mut modifiers = fields.next().unwrap_or("").split(':');
    let mods = number(modifiers.next(), 1)?.saturating_sub(1)
        & !(KITTY_MOD_CAPS_LOCK | KITTY_MOD_NUM_LOCK);
    let event = number(modifiers.next(), 1)?;
    let text = fields.next();

    if event == KITTY_EVENT_RELEASE
        || (KITTY_KEY_CAPS_LOCK..=KITTY_KEY_NUM_LOCK).contains(&key)
        || (KITTY_KEY_LEFT_SHIFT..=KITTY_KEY_ISO_LEVEL5_SHIFT).contains(&key)
    {
        return Some(EscapeKey::Ignore);
    }
    if key == u32::from(b'\r') || key == KITTY_KEY_KP_ENTER {
        return Some(EscapeKey::Enter);
    }

    let ch = match text {
        Some(text) if !text.contains(':') => text.parse().ok(),
        Some(_) => None,
        None if mods & !KITTY_MOD_SHIFT != 0 => None,
        // Without the alternate keys flag only the unshifted key is reported,
        // so assume a US layout where `~` is Shift+`.
        None if mods & KITTY_MOD_SHIFT != 0 => {
            shifted.or((key == u32::from(b'`')).then_some(u32::from(b'~')))
        }
        None => Some(key),
    };
    Some(match ch {
        Some(ch) if ch == u32::from(b'~') => EscapeKey::Tilde,
        Some(ch) if ch == u32::from(b'.') => EscapeKey::Dot,
        _ => EscapeKey::Other,
    })
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

pub(crate) async fn expect_session_ready(mut recv: quinn::RecvStream) -> Result<quinn::RecvStream> {
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

    #[test]
    fn escape_filter_detects_kitty_report_all_keys() {
        // Enter, Shift down, ` with Shift, Shift up, then `.`.
        let (escaped, output) = run_escape_filter(
            true,
            &[b"hi\x1b[13u\x1b[57441;2u\x1b[96;2u\x1b[57441;1:3u\x1b[46u"],
        );
        assert!(escaped);
        assert_eq!(output, b"hi\x1b[13u\x1b[57441;2u");
    }

    #[test]
    fn escape_filter_detects_kitty_with_release_events() {
        let (escaped, _) = run_escape_filter(
            true,
            &[b"\x1b[13u\x1b[13;1:3u\x1b[96;2u\x1b[96;2:3u\x1b[46;65u"],
        );
        assert!(escaped);
    }

    #[test]
    fn escape_filter_detects_kitty_alternate_keys_and_text() {
        let (escaped, _) = run_escape_filter(true, &[b"\x1b[13u\x1b[96:126;2;126u\x1b[46;;46u"]);
        assert!(escaped);
    }

    #[test]
    fn escape_filter_carries_kitty_sequences_across_reads() {
        let (escaped, output) =
            run_escape_filter(true, &[b"\x1b[13", b"u\x1b[96", b";2u", b"\x1b[46u"]);
        assert!(escaped);
        assert_eq!(output, b"\x1b[13u");
    }

    #[test]
    fn escape_filter_passes_held_kitty_keys_through_in_order() {
        let input: &[u8] = b"\x1b[13u\x1b[96;2u\x1b[57441;1:3u\x1b[46;2u\x1b[120u";
        let (escaped, output) = run_escape_filter(true, &[input]);
        assert!(!escaped);
        assert_eq!(output, input);
    }

    #[test]
    fn escape_filter_ignores_focus_reports() {
        let (escaped, _) = run_escape_filter(true, &[b"\r\x1b[I~\x1b[O."]);
        assert!(escaped);
    }

    #[test]
    fn escape_filter_does_not_hold_lone_escape() {
        let mut filter = EscapeFilter::new(true);
        let mut output = Vec::new();
        assert!(!filter.push(b"\x1b", &mut output));
        assert_eq!(output, b"\x1b");
        assert!(!filter.push(b"[~.", &mut output));
        assert_eq!(output, b"\x1b[~.");
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
