use anyhow::{Context, Result, bail};
use quinn::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const MAX_FRAME_LEN: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TermSize {
    pub rows: u16,
    pub cols: u16,
    pub width_px: u16,
    pub height_px: u16,
}

impl Default for TermSize {
    fn default() -> Self {
        Self {
            rows: 24,
            cols: 80,
            width_px: 0,
            height_px: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionMode {
    Pty { term: String, size: TermSize },
    Pipes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenSession {
    pub user: String,
    pub command: Vec<String>,
    pub use_shell: bool,
    pub mode: SessionMode,
    pub env: Vec<EnvVar>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvVar {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpTarget {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteForwardRequest {
    pub listen_host: String,
    pub listen_port: u16,
    pub target: TcpTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteSignal {
    SIGABRT,
    SIGALRM,
    SIGFPE,
    SIGHUP,
    SIGILL,
    SIGINT,
    SIGKILL,
    SIGPIPE,
    SIGQUIT,
    SIGSEGV,
    SIGTERM,
    SIGUSR1,
    SIGUSR2,
}

impl RemoteSignal {
    pub fn as_raw(self) -> i32 {
        crate::os::remote_signal_as_raw(self)
    }

    pub fn from_raw(signal: i32) -> Option<Self> {
        crate::os::remote_signal_from_raw(signal)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamResponse {
    Ok,
    SessionReady,
    Error(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ProcessExit {
    Code(i32),
    Signal(RemoteSignal),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamOpen {
    Session { request: OpenSession },
    SessionStderr,
    SessionExitStatus(ProcessExit),
    SessionError(String),
    Resize(TermSize),
    Signal(RemoteSignal),
    OpenRemoteForward(RemoteForwardRequest),
    LocalTcpForward { target: TcpTarget },
    RemoteTcpForward { target: TcpTarget },
}

pub async fn write_frame<T: Serialize>(send: &mut SendStream, value: &T) -> Result<()> {
    let bytes = postcard::to_allocvec(value).context("serialize frame")?;
    if bytes.len() > MAX_FRAME_LEN {
        bail!("frame too large: {} bytes", bytes.len());
    }
    send.write_u32(bytes.len() as u32).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

pub async fn read_frame<T: for<'de> Deserialize<'de>>(recv: &mut RecvStream) -> Result<T> {
    let len = recv.read_u32().await? as usize;
    if len > MAX_FRAME_LEN {
        bail!("frame too large: {len} bytes");
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    postcard::from_bytes(&buf).context("deserialize frame")
}
