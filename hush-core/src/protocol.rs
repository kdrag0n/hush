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
    pub mode: SessionMode,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlRequest {
    OpenSession(OpenSession),
    Resize(TermSize),
    OpenRemoteForward(RemoteForwardRequest),
    Close,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlResponse {
    Ok,
    SessionReady,
    ExitStatus(i32),
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamOpen {
    SessionPtyData,
    SessionStdIo,
    SessionStderr,
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
