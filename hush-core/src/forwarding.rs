use crate::{
    net::{copy_reader_to_stream, copy_stream_to_writer},
    protocol::{StreamOpen, TcpTarget, read_frame, write_frame},
    transport::{Connection, RecvStream, SendStream},
};
use anyhow::{Context, Result};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Clone)]
pub struct LocalForward {
    pub listen_host: String,
    pub listen_port: u16,
    pub target: TcpTarget,
}

pub async fn run_local_forward(conn: Connection, spec: LocalForward) -> Result<()> {
    let listener = TcpListener::bind((spec.listen_host.as_str(), spec.listen_port))
        .await
        .with_context(|| {
            format!(
                "bind local forward {}:{}",
                spec.listen_host, spec.listen_port
            )
        })?;
    tracing::info!(
        listen = %listener.local_addr()?,
        target = %format!("{}:{}", spec.target.host, spec.target.port),
        "local forward listening"
    );
    loop {
        let (tcp, _) = listener.accept().await?;
        let conn = conn.clone();
        let target = spec.target.clone();
        tokio::spawn(async move {
            if let Err(err) = open_local_forward_stream(conn, tcp, target).await {
                tracing::warn!(%err, "local forward connection failed");
            }
        });
    }
}

async fn open_local_forward_stream(
    conn: Connection,
    tcp: TcpStream,
    target: TcpTarget,
) -> Result<()> {
    let (mut send, recv) = conn.open_bi().await?;
    write_frame(&mut send, &StreamOpen::LocalTcpForward { target }).await?;
    bridge_tcp_streams(tcp, send, recv).await
}

pub async fn serve_local_forward_stream(
    target: TcpTarget,
    send: SendStream,
    recv: RecvStream,
) -> Result<()> {
    let tcp = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .with_context(|| format!("connect remote target {}:{}", target.host, target.port))?;
    bridge_tcp_streams(tcp, send, recv).await
}

pub async fn serve_remote_forward_stream(send: SendStream, mut recv: RecvStream) -> Result<()> {
    let header: StreamOpen = read_frame(&mut recv).await?;
    let StreamOpen::RemoteTcpForward { target } = header else {
        anyhow::bail!("unexpected remote forward stream header");
    };
    let tcp = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .with_context(|| format!("connect local target {}:{}", target.host, target.port))?;
    bridge_tcp_streams(tcp, send, recv).await
}

pub async fn run_remote_forward_listener(
    conn: Connection,
    listen_host: String,
    listen_port: u16,
    target: TcpTarget,
) -> Result<()> {
    let listener = TcpListener::bind((listen_host.as_str(), listen_port))
        .await
        .with_context(|| format!("bind remote forward {listen_host}:{listen_port}"))?;
    tracing::info!(
        listen = %listener.local_addr()?,
        target = %format!("{}:{}", target.host, target.port),
        "remote forward listening"
    );
    loop {
        let (tcp, _) = listener.accept().await?;
        let conn = conn.clone();
        let target = target.clone();
        tokio::spawn(async move {
            if let Err(err) = open_remote_forward_stream(conn, tcp, target).await {
                tracing::warn!(%err, "remote forward connection failed");
            }
        });
    }
}

async fn open_remote_forward_stream(
    conn: Connection,
    tcp: TcpStream,
    target: TcpTarget,
) -> Result<()> {
    let (mut send, recv) = conn.open_bi().await?;
    write_frame(&mut send, &StreamOpen::RemoteTcpForward { target }).await?;
    bridge_tcp_streams(tcp, send, recv).await
}

async fn bridge_tcp_streams(tcp: TcpStream, send: SendStream, recv: RecvStream) -> Result<()> {
    let (read_half, write_half) = tcp.into_split();
    let a = tokio::spawn(copy_reader_to_stream(read_half, send));
    let b = tokio::spawn(copy_stream_to_writer(recv, write_half));
    let (ra, rb) = tokio::join!(a, b);
    ra??;
    rb??;
    Ok(())
}
