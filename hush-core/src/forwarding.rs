use crate::{
    net::{copy_quic_to_writer, copy_reader_to_quic},
    priority::{StreamPriority, set_stream_priority},
    protocol::{StreamOpen, TcpTarget, write_frame},
};
use anyhow::{Context, Result};
use quinn::{Connection, RecvStream, SendStream};
use std::sync::Arc;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};

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
    set_stream_priority(&send, StreamPriority::Forward);
    write_frame(&mut send, &StreamOpen::LocalTcpForward { target }).await?;
    bridge_tcp_quic(tcp, send, recv).await
}

pub(crate) async fn serve_local_forward_stream(
    target: TcpTarget,
    send: SendStream,
    recv: RecvStream,
) -> Result<()> {
    set_stream_priority(&send, StreamPriority::Forward);
    let tcp = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .with_context(|| format!("connect remote target {}:{}", target.host, target.port))?;
    bridge_tcp_quic(tcp, send, recv).await
}

pub async fn serve_remote_forward_stream(
    target: TcpTarget,
    send: SendStream,
    recv: RecvStream,
) -> Result<()> {
    set_stream_priority(&send, StreamPriority::Forward);
    let tcp = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .with_context(|| format!("connect local target {}:{}", target.host, target.port))?;
    bridge_tcp_quic(tcp, send, recv).await
}

pub(crate) async fn run_remote_forward_listener(
    conn: Connection,
    listener: TcpListener,
    forward_id: u64,
    stream_limit: Arc<Semaphore>,
) -> Result<()> {
    tracing::info!(
        listen = %listener.local_addr()?,
        "remote forward listening"
    );
    loop {
        let permit = tokio::select! {
            _ = conn.closed() => return Ok(()),
            permit = stream_limit.clone().acquire_owned() => permit?,
        };
        let (tcp, _) = tokio::select! {
            _ = conn.closed() => return Ok(()),
            accepted = listener.accept() => accepted?,
        };
        let conn = conn.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(err) = open_remote_forward_stream(conn, tcp, forward_id).await {
                tracing::warn!(%err, "remote forward connection failed");
            }
        });
    }
}

async fn open_remote_forward_stream(
    conn: Connection,
    tcp: TcpStream,
    forward_id: u64,
) -> Result<()> {
    let (mut send, recv) = conn.open_bi().await?;
    set_stream_priority(&send, StreamPriority::Forward);
    write_frame(&mut send, &StreamOpen::RemoteTcpForward { forward_id }).await?;
    bridge_tcp_quic(tcp, send, recv).await
}

async fn bridge_tcp_quic(tcp: TcpStream, send: SendStream, recv: RecvStream) -> Result<()> {
    let (read_half, write_half) = tcp.into_split();
    let a = tokio::spawn(copy_reader_to_quic(read_half, send));
    let b = tokio::spawn(copy_quic_to_writer(recv, write_half));
    let (ra, rb) = tokio::join!(a, b);
    ra??;
    rb??;
    Ok(())
}
