use anyhow::{Context, Result};
use quinn::{RecvStream, SendStream};
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};

pub async fn copy_reader_to_quic<R>(mut reader: R, mut send: SendStream) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    io::copy(&mut reader, &mut send).await?;
    send.finish()?;
    let _ = send.stopped().await;
    Ok(())
}

pub async fn copy_quic_to_writer<W>(mut recv: RecvStream, mut writer: W) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    io::copy(&mut recv, &mut writer).await?;
    writer.shutdown().await.ok();
    Ok(())
}

pub async fn join_io_pair<R, W>(
    reader: R,
    writer: W,
    send: SendStream,
    recv: RecvStream,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let a = tokio::spawn(copy_reader_to_quic(reader, send));
    let b = tokio::spawn(copy_quic_to_writer(recv, writer));
    let (ra, rb) = tokio::join!(a, b);
    ra.context("reader-to-quic task")??;
    rb.context("quic-to-writer task")??;
    Ok(())
}
