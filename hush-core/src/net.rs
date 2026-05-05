use crate::transport::{RecvStream, SendStream};
use anyhow::{Context, Result};
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};

pub async fn copy_reader_to_stream<R>(mut reader: R, mut send: SendStream) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    io::copy(&mut reader, &mut send).await?;
    send.finish().await?;
    Ok(())
}

pub async fn copy_stream_to_writer<W>(mut recv: RecvStream, mut writer: W) -> Result<()>
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
    let a = tokio::spawn(copy_reader_to_stream(reader, send));
    let b = tokio::spawn(copy_stream_to_writer(recv, writer));
    let (ra, rb) = tokio::join!(a, b);
    ra.context("reader-to-stream task")??;
    rb.context("stream-to-writer task")??;
    Ok(())
}
