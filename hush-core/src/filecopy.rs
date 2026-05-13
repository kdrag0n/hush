use crate::protocol::{
    FileCopyCompression, FileCopyEntry, FileCopyPlan, FileCopyRequest, StreamResponse, write_frame,
};
use anyhow::{Context, Result, bail};
use async_compression::{
    Level,
    tokio::{bufread::ZstdDecoder, write::ZstdEncoder},
};
use quinn::{RecvStream, SendStream};
use std::{
    path::Path,
    pin::Pin,
    task::{Context as TaskContext, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio_tar::{ArchiveBuilder, Builder};

pub fn entry_for_path(path: &Path) -> Result<FileCopyEntry> {
    let archive_name = path
        .file_name()
        .context("source path has no file name")?
        .to_string_lossy()
        .into_owned();
    Ok(FileCopyEntry {
        path: path.to_string_lossy().into_owned(),
        archive_name,
    })
}

pub async fn plan_for_destination(
    destination: &Path,
    entries: &[FileCopyEntry],
) -> Result<FileCopyPlan> {
    if entries.is_empty() {
        bail!("no sources to copy");
    }

    let destination_is_dir = destination_looks_like_dir(destination)
        || tokio::fs::metadata(destination)
            .await
            .map(|metadata| metadata.is_dir())
            .unwrap_or(false);

    if entries.len() == 1 && !destination_is_dir {
        let archive_name = destination
            .file_name()
            .context("destination path has no file name")?
            .to_string_lossy()
            .into_owned();
        let extract_dir = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_string_lossy()
            .into_owned();
        let mut entry = entries[0].clone();
        entry.archive_name = archive_name;
        return Ok(FileCopyPlan {
            extract_dir,
            entries: vec![entry],
        });
    }

    Ok(FileCopyPlan {
        extract_dir: destination.to_string_lossy().into_owned(),
        entries: entries.to_vec(),
    })
}

pub async fn send_archive(
    send: SendStream,
    entries: &[FileCopyEntry],
    compression: FileCopyCompression,
) -> Result<()> {
    send_archive_with_progress(send, entries, compression, |_| {}, |_| {}).await
}

pub async fn send_archive_with_progress<EntryStarted, BytesTransferred>(
    send: SendStream,
    entries: &[FileCopyEntry],
    compression: FileCopyCompression,
    mut entry_started: EntryStarted,
    bytes_transferred: BytesTransferred,
) -> Result<()>
where
    EntryStarted: FnMut(&FileCopyEntry),
    BytesTransferred: FnMut(u64) + Send + Unpin + 'static,
{
    if entries.is_empty() {
        bail!("no sources to copy");
    }

    let writer = archive_writer(send, compression);
    let writer = ProgressWriter::new(writer, bytes_transferred);
    let mut archive = Builder::new(writer);
    for entry in entries {
        entry_started(entry);
        let src = Path::new(&entry.path);
        let archive_name = Path::new(&entry.archive_name);
        let metadata = tokio::fs::symlink_metadata(src)
            .await
            .with_context(|| format!("stat source `{}`", src.display()))?;
        if metadata.is_dir() {
            archive
                .append_dir_all(archive_name, src)
                .await
                .with_context(|| format!("archive directory `{}`", src.display()))?;
        } else {
            archive
                .append_path_with_name(src, archive_name)
                .await
                .with_context(|| format!("archive path `{}`", src.display()))?;
        }
    }

    let mut writer = archive.into_inner().await.context("finish tar archive")?;
    writer.shutdown().await.context("finish copy stream")?;
    Ok(())
}

pub async fn receive_archive(
    recv: RecvStream,
    destination: &Path,
    compression: FileCopyCompression,
) -> Result<()> {
    receive_archive_with_progress(recv, destination, compression, |_| {}).await
}

pub async fn receive_archive_with_progress<BytesTransferred>(
    recv: RecvStream,
    destination: &Path,
    compression: FileCopyCompression,
    bytes_transferred: BytesTransferred,
) -> Result<()>
where
    BytesTransferred: FnMut(u64) + Unpin,
{
    let reader = archive_reader(recv, compression);
    let reader = ProgressReader::new(reader, bytes_transferred);
    let mut archive = ArchiveBuilder::new(reader).build();
    archive
        .unpack(destination)
        .await
        .with_context(|| format!("extract archive into `{}`", destination.display()))?;
    Ok(())
}

pub async fn handle_upload(
    mut send: SendStream,
    recv: RecvStream,
    request: FileCopyRequest,
) -> Result<()> {
    let plan = plan_for_destination(Path::new(&request.destination), &request.entries).await?;
    write_frame(&mut send, &StreamResponse::FileCopyReady(plan.clone())).await?;
    let result = receive_archive(recv, Path::new(&plan.extract_dir), request.compression).await;
    write_copy_result(send, result).await
}

pub async fn handle_download(mut send: SendStream, request: FileCopyRequest) -> Result<()> {
    write_frame(
        &mut send,
        &StreamResponse::FileCopyReady(FileCopyPlan {
            extract_dir: String::new(),
            entries: request.entries.clone(),
        }),
    )
    .await?;
    send_archive(send, &request.entries, request.compression).await
}

async fn write_copy_result(mut send: SendStream, result: Result<()>) -> Result<()> {
    match result {
        Ok(()) => write_frame(&mut send, &StreamResponse::Ok).await?,
        Err(err) => write_frame(&mut send, &StreamResponse::Error(err.to_string())).await?,
    }
    send.finish()?;
    Ok(())
}

fn archive_writer(
    send: SendStream,
    compression: FileCopyCompression,
) -> Pin<Box<dyn AsyncWrite + Send>> {
    match compression {
        FileCopyCompression::None => Box::pin(send),
        FileCopyCompression::Zstd => Box::pin(ZstdEncoder::with_quality(send, Level::Precise(1))),
    }
}

fn archive_reader(
    recv: RecvStream,
    compression: FileCopyCompression,
) -> Pin<Box<dyn AsyncRead + Send>> {
    match compression {
        FileCopyCompression::None => Box::pin(recv),
        FileCopyCompression::Zstd => Box::pin(ZstdDecoder::new(BufReader::new(recv))),
    }
}

struct ProgressWriter<W, F> {
    inner: W,
    bytes_transferred: F,
}

impl<W, F> ProgressWriter<W, F> {
    fn new(inner: W, bytes_transferred: F) -> Self {
        Self {
            inner,
            bytes_transferred,
        }
    }
}

impl<W, F> AsyncWrite for ProgressWriter<W, F>
where
    W: AsyncWrite + Unpin,
    F: FnMut(u64) + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let written = std::task::ready!(Pin::new(&mut self.inner).poll_write(cx, buf))?;
        if written > 0 {
            (self.bytes_transferred)(written as u64);
        }
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct ProgressReader<R, F> {
    inner: R,
    bytes_transferred: F,
}

impl<R, F> ProgressReader<R, F> {
    fn new(inner: R, bytes_transferred: F) -> Self {
        Self {
            inner,
            bytes_transferred,
        }
    }
}

impl<R, F> AsyncRead for ProgressReader<R, F>
where
    R: AsyncRead + Unpin,
    F: FnMut(u64) + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        std::task::ready!(Pin::new(&mut self.inner).poll_read(cx, buf))?;
        let read = buf.filled().len() - before;
        if read > 0 {
            (self.bytes_transferred)(read as u64);
        }
        Poll::Ready(Ok(()))
    }
}

fn destination_looks_like_dir(path: &Path) -> bool {
    path.as_os_str()
        .to_string_lossy()
        .ends_with(std::path::MAIN_SEPARATOR)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn plans_single_file_rename() {
        let entries = vec![FileCopyEntry {
            path: "src.txt".to_owned(),
            archive_name: "src.txt".to_owned(),
        }];
        let plan = plan_for_destination(Path::new("dest.txt"), &entries)
            .await
            .unwrap();
        assert_eq!(plan.extract_dir, ".");
        assert_eq!(plan.entries[0].archive_name, "dest.txt");
    }

    #[tokio::test]
    async fn plans_directory_destination() {
        let entries = vec![FileCopyEntry {
            path: "src.txt".to_owned(),
            archive_name: "src.txt".to_owned(),
        }];
        let plan = plan_for_destination(Path::new("dest/"), &entries)
            .await
            .unwrap();
        assert_eq!(plan.extract_dir, "dest/");
        assert_eq!(plan.entries[0].archive_name, "src.txt");
    }
}
