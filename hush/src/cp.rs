use crate::{cli::Target, connect, expect_ok, host_trust, logging};
use anyhow::{Context, Result, anyhow, bail};
use hush_core::{
    auth, filecopy,
    priority::{StreamPriority, set_stream_priority},
    protocol::{
        FileCopyCompression, FileCopyDirection, FileCopyEntry, FileCopyPlan, FileCopyRequest,
        StreamOpen, StreamResponse, read_frame, write_frame,
    },
    tls::TransportProfile,
};
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Debug, usage::Cli)]
#[usage(
    bin = "hcp",
    version,
    unknown_flags = "error",
    args_override_self = false,
    about = "Copy files over hush",
    long_about = "Copy files over hush using a streaming tar archive over QUIC.\n\nRemote syntax is [user@]host[:port]:path. Compression is zstd level 1 by default; -C disables compression."
)]
pub(crate) struct CpArgs {
    /// Enable client logging. Without this, client logging is disabled.
    #[usage(short = 'v', long)]
    pub(crate) verbose: bool,

    /// Skip TOFU host certificate verification for this connection.
    #[usage(short = 'k', long, help_heading = "Host Trust")]
    pub(crate) insecure: bool,

    /// Connect to this remote port, overriding target and ssh_config ports.
    #[usage(short = 'p', value_name = "PORT")]
    pub(crate) port: Option<u16>,

    /// Disable compression. By default, hcp uses zstd level 1.
    #[usage(short = 'C')]
    pub(crate) no_compression: bool,

    /// Data directory for known_hosts and client state.
    #[usage(long, value_name = "DIR", help_heading = "Files")]
    pub(crate) data_dir: Option<PathBuf>,

    /// SSH identity file (Ed25519 or ECDSA). Agent use is preferred when it has this key.
    #[usage(short = 'i', value_name = "PATH", help_heading = "Authentication")]
    pub(crate) identity_file: Option<PathBuf>,

    /// Source paths followed by one destination.
    #[usage(arg, required, var_min = 2, value_name = "SRC... DEST")]
    pub(crate) paths: Vec<String>,
}

#[derive(Debug, Clone)]
struct RemotePath {
    target: Target,
    path: PathBuf,
}

#[derive(Debug, Clone)]
enum CopyPath {
    Local(PathBuf),
    Remote(RemotePath),
}

pub(crate) async fn run(args: CpArgs) -> Result<()> {
    logging::init(args.verbose);
    hush_core::os::raise_nofile_soft_limit_to_hard()?;

    let compression = if args.no_compression {
        FileCopyCompression::None
    } else {
        FileCopyCompression::Zstd
    };
    let (sources, destination) = split_sources_destination(&args.paths)?;
    let parsed_sources = sources
        .iter()
        .map(|source| parse_copy_path(source, args.port))
        .collect::<Result<Vec<_>>>()?;
    let parsed_destination = parse_copy_path(destination, args.port)?;

    let remote_sources = sources_are_remote(&parsed_sources)?;
    match (remote_sources, &parsed_destination) {
        (false, CopyPath::Remote(remote_destination)) => {
            upload(&args, compression, &parsed_sources, remote_destination).await
        }
        (true, CopyPath::Local(local_destination)) => {
            download(&args, compression, &parsed_sources, local_destination).await
        }
        (true, CopyPath::Remote(remote_destination)) => {
            relay(&args, compression, &parsed_sources, remote_destination).await
        }
        (false, CopyPath::Local(_)) => bail!("one side of the copy must be remote"),
    }
}

async fn upload(
    args: &CpArgs,
    compression: FileCopyCompression,
    sources: &[CopyPath],
    destination: &RemotePath,
) -> Result<()> {
    let entries = sources
        .iter()
        .map(|source| match source {
            CopyPath::Local(path) => filecopy::entry_for_path(path),
            CopyPath::Remote(_) => bail!("upload source must be local"),
        })
        .collect::<Result<Vec<_>>>()?;
    let connected = connect(
        &destination.target,
        args.port,
        args.data_dir.clone(),
        args.identity_file.clone(),
        host_trust(args.insecure),
        auth::Passphrase::Prompt,
        TransportProfile::Bulk,
    )
    .await?;
    let (mut send, mut recv) = connected.conn.open_bi().await?;
    set_stream_priority(&send, StreamPriority::FileCopy);
    write_frame(
        &mut send,
        &StreamOpen::FileCopy(FileCopyRequest {
            direction: FileCopyDirection::Upload,
            entries,
            destination: destination.path.to_string_lossy().into_owned(),
            compression,
        }),
    )
    .await?;

    let plan = expect_copy_ready(&mut recv).await?;
    let progress = Arc::new(Mutex::new(CopyProgress::new("upload")));
    let entry_progress = Arc::clone(&progress);
    let byte_progress = Arc::clone(&progress);
    let copy_result = filecopy::send_archive_with_progress(
        send,
        &plan.entries,
        compression,
        move |entry| entry_progress.lock().unwrap().start_entry(entry),
        move |bytes| byte_progress.lock().unwrap().add_bytes(bytes),
    )
    .await;
    let result = match copy_result {
        Ok(()) => expect_ok(&mut recv).await,
        Err(err) => Err(err),
    };
    tracing::debug!(stats = ?connected.conn.stats(), "upload finished");
    if result.is_ok() {
        progress.lock().unwrap().finish("done");
    } else {
        progress.lock().unwrap().finish("failed");
    }
    result
}

async fn download(
    args: &CpArgs,
    compression: FileCopyCompression,
    sources: &[CopyPath],
    destination: &Path,
) -> Result<()> {
    let (first_remote, entries) = remote_source_entries(sources)?;
    let plan = filecopy::plan_for_destination(destination, &entries).await?;
    let connected = connect(
        &first_remote.target,
        args.port,
        args.data_dir.clone(),
        args.identity_file.clone(),
        host_trust(args.insecure),
        auth::Passphrase::Prompt,
        TransportProfile::Bulk,
    )
    .await?;
    let (mut send, mut recv) = connected.conn.open_bi().await?;
    set_stream_priority(&send, StreamPriority::FileCopy);
    let request_entries = plan.entries.clone();
    write_frame(
        &mut send,
        &StreamOpen::FileCopy(FileCopyRequest {
            direction: FileCopyDirection::Download,
            entries: request_entries,
            destination: String::new(),
            compression,
        }),
    )
    .await?;
    send.finish()?;

    let _ = expect_copy_ready(&mut recv).await?;
    let progress = Arc::new(Mutex::new(CopyProgress::new("download")));
    progress.lock().unwrap().start_plan(&plan.entries);
    let byte_progress = Arc::clone(&progress);
    let copy_result = filecopy::receive_archive_with_progress(
        recv,
        Path::new(&plan.extract_dir),
        compression,
        move |bytes| byte_progress.lock().unwrap().add_bytes(bytes),
    )
    .await;
    tracing::debug!(stats = ?connected.conn.stats(), "download finished");
    if copy_result.is_ok() {
        progress.lock().unwrap().finish("done");
    } else {
        progress.lock().unwrap().finish("failed");
    }
    copy_result
}

/// Copy between two remotes by relaying through this client, like `scp -3`.
/// The destination plans the copy first so the source can name archive
/// entries the way the destination expects; the archive is then forwarded
/// as-is, still compressed, without being unpacked here.
async fn relay(
    args: &CpArgs,
    compression: FileCopyCompression,
    sources: &[CopyPath],
    destination: &RemotePath,
) -> Result<()> {
    let (source, entries) = remote_source_entries(sources)?;
    let destination_conn = connect(
        &destination.target,
        args.port,
        args.data_dir.clone(),
        args.identity_file.clone(),
        host_trust(args.insecure),
        auth::Passphrase::Prompt,
        TransportProfile::Bulk,
    )
    .await?;
    let source_conn = connect(
        &source.target,
        args.port,
        args.data_dir.clone(),
        args.identity_file.clone(),
        host_trust(args.insecure),
        auth::Passphrase::Prompt,
        TransportProfile::Bulk,
    )
    .await?;

    let (mut destination_send, mut destination_recv) = destination_conn.conn.open_bi().await?;
    set_stream_priority(&destination_send, StreamPriority::FileCopy);
    write_frame(
        &mut destination_send,
        &StreamOpen::FileCopy(FileCopyRequest {
            direction: FileCopyDirection::Upload,
            entries,
            destination: destination.path.to_string_lossy().into_owned(),
            compression,
        }),
    )
    .await?;
    let plan = expect_copy_ready(&mut destination_recv).await?;

    let source_result = async {
        let (mut send, mut recv) = source_conn.conn.open_bi().await?;
        set_stream_priority(&send, StreamPriority::FileCopy);
        write_frame(
            &mut send,
            &StreamOpen::FileCopy(FileCopyRequest {
                direction: FileCopyDirection::Download,
                entries: plan.entries.clone(),
                destination: String::new(),
                compression,
            }),
        )
        .await?;
        send.finish()?;
        expect_copy_ready(&mut recv).await?;
        Ok(recv)
    }
    .await;
    let source_recv = match source_result {
        Ok(recv) => recv,
        Err(err) => {
            // The destination is already waiting for an archive; abort it so
            // it does not extract an empty one.
            let _ = destination_send.reset(0u32.into());
            return Err(err);
        }
    };

    let progress = Arc::new(Mutex::new(CopyProgress::new("copy")));
    progress.lock().unwrap().start_plan(&plan.entries);
    let byte_progress = Arc::clone(&progress);
    let result = relay_archive(
        source_recv,
        destination_send,
        &mut destination_recv,
        move |bytes| byte_progress.lock().unwrap().add_bytes(bytes),
    )
    .await;
    tracing::debug!(
        source_stats = ?source_conn.conn.stats(),
        destination_stats = ?destination_conn.conn.stats(),
        "remote copy finished"
    );
    if result.is_ok() {
        progress.lock().unwrap().finish("done");
    } else {
        progress.lock().unwrap().finish("failed");
    }
    result
}

/// Forward the source's archive stream to the destination chunk by chunk and
/// wait for the destination to finish extracting it.
async fn relay_archive(
    mut source: quinn::RecvStream,
    mut destination: quinn::SendStream,
    destination_recv: &mut quinn::RecvStream,
    mut bytes_transferred: impl FnMut(u64),
) -> Result<()> {
    // Moving several chunks per call takes each connection's lock once per
    // batch rather than once per packet.
    let mut chunks: [_; 32] = Default::default();
    loop {
        let count = match source.read_chunks(&mut chunks).await {
            Ok(Some(count)) => count,
            Ok(None) => break,
            Err(err) => {
                // Reset rather than finish so the destination does not take
                // a truncated archive for a complete one.
                let _ = destination.reset(0u32.into());
                return Err(err).context("read archive from source");
            }
        };
        let bytes = chunks[..count].iter().map(|chunk| chunk.len() as u64).sum();
        if let Err(err) = destination.write_all_chunks(&mut chunks[..count]).await {
            let _ = source.stop(0u32.into());
            // The destination stops reading when extraction fails, and its
            // response says why.
            return match expect_ok(destination_recv).await {
                Err(destination_err) => Err(destination_err),
                Ok(()) => Err(err).context("write archive to destination"),
            };
        }
        bytes_transferred(bytes);
    }
    destination.finish()?;
    expect_ok(destination_recv).await
}

/// Check that every source names the same remote and build its copy entries.
fn remote_source_entries(sources: &[CopyPath]) -> Result<(&RemotePath, Vec<FileCopyEntry>)> {
    let first_remote = match &sources[0] {
        CopyPath::Remote(remote) => remote,
        CopyPath::Local(_) => bail!("copy source must be remote"),
    };
    let mut entries = Vec::with_capacity(sources.len());
    for source in sources {
        let CopyPath::Remote(remote) = source else {
            bail!("cannot mix local and remote sources");
        };
        if remote.target.host_alias != first_remote.target.host_alias
            || remote.target.user != first_remote.target.user
            || remote.target.port != first_remote.target.port
        {
            bail!("all remote sources must use the same target");
        }
        entries.push(filecopy::entry_for_path(&remote.path)?);
    }
    Ok((first_remote, entries))
}

fn split_sources_destination(paths: &[String]) -> Result<(&[String], &String)> {
    let (destination, sources) = paths.split_last().context("missing destination")?;
    if sources.is_empty() {
        bail!("missing source");
    }
    Ok((sources, destination))
}

fn parse_copy_path(input: &str, port_override: Option<u16>) -> Result<CopyPath> {
    match split_remote(input) {
        Some((target, path)) => Ok(CopyPath::Remote(RemotePath {
            target: Target::parse(target, port_override)?,
            path: PathBuf::from(path),
        })),
        None => Ok(CopyPath::Local(PathBuf::from(input))),
    }
}

pub(crate) fn split_remote(input: &str) -> Option<(&str, &str)> {
    if input.starts_with('/') || input.starts_with("./") || input.starts_with("../") {
        return None;
    }

    let bytes = input.as_bytes();
    let mut bracket_depth = 0usize;
    for (idx, byte) in bytes.iter().enumerate() {
        match *byte {
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b':' if bracket_depth == 0 => {
                if idx == 0 {
                    return None;
                }
                return Some((&input[..idx], &input[idx + 1..]));
            }
            _ => {}
        }
    }
    None
}

fn sources_are_remote(sources: &[CopyPath]) -> Result<bool> {
    let remote = matches!(sources[0], CopyPath::Remote(_));
    if !sources
        .iter()
        .all(|source| matches!(source, CopyPath::Remote(_)) == remote)
    {
        bail!("cannot mix local and remote sources");
    }
    Ok(remote)
}

async fn expect_copy_ready(recv: &mut quinn::RecvStream) -> Result<FileCopyPlan> {
    let response = read_frame::<StreamResponse>(recv).await.map_err(|err| {
        match err.downcast_ref::<io::Error>() {
            Some(io_err) if io_err.kind() == io::ErrorKind::UnexpectedEof => {
                anyhow!("server closed the copy stream without a response")
            }
            _ => err,
        }
    })?;
    match response {
        StreamResponse::FileCopyReady(plan) => Ok(plan),
        StreamResponse::Error(err) => bail!("{err}"),
        other => bail!("unexpected copy response: {other:?}"),
    }
}

#[derive(Debug)]
struct CopyProgress {
    verb: &'static str,
    current: String,
    bytes: u64,
    last_draw: Instant,
}

impl CopyProgress {
    fn new(verb: &'static str) -> Self {
        Self {
            verb,
            current: String::new(),
            bytes: 0,
            last_draw: Instant::now() - Duration::from_secs(1),
        }
    }

    fn start(&mut self, entry: &str) {
        self.current = entry.to_owned();
        self.draw(true, None);
    }

    fn start_entry(&mut self, entry: &FileCopyEntry) {
        self.start(&progress_name(entry));
    }

    fn start_plan(&mut self, entries: &[FileCopyEntry]) {
        match entries {
            [entry] => self.start_entry(entry),
            _ => self.start(&format!("{} files", entries.len())),
        }
    }

    fn add_bytes(&mut self, bytes: u64) {
        self.bytes += bytes;
        self.draw(false, None);
    }

    fn finish(&mut self, status: &str) {
        self.draw(true, Some(status));
        let _ = writeln!(io::stderr());
    }

    fn draw(&mut self, force: bool, status: Option<&str>) {
        if !force && self.last_draw.elapsed() < Duration::from_millis(50) {
            return;
        }
        self.last_draw = Instant::now();
        let status = status
            .map(|status| format!(" {status}"))
            .unwrap_or_default();
        let _ = write!(
            io::stderr(),
            "\r\x1b[2K{} {} {}{}",
            self.verb,
            self.current,
            format_bytes(self.bytes),
            status
        );
        let _ = io::stderr().flush();
    }
}

fn progress_name(entry: &FileCopyEntry) -> String {
    let source_name = Path::new(&entry.path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| entry.path.clone());
    if source_name == entry.archive_name {
        source_name
    } else {
        format!("{source_name} -> {}", entry.archive_name)
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;

    let bytes_f = bytes as f64;
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes_f < MIB {
        format!("{:.1} KiB", bytes_f / KIB)
    } else if bytes_f < GIB {
        format!("{:.1} MiB", bytes_f / MIB)
    } else {
        format!("{:.1} GiB", bytes_f / GIB)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_remote_path() {
        let (target, path) = split_remote("alice@example.test:/tmp/file").unwrap();
        assert_eq!(target, "alice@example.test");
        assert_eq!(path, "/tmp/file");
    }

    #[test]
    fn parses_bracketed_remote_path() {
        let (target, path) = split_remote("alice@[::1]:file").unwrap();
        assert_eq!(target, "alice@[::1]");
        assert_eq!(path, "file");
    }

    #[test]
    fn leaves_local_relative_path_with_prefix() {
        assert!(split_remote("./a:b").is_none());
        assert!(split_remote("../a:b").is_none());
    }

    #[test]
    fn leaves_local_absolute_path() {
        assert!(split_remote("/tmp/a:b").is_none());
    }
}
