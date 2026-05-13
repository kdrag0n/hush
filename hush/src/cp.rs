use crate::{cli::Target, connect, expect_ok, logging};
use anyhow::{Context, Result, bail};
use clap::Parser;
use hush_core::{
    filecopy,
    protocol::{
        FileCopyCompression, FileCopyDirection, FileCopyEntry, FileCopyPlan, FileCopyRequest,
        StreamOpen, StreamResponse, read_frame, write_frame,
    },
};
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Debug, Parser)]
#[command(
    name = "hcp",
    version,
    about = "Copy files over hush",
    long_about = "Copy files over hush using a streaming tar archive over QUIC.\n\nRemote syntax is [user@]host[:port]:path. Compression is zstd level 1 by default; -C disables compression."
)]
pub(crate) struct CpArgs {
    /// Enable client logging. Without this, client logging is disabled.
    #[arg(short = 'v', long)]
    pub(crate) verbose: bool,

    /// Skip TOFU host certificate verification for this connection.
    #[arg(short = 'k', long, help_heading = "Host Trust")]
    pub(crate) insecure: bool,

    /// Connect to this remote port, overriding target and ssh_config ports.
    #[arg(short = 'p', value_name = "PORT")]
    pub(crate) port: Option<u16>,

    /// Disable compression. By default, hcp uses zstd level 1.
    #[arg(short = 'C')]
    pub(crate) no_compression: bool,

    /// Data directory for known_hosts and client state.
    #[arg(long, value_name = "DIR", help_heading = "Files")]
    pub(crate) data_dir: Option<PathBuf>,

    /// SSH Ed25519 identity file. Agent use is preferred when it has this key.
    #[arg(short = 'i', value_name = "PATH", help_heading = "Authentication")]
    pub(crate) identity_file: Option<PathBuf>,

    /// Source paths followed by one destination.
    #[arg(value_name = "SRC... DEST", required = true, num_args = 2..)]
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
        (true, CopyPath::Remote(_)) => bail!("remote-to-remote copies are not supported yet"),
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
    let (_endpoint, conn, _, _, user) = connect(
        &destination.target,
        args.port,
        args.data_dir.clone(),
        args.identity_file.clone(),
        args.insecure,
    )
    .await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    write_frame(
        &mut send,
        &StreamOpen::FileCopy(FileCopyRequest {
            direction: FileCopyDirection::Upload,
            user,
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
    let first_remote = match &sources[0] {
        CopyPath::Remote(remote) => remote,
        CopyPath::Local(_) => bail!("download source must be remote"),
    };
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
    }

    let entries = sources
        .iter()
        .map(|source| match source {
            CopyPath::Remote(remote) => filecopy::entry_for_path(&remote.path),
            CopyPath::Local(_) => bail!("download source must be remote"),
        })
        .collect::<Result<Vec<_>>>()?;
    let plan = filecopy::plan_for_destination(destination, &entries).await?;
    let (_endpoint, conn, _, _, user) = connect(
        &first_remote.target,
        args.port,
        args.data_dir.clone(),
        args.identity_file.clone(),
        args.insecure,
    )
    .await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    let request_entries = plan.entries.clone();
    write_frame(
        &mut send,
        &StreamOpen::FileCopy(FileCopyRequest {
            direction: FileCopyDirection::Download,
            user,
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
    if copy_result.is_ok() {
        progress.lock().unwrap().finish("done");
    } else {
        progress.lock().unwrap().finish("failed");
    }
    copy_result
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

fn split_remote(input: &str) -> Option<(&str, &str)> {
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
    match read_frame::<StreamResponse>(recv).await? {
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
