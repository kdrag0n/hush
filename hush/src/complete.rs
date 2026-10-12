//! Shell completion: the scripts `hush --completions` prints, and the hidden
//! `__complete-remote` helper they call to list remote paths for `hush cp`.

use crate::{
    cli::Target,
    connect, cp, host_trust,
    session::{expect_session_ready, session_env},
};
use anyhow::{Result, bail};
use hush_core::{
    auth,
    priority::{StreamPriority, set_stream_priority},
    protocol::{OpenSession, SessionMode, StreamOpen, write_frame},
    tls::{HostTrust, TransportProfile},
};
use std::{io::Write, path::PathBuf, time::Duration};

pub(crate) const COMPLETE_REMOTE: &str = "__complete-remote";

pub(crate) const ZSH: &str = include_str!("../completions/_hush");
pub(crate) const BASH: &str = include_str!("../completions/hush.bash");

/// A Tab that waits on an unreachable host should give up long before the
/// user does.
const LIST_TIMEOUT: Duration = Duration::from_secs(5);
const CLOSE_TIMEOUT: Duration = Duration::from_millis(500);
/// More than a shell can usefully offer; the rest of a huge directory is cut.
const LIST_MAX_BYTES: usize = 1 << 20;

/// Lists the entries of the remote directory named by everything up to the
/// last `/` of the path, keeping those that start with what follows it.
/// Directories get a trailing `/`. Paths resolve the way `hush cp` resolves
/// them: relative to the remote home, which `~/` also names.
///
/// Runs `/bin/sh` directly rather than the user's shell, so the listing works
/// whatever that shell is and nothing from its startup files reaches stdout.
/// Uses only builtins, since the server's `PATH` is unknown, and no `'` or
/// `\`, since a root server hands this to `su -c` through the user's shell.
const LIST_SCRIPT: &str = r#"exec 2>/dev/null
cd || cd /
p=$1
case $p in "~/"*) p=${p#"~/"} ;; esac
for f in "$p"*; do
  n=${f##*/}
  case $n in .|..) continue ;; esac
  [ -e "$f" ] || [ -L "$f" ] || continue
  [ -d "$f" ] && n=$n/
  printf "%s
" "$n"
done
"#;

#[derive(Debug, usage::Cli)]
#[usage(
    bin = "hush __complete-remote",
    unknown_flags = "error",
    args_override_self = false,
    about = "List remote path completions for shell completion scripts"
)]
pub(crate) struct RemoteArgs {
    #[usage(short = 'k', long)]
    insecure: bool,

    #[usage(short = 'p', value_name = "PORT")]
    port: Option<u16>,

    #[usage(long, value_name = "DIR")]
    data_dir: Option<PathBuf>,

    #[usage(short = 'i', value_name = "PATH")]
    identity_file: Option<PathBuf>,

    /// The word being completed, as [user@]host:path.
    #[usage(value_name = "[USER@]HOST:PATH")]
    word: String,
}

/// Never fails loudly: whatever goes wrong, the shell just gets no remote
/// candidates, the same as for an empty directory.
pub(crate) async fn run_remote(args: RemoteArgs) -> Result<()> {
    crate::logging::init(false);
    let listing = match tokio::time::timeout(LIST_TIMEOUT, list_remote(&args)).await {
        Ok(Ok(listing)) => listing,
        _ => std::process::exit(1),
    };
    std::io::stdout().write_all(&listing)?;
    Ok(())
}

async fn list_remote(args: &RemoteArgs) -> Result<Vec<u8>> {
    let Some((target, path)) = cp::split_remote(&args.word) else {
        bail!("not a remote path");
    };
    let target = Target::parse(target, args.port)?;
    // Completion must not pin a host as a side effect, nor block on a
    // passphrase prompt while the shell owns the terminal.
    let trust = match host_trust(args.insecure) {
        HostTrust::Tofu => HostTrust::KnownOnly,
        trust => trust,
    };
    let connected = connect(
        &target,
        args.port,
        args.data_dir.clone(),
        args.identity_file.clone(),
        trust,
        auth::Passphrase::Refuse,
        TransportProfile::Interactive,
    )
    .await?;
    let conn = &connected.conn;

    let mode = SessionMode::Pipes;
    let session = OpenSession {
        command: ["/bin/sh", "-c", LIST_SCRIPT, "sh", path]
            .map(str::to_owned)
            .into(),
        use_shell: false,
        env: session_env(&mode),
        mode,
        set_env: Vec::new(),
        forward_agent: false,
    };
    let (mut send, recv) = conn.open_bi().await?;
    set_stream_priority(&send, StreamPriority::Shell);
    write_frame(&mut send, &StreamOpen::Session { request: session }).await?;
    send.finish()?;
    let mut recv = expect_session_ready(recv).await?;

    let mut listing = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    while let Some(n) = recv.read(&mut buf).await? {
        listing.extend_from_slice(&buf[..n]);
        if listing.len() >= LIST_MAX_BYTES {
            let end = listing
                .iter()
                .rposition(|&b| b == b'\n')
                .map_or(0, |i| i + 1);
            listing.truncate(end);
            break;
        }
    }
    // Make sure the close reaches the server, which would otherwise hold the
    // connection open until its idle timeout.
    conn.close(0u32.into(), b"");
    let _ = tokio::time::timeout(CLOSE_TIMEOUT, connected.endpoint.wait_idle()).await;
    Ok(listing)
}
