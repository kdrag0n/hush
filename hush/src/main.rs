mod cli;
mod logging;
mod net;
mod os;
mod session;

use anyhow::{Result, bail};
use clap::Parser;
use cli::{Args, Target};
use hush_core::{
    auth, config,
    forwarding::LocalForward,
    protocol::{
        OpenSession, RemoteForwardRequest, SessionMode, StreamOpen, StreamResponse, TcpTarget,
        read_frame, write_frame,
    },
    transport::RecvStream,
};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    logging::init(args.verbose);
    hush_core::resource::raise_nofile_soft_limit_to_hard()?;

    let target = Target::parse(&args.target, args.port)?;
    let ssh_cfg = config::read_ssh_config(&target.host_alias)?;
    let user = target
        .user
        .or(ssh_cfg.user)
        .unwrap_or_else(auth::current_username);
    let host = ssh_cfg.hostname.unwrap_or(target.host);
    let port = target.port.or(ssh_cfg.port).unwrap_or(4433);
    let data_dir = args
        .data_dir
        .unwrap_or_else(hush_core::paths::default_data_dir);
    let identity_file = args.identity_file.or(ssh_cfg.identity_file);

    let identity = auth::load_identity_with_file(identity_file.as_deref())?;
    let conn = net::connect_any(&host, port, &data_dir, identity, args.insecure).await?;

    for spec in args.local_forward.iter().cloned() {
        let conn = conn.clone();
        tokio::spawn(async move {
            let local = LocalForward {
                listen_host: spec.listen_host,
                listen_port: spec.listen_port,
                target: TcpTarget {
                    host: spec.target_host,
                    port: spec.target_port,
                },
            };
            if let Err(err) = hush_core::forwarding::run_local_forward(conn, local).await {
                tracing::warn!(%err, "local forwarding stopped");
            }
        });
    }

    let conn_for_remote = conn.clone();
    tokio::spawn(async move {
        while let Ok((send, recv)) = conn_for_remote.accept_bi().await {
            tokio::spawn(async move {
                if let Err(err) =
                    hush_core::forwarding::serve_remote_forward_stream(send, recv).await
                {
                    tracing::warn!(%err, "remote forwarding stream failed");
                }
            });
        }
    });

    for spec in args.remote_forward.iter().cloned() {
        let (mut send, mut recv) = conn.open_bi().await?;
        write_frame(
            &mut send,
            &StreamOpen::OpenRemoteForward(RemoteForwardRequest {
                listen_host: spec.listen_host,
                listen_port: spec.listen_port,
                target: TcpTarget {
                    host: spec.target_host,
                    port: spec.target_port,
                },
            }),
        )
        .await?;
        send.finish().await?;
        expect_ok(&mut recv).await?;
    }

    let mode = session::choose_mode(args.tty, args.no_tty);
    let env = session::session_env(&mode);
    let session = OpenSession {
        user,
        command: args.command,
        use_shell: !args.no_shell,
        mode,
        env,
    };
    match session.mode {
        SessionMode::Pty { .. } => session::run_pty(conn, session).await,
        SessionMode::Pipes => session::run_pipes(conn, session).await,
    }
}

async fn expect_ok(recv: &mut RecvStream) -> Result<()> {
    match read_frame::<StreamResponse>(recv).await? {
        StreamResponse::Ok => Ok(()),
        StreamResponse::Error(err) => bail!("{err}"),
        other => bail!("unexpected control response: {other:?}"),
    }
}
