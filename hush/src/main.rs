mod cli;
mod cp;
mod logging;
mod net;
mod os;
mod session;

use anyhow::{Result, bail};
use cli::{Cli, Target};
use hush_core::{
    auth,
    config::{self, SshForward},
    forwarding::LocalForward,
    protocol::{
        OpenSession, RemoteForwardRequest, SessionMode, StreamOpen, StreamResponse, TcpTarget,
        read_frame, write_frame,
    },
};
use quinn::Endpoint;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse_from_env()?;
    let args = match cli {
        Cli::Session(args) => args,
        Cli::Copy(args) => return cp::run(args).await,
    };
    logging::init(args.verbose);
    hush_core::os::raise_nofile_soft_limit_to_hard()?;

    let target = Target::parse(&args.target, args.port)?;
    let ssh_cfg = config::read_ssh_config(&target.host_alias)?;
    let config::SshHostConfig {
        user: config_user,
        hostname: config_hostname,
        port: config_port,
        identity_file: config_identity_file,
        local_forwards,
        remote_forwards,
    } = ssh_cfg;
    let user = target
        .user
        .or(config_user)
        .unwrap_or_else(auth::current_username);
    let host = config_hostname.unwrap_or(target.host);
    let port = target
        .port
        .or(config_port)
        .unwrap_or(hush_core::defaults::DEFAULT_PORT);
    let data_dir = args
        .data_dir
        .unwrap_or_else(hush_core::paths::default_data_dir);
    let identity_file = args.identity_file.or(config_identity_file);

    let identity = auth::load_identity_with_file(identity_file.as_deref())?;
    let mut endpoint = Endpoint::client("[::]:0".parse::<SocketAddr>()?)?;
    endpoint.set_default_client_config(hush_core::tls::make_client_config(
        &data_dir,
        hush_core::tls::host_key(&host, port),
        identity,
        args.insecure,
    )?);

    let conn = net::connect_any(&endpoint, &host, port).await?;

    for spec in local_forwards {
        spawn_local_forward(conn.clone(), spec);
    }
    for spec in args.local_forward.iter().cloned() {
        spawn_local_forward(conn.clone(), cli_forward_to_ssh_forward(spec));
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

    for spec in remote_forwards {
        request_remote_forward(&conn, spec).await?;
    }
    for spec in args.remote_forward.iter().cloned() {
        request_remote_forward(&conn, cli_forward_to_ssh_forward(spec)).await?;
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

pub(crate) async fn connect(
    target: &Target,
    port_override: Option<u16>,
    data_dir: Option<std::path::PathBuf>,
    identity_file: Option<std::path::PathBuf>,
    insecure: bool,
) -> Result<(Endpoint, quinn::Connection, String, u16, String)> {
    let ssh_cfg = config::read_ssh_config(&target.host_alias)?;
    let config::SshHostConfig {
        user: config_user,
        hostname: config_hostname,
        port: config_port,
        identity_file: config_identity_file,
        ..
    } = ssh_cfg;
    let user = target
        .user
        .clone()
        .or(config_user)
        .unwrap_or_else(auth::current_username);
    let host = config_hostname.unwrap_or_else(|| target.host.clone());
    let port = port_override
        .or(target.port)
        .or(config_port)
        .unwrap_or(hush_core::defaults::DEFAULT_PORT);
    let data_dir = data_dir.unwrap_or_else(hush_core::paths::default_data_dir);
    let identity_file = identity_file.or(config_identity_file);

    let identity = auth::load_identity_with_file(identity_file.as_deref())?;
    let mut endpoint = Endpoint::client("[::]:0".parse::<SocketAddr>()?)?;
    endpoint.set_default_client_config(hush_core::tls::make_client_config(
        &data_dir,
        hush_core::tls::host_key(&host, port),
        identity,
        insecure,
    )?);

    let conn = net::connect_any(&endpoint, &host, port).await?;
    Ok((endpoint, conn, host, port, user))
}

fn cli_forward_to_ssh_forward(value: cli::ForwardArg) -> SshForward {
    SshForward {
        listen_host: value.listen_host,
        listen_port: value.listen_port,
        target_host: value.target_host,
        target_port: value.target_port,
    }
}

fn spawn_local_forward(conn: quinn::Connection, spec: SshForward) {
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

async fn request_remote_forward(conn: &quinn::Connection, spec: SshForward) -> Result<()> {
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
    send.finish()?;
    expect_ok(&mut recv).await
}

async fn expect_ok(recv: &mut quinn::RecvStream) -> Result<()> {
    match read_frame::<StreamResponse>(recv).await? {
        StreamResponse::Ok => Ok(()),
        StreamResponse::Error(err) => bail!("{err}"),
        other => bail!("unexpected control response: {other:?}"),
    }
}
