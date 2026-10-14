mod cli;
mod complete;
mod cp;
mod logging;
mod net;
mod os;
mod roam;
mod session;

use anyhow::{Result, bail};
use cli::{Cli, Target};
use hush_core::tls::{HostTrust, TransportProfile};
use hush_core::{
    auth,
    config::{self, SshForward},
    forwarding::LocalForward,
    priority::{StreamPriority, set_stream_priority},
    protocol::{
        OpenSession, RemoteForwardRequest, SessionMode, StreamOpen, StreamResponse, TcpTarget,
        read_frame, write_frame,
    },
};
use quinn::Endpoint;
use std::{collections::HashMap, sync::Arc};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse_from_env()?;
    let args = match cli {
        Cli::Session(args) => args,
        Cli::Copy(args) => return cp::run(args).await,
        Cli::Completions(script) => {
            print!("{script}");
            return Ok(());
        }
        Cli::CompleteRemote(args) => return complete::run_remote(args).await,
    };
    logging::init(args.verbose);
    hush_core::os::raise_nofile_soft_limit_to_hard()?;

    let target = Target::parse(&args.target, args.port)?;
    let ClientConnection {
        endpoint: _endpoint,
        conn,
        ssh_cfg,
    } = connect(
        &target,
        None,
        args.data_dir,
        args.identity_file,
        host_trust(args.insecure),
        auth::Passphrase::Prompt,
        TransportProfile::Interactive,
    )
    .await?;
    let config::SshHostConfig {
        forward_agent: config_forward_agent,
        set_env,
        local_forwards,
        remote_forwards,
        ..
    } = ssh_cfg;
    let agent_forward = agent_forward_context(&conn, args.forward_agent, config_forward_agent);
    let remote_forwards = remote_forwards
        .into_iter()
        .chain(
            args.remote_forward
                .iter()
                .cloned()
                .map(cli_forward_to_ssh_forward),
        )
        .enumerate()
        .map(|(index, spec)| ((index as u64) + 1, spec))
        .collect::<Vec<_>>();
    let remote_targets = Arc::new(
        remote_forwards
            .iter()
            .map(|(forward_id, spec)| {
                (
                    *forward_id,
                    TcpTarget {
                        host: spec.target_host.clone(),
                        port: spec.target_port,
                    },
                )
            })
            .collect::<HashMap<_, _>>(),
    );

    for spec in local_forwards {
        spawn_local_forward(conn.clone(), spec);
    }
    for spec in args.local_forward.iter().cloned() {
        spawn_local_forward(conn.clone(), cli_forward_to_ssh_forward(spec));
    }

    let conn_for_remote = conn.clone();
    let agent_forward_streams = agent_forward.clone();
    let remote_forward_targets = remote_targets.clone();
    tokio::spawn(async move {
        while let Ok((send, recv)) = conn_for_remote.accept_bi().await {
            let agent_forward = agent_forward_streams.clone();
            let remote_targets = remote_forward_targets.clone();
            tokio::spawn(async move {
                if let Err(err) =
                    serve_server_stream(send, recv, agent_forward, remote_targets).await
                {
                    tracing::warn!(%err, "server-initiated stream failed");
                }
            });
        }
    });

    for (forward_id, spec) in remote_forwards {
        request_remote_forward(&conn, forward_id, spec).await?;
    }

    let set_env_term = set_env
        .iter()
        .find(|var| var.key == "TERM")
        .map(|var| var.value.as_str());
    let mode = session::choose_mode(args.tty, args.no_tty, set_env_term);
    let env = session::session_env(&mode);
    let session = OpenSession {
        command: args.command,
        use_shell: !args.no_shell,
        mode,
        env,
        set_env,
        forward_agent: agent_forward.is_some(),
    };
    match session.mode {
        SessionMode::Pty { .. } => session::run_pty(conn, session).await,
        SessionMode::Pipes => session::run_pipes(conn, session).await,
    }
}

/// An established, authenticated connection. `endpoint` must be kept alive for
/// as long as `conn` is used.
pub(crate) struct ClientConnection {
    pub(crate) endpoint: Endpoint,
    pub(crate) conn: quinn::Connection,
    pub(crate) ssh_cfg: config::SshHostConfig,
}

/// Resolve the target against ssh_config and connect. The username rides in
/// the client certificate, so the connection is authenticated as part of the
/// TLS handshake itself — the server serves nothing otherwise.
pub(crate) async fn connect(
    target: &Target,
    port_override: Option<u16>,
    data_dir: Option<std::path::PathBuf>,
    identity_file: Option<std::path::PathBuf>,
    trust: HostTrust,
    passphrase: auth::Passphrase,
    profile: TransportProfile,
) -> Result<ClientConnection> {
    let ssh_cfg = config::read_ssh_config(&target.host_alias)?;
    let user = target
        .user
        .clone()
        .or_else(|| ssh_cfg.user.clone())
        .unwrap_or_else(auth::current_username);
    let host = ssh_cfg
        .hostname
        .clone()
        .unwrap_or_else(|| target.host.clone());
    let port = port_override
        .or(target.port)
        .or(ssh_cfg.port)
        .unwrap_or(hush_core::defaults::DEFAULT_PORT);
    let data_dir = data_dir.unwrap_or_else(hush_core::paths::default_data_dir);
    let identity_file = identity_file.or_else(|| ssh_cfg.identity_file.clone());
    let agent = agent_socket(ssh_cfg.identity_agent.clone());

    let identity = auth::load_identity_with_options(identity_file.as_deref(), &agent, passphrase)?;
    let client_config = hush_core::tls::make_client_config(
        &data_dir,
        hush_core::tls::host_key(&host, port),
        identity,
        &user,
        trust,
        profile,
    )?;
    let (endpoint, conn) = net::connect_any(client_config, &host, port).await?;
    Ok(ClientConnection {
        endpoint,
        conn,
        ssh_cfg,
    })
}

pub(crate) fn host_trust(insecure: bool) -> HostTrust {
    if insecure {
        HostTrust::Insecure
    } else {
        HostTrust::Tofu
    }
}

/// What the client needs to serve forwarded agent connections: the local agent
/// socket, plus the host key and session identifier used to bind each
/// connection to this session with `session-bind@openssh.com`.
struct AgentForwardContext {
    socket: std::path::PathBuf,
    host_key: Option<Vec<u8>>,
    session_id: Option<[u8; hush_core::agent::SESSION_ID_LEN]>,
}

impl AgentForwardContext {
    fn bind(&self, signature: Vec<u8>) -> Option<hush_core::agent::SessionBind> {
        if signature.is_empty() {
            return None;
        }
        Some(hush_core::agent::SessionBind {
            host_key: self.host_key.clone()?,
            session_id: self.session_id?.to_vec(),
            signature,
        })
    }
}

fn agent_forward_context(
    conn: &quinn::Connection,
    cli_forward_agent: bool,
    config_forward_agent: Option<config::ForwardAgent>,
) -> Option<std::sync::Arc<AgentForwardContext>> {
    let enabled = cli_forward_agent
        || matches!(
            config_forward_agent,
            Some(config::ForwardAgent::Yes | config::ForwardAgent::Socket(_))
        );
    if !enabled {
        return None;
    }
    let socket_override = match config_forward_agent {
        Some(config::ForwardAgent::Socket(path)) => Some(path),
        _ => None,
    };
    let Some(socket) =
        socket_override.or_else(|| std::env::var_os("SSH_AUTH_SOCK").map(std::path::PathBuf::from))
    else {
        eprintln!("hush: agent forwarding requested but no ssh-agent socket is available");
        return None;
    };
    let host_key = match hush_core::agent::peer_host_key_blob(conn) {
        Ok(blob) => Some(blob),
        Err(err) => {
            tracing::debug!(%err, "agent session binding disabled: no usable host key");
            None
        }
    };
    let session_id = hush_core::agent::session_bind_id(conn).ok();
    Some(std::sync::Arc::new(AgentForwardContext {
        socket,
        host_key,
        session_id,
    }))
}

async fn serve_server_stream(
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    agent: Option<std::sync::Arc<AgentForwardContext>>,
    remote_targets: Arc<HashMap<u64, TcpTarget>>,
) -> Result<()> {
    match read_frame::<StreamOpen>(&mut recv).await? {
        StreamOpen::RemoteTcpForward { forward_id } => {
            let target = remote_targets
                .get(&forward_id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("server opened an unknown remote forward"))?;
            hush_core::forwarding::serve_remote_forward_stream(target, send, recv).await
        }
        StreamOpen::AgentForward { bind_signature } => {
            let Some(agent) = agent else {
                bail!("server opened an agent stream but agent forwarding is not enabled");
            };
            hush_core::agent::serve_agent_forward_stream(
                send,
                recv,
                &agent.socket,
                agent.bind(bind_signature).as_ref(),
            )
            .await
        }
        other => bail!("unexpected server-initiated stream header: {other:?}"),
    }
}

fn agent_socket(setting: Option<config::IdentityAgent>) -> auth::AgentSocket {
    match setting {
        None => auth::AgentSocket::Default,
        Some(config::IdentityAgent::Disabled) => auth::AgentSocket::Disabled,
        Some(config::IdentityAgent::Socket(path)) => auth::AgentSocket::Socket(path),
    }
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

async fn request_remote_forward(
    conn: &quinn::Connection,
    forward_id: u64,
    spec: SshForward,
) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await?;
    set_stream_priority(&send, StreamPriority::Forward);
    write_frame(
        &mut send,
        &StreamOpen::OpenRemoteForward(RemoteForwardRequest {
            forward_id,
            listen_host: spec.listen_host,
            listen_port: spec.listen_port,
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
