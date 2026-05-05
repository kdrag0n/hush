use crate::cli::Args;
use anyhow::Result;
use hush_core::{
    config::{self, ServerRuntimeConfig},
    protocol::{StreamOpen, StreamResponse, read_frame, write_frame},
    transport::{Connection, Listener},
};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::Semaphore;

pub(crate) async fn run(args: Args) -> Result<()> {
    let initial_data_dir = args
        .data_dir
        .clone()
        .unwrap_or_else(hush_core::paths::default_data_dir);
    let config_path = args
        .config
        .clone()
        .unwrap_or_else(|| hush_core::paths::server_config_path(&initial_data_dir));
    let file_cfg = config::read_server_config(&config_path)?.unwrap_or_else(empty_file_config);
    let data_dir = args
        .data_dir
        .or(file_cfg.data_dir)
        .unwrap_or(initial_data_dir);
    let listen = if args.listen.to_string() != "0.0.0.0:4433" {
        args.listen
    } else {
        file_cfg.listen.unwrap_or(args.listen)
    };
    let runtime_config = ServerRuntimeConfig {
        authorized_keys_path: args.authorized_keys.or(file_cfg.authorized_keys_path),
        allow_users: if args.allow_user.is_empty() {
            file_cfg.allow_users.unwrap_or_default()
        } else {
            args.allow_user
        },
        allow_tcp_forwarding: if args.disable_tcp_forwarding {
            false
        } else {
            file_cfg.allow_tcp_forwarding.unwrap_or(true)
        },
        max_connections: args
            .max_connections
            .or(file_cfg.max_connections)
            .unwrap_or(config::DEFAULT_MAX_CONNECTIONS),
        max_sessions_per_connection: args
            .max_sessions_per_connection
            .or(file_cfg.max_sessions_per_connection)
            .unwrap_or(config::DEFAULT_MAX_SESSIONS_PER_CONNECTION),
        max_forwards_per_connection: args
            .max_forwards_per_connection
            .or(file_cfg.max_forwards_per_connection)
            .unwrap_or(config::DEFAULT_MAX_FORWARDS_PER_CONNECTION),
        max_forward_streams_per_connection: args
            .max_forward_streams_per_connection
            .or(file_cfg.max_forward_streams_per_connection)
            .unwrap_or(config::DEFAULT_MAX_FORWARD_STREAMS_PER_CONNECTION),
    };

    let connection_slots = Arc::new(Semaphore::new(runtime_config.max_connections));
    let listener = Listener::bind(listen, data_dir).await?;
    log_listening(listener.local_addr(), &runtime_config);
    accept_loop(listener, runtime_config, connection_slots).await
}

fn log_listening(local_addr: SocketAddr, runtime_config: &ServerRuntimeConfig) {
    tracing::info!(
        addr = %local_addr,
        max_connections = runtime_config.max_connections,
        max_sessions_per_connection = runtime_config.max_sessions_per_connection,
        max_forwards_per_connection = runtime_config.max_forwards_per_connection,
        max_forward_streams_per_connection = runtime_config.max_forward_streams_per_connection,
        "hush server listening"
    );
}

async fn accept_loop(
    mut listener: Listener,
    runtime_config: ServerRuntimeConfig,
    connection_slots: Arc<Semaphore>,
) -> Result<()> {
    let local_addr = listener.local_addr();
    loop {
        let permit = match connection_slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::warn!("rejecting connection because max_connections is reached");
                let conn = listener.accept().await?;
                conn.close();
                continue;
            }
        };
        let conn = listener.accept().await?;
        let runtime_config = runtime_config.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(err) = handle_connection(conn, runtime_config, local_addr).await {
                tracing::warn!(%err, "connection failed");
            }
        });
    }
}

fn empty_file_config() -> config::ServerConfigFile {
    config::ServerConfigFile {
        listen: None,
        data_dir: None,
        authorized_keys_path: None,
        allow_users: None,
        allow_tcp_forwarding: None,
        max_connections: None,
        max_sessions_per_connection: None,
        max_forwards_per_connection: None,
        max_forward_streams_per_connection: None,
    }
}

async fn handle_connection(
    conn: Connection,
    config: ServerRuntimeConfig,
    server_addr: SocketAddr,
) -> Result<()> {
    let peer_key = conn.peer_public_key();
    let mut remote_forwards = 0usize;
    loop {
        let (mut send, mut recv) = conn.accept_bi().await?;
        match read_frame::<StreamOpen>(&mut recv).await? {
            StreamOpen::OpenRemoteForward(req) => {
                if !config.allow_tcp_forwarding {
                    write_frame(
                        &mut send,
                        &StreamResponse::Error("TCP forwarding is disabled".to_owned()),
                    )
                    .await?;
                    send.finish().await?;
                    continue;
                }
                if remote_forwards >= config.max_forwards_per_connection {
                    write_frame(
                        &mut send,
                        &StreamResponse::Error("remote forward limit reached".to_owned()),
                    )
                    .await?;
                    send.finish().await?;
                    continue;
                }
                remote_forwards += 1;
                let conn2 = conn.clone();
                tokio::spawn(async move {
                    if let Err(err) = hush_core::forwarding::run_remote_forward_listener(
                        conn2,
                        req.listen_host,
                        req.listen_port,
                        req.target,
                    )
                    .await
                    {
                        tracing::warn!(%err, "remote forward stopped");
                    }
                });
                write_frame(&mut send, &StreamResponse::Ok).await?;
                send.finish().await?;
            }
            StreamOpen::Session { request: session } => {
                if config.max_sessions_per_connection == 0 {
                    write_frame(
                        &mut send,
                        &StreamResponse::Error("session limit reached".to_owned()),
                    )
                    .await?;
                    send.finish().await?;
                    continue;
                }
                return match hush_core::session::run_server_session(
                    conn,
                    send,
                    recv,
                    session,
                    peer_key,
                    config,
                    server_addr,
                )
                .await
                {
                    Ok(_) => Ok(()),
                    Err(err) => {
                        tracing::warn!(%err, "session failed");
                        Ok(())
                    }
                };
            }
            other => {
                tracing::warn!(?other, "unexpected pre-session stream");
            }
        };
    }
}
