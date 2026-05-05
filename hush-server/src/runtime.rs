use crate::cli::Args;
use anyhow::{Context, Result};
use hush_core::{
    auth,
    config::{self, ServerRuntimeConfig},
    protocol::{StreamOpen, StreamResponse, read_frame, write_frame},
};
use quinn::{Endpoint, default_runtime};
use rustls_pki_types::CertificateDer;
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
    let listen = if args.listen.to_string() != "[::]:4433" {
        args.listen
    } else {
        file_cfg.listen.unwrap_or(args.listen)
    };
    let host_cert = args.host_cert.or(file_cfg.host_cert_path);
    let host_key = args.host_key.or(file_cfg.host_key_path);
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

    let server_config =
        hush_core::tls::make_server_config(&data_dir, host_cert.as_deref(), host_key.as_deref())?;
    let endpoint_config = hush_core::endpoint::server_endpoint_config(&data_dir)?;
    let socket = std::net::UdpSocket::bind(listen)?;
    let runtime = default_runtime().context("no async runtime found")?;
    let endpoint = Endpoint::new(endpoint_config, Some(server_config), socket, runtime)?;
    let local_addr = endpoint.local_addr()?;
    tracing::info!(
        addr = %local_addr,
        max_connections = runtime_config.max_connections,
        max_sessions_per_connection = runtime_config.max_sessions_per_connection,
        max_forwards_per_connection = runtime_config.max_forwards_per_connection,
        max_forward_streams_per_connection = runtime_config.max_forward_streams_per_connection,
        "hush server listening"
    );

    let connection_slots = Arc::new(Semaphore::new(runtime_config.max_connections));
    while let Some(connecting) = endpoint.accept().await {
        let permit = match connection_slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::warn!("rejecting connection because max_connections is reached");
                tokio::spawn(async move {
                    if let Ok(conn) = connecting.await {
                        conn.close(0u32.into(), b"server connection limit reached");
                    }
                });
                continue;
            }
        };
        let runtime_config = runtime_config.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match connecting.await {
                Ok(conn) => {
                    if let Err(err) = handle_connection(conn, runtime_config, local_addr).await {
                        tracing::warn!(%err, "connection failed");
                    }
                }
                Err(err) => tracing::warn!(%err, "accept failed"),
            }
        });
    }
    Ok(())
}

fn empty_file_config() -> config::ServerConfigFile {
    config::ServerConfigFile {
        listen: None,
        data_dir: None,
        host_cert_path: None,
        host_key_path: None,
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
    conn: quinn::Connection,
    config: ServerRuntimeConfig,
    server_addr: SocketAddr,
) -> Result<()> {
    let peer_key = peer_public_key(&conn)?;
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
                    send.finish()?;
                    continue;
                }
                if remote_forwards >= config.max_forwards_per_connection {
                    write_frame(
                        &mut send,
                        &StreamResponse::Error("remote forward limit reached".to_owned()),
                    )
                    .await?;
                    send.finish()?;
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
                send.finish()?;
            }
            StreamOpen::Session { request: session } => {
                if config.max_sessions_per_connection == 0 {
                    write_frame(
                        &mut send,
                        &StreamResponse::Error("session limit reached".to_owned()),
                    )
                    .await?;
                    send.finish()?;
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

fn peer_public_key(conn: &quinn::Connection) -> Result<ssh_key::PublicKey> {
    let identity = conn
        .peer_identity()
        .context("client did not present a certificate")?;
    let certs = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| anyhow::anyhow!("unexpected peer identity type"))?;
    let cert = certs.first().context("client certificate chain is empty")?;
    auth::public_key_from_cert_der(cert.as_ref())
}
