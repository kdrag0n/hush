use crate::cli::Args;
use anyhow::{Context, Result};
use hush_core::{
    auth,
    config::{self, ServerRuntimeConfig},
    protocol::{ControlRequest, ControlResponse, OpenSession, read_frame, write_frame},
};
use quinn::Endpoint;
use rustls_pki_types::CertificateDer;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::Semaphore;

pub(crate) async fn run(args: Args) -> Result<()> {
    let config_path = args
        .config
        .clone()
        .unwrap_or_else(hush_core::paths::default_server_config_path);
    let file_cfg = config::read_server_config(&config_path)?.unwrap_or_else(empty_file_config);
    let data_dir = args
        .data_dir
        .or(file_cfg.data_dir)
        .unwrap_or_else(hush_core::paths::default_data_dir);
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
    let endpoint = Endpoint::server(server_config, listen)?;
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
    let (mut control_send, mut control_recv) = conn.accept_bi().await?;
    let mut remote_forwards = 0usize;
    let session = loop {
        match read_frame::<ControlRequest>(&mut control_recv).await? {
            ControlRequest::OpenRemoteForward(req) => {
                if !config.allow_tcp_forwarding {
                    write_frame(
                        &mut control_send,
                        &ControlResponse::Error("TCP forwarding is disabled".to_owned()),
                    )
                    .await?;
                    continue;
                }
                if remote_forwards >= config.max_forwards_per_connection {
                    write_frame(
                        &mut control_send,
                        &ControlResponse::Error("remote forward limit reached".to_owned()),
                    )
                    .await?;
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
                write_frame(&mut control_send, &ControlResponse::Ok).await?;
            }
            ControlRequest::OpenSession(session) => {
                if config.max_sessions_per_connection == 0 {
                    write_frame(
                        &mut control_send,
                        &ControlResponse::Error("session limit reached".to_owned()),
                    )
                    .await?;
                    continue;
                }
                break session;
            }
            ControlRequest::Close => return Ok(()),
            ControlRequest::Resize(_) | ControlRequest::Signal(_) => {}
        }
    };
    run_session(
        conn,
        control_send,
        control_recv,
        session,
        peer_key,
        config,
        server_addr,
    )
    .await
}

async fn run_session(
    conn: quinn::Connection,
    control_send: quinn::SendStream,
    control_recv: quinn::RecvStream,
    session: OpenSession,
    peer_key: ssh_key::PublicKey,
    config: ServerRuntimeConfig,
    server_addr: SocketAddr,
) -> Result<()> {
    match hush_core::session::run_server_session(
        conn,
        control_send,
        control_recv,
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
            // The stream may already be closed; best effort is enough here.
            let _ = err;
            Ok(())
        }
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
