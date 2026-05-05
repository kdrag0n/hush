use anyhow::{Context, Result};
use clap::Parser;
use hush_core::{
    auth,
    config::{self, ServerRuntimeConfig},
    protocol::{ControlRequest, ControlResponse, OpenSession, read_frame, write_frame},
};
use quinn::Endpoint;
use rustls::pki_types::CertificateDer;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Debug, Parser)]
#[command(name = "hush-server", version)]
struct Args {
    #[arg(short, long)]
    verbose: bool,
    #[arg(long)]
    data_dir: Option<PathBuf>,
    #[arg(short, long, default_value = "[::]:4433")]
    listen: SocketAddr,
    #[arg(short, long)]
    config: Option<PathBuf>,
    #[arg(long)]
    host_cert: Option<PathBuf>,
    #[arg(long)]
    host_key: Option<PathBuf>,
    #[arg(long)]
    authorized_keys: Option<PathBuf>,
    #[arg(long)]
    allow_user: Vec<String>,
    #[arg(long)]
    disable_tcp_forwarding: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_logging(args.verbose);
    let config_path = args
        .config
        .clone()
        .unwrap_or_else(hush_core::paths::default_server_config_path);
    let file_cfg = config::read_server_config(&config_path)?.unwrap_or(config::ServerConfigFile {
        listen: None,
        data_dir: None,
        host_cert_path: None,
        host_key_path: None,
        authorized_keys_path: None,
        allow_users: None,
        allow_tcp_forwarding: None,
    });
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
    };

    let server_config =
        hush_core::tls::make_server_config(&data_dir, host_cert.as_deref(), host_key.as_deref())?;
    let endpoint = Endpoint::server(server_config, listen)?;
    tracing::info!(addr = %endpoint.local_addr()?, "hush server listening");

    while let Some(connecting) = endpoint.accept().await {
        let runtime_config = runtime_config.clone();
        tokio::spawn(async move {
            match connecting.await {
                Ok(conn) => {
                    if let Err(err) = handle_connection(conn, runtime_config).await {
                        tracing::warn!(%err, "connection failed");
                    }
                }
                Err(err) => tracing::warn!(%err, "accept failed"),
            }
        });
    }
    Ok(())
}

async fn handle_connection(conn: quinn::Connection, config: ServerRuntimeConfig) -> Result<()> {
    let peer_key = peer_public_key(&conn)?;
    let (mut control_send, mut control_recv) = conn.accept_bi().await?;
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
            ControlRequest::OpenSession(session) => break session,
            ControlRequest::Close => return Ok(()),
            ControlRequest::Resize(_) | ControlRequest::Signal(_) => {}
        }
    };
    run_session(conn, control_send, control_recv, session, peer_key, config).await
}

async fn run_session(
    conn: quinn::Connection,
    control_send: quinn::SendStream,
    control_recv: quinn::RecvStream,
    session: OpenSession,
    peer_key: ssh_key::PublicKey,
    config: ServerRuntimeConfig,
) -> Result<()> {
    match hush_core::session::run_server_session(
        conn,
        control_send,
        control_recv,
        session,
        peer_key,
        config,
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

fn init_logging(verbose: bool) {
    let filter = if verbose {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "hush_server=debug,hush_core=debug,quinn=info".into())
    } else {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "hush_server=info,hush_core=info,quinn=warn".into())
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
