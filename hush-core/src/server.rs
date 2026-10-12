//! Server-side connection lifecycle, with authorization enforced by
//! construction.
//!
//! A freshly accepted connection only exists as a [`PendingConnection`], whose
//! sole capability is [`PendingConnection::authenticate`]. Every stream
//! handler — sessions, TCP forwarding, agent forwarding, file copy — hangs off
//! [`AuthenticatedConnection`], which has private fields and no other way to
//! be constructed. Serving a request on an unauthenticated connection is
//! therefore not a code path that can be written outside this module, rather
//! than a rule each handler must remember to enforce.
//!
//! Authentication itself costs no round trip: the client's certificate carries
//! both its key and the username it claims (covered by the live handshake
//! signature), so everything needed to authorize the connection arrived with
//! the TLS handshake.

use crate::{
    auth,
    config::ServerRuntimeConfig,
    fastsock::MultiSocket,
    filecopy,
    priority::{StreamPriority, set_stream_priority},
    protocol::{
        FileCopyDirection, RemoteForwardRequest, StreamOpen, StreamResponse, read_frame,
        write_frame,
    },
};
use anyhow::{Context, Result, anyhow, bail};
use quinn::{Connection, SendStream};
use rustls_pki_types::CertificateDer;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::{net::TcpListener, sync::Semaphore};

/// The only detail a rejected peer learns about why it was rejected.
const AUTH_FAILURE_MESSAGE: &str = "unauthorized";

/// Authenticate and serve one accepted connection. This is the single entry
/// point for handling a connection.
pub enum ConnectionSockets {
    Bsd(Arc<MultiSocket>),
    #[cfg(target_os = "macos")]
    Network(Arc<crate::nwsock::NwSocket>),
}

enum ConnectionSocketGuard {
    Bsd {
        _guard: crate::fastsock::PrivateSocketGuard,
    },
    #[cfg(target_os = "macos")]
    Network { _guard: crate::nwsock::NwFlowGuard },
}

impl ConnectionSockets {
    fn adopt(
        &self,
        local_ip: Option<IpAddr>,
        peer: SocketAddr,
    ) -> std::io::Result<ConnectionSocketGuard> {
        match self {
            Self::Bsd(sockets) => {
                let local_ip = local_ip.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        "connection has no local address",
                    )
                })?;
                Ok(ConnectionSocketGuard::Bsd {
                    _guard: sockets.adopt(local_ip, peer),
                })
            }
            #[cfg(target_os = "macos")]
            Self::Network(socket) => socket
                .adopt(peer)
                .map(|guard| ConnectionSocketGuard::Network { _guard: guard }),
        }
    }
}

pub async fn serve_connection(
    conn: Connection,
    config: ServerRuntimeConfig,
    server_addr: SocketAddr,
    sockets: Option<Arc<ConnectionSockets>>,
) -> Result<()> {
    PendingConnection::new(conn, config, server_addr)?
        .authenticate()?
        .serve(sockets)
        .await
}

/// A connection whose peer has presented a TLS key and claimed a user, but has
/// not yet been checked against authorized_keys. It can do exactly one thing:
/// authenticate.
pub struct PendingConnection {
    conn: Connection,
    peer_key: ssh_key::PublicKey,
    claimed_user: String,
    config: ServerRuntimeConfig,
    server_addr: SocketAddr,
}

impl PendingConnection {
    pub fn new(
        conn: Connection,
        config: ServerRuntimeConfig,
        server_addr: SocketAddr,
    ) -> Result<Self> {
        let (peer_key, claimed_user) = match peer_identity(&conn) {
            Ok(identity) => identity,
            Err(err) => {
                conn.close(0u32.into(), AUTH_FAILURE_MESSAGE.as_bytes());
                return Err(err);
            }
        };
        Ok(Self {
            conn,
            peer_key,
            claimed_user,
            config,
            server_addr,
        })
    }

    /// Verify the certificate's claimed user against the peer key. Both
    /// arrived with the TLS handshake, so this involves no peer interaction.
    /// On success this consumes the pending state and returns the only handle
    /// that can serve streams; on failure the connection is closed.
    pub fn authenticate(self) -> Result<AuthenticatedConnection> {
        let peer_fp =
            auth::public_key_fingerprint(&self.peer_key).unwrap_or_else(|_| "unknown".into());
        tracing::info!(user = %self.claimed_user, key = %peer_fp, "auth attempt");
        if let Err(reason) = self.check_authorization(&self.claimed_user) {
            tracing::warn!(user = %self.claimed_user, key = %peer_fp, %reason, "auth rejected");
            self.conn
                .close(0u32.into(), AUTH_FAILURE_MESSAGE.as_bytes());
            bail!(AUTH_FAILURE_MESSAGE);
        }
        tracing::info!(user = %self.claimed_user, key = %peer_fp, "auth accepted");
        Ok(AuthenticatedConnection {
            conn: self.conn,
            user: self.claimed_user,
            config: self.config,
            server_addr: self.server_addr,
        })
    }

    /// Whether the peer key may act as `user`. The reason is logged but never
    /// sent to the peer.
    fn check_authorization(&self, user: &str) -> Result<()> {
        if !self.config.allow_users.is_empty()
            && !self
                .config
                .allow_users
                .iter()
                .any(|allowed| allowed == user)
        {
            bail!("user is not allowed by server config");
        }
        if !auth::can_login_as(user) {
            bail!(
                "server is not root and requested user differs from {}",
                auth::current_username()
            );
        }
        match auth::is_authorized(
            user,
            &self.peer_key,
            self.config.authorized_keys_path.as_deref(),
        ) {
            Ok(true) => Ok(()),
            Ok(false) => bail!("public key is not authorized"),
            Err(err) => Err(err),
        }
    }
}

/// Proof that the peer's key was verified against [`Self::user`]'s
/// authorized_keys. Only [`PendingConnection::authenticate`] can construct
/// one, so anything reachable from here is authorized by construction.
pub struct AuthenticatedConnection {
    conn: Connection,
    user: String,
    config: ServerRuntimeConfig,
    server_addr: SocketAddr,
}

impl AuthenticatedConnection {
    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }

    /// The user this connection authenticated as. All streams act as this
    /// user; requests carry no user of their own.
    pub(crate) fn user(&self) -> &str {
        &self.user
    }

    pub(crate) fn config(&self) -> &ServerRuntimeConfig {
        &self.config
    }

    pub(crate) fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    /// Serve streams until the connection closes or a session finishes.
    pub async fn serve(self, sockets: Option<Arc<ConnectionSockets>>) -> Result<()> {
        let mut remote_forwards = 0usize;
        let mut remote_forward_tasks = RemoteForwardTasks::default();
        let remote_forward_streams = Arc::new(Semaphore::new(
            self.config.max_forward_streams_per_connection,
        ));
        // Give the connection a private socket once it has settled, and keep
        // the guard alive as long as the connection: every packet of it,
        // including its close, then goes through that socket.
        let private_socket = sockets.and_then(|sockets| {
            match sockets.adopt(self.conn.local_ip(), self.conn.remote_address()) {
                Ok(guard) => Some(guard),
                Err(err) => {
                    tracing::debug!(%err, "could not adopt authenticated peer socket");
                    None
                }
            }
        });
        if let Some(private_socket) = private_socket {
            let conn = self.conn.clone();
            tokio::spawn(async move {
                conn.closed().await;
                drop(private_socket);
            });
        }
        loop {
            let (mut send, mut recv) = self.conn.accept_bi().await?;
            match read_frame::<StreamOpen>(&mut recv).await? {
                StreamOpen::OpenRemoteForward(request) => {
                    self.open_remote_forward(
                        &mut send,
                        request,
                        &mut remote_forwards,
                        &mut remote_forward_tasks,
                        remote_forward_streams.clone(),
                    )
                    .await?;
                }
                StreamOpen::Session { request } => {
                    set_stream_priority(&send, StreamPriority::Shell);
                    if self.config.max_sessions_per_connection == 0 {
                        send_response_error(&mut send, "session limit reached").await;
                        continue;
                    }
                    return match crate::session::run_server_session(&self, send, recv, request)
                        .await
                    {
                        Ok(_) => Ok(()),
                        Err(err) => {
                            tracing::warn!(%err, "session failed");
                            Ok(())
                        }
                    };
                }
                StreamOpen::FileCopy(request) => {
                    set_stream_priority(&send, StreamPriority::FileCopy);
                    tracing::info!(user = %self.user, direction = ?request.direction, "file copy");
                    crate::tls::switch_to_bulk(&self.conn);
                    let result = match request.direction {
                        FileCopyDirection::Upload => {
                            filecopy::handle_upload(
                                send,
                                recv,
                                &self.user,
                                request,
                                self.config.file_copy_limits,
                            )
                            .await
                        }
                        FileCopyDirection::Download => {
                            filecopy::handle_download(
                                send,
                                &self.user,
                                request,
                                self.config.file_copy_limits,
                            )
                            .await
                        }
                    };
                    tracing::debug!(stats = ?self.conn.stats(), "file copy finished");
                    if let Err(err) = result {
                        tracing::warn!(%err, "file copy failed");
                    }
                }
                other => {
                    tracing::warn!(?other, "unexpected stream header");
                }
            }
        }
    }

    async fn open_remote_forward(
        &self,
        send: &mut SendStream,
        request: RemoteForwardRequest,
        remote_forwards: &mut usize,
        remote_forward_tasks: &mut RemoteForwardTasks,
        remote_forward_streams: Arc<Semaphore>,
    ) -> Result<()> {
        set_stream_priority(send, StreamPriority::Forward);
        if !self.config.allow_tcp_forwarding {
            write_frame(
                send,
                &StreamResponse::Error("TCP forwarding is disabled".to_owned()),
            )
            .await?;
            send.finish()?;
            return Ok(());
        }
        if *remote_forwards >= self.config.max_forwards_per_connection {
            write_frame(
                send,
                &StreamResponse::Error("remote forward limit reached".to_owned()),
            )
            .await?;
            send.finish()?;
            return Ok(());
        }
        let listen_ip = if request.listen_host == "localhost" {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            match request.listen_host.parse::<IpAddr>() {
                Ok(ip) if ip.is_loopback() => ip,
                _ => {
                    send_response_error(send, "remote forwards must listen on a loopback address")
                        .await;
                    return Ok(());
                }
            }
        };
        if request.listen_port != 0
            && request.listen_port < 1024
            && crate::os::is_root()
            && self.user != auth::current_username()
        {
            send_response_error(send, "remote forwards may not use privileged ports").await;
            return Ok(());
        }
        let listener =
            match TcpListener::bind(SocketAddr::new(listen_ip, request.listen_port)).await {
                Ok(listener) => listener,
                Err(err) => {
                    tracing::warn!(%err, "remote forward bind failed");
                    send_response_error(send, "remote forward bind failed").await;
                    return Ok(());
                }
            };
        *remote_forwards += 1;
        let conn = self.conn.clone();
        let forward_id = request.forward_id;
        let task = tokio::spawn(async move {
            if let Err(err) = crate::forwarding::run_remote_forward_listener(
                conn,
                listener,
                forward_id,
                remote_forward_streams,
            )
            .await
            {
                tracing::warn!(%err, "remote forward stopped");
            }
        });
        remote_forward_tasks.0.push(task);
        write_frame(send, &StreamResponse::Ok).await?;
        send.finish()?;
        Ok(())
    }
}

#[derive(Default)]
struct RemoteForwardTasks(Vec<tokio::task::JoinHandle<()>>);

impl Drop for RemoteForwardTasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

async fn send_response_error(send: &mut SendStream, msg: &str) {
    let _ = write_frame(send, &StreamResponse::Error(msg.to_owned())).await;
    let _ = send.finish();
    let _ = send.stopped().await;
}

fn peer_identity(conn: &Connection) -> Result<(ssh_key::PublicKey, String)> {
    let identity = conn
        .peer_identity()
        .context("client did not present a certificate")?;
    let certs = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| anyhow!("unexpected peer identity type"))?;
    let cert = certs.first().context("client certificate chain is empty")?;
    Ok((
        auth::public_key_from_cert_der(cert.as_ref())?,
        auth::username_from_cert_der(cert.as_ref())?,
    ))
}
