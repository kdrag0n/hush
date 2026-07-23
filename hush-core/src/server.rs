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
use std::net::SocketAddr;

/// The only detail a rejected peer learns about why it was rejected.
const AUTH_FAILURE_MESSAGE: &str = "unauthorized";

/// Authenticate and serve one accepted connection. This is the single entry
/// point for handling a connection.
pub async fn serve_connection(
    conn: Connection,
    config: ServerRuntimeConfig,
    server_addr: SocketAddr,
) -> Result<()> {
    PendingConnection::new(conn, config, server_addr)?
        .authenticate()?
        .serve()
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
            && !self.config.allow_users.iter().any(|allowed| allowed == user)
        {
            bail!("user is not allowed by server config");
        }
        if !auth::can_login_as(user) {
            bail!(
                "server is not root and requested user differs from {}",
                auth::current_username()
            );
        }
        match auth::is_authorized(user, &self.peer_key, self.config.authorized_keys_path.as_deref())
        {
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
    pub async fn serve(self) -> Result<()> {
        let mut remote_forwards = 0usize;
        loop {
            let (mut send, mut recv) = self.conn.accept_bi().await?;
            match read_frame::<StreamOpen>(&mut recv).await? {
                StreamOpen::OpenRemoteForward(request) => {
                    self.open_remote_forward(&mut send, request, &mut remote_forwards)
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
                    let result = match request.direction {
                        FileCopyDirection::Upload => {
                            filecopy::handle_upload(send, recv, request).await
                        }
                        FileCopyDirection::Download => filecopy::handle_download(send, request).await,
                    };
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
        *remote_forwards += 1;
        let conn = self.conn.clone();
        tokio::spawn(async move {
            if let Err(err) = crate::forwarding::run_remote_forward_listener(
                conn,
                request.listen_host,
                request.listen_port,
                request.target,
            )
            .await
            {
                tracing::warn!(%err, "remote forward stopped");
            }
        });
        write_frame(send, &StreamResponse::Ok).await?;
        send.finish()?;
        Ok(())
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
