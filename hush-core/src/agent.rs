//! SSH agent forwarding (`hush -A`).
//!
//! The server end listens on a per-session unix socket and relays each
//! connection to the client over a QUIC stream. The client end bridges those
//! streams to the local ssh-agent, first binding each connection to this hush
//! session with the OpenSSH `session-bind@openssh.com` agent protocol
//! extension so agents that support key destination constraints know the
//! connection is forwarded and which host it was forwarded through.
//!
//! The extension needs three values: the server host key in SSH wire form, a
//! session identifier, and the server's signature over that identifier. hush
//! has no SSH transport, so the equivalents are derived from the QUIC/TLS
//! session: the host key is extracted from the server's TLS certificate, and
//! the session identifier is a TLS 1.3 keying-material export that both sides
//! compute independently. The server signs it with its host private key and
//! sends the signature in each `AgentForward` stream header.

use crate::{
    auth,
    net::join_io_pair,
    priority::{StreamPriority, set_stream_priority},
    protocol::{StreamOpen, write_frame},
};
use anyhow::{Context, Result, bail};
use aws_lc_rs::signature::KeyPair as _;
use quinn::{Connection, RecvStream, SendStream};
use ssh_key::{Algorithm, EcdsaCurve};
use std::{
    fmt, fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
};

pub const SESSION_BIND_EXTENSION: &str = "session-bind@openssh.com";

/// Label for the TLS keying-material export both peers use as the agent
/// session identifier. Changing it invalidates recorded destination
/// constraints, so treat it as part of the wire protocol.
const SESSION_ID_EXPORT_LABEL: &[u8] = b"hush ssh-agent session-bind";
pub const SESSION_ID_LEN: usize = 32;

const SSH_AGENTC_EXTENSION: u8 = 27;
const SSH_AGENT_SUCCESS: u8 = 6;

/// Upper bound on a single agent protocol reply, matching OpenSSH's
/// MAX_AGENT_REPLY_LEN.
const MAX_AGENT_REPLY_LEN: usize = 256 * 1024;

/// The session identifier for `session-bind@openssh.com`, derived from the
/// connection's TLS exporter so both peers agree on it without extra round
/// trips. It is bound to the TLS session (and thereby both certificates).
pub fn session_bind_id(conn: &Connection) -> Result<[u8; SESSION_ID_LEN]> {
    let mut id = [0u8; SESSION_ID_LEN];
    conn.export_keying_material(&mut id, SESSION_ID_EXPORT_LABEL, b"")
        .map_err(|_| anyhow::anyhow!("TLS keying material export failed"))?;
    Ok(id)
}

/// The peer's public key in SSH wire form, extracted from its TLS certificate.
pub fn peer_host_key_blob(conn: &Connection) -> Result<Vec<u8>> {
    let identity = conn
        .peer_identity()
        .context("peer did not present a certificate")?;
    let certs = identity
        .downcast::<Vec<rustls_pki_types::CertificateDer<'static>>>()
        .map_err(|_| anyhow::anyhow!("unexpected peer identity type"))?;
    let cert = certs.first().context("peer certificate chain is empty")?;
    let key = auth::public_key_from_cert_der(cert.as_ref())?;
    key.to_bytes().context("serialize peer host key")
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

/// Everything the client needs to bind one forwarded agent connection.
#[derive(Debug, Clone)]
pub struct SessionBind {
    /// Server host public key, SSH wire encoded.
    pub host_key: Vec<u8>,
    /// Session identifier from [`session_bind_id`].
    pub session_id: Vec<u8>,
    /// Server host key signature over `session_id`, SSH wire encoded.
    pub signature: Vec<u8>,
}

/// Bridge one server-initiated agent forwarding stream to the local agent at
/// `socket`. When `bind` is available, the connection is first bound to this
/// session with `session-bind@openssh.com` (`is_forwarding = true`); agents
/// that do not support the extension are tolerated, matching OpenSSH.
pub async fn serve_agent_forward_stream(
    send: SendStream,
    recv: RecvStream,
    socket: &Path,
    bind: Option<&SessionBind>,
) -> Result<()> {
    set_stream_priority(&send, StreamPriority::Forward);
    let mut agent = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connect ssh-agent {}", socket.display()))?;
    match bind {
        Some(bind) => match bind_agent_connection(&mut agent, bind).await? {
            true => tracing::debug!("bound forwarded agent connection to session"),
            false => tracing::warn!(
                "ssh-agent refused session-bind@openssh.com; forwarding without binding"
            ),
        },
        None => tracing::debug!("forwarding agent connection without session binding"),
    }
    let (read_half, write_half) = agent.into_split();
    join_io_pair(read_half, write_half, send, recv).await
}

/// Send `session-bind@openssh.com` on a fresh agent connection and consume the
/// reply. Returns whether the agent accepted the binding.
async fn bind_agent_connection(agent: &mut UnixStream, bind: &SessionBind) -> Result<bool> {
    let mut body = vec![SSH_AGENTC_EXTENSION];
    put_string(&mut body, SESSION_BIND_EXTENSION.as_bytes());
    put_string(&mut body, &bind.host_key);
    put_string(&mut body, &bind.session_id);
    put_string(&mut body, &bind.signature);
    body.push(1); // is_forwarding
    agent.write_u32(body.len() as u32).await?;
    agent.write_all(&body).await?;

    let len = agent.read_u32().await.context("read agent reply")? as usize;
    if len == 0 || len > MAX_AGENT_REPLY_LEN {
        bail!("invalid agent reply length {len}");
    }
    let mut reply = vec![0u8; len];
    agent
        .read_exact(&mut reply)
        .await
        .context("read agent reply")?;
    Ok(reply[0] == SSH_AGENT_SUCCESS)
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

/// A per-session agent forwarding listener. Dropping it stops the accept loop
/// and removes the socket directory.
pub(crate) struct AgentForwardGuard {
    socket_path: PathBuf,
    dir: PathBuf,
    task: tokio::task::JoinHandle<()>,
}

impl AgentForwardGuard {
    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

impl Drop for AgentForwardGuard {
    fn drop(&mut self) {
        self.task.abort();
        if let Err(err) = fs::remove_dir_all(&self.dir) {
            tracing::debug!(%err, dir = %self.dir.display(), "failed to remove agent socket dir");
        }
    }
}

/// Create the session's agent socket and start relaying connections to the
/// client. `owner` chowns the socket to the session user when the server runs
/// as root; `signer` produces the `session-bind@openssh.com` signature (an
/// empty signature tells the client to skip binding).
pub(crate) fn start_agent_forward(
    conn: &Connection,
    signer: Option<&HostSigner>,
    owner: Option<(u32, u32)>,
    slots: Arc<Semaphore>,
) -> Result<AgentForwardGuard> {
    let bind_signature = signer
        .map(|signer| {
            let session_id = session_bind_id(conn)?;
            signer.sign_session_id(&session_id)
        })
        .transpose()
        .unwrap_or_else(|err| {
            tracing::warn!(%err, "agent session-bind signature unavailable");
            None
        })
        .unwrap_or_default();

    let (dir, socket_path, listener) = bind_agent_socket(owner)?;
    tracing::debug!(socket = %socket_path.display(), "agent forwarding listening");
    let conn = conn.clone();
    let task = tokio::spawn(async move {
        if let Err(err) = run_agent_listener(listener, conn, bind_signature, slots).await {
            tracing::warn!(%err, "agent forwarding stopped");
        }
    });
    Ok(AgentForwardGuard {
        socket_path,
        dir,
        task,
    })
}

/// Bind the agent socket inside a fresh private directory, like OpenSSH's
/// `/tmp/ssh-XXXXXXXX/agent.<pid>`. The directory is created with mode 0700
/// before the socket exists, so there is no window where another user can
/// reach it.
fn bind_agent_socket(owner: Option<(u32, u32)>) -> Result<(PathBuf, PathBuf, UnixListener)> {
    let mut nonce = [0u8; 8];
    aws_lc_rs::rand::fill(&mut nonce).map_err(|_| anyhow::anyhow!("generate socket nonce"))?;
    let dir = std::env::temp_dir().join(format!("hush-{}", hex::encode(nonce)));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .with_context(|| format!("create agent socket dir {}", dir.display()))?;
    let result = (|| {
        let socket_path = dir.join(format!("agent.{}", std::process::id()));
        let listener = UnixListener::bind(&socket_path)
            .with_context(|| format!("bind agent socket {}", socket_path.display()))?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::chown(&dir, Some(uid), Some(gid))
                .context("chown agent socket dir")?;
            std::os::unix::fs::chown(&socket_path, Some(uid), Some(gid))
                .context("chown agent socket")?;
        }
        Ok((socket_path, listener))
    })();
    match result {
        Ok((socket_path, listener)) => Ok((dir, socket_path, listener)),
        Err(err) => {
            let _ = fs::remove_dir_all(&dir);
            Err(err)
        }
    }
}

async fn run_agent_listener(
    listener: UnixListener,
    conn: Connection,
    bind_signature: Vec<u8>,
    slots: Arc<Semaphore>,
) -> Result<()> {
    loop {
        let (unix, _) = listener.accept().await?;
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            tracing::warn!("rejected agent connection because forward stream limit is reached");
            continue;
        };
        let conn = conn.clone();
        let bind_signature = bind_signature.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(err) = serve_agent_connection(conn, unix, bind_signature).await {
                tracing::debug!(%err, "agent forward connection failed");
            }
        });
    }
}

async fn serve_agent_connection(
    conn: Connection,
    unix: UnixStream,
    bind_signature: Vec<u8>,
) -> Result<()> {
    let (mut send, recv) = conn.open_bi().await?;
    set_stream_priority(&send, StreamPriority::Forward);
    write_frame(&mut send, &StreamOpen::AgentForward { bind_signature }).await?;
    let (read_half, write_half) = unix.into_split();
    join_io_pair(read_half, write_half, send, recv).await
}

// ---------------------------------------------------------------------------
// Host key signing
// ---------------------------------------------------------------------------

/// Signs agent session identifiers with the server's TLS host key, producing
/// SSH wire format signatures an ssh-agent can verify against the host public
/// key the client extracts from the server certificate.
pub struct HostSigner {
    algorithm: Algorithm,
    key: HostSignerKey,
}

enum HostSignerKey {
    Ed25519(aws_lc_rs::signature::Ed25519KeyPair),
    Ecdsa(aws_lc_rs::signature::EcdsaKeyPair),
}

impl fmt::Debug for HostSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostSigner")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl HostSigner {
    /// Build a signer from the host certificate and its PKCS#8 private key.
    pub fn from_host_key(
        cert_der: &[u8],
        key: &rustls_pki_types::PrivateKeyDer<'_>,
    ) -> Result<Self> {
        let public = auth::public_key_from_cert_der(cert_der)?;
        let algorithm = public.algorithm();
        let rustls_pki_types::PrivateKeyDer::Pkcs8(pkcs8) = key else {
            bail!("host key is not PKCS#8");
        };
        let der = pkcs8.secret_pkcs8_der();
        let key = match &algorithm {
            Algorithm::Ed25519 => {
                let keypair = aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(der)
                    .or_else(|_| {
                        aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(der)
                    })
                    .map_err(|_| anyhow::anyhow!("parse Ed25519 host key"))?;
                HostSignerKey::Ed25519(keypair)
            }
            Algorithm::Ecdsa { curve } => {
                let signing = match curve {
                    EcdsaCurve::NistP256 => &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                    EcdsaCurve::NistP384 => &aws_lc_rs::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                    EcdsaCurve::NistP521 => &aws_lc_rs::signature::ECDSA_P521_SHA512_FIXED_SIGNING,
                };
                let keypair = aws_lc_rs::signature::EcdsaKeyPair::from_pkcs8(signing, der)
                    .map_err(|_| anyhow::anyhow!("parse ECDSA host key"))?;
                HostSignerKey::Ecdsa(keypair)
            }
            other => bail!("unsupported host key type {other}"),
        };
        verify_key_matches_cert(&public, &key)?;
        Ok(Self { algorithm, key })
    }

    /// Sign a session identifier, returning the SSH wire format signature blob
    /// (`string algorithm, string data`).
    pub fn sign_session_id(&self, session_id: &[u8]) -> Result<Vec<u8>> {
        let data = match &self.key {
            HostSignerKey::Ed25519(keypair) => keypair.sign(session_id).as_ref().to_vec(),
            HostSignerKey::Ecdsa(keypair) => {
                let rng = aws_lc_rs::rand::SystemRandom::new();
                let fixed = keypair
                    .sign(&rng, session_id)
                    .map_err(|_| anyhow::anyhow!("ECDSA host key signing failed"))?;
                ecdsa_fixed_to_ssh(fixed.as_ref())?
            }
        };
        let mut blob = Vec::with_capacity(data.len() + 32);
        put_string(&mut blob, self.algorithm.as_str().as_bytes());
        put_string(&mut blob, &data);
        Ok(blob)
    }
}

/// Guard against a mismatched host cert/key pair, which would produce
/// signatures the client's agent can never verify.
fn verify_key_matches_cert(public: &ssh_key::PublicKey, key: &HostSignerKey) -> Result<()> {
    let cert_public = auth::raw_public_key_bytes(public)?;
    let key_public = match key {
        HostSignerKey::Ed25519(keypair) => keypair.public_key().as_ref().to_vec(),
        HostSignerKey::Ecdsa(keypair) => keypair.public_key().as_ref().to_vec(),
    };
    if cert_public != key_public {
        bail!("host certificate public key does not match the host private key");
    }
    Ok(())
}

/// Convert a fixed-width `r || s` ECDSA signature into the SSH encoding
/// (`mpint r, mpint s`).
fn ecdsa_fixed_to_ssh(fixed: &[u8]) -> Result<Vec<u8>> {
    if fixed.is_empty() || !fixed.len().is_multiple_of(2) {
        bail!("unexpected ECDSA signature length {}", fixed.len());
    }
    let (r, s) = fixed.split_at(fixed.len() / 2);
    let mut out = Vec::with_capacity(fixed.len() + 16);
    put_mpint(&mut out, r);
    put_mpint(&mut out, s);
    Ok(out)
}

fn put_string(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Append an SSH `mpint`: big-endian with leading zeros stripped, and a zero
/// byte prepended when the most significant bit is set.
fn put_mpint(buf: &mut Vec<u8>, magnitude: &[u8]) {
    let start = magnitude
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(magnitude.len());
    let trimmed = &magnitude[start..];
    let pad = trimmed.first().is_some_and(|&b| b & 0x80 != 0);
    buf.extend_from_slice(&((trimmed.len() + usize::from(pad)) as u32).to_be_bytes());
    if pad {
        buf.push(0);
    }
    buf.extend_from_slice(trimmed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    fn take_string(buf: &mut &[u8]) -> Vec<u8> {
        let (len, rest) = buf.split_at(4);
        let len = u32::from_be_bytes(len.try_into().unwrap()) as usize;
        let (data, rest) = rest.split_at(len);
        *buf = rest;
        data.to_vec()
    }

    fn host_cert_and_key(
        alg: &'static rcgen::SignatureAlgorithm,
    ) -> (Vec<u8>, PrivateKeyDer<'static>) {
        let keypair = rcgen::KeyPair::generate_for(alg).unwrap();
        let key_der = keypair.serialize_der();
        let cert = rcgen::CertificateParams::new(vec!["hush-server".to_owned()])
            .unwrap()
            .self_signed(&keypair)
            .unwrap();
        (
            cert.der().as_ref().to_vec(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
        )
    }

    #[test]
    fn mpint_strips_zeros_and_pads_high_bit() {
        let mut out = Vec::new();
        put_mpint(&mut out, &[0x00, 0x00, 0x7f, 0x01]);
        assert_eq!(out, [0, 0, 0, 2, 0x7f, 0x01]);

        let mut out = Vec::new();
        put_mpint(&mut out, &[0x80, 0x01]);
        assert_eq!(out, [0, 0, 0, 3, 0x00, 0x80, 0x01]);

        let mut out = Vec::new();
        put_mpint(&mut out, &[0x00, 0x00]);
        assert_eq!(out, [0, 0, 0, 0]);
    }

    #[test]
    fn ed25519_host_signer_produces_verifiable_ssh_signature() {
        let (cert, key) = host_cert_and_key(&rcgen::PKCS_ED25519);
        let signer = HostSigner::from_host_key(&cert, &key).unwrap();
        let session_id = [0x42u8; SESSION_ID_LEN];
        let blob = signer.sign_session_id(&session_id).unwrap();

        let mut rest = blob.as_slice();
        assert_eq!(take_string(&mut rest), b"ssh-ed25519");
        let sig = take_string(&mut rest);
        assert!(rest.is_empty());
        assert_eq!(sig.len(), 64);

        let public = auth::public_key_from_cert_der(&cert).unwrap();
        let raw = auth::raw_public_key_bytes(&public).unwrap();
        aws_lc_rs::signature::UnparsedPublicKey::new(&aws_lc_rs::signature::ED25519, &raw)
            .verify(&session_id, &sig)
            .expect("Ed25519 signature should verify");
    }

    #[test]
    fn ecdsa_host_signer_produces_verifiable_ssh_signature() {
        use p256::ecdsa::signature::Verifier;

        let (cert, key) = host_cert_and_key(&rcgen::PKCS_ECDSA_P256_SHA256);
        let signer = HostSigner::from_host_key(&cert, &key).unwrap();
        let session_id = [0x24u8; SESSION_ID_LEN];
        let blob = signer.sign_session_id(&session_id).unwrap();

        let mut rest = blob.as_slice();
        assert_eq!(take_string(&mut rest), b"ecdsa-sha2-nistp256");
        let data = take_string(&mut rest);
        assert!(rest.is_empty());

        let ssh_sig = ssh_key::Signature::new(
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
            data,
        )
        .unwrap();
        let sig = p256::ecdsa::Signature::try_from(&ssh_sig).unwrap();
        let public = auth::public_key_from_cert_der(&cert).unwrap();
        let raw = auth::raw_public_key_bytes(&public).unwrap();
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&raw)
            .unwrap()
            .verify(&session_id, &sig)
            .expect("P-256 signature should verify");
    }

    #[test]
    fn host_signer_rejects_mismatched_cert_and_key() {
        let (cert, _) = host_cert_and_key(&rcgen::PKCS_ED25519);
        let (_, other_key) = host_cert_and_key(&rcgen::PKCS_ED25519);
        assert!(HostSigner::from_host_key(&cert, &other_key).is_err());
    }
}
