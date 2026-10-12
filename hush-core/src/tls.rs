use crate::{
    ALPN,
    auth::{self, IdentityKey},
};
use anyhow::{Result, bail};
use quinn::{
    AckFrequencyConfig, ClientConfig, MtuDiscoveryConfig, ServerConfig, TransportConfig, VarInt,
};
use quinn_proto::{
    congestion::{BbrConfig, ControllerFactory, CubicConfig},
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::{
    ClientConfig as RustlsClientConfig, DigitallySignedStruct, Error as RustlsError,
    ServerConfig as RustlsServerConfig, SignatureAlgorithm, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer,
        UnixTime,
    },
    server::danger::{ClientCertVerified, ClientCertVerifier},
    sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey},
};
use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm, EcdsaCurve};
use std::{
    collections::BTreeMap,
    fmt, fs, io,
    net::SocketAddr,
    os::{
        fd::AsRawFd,
        unix::fs::{OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

const QUIC_FAST_SEND_WINDOW: u64 = 10_000_000;
const QUIC_FAST_STREAM_RECV_WINDOW: u32 = 4 * 1024 * 1024;
const QUIC_FAST_CONN_RECV_WINDOW: u32 = 16 * 1024 * 1024;
const QUIC_FAST_PACKET_THRESHOLD: u32 = 3;
const QUIC_FAST_TIME_THRESHOLD: f32 = 1.0;
const QUIC_FAST_INITIAL_RTT: Duration = Duration::from_millis(100);
const QUIC_FAST_ACK_DELAY: Duration = Duration::from_millis(1);
const QUIC_CLIENT_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(45);
const QUIC_MTU_BLACK_HOLE_COOLDOWN: Duration = Duration::from_secs(1);
const QUIC_MTU_UPPER_BOUND: u16 = 1500 - 20 - 8;
/// Bulk transfers ask the peer to acknowledge at most every 51 packets or
/// 20ms. Every ACK is a frame the receiver must send back over the link, and
/// on half-duplex media such as Wi-Fi that reverse traffic costs airtime that
/// would otherwise carry payload; it also lets the receiver batch work.
const QUIC_BULK_ACK_ELICITING_THRESHOLD: u32 = 50;
const QUIC_BULK_ACK_DELAY: Duration = Duration::from_millis(20);
const QUIC_BULK_TIME_THRESHOLD: f32 = 9.0 / 8.0;
const QUIC_BULK_PACKET_THRESHOLD: u32 = 10;

/// How a connection's transport should be tuned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProfile {
    /// Interactive sessions and port forwards: ACK eagerly and use BBR, which
    /// keeps latency low and holds up on lossy mobile links.
    Interactive,
    /// A single large transfer: use CUBIC and sparse ACKs. BBR's bandwidth
    /// probing overshoots badly on links that drop rather than queue excess
    /// packets (Wi-Fi in particular), and every ACK is reverse traffic.
    Bulk,
}

/// How the server's host certificate is checked against known_hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostTrust {
    /// Trust a host on first use and remember it; reject a changed certificate.
    Tofu,
    /// Accept only hosts already in known_hosts, and never write it. For
    /// non-interactive callers that must not pin a host as a side effect.
    KnownOnly,
    /// Skip verification entirely (`-k`).
    Insecure,
}

#[derive(Debug, Clone)]
struct KnownHosts {
    path: PathBuf,
    entries: BTreeMap<String, String>,
}

impl KnownHosts {
    fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let entries = Self::read_entries(&path)?;
        Ok(Self { path, entries })
    }

    fn read_entries(path: &Path) -> Result<BTreeMap<String, String>> {
        let data = match fs::read_to_string(path) {
            Ok(data) => data,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(err) => return Err(err.into()),
        };
        if data.trim().is_empty() {
            return Ok(BTreeMap::new());
        }
        let file = toml::from_str::<KnownHostsFile>(&data)
            .map_err(|err| anyhow::anyhow!("parse {}: {err}", path.display()))?;
        Ok(file.hosts)
    }

    fn check_or_insert(&mut self, host: &str, fingerprint: &str, trust: HostTrust) -> Result<()> {
        if trust == HostTrust::Insecure {
            return Ok(());
        }
        if trust == HostTrust::KnownOnly {
            self.entries = Self::read_entries(&self.path)?;
            return self.check_existing(host, fingerprint, false);
        }
        if let Some(parent) = self.path.parent() {
            ensure_private_dir(parent)?;
        }
        let _lock = ExclusiveFileLock::acquire(&lock_path_for(&self.path))?;
        // Another client may have pinned a host after this process loaded its
        // initial snapshot. Always merge from disk while holding the lock.
        self.entries = Self::read_entries(&self.path)?;
        self.check_existing(host, fingerprint, true)
    }

    fn check_existing(&mut self, host: &str, fingerprint: &str, insert: bool) -> Result<()> {
        match self.entries.get(host) {
            Some(old) if old == fingerprint => Ok(()),
            Some(old) => {
                bail!(
                    "host certificate mismatch for {host}: known {old}, got {fingerprint}; use -k to bypass"
                )
            }
            None if !insert => bail!("unknown host {host}"),
            None => {
                self.entries.insert(host.to_owned(), fingerprint.to_owned());
                self.save()?;
                Ok(())
            }
        }
    }

    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            ensure_private_dir(parent)?;
        }
        let data = toml::to_string_pretty(&KnownHostsFile {
            hosts: self.entries.clone(),
        })?;
        write_private_file_atomic(&self.path, data.as_bytes())?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KnownHostsFile {
    #[serde(default)]
    hosts: BTreeMap<String, String>,
}

pub fn make_client_config(
    data_dir: &Path,
    host_key: String,
    identity: auth::LoadedIdentity,
    user: &str,
    trust: HostTrust,
    profile: TransportProfile,
) -> Result<ClientConfig> {
    let provider = pq_provider();
    let verifier = Arc::new(TofuServerVerifier {
        provider: provider.clone(),
        known_hosts: Mutex::new(KnownHosts::load(data_dir.join("known_hosts"))?),
        host_key,
        trust,
    });
    let builder = RustlsClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let algorithm = identity.public_key.algorithm();
    let mut cfg = match identity.key {
        IdentityKey::File { private_key_der } => {
            let cert = self_signed_cert("hush-client", user, &private_key_der, &algorithm)?;
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key_der));
            builder.with_client_auth_cert(vec![cert], key)?
        }
        IdentityKey::Agent { socket, spki_der } => {
            let cert = self_signed_agent_cert("hush-client", user, &identity.public_key)?;
            let (scheme, signature_algorithm) = tls_signature_scheme(&algorithm)?;
            let key = AgentTlsSigningKey {
                socket,
                public_key: identity.public_key,
                spki_der,
                scheme,
                signature_algorithm,
            };
            let certified_key = CertifiedKey::new(vec![cert], Arc::new(key));
            builder.with_client_cert_resolver(Arc::new(SingleCertAndKey::from(certified_key)))
        }
    };
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    let mut quic_cfg = ClientConfig::new(Arc::new(QuicClientConfig::try_from(cfg)?));
    quic_cfg.transport_config(Arc::new(long_idle_transport(
        Some(QUIC_CLIENT_KEEP_ALIVE_INTERVAL),
        profile,
    )?));
    Ok(quic_cfg)
}

pub fn make_server_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig> {
    let provider = pq_provider();
    let mut cfg = RustlsServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(AuthorizedClientVerifier {
            provider: pq_provider(),
        }))
        .with_single_cert(vec![cert], key)?;
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    let mut quic_cfg = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(cfg)?));
    quic_cfg.transport = Arc::new(long_idle_transport(None, TransportProfile::Interactive)?);
    Ok(quic_cfg)
}

pub fn load_or_create_host_cert(
    data_dir: &Path,
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let server_dir = crate::paths::server_dir(data_dir);
    ensure_private_dir(&server_dir)?;
    let cert_path = cert_path
        .map(Path::to_owned)
        .unwrap_or_else(|| server_dir.join("host_cert.der"));
    let key_path = key_path
        .map(Path::to_owned)
        .unwrap_or_else(|| server_dir.join("host_key.der"));
    if cert_path.exists() && key_path.exists() {
        return Ok((
            CertificateDer::from(fs::read(cert_path)?),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fs::read(key_path)?)),
        ));
    }
    let signing_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let key_der = signing_key.serialize_der();
    let cert =
        rcgen::CertificateParams::new(vec!["hush-server".to_owned()])?.self_signed(&signing_key)?;
    write_private_file_atomic(&cert_path, cert.der().as_ref())?;
    write_private_file_atomic(&key_path, &key_der)?;
    Ok((
        cert.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
    ))
}

pub fn host_key(host: &str, port: u16) -> String {
    format!("{host}:{port}")
}

pub fn host_key_from_addr(host: &str, addr: SocketAddr) -> String {
    host_key(host, addr.port())
}

/// Parameters for a synthetic client certificate: the key travels in the
/// SubjectPublicKeyInfo and the username in a private extension. Both are
/// covered by the client's live handshake signature, so the server can
/// authenticate the connection from the TLS handshake alone, with no
/// application-level round trip.
fn client_cert_params(name: &str, user: &str) -> Result<rcgen::CertificateParams> {
    let mut params = rcgen::CertificateParams::new(vec![name.to_owned()])?;
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            auth::HUSH_USERNAME_OID,
            auth::encode_username_extension(user)?,
        ));
    Ok(params)
}

fn self_signed_cert(
    name: &str,
    user: &str,
    pkcs8_der: &[u8],
    algorithm: &Algorithm,
) -> Result<CertificateDer<'static>> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der.to_vec()));
    let key = rcgen::KeyPair::from_der_and_sign_algo(&key, rcgen_algorithm(algorithm)?)?;
    let cert = client_cert_params(name, user)?.self_signed(&key)?;
    Ok(cert.der().clone())
}

fn self_signed_agent_cert(
    name: &str,
    user: &str,
    public_key: &ssh_key::PublicKey,
) -> Result<CertificateDer<'static>> {
    // The certificate only needs to *carry* the agent's public key: the server
    // extracts it and authenticates the live TLS handshake signature, never the
    // certificate's own signature. So we emit the certificate with an empty
    // signature rather than asking the agent to sign its body — that would be a
    // second agent round-trip (and a second confirmation prompt on touch-to-sign
    // hardware keys) for something nobody verifies.
    let key = UnsignedAgentCertKey {
        raw_public_key: auth::raw_public_key_bytes(public_key)?,
        algorithm: rcgen_algorithm(&public_key.algorithm())?,
    };
    let cert = client_cert_params(name, user)?.self_signed(&key)?;
    Ok(cert.der().clone())
}

/// Carries the agent's public key into a certificate's SubjectPublicKeyInfo and
/// emits an empty signature. The certificate's signature is never verified (see
/// [`self_signed_agent_cert`]), so there is nothing to sign.
struct UnsignedAgentCertKey {
    raw_public_key: Vec<u8>,
    algorithm: &'static rcgen::SignatureAlgorithm,
}

impl rcgen::PublicKeyData for UnsignedAgentCertKey {
    fn der_bytes(&self) -> &[u8] {
        &self.raw_public_key
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        self.algorithm
    }
}

impl rcgen::SigningKey for UnsignedAgentCertKey {
    fn sign(&self, _msg: &[u8]) -> std::result::Result<Vec<u8>, rcgen::Error> {
        Ok(Vec::new())
    }
}

#[derive(Clone)]
struct AgentTlsSigningKey {
    socket: PathBuf,
    public_key: ssh_key::PublicKey,
    spki_der: Vec<u8>,
    scheme: SignatureScheme,
    signature_algorithm: SignatureAlgorithm,
}

impl fmt::Debug for AgentTlsSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentTlsSigningKey").finish_non_exhaustive()
    }
}

impl SigningKey for AgentTlsSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&self.scheme)
            .then(|| Box::new(AgentTlsSigner(self.clone())) as Box<dyn Signer>)
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(self.spki_der.as_slice()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.signature_algorithm
    }
}

#[derive(Clone)]
struct AgentTlsSigner(AgentTlsSigningKey);

impl fmt::Debug for AgentTlsSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentTlsSigner").finish_non_exhaustive()
    }
}

impl Signer for AgentTlsSigner {
    fn sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, RustlsError> {
        auth::agent_sign(&self.0.socket, &self.0.public_key, message)
            .map_err(|err| RustlsError::General(format!("ssh-agent signing failed: {err}")))
    }

    fn scheme(&self) -> SignatureScheme {
        self.0.scheme
    }
}

/// The rcgen signature algorithm matching an SSH key type, used to self-sign
/// the client certificate that carries the key's public key.
fn rcgen_algorithm(algorithm: &Algorithm) -> Result<&'static rcgen::SignatureAlgorithm> {
    Ok(match algorithm {
        Algorithm::Ed25519 => &rcgen::PKCS_ED25519,
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        } => &rcgen::PKCS_ECDSA_P256_SHA256,
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        } => &rcgen::PKCS_ECDSA_P384_SHA384,
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP521,
        } => &rcgen::PKCS_ECDSA_P521_SHA512,
        other => bail!("unsupported SSH key type {other}"),
    })
}

/// The TLS 1.3 signature scheme (and its algorithm family) for an SSH key type,
/// used when an ssh-agent performs the handshake signature.
fn tls_signature_scheme(algorithm: &Algorithm) -> Result<(SignatureScheme, SignatureAlgorithm)> {
    Ok(match algorithm {
        Algorithm::Ed25519 => (SignatureScheme::ED25519, SignatureAlgorithm::ED25519),
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        } => (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureAlgorithm::ECDSA,
        ),
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        } => (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureAlgorithm::ECDSA,
        ),
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP521,
        } => (
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureAlgorithm::ECDSA,
        ),
        other => bail!("unsupported SSH key type {other}"),
    })
}

fn pq_provider() -> CryptoProvider {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    provider
}

fn long_idle_transport(
    keep_alive_interval: Option<Duration>,
    profile: TransportProfile,
) -> Result<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(7 * 24 * 60 * 60).try_into()?));
    transport.keep_alive_interval(keep_alive_interval);
    transport.send_window(QUIC_FAST_SEND_WINDOW);
    transport.stream_receive_window(VarInt::from_u32(QUIC_FAST_STREAM_RECV_WINDOW));
    transport.receive_window(VarInt::from_u32(QUIC_FAST_CONN_RECV_WINDOW));
    transport.packet_threshold(match profile {
        TransportProfile::Interactive => QUIC_FAST_PACKET_THRESHOLD,
        // Wi-Fi block acknowledgement reorders packets routinely; leave real
        // loss to the time threshold rather than reacting to reordering.
        TransportProfile::Bulk => QUIC_BULK_PACKET_THRESHOLD,
    });
    transport.time_threshold(match profile {
        TransportProfile::Interactive => QUIC_FAST_TIME_THRESHOLD,
        // Declaring a packet lost costs a bulk flow a congestion window cut
        // and seconds of regrowth, so use the RFC 9002 margin over links that
        // jitter, such as Wi-Fi with frame aggregation.
        TransportProfile::Bulk => QUIC_BULK_TIME_THRESHOLD,
    });
    transport.initial_rtt(QUIC_FAST_INITIAL_RTT);
    transport.ack_frequency_config(Some(ack_frequency_config(profile)));
    transport.persistent_congestion_threshold(10);
    let mut mtu_discovery = MtuDiscoveryConfig::default();
    // Lossy links (Wi-Fi, mobile) drop full-size packets in bursts that look
    // exactly like an MTU black hole, and quinn then pins the MTU at the
    // 1200-byte floor until the cooldown passes. Probing is nearly free, so
    // recover quickly instead of paying 20% more packets per byte for a minute.
    mtu_discovery.black_hole_cooldown(QUIC_MTU_BLACK_HOLE_COOLDOWN);
    // Ethernet MTU minus IPv4 and UDP headers. IPv6 paths settle at 1452.
    mtu_discovery.upper_bound(QUIC_MTU_UPPER_BOUND);
    transport.mtu_discovery_config(Some(mtu_discovery));
    transport.congestion_controller_factory(congestion_controller(profile));
    Ok(transport)
}

fn ack_frequency_config(profile: TransportProfile) -> AckFrequencyConfig {
    let mut ack_frequency = AckFrequencyConfig::default();
    match profile {
        TransportProfile::Interactive => {
            ack_frequency.ack_eliciting_threshold(VarInt::from_u32(0));
            ack_frequency.max_ack_delay(Some(QUIC_FAST_ACK_DELAY));
        }
        TransportProfile::Bulk => {
            ack_frequency
                .ack_eliciting_threshold(VarInt::from_u32(QUIC_BULK_ACK_ELICITING_THRESHOLD));
            ack_frequency.max_ack_delay(Some(QUIC_BULK_ACK_DELAY));
        }
    }
    ack_frequency.reordering_threshold(VarInt::from_u32(match profile {
        TransportProfile::Interactive => QUIC_FAST_PACKET_THRESHOLD - 1,
        TransportProfile::Bulk => QUIC_BULK_PACKET_THRESHOLD - 1,
    }));
    ack_frequency
}

fn congestion_controller(profile: TransportProfile) -> Arc<dyn ControllerFactory + Send + Sync> {
    match profile {
        TransportProfile::Interactive => Arc::new(BbrConfig::default()),
        TransportProfile::Bulk => Arc::new(CubicConfig::default()),
    }
}

/// Retune an established connection for a bulk transfer. Servers accept every
/// connection with the interactive profile because they learn what a
/// connection is for only once the client opens its first stream.
pub fn switch_to_bulk(conn: &quinn::Connection) {
    conn.set_congestion_controller(congestion_controller(TransportProfile::Bulk));
    conn.set_ack_frequency_config(Some(ack_frequency_config(TransportProfile::Bulk)));
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn write_private_file_atomic(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("hush");
    for _ in 0..32 {
        let mut nonce = [0u8; 12];
        aws_lc_rs::rand::fill(&mut nonce)
            .map_err(|_| anyhow::anyhow!("generate temporary filename"))?;
        let tmp = parent.join(format!(".{name}.{}.tmp", hex::encode(nonce)));
        let file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&tmp);
        let mut file = match file {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        };
        let result = (|| -> Result<()> {
            use std::io::Write;
            file.write_all(data)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&tmp, path)?;
            fs::File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        return result;
    }
    bail!("could not allocate a temporary file for {}", path.display())
}

struct ExclusiveFileLock(fs::File);

impl ExclusiveFileLock {
    fn acquire(path: &Path) -> Result<Self> {
        let file = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?;
        loop {
            // SAFETY: `file` owns a live descriptor for the duration of the lock.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                return Ok(Self(file));
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err.into());
            }
        }
    }
}

impl Drop for ExclusiveFileLock {
    fn drop(&mut self) {
        // SAFETY: the descriptor remains live until after Drop returns.
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn lock_path_for(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("hush");
    path.with_file_name(format!(".{name}.lock"))
}

#[derive(Debug)]
struct TofuServerVerifier {
    provider: CryptoProvider,
    known_hosts: Mutex<KnownHosts>,
    host_key: String,
    trust: HostTrust,
}

impl ServerCertVerifier for TofuServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let fp = auth::cert_fingerprint(end_entity.as_ref());
        self.known_hosts
            .lock()
            .map_err(|_| RustlsError::General("known_hosts lock poisoned".into()))?
            .check_or_insert(&self.host_key, &fp, self.trust)
            .map_err(|e| RustlsError::General(e.to_string()))?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
struct AuthorizedClientVerifier {
    provider: CryptoProvider,
}

impl ClientCertVerifier for AuthorizedClientVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        auth::public_key_from_cert_der(end_entity.as_ref())
            .map_err(|e| RustlsError::General(e.to_string()))?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn known_hosts_saves_host_hash_map() {
        let path = temp_known_hosts_path("new");

        let mut known_hosts = KnownHosts::load(&path).unwrap();
        known_hosts
            .check_or_insert("example.com:4433", "SHA256:abc123", HostTrust::Tofu)
            .unwrap();

        let data = fs::read_to_string(&path).unwrap();
        assert!(data.contains("[hosts]"));
        assert!(data.contains("\"example.com:4433\" = \"SHA256:abc123\""));
    }

    #[test]
    fn known_hosts_known_only_rejects_new_hosts_without_saving() {
        let path = temp_known_hosts_path("known-only");

        let mut known_hosts = KnownHosts::load(&path).unwrap();
        known_hosts
            .check_or_insert("example.com:4433", "SHA256:abc123", HostTrust::KnownOnly)
            .unwrap_err();
        assert!(!path.exists());

        known_hosts
            .check_or_insert("example.com:4433", "SHA256:abc123", HostTrust::Tofu)
            .unwrap();
        known_hosts
            .check_or_insert("example.com:4433", "SHA256:abc123", HostTrust::KnownOnly)
            .unwrap();
    }

    #[test]
    fn known_hosts_rejects_legacy_line_format() {
        let path = temp_known_hosts_path("legacy");
        fs::write(&path, "example.com:4433 SHA256:abc123\n").unwrap();

        let err = KnownHosts::load(&path).unwrap_err();
        assert!(err.to_string().contains("parse"));
    }

    #[test]
    fn known_hosts_loads_hash_only_format() {
        let path = temp_known_hosts_path("hash-only");
        fs::write(
            &path,
            r#"
[hosts]
"example.com:4433" = "SHA256:abc123"
"#,
        )
        .unwrap();

        let mut known_hosts = KnownHosts::load(&path).unwrap();
        known_hosts
            .check_or_insert("example.com:4433", "SHA256:abc123", HostTrust::Tofu)
            .unwrap();
    }

    #[test]
    fn known_hosts_merges_stale_process_snapshots() {
        let path = temp_known_hosts_path("merge");
        let mut first = KnownHosts::load(&path).unwrap();
        let mut stale = KnownHosts::load(&path).unwrap();

        first
            .check_or_insert("first.example:22022", "SHA256:first", HostTrust::Tofu)
            .unwrap();
        stale
            .check_or_insert("second.example:22022", "SHA256:second", HostTrust::Tofu)
            .unwrap();

        let merged = KnownHosts::load(&path).unwrap();
        assert_eq!(merged.entries.len(), 2);
        assert_eq!(merged.entries["first.example:22022"], "SHA256:first");
        assert_eq!(merged.entries["second.example:22022"], "SHA256:second");
    }

    #[test]
    fn known_hosts_stale_snapshot_cannot_replace_a_new_pin() {
        let path = temp_known_hosts_path("pin-race");
        let mut first = KnownHosts::load(&path).unwrap();
        let mut stale = KnownHosts::load(&path).unwrap();

        first
            .check_or_insert("example.com:22022", "SHA256:first", HostTrust::Tofu)
            .unwrap();
        let err = stale
            .check_or_insert("example.com:22022", "SHA256:second", HostTrust::Tofu)
            .unwrap_err();

        assert!(err.to_string().contains("host certificate mismatch"));
        assert_eq!(
            KnownHosts::load(&path).unwrap().entries["example.com:22022"],
            "SHA256:first"
        );
    }

    fn temp_known_hosts_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("hush-known-hosts-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }
}
