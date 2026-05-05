use crate::{
    ALPN,
    auth::{self, IdentityKey},
};
use anyhow::{Result, bail};
use quinn::TransportConfig;
use quinn::{ClientConfig, ServerConfig};
use quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
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
use std::{
    collections::HashMap,
    fmt, fs,
    net::SocketAddr,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Debug, Clone)]
pub struct KnownHosts {
    path: PathBuf,
    entries: HashMap<String, String>,
}

impl KnownHosts {
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let mut entries = HashMap::new();
        if let Ok(data) = fs::read_to_string(&path) {
            for line in data.lines() {
                let mut parts = line.split_whitespace();
                let Some(host) = parts.next() else { continue };
                let Some(fp) = parts.next() else { continue };
                entries.insert(host.to_owned(), fp.to_owned());
            }
        }
        Ok(Self { path, entries })
    }

    pub fn check_or_insert(&mut self, host: &str, fingerprint: &str, insecure: bool) -> Result<()> {
        if insecure {
            return Ok(());
        }
        match self.entries.get(host) {
            Some(old) if old == fingerprint => Ok(()),
            Some(old) => bail!(
                "host certificate mismatch for {host}: known {old}, got {fingerprint}; use -k to bypass"
            ),
            None => {
                self.entries.insert(host.to_owned(), fingerprint.to_owned());
                self.save()
            }
        }
    }

    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            ensure_private_dir(parent)?;
        }
        let mut data = String::new();
        for (host, fp) in &self.entries {
            data.push_str(host);
            data.push(' ');
            data.push_str(fp);
            data.push('\n');
        }
        write_private_file_atomic(&self.path, data.as_bytes())?;
        Ok(())
    }
}

pub fn make_client_config(
    data_dir: &Path,
    host_key: String,
    identity: auth::LoadedIdentity,
    insecure: bool,
) -> Result<ClientConfig> {
    let provider = pq_provider();
    let verifier = Arc::new(TofuServerVerifier {
        provider: provider.clone(),
        known_hosts: Mutex::new(KnownHosts::load(data_dir.join("known_hosts"))?),
        host_key,
        insecure,
    });
    let builder = RustlsClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut cfg = match identity.key {
        IdentityKey::File { private_key_der } => {
            let cert = self_signed_cert("hush-client", &private_key_der)?;
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key_der));
            builder.with_client_auth_cert(vec![cert], key)?
        }
        IdentityKey::Agent { socket, spki_der } => {
            let cert = self_signed_agent_cert("hush-client", &identity.public_key, &socket)?;
            let key = AgentTlsSigningKey {
                socket,
                public_key: identity.public_key,
                spki_der,
            };
            let certified_key = CertifiedKey::new(vec![cert], Arc::new(key));
            builder.with_client_cert_resolver(Arc::new(SingleCertAndKey::from(certified_key)))
        }
    };
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    let mut quic_cfg = ClientConfig::new(Arc::new(QuicClientConfig::try_from(cfg)?));
    quic_cfg.transport_config(Arc::new(long_idle_transport()?));
    Ok(quic_cfg)
}

pub fn make_server_config(
    data_dir: &Path,
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
) -> Result<ServerConfig> {
    let provider = pq_provider();
    let (cert, key) = load_or_create_host_cert(data_dir, cert_path, key_path)?;
    let mut cfg = RustlsServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(AuthorizedClientVerifier {
            provider: pq_provider(),
        }))
        .with_single_cert(vec![cert], key)?;
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    let mut quic_cfg = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(cfg)?));
    quic_cfg.transport = Arc::new(long_idle_transport()?);
    Ok(quic_cfg)
}

pub fn load_or_create_host_cert(
    data_dir: &Path,
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    ensure_private_dir(data_dir)?;
    let cert_path = cert_path
        .map(Path::to_owned)
        .unwrap_or_else(|| data_dir.join("host_cert.der"));
    let key_path = key_path
        .map(Path::to_owned)
        .unwrap_or_else(|| data_dir.join("host_key.der"));
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

fn self_signed_cert(name: &str, pkcs8_der: &[u8]) -> Result<CertificateDer<'static>> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der.to_vec()));
    let key = rcgen::KeyPair::from_der_and_sign_algo(&key, &rcgen::PKCS_ED25519)?;
    let cert = rcgen::CertificateParams::new(vec![name.to_owned()])?.self_signed(&key)?;
    Ok(cert.der().clone())
}

fn self_signed_agent_cert(
    name: &str,
    public_key: &ssh_key::PublicKey,
    socket: &Path,
) -> Result<CertificateDer<'static>> {
    let key = AgentRcgenSigningKey {
        socket: socket.to_owned(),
        public_key: public_key.clone(),
        raw_public_key: auth::ed25519_public_key_bytes(public_key)?.to_vec(),
    };
    let cert = rcgen::CertificateParams::new(vec![name.to_owned()])?.self_signed(&key)?;
    Ok(cert.der().clone())
}

struct AgentRcgenSigningKey {
    socket: PathBuf,
    public_key: ssh_key::PublicKey,
    raw_public_key: Vec<u8>,
}

impl fmt::Debug for AgentRcgenSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentRcgenSigningKey")
            .finish_non_exhaustive()
    }
}

impl rcgen::PublicKeyData for AgentRcgenSigningKey {
    fn der_bytes(&self) -> &[u8] {
        &self.raw_public_key
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ED25519
    }
}

impl rcgen::SigningKey for AgentRcgenSigningKey {
    fn sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, rcgen::Error> {
        auth::agent_sign(&self.socket, &self.public_key, msg)
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}

#[derive(Clone)]
struct AgentTlsSigningKey {
    socket: PathBuf,
    public_key: ssh_key::PublicKey,
    spki_der: Vec<u8>,
}

impl fmt::Debug for AgentTlsSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentTlsSigningKey").finish_non_exhaustive()
    }
}

impl SigningKey for AgentTlsSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ED25519)
            .then(|| Box::new(AgentTlsSigner(self.clone())) as Box<dyn Signer>)
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(self.spki_der.as_slice()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
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
        SignatureScheme::ED25519
    }
}

fn pq_provider() -> CryptoProvider {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    provider
}

fn long_idle_transport() -> Result<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(7 * 24 * 60 * 60).try_into()?));
    transport.keep_alive_interval(None);
    Ok(transport)
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
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension().and_then(|s| s.to_str()).unwrap_or("hush")
    ));
    {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)?;
        use std::io::Write;
        file.write_all(data)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[derive(Debug)]
struct TofuServerVerifier {
    provider: CryptoProvider,
    known_hosts: Mutex<KnownHosts>,
    host_key: String,
    insecure: bool,
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
            .check_or_insert(&self.host_key, &fp, self.insecure)
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
