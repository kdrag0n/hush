use crate::{ALPN, auth};
use anyhow::{Result, bail};
use quinn::{ClientConfig, ServerConfig};
use quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::{
    ClientConfig as RustlsClientConfig, DigitallySignedStruct, Error as RustlsError,
    ServerConfig as RustlsServerConfig, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use std::{
    collections::HashMap,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
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
            fs::create_dir_all(parent)?;
        }
        let mut data = String::new();
        for (host, fp) in &self.entries {
            data.push_str(host);
            data.push(' ');
            data.push_str(fp);
            data.push('\n');
        }
        fs::write(&self.path, data)?;
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
    let cert = self_signed_cert("hush-client", &identity.private_key_der)?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.private_key_der));
    let mut cfg = RustlsClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![cert], key)?;
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    Ok(ClientConfig::new(Arc::new(QuicClientConfig::try_from(
        cfg,
    )?)))
}

pub fn make_server_config(data_dir: &Path) -> Result<ServerConfig> {
    let provider = pq_provider();
    let (cert, key) = load_or_create_host_cert(data_dir)?;
    let mut cfg = RustlsServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(AuthorizedClientVerifier {
            provider: pq_provider(),
        }))
        .with_single_cert(vec![cert], key)?;
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    Ok(ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(cfg)?,
    )))
}

pub fn load_or_create_host_cert(
    data_dir: &Path,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    fs::create_dir_all(data_dir)?;
    let cert_path = data_dir.join("host_cert.der");
    let key_path = data_dir.join("host_key.der");
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
    fs::write(&cert_path, cert.der().as_ref())?;
    fs::write(&key_path, &key_der)?;
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

fn pq_provider() -> CryptoProvider {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    provider
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
