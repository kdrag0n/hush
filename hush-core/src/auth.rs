use anyhow::{Context, Result, bail};
use base64::Engine;
use sha2::{Digest, Sha256};
use ssh_key::{
    Algorithm, EcdsaCurve, PrivateKey, PublicKey, Signature,
    private::EcdsaKeypair,
    public::{EcdsaPublicKey, Ed25519PublicKey, KeyData},
};
use std::{
    env, fs,
    path::{Path, PathBuf},
};
use subtle::ConstantTimeEq;
use x509_parser::prelude::FromDer;

/// Default private key files to try, in order, when no `-i`/`IdentityFile` is
/// given and no agent key matches. Mirrors a subset of OpenSSH's defaults.
const DEFAULT_IDENTITY_FILES: &[&str] = &["id_ed25519", "id_ecdsa"];

const OID_ED25519: &str = "1.3.101.112";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";

/// SSH key algorithms hush can authenticate with: Ed25519 and the NIST ECDSA
/// curves (P-256/384/521).
fn is_supported_algorithm(algorithm: &Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::Ed25519
            | Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256 | EcdsaCurve::NistP384 | EcdsaCurve::NistP521,
            }
    )
}

#[derive(Debug, Clone)]
pub struct LoadedIdentity {
    pub public_key: PublicKey,
    pub key: IdentityKey,
}

#[derive(Debug, Clone)]
pub enum IdentityKey {
    Agent { socket: PathBuf, spki_der: Vec<u8> },
    File { private_key_der: Vec<u8> },
}

/// Where to look for an ssh-agent. `Default` uses `SSH_AUTH_SOCK`; `Socket`
/// pins an explicit path (from an `IdentityAgent` directive); `Disabled` skips
/// the agent entirely.
#[derive(Debug, Clone, Default)]
pub enum AgentSocket {
    #[default]
    Default,
    Socket(PathBuf),
    Disabled,
}

impl AgentSocket {
    fn resolve(&self) -> Option<PathBuf> {
        match self {
            AgentSocket::Default => env::var_os("SSH_AUTH_SOCK").map(PathBuf::from),
            AgentSocket::Socket(path) => Some(path.clone()),
            AgentSocket::Disabled => None,
        }
    }
}

pub fn load_identity() -> Result<LoadedIdentity> {
    load_identity_with_options(None, &AgentSocket::Default)
}

pub fn load_identity_with_file(identity_file: Option<&Path>) -> Result<LoadedIdentity> {
    load_identity_with_options(identity_file, &AgentSocket::Default)
}

pub fn load_identity_with_options(
    identity_file: Option<&Path>,
    agent: &AgentSocket,
) -> Result<LoadedIdentity> {
    let socket = agent.resolve();
    if let Some(path) = identity_file {
        if let Some(socket) = &socket
            && let Some(identity) = load_identity_from_agent_matching_file(socket, path)?
        {
            return Ok(identity);
        }
        return load_identity_from_file(path);
    }
    if let Some(socket) = &socket
        && let Some(identity) = load_identity_from_agent(socket)?
    {
        return Ok(identity);
    }
    let ssh_dir = crate::paths::current_home().join(".ssh");
    let path = DEFAULT_IDENTITY_FILES
        .iter()
        .map(|name| ssh_dir.join(name))
        .find(|path| path.exists())
        .unwrap_or_else(|| ssh_dir.join(DEFAULT_IDENTITY_FILES[0]));
    load_identity_from_file(&path)
}

fn load_identity_from_agent(socket: &Path) -> Result<Option<LoadedIdentity>> {
    let socket = socket.to_path_buf();
    let mut client = match ssh_agent_client_rs::Client::connect(&socket) {
        Ok(client) => client,
        Err(err) => {
            tracing::debug!(%err, "failed to connect to ssh-agent");
            return Ok(None);
        }
    };
    let identities = client
        .list_all_identities()
        .context("list ssh-agent identities")?;
    let preferred = preferred_public_key();
    for identity in identities {
        let ssh_agent_client_rs::Identity::PublicKey(public_key) = identity else {
            continue;
        };
        let public_key = public_key.into_owned();
        if !is_supported_algorithm(&public_key.algorithm()) {
            continue;
        }
        if let Some(preferred) = &preferred {
            if !same_public_key(&public_key, preferred)? {
                continue;
            }
        }
        let spki_der = public_key_to_spki(&public_key)?;
        tracing::debug!(algorithm = %public_key.algorithm(), "using identity from ssh-agent");
        return Ok(Some(LoadedIdentity {
            public_key,
            key: IdentityKey::Agent { socket, spki_der },
        }));
    }
    Ok(None)
}

fn load_identity_from_agent_matching_file(
    socket: &Path,
    path: &Path,
) -> Result<Option<LoadedIdentity>> {
    let public_path = public_key_path_for_private_key(path);
    let preferred = fs::read_to_string(&public_path)
        .ok()
        .and_then(|data| PublicKey::from_openssh(&data).ok());
    let Some(preferred) = preferred else {
        return Ok(None);
    };
    load_identity_from_agent_matching(socket, &preferred)
}

fn load_identity_from_agent_matching(
    socket: &Path,
    preferred: &PublicKey,
) -> Result<Option<LoadedIdentity>> {
    let socket = socket.to_path_buf();
    let mut client = match ssh_agent_client_rs::Client::connect(&socket) {
        Ok(client) => client,
        Err(err) => {
            tracing::debug!(%err, "failed to connect to ssh-agent");
            return Ok(None);
        }
    };
    let identities = client
        .list_all_identities()
        .context("list ssh-agent identities")?;
    for identity in identities {
        let ssh_agent_client_rs::Identity::PublicKey(public_key) = identity else {
            continue;
        };
        let public_key = public_key.into_owned();
        if !is_supported_algorithm(&public_key.algorithm())
            || !same_public_key(&public_key, preferred)?
        {
            continue;
        }
        let spki_der = public_key_to_spki(&public_key)?;
        tracing::debug!(algorithm = %public_key.algorithm(), "using matching identity from ssh-agent");
        return Ok(Some(LoadedIdentity {
            public_key,
            key: IdentityKey::Agent { socket, spki_der },
        }));
    }
    Ok(None)
}

pub fn load_identity_from_file(path: &Path) -> Result<LoadedIdentity> {
    let pem =
        fs::read(path).with_context(|| format!("read OpenSSH private key {}", path.display()))?;
    match PrivateKey::from_openssh(&pem) {
        Ok(key) => {
            if !key.is_encrypted() {
                return identity_from_private_key(&key);
            }
            let pass =
                rpassword::prompt_password(format!("Enter passphrase for {}: ", path.display()))?;
            match key.decrypt(&pass) {
                Ok(decrypted) => identity_from_private_key(&decrypted),
                // ssh-key 0.6 mis-decodes some ECDSA scalars (see
                // `ecdsa_identity_from_section`); retry those ourselves.
                Err(_) if is_ecdsa(&key.public_key().algorithm()) => {
                    ecdsa_identity_from_encrypted(&key, &pass)
                        .with_context(|| format!("decrypt private key {}", path.display()))
                }
                Err(decrypt_err) => Err(anyhow::Error::new(decrypt_err))
                    .with_context(|| format!("decrypt private key {}", path.display())),
            }
        }
        // ssh-key rejects some valid unencrypted ECDSA keys; fall back to our
        // own parser before surfacing the original error.
        Err(parse_err) => ecdsa_identity_from_unencrypted(&pem).map_err(|fallback_err| {
            tracing::debug!(%fallback_err, "lenient ECDSA parse failed");
            anyhow::Error::new(parse_err)
                .context(format!("read OpenSSH private key {}", path.display()))
        }),
    }
}

fn identity_from_private_key(key: &PrivateKey) -> Result<LoadedIdentity> {
    let private_key_der = if let Some(keypair) = key.key_data().ed25519() {
        ed25519_seed_to_pkcs8_der(keypair.private.as_ref())
    } else if let Some(keypair) = key.key_data().ecdsa() {
        ecdsa_keypair_to_pkcs8_der(keypair)?
    } else {
        bail!(
            "unsupported SSH key type {}; hush supports Ed25519 and ECDSA (P-256/384/521)",
            key.algorithm()
        );
    };
    Ok(LoadedIdentity {
        public_key: key.public_key().clone(),
        key: IdentityKey::File { private_key_der },
    })
}

fn is_ecdsa(algorithm: &Algorithm) -> bool {
    matches!(algorithm, Algorithm::Ecdsa { .. })
}

pub fn agent_sign(socket: &Path, public_key: &PublicKey, message: &[u8]) -> Result<Vec<u8>> {
    let mut client = ssh_agent_client_rs::Client::connect(socket)
        .with_context(|| format!("connect ssh-agent {}", socket.display()))?;
    let sig = client
        .sign(public_key, message)
        .context("ssh-agent sign request")?;
    signature_to_tls_bytes(&sig)
}

/// Convert an ssh-agent signature into the raw form rustls/TLS expects. Ed25519
/// signatures are already in the right form; ECDSA signatures arrive in the SSH
/// `mpint r, mpint s` encoding and must be re-encoded as ASN.1 DER.
fn signature_to_tls_bytes(sig: &Signature) -> Result<Vec<u8>> {
    match sig.algorithm() {
        Algorithm::Ed25519 => Ok(sig.as_bytes().to_vec()),
        Algorithm::Ecdsa { curve } => ecdsa_signature_to_der(sig, curve),
        other => bail!("ssh-agent returned unsupported signature type {other}"),
    }
}

fn ecdsa_signature_to_der(sig: &Signature, curve: EcdsaCurve) -> Result<Vec<u8>> {
    Ok(match curve {
        EcdsaCurve::NistP256 => p256::ecdsa::Signature::try_from(sig)
            .context("decode P-256 signature")?
            .to_der()
            .as_bytes()
            .to_vec(),
        EcdsaCurve::NistP384 => p384::ecdsa::Signature::try_from(sig)
            .context("decode P-384 signature")?
            .to_der()
            .as_bytes()
            .to_vec(),
        EcdsaCurve::NistP521 => p521::ecdsa::Signature::try_from(sig)
            .context("decode P-521 signature")?
            .to_der()
            .as_bytes()
            .to_vec(),
    })
}

pub fn public_key_from_cert_der(cert_der: &[u8]) -> Result<PublicKey> {
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der)
        .context("parse peer certificate")?;
    let spki = cert.public_key();
    let raw = spki.subject_public_key.data.as_ref();
    let oid = spki.algorithm.algorithm.to_id_string();
    let key_data = match oid.as_str() {
        OID_ED25519 => {
            let ed = Ed25519PublicKey::try_from(raw).context("extract Ed25519 public key")?;
            KeyData::Ed25519(ed)
        }
        OID_EC_PUBLIC_KEY => {
            let ec = EcdsaPublicKey::from_sec1_bytes(raw).context("extract ECDSA public key")?;
            KeyData::Ecdsa(ec)
        }
        other => bail!("unsupported peer certificate key type (OID {other})"),
    };
    Ok(PublicKey::new(key_data, "hush-client"))
}

pub fn cert_fingerprint(cert_der: &[u8]) -> String {
    let digest = Sha256::digest(cert_der);
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    )
}

pub fn public_key_fingerprint(key: &PublicKey) -> Result<String> {
    let bytes = key.to_bytes().context("serialize public key")?;
    let digest = Sha256::digest(bytes);
    Ok(format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    ))
}

pub fn authorized_keys_for_user(user: &str) -> Result<PathBuf> {
    let home = home_for_user(user)?.context("user has no home directory")?;
    Ok(crate::paths::ssh_dir_for_home(home).join("authorized_keys"))
}

pub fn is_authorized(user: &str, key: &PublicKey, override_path: Option<&Path>) -> Result<bool> {
    let path = match override_path {
        Some(path) => path.to_owned(),
        None => authorized_keys_for_user(user)?,
    };
    let Ok(data) = fs::read_to_string(&path) else {
        return Ok(false);
    };
    let wanted = key.to_bytes().context("serialize peer public key")?;
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parsed = PublicKey::from_openssh(line);
        if let Ok(candidate) = parsed {
            if is_supported_algorithm(&candidate.algorithm())
                && candidate
                    .to_bytes()
                    .ok()
                    .is_some_and(|candidate| same_public_key_bytes(&candidate, &wanted))
            {
                return Ok(true);
            }
            continue;
        }

        // The line didn't parse as a bare key; it may carry leading options
        // (e.g. `command="..." ssh-ed25519 AAAA...`). Look for the wanted key's
        // type prefix and re-parse from there.
        let prefix = format!("{} ", key.algorithm().as_str());
        if let Some(key_start) = line.find(&prefix) {
            let candidate_line = &line[key_start..];
            if let Ok(candidate) = PublicKey::from_openssh(candidate_line) {
                if candidate
                    .to_bytes()
                    .ok()
                    .is_some_and(|candidate| same_public_key_bytes(&candidate, &wanted))
                {
                    bail!(
                        "{} contains options for a matching key; authorized_keys options are not supported yet",
                        path.display()
                    );
                }
            }
        }
    }
    Ok(false)
}

pub fn current_username() -> String {
    crate::os::current_username()
}

pub fn can_login_as(user: &str) -> bool {
    crate::os::is_root() || user == current_username()
}

pub fn home_for_user(user: &str) -> Result<Option<PathBuf>> {
    crate::os::home_for_user(user)
}

fn ed25519_seed_to_pkcs8_der(seed: &[u8; 32]) -> Vec<u8> {
    let mut der = hex::decode("302e020100300506032b657004220420").expect("valid pkcs8 prefix");
    der.extend_from_slice(seed);
    der
}

pub fn ed25519_public_key_to_spki(public_key: &PublicKey) -> Result<Vec<u8>> {
    let raw = ed25519_public_key_bytes(public_key)?;
    let mut der = hex::decode("302a300506032b6570032100").expect("valid spki prefix");
    der.extend_from_slice(raw);
    Ok(der)
}

pub fn ed25519_public_key_bytes(public_key: &PublicKey) -> Result<&[u8; 32]> {
    match public_key.key_data() {
        KeyData::Ed25519(key) => Ok(key.as_ref()),
        _ => bail!("expected an Ed25519 public key, got {}", public_key.algorithm()),
    }
}

/// The X.509 SubjectPublicKeyInfo (SPKI) DER for a supported public key. Used to
/// describe an ssh-agent key to rustls without holding the private key.
pub fn public_key_to_spki(public_key: &PublicKey) -> Result<Vec<u8>> {
    match public_key.key_data() {
        KeyData::Ed25519(_) => ed25519_public_key_to_spki(public_key),
        KeyData::Ecdsa(ecdsa) => ecdsa_public_key_to_spki(ecdsa),
        _ => bail!("unsupported SSH key type {}", public_key.algorithm()),
    }
}

/// The raw public key bytes embedded in a certificate's SPKI: the 32-byte point
/// for Ed25519, or the SEC1-encoded curve point for ECDSA.
pub fn raw_public_key_bytes(public_key: &PublicKey) -> Result<Vec<u8>> {
    match public_key.key_data() {
        KeyData::Ed25519(key) => Ok(key.as_ref().to_vec()),
        KeyData::Ecdsa(key) => Ok(key.as_sec1_bytes().to_vec()),
        _ => bail!("unsupported SSH key type {}", public_key.algorithm()),
    }
}

fn ecdsa_public_key_to_spki(key: &EcdsaPublicKey) -> Result<Vec<u8>> {
    use p256::pkcs8::EncodePublicKey;
    let sec1 = key.as_sec1_bytes();
    let der = match key {
        EcdsaPublicKey::NistP256(_) => p256::PublicKey::from_sec1_bytes(sec1)
            .context("decode P-256 public key")?
            .to_public_key_der()
            .context("encode P-256 SPKI")?,
        EcdsaPublicKey::NistP384(_) => p384::PublicKey::from_sec1_bytes(sec1)
            .context("decode P-384 public key")?
            .to_public_key_der()
            .context("encode P-384 SPKI")?,
        EcdsaPublicKey::NistP521(_) => p521::PublicKey::from_sec1_bytes(sec1)
            .context("decode P-521 public key")?
            .to_public_key_der()
            .context("encode P-521 SPKI")?,
    };
    Ok(der.as_bytes().to_vec())
}

fn ecdsa_keypair_to_pkcs8_der(keypair: &EcdsaKeypair) -> Result<Vec<u8>> {
    let (curve, scalar) = match keypair {
        EcdsaKeypair::NistP256 { private, .. } => (EcdsaCurve::NistP256, private.as_slice()),
        EcdsaKeypair::NistP384 { private, .. } => (EcdsaCurve::NistP384, private.as_slice()),
        EcdsaKeypair::NistP521 { private, .. } => (EcdsaCurve::NistP521, private.as_slice()),
    };
    ecdsa_scalar_to_pkcs8_der(curve, scalar)
}

fn ecdsa_scalar_to_pkcs8_der(curve: EcdsaCurve, scalar: &[u8]) -> Result<Vec<u8>> {
    use p256::pkcs8::EncodePrivateKey;
    let der = match curve {
        EcdsaCurve::NistP256 => p256::SecretKey::from_slice(scalar)
            .context("decode P-256 private key")?
            .to_pkcs8_der()
            .context("encode P-256 PKCS#8")?,
        EcdsaCurve::NistP384 => p384::SecretKey::from_slice(scalar)
            .context("decode P-384 private key")?
            .to_pkcs8_der()
            .context("encode P-384 PKCS#8")?,
        EcdsaCurve::NistP521 => p521::SecretKey::from_slice(scalar)
            .context("decode P-521 private key")?
            .to_pkcs8_der()
            .context("encode P-521 PKCS#8")?,
    };
    Ok(der.as_bytes().to_vec())
}

fn preferred_public_key() -> Option<PublicKey> {
    let ssh_dir = crate::paths::current_home().join(".ssh");
    for name in DEFAULT_IDENTITY_FILES {
        let path = ssh_dir.join(format!("{name}.pub"));
        if let Ok(data) = fs::read_to_string(&path)
            && let Ok(key) = PublicKey::from_openssh(&data)
        {
            return Some(key);
        }
    }
    None
}

fn same_public_key(a: &PublicKey, b: &PublicKey) -> Result<bool> {
    Ok(same_public_key_bytes(&a.to_bytes()?, &b.to_bytes()?))
}

fn same_public_key_bytes(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

fn public_key_path_for_private_key(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".pub");
    PathBuf::from(s)
}

// ---------------------------------------------------------------------------
// Lenient ECDSA private key parsing.
//
// ssh-key 0.6 decodes the ECDSA private scalar as a fixed-size field and rejects
// SSH `mpint`s whose leading zero bytes were stripped during encoding. That
// happens for roughly half of all P-521 keys (and occasionally P-256/384), so we
// parse the OpenSSH private key format ourselves and rebuild the scalar with the
// correct zero-padding. We reuse ssh-key for the public key, cipher and KDF, so
// no cryptographic primitives are reimplemented here.
// ---------------------------------------------------------------------------

const OPENSSH_AUTH_MAGIC: &[u8] = b"openssh-key-v1\0";

/// Minimal reader for the SSH wire format (`uint32` and length-prefixed strings).
struct SshReader<'a> {
    buf: &'a [u8],
}

impl<'a> SshReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() < n {
            bail!("truncated OpenSSH key");
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn string(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}

fn ecdsa_params_for_name(name: &[u8]) -> Option<(EcdsaCurve, usize)> {
    match name {
        b"ecdsa-sha2-nistp256" => Some((EcdsaCurve::NistP256, 32)),
        b"ecdsa-sha2-nistp384" => Some((EcdsaCurve::NistP384, 48)),
        b"ecdsa-sha2-nistp521" => Some((EcdsaCurve::NistP521, 66)),
        _ => None,
    }
}

/// Decode the base64 body of an `OPENSSH PRIVATE KEY` PEM file.
fn decode_openssh_pem(pem: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(pem).context("private key is not valid UTF-8")?;
    let mut body = String::new();
    let mut in_body = false;
    for line in text.lines() {
        let line = line.trim();
        match line {
            "-----BEGIN OPENSSH PRIVATE KEY-----" => in_body = true,
            "-----END OPENSSH PRIVATE KEY-----" => break,
            _ if in_body => body.push_str(line),
            _ => {}
        }
    }
    if !in_body {
        bail!("not an OpenSSH private key");
    }
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .context("decode OpenSSH key base64")
}

/// Parse an unencrypted OpenSSH private key file into a [`LoadedIdentity`],
/// tolerating the ECDSA scalar encoding ssh-key rejects.
fn ecdsa_identity_from_unencrypted(pem: &[u8]) -> Result<LoadedIdentity> {
    let blob = decode_openssh_pem(pem)?;
    let mut reader = SshReader::new(&blob);
    if reader.take(OPENSSH_AUTH_MAGIC.len())? != OPENSSH_AUTH_MAGIC {
        bail!("bad OpenSSH key magic");
    }
    let cipher = reader.string()?;
    let _kdfname = reader.string()?;
    let _kdfoptions = reader.string()?;
    if cipher != b"none" {
        bail!("encrypted key is not handled by the lenient parser");
    }
    let count = reader.u32()?;
    if count != 1 {
        bail!("expected exactly one key, found {count}");
    }
    let _public = reader.string()?;
    let private_section = reader.string()?;
    ecdsa_identity_from_section(private_section)
}

/// Decrypt an encrypted OpenSSH private key using ssh-key's cipher and KDF, then
/// parse the plaintext leniently.
fn ecdsa_identity_from_encrypted(key: &PrivateKey, password: &str) -> Result<LoadedIdentity> {
    let cipher = key.cipher();
    let (enc_key, iv) = key
        .kdf()
        .derive_key_and_iv(cipher, password)
        .context("derive key encryption key")?;
    let ciphertext = key.key_data().encrypted().context("key is not encrypted")?;
    let mut buffer = ciphertext.to_vec();
    cipher
        .decrypt(&enc_key, &iv, &mut buffer, None)
        .map_err(|_| anyhow::anyhow!("wrong passphrase or unsupported cipher"))?;
    ecdsa_identity_from_section(&buffer)
}

/// Parse the (decrypted) private section of an OpenSSH ECDSA key.
fn ecdsa_identity_from_section(section: &[u8]) -> Result<LoadedIdentity> {
    let mut reader = SshReader::new(section);
    let check1 = reader.u32()?;
    let check2 = reader.u32()?;
    if check1 != check2 {
        bail!("private key checkints do not match (wrong passphrase?)");
    }
    let name = reader.string()?;
    let Some((curve, size)) = ecdsa_params_for_name(name) else {
        bail!("not an ECDSA private key");
    };
    let _curve_name = reader.string()?;
    let point = reader.string()?;
    let scalar = reader.string()?;
    let comment = reader.string()?;

    let scalar = normalize_scalar(scalar, size)?;
    let private_key_der = ecdsa_scalar_to_pkcs8_der(curve, &scalar)?;
    let public = EcdsaPublicKey::from_sec1_bytes(point).context("decode ECDSA public point")?;
    let public_key = PublicKey::new(
        KeyData::Ecdsa(public),
        String::from_utf8_lossy(comment).into_owned(),
    );
    Ok(LoadedIdentity {
        public_key,
        key: IdentityKey::File { private_key_der },
    })
}

/// Convert an SSH `mpint` scalar into a fixed-size big-endian field element by
/// trimming leading zeros and left-padding to `size` bytes.
fn normalize_scalar(mpint: &[u8], size: usize) -> Result<Vec<u8>> {
    let start = mpint.iter().position(|&b| b != 0).unwrap_or(mpint.len());
    let trimmed = &mpint[start..];
    if trimmed.len() > size {
        bail!("ECDSA private scalar is too large for the curve");
    }
    let mut out = vec![0u8; size];
    out[size - trimmed.len()..].copy_from_slice(trimmed);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_scalar_left_pads_short_mpint() {
        // A P-521 scalar whose leading byte was stripped during mpint encoding.
        let mpint = vec![0x12, 0x34, 0x56];
        let out = normalize_scalar(&mpint, 66).unwrap();
        assert_eq!(out.len(), 66);
        assert_eq!(&out[..63], &[0u8; 63]);
        assert_eq!(&out[63..], &[0x12, 0x34, 0x56]);
    }

    #[test]
    fn normalize_scalar_strips_leading_zero_then_pads() {
        // mpint with a leading zero (added because the MSB was set).
        let mpint = vec![0x00, 0xff, 0xee];
        let out = normalize_scalar(&mpint, 4).unwrap();
        assert_eq!(out, vec![0x00, 0x00, 0xff, 0xee]);
    }

    #[test]
    fn normalize_scalar_keeps_full_width() {
        let mpint = vec![0xab; 32];
        let out = normalize_scalar(&mpint, 32).unwrap();
        assert_eq!(out, vec![0xab; 32]);
    }

    #[test]
    fn normalize_scalar_rejects_oversized() {
        assert!(normalize_scalar(&[1, 2, 3, 4, 5], 4).is_err());
    }

    #[test]
    fn ecdsa_params_cover_the_nist_curves() {
        assert_eq!(
            ecdsa_params_for_name(b"ecdsa-sha2-nistp256"),
            Some((EcdsaCurve::NistP256, 32))
        );
        assert_eq!(
            ecdsa_params_for_name(b"ecdsa-sha2-nistp384"),
            Some((EcdsaCurve::NistP384, 48))
        );
        assert_eq!(
            ecdsa_params_for_name(b"ecdsa-sha2-nistp521"),
            Some((EcdsaCurve::NistP521, 66))
        );
        assert_eq!(ecdsa_params_for_name(b"ssh-ed25519"), None);
    }

    #[test]
    fn supported_algorithms_include_ecdsa_and_ed25519() {
        assert!(is_supported_algorithm(&Algorithm::Ed25519));
        for curve in [
            EcdsaCurve::NistP256,
            EcdsaCurve::NistP384,
            EcdsaCurve::NistP521,
        ] {
            assert!(is_supported_algorithm(&Algorithm::Ecdsa { curve }));
        }
        assert!(!is_supported_algorithm(&Algorithm::Rsa { hash: None }));
    }
}
