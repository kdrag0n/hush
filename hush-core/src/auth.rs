use anyhow::{Context, Result, bail};
use base64::Engine;
use sha2::{Digest, Sha256};
use ssh_key::{
    Algorithm, PrivateKey, PublicKey,
    public::{Ed25519PublicKey, KeyData},
};
use std::{
    fs,
    path::{Path, PathBuf},
};
use x509_parser::prelude::FromDer;

#[derive(Debug, Clone)]
pub struct LoadedIdentity {
    pub private_key_der: Vec<u8>,
    pub public_key: PublicKey,
}

pub fn load_identity() -> Result<LoadedIdentity> {
    let path = crate::paths::current_home().join(".ssh/id_ed25519");
    load_identity_from_file(&path)
}

pub fn load_identity_from_file(path: &Path) -> Result<LoadedIdentity> {
    let mut key = PrivateKey::read_openssh_file(path)
        .with_context(|| format!("read OpenSSH private key {}", path.display()))?;
    if key.is_encrypted() {
        let pass =
            rpassword::prompt_password(format!("Enter passphrase for {}: ", path.display()))?;
        key = key.decrypt(pass).context("decrypt private key")?;
    }
    if key.algorithm() != Algorithm::Ed25519 {
        bail!("only Ed25519 SSH keys are supported for now");
    }
    let keypair = key
        .key_data()
        .ed25519()
        .context("private key is not Ed25519")?;
    let private_key_der = ed25519_seed_to_pkcs8_der(keypair.private.as_ref());
    Ok(LoadedIdentity {
        private_key_der,
        public_key: key.public_key().clone(),
    })
}

pub fn public_key_from_cert_der(cert_der: &[u8]) -> Result<PublicKey> {
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der)
        .context("parse peer certificate")?;
    let raw = &cert.public_key().subject_public_key.data;
    let ed = Ed25519PublicKey::try_from(raw.as_ref()).context("extract Ed25519 public key")?;
    Ok(PublicKey::new(KeyData::Ed25519(ed), "hush-client"))
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

pub fn is_authorized(user: &str, key: &PublicKey) -> Result<bool> {
    let path = authorized_keys_for_user(user)?;
    let Ok(data) = fs::read_to_string(&path) else {
        return Ok(false);
    };
    let wanted = key.to_bytes().context("serialize peer public key")?;
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parsed = if line.starts_with("ssh-ed25519 ") {
            PublicKey::from_openssh(line)
        } else {
            let mut fields = line.splitn(2, char::is_whitespace);
            let _options = fields.next();
            let Some(rest) = fields.next() else { continue };
            PublicKey::from_openssh(rest)
        };
        if let Ok(candidate) = parsed {
            if candidate.algorithm() == Algorithm::Ed25519
                && candidate.to_bytes().ok().as_deref() == Some(wanted.as_slice())
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub fn current_username() -> String {
    whoami::username()
}

pub fn can_login_as(user: &str) -> bool {
    (unsafe { libc::geteuid() == 0 }) || user == current_username()
}

pub fn home_for_user(user: &str) -> Result<Option<PathBuf>> {
    unsafe {
        let c_user = std::ffi::CString::new(user).context("username contains NUL")?;
        let pwd = libc::getpwnam(c_user.as_ptr());
        if pwd.is_null() {
            return Ok(None);
        }
        let dir = std::ffi::CStr::from_ptr((*pwd).pw_dir)
            .to_string_lossy()
            .into_owned();
        Ok(Some(PathBuf::from(dir)))
    }
}

fn ed25519_seed_to_pkcs8_der(seed: &[u8; 32]) -> Vec<u8> {
    let mut der = hex::decode("302e020100300506032b657004220420").expect("valid pkcs8 prefix");
    der.extend_from_slice(seed);
    der
}
