use anyhow::{Context, Result, bail};
use base64::Engine;
use sha2::{Digest, Sha256};
use signature::{Signer, Verifier};
use ssh_key::{
    Algorithm, PrivateKey, PublicKey, Signature,
    public::{Ed25519PublicKey, KeyData},
};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone)]
pub struct LoadedIdentity {
    pub public_key: PublicKey,
    pub key: IdentityKey,
}

#[derive(Debug, Clone)]
pub enum IdentityKey {
    Agent { socket: PathBuf },
    File { private_key: PrivateKey },
}

pub fn load_identity() -> Result<LoadedIdentity> {
    if let Some(identity) = load_identity_from_agent()? {
        return Ok(identity);
    }
    let path = crate::paths::current_home().join(".ssh/id_ed25519");
    load_identity_from_file(&path)
}

pub fn load_identity_with_file(identity_file: Option<&Path>) -> Result<LoadedIdentity> {
    if let Some(path) = identity_file {
        if let Some(identity) = load_identity_from_agent_matching_file(path)? {
            return Ok(identity);
        }
        return load_identity_from_file(path);
    }
    load_identity()
}

fn load_identity_from_agent() -> Result<Option<LoadedIdentity>> {
    let Ok(sock) = env::var("SSH_AUTH_SOCK") else {
        return Ok(None);
    };
    let socket = PathBuf::from(sock);
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
        if public_key.algorithm() != Algorithm::Ed25519 {
            continue;
        }
        if let Some(preferred) = &preferred {
            if !same_public_key(&public_key, preferred)? {
                continue;
            }
        }
        tracing::debug!("using Ed25519 identity from ssh-agent");
        return Ok(Some(LoadedIdentity {
            public_key,
            key: IdentityKey::Agent { socket },
        }));
    }
    Ok(None)
}

fn load_identity_from_agent_matching_file(path: &Path) -> Result<Option<LoadedIdentity>> {
    let public_path = public_key_path_for_private_key(path);
    let preferred = fs::read_to_string(&public_path)
        .ok()
        .and_then(|data| PublicKey::from_openssh(&data).ok());
    let Some(preferred) = preferred else {
        return Ok(None);
    };
    load_identity_from_agent_matching(&preferred)
}

fn load_identity_from_agent_matching(preferred: &PublicKey) -> Result<Option<LoadedIdentity>> {
    let Ok(sock) = env::var("SSH_AUTH_SOCK") else {
        return Ok(None);
    };
    let socket = PathBuf::from(sock);
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
        if public_key.algorithm() != Algorithm::Ed25519 || !same_public_key(&public_key, preferred)?
        {
            continue;
        }
        tracing::debug!("using matching Ed25519 identity from ssh-agent");
        return Ok(Some(LoadedIdentity {
            public_key,
            key: IdentityKey::Agent { socket },
        }));
    }
    Ok(None)
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
    Ok(LoadedIdentity {
        public_key: key.public_key().clone(),
        key: IdentityKey::File { private_key: key },
    })
}

pub fn agent_sign(socket: &Path, public_key: &PublicKey, message: &[u8]) -> Result<Vec<u8>> {
    let mut client = ssh_agent_client_rs::Client::connect(socket)
        .with_context(|| format!("connect ssh-agent {}", socket.display()))?;
    let sig = client
        .sign(public_key, message)
        .context("ssh-agent sign request")?;
    if sig.algorithm() != Algorithm::Ed25519 {
        bail!("ssh-agent returned non-Ed25519 signature");
    }
    Ok(sig.as_bytes().to_vec())
}

pub fn sign_identity(identity: &LoadedIdentity, message: &[u8]) -> Result<Vec<u8>> {
    match &identity.key {
        IdentityKey::Agent { socket } => agent_sign(socket, &identity.public_key, message),
        IdentityKey::File { private_key } => {
            let sig: Signature = private_key.try_sign(message).context("sign with SSH key")?;
            if sig.algorithm() != Algorithm::Ed25519 {
                bail!("private key returned non-Ed25519 signature");
            }
            Ok(sig.as_bytes().to_vec())
        }
    }
}

pub fn verify_public_key_signature(
    key: &PublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    let sig = Signature::new(Algorithm::Ed25519, signature).context("parse SSH signature")?;
    Verifier::verify(key, message, &sig).context("verify SSH public key signature")
}

pub fn bytes_fingerprint(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    )
}

pub fn ed25519_public_key_bytes(public_key: &PublicKey) -> Result<&[u8; 32]> {
    match public_key.key_data() {
        KeyData::Ed25519(key) => Ok(key.as_ref()),
        _ => bail!("only Ed25519 SSH keys are supported for now"),
    }
}

pub fn ed25519_public_key_from_bytes(bytes: &[u8]) -> Result<PublicKey> {
    let ed = Ed25519PublicKey::try_from(bytes).context("parse raw Ed25519 public key")?;
    Ok(PublicKey::new(KeyData::Ed25519(ed), "hush-client"))
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
            if candidate.algorithm() == Algorithm::Ed25519
                && candidate.to_bytes().ok().as_deref() == Some(wanted.as_slice())
            {
                return Ok(true);
            }
            continue;
        }

        if let Some(key_start) = line.find("ssh-ed25519 ") {
            let candidate_line = &line[key_start..];
            if let Ok(candidate) = PublicKey::from_openssh(candidate_line) {
                if candidate.to_bytes().ok().as_deref() == Some(wanted.as_slice()) {
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

fn preferred_public_key() -> Option<PublicKey> {
    let path = crate::paths::current_home().join(".ssh/id_ed25519.pub");
    let data = fs::read_to_string(path).ok()?;
    PublicKey::from_openssh(&data).ok()
}

fn same_public_key(a: &PublicKey, b: &PublicKey) -> Result<bool> {
    Ok(a.to_bytes()? == b.to_bytes()?)
}

fn public_key_path_for_private_key(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".pub");
    PathBuf::from(s)
}
