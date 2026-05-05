use anyhow::{Context, Result, bail};
use aws_lc_rs::{hmac, rand};
use quinn::EndpointConfig;
use quinn_proto::HashedConnectionIdGenerator;
use std::{
    fs,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::Arc,
};

const STATELESS_RESET_KEY_LEN: usize = 64;

pub fn server_endpoint_config(data_dir: &Path) -> Result<EndpointConfig> {
    let key = load_or_create_stateless_reset_key(data_dir)?;
    let cid_key = cid_generator_key_from_reset_key(&key);
    let mut config = EndpointConfig::new(Arc::new(hmac::Key::new(hmac::HMAC_SHA256, &key)));
    config.cid_generator(move || Box::new(HashedConnectionIdGenerator::from_key(cid_key)));
    Ok(config)
}

fn cid_generator_key_from_reset_key(key: &[u8; STATELESS_RESET_KEY_LEN]) -> u64 {
    u64::from_le_bytes(key[..8].try_into().expect("slice length is fixed"))
}

fn load_or_create_stateless_reset_key(data_dir: &Path) -> Result<[u8; STATELESS_RESET_KEY_LEN]> {
    let server_dir = crate::paths::server_dir(data_dir);
    fs::create_dir_all(&server_dir)?;
    fs::set_permissions(&server_dir, fs::Permissions::from_mode(0o700))?;
    let path = server_dir.join("stateless_reset.key");

    if path.exists() {
        let data = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        if data.len() != STATELESS_RESET_KEY_LEN {
            bail!(
                "invalid stateless reset key length in {}: expected {}, got {}",
                path.display(),
                STATELESS_RESET_KEY_LEN,
                data.len()
            );
        }
        let mut key = [0u8; STATELESS_RESET_KEY_LEN];
        key.copy_from_slice(&data);
        return Ok(key);
    }

    let rng = rand::SystemRandom::new();
    let mut key = [0u8; STATELESS_RESET_KEY_LEN];
    rand::SecureRandom::fill(&rng, &mut key).context("generate stateless reset key")?;

    let tmp = path.with_extension("key.tmp");
    {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        use std::io::Write;
        file.write_all(&key)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, &path).with_context(|| format!("install {}", path.display()))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stateless_reset_key_is_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let first = load_or_create_stateless_reset_key(dir.path()).unwrap();
        let second = load_or_create_stateless_reset_key(dir.path()).unwrap();
        assert_eq!(first, second);

        let path = crate::paths::server_dir(dir.path()).join("stateless_reset.key");
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn cid_generator_key_is_stable() {
        let mut key = [0u8; STATELESS_RESET_KEY_LEN];
        key[..8].copy_from_slice(&1234u64.to_le_bytes());

        assert_eq!(cid_generator_key_from_reset_key(&key), 1234);
    }
}
