use anyhow::{Context, Result, bail};
use aws_lc_rs::{hmac, rand};
use quinn::EndpointConfig;
use quinn_proto::HashedConnectionIdGenerator;
use std::{
    fs, io,
    io::{Read, Write},
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

    if let Some(key) = read_stateless_reset_key(&path)? {
        return Ok(key);
    }

    let rng = rand::SystemRandom::new();
    let mut key = [0u8; STATELESS_RESET_KEY_LEN];
    rand::SecureRandom::fill(&rng, &mut key).context("generate stateless reset key")?;

    for _ in 0..32 {
        let mut nonce = [0u8; 12];
        rand::SecureRandom::fill(&rng, &mut nonce).context("generate temporary filename")?;
        let tmp = server_dir.join(format!(".stateless_reset.{}.tmp", hex::encode(nonce)));
        let file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()));
        let mut file = match file {
            Ok(file) => file,
            Err(err)
                if err
                    .downcast_ref::<io::Error>()
                    .is_some_and(|err| err.kind() == io::ErrorKind::AlreadyExists) =>
            {
                continue;
            }
            Err(err) => return Err(err),
        };
        let install = (|| -> Result<Option<[u8; STATELESS_RESET_KEY_LEN]>> {
            file.write_all(&key)?;
            file.sync_all()?;
            drop(file);

            match fs::hard_link(&tmp, &path) {
                Ok(()) => {
                    fs::remove_file(&tmp)?;
                    fs::File::open(&server_dir)?.sync_all()?;
                    Ok(Some(key))
                }
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                    fs::remove_file(&tmp)?;
                    // Another process installed the key first. Read its value;
                    // if it was removed concurrently, retry with a new name.
                    read_stateless_reset_key(&path)
                }
                Err(err) => Err(err.into()),
            }
        })();
        if install.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        if let Some(installed) = install? {
            return Ok(installed);
        }
    }
    bail!(
        "could not install stateless reset key at {}",
        path.display()
    )
}

fn read_stateless_reset_key(path: &Path) -> Result<Option<[u8; STATELESS_RESET_KEY_LEN]>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path);
    let mut file = match file {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("open {}", path.display())),
    };
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    let mut key = [0u8; STATELESS_RESET_KEY_LEN];
    file.read_exact(&mut key)
        .with_context(|| format!("read {}", path.display()))?;
    let mut extra = [0u8; 1];
    if file.read(&mut extra)? != 0 {
        bail!(
            "invalid stateless reset key length in {}: expected {} bytes",
            path.display(),
            STATELESS_RESET_KEY_LEN
        );
    }
    Ok(Some(key))
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
    fn concurrent_stateless_reset_key_creation_converges() {
        use std::sync::{Arc, Barrier};

        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_owned();
        let barrier = Arc::new(Barrier::new(8));
        let threads = (0..8)
            .map(|_| {
                let data_dir = data_dir.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    load_or_create_stateless_reset_key(&data_dir).unwrap()
                })
            })
            .collect::<Vec<_>>();
        let keys = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();

        assert!(keys.iter().all(|key| key == &keys[0]));
    }

    #[test]
    fn cid_generator_key_is_stable() {
        let mut key = [0u8; STATELESS_RESET_KEY_LEN];
        key[..8].copy_from_slice(&1234u64.to_le_bytes());

        assert_eq!(cid_generator_key_from_reset_key(&key), 1234);
    }
}
