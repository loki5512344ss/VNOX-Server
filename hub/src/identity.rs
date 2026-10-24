use std::{fs::OpenOptions, io::Write, path::Path};

use anyhow::{Context, Result, bail};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredIdentity {
    version: u32,
    issuer_id: Uuid,
    secret_key: String,
    public_key: String,
}

/// Stable issuer identity. Only its public projection is exposed through HTTP.
pub struct Issuer {
    pub id: Uuid,
    pub public_key: String,
}

impl Issuer {
    pub fn load_or_create(directory: &Path) -> Result<Self> {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(directory)
            .context("creating Hub data directory")?;
        check_private_directory(directory)?;
        let path = directory.join("issuer.json");
        let stored = match OpenOptions::new().read(true).open(&path) {
            Ok(file) => {
                check_private_permissions(&file)?;
                if file.metadata()?.len() > 4096 {
                    bail!("Hub issuer identity exceeds the expected size");
                }
                let value: StoredIdentity =
                    serde_json::from_reader(file).context("reading Hub issuer identity")?;
                value
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let key = SigningKey::generate(&mut rand::rng());
                let value = StoredIdentity {
                    version: 1,
                    issuer_id: Uuid::new_v4(),
                    secret_key: hex::encode(key.to_bytes()),
                    public_key: hex::encode(key.verifying_key().to_bytes()),
                };
                persist_new_identity(&path, &value)?;
                value
            }
            Err(error) => return Err(error).context("opening Hub issuer identity"),
        };
        let secret = hex::decode(&stored.secret_key)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .context("Hub issuer private key has invalid encoding or length")?;
        let key = SigningKey::from_bytes(&secret);
        if stored.version != 1 || hex::encode(key.verifying_key().to_bytes()) != stored.public_key {
            bail!("Hub issuer identity failed integrity validation");
        }
        Ok(Self {
            id: stored.issuer_id,
            public_key: stored.public_key,
        })
    }
}

/// Loads a 32-byte server secret stored as hex in a 0600 file, creating it from the OS
/// CSPRNG on first use. The value is never logged and has no Debug/Serialize wrapper.
pub fn load_or_create_secret(directory: &Path, name: &str) -> Result<[u8; 32]> {
    check_private_directory(directory)?;
    let path = directory.join(name);
    for _ in 0..2 {
        match OpenOptions::new().read(true).open(&path) {
            Ok(file) => {
                check_private_permissions(&file)?;
                if file.metadata()?.len() > 256 {
                    bail!("Hub secret file exceeds the expected size");
                }
                let text = std::io::read_to_string(file).context("reading Hub secret file")?;
                return hex::decode(text.trim())
                    .ok()
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                    .context("Hub secret file has invalid encoding or length");
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                use rand::Rng;
                let mut bytes = [0u8; 32];
                rand::rng().fill_bytes(&mut bytes);
                // A concurrent creator winning the race is fine: the loop re-reads its file.
                let _ = persist_new_file(&path, hex::encode(bytes).as_bytes());
            }
            Err(error) => return Err(error).context("opening Hub secret file"),
        }
    }
    bail!("could not create Hub secret file")
}

fn check_private_permissions(file: &std::fs::File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if file.metadata()?.permissions().mode() & 0o077 != 0 {
            bail!("Hub issuer identity must not be accessible to group/other users (use 0600)");
        }
    }
    Ok(())
}

fn check_private_directory(directory: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::metadata(directory)?.permissions().mode() & 0o077 != 0 {
            bail!("Hub data directory must be private (use 0700)");
        }
    }
    Ok(())
}

// Publish a fully synced key file without replacing any concurrent issuer.
// A failed first write must never leave a truncated final identity behind.
fn persist_new_identity(path: &Path, identity: &StoredIdentity) -> Result<()> {
    persist_new_file(path, &serde_json::to_vec_pretty(identity)?)
}

fn persist_new_file(path: &Path, contents: &[u8]) -> Result<()> {
    let temporary = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        {
            let mut file = options
                .open(&temporary)
                .context("preparing Hub issuer identity")?;
            file.write_all(contents)
                .context("writing Hub issuer identity")?;
            file.sync_all().context("syncing Hub issuer identity")?;
        }
        std::fs::hard_link(&temporary, path).context("publishing new Hub issuer identity")?;
        #[cfg(unix)]
        std::fs::File::open(path.parent().context("issuer directory is missing")?)?
            .sync_all()
            .context("syncing Hub issuer directory")?;
        Ok(())
    })();
    let _ = std::fs::remove_file(&temporary);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_secret_is_stable_private_and_validated() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let first = load_or_create_secret(directory.path(), "s.key").unwrap();
        assert_eq!(
            first,
            load_or_create_secret(directory.path(), "s.key").unwrap()
        );
        assert_ne!(first, [0; 32]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(directory.path().join("s.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0);
        }
        std::fs::write(directory.path().join("bad.key"), "zz").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                directory.path().join("bad.key"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        assert!(load_or_create_secret(directory.path(), "bad.key").is_err());
    }

    #[test]
    fn publishing_never_overwrites_an_existing_identity_or_leaves_temp_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("issuer.json");
        std::fs::write(&path, b"existing issuer").unwrap();
        let key = SigningKey::generate(&mut rand::rng());
        let candidate = StoredIdentity {
            version: 1,
            issuer_id: Uuid::new_v4(),
            secret_key: hex::encode(key.to_bytes()),
            public_key: hex::encode(key.verifying_key().to_bytes()),
        };
        assert!(persist_new_identity(&path, &candidate).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"existing issuer");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}
