use anyhow::Result;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Serialize, Deserialize)]
struct StoredIdentity {
    pubkey_hex: String,
    privkey_hex: String,
}

/// Gateway Ed25519 identity — loaded from disk or generated on first start.
pub struct ServerIdentity {
    signing_key: SigningKey,
}

impl ServerIdentity {
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        self.signing_key.sign(message).to_bytes().to_vec()
    }
    /// Ed25519 seed. Only used to derive the TLS key of the auto generated certificate
    /// (see `crate::tls`), so the certificate fingerprint is a function of the identity.
    pub(crate) fn signing_seed(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    pub fn load_or_generate(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join("server_identity.json");

        if std::fs::symlink_metadata(&path).is_ok() {
            anyhow::ensure!(
                std::fs::symlink_metadata(&path)?.file_type().is_file(),
                "server identity must be a regular file"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            }
            let text = std::fs::read_to_string(&path)?;
            let stored: StoredIdentity = serde_json::from_str(&text)?;
            let signing_key = SigningKey::from_bytes(
                hex::decode(&stored.privkey_hex)?
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid server private key length"))?,
            );
            let computed_pubkey = hex::encode(signing_key.verifying_key().to_bytes());
            if stored.pubkey_hex != computed_pubkey {
                return Err(anyhow::anyhow!(
                    "server_identity.json pubkey does not match private key"
                ));
            }
            return Ok(Self { signing_key });
        }

        let signing_key = SigningKey::generate(&mut rand::rng());
        let verifying_key = signing_key.verifying_key();
        let pubkey_hex = hex::encode(verifying_key.to_bytes());

        let stored = StoredIdentity {
            pubkey_hex,
            privkey_hex: hex::encode(signing_key.to_bytes()),
        };

        std::fs::create_dir_all(data_dir)?;
        let temporary = data_dir.join(format!(".server-identity-{}.tmp", uuid::Uuid::new_v4()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let result = (|| -> Result<()> {
            use std::io::Write;
            let mut file = options.open(&temporary)?;
            file.write_all(serde_json::to_string_pretty(&stored)?.as_bytes())?;
            file.sync_all()?;
            std::fs::hard_link(&temporary, &path)?;
            #[cfg(unix)]
            std::fs::File::open(data_dir)?.sync_all()?;
            Ok(())
        })();
        let _ = std::fs::remove_file(&temporary);
        if let Err(error) = result {
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists)
            {
                return Self::load_or_generate(data_dir);
            }
            return Err(error);
        }

        Ok(Self { signing_key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gateway_identity_is_private_stable_and_never_replaced() {
        let dir =
            std::env::temp_dir().join(format!("vnox-private-identity-{}", uuid::Uuid::new_v4()));
        let first = ServerIdentity::load_or_generate(&dir).unwrap();
        let second = ServerIdentity::load_or_generate(&dir).unwrap();
        assert_eq!(first.pubkey_hex(), second.pubkey_hex());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(dir.join("server_identity.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        std::fs::write(dir.join("server_identity.json"), "corrupt").unwrap();
        assert!(ServerIdentity::load_or_generate(&dir).is_err());
        assert_eq!(
            std::fs::read_to_string(dir.join("server_identity.json")).unwrap(),
            "corrupt"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
