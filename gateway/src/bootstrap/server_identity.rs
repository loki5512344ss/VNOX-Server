use anyhow::Result;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredIdentity {
    pubkey_hex: String,
    privkey_hex: String,
}

/// Gateway Ed25519 identity — loaded from disk or generated on first start.
pub struct ServerIdentity {
    signing_key: SigningKey,
}

impl ServerIdentity {
    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    pub fn load_or_generate(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join("server_identity.json");

        if path.exists() {
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
        std::fs::write(&path, serde_json::to_string_pretty(&stored)?)?;

        Ok(Self { signing_key })
    }
}
