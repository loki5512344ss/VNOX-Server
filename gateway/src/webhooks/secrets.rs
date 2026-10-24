use anyhow::{Result, bail};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::{Digest, Sha256};

pub fn new_secret() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}
pub fn digest(secret: &[u8]) -> String {
    hex::encode(Sha256::digest(secret))
}

pub fn seal(master: &[u8; 32], id: &str, secret: &str) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(master)
        .map_err(|_| anyhow::anyhow!("invalid webhook key"))?;
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let encrypted = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: secret.as_bytes(),
                aad: id.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("could not protect webhook signing secret"))?;
    Ok([nonce.as_slice(), encrypted.as_slice()].concat())
}

pub fn open(master: &[u8; 32], id: &str, encoded: &[u8]) -> Result<String> {
    if encoded.len() < 28 {
        bail!("invalid protected webhook secret")
    }
    let nonce = <[u8; 12]>::try_from(&encoded[..12])?;
    let cipher = ChaCha20Poly1305::new_from_slice(master)
        .map_err(|_| anyhow::anyhow!("invalid webhook key"))?;
    let plain = cipher
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &encoded[12..],
                aad: id.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("webhook signing secret could not be opened"))?;
    String::from_utf8(plain).map_err(|_| anyhow::anyhow!("invalid webhook signing secret"))
}

pub fn sign(secret: &str, body: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(secret.as_bytes())
        .expect("HMAC permits any key length");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify(secret: &str, body: &[u8], signature: &str) -> bool {
    let Some(raw) = signature
        .strip_prefix("sha256=")
        .and_then(|s| hex::decode(s).ok())
    else {
        return false;
    };
    let Ok(mut mac) = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(secret.as_bytes())
    else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&raw).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn github_reference_signature_and_tampering() {
        let key = "It's a Secret to Everybody";
        let body = b"Hello, World!";
        let signature = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
        assert!(verify(key, body, signature));
        assert!(!verify(key, b"changed", signature));
    }
    #[test]
    fn protected_secret_is_bound_to_hook_identity() {
        let blob = seal(&[7; 32], "first", "secret").unwrap();
        assert_eq!(open(&[7; 32], "first", &blob).unwrap(), "secret");
        assert!(open(&[7; 32], "second", &blob).is_err());
        assert!(open(&[8; 32], "first", &blob).is_err());
    }
}
