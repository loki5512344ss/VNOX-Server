use anyhow::Result;
use ed25519_dalek::{Signature, VerifyingKey};

/// Verify Ed25519 signature from AUTH packet.
pub fn verify_auth(challenge: &[u8; 32], pubkey: &[u8; 32], signature: &[u8; 64]) -> Result<()> {
    let key = VerifyingKey::from_bytes(pubkey).map_err(|_| anyhow::anyhow!("invalid pubkey"))?;
    let sig = Signature::from_bytes(signature);
    key.verify_strict(challenge, &sig)
        .map_err(|_| anyhow::anyhow!("invalid signature"))
}

/// Random 32-byte challenge nonce for HELLO.
pub fn new_challenge() -> [u8; 32] {
    use rand::Rng;
    let mut n = [0u8; 32];
    rand::rng().fill_bytes(&mut n);
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn verify_auth_accepts_valid_signature() {
        let sk = SigningKey::generate(&mut rand::rng());
        let vk = sk.verifying_key();
        let challenge = [7u8; 32];
        let sig = sk.sign(&challenge);
        verify_auth(&challenge, vk.as_bytes(), &sig.to_bytes()).unwrap();
    }

    #[test]
    fn verify_auth_rejects_tampered_challenge() {
        let sk = SigningKey::generate(&mut rand::rng());
        let vk = sk.verifying_key();
        let challenge = [7u8; 32];
        let sig = sk.sign(&challenge);
        let mut other = challenge;
        other[0] ^= 1;
        assert!(verify_auth(&other, vk.as_bytes(), &sig.to_bytes()).is_err());
    }
}
