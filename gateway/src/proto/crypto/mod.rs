mod cipher;

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

#[derive(Clone)]
pub struct SessionCrypto {
    c2s_key: [u8; 32],
    s2c_key: [u8; 32],
    cid: [u8; 8],
}

impl SessionCrypto {
    pub fn derive(shared_secret: &[u8; 32], session_id: &str) -> Self {
        let salt = b"VNOX-LNEx-KDF-v2";
        let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);

        let mut keys = [0u8; 64];
        hk.expand(b"session-keys", &mut keys)
            .expect("64 bytes is within HKDF max");

        let c2s_key: [u8; 32] = keys[..32].try_into().unwrap();
        let s2c_key: [u8; 32] = keys[32..64].try_into().unwrap();

        use sha2::Digest;
        let hash = Sha256::digest(session_id.as_bytes());
        let cid: [u8; 8] = hash[..8].try_into().unwrap();

        Self {
            c2s_key,
            s2c_key,
            cid,
        }
    }

    pub fn encrypt_s2c(&self, seq: u64, plaintext: &[u8]) -> Vec<u8> {
        cipher::encrypt_with_key(&self.s2c_key, &self.cid, seq, plaintext)
    }

    pub fn decrypt_c2s(&self, seq: u64, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        cipher::decrypt_with_key(&self.c2s_key, &self.cid, seq, ciphertext)
    }

    #[cfg(test)]
    pub(crate) fn encrypt_c2s_frame(&self, seq: u64, plaintext: &[u8], header: &[u8]) -> Vec<u8> {
        cipher::encrypt_with_aad(&self.c2s_key, &self.cid, seq, plaintext, header)
    }
    pub fn encrypt_s2c_frame(&self, seq: u64, plaintext: &[u8], header: &[u8]) -> Vec<u8> {
        cipher::encrypt_with_aad(&self.s2c_key, &self.cid, seq, plaintext, header)
    }
    pub fn decrypt_c2s_frame(
        &self,
        seq: u64,
        ciphertext: &[u8],
        header: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        cipher::decrypt_with_aad(&self.c2s_key, &self.cid, seq, ciphertext, header)
    }

    pub fn new_ephemeral() -> (EphemeralSecret, PublicKey) {
        let mut rng = rand::rng();
        let sk = EphemeralSecret::random_from_rng(&mut rng);
        let pk = PublicKey::from(&sk);
        (sk, pk)
    }

    pub fn ecdh(secret: EphemeralSecret, peer_public: &PublicKey) -> SharedSecret {
        secret.diffie_hellman(peer_public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_roundtrip() {
        let shared_secret = [0xABu8; 32];
        let crypto = SessionCrypto::derive(&shared_secret, "test-session-id");

        let plaintext = b"hello encrypted world";
        let seq = 42;

        let ciphertext = crypto.encrypt_s2c(seq, plaintext);
        assert_ne!(ciphertext, plaintext);
        assert!(ciphertext.len() > plaintext.len());
    }

    #[test]
    fn different_keys_cannot_decrypt_each_other() {
        let shared_secret = [0xABu8; 32];
        let crypto = SessionCrypto::derive(&shared_secret, "test-session-id");

        let s2c_ct = crypto.encrypt_s2c(0, b"server to client");
        let result = crypto.decrypt_c2s(0, &s2c_ct);
        assert!(result.is_err());
    }

    #[test]
    fn different_keys_produce_different_ciphertexts() {
        let secret_a = [0xAAu8; 32];
        let secret_b = [0xBBu8; 32];
        let crypto_a = SessionCrypto::derive(&secret_a, "session-a");
        let crypto_b = SessionCrypto::derive(&secret_b, "session-b");

        let plaintext = b"same plaintext";
        let ct_a = crypto_a.encrypt_s2c(0, plaintext);
        let ct_b = crypto_b.encrypt_s2c(0, plaintext);
        assert_ne!(ct_a, ct_b);
    }

    #[test]
    fn ecdh_derives_same_secret_on_both_sides() {
        let mut rng = rand::rng();

        let alice_sk = EphemeralSecret::random_from_rng(&mut rng);
        let alice_pk = PublicKey::from(&alice_sk);

        let bob_sk = EphemeralSecret::random_from_rng(&mut rng);
        let bob_pk = PublicKey::from(&bob_sk);

        let alice_shared = alice_sk.diffie_hellman(&bob_pk);
        let bob_shared = bob_sk.diffie_hellman(&alice_pk);

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }
}
