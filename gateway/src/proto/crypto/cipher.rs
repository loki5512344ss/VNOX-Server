use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};

pub(super) fn make_nonce(cid: &[u8; 8], seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(cid);
    nonce[8..12].copy_from_slice(&(seq as u32).to_le_bytes());
    nonce
}

pub(super) fn encrypt_with_key(
    key: &[u8; 32],
    cid: &[u8; 8],
    seq: u64,
    plaintext: &[u8],
) -> Vec<u8> {
    encrypt_with_aad(key, cid, seq, plaintext, &[])
}

pub(super) fn encrypt_with_aad(
    key: &[u8; 32],
    cid: &[u8; 8],
    seq: u64,
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let nonce_bytes = make_nonce(cid, seq);
    let nonce = Nonce::from(nonce_bytes);
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("ChaCha20-Poly1305 encryption is infallible")
}

pub(super) fn decrypt_with_key(
    key: &[u8; 32],
    cid: &[u8; 8],
    seq: u64,
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    decrypt_with_aad(key, cid, seq, ciphertext, &[])
}

pub(super) fn decrypt_with_aad(
    key: &[u8; 32],
    cid: &[u8; 8],
    seq: u64,
    ciphertext: &[u8],
    aad: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let nonce_bytes = make_nonce(cid, seq);
    let nonce = Nonce::from(nonce_bytes);
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| anyhow::anyhow!("decryption failed: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_ciphertext_matches_independent_chacha20_poly1305_vector() {
        let key = std::array::from_fn(|index| index as u8);
        let cid = [0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43];
        let seq = 0x4746_4544;
        let plaintext = b"VNOX dependency migration";
        // Cross-checked with Python cryptography's ChaCha20Poly1305 implementation,
        // IETF nonce 070000004041424344454647, and empty associated data.
        let expected = hex::decode(
            "1fa23e7a312509b0fc8729521811348ff880daa5598c43a57635975f81278abdf4461b25af86aee1c3",
        )
        .unwrap();
        assert_eq!(encrypt_with_key(&key, &cid, seq, plaintext), expected);
        assert_eq!(
            decrypt_with_key(&key, &cid, seq, &expected).unwrap(),
            plaintext
        );
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let key = [7; 32];
        let cid = [9; 8];
        let mut ciphertext = encrypt_with_key(&key, &cid, 42, b"authenticated");
        ciphertext[0] ^= 1;
        assert!(decrypt_with_key(&key, &cid, 42, &ciphertext).is_err());
    }
}
