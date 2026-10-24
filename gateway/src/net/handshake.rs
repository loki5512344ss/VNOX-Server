use anyhow::Result;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn};

use crate::{
    domain::{auth, session},
    net::io,
    net::state::State,
    proto::{self, AuthPayload, HelloPayload, PacketId, SessionPayload, to_payload},
};

/// LNEx protocol version. v3 runs inside TLS 1.3 (see `docs/02-protocol/tls.md`).
pub const LNEX_VERSION: &str = "v3";

const SERVER_HELLO_CONTEXT: &[u8] = b"VNOX-LNEx-v3-server-hello\0";
const CLIENT_AUTH_CONTEXT: &[u8] = b"VNOX-LNEx-v3-client-auth\0";

/// Bytes the server identity signs: context, TLS exporter, HELLO without its signature.
pub fn server_hello_transcript(binding: &[u8], unsigned_hello: &[u8]) -> Vec<u8> {
    let mut out = SERVER_HELLO_CONTEXT.to_vec();
    out.extend_from_slice(binding);
    out.extend_from_slice(unsigned_hello);
    out
}

/// Bytes the client identity signs: context, TLS exporter, the signed HELLO, AUTH without
/// its signature. The exporter makes the signature valid for this TLS connection only.
pub fn client_auth_transcript(
    binding: &[u8],
    signed_hello: &[u8],
    unsigned_auth: &[u8],
) -> Vec<u8> {
    let mut out = CLIENT_AUTH_CONTEXT.to_vec();
    out.extend_from_slice(binding);
    out.extend_from_slice(&(signed_hello.len() as u32).to_be_bytes());
    out.extend_from_slice(signed_hello);
    out.extend_from_slice(unsigned_auth);
    out
}

/// Run HELLO, AUTH, SESSION inside an established TLS 1.3 connection.
///
/// `binding` is the TLS exporter value of this connection; both signatures cover it.
pub async fn run(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    addr: std::net::SocketAddr,
    state: &State,
    seq: &mut u32,
    binding: &[u8],
) -> Result<session::Session> {
    // HELLO: server key, challenge, privacy mode, signature bound to this TLS connection.
    let challenge = auth::new_challenge();
    let private_mode = state.config.is_private();
    let mut hello = HelloPayload {
        lnex_version: LNEX_VERSION.into(),
        server_pubkey: hex::decode(state.server_identity.pubkey_hex())?,
        challenge_nonce: challenge.to_vec(),
        node_name: state.config.node.name.clone(),
        private_mode,
        server_signature: Vec::new(),
    };
    let hello_transcript = server_hello_transcript(binding, &hello.encode_to_vec());
    hello.server_signature = state.server_identity.sign(&hello_transcript);
    io::send_packet(stream, PacketId::Hello, seq, &to_payload(&hello)).await?;
    debug!("{addr} HELLO sent");

    // AUTH
    let (hdr, payload) = io::read_packet(stream).await?;
    if PacketId::from_u16(hdr.packet_id) != Some(PacketId::Auth) || hdr.sequence != 0 {
        io::send_error(
            stream,
            seq,
            proto::ErrorCode::InvalidPacket,
            "expected AUTH",
        )
        .await?;
        return Err(anyhow::anyhow!("expected AUTH"));
    }

    let msg = AuthPayload::decode(payload.as_slice())?;
    if msg.lnex_version != LNEX_VERSION {
        io::send_error(
            stream,
            seq,
            proto::ErrorCode::VersionMismatch,
            "unsupported version: LNEx v3 required",
        )
        .await?;
        return Err(anyhow::anyhow!("version mismatch"));
    }
    anyhow::ensure!(
        !msg.nickname.trim().is_empty() && msg.nickname.chars().count() <= 64,
        "invalid nickname"
    );
    debug!("{addr} AUTH received");

    let pubkey: [u8; 32] = msg.client_pubkey.as_slice().try_into()?;
    let sig: [u8; 64] = msg.signature.as_slice().try_into()?;

    let mut auth_without_signature = msg.clone();
    auth_without_signature.signature.clear();
    let auth_transcript = client_auth_transcript(
        binding,
        &hello.encode_to_vec(),
        &auth_without_signature.encode_to_vec(),
    );
    if let Err(e) = auth::verify_auth(&auth_transcript, &pubkey, &sig) {
        warn!("{addr} auth failed: {e}");
        state.metrics.inc(&state.metrics.auth_failures);
        io::send_error(
            stream,
            seq,
            proto::ErrorCode::AuthFailed,
            "invalid signature",
        )
        .await?;
        return Err(anyhow::anyhow!("auth failed"));
    }

    if state
        .storage
        .is_banned(&hex::encode(&msg.client_pubkey))
        .await?
    {
        state.metrics.inc(&state.metrics.auth_failures);
        io::send_error(stream, seq, proto::ErrorCode::AuthFailed, "banned").await?;
        return Err(anyhow::anyhow!("banned"));
    }

    state
        .storage
        .upsert_user(&hex::encode(&msg.client_pubkey), &msg.nickname)
        .await?;

    // SESSION
    let sess = session::create(
        &state.sessions,
        hex::encode(&msg.client_pubkey),
        msg.nickname.clone(),
    )
    .await;

    let timeout_secs = state.config.gateway.session_timeout.unwrap_or(600);
    let expires_at = std::time::SystemTime::now()
        .checked_add(std::time::Duration::from_secs(timeout_secs))
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let sp = SessionPayload {
        session_id: sess.session_id.clone(),
        token: sess.token.clone(),
        expires_at,
    };
    io::send_packet(stream, PacketId::Session, seq, &to_payload(&sp)).await?;
    info!(
        "{addr} auth ok, nick={} sid={}",
        sess.nickname,
        &sess.session_id[..8]
    );

    Ok(sess)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::{Arc, atomic::AtomicUsize};
    use tokio::io::{AsyncWriteExt, DuplexStream};

    async fn state() -> State {
        let storage = crate::domain::storage::Storage::connect_sqlite(":memory:")
            .await
            .unwrap();
        let config = toml::from_str(include_str!("../../../dev/config.toml")).unwrap();
        let dir = std::env::temp_dir().join(format!("vnox-hs-test-{}", uuid::Uuid::new_v4()));
        let identity =
            crate::bootstrap::server_identity::ServerIdentity::load_or_generate(&dir).unwrap();
        let _ = std::fs::remove_dir_all(dir);
        let (broadcast, _) = tokio::sync::broadcast::channel(16);
        State::new(
            session::new_store(),
            crate::domain::channels::new_store(),
            Arc::new(storage),
            Arc::new(config),
            Arc::new(identity),
            broadcast,
            crate::admin::metrics::Metrics::new(),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
            None,
        )
    }

    /// Minimal client: reads HELLO, signs AUTH over `client_binding`, sends it.
    async fn client_auth(
        peer: &mut DuplexStream,
        client_binding: &[u8],
        version: &str,
    ) -> HelloPayload {
        let (hdr, payload) = io::read_packet(peer).await.unwrap();
        assert_eq!(hdr.packet_id, PacketId::Hello as u16);
        let hello = HelloPayload::decode(payload.as_slice()).unwrap();
        let key = SigningKey::generate(&mut rand::rng());
        let mut auth = AuthPayload {
            client_pubkey: key.verifying_key().to_bytes().to_vec(),
            nickname: "tester".into(),
            lnex_version: version.into(),
            signature: Vec::new(),
        };
        let transcript = client_auth_transcript(client_binding, &payload, &auth.encode_to_vec());
        auth.signature = key.sign(&transcript).to_bytes().to_vec();
        let mut seq = 0;
        io::send_packet(peer, PacketId::Auth, &mut seq, &to_payload(&auth))
            .await
            .unwrap();
        hello
    }

    async fn handshake(
        server_binding: &[u8],
        client_binding: &[u8],
        version: &str,
    ) -> (Result<session::Session>, proto::ErrorPayload) {
        let state = state().await;
        let (mut server, mut peer) = tokio::io::duplex(65536);
        let server_binding = server_binding.to_vec();
        let task = tokio::spawn(async move {
            let mut seq = 0;
            let result = run(
                &mut server,
                "127.0.0.1:1".parse().unwrap(),
                &state,
                &mut seq,
                &server_binding,
            )
            .await;
            let _ = server.shutdown().await;
            result
        });
        client_auth(&mut peer, client_binding, version).await;
        let (hdr, payload) = io::read_packet(&mut peer).await.unwrap();
        let error = if hdr.packet_id == PacketId::Error as u16 {
            proto::ErrorPayload::decode(payload.as_slice()).unwrap()
        } else {
            assert_eq!(hdr.packet_id, PacketId::Session as u16);
            proto::ErrorPayload::default()
        };
        (task.await.unwrap(), error)
    }

    #[tokio::test]
    async fn signature_for_the_same_channel_binding_is_accepted() {
        let (result, _) = handshake(&[9; 32], &[9; 32], LNEX_VERSION).await;
        result.unwrap();
    }

    #[tokio::test]
    async fn client_signature_cannot_be_replayed_on_another_connection() {
        // The AUTH was signed for TLS connection A (binding [1;32]) but arrives on B ([2;32]).
        let (result, error) = handshake(&[2; 32], &[1; 32], LNEX_VERSION).await;
        assert!(result.is_err());
        assert_eq!(error.code, proto::ErrorCode::AuthFailed as u32);
    }

    #[tokio::test]
    async fn old_protocol_version_is_rejected_with_explicit_error() {
        let (result, error) = handshake(&[3; 32], &[3; 32], "v2").await;
        assert!(result.is_err());
        assert_eq!(error.code, proto::ErrorCode::VersionMismatch as u32);
        assert!(error.message.contains("v3"));
    }

    #[tokio::test]
    async fn server_hello_signature_is_bound_to_the_connection() {
        let state = state().await;
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(
            &hex::decode(state.server_identity.pubkey_hex())
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let (mut server, mut peer) = tokio::io::duplex(65536);
        tokio::spawn(async move {
            let mut seq = 0;
            let _ = run(
                &mut server,
                "127.0.0.1:1".parse().unwrap(),
                &state,
                &mut seq,
                &[5; 32],
            )
            .await;
        });
        let (_, payload) = io::read_packet(&mut peer).await.unwrap();
        let mut hello = HelloPayload::decode(payload.as_slice()).unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&hello.server_signature).unwrap();
        hello.server_signature.clear();
        let unsigned = hello.encode_to_vec();
        verifying
            .verify_strict(&server_hello_transcript(&[5; 32], &unsigned), &signature)
            .unwrap();
        assert!(
            verifying
                .verify_strict(&server_hello_transcript(&[6; 32], &unsigned), &signature)
                .is_err(),
            "a relay with a different TLS session cannot reuse the server HELLO"
        );
    }
}
