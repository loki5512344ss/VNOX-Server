use anyhow::Result;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn};

use crate::{
    domain::{auth, session},
    net::io,
    net::state::State,
    proto::{self, AuthPayload, HelloPayload, PacketId, SessionCrypto, SessionPayload, to_payload},
};

const LNEX_VERSION: &str = "v2";

/// Run HELLO → AUTH → SESSION with X25519 ECDH key exchange.
///
/// Returns the session and the derived crypto context (encryption keys).
/// All subsequent packets must be encrypted with `crypto`.
pub async fn run(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    addr: std::net::SocketAddr,
    state: &State,
    seq: &mut u32,
) -> Result<(session::Session, SessionCrypto)> {
    // Generate ephemeral X25519 keypair for forward secrecy
    let (eph_sk, eph_pk) = SessionCrypto::new_ephemeral();
    let eph_pk_raw = eph_pk.as_bytes();

    // HELLO — include server's ephemeral public key + privacy mode
    let challenge = auth::new_challenge();
    let private_mode = state.config.is_private();
    let mut hello = HelloPayload {
        lnex_version: LNEX_VERSION.into(),
        server_pubkey: hex::decode(state.server_identity.pubkey_hex())?,
        challenge_nonce: challenge.to_vec(),
        node_name: state.config.node.name.clone(),
        server_eph_pubkey: eph_pk_raw.to_vec(),
        private_mode,
        server_signature: Vec::new(),
    };
    let mut hello_transcript = b"VNOX-LNEx-v2-server-hello\0".to_vec();
    hello_transcript.extend_from_slice(&hello.encode_to_vec());
    hello.server_signature = state.server_identity.sign(&hello_transcript);
    io::send_packet(stream, PacketId::Hello, seq, &to_payload(&hello)).await?;
    debug!("{addr} ← HELLO (eph key included)");

    // AUTH — receive client's ephemeral public key
    let (hdr, payload) = io::read_packet(stream).await?;
    if PacketId::from_u16(hdr.packet_id) != Some(PacketId::Auth)
        || hdr.flags != 0
        || hdr.sequence != 0
    {
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
    anyhow::ensure!(
        !msg.nickname.trim().is_empty() && msg.nickname.chars().count() <= 64,
        "invalid nickname"
    );
    debug!("{addr} → AUTH");

    if msg.lnex_version != LNEX_VERSION {
        io::send_error(
            stream,
            seq,
            proto::ErrorCode::VersionMismatch,
            "unsupported version",
        )
        .await?;
        return Err(anyhow::anyhow!("version mismatch"));
    }

    let pubkey: [u8; 32] = msg.client_pubkey.as_slice().try_into()?;
    let sig: [u8; 64] = msg.signature.as_slice().try_into()?;

    let mut auth_without_signature = msg.clone();
    auth_without_signature.signature.clear();
    let hello_bytes = hello.encode_to_vec();
    let mut auth_transcript = b"VNOX-LNEx-v2-client-auth\0".to_vec();
    auth_transcript.extend_from_slice(&(hello_bytes.len() as u32).to_be_bytes());
    auth_transcript.extend_from_slice(&hello_bytes);
    auth_transcript.extend_from_slice(&auth_without_signature.encode_to_vec());
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

    // ECDH: compute shared secret from server's ephemeral sk + client's ephemeral pk
    let client_eph_raw: [u8; 32] = msg.client_eph_pubkey.as_slice().try_into()?;
    let client_eph_pk = x25519_dalek::PublicKey::from(client_eph_raw);
    let shared_secret = SessionCrypto::ecdh(eph_sk, &client_eph_pk);
    anyhow::ensure!(shared_secret.was_contributory(), "invalid ephemeral key");

    // SESSION
    let sess = session::create(
        &state.sessions,
        hex::encode(&msg.client_pubkey),
        msg.nickname.clone(),
    )
    .await;

    // Derive encryption keys from shared secret + session_id
    let crypto = SessionCrypto::derive(shared_secret.as_bytes(), &sess.session_id);

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
        "{addr} auth ok — nick={} sid={} encrypted",
        sess.nickname,
        &sess.session_id[..8]
    );

    Ok((sess, crypto))
}
