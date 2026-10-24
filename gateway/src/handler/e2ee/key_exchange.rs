use anyhow::Result;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::warn;

use crate::{
    domain::session,
    net::{
        io,
        state::{BroadcastMsg, State},
    },
    proto::{
        self, E2eeDmKeyExchangeAckPayload, E2eeDmKeyExchangePayload, ErrorCode, PacketId,
        encode_packet, to_payload,
    },
};

pub async fn handle_e2ee_key_exchange(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    state: &State,
) -> Result<()> {
    let msg = E2eeDmKeyExchangePayload::decode(payload)?;

    let sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;
    let my_id = sess.user_id.clone();
    drop(sess);

    let other_id = state
        .storage
        .get_dm_user_id(&msg.dm_id, &my_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("user not in DM"))?;

    if state.storage.is_blocked(&other_id, &my_id).await? {
        io::send_frame(
            stream,
            PacketId::Error,
            seq,
            &to_payload(&proto::ErrorPayload {
                code: ErrorCode::Blocked as u32,
                message: "blocked".into(),
            }),
        )
        .await?;
        return Ok(());
    }

    {
        let mut keys = state.e2ee_keys.write().await;
        keys.insert(my_id.clone(), msg.e2ee_public_key.clone());
    }

    if let Some(recipient_sid) =
        session::get_session_id_by_user_id(&state.sessions, &other_id).await
    {
        let data = encode_packet(
            PacketId::E2eeDmKeyExchange,
            0,
            &to_payload(&E2eeDmKeyExchangePayload {
                dm_id: msg.dm_id.clone(),
                e2ee_public_key: msg.e2ee_public_key.clone(),
            }),
        );
        let _ = state.broadcast.send(BroadcastMsg {
            channel_id: None,
            exclude_session: None,
            target_session_id: Some(recipient_sid),
            data,
        });
    } else {
        warn!("e2ee key exchange recipient offline: {}", &other_id[..8]);
    }

    io::send_frame(
        stream,
        PacketId::E2eeDmKeyExchange,
        seq,
        &to_payload(&E2eeDmKeyExchangeAckPayload { dm_id: msg.dm_id }),
    )
    .await?;
    Ok(())
}

pub async fn handle_e2ee_key_exchange_ack(
    _stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    _seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    state: &State,
) -> Result<()> {
    let msg = E2eeDmKeyExchangeAckPayload::decode(payload)?;

    let sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;
    let my_id = sess.user_id.clone();
    drop(sess);

    let other_id = state
        .storage
        .get_dm_user_id(&msg.dm_id, &my_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("user not in DM"))?;

    if let Some(recipient_sid) =
        session::get_session_id_by_user_id(&state.sessions, &other_id).await
    {
        let data = encode_packet(
            PacketId::E2eeDmKeyExchangeAck,
            0,
            &to_payload(&E2eeDmKeyExchangeAckPayload { dm_id: msg.dm_id }),
        );
        let _ = state.broadcast.send(BroadcastMsg {
            channel_id: None,
            exclude_session: None,
            target_session_id: Some(recipient_sid),
            data,
        });
    }

    Ok(())
}
