use anyhow::Result;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    domain::session,
    net::{io, state::State},
    proto::{self, DmStartPayload, DmStartResponsePayload, PacketId, to_payload},
};

pub async fn handle_dm_start(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    state: &State,
) -> Result<()> {
    let req = DmStartPayload::decode(payload)?;

    let sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;
    let my_id = sess.user_id.clone();
    drop(sess);

    if state
        .storage
        .is_blocked(&req.target_user_id, &my_id)
        .await?
    {
        io::send_frame(
            stream,
            PacketId::Error,
            seq,
            &to_payload(&proto::ErrorPayload {
                code: proto::ErrorCode::Blocked as u32,
                message: "blocked".into(),
            }),
        )
        .await?;
        return Ok(());
    }

    if req.target_user_id == my_id {
        io::send_frame(
            stream,
            PacketId::Error,
            seq,
            &to_payload(&proto::ErrorPayload {
                code: proto::ErrorCode::InvalidPacket as u32,
                message: "cannot DM yourself".into(),
            }),
        )
        .await?;
        return Ok(());
    }

    let (dm_id, unread_count) = state
        .storage
        .find_or_create_dm(&my_id, &req.target_user_id)
        .await?;
    let other_id = state
        .storage
        .get_dm_user_id(&dm_id, &my_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("user not in DM"))?;
    let nickname = state
        .storage
        .get_dm_nickname(&other_id)
        .await?
        .unwrap_or_else(|| other_id[..8].to_string());
    let messages = state
        .storage
        .get_dm_messages(&dm_id, 50, None, None)
        .await?;

    let resp = DmStartResponsePayload {
        dm_id,
        other_user_id: other_id,
        other_nickname: nickname,
        messages,
        unread_count: unread_count as u32,
    };
    io::send_frame(stream, PacketId::DmStart, seq, &to_payload(&resp)).await?;
    Ok(())
}

pub async fn handle_dm_read_ack(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    state: &State,
) -> Result<()> {
    let req = crate::proto::DmReadAckPayload::decode(payload)?;

    let sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;
    let my_id = sess.user_id.clone();
    drop(sess);

    state.storage.reset_dm_unread(&req.dm_id, &my_id).await?;

    io::send_frame(stream, PacketId::DmReadAck, seq, b"{}").await?;
    Ok(())
}
