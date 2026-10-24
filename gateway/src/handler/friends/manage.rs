use anyhow::Result;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    domain::session,
    net::{io, state::State},
    proto::{
        BlockListPayload, BlockUserPayload, FriendRemovePayload, PacketId, SimpleResponsePayload,
        UnblockUserPayload, to_payload,
    },
};

pub async fn handle_friend_remove(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    state: &State,
) -> Result<()> {
    let req = FriendRemovePayload::decode(payload)?;
    let sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;

    state
        .storage
        .remove_friend(&sess.user_id, &req.user_id)
        .await?;

    io::send_frame(
        stream,
        PacketId::FriendRemove,
        seq,
        &to_payload(&SimpleResponsePayload {
            ok: true,
            user_id: None,
            role_id: None,
        }),
    )
    .await?;
    Ok(())
}

pub async fn handle_block_user(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    state: &State,
) -> Result<()> {
    let req = BlockUserPayload::decode(payload)?;
    let sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;

    state
        .storage
        .block_user(&sess.user_id, &req.user_id)
        .await?;

    io::send_frame(
        stream,
        PacketId::BlockUser,
        seq,
        &to_payload(&SimpleResponsePayload {
            ok: true,
            user_id: None,
            role_id: None,
        }),
    )
    .await?;
    Ok(())
}

pub async fn handle_unblock_user(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    state: &State,
) -> Result<()> {
    let req = UnblockUserPayload::decode(payload)?;
    let sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;

    state
        .storage
        .unblock_user(&sess.user_id, &req.user_id)
        .await?;

    io::send_frame(
        stream,
        PacketId::UnblockUser,
        seq,
        &to_payload(&SimpleResponsePayload {
            ok: true,
            user_id: None,
            role_id: None,
        }),
    )
    .await?;
    Ok(())
}

pub async fn handle_block_list(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    state: &State,
) -> Result<()> {
    let sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;

    let blocked = state.storage.list_blocks(&sess.user_id).await?;

    io::send_frame(
        stream,
        PacketId::BlockList,
        seq,
        &to_payload(&BlockListPayload { blocked }),
    )
    .await?;
    Ok(())
}
