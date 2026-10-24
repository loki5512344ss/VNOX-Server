use anyhow::Result;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    domain::session,
    net::{io, state::State},
    proto::{
        FriendAcceptPayload, FriendEventPayload, FriendRequestPayload, PacketId, SessionCrypto,
        to_payload,
    },
};

use super::send_err;

pub async fn handle_friend_request(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    crypto: &SessionCrypto,
    state: &State,
) -> Result<()> {
    let req = FriendRequestPayload::decode(payload)?;
    let sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;

    if state
        .storage
        .is_blocked(&req.to_user_id, &sess.user_id)
        .await?
    {
        send_err(
            stream,
            seq,
            crate::proto::ErrorCode::Blocked,
            "you are blocked by this user",
            crypto,
        )
        .await?;
        return Ok(());
    }

    if state
        .storage
        .is_friend(&sess.user_id, &req.to_user_id)
        .await?
    {
        send_err(
            stream,
            seq,
            crate::proto::ErrorCode::InvalidPacket,
            "already friends",
            crypto,
        )
        .await?;
        return Ok(());
    }

    let ok = state
        .storage
        .create_friend_request(&sess.user_id, &req.to_user_id)
        .await?;
    if !ok {
        send_err(
            stream,
            seq,
            crate::proto::ErrorCode::InvalidPacket,
            "already friends or request pending",
            crypto,
        )
        .await?;
        return Ok(());
    }

    let ev = FriendEventPayload {
        event: "REQUEST_RECEIVED".into(),
        user_id: sess.user_id.clone(),
        nickname: Some(sess.nickname.clone()),
    };
    super::notify_user(state, &req.to_user_id, &ev).await;

    io::send_encrypted(
        stream,
        PacketId::FriendRequest,
        seq,
        &to_payload(&FriendRequestPayload {
            to_user_id: req.to_user_id.clone(),
        }),
        crypto,
    )
    .await?;
    Ok(())
}

pub async fn handle_friend_accept(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    crypto: &SessionCrypto,
    state: &State,
) -> Result<()> {
    let req = FriendAcceptPayload::decode(payload)?;
    let sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;

    let ok = state
        .storage
        .accept_friend_request(&req.from_user_id, &sess.user_id)
        .await?;
    if !ok {
        send_err(
            stream,
            seq,
            crate::proto::ErrorCode::InvalidPacket,
            "no pending request",
            crypto,
        )
        .await?;
        return Ok(());
    }

    let ev = FriendEventPayload {
        event: "REQUEST_ACCEPTED".into(),
        user_id: sess.user_id.clone(),
        nickname: Some(sess.nickname.clone()),
    };
    super::notify_user(state, &req.from_user_id, &ev).await;

    io::send_encrypted(
        stream,
        PacketId::FriendAccept,
        seq,
        &to_payload(&FriendAcceptPayload {
            from_user_id: req.from_user_id.clone(),
        }),
        crypto,
    )
    .await?;
    Ok(())
}
