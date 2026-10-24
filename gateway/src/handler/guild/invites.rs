use anyhow::Result;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    domain::{permissions::Permissions, session},
    net::{io, state::State},
    proto::{
        InviteAcceptPayload, InviteCreatePayload, InviteDeletePayload, InviteInfo, PacketId,
        to_payload,
    },
};

use super::{now_ms, send_err};

pub async fn handle_invite_create(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    state: &State,
) -> Result<()> {
    let req = InviteCreatePayload::decode(payload)?;
    let sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;

    if !super::require_perm(
        state,
        &req.guild_id,
        &sess.user_id,
        Permissions::CREATE_INVITE,
    )
    .await?
    {
        send_err(
            stream,
            seq,
            crate::proto::ErrorCode::PermissionDenied,
            "missing CREATE_INVITE permission",
        )
        .await?;
        return Ok(());
    }

    let inv = state
        .storage
        .create_invite(
            &req.guild_id,
            &sess.user_id,
            req.max_uses,
            req.expires_in_seconds,
        )
        .await?;

    state
        .storage
        .append_audit_log(
            &req.guild_id,
            &sess.user_id,
            "INVITE_CREATE",
            Some(&inv.id),
            Some("invite"),
            None,
        )
        .await?;

    let info = InviteInfo {
        id: inv.id,
        guild_id: inv.guild_id,
        guild_name: inv.guild_name,
        code: inv.code,
        creator_id: inv.creator_id,
        max_uses: inv.max_uses,
        uses: inv.uses,
        expires_at: inv.expires_at,
        created_at: inv.created_at,
    };
    io::send_frame(stream, PacketId::InviteCreate, seq, &to_payload(&info)).await?;
    Ok(())
}

pub async fn handle_invite_accept(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    state: &State,
) -> Result<()> {
    let req = InviteAcceptPayload::decode(payload)?;
    let sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;

    let inv = state
        .storage
        .get_invite_by_code(&req.code)
        .await?
        .ok_or_else(|| anyhow::anyhow!("invite not found"))?;

    if let Some(exp) = inv.expires_at {
        let now = now_ms();
        if now > exp {
            send_err(
                stream,
                seq,
                crate::proto::ErrorCode::InvalidPacket,
                "invite expired",
            )
            .await?;
            return Ok(());
        }
    }
    if let Some(max) = inv.max_uses
        && inv.uses >= max
    {
        send_err(
            stream,
            seq,
            crate::proto::ErrorCode::InvalidPacket,
            "invite max uses reached",
        )
        .await?;
        return Ok(());
    }

    state
        .storage
        .add_guild_member(&inv.guild_id, &sess.user_id)
        .await?;
    state.storage.use_invite(&inv.id).await?;
    state
        .storage
        .append_audit_log(
            &inv.guild_id,
            &sess.user_id,
            "MEMBER_JOIN_INVITE",
            Some(&sess.user_id),
            Some("member"),
            None,
        )
        .await?;

    io::send_frame(
        stream,
        PacketId::InviteAccept,
        seq,
        &to_payload(&InviteAcceptPayload {
            code: "".into(),
            guild_id: inv.guild_id.clone(),
            guild_name: inv.guild_name.clone(),
        }),
    )
    .await?;
    Ok(())
}

pub async fn handle_invite_delete(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    state: &State,
) -> Result<()> {
    let req = InviteDeletePayload::decode(payload)?;
    let sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;

    if !super::require_perm(
        state,
        &req.guild_id,
        &sess.user_id,
        Permissions::MANAGE_GUILD,
    )
    .await?
    {
        send_err(
            stream,
            seq,
            crate::proto::ErrorCode::PermissionDenied,
            "missing MANAGE_GUILD permission",
        )
        .await?;
        return Ok(());
    }

    state.storage.delete_invite(&req.invite_id).await?;
    state
        .storage
        .append_audit_log(
            &req.guild_id,
            &sess.user_id,
            "INVITE_DELETE",
            Some(&req.invite_id),
            Some("invite"),
            None,
        )
        .await?;
    io::send_frame(
        stream,
        PacketId::InviteDelete,
        seq,
        &to_payload(&InviteDeletePayload {
            guild_id: req.guild_id.clone(),
            invite_id: req.invite_id.clone(),
        }),
    )
    .await?;
    Ok(())
}
