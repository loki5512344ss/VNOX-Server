use anyhow::Result;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    domain::{permissions::Permissions, session},
    net::{io, state::State},
    proto::{
        GuildMemberJoinPayload, GuildMemberKickPayload, GuildMemberLeavePayload, PacketId,
        SessionCrypto, to_payload,
    },
};

use super::send_err;

pub async fn handle_guild_member_join(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    crypto: &SessionCrypto,
    state: &State,
) -> Result<()> {
    let guard = state.access.write().await;
    let req = GuildMemberJoinPayload::decode(payload)?;
    let sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;

    if !state
        .storage
        .list_user_guilds(&sess.user_id)
        .await?
        .iter()
        .any(|g| g.id == req.guild_id)
    {
        drop(guard);
        send_err(
            stream,
            seq,
            crate::proto::ErrorCode::PermissionDenied,
            "a valid invitation is required",
            crypto,
        )
        .await?;
        return Ok(());
    }
    state
        .storage
        .add_guild_member(&req.guild_id, &sess.user_id)
        .await?;

    let roles = state
        .storage
        .get_user_roles(&req.guild_id, &sess.user_id)
        .await?;
    let color = roles
        .iter()
        .max_by_key(|r| r.position)
        .map(|r| r.color.clone())
        .unwrap_or_else(|| "#ffffff".into());

    drop(guard);
    io::send_encrypted(
        stream,
        PacketId::GuildMemberJoin,
        seq,
        &to_payload(&crate::proto::GuildMemberJoinPayload {
            guild_id: req.guild_id.clone(),
        }),
        crypto,
    )
    .await?;

    io::send_encrypted(
        stream,
        PacketId::UserRoleUpdate,
        seq,
        &to_payload(&crate::proto::UserRoleUpdatePayload {
            user_id: sess.user_id.clone(),
            guild_id: req.guild_id.clone(),
            color,
        }),
        crypto,
    )
    .await?;
    Ok(())
}

pub async fn handle_guild_member_leave(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    crypto: &SessionCrypto,
    state: &State,
) -> Result<()> {
    let guard = state.access.write().await;
    let req = GuildMemberLeavePayload::decode(payload)?;
    let sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;

    let target = if req.user_id.is_empty() {
        sess.user_id.clone()
    } else {
        req.user_id.clone()
    };
    let owner = state
        .storage
        .get_guild(&req.guild_id)
        .await?
        .is_some_and(|g| g.owner_id == target);
    if target != sess.user_id || owner {
        drop(guard);
        send_err(
            stream,
            seq,
            crate::proto::ErrorCode::PermissionDenied,
            "only a non-owner may leave their own membership",
            crypto,
        )
        .await?;
        return Ok(());
    }
    state
        .storage
        .remove_guild_member(&req.guild_id, target.as_str())
        .await?;
    crate::handler::channel::revoke_guild_access(state, &req.guild_id, Some(&target)).await;
    drop(guard);
    io::send_encrypted(
        stream,
        PacketId::GuildMemberLeave,
        seq,
        &to_payload(&GuildMemberLeavePayload {
            guild_id: req.guild_id.clone(),
            user_id: target,
        }),
        crypto,
    )
    .await?;
    Ok(())
}

pub async fn handle_guild_member_kick(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    crypto: &SessionCrypto,
    state: &State,
) -> Result<()> {
    let guard = state.access.write().await;
    let req = GuildMemberKickPayload::decode(payload)?;
    let sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;

    if !super::require_perm(
        state,
        &req.guild_id,
        &sess.user_id,
        Permissions::KICK_MEMBERS,
    )
    .await?
    {
        drop(guard);
        send_err(
            stream,
            seq,
            crate::proto::ErrorCode::PermissionDenied,
            "missing KICK_MEMBERS permission",
            crypto,
        )
        .await?;
        return Ok(());
    }

    if state
        .storage
        .get_guild(&req.guild_id)
        .await?
        .is_some_and(|g| g.owner_id == req.user_id)
    {
        drop(guard);
        send_err(
            stream,
            seq,
            crate::proto::ErrorCode::PermissionDenied,
            "guild owner cannot be kicked",
            crypto,
        )
        .await?;
        return Ok(());
    }
    state
        .storage
        .remove_guild_member(&req.guild_id, &req.user_id)
        .await?;
    crate::handler::channel::revoke_guild_access(state, &req.guild_id, Some(&req.user_id)).await;
    state
        .storage
        .append_audit_log(
            &req.guild_id,
            &sess.user_id,
            "MEMBER_KICK",
            Some(&req.user_id),
            Some("member"),
            None,
        )
        .await?;
    drop(guard);
    io::send_encrypted(
        stream,
        PacketId::GuildMemberKick,
        seq,
        &to_payload(&GuildMemberKickPayload {
            guild_id: req.guild_id.clone(),
            user_id: req.user_id.clone(),
        }),
        crypto,
    )
    .await?;
    Ok(())
}
