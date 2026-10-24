use anyhow::Result;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    domain::{permissions::Permissions, session},
    net::{io, state::State},
    proto::{
        GuildMemberInfoPayload, GuildMemberListFetchPayload, GuildMemberListPayload,
        GuildRoleInfoPayload, GuildRoleListFetchPayload, GuildRoleListPayload, PacketId,
        RoleAssignPayload, SessionCrypto, to_payload,
    },
};

use super::{require_perm, send_err};

/// Fetch the member list for a guild (visible to all members).
pub async fn handle_member_list_fetch(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    crypto: &SessionCrypto,
    state: &State,
) -> Result<()> {
    let req = GuildMemberListFetchPayload::decode(payload)?;
    let sess = match session::get(&state.sessions, session_id).await {
        Some(s) => s,
        None => return Ok(()),
    };

    if !state
        .storage
        .list_user_guilds(&sess.user_id)
        .await?
        .iter()
        .any(|g| g.id == req.guild_id)
    {
        send_err(
            stream,
            seq,
            crate::proto::ErrorCode::PermissionDenied,
            "guild membership required",
            crypto,
        )
        .await?;
        return Ok(());
    }
    // Membership is checked before listing identities.
    let owner_id = state
        .storage
        .get_guild(&req.guild_id)
        .await?
        .map(|g| g.owner_id);

    let rows = state.storage.list_guild_members(&req.guild_id).await?;
    let members: Vec<GuildMemberInfoPayload> = rows
        .into_iter()
        .map(|r| GuildMemberInfoPayload {
            user_id: r.user_id.clone(),
            nickname: r.nickname,
            joined_at: r.joined_at,
            role_color: r.role_color,
            role_name: r.role_name,
            is_owner: owner_id.as_deref() == Some(&r.user_id),
        })
        .collect();
    let _ = sess;
    let resp = GuildMemberListPayload {
        guild_id: req.guild_id,
        members,
    };
    io::send_encrypted(
        stream,
        PacketId::GuildMemberList,
        seq,
        &to_payload(&resp),
        crypto,
    )
    .await?;
    Ok(())
}

/// Assign a role to a user (admin only: requires MANAGE_ROLES).
pub async fn handle_role_assign(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    crypto: &SessionCrypto,
    state: &State,
) -> Result<()> {
    let req = RoleAssignPayload::decode(payload)?;
    let sess = match session::get(&state.sessions, session_id).await {
        Some(s) => s,
        None => return Ok(()),
    };

    let access = state.access.write().await;
    if !require_perm(
        state,
        &req.guild_id,
        &sess.user_id,
        Permissions::MANAGE_ROLES,
    )
    .await?
    {
        drop(access);
        send_err(
            stream,
            seq,
            crate::proto::ErrorCode::PermissionDenied,
            "missing MANAGE_ROLES permission",
            crypto,
        )
        .await?;
        return Ok(());
    }

    let role = super::roles::role_permissions(state, &req.guild_id, &req.role_id).await?;
    if !state
        .storage
        .list_user_guilds(&req.user_id)
        .await?
        .iter()
        .any(|g| g.id == req.guild_id)
        || match role {
            Some(permissions) => {
                !super::roles::may_grant(state, &req.guild_id, &sess.user_id, permissions).await?
            }
            None => true,
        }
    {
        drop(access);
        send_err(
            stream,
            seq,
            crate::proto::ErrorCode::PermissionDenied,
            "role or target not permitted in this guild",
            crypto,
        )
        .await?;
        return Ok(());
    }
    state
        .storage
        .assign_role(&req.guild_id, &req.user_id, &req.role_id)
        .await?;
    state
        .storage
        .append_audit_log(
            &req.guild_id,
            &sess.user_id,
            "ROLE_ASSIGN",
            Some(&req.user_id),
            Some("user"),
            Some(&req.role_id),
        )
        .await?;

    drop(access);
    // Confirm to caller.
    io::send_encrypted(
        stream,
        PacketId::GuildRoleAssign,
        seq,
        &to_payload(&RoleAssignPayload {
            guild_id: req.guild_id.clone(),
            user_id: req.user_id.clone(),
            role_id: req.role_id.clone(),
        }),
        crypto,
    )
    .await?;
    Ok(())
}

/// Remove a role from a user (admin only: requires MANAGE_ROLES).
pub async fn handle_role_unassign(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    crypto: &SessionCrypto,
    state: &State,
) -> Result<()> {
    let req = RoleAssignPayload::decode(payload)?;
    let sess = match session::get(&state.sessions, session_id).await {
        Some(s) => s,
        None => return Ok(()),
    };

    let access = state.access.write().await;
    if !require_perm(
        state,
        &req.guild_id,
        &sess.user_id,
        Permissions::MANAGE_ROLES,
    )
    .await?
    {
        drop(access);
        send_err(
            stream,
            seq,
            crate::proto::ErrorCode::PermissionDenied,
            "missing MANAGE_ROLES permission",
            crypto,
        )
        .await?;
        return Ok(());
    }

    let role = super::roles::role_permissions(state, &req.guild_id, &req.role_id).await?;
    if !state
        .storage
        .list_user_guilds(&req.user_id)
        .await?
        .iter()
        .any(|g| g.id == req.guild_id)
        || match role {
            Some(permissions) => {
                !super::roles::may_grant(state, &req.guild_id, &sess.user_id, permissions).await?
            }
            None => true,
        }
    {
        drop(access);
        send_err(
            stream,
            seq,
            crate::proto::ErrorCode::PermissionDenied,
            "role or target not permitted in this guild",
            crypto,
        )
        .await?;
        return Ok(());
    }
    state
        .storage
        .remove_role_from_user(&req.guild_id, &req.user_id, &req.role_id)
        .await?;
    crate::handler::channel::recheck_voice_permissions(state, &req.guild_id, Some(&req.user_id))
        .await?;
    state
        .storage
        .append_audit_log(
            &req.guild_id,
            &sess.user_id,
            "ROLE_UNASSIGN",
            Some(&req.user_id),
            Some("user"),
            Some(&req.role_id),
        )
        .await?;

    drop(access);
    io::send_encrypted(
        stream,
        PacketId::GuildRoleUnassign,
        seq,
        &to_payload(&RoleAssignPayload {
            guild_id: req.guild_id.clone(),
            user_id: req.user_id.clone(),
            role_id: req.role_id.clone(),
        }),
        crypto,
    )
    .await?;
    Ok(())
}

/// Fetch all roles defined in a guild (visible to all members).
pub async fn handle_role_list_fetch(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    crypto: &SessionCrypto,
    state: &State,
) -> Result<()> {
    let req = GuildRoleListFetchPayload::decode(payload)?;
    let Some(sess) = session::get(&state.sessions, session_id).await else {
        return Ok(());
    };
    if !state
        .storage
        .list_user_guilds(&sess.user_id)
        .await?
        .iter()
        .any(|g| g.id == req.guild_id)
    {
        send_err(
            stream,
            seq,
            crate::proto::ErrorCode::PermissionDenied,
            "guild membership required",
            crypto,
        )
        .await?;
        return Ok(());
    }

    let rows = state.storage.list_guild_roles(&req.guild_id).await?;
    let roles: Vec<GuildRoleInfoPayload> = rows
        .into_iter()
        .map(|r| GuildRoleInfoPayload {
            id: r.id,
            guild_id: r.guild_id,
            name: r.name,
            color: r.color,
            permissions: r.permissions as u64,
            position: r.position,
        })
        .collect();
    let resp = GuildRoleListPayload {
        guild_id: req.guild_id,
        roles,
    };
    io::send_encrypted(
        stream,
        PacketId::GuildRoleList,
        seq,
        &to_payload(&resp),
        crypto,
    )
    .await?;
    Ok(())
}
