use anyhow::Result;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    domain::{permissions::Permissions, session},
    net::{io, state::State},
    proto::{PacketId, RoleCreatePayload, RoleDeletePayload, SessionCrypto, to_payload},
};

use super::send_err;

pub async fn handle_role_create(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    crypto: &SessionCrypto,
    state: &State,
) -> Result<()> {
    let req = RoleCreatePayload::decode(payload)?;
    let sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;

    let access = state.access.write().await;
    if !super::require_perm(
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

    let color = req.color.as_deref().unwrap_or("#ffffff");
    let permissions = req.permissions.unwrap_or(0);
    if req.name.trim().is_empty()
        || req.name.chars().count() > 64
        || req.name.chars().any(char::is_control)
        || !may_grant(state, &req.guild_id, &sess.user_id, permissions).await?
    {
        drop(access);
        send_err(
            stream,
            seq,
            crate::proto::ErrorCode::PermissionDenied,
            "cannot grant requested role",
            crypto,
        )
        .await?;
        return Ok(());
    }
    let role_id = state
        .storage
        .create_role(&req.guild_id, &req.name, color, permissions, 1)
        .await?;

    state
        .storage
        .append_audit_log(
            &req.guild_id,
            &sess.user_id,
            "ROLE_CREATE",
            Some(&role_id),
            Some("role"),
            None,
        )
        .await?;
    drop(access);
    io::send_encrypted(
        stream,
        PacketId::RoleCreate,
        seq,
        &to_payload(&RoleCreatePayload {
            guild_id: req.guild_id.clone(),
            name: req.name.clone(),
            color: req.color.clone(),
            permissions: req.permissions,
            id: role_id,
        }),
        crypto,
    )
    .await?;
    Ok(())
}

pub async fn handle_role_delete(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    crypto: &SessionCrypto,
    state: &State,
) -> Result<()> {
    let req = RoleDeletePayload::decode(payload)?;
    let sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;

    let access = state.access.write().await;
    if !super::require_perm(
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

    let Some(permissions) = role_permissions(state, &req.guild_id, &req.role_id).await? else {
        drop(access);
        send_err(
            stream,
            seq,
            crate::proto::ErrorCode::PermissionDenied,
            "role is outside this guild",
            crypto,
        )
        .await?;
        return Ok(());
    };
    if !may_grant(state, &req.guild_id, &sess.user_id, permissions).await? {
        drop(access);
        send_err(
            stream,
            seq,
            crate::proto::ErrorCode::PermissionDenied,
            "cannot manage requested role",
            crypto,
        )
        .await?;
        return Ok(());
    }
    state.storage.delete_role(&req.role_id).await?;
    crate::handler::channel::recheck_voice_permissions(state, &req.guild_id, None).await?;
    state
        .storage
        .append_audit_log(
            &req.guild_id,
            &sess.user_id,
            "ROLE_DELETE",
            Some(&req.role_id),
            Some("role"),
            None,
        )
        .await?;
    drop(access);
    io::send_encrypted(
        stream,
        PacketId::RoleDelete,
        seq,
        &to_payload(&RoleDeletePayload {
            guild_id: req.guild_id.clone(),
            role_id: req.role_id.clone(),
        }),
        crypto,
    )
    .await?;
    Ok(())
}

/// A role manager cannot create/assign permissions they do not themselves hold.
pub(super) async fn may_grant(
    state: &State,
    guild: &str,
    actor: &str,
    permissions: u64,
) -> Result<bool> {
    if state
        .storage
        .get_guild(guild)
        .await?
        .is_some_and(|g| g.owner_id == actor)
    {
        return Ok(true);
    }
    let held =
        Permissions::from_role_perms(&state.storage.get_user_role_perms(guild, actor).await?);
    Ok(held.has(Permissions::ADMINISTRATOR) || permissions & !held.bits() == 0)
}
pub(super) async fn role_permissions(
    state: &State,
    guild: &str,
    role: &str,
) -> Result<Option<u64>> {
    Ok(state
        .storage
        .list_guild_roles(guild)
        .await?
        .into_iter()
        .find(|r| r.id == role)
        .map(|r| r.permissions as u64))
}
