use anyhow::Result;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

use crate::{
    domain::session,
    net::{io, state::State},
    proto::{GuildCreatePayload, GuildInfo, PacketId, to_payload},
};

use super::send_err;

pub async fn handle_guild_create(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    state: &State,
) -> Result<()> {
    let req = GuildCreatePayload::decode(payload)?;
    let sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;

    if req.name.len() < 2 || req.name.len() > 100 {
        send_err(
            stream,
            seq,
            crate::proto::ErrorCode::InvalidPacket,
            "guild name must be 2-100 chars",
        )
        .await?;
        return Ok(());
    }

    let guild_id = state.storage.create_guild(&sess.user_id, &req.name).await?;
    let guild = state
        .storage
        .get_guild(&guild_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("guild not found after create"))?;

    let info = GuildInfo {
        id: guild.id.clone(),
        owner_id: guild.owner_id,
        name: guild.name,
        member_count: guild.member_count,
        created_at: guild.created_at,
    };

    io::send_frame(stream, PacketId::GuildCreate, seq, &to_payload(&info)).await?;

    debug!(
        "guild: {} created {} (owner={})",
        sess.nickname, guild_id, sess.user_id
    );
    Ok(())
}

pub async fn handle_guild_delete(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    state: &State,
) -> Result<()> {
    let guard = state.access.write().await;
    let req = crate::proto::GuildDeletePayload::decode(payload)?;
    let sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;

    let guild = state
        .storage
        .get_guild(&req.guild_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("guild not found"))?;
    if guild.owner_id != sess.user_id {
        drop(guard);
        send_err(
            stream,
            seq,
            crate::proto::ErrorCode::PermissionDenied,
            "only owner can delete guild",
        )
        .await?;
        return Ok(());
    }

    crate::handler::channel::revoke_guild_access(state, &req.guild_id, None).await;
    state.storage.delete_guild(&req.guild_id).await?;
    state
        .storage
        .append_audit_log(
            &req.guild_id,
            &sess.user_id,
            "GUILD_DELETE",
            None,
            None,
            None,
        )
        .await?;

    drop(guard);
    io::send_frame(
        stream,
        PacketId::GuildDelete,
        seq,
        &to_payload(&crate::proto::GuildDeletePayload {
            guild_id: req.guild_id.clone(),
        }),
    )
    .await?;
    Ok(())
}
