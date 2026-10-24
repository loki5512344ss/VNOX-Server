use anyhow::Result;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    domain::permissions::Permissions,
    net::{io, state::State},
    proto::{
        AuditLogEntryPayload, GuildAuditLogFetchPayload, GuildAuditLogPayload, PacketId, to_payload,
    },
};

/// Fetch audit log entries for a guild (admin-only: requires VIEW_AUDIT_LOG or owner).
pub async fn handle_audit_log_fetch(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    state: &State,
) -> Result<()> {
    let req = GuildAuditLogFetchPayload::decode(payload)?;
    let sess = match crate::domain::session::get(&state.sessions, session_id).await {
        Some(s) => s,
        None => return Ok(()),
    };

    // Permission check: owner always passes; otherwise require VIEW_AUDIT_LOG.
    // We reuse the existing helper via the same logic.
    let allowed = if let Some(g) = state.storage.get_guild(&req.guild_id).await?
        && g.owner_id == sess.user_id
    {
        true
    } else {
        // No VIEW_AUDIT_LOG bit defined yet — fall back to MANAGE_GUILD.
        let perms = state
            .storage
            .get_user_role_perms(&req.guild_id, &sess.user_id)
            .await?;
        Permissions::from_role_perms(&perms).has(Permissions::MANAGE_GUILD)
    };

    if !allowed {
        io::send_frame(
            stream,
            PacketId::Error,
            seq,
            &to_payload(&crate::proto::ErrorPayload {
                code: crate::proto::ErrorCode::PermissionDenied as u32,
                message: "audit log access requires MANAGE_GUILD".into(),
            }),
        )
        .await?;
        return Ok(());
    }

    let limit = req.limit.clamp(1, 200);
    let rows = state.storage.get_audit_log(&req.guild_id, limit).await?;
    let entries: Vec<AuditLogEntryPayload> = rows
        .into_iter()
        .map(|r| AuditLogEntryPayload {
            id: r.id,
            guild_id: r.guild_id,
            actor_id: r.actor_id,
            action: r.action,
            target_id: r.target_id,
            target_type: r.target_type,
            reason: r.reason,
            created_at: r.created_at,
        })
        .collect();
    let resp = GuildAuditLogPayload {
        guild_id: req.guild_id,
        entries,
    };
    io::send_frame(stream, PacketId::GuildAuditLog, seq, &to_payload(&resp)).await?;
    Ok(())
}
