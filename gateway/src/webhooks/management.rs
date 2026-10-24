//! Management is available only inside an authenticated encrypted LNEx session.
use super::{now_ms, policy, secrets};
use crate::{
    domain::{permissions::Permissions, storage::webhooks::Hook},
    handler::Ctx,
    net::{io, state::State},
    proto::*,
};
use anyhow::Result;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};

pub async fn authorize(state: &State, user: &str, channel: &str) -> Result<Option<String>> {
    let Some((guild_id, owner, memberships)) = state.storage.webhook_scope(channel, user).await?
    else {
        return Ok(None);
    };
    if owner == user {
        return Ok(Some(guild_id));
    }
    if memberships == 0 {
        return Ok(None);
    }
    let roles = state.storage.get_user_role_perms(&guild_id, user).await?;
    Ok(Permissions::from_role_perms(&roles)
        .has(Permissions::MANAGE_WEBHOOKS)
        .then_some(guild_id))
}
fn info(h: &Hook) -> WebhookInfo {
    WebhookInfo {
        id: h.id.clone(),
        channel_id: h.channel_id.clone(),
        name: h.name.clone(),
        direction: h.direction.clone(),
        provider: h.provider.clone(),
        endpoint: h.endpoint.clone(),
        created_at: h.created_at,
        revoked: h.revoked_at.is_some(),
        suspended_reason: h.suspended_reason.clone().unwrap_or_default(),
    }
}
pub async fn handle<S: AsyncRead + AsyncWrite + Unpin>(
    ctx: &mut Ctx<'_, S>,
    session_id: &str,
    pid: PacketId,
    payload: &[u8],
) -> Result<()> {
    let Some(session) = crate::domain::session::get(&ctx.state.sessions, session_id).await else {
        return Ok(());
    };
    if payload.len() > 8192 {
        return error(
            ctx,
            "",
            ErrorCode::InvalidPacket,
            "webhook management payload too large",
        )
        .await;
    }
    let req = WebhookRequest::decode(payload)?;
    let request_id = req.request_id.clone();
    if request_id.len() > 64
        || !request_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return error(
            ctx,
            "",
            ErrorCode::InvalidPacket,
            "invalid request identifier",
        )
        .await;
    }
    if !ctx.state.rate_limiter.try_consume(session_id) {
        return error(ctx, &request_id, ErrorCode::RateLimited, "rate limited").await;
    }
    let existing = if pid == PacketId::WebhookRotate || pid == PacketId::WebhookRevoke {
        ctx.state.storage.hook(&req.id).await?
    } else {
        None
    };
    let channel = existing
        .as_ref()
        .map(|h| h.channel_id.as_str())
        .unwrap_or(&req.channel_id);
    let Some(guild) = authorize(ctx.state, &session.user_id, channel).await? else {
        return error(
            ctx,
            &request_id,
            ErrorCode::PermissionDenied,
            "permission denied",
        )
        .await;
    };
    if pid == PacketId::WebhookList {
        let hooks = ctx
            .state
            .storage
            .hooks(channel)
            .await?
            .iter()
            .map(info)
            .collect();
        return io::send_encrypted(
            ctx.stream,
            PacketId::WebhookListResult,
            ctx.seq,
            &to_payload(&WebhookListResult { hooks, request_id }),
            ctx.crypto,
        )
        .await;
    }
    let mut secret = String::new();
    let hook = if pid == PacketId::WebhookCreate {
        if req.name.trim().is_empty()
            || req.name.chars().count() > 64
            || req.name.chars().any(char::is_control)
        {
            return error(ctx, &request_id, ErrorCode::InvalidPacket, "invalid name").await;
        }
        if !matches!(
            (req.direction.as_str(), req.provider.as_str()),
            ("incoming", "generic" | "github") | ("outgoing", "generic")
        ) {
            return error(
                ctx,
                &request_id,
                ErrorCode::InvalidPacket,
                "unsupported webhook type",
            )
            .await;
        }
        if req.direction == "outgoing" && policy::endpoint(&req.endpoint).is_err() {
            return error(
                ctx,
                &request_id,
                ErrorCode::InvalidPacket,
                "HTTPS public endpoint required; no credentials/query/fragment",
            )
            .await;
        }
        let id = uuid::Uuid::new_v4().to_string();
        secret = secrets::new_secret();
        let sealed = if req.direction == "outgoing" || req.provider == "github" {
            let Some(key) = ctx.state.webhooks.key() else {
                return error(
                    ctx,
                    &request_id,
                    ErrorCode::Internal,
                    "webhook master key not configured",
                )
                .await;
            };
            secrets::seal(key, &id, &secret)?
        } else {
            Vec::new()
        };
        let h = Hook {
            id,
            channel_id: channel.into(),
            guild_id: guild,
            creator_id: session.user_id,
            name: req.name,
            direction: req.direction.clone(),
            provider: req.provider,
            endpoint: if req.direction == "outgoing" {
                req.endpoint
            } else {
                String::new()
            },
            token_hash: secrets::digest(secret.as_bytes()),
            sealed_secret: sealed,
            created_at: now_ms(),
            revoked_at: None,
            suspended_reason: None,
        };
        if let Err(problem) = ctx.state.storage.insert_hook(&h).await {
            let (code, message) = if problem.to_string() == "channel webhook limit reached" {
                (ErrorCode::RateLimited, "channel webhook limit reached")
            } else {
                (ErrorCode::Internal, "webhook creation failed")
            };
            return error(ctx, &request_id, code, message).await;
        }
        h
    } else {
        let Some(mut h) = existing.filter(|h| h.revoked_at.is_none()) else {
            return error(
                ctx,
                &request_id,
                ErrorCode::InvalidPacket,
                "webhook not found",
            )
            .await;
        };
        if pid == PacketId::WebhookRevoke {
            ctx.state.storage.revoke_hook(&h.id).await?;
            h.revoked_at = Some(now_ms());
        } else {
            secret = secrets::new_secret();
            let sealed = if h.direction == "outgoing" || h.provider == "github" {
                let Some(key) = ctx.state.webhooks.key() else {
                    return error(
                        ctx,
                        &request_id,
                        ErrorCode::Internal,
                        "webhook master key not configured",
                    )
                    .await;
                };
                secrets::seal(key, &h.id, &secret)?
            } else {
                Vec::new()
            };
            ctx.state
                .storage
                .rotate_hook(&h.id, &secrets::digest(secret.as_bytes()), &sealed)
                .await?;
            h.suspended_reason = None;
        }
        h
    };
    io::send_encrypted(
        ctx.stream,
        PacketId::WebhookResult,
        ctx.seq,
        &to_payload(&WebhookResult {
            hook: Some(info(&hook)),
            secret,
            request_id,
        }),
        ctx.crypto,
    )
    .await
}
async fn error<S: AsyncRead + AsyncWrite + Unpin>(
    ctx: &mut Ctx<'_, S>,
    request_id: &str,
    code: ErrorCode,
    msg: &str,
) -> Result<()> {
    io::send_encrypted(
        ctx.stream,
        PacketId::WebhookErrorResult,
        ctx.seq,
        &to_payload(&WebhookErrorResult {
            request_id: request_id.into(),
            code: code as u32,
            message: msg.into(),
        }),
        ctx.crypto,
    )
    .await
}
