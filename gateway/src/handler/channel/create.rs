use anyhow::Result;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{info, warn};

use crate::{
    domain::{channels, session},
    net::{io, state::State},
    proto::{
        ChannelCreatePayload, ChannelDeletePayload, ChannelListItem, ChannelListPayload,
        ChannelStatePayload, PacketId, SessionCrypto, encode_packet, to_payload,
    },
};

/// Handle a ChannelCreate request — register a new channel in the store and
/// broadcast the new ChannelState to all sessions so their sidebars update.
pub async fn handle_channel_create(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    crypto: &SessionCrypto,
    state: &State,
) -> Result<()> {
    let req = ChannelCreatePayload::decode(payload)?;
    let sess = match session::get(&state.sessions, session_id).await {
        Some(s) => s,
        None => return Ok(()),
    };

    // Validate kind.
    let kind = match req.kind.as_str() {
        "text" => channels::ChannelKind::Text,
        "voice" => channels::ChannelKind::Voice,
        other => {
            warn!(
                "channel_create from {}: invalid kind '{other}'",
                sess.nickname
            );
            io::send_encrypted(
                stream,
                PacketId::Error,
                seq,
                &to_payload(&crate::proto::ErrorPayload {
                    code: crate::proto::ErrorCode::InvalidPacket as u32,
                    message: format!("invalid channel kind: {other}"),
                }),
                crypto,
            )
            .await?;
            return Ok(());
        }
    };

    let channel_id = req.channel_id.trim().to_string();
    let channel_name = if req.channel_name.trim().is_empty() {
        channel_id.clone()
    } else {
        req.channel_name.trim().to_string()
    };

    if channel_id.is_empty()
        || channel_id.len() > 128
        || channel_name.chars().count() > 100
        || channel_id.chars().any(char::is_control)
        || channel_name.chars().any(char::is_control)
    {
        io::send_encrypted(
            stream,
            PacketId::Error,
            seq,
            &to_payload(&crate::proto::ErrorPayload {
                code: crate::proto::ErrorCode::InvalidPacket as u32,
                message: "channel_id is required".into(),
            }),
            crypto,
        )
        .await?;
        return Ok(());
    }

    // Limit channel-create rate (reuse the per-session token bucket — 1 token
    // means 1 channel-create per rate window).
    if !state.rate_limiter.try_consume(session_id) {
        state.metrics.inc(&state.metrics.rate_limited_events);
        warn!("rate-limited channel_create from {}", sess.nickname);
        io::send_encrypted(
            stream,
            PacketId::Error,
            seq,
            &to_payload(&crate::proto::ErrorPayload {
                code: crate::proto::ErrorCode::RateLimited as u32,
                message: "slow down — too many channel operations".into(),
            }),
            crypto,
        )
        .await?;
        return Ok(());
    }

    let access = state.access.write().await;
    if !super::may_manage(state, &sess.user_id, req.guild_id.as_deref()).await? {
        drop(access);
        super::denied(stream, seq, crypto).await?;
        return Ok(());
    }

    let guild_id = req.guild_id.clone();

    let created = channels::create(
        &state.channels,
        &channel_id,
        &channel_name,
        kind.clone(),
        guild_id.clone(),
    )
    .await;

    if created
        && let Err(error) = state
            .storage
            .create_channel(
                &channel_id,
                &channel_name,
                kind.as_str(),
                guild_id.as_deref(),
            )
            .await
    {
        channels::delete(&state.channels, &channel_id).await;
        return Err(error);
    }

    drop(access);
    if !created {
        io::send_encrypted(
            stream,
            PacketId::Error,
            seq,
            &to_payload(&crate::proto::ErrorPayload {
                code: crate::proto::ErrorCode::ChannelNotFound as u32,
                message: "channel already exists".into(),
            }),
            crypto,
        )
        .await?;
        return Ok(());
    }

    info!(
        "channel_create: {} created '{}' ({}) by {}",
        channel_id,
        channel_name,
        kind.as_str(),
        sess.nickname
    );

    // Reply to creator with ChannelState (no members yet).
    let sp = ChannelStatePayload {
        channel_id: channel_id.clone(),
        channel_name: channel_name.clone(),
        kind: kind.as_str().into(),
        members: Vec::new(),
        voice_endpoint: state.config.voice.bind.clone(),
        guild_id: req.guild_id.clone(),
    };
    io::send_encrypted(
        stream,
        PacketId::ChannelState,
        seq,
        &to_payload(&sp),
        crypto,
    )
    .await?;

    super::notify_guild(
        state,
        guild_id.as_deref(),
        Some(session_id),
        encode_packet(
            PacketId::ChannelCreate,
            0,
            &to_payload(&ChannelCreatePayload {
                channel_id: channel_id.clone(),
                channel_name: channel_name.clone(),
                kind: kind.as_str().into(),
                guild_id: guild_id.clone(),
            }),
        ),
    )
    .await?;

    Ok(())
}

/// Handle a ChannelDelete request — remove the channel from the store and
/// broadcast the deletion to all sessions.
pub async fn handle_channel_delete(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    crypto: &SessionCrypto,
    state: &State,
) -> Result<()> {
    let req = ChannelDeletePayload::decode(payload)?;
    let sess = match session::get(&state.sessions, session_id).await {
        Some(s) => s,
        None => return Ok(()),
    };

    // Protect default channels from deletion.
    if req.channel_id == "general" || req.channel_id == "voice" {
        io::send_encrypted(
            stream,
            PacketId::Error,
            seq,
            &to_payload(&crate::proto::ErrorPayload {
                code: crate::proto::ErrorCode::PermissionDenied as u32,
                message: "cannot delete default channels".into(),
            }),
            crypto,
        )
        .await?;
        return Ok(());
    }

    let access = state.access.write().await;
    let channel = channels::get_channel(&state.channels, &req.channel_id).await;
    if !super::may_manage(
        state,
        &sess.user_id,
        channel.as_ref().and_then(|c| c.guild_id.as_deref()),
    )
    .await?
    {
        drop(access);
        super::denied(stream, seq, crypto).await?;
        return Ok(());
    }
    state.storage.delete_channel(&req.channel_id).await?;
    super::revoke_channel(state, &req.channel_id).await;
    let existed = channels::delete(&state.channels, &req.channel_id).await;
    drop(access);

    if !existed {
        io::send_encrypted(
            stream,
            PacketId::Error,
            seq,
            &to_payload(&crate::proto::ErrorPayload {
                code: crate::proto::ErrorCode::ChannelNotFound as u32,
                message: "channel not found".into(),
            }),
            crypto,
        )
        .await?;
        return Ok(());
    }

    info!(
        "channel_delete: '{}' removed by {}",
        req.channel_id, sess.nickname
    );

    super::notify_guild(
        state,
        channel
            .as_ref()
            .and_then(|channel| channel.guild_id.as_deref()),
        None,
        encode_packet(
            PacketId::ChannelDelete,
            0,
            &to_payload(&ChannelDeletePayload {
                channel_id: req.channel_id.clone(),
            }),
        ),
    )
    .await?;

    Ok(())
}

/// Handle a ChannelList request — reply with known channels, optionally filtered by guild_id.
pub async fn handle_channel_list(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    crypto: &SessionCrypto,
    state: &State,
) -> Result<()> {
    let Some(sess) = session::get(&state.sessions, session_id).await else {
        return Ok(());
    };
    let guilds = state.storage.list_user_guilds(&sess.user_id).await?;

    // Decode optional guild_id filter from request.
    let filter_guild_id = if !payload.is_empty() {
        let req = ChannelListPayload::decode(payload).ok();
        req.and_then(|r| r.guild_id)
    } else {
        None
    };

    let channels = channels::list(&state.channels).await;
    let items: Vec<ChannelListItem> = channels
        .iter()
        .filter(|c| {
            c.guild_id
                .as_ref()
                .is_none_or(|guild| guilds.iter().any(|g| &g.id == guild))
        })
        .filter(|c| {
            filter_guild_id
                .as_ref()
                .map(|gid| c.guild_id.as_deref() == Some(gid.as_str()))
                .unwrap_or(true)
        })
        .map(|c| ChannelListItem {
            channel_id: c.id.clone(),
            channel_name: c.name.clone(),
            kind: c.kind.as_str().into(),
            guild_id: c.guild_id.clone(),
        })
        .collect();
    let p = ChannelListPayload {
        channels: items,
        guild_id: None,
    };
    io::send_encrypted(stream, PacketId::ChannelList, seq, &to_payload(&p), crypto).await?;
    Ok(())
}
