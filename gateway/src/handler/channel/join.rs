use std::net::SocketAddr;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::info;

use crate::{
    domain::{channels, session},
    net::{
        io,
        state::{BroadcastMsg, State},
    },
    proto::{
        self, ChannelStatePayload, ChatHistoryPayload, MemberInfo, PacketId, SessionCrypto,
        UserJoinPayload, encode_packet, to_payload,
    },
};

use super::{broadcast_leave, set_channel};

const HISTORY_LIMIT: i64 = 50;

pub async fn join(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    channel_id: &str,
    crypto: &SessionCrypto,
    state: &State,
    addr: SocketAddr,
) -> Result<()> {
    let Some(sess) = session::get(&state.sessions, session_id).await else {
        return Ok(());
    };
    let prev_channel = sess.channel_id;

    let ch = match channels::get_channel(&state.channels, channel_id).await {
        Some(c) => c,
        None => {
            io::send_encrypted(
                stream,
                PacketId::Error,
                seq,
                &to_payload(&proto::ErrorPayload {
                    code: proto::ErrorCode::ChannelNotFound as u32,
                    message: "not found".into(),
                }),
                crypto,
            )
            .await?;
            return Ok(());
        }
    };

    // Validate the destination before changing membership or exposing its history.
    // Role assignments alone are insufficient: a kicked user can retain stale roles.
    if let Some(guild_id) = ch.guild_id.as_deref() {
        let is_member = state
            .storage
            .list_user_guilds(&sess.user_id)
            .await?
            .iter()
            .any(|guild| guild.id == guild_id);
        if !is_member {
            io::send_encrypted(
                stream,
                PacketId::Error,
                seq,
                &to_payload(&proto::ErrorPayload {
                    code: proto::ErrorCode::PermissionDenied as u32,
                    message: "guild membership required".into(),
                }),
                crypto,
            )
            .await?;
            return Ok(());
        }
    }

    if prev_channel.as_deref() == Some(channel_id) {
        return Ok(());
    }

    if let Some(prev) = prev_channel {
        channels::leave(&state.channels, &prev, session_id).await;
        broadcast_leave(state, &prev, session_id).await;
    }

    channels::join(&state.channels, channel_id, session_id).await;
    set_channel(state, session_id, Some(channel_id.into())).await;

    let mut members = Vec::new();
    for sid in channels::members(&state.channels, channel_id).await {
        if let Some(s) = session::get(&state.sessions, &sid).await {
            members.push(MemberInfo {
                user_id: s.user_id.clone(),
                nickname: s.nickname.clone(),
                in_voice: ch.kind == channels::ChannelKind::Voice,
            });
        }
    }

    let sp = ChannelStatePayload {
        channel_id: ch.id.clone(),
        channel_name: ch.name.clone(),
        kind: ch.kind.as_str().into(),
        members,
        voice_endpoint: state.config.voice.bind.clone(),
        guild_id: ch.guild_id.clone(),
    };
    io::send_encrypted(
        stream,
        PacketId::ChannelState,
        seq,
        &to_payload(&sp),
        crypto,
    )
    .await?;

    let history = state.storage.get_history(channel_id, HISTORY_LIMIT).await?;
    if !history.is_empty() {
        let hp = ChatHistoryPayload {
            channel_id: channel_id.into(),
            messages: history,
        };
        io::send_encrypted(stream, PacketId::ChatHistory, seq, &to_payload(&hp), crypto).await?;
    }

    if let Some(sess) = session::get(&state.sessions, session_id).await {
        let jp = UserJoinPayload {
            channel_id: channel_id.into(),
            user_id: sess.user_id.clone(),
            nickname: sess.nickname.clone(),
        };
        let _ = state.broadcast.send(BroadcastMsg {
            channel_id: Some(channel_id.into()),
            exclude_session: Some(session_id.into()),
            target_session_id: None,
            data: encode_packet(PacketId::UserJoin, 0, &to_payload(&jp)),
        });
    }

    if ch.kind == channels::ChannelKind::Voice
        && let Some(tx) = &state.voice_member_tx
        && let Some(sess) = session::get(&state.sessions, session_id).await
    {
        let event = serde_json::json!({
            "type": "join",
            "channel_id": channel_id,
            "user_id": sess.user_id,
            "endpoint": format!("{}:{}", addr.ip(), addr.port()),
        });
        let _ = tx.send(event.to_string());
    }

    info!("session {} joined {channel_id}", &session_id[..8]);
    Ok(())
}

#[cfg(test)]
mod tests;
