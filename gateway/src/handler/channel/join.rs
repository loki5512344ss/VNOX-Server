use super::{broadcast_leave, set_channel, set_voice_channel};
use crate::{
    domain::{channels, session},
    net::{
        io,
        state::{BroadcastMsg, State},
    },
    proto::{
        self, ChannelStatePayload, ChatHistoryPayload, MemberInfo, PacketId, UserJoinPayload,
        encode_packet, to_payload,
    },
};
use anyhow::Result;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
const HISTORY_LIMIT: i64 = 50;
#[allow(clippy::too_many_arguments)]
pub async fn join(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    channel_id: &str,
    state: &State,
    _addr: SocketAddr,
) -> Result<()> {
    let guard = state.access.read().await;
    let Some(sess) = session::get(&state.sessions, session_id).await else {
        return Ok(());
    };
    let Some(ch) = channels::get_channel(&state.channels, channel_id).await else {
        drop(guard);
        return io::send_frame(
            stream,
            PacketId::Error,
            seq,
            &to_payload(&proto::ErrorPayload {
                code: proto::ErrorCode::ChannelNotFound as u32,
                message: "not found".into(),
            }),
        )
        .await;
    };
    if let Some(guild) = &ch.guild_id
        && !state
            .storage
            .list_user_guilds(&sess.user_id)
            .await?
            .iter()
            .any(|g| g.id == *guild)
    {
        drop(guard);
        return io::send_frame(
            stream,
            PacketId::Error,
            seq,
            &to_payload(&proto::ErrorPayload {
                code: proto::ErrorCode::PermissionDenied as u32,
                message: "guild membership required".into(),
            }),
        )
        .await;
    }
    let is_voice = ch.kind == channels::ChannelKind::Voice;
    if is_voice && state.voice_member_tx.is_none() {
        drop(guard);
        return io::send_frame(
            stream,
            PacketId::Error,
            seq,
            &to_payload(&proto::ErrorPayload {
                code: proto::ErrorCode::NodeUnavailable as u32,
                message: "voice requires the combined server process".into(),
            }),
        )
        .await;
    }
    if is_voice && let Some(guild) = &ch.guild_id {
        let owner = state
            .storage
            .get_guild(guild)
            .await?
            .is_some_and(|g| g.owner_id == sess.user_id);
        let perms = state
            .storage
            .get_user_role_perms(guild, &sess.user_id)
            .await?;
        if !owner
            && !crate::domain::permissions::Permissions::from_role_perms(&perms)
                .has(crate::domain::permissions::Permissions::VOICE_SPEAK)
        {
            drop(guard);
            return io::send_frame(
                stream,
                PacketId::Error,
                seq,
                &to_payload(&proto::ErrorPayload {
                    code: proto::ErrorCode::PermissionDenied as u32,
                    message: "VOICE_SPEAK permission required".into(),
                }),
            )
            .await;
        }
    }
    let previous = if is_voice {
        sess.voice_channel_id.clone()
    } else {
        sess.channel_id.clone()
    };
    if previous.as_deref() == Some(channel_id) {
        return Ok(());
    }
    if let Some(previous) = previous {
        channels::leave(&state.channels, &previous, session_id).await;
        broadcast_leave(state, &previous, session_id).await;
        if is_voice {
            state.media.revoke(state, session_id).await;
            if let Some(tx) = &state.voice_member_tx {
                let _=tx.send(serde_json::json!({"type":"leave","session_id":session_id,"channel_id":previous,"user_id":sess.user_id}).to_string());
            }
        }
    }
    channels::join(&state.channels, channel_id, session_id).await;
    if is_voice {
        set_voice_channel(state, session_id, Some(channel_id.into())).await;
    } else {
        set_channel(state, session_id, Some(channel_id.into())).await;
    }
    // Issue/revoke credentials while access mutations are serialized. Never hold this guard while writing to a client socket.
    let credentials = if is_voice {
        if let Some(tx) = &state.voice_member_tx {
            use rand::Rng;
            let (route_id, c2s_key, s2c_key) = {
                let mut rng = rand::rng();
                let mut r = [0u8; 16];
                let mut c = [0u8; 32];
                let mut s = [0u8; 32];
                rng.fill_bytes(&mut r);
                rng.fill_bytes(&mut c);
                rng.fill_bytes(&mut s);
                (r, c, s)
            };
            let event = serde_json::json!({"type":"join","session_id":session_id,"channel_id":channel_id,"user_id":sess.user_id,"route_id":hex::encode(route_id),"c2s_key":hex::encode(c2s_key),"s2c_key":hex::encode(s2c_key)});
            if tx.send(event.to_string()).is_err() {
                channels::leave(&state.channels, channel_id, session_id).await;
                set_voice_channel(state, session_id, None).await;
                drop(guard);
                return io::send_frame(
                    stream,
                    PacketId::Error,
                    seq,
                    &to_payload(&proto::ErrorPayload {
                        code: proto::ErrorCode::NodeUnavailable as u32,
                        message: "voice service unavailable".into(),
                    }),
                )
                .await;
            }
            Some(proto::VoiceSession {
                route_id: route_id.to_vec(),
                c2s_key: c2s_key.to_vec(),
                s2c_key: s2c_key.to_vec(),
                channel_id: channel_id.into(),
            })
        } else {
            None
        }
    } else {
        None
    };
    let mut members = Vec::new();
    for sid in channels::members(&state.channels, channel_id).await {
        if let Some(s) = session::get(&state.sessions, &sid).await {
            members.push(MemberInfo {
                user_id: s.user_id,
                nickname: s.nickname,
                in_voice: is_voice,
            });
        }
    }
    let message = UserJoinPayload {
        channel_id: channel_id.into(),
        user_id: sess.user_id,
        nickname: sess.nickname,
    };
    let _ = state.broadcast.send(BroadcastMsg {
        channel_id: Some(channel_id.into()),
        exclude_session: Some(session_id.into()),
        target_session_id: None,
        data: encode_packet(PacketId::UserJoin, 0, &to_payload(&message)),
    });
    drop(guard);
    let payload = ChannelStatePayload {
        channel_id: ch.id,
        channel_name: ch.name,
        kind: ch.kind.as_str().into(),
        members,
        voice_endpoint: state.config.voice.bind.clone(),
        guild_id: ch.guild_id,
    };
    io::send_frame(stream, PacketId::ChannelState, seq, &to_payload(&payload)).await?;
    if let Some(credentials) = credentials {
        io::send_frame(
            stream,
            PacketId::VoiceSession,
            seq,
            &to_payload(&credentials),
        )
        .await?;
    }
    if !is_voice {
        let history = state.storage.get_history(channel_id, HISTORY_LIMIT).await?;
        if !history.is_empty() {
            let _ = state.broadcast.send(BroadcastMsg {
                channel_id: Some(channel_id.into()),
                exclude_session: None,
                target_session_id: Some(session_id.into()),
                data: encode_packet(
                    PacketId::ChatHistory,
                    0,
                    &to_payload(&ChatHistoryPayload {
                        channel_id: channel_id.into(),
                        messages: history,
                    }),
                ),
            });
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests;
