pub mod create;
pub mod edit;
pub mod join;
pub mod leave;

pub use create::{handle_channel_create, handle_channel_delete, handle_channel_list};
pub use edit::handle_channel_edit;
pub use join::join;
pub use leave::leave;

use crate::{
    net::state::{BroadcastMsg, State},
    proto::{PacketId, UserLeavePayload, encode_packet, to_payload},
};

pub async fn broadcast_leave(state: &State, channel_id: &str, session_id: &str) {
    if let Some(sess) = crate::domain::session::get(&state.sessions, session_id).await {
        let p = UserLeavePayload {
            channel_id: channel_id.into(),
            user_id: sess.user_id.clone(),
        };
        let _ = state.broadcast.send(BroadcastMsg {
            channel_id: Some(channel_id.into()),
            exclude_session: Some(session_id.into()),
            target_session_id: None,
            data: encode_packet(PacketId::UserLeave, 0, &to_payload(&p)),
        });
    }
}

async fn set_channel(state: &State, session_id: &str, ch: Option<String>) {
    if let Some(s) = state.sessions.write().await.get_mut(session_id) {
        s.channel_id = ch;
    }
}

async fn set_voice_channel(state: &State, session_id: &str, ch: Option<String>) {
    if let Some(s) = state.sessions.write().await.get_mut(session_id) {
        s.voice_channel_id = ch;
    }
}

/// Remove active subscriptions and UDP credentials when guild access is revoked.
pub async fn revoke_guild_access(state: &State, guild: &str, user: Option<&str>) {
    let sessions: Vec<_> = state
        .sessions
        .read()
        .await
        .values()
        .filter(|s| user.is_none_or(|u| u == s.user_id))
        .cloned()
        .collect();
    for sess in sessions {
        for (voice, ch) in [(false, sess.channel_id), (true, sess.voice_channel_id)] {
            let Some(ch) = ch else { continue };
            if !crate::domain::channels::get_channel(&state.channels, &ch)
                .await
                .is_some_and(|c| c.guild_id.as_deref() == Some(guild))
            {
                continue;
            }
            crate::domain::channels::leave(&state.channels, &ch, &sess.session_id).await;
            if voice {
                set_voice_channel(state, &sess.session_id, None).await;
                if let Some(tx) = &state.voice_member_tx {
                    let _=tx.send(serde_json::json!({"type":"leave","session_id":sess.session_id,"channel_id":ch,"user_id":sess.user_id}).to_string());
                }
                state.media.revoke(state, &sess.session_id).await;
                let event = crate::proto::VoiceState {
                    user_id: sess.user_id.clone(),
                    channel_id: ch.clone(),
                    state: "disconnected".into(),
                };
                let _ = state.broadcast.send(BroadcastMsg {
                    channel_id: None,
                    exclude_session: None,
                    target_session_id: Some(sess.session_id.clone()),
                    data: encode_packet(PacketId::VoiceState, 0, &to_payload(&event)),
                });
            } else {
                set_channel(state, &sess.session_id, None).await;
            }
            broadcast_leave(state, &ch, &sess.session_id).await;
        }
    }
}

/// Global channels have no modeled server administrator: authenticated users cannot mutate them.
pub(super) async fn may_manage(
    state: &State,
    user: &str,
    guild: Option<&str>,
) -> anyhow::Result<bool> {
    let Some(guild) = guild else { return Ok(false) };
    let Some(info) = state.storage.get_guild(guild).await? else {
        return Ok(false);
    };
    if info.owner_id == user {
        return Ok(true);
    }
    if !state
        .storage
        .list_user_guilds(user)
        .await?
        .iter()
        .any(|g| g.id == guild)
    {
        return Ok(false);
    }
    let roles = state.storage.get_user_role_perms(guild, user).await?;
    Ok(
        crate::domain::permissions::Permissions::from_role_perms(&roles)
            .has(crate::domain::permissions::Permissions::MANAGE_CHANNELS),
    )
}

pub(super) async fn denied(
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    seq: &mut u32,
    crypto: &crate::proto::SessionCrypto,
) -> anyhow::Result<()> {
    crate::net::io::send_encrypted(
        stream,
        PacketId::Error,
        seq,
        &to_payload(&crate::proto::ErrorPayload {
            code: crate::proto::ErrorCode::PermissionDenied as u32,
            message: "guild MANAGE_CHANNELS permission required".into(),
        }),
        crypto,
    )
    .await
}

/// Caller serializes access mutation against joins. Revoke before removing cached channel metadata.
pub async fn revoke_channel(state: &State, channel: &str) {
    let sessions: Vec<_> = state
        .sessions
        .read()
        .await
        .values()
        .filter(|s| {
            s.channel_id.as_deref() == Some(channel)
                || s.voice_channel_id.as_deref() == Some(channel)
        })
        .cloned()
        .collect();
    for session in sessions {
        crate::domain::channels::leave(&state.channels, channel, &session.session_id).await;
        if session.channel_id.as_deref() == Some(channel) {
            set_channel(state, &session.session_id, None).await;
        }
        if session.voice_channel_id.as_deref() == Some(channel) {
            set_voice_channel(state, &session.session_id, None).await;
            if let Some(tx) = &state.voice_member_tx {
                let _ = tx.send(
                    serde_json::json!({"type":"leave","session_id":session.session_id}).to_string(),
                );
            }
            state.media.revoke(state, &session.session_id).await;
            let event = crate::proto::VoiceState {
                user_id: session.user_id,
                channel_id: channel.into(),
                state: "disconnected".into(),
            };
            let _ = state.broadcast.send(BroadcastMsg {
                channel_id: None,
                exclude_session: None,
                target_session_id: Some(session.session_id.clone()),
                data: encode_packet(PacketId::VoiceState, 0, &to_payload(&event)),
            });
        }
        broadcast_leave(state, channel, &session.session_id).await;
    }
}

/// Removing voice permission also invalidates existing relay credentials and screen shares.
pub async fn recheck_voice_permissions(
    state: &State,
    guild: &str,
    user: Option<&str>,
) -> anyhow::Result<()> {
    let owner = state.storage.get_guild(guild).await?.map(|g| g.owner_id);
    let sessions: Vec<_> = state
        .sessions
        .read()
        .await
        .values()
        .filter(|s| user.is_none_or(|u| u == s.user_id))
        .cloned()
        .collect();
    for session in sessions {
        let Some(channel) = session.voice_channel_id else {
            continue;
        };
        if !crate::domain::channels::get_channel(&state.channels, &channel)
            .await
            .is_some_and(|c| c.guild_id.as_deref() == Some(guild))
        {
            continue;
        }
        if owner.as_deref() == Some(&session.user_id) {
            continue;
        }
        let roles = state
            .storage
            .get_user_role_perms(guild, &session.user_id)
            .await?;
        if crate::domain::permissions::Permissions::from_role_perms(&roles)
            .has(crate::domain::permissions::Permissions::VOICE_SPEAK)
        {
            continue;
        }
        crate::domain::channels::leave(&state.channels, &channel, &session.session_id).await;
        set_voice_channel(state, &session.session_id, None).await;
        if let Some(tx) = &state.voice_member_tx {
            let _ = tx.send(
                serde_json::json!({"type":"leave","session_id":session.session_id}).to_string(),
            );
        }
        state.media.revoke(state, &session.session_id).await;
        let event = crate::proto::VoiceState {
            user_id: session.user_id,
            channel_id: channel,
            state: "disconnected".into(),
        };
        let _ = state.broadcast.send(BroadcastMsg {
            channel_id: None,
            exclude_session: None,
            target_session_id: Some(session.session_id.clone()),
            data: encode_packet(PacketId::VoiceState, 0, &to_payload(&event)),
        });
    }
    Ok(())
}

/// Metadata is addressed only to currently persisted guild members, including non-subscribers.
pub(super) async fn notify_guild(
    state: &State,
    guild: Option<&str>,
    exclude: Option<&str>,
    data: Vec<u8>,
) -> anyhow::Result<()> {
    let Some(guild) = guild else { return Ok(()) };
    let _access = state.access.read().await;
    let members = state.storage.list_guild_members(guild).await?;
    let sessions: Vec<_> = state
        .sessions
        .read()
        .await
        .values()
        .filter(|session| {
            Some(session.session_id.as_str()) != exclude
                && members
                    .iter()
                    .any(|member| member.user_id == session.user_id)
        })
        .map(|session| session.session_id.clone())
        .collect();
    for target in sessions {
        let _ = state.broadcast.send(BroadcastMsg {
            channel_id: None,
            exclude_session: None,
            target_session_id: Some(target),
            data: data.clone(),
        });
    }
    Ok(())
}

/// Creation/rename payloads queued before removal must not disclose new metadata afterwards.
pub async fn may_deliver_metadata(
    state: &State,
    recipient: &str,
    packet: PacketId,
    payload: &[u8],
) -> bool {
    use prost::Message;
    let guild = match packet {
        PacketId::ChannelCreate => match crate::proto::ChannelCreatePayload::decode(payload) {
            Ok(message) => message.guild_id,
            Err(_) => return false,
        },
        PacketId::ChannelEdit => match crate::proto::ChannelEditPayload::decode(payload) {
            Ok(message) => {
                match crate::domain::channels::get_channel(&state.channels, &message.channel_id)
                    .await
                {
                    Some(channel) => channel.guild_id,
                    None => return false,
                }
            }
            Err(_) => return false,
        },
        _ => return true,
    };
    let Some(guild) = guild else { return true };
    let Some(session) = crate::domain::session::get(&state.sessions, recipient).await else {
        return false;
    };
    state
        .storage
        .list_user_guilds(&session.user_id)
        .await
        .is_ok_and(|guilds| guilds.iter().any(|g| g.id == guild))
}
