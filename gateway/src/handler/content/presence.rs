use anyhow::Result;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    domain::session,
    net::{
        io,
        state::{BroadcastMsg, State},
    },
    proto::{
        PacketId, PresenceEventPayload, PresenceInfo, PresenceSyncPayload, PresenceUpdatePayload,
        encode_packet, to_payload,
    },
};

fn valid_status(s: &str) -> bool {
    matches!(
        s,
        "ONLINE" | "IDLE" | "DO_NOT_DISTURB" | "OFFLINE" | "INVISIBLE"
    )
}

fn valid_activity_type(s: &str) -> bool {
    matches!(
        s,
        "PLAYING" | "LISTENING" | "WATCHING" | "STREAMING" | "CUSTOM"
    )
}

pub async fn handle_presence_update(
    _stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    state: &State,
) -> Result<()> {
    let req = PresenceUpdatePayload::decode(payload)?;
    let sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;

    let status = if valid_status(&req.status) {
        req.status.clone()
    } else {
        "ONLINE".to_string()
    };

    let activity_type = req.activity_type.filter(|a| valid_activity_type(a));

    let info = PresenceInfo {
        user_id: sess.user_id.clone(),
        nickname: sess.nickname.clone(),
        status: status.clone(),
        activity_type: activity_type.clone(),
        activity_text: req.activity_text,
    };

    state
        .presences
        .write()
        .await
        .insert(sess.user_id.clone(), info.clone());

    if let Err(e) = state
        .storage
        .save_presence(
            &sess.user_id,
            &sess.nickname,
            &status,
            activity_type.as_deref(),
            info.activity_text.as_deref(),
        )
        .await
    {
        tracing::warn!("failed to save presence: {e}");
    }

    let event = PresenceEventPayload {
        user_id: info.user_id,
        nickname: info.nickname,
        status: info.status,
        activity_type: info.activity_type,
        activity_text: info.activity_text,
    };

    let _ = state.broadcast.send(BroadcastMsg {
        channel_id: None,
        exclude_session: Some(session_id.into()),
        target_session_id: None,
        data: encode_packet(PacketId::PresenceEvent, *seq, &to_payload(&event)),
    });

    Ok(())
}

pub async fn handle_presence_sync(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    state: &State,
) -> Result<()> {
    let _sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;

    let presences: Vec<PresenceInfo> = state.presences.read().await.values().cloned().collect();

    io::send_frame(
        stream,
        PacketId::PresenceSync,
        seq,
        &to_payload(&PresenceSyncPayload { presences }),
    )
    .await?;
    Ok(())
}
