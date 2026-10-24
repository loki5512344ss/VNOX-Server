use anyhow::Result;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::warn;

use crate::{
    domain::session,
    net::{
        io,
        state::{BroadcastMsg, State},
    },
    proto::{self, DmMessagePayload, ErrorCode, PacketId, encode_packet, to_payload},
};

pub async fn handle_dm_message(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    state: &State,
) -> Result<()> {
    let msg = DmMessagePayload::decode(payload)?;

    let sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;
    let my_id = sess.user_id.clone();
    drop(sess);

    // Rate limit check (token bucket per session).
    if !state.rate_limiter.try_consume(session_id) {
        state.metrics.inc(&state.metrics.rate_limited_events);
        warn!("rate-limited DM session {session_id}");
        io::send_frame(
            stream,
            PacketId::Error,
            seq,
            &to_payload(&proto::ErrorPayload {
                code: ErrorCode::RateLimited as u32,
                message: "you are sending messages too quickly".into(),
            }),
        )
        .await?;
        return Ok(());
    }

    let other_id = state
        .storage
        .get_dm_user_id(&msg.dm_id, &my_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("user not in DM"))?;
    if state.storage.is_blocked(&other_id, &my_id).await? {
        io::send_frame(
            stream,
            PacketId::Error,
            seq,
            &to_payload(&proto::ErrorPayload {
                code: proto::ErrorCode::Blocked as u32,
                message: "blocked".into(),
            }),
        )
        .await?;
        return Ok(());
    }

    let saved = state
        .storage
        .save_dm_message(&msg.dm_id, &my_id, &msg.content)
        .await?;
    state.metrics.inc(&state.metrics.dm_messages_sent);

    state
        .storage
        .increment_dm_unread(&msg.dm_id, &other_id)
        .await?;

    if let Some(recipient_sid) =
        session::get_session_id_by_user_id(&state.sessions, &other_id).await
    {
        let data = encode_packet(
            PacketId::DmMessage,
            0,
            &to_payload(&DmMessagePayload {
                dm_id: msg.dm_id.clone(),
                sender_id: my_id.clone(),
                content: msg.content.clone(),
                timestamp: saved.timestamp,
            }),
        );
        let _ = state.broadcast.send(BroadcastMsg {
            channel_id: None,
            exclude_session: None,
            target_session_id: Some(recipient_sid),
            data,
        });
    } else {
        warn!("dm recipient offline: {}", &other_id[..8]);
    }

    io::send_frame(stream, PacketId::DmMessage, seq, &to_payload(&saved)).await?;
    Ok(())
}
