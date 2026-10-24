use anyhow::Result;
use tracing::{debug, warn};

use crate::{
    net::state::{BroadcastMsg, State},
    proto::{ChatMessagePayload, ErrorCode, PacketId, encode_packet, to_payload},
};

pub async fn handle(session_id: &str, mut msg: ChatMessagePayload, state: &State) -> Result<()> {
    let sess = match crate::domain::session::get(&state.sessions, session_id).await {
        Some(s) => s,
        None => return Ok(()),
    };

    if sess.channel_id.as_deref() != Some(&msg.channel_id) {
        return Ok(());
    }

    // Rate limit check (token bucket per session).
    if !state.rate_limiter.try_consume(session_id) {
        state.metrics.inc(&state.metrics.rate_limited_events);
        warn!("rate-limited session {session_id}");
        let _ = state.broadcast.send(BroadcastMsg {
            channel_id: None,
            exclude_session: None,
            target_session_id: Some(session_id.to_string()),
            data: encode_packet(
                PacketId::Error,
                0,
                &to_payload(&crate::proto::ErrorPayload {
                    code: ErrorCode::RateLimited as u32,
                    message: "you are sending messages too quickly".into(),
                }),
            ),
        });
        return Ok(());
    }

    msg.sender_id = sess.user_id.clone();
    if msg.timestamp == 0 {
        msg.timestamp = now_ms();
    }

    if !state.storage.save_webhook_message(&msg, None).await? {
        return Ok(());
    }
    state.metrics.inc(&state.metrics.messages_sent);

    let _ = state.broadcast.send(BroadcastMsg {
        channel_id: Some(msg.channel_id.clone()),
        exclude_session: None,
        target_session_id: None,
        data: encode_packet(PacketId::ChatMessage, 0, &to_payload(&msg)),
    });

    debug!(channel=%msg.channel_id,message_id=%msg.message_id,"chat message accepted");
    Ok(())
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
