use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::info;

use crate::{
    domain::{channels, session},
    net::state::State,
    proto::SessionCrypto,
};

use super::{broadcast_leave, set_channel, set_voice_channel};

pub async fn leave(
    _stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    _seq: &mut u32,
    session_id: &str,
    channel_id: &str,
    _crypto: &SessionCrypto,
    state: &State,
) -> Result<()> {
    let Some(sess) = session::get(&state.sessions, session_id).await else {
        return Ok(());
    };
    let is_voice = sess.voice_channel_id.as_deref() == Some(channel_id);
    if !is_voice && sess.channel_id.as_deref() != Some(channel_id) {
        return Ok(());
    }
    let user_id = Some(sess.user_id);

    channels::leave(&state.channels, channel_id, session_id).await;
    if is_voice {
        set_voice_channel(state, session_id, None).await;
    } else {
        set_channel(state, session_id, None).await;
    }
    broadcast_leave(state, channel_id, session_id).await;
    if is_voice {
        state.media.revoke(state, session_id).await;
    }

    if is_voice
        && let Some(tx) = &state.voice_member_tx
        && let Some(ref uid) = user_id
    {
        let event = serde_json::json!({
            "type": "leave",
            "session_id": session_id,
            "channel_id": channel_id,
            "user_id": uid,
        });
        let _ = tx.send(event.to_string());
    }

    info!("session {} left {channel_id}", &session_id[..8]);
    Ok(())
}
