use anyhow::Result;
use tracing::debug;

use crate::{
    domain::session,
    net::state::{BroadcastMsg, State},
    proto::{PacketId, ReactionPayload, encode_packet, to_payload},
};

pub async fn handle_reaction_add(
    session_id: &str,
    mut payload: ReactionPayload,
    state: &State,
) -> Result<()> {
    let sess = match session::get(&state.sessions, session_id).await {
        Some(s) => s,
        None => return Ok(()),
    };

    if sess.channel_id.as_deref() != Some(&payload.channel_id) {
        return Ok(());
    }

    // Verify message exists in the channel
    let msg = state.storage.get_message(&payload.message_id).await?;
    if msg.is_none() || msg.as_ref().unwrap().channel_id != payload.channel_id {
        return Ok(());
    }

    payload.user_id = sess.user_id.clone();
    state
        .storage
        .add_reaction(&payload.message_id, &sess.user_id, &payload.emoji)
        .await?;

    let _ = state.broadcast.send(BroadcastMsg {
        channel_id: Some(payload.channel_id.clone()),
        exclude_session: None,
        target_session_id: None,
        data: encode_packet(PacketId::MessageReactionAdd, 0, &to_payload(&payload)),
    });

    debug!(
        "reaction {} +{} on {}",
        sess.nickname, payload.emoji, payload.message_id
    );
    Ok(())
}

pub async fn handle_reaction_remove(
    session_id: &str,
    mut payload: ReactionPayload,
    state: &State,
) -> Result<()> {
    let sess = match session::get(&state.sessions, session_id).await {
        Some(s) => s,
        None => return Ok(()),
    };

    if sess.channel_id.as_deref() != Some(&payload.channel_id) {
        return Ok(());
    }

    payload.user_id = sess.user_id.clone();

    // Check user owns the reaction
    let has = state
        .storage
        .has_user_reacted(&payload.message_id, &sess.user_id, &payload.emoji)
        .await?;
    if !has {
        return Ok(());
    }

    state
        .storage
        .remove_reaction(&payload.message_id, &sess.user_id, &payload.emoji)
        .await?;

    let _ = state.broadcast.send(BroadcastMsg {
        channel_id: Some(payload.channel_id.clone()),
        exclude_session: None,
        target_session_id: None,
        data: encode_packet(PacketId::MessageReactionRemove, 0, &to_payload(&payload)),
    });

    debug!(
        "reaction {} -{} on {}",
        sess.nickname, payload.emoji, payload.message_id
    );
    Ok(())
}
