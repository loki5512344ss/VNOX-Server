use anyhow::Result;
use prost::Message;
use tracing::debug;

use crate::{
    domain::session,
    net::state::{BroadcastMsg, State},
    proto::{ChatMessagePayload, MessageDeletePayload, PacketId, encode_packet, to_payload},
};

pub async fn handle_message_edit(session_id: &str, payload: &[u8], state: &State) -> Result<()> {
    let edit = crate::proto::MessageEditPayload::decode(payload)?;
    let sess = match session::get(&state.sessions, session_id).await {
        Some(s) => s,
        None => return Ok(()),
    };

    if sess.channel_id.as_deref() != Some(&edit.channel_id) {
        return Ok(());
    }

    // Verify sender owns the message
    let sender = state.storage.get_message_sender(&edit.message_id).await?;
    if sender.as_deref() != Some(&sess.user_id) {
        return Ok(());
    }

    let msg = state.storage.get_message(&edit.message_id).await?;
    let msg = match msg {
        Some(m) => m,
        None => return Ok(()),
    };

    state
        .storage
        .edit_message(&edit.message_id, &edit.content)
        .await?;

    let broadcast_msg = ChatMessagePayload {
        message_id: edit.message_id.clone(),
        channel_id: edit.channel_id.clone(),
        sender_id: sess.user_id.clone(),
        content: edit.content,
        timestamp: msg.timestamp,
        edited: true,
        reply_to: msg.reply_to.clone(),
    };

    let _ = state.broadcast.send(BroadcastMsg {
        channel_id: Some(edit.channel_id.clone()),
        exclude_session: None,
        target_session_id: None,
        data: encode_packet(PacketId::MessageEdit, 0, &to_payload(&broadcast_msg)),
    });

    debug!(
        "edit {} {}:{}",
        sess.nickname, edit.channel_id, edit.message_id
    );
    Ok(())
}

pub async fn handle_message_delete(session_id: &str, payload: &[u8], state: &State) -> Result<()> {
    let delete = MessageDeletePayload::decode(payload)?;
    let sess = match session::get(&state.sessions, session_id).await {
        Some(s) => s,
        None => return Ok(()),
    };

    if sess.channel_id.as_deref() != Some(&delete.channel_id) {
        return Ok(());
    }

    // Verify sender owns the message
    let sender = state.storage.get_message_sender(&delete.message_id).await?;
    if sender.as_deref() != Some(&sess.user_id) {
        return Ok(());
    }

    state.storage.delete_message(&delete.message_id).await?;

    let _ = state.broadcast.send(BroadcastMsg {
        channel_id: Some(delete.channel_id.clone()),
        exclude_session: None,
        target_session_id: None,
        data: encode_packet(PacketId::MessageDelete, 0, &to_payload(&delete)),
    });

    debug!(
        "delete {} {}:{}",
        sess.nickname, delete.channel_id, delete.message_id
    );
    Ok(())
}
