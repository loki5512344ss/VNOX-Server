use anyhow::Result;
use prost::Message;

use crate::{
    domain::session,
    net::state::{BroadcastMsg, State},
    proto::{PacketId, ReadReceiptBroadcastPayload, ReadReceiptPayload, encode_packet, to_payload},
};

pub async fn handle_read_receipt(
    _stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    state: &State,
) -> Result<()> {
    let req = ReadReceiptPayload::decode(payload)?;
    let sess = match session::get(&state.sessions, session_id).await {
        Some(s) => s,
        None => return Ok(()),
    };

    state
        .storage
        .update_read_receipt(&req.channel_id, &sess.user_id, &req.last_read_message_id)
        .await?;

    let broadcast_data = ReadReceiptBroadcastPayload {
        channel_id: req.channel_id.clone(),
        user_id: sess.user_id.clone(),
        last_read_message_id: req.last_read_message_id,
    };

    let _ = state.broadcast.send(BroadcastMsg {
        channel_id: Some(req.channel_id),
        exclude_session: Some(session_id.into()),
        target_session_id: None,
        data: encode_packet(
            PacketId::ReadReceiptBroadcast,
            *seq,
            &to_payload(&broadcast_data),
        ),
    });

    Ok(())
}
