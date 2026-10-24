use anyhow::Result;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    domain::session,
    net::{io, state::State},
    proto::{DmHistoryPayload, PacketId, to_payload},
};

pub async fn handle_dm_history(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    state: &State,
) -> Result<()> {
    let req = DmHistoryPayload::decode(payload)?;

    let sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;
    let my_id = sess.user_id.clone();
    drop(sess);

    let _other_id = state
        .storage
        .get_dm_user_id(&req.dm_id, &my_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("user not in DM"))?;

    let limit = req.limit.unwrap_or(50);
    let messages = state
        .storage
        .get_dm_messages(&req.dm_id, limit, req.search_query.as_deref(), None)
        .await?;

    let resp = DmHistoryPayload {
        dm_id: req.dm_id,
        messages,
        search_query: None,
        limit: None,
    };
    io::send_frame(stream, PacketId::DmHistory, seq, &to_payload(&resp)).await?;
    Ok(())
}
