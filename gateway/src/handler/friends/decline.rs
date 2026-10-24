use anyhow::Result;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    domain::session,
    net::io,
    proto::{FriendDeclinePayload, PacketId, SimpleResponsePayload, to_payload},
};

pub async fn handle_friend_decline(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    state: &crate::net::state::State,
) -> Result<()> {
    let req = FriendDeclinePayload::decode(payload)?;
    let sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;

    state
        .storage
        .decline_friend_request(&req.from_user_id, &sess.user_id)
        .await?;

    io::send_frame(
        stream,
        PacketId::FriendDecline,
        seq,
        &to_payload(&SimpleResponsePayload {
            ok: true,
            user_id: None,
            role_id: None,
        }),
    )
    .await?;
    Ok(())
}
