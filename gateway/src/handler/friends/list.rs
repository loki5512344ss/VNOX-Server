use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    domain::session,
    net::{io, state::State},
    proto::{FriendInfo, FriendListPayload, PacketId, to_payload},
};

pub async fn handle_friend_list(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    state: &State,
) -> Result<()> {
    let sess = session::get(&state.sessions, session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;

    let friend_ids = state.storage.list_friends(&sess.user_id).await?;
    let mut friends = Vec::new();
    let presences = state.presences.read().await;

    for fid in &friend_ids {
        let nick = state.storage.get_nickname(fid).await?.unwrap_or_default();
        let presence = presences.get(fid);
        friends.push(FriendInfo {
            user_id: fid.clone(),
            nickname: nick,
            status: presence
                .map(|p| p.status.clone())
                .unwrap_or_else(|| "OFFLINE".into()),
            since: 0,
        });
    }

    io::send_frame(
        stream,
        PacketId::FriendList,
        seq,
        &to_payload(&FriendListPayload { friends }),
    )
    .await?;
    Ok(())
}
