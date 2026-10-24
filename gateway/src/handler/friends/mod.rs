mod decline;
mod list;
mod manage;
mod requests;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    net::io,
    proto::{ErrorPayload, PacketId, to_payload},
};

async fn send_err(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    code: crate::proto::ErrorCode,
    msg: &str,
) -> Result<()> {
    io::send_frame(
        stream,
        PacketId::Error,
        seq,
        &to_payload(&ErrorPayload {
            code: code as u32,
            message: msg.into(),
        }),
    )
    .await
}

pub use decline::handle_friend_decline;
pub use list::handle_friend_list;
pub use manage::{handle_block_list, handle_block_user, handle_friend_remove, handle_unblock_user};
pub use requests::{handle_friend_accept, handle_friend_request};

async fn notify_user(
    state: &crate::net::state::State,
    user: &str,
    event: &crate::proto::FriendEventPayload,
) {
    let ids: Vec<_> = state
        .sessions
        .read()
        .await
        .values()
        .filter(|s| s.user_id == user)
        .map(|s| s.session_id.clone())
        .collect();
    for id in ids {
        let _ = state.broadcast.send(crate::net::state::BroadcastMsg {
            channel_id: None,
            exclude_session: None,
            target_session_id: Some(id),
            data: crate::proto::encode_packet(PacketId::FriendEvent, 0, &to_payload(event)),
        });
    }
}
