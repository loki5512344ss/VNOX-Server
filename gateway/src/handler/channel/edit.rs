use anyhow::Result;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::info;

use crate::{
    domain::{channels, session},
    net::{io, state::State},
    proto::{ChannelEditPayload, PacketId, SessionCrypto, encode_packet, to_payload},
};

pub async fn handle_channel_edit(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    payload: &[u8],
    crypto: &SessionCrypto,
    state: &State,
) -> Result<()> {
    let req = ChannelEditPayload::decode(payload)?;
    let sess = match session::get(&state.sessions, session_id).await {
        Some(s) => s,
        None => return Ok(()),
    };

    let channel_id = req.channel_id.trim().to_string();
    let channel_name = req.channel_name.trim().to_string();

    if channel_id.is_empty()
        || channel_name.is_empty()
        || channel_id.len() > 128
        || channel_name.chars().count() > 100
        || channel_name.chars().any(char::is_control)
    {
        io::send_encrypted(
            stream,
            PacketId::Error,
            seq,
            &to_payload(&crate::proto::ErrorPayload {
                code: crate::proto::ErrorCode::InvalidPacket as u32,
                message: "channel_id and channel_name are required".into(),
            }),
            crypto,
        )
        .await?;
        return Ok(());
    }

    let access = state.access.write().await;
    let channel = channels::get_channel(&state.channels, &channel_id).await;
    if !super::may_manage(
        state,
        &sess.user_id,
        channel.as_ref().and_then(|c| c.guild_id.as_deref()),
    )
    .await?
    {
        drop(access);
        super::denied(stream, seq, crypto).await?;
        return Ok(());
    }
    state
        .storage
        .update_channel(&channel_id, &channel_name)
        .await?;
    let renamed = channels::rename(&state.channels, &channel_id, &channel_name).await;

    drop(access);
    if !renamed {
        io::send_encrypted(
            stream,
            PacketId::Error,
            seq,
            &to_payload(&crate::proto::ErrorPayload {
                code: crate::proto::ErrorCode::ChannelNotFound as u32,
                message: "channel not found".into(),
            }),
            crypto,
        )
        .await?;
        return Ok(());
    }

    info!(
        "channel_edit: '{}' renamed to '{}' by {}",
        channel_id, channel_name, sess.nickname
    );

    super::notify_guild(
        state,
        channel
            .as_ref()
            .and_then(|channel| channel.guild_id.as_deref()),
        None,
        encode_packet(
            PacketId::ChannelEdit,
            0,
            &to_payload(&ChannelEditPayload {
                channel_id: channel_id.clone(),
                channel_name: channel_name.clone(),
            }),
        ),
    )
    .await?;

    Ok(())
}
