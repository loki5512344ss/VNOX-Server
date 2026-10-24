use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    domain::session,
    net::{io, state::BroadcastMsg, state::State},
    proto::SessionCrypto,
};

pub async fn deliver_encrypted(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    session_id: &str,
    msg: &BroadcastMsg,
    crypto: &SessionCrypto,
    state: &State,
) -> Result<()> {
    if msg.exclude_session.as_deref() == Some(session_id)
        || msg
            .target_session_id
            .as_deref()
            .is_some_and(|target| target != session_id)
    {
        return Ok(());
    }
    if msg.data.len() >= crate::proto::PacketHeader::SIZE {
        let hdr = crate::proto::PacketHeader::from_bytes(
            msg.data[..crate::proto::PacketHeader::SIZE]
                .try_into()
                .unwrap(),
        );
        if let Some(packet) = crate::proto::PacketId::from_u16(hdr.packet_id)
            && matches!(
                packet,
                crate::proto::PacketId::ChannelCreate | crate::proto::PacketId::ChannelEdit
            )
            && !crate::handler::channel::may_deliver_metadata(
                state,
                session_id,
                packet,
                &msg.data[crate::proto::PacketHeader::SIZE..],
            )
            .await
        {
            return Ok(());
        }
        if crate::proto::PacketId::from_u16(hdr.packet_id)
            == Some(crate::proto::PacketId::MediaEvent)
            && !crate::media::may_deliver(
                state,
                session_id,
                &msg.data[crate::proto::PacketHeader::SIZE..],
            )
            .await
        {
            return Ok(());
        }
    }
    if let Some(ref ch) = msg.channel_id {
        let access = state.access.read().await;
        let in_ch = session::get(&state.sessions, session_id)
            .await
            .is_some_and(|s| {
                s.channel_id.as_deref() == Some(ch.as_str())
                    || s.voice_channel_id.as_deref() == Some(ch.as_str())
            });
        if !in_ch {
            return Ok(());
        }
        drop(access);
    }
    io::deliver_encrypted(stream, crypto, seq, &msg.data).await
}
