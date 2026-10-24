use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::broadcast;
use tracing::warn;

use crate::{
    net::{io, state::BroadcastMsg, state::State},
    proto::{self, PacketId, to_payload},
};

use super::{Ctx, deliver::deliver_frame, dispatch};

pub async fn run_session<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    addr: std::net::SocketAddr,
    seq: &mut u32,
    session_id: &str,
    state: &State,
    bcast_rx: &mut broadcast::Receiver<BroadcastMsg>,
) -> Result<()> {
    let mut ctx = Ctx { stream, seq, state };
    let mut reader = io::FrameReader::default();
    loop {
        tokio::select! {
            result = reader.read(ctx.stream) => {
                let (hdr, payload) = result?;
                let pid = match PacketId::from_u16(hdr.packet_id) {
                    Some(p) => p,
                    None => {
                        warn!("{addr} unknown 0x{:04X}", hdr.packet_id);
                        io::send_frame(ctx.stream, PacketId::Error, ctx.seq, &to_payload(&proto::ErrorPayload {
                            code: proto::ErrorCode::InvalidPacket as u32,
                            message: "unknown packet".into(),
                        })).await?;
                        continue;
                    }
                };
                dispatch(&mut ctx, session_id, pid, &payload, addr).await?;
                if pid == PacketId::Disconnect { return Ok(()); }
            }
            bcast = bcast_rx.recv() => {
                match bcast {
                    Ok(msg) => deliver_frame(ctx.stream, ctx.seq, session_id, &msg, ctx.state).await?,
                    Err(broadcast::error::RecvError::Lagged(n))     => warn!("{addr} lagged {n}"),
                    Err(broadcast::error::RecvError::Closed)        => return Ok(()),
                }
            }
        }
    }
}
