use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::broadcast;
use tracing::warn;

use crate::{
    net::{io, state::BroadcastMsg, state::State},
    proto::{self, PacketId, SessionCrypto, to_payload},
};

use super::{Ctx, deliver::deliver_encrypted, dispatch};

pub async fn run_session<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    addr: std::net::SocketAddr,
    seq: &mut u32,
    session_id: &str,
    crypto: &SessionCrypto,
    state: &State,
    bcast_rx: &mut broadcast::Receiver<BroadcastMsg>,
) -> Result<()> {
    let mut ctx = Ctx {
        stream,
        seq,
        crypto,
        state,
    };
    let mut reader = io::EncryptedReader::default();
    loop {
        tokio::select! {
            result = reader.read(ctx.stream, ctx.crypto) => {
                let (hdr, payload) = result?;
                let pid = match PacketId::from_u16(hdr.packet_id) {
                    Some(p) => p,
                    None => {
                        warn!("{addr} unknown 0x{:04X}", hdr.packet_id);
                        io::send_encrypted(ctx.stream, PacketId::Error, ctx.seq, &to_payload(&proto::ErrorPayload {
                            code: proto::ErrorCode::InvalidPacket as u32,
                            message: "unknown packet".into(),
                        }), ctx.crypto).await?;
                        continue;
                    }
                };
                dispatch(&mut ctx, session_id, pid, &payload, addr).await?;
                if pid == PacketId::Disconnect { return Ok(()); }
            }
            bcast = bcast_rx.recv() => {
                match bcast {
                    Ok(msg) => deliver_encrypted(ctx.stream, ctx.seq, session_id, &msg, ctx.crypto, ctx.state).await?,
                    Err(broadcast::error::RecvError::Lagged(n))     => warn!("{addr} lagged {n}"),
                    Err(broadcast::error::RecvError::Closed)        => return Ok(()),
                }
            }
        }
    }
}
