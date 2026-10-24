//! LNEx v3 TCP framing. Frames are written directly into the TLS 1.3 stream, so there is
//! no per frame encryption: the 12 byte header is followed by the protobuf payload and
//! `flags` must be zero on the control plane.
use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::proto::{ErrorCode, ErrorPayload, PacketHeader, PacketId, encode_packet, to_payload};

const MAX_PAYLOAD: u32 = 4 * 1024 * 1024;

pub async fn send_packet(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    id: PacketId,
    seq: &mut u32,
    payload: &[u8],
) -> Result<()> {
    anyhow::ensure!(
        payload.len() <= MAX_PAYLOAD as usize,
        "payload too large: {}",
        payload.len()
    );
    let data = encode_packet(id, *seq, payload);
    *seq = seq.wrapping_add(1);
    stream.write_all(&data).await?;
    Ok(())
}

pub async fn send_error(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    code: ErrorCode,
    msg: &str,
) -> Result<()> {
    let p = ErrorPayload {
        code: code as u32,
        message: msg.into(),
    };
    debug_assert!(ErrorCode::from_u32(p.code).is_some());
    send_packet(stream, PacketId::Error, seq, &to_payload(&p)).await
}

/// Read one frame during the handshake (strictly `flags == 0`).
pub async fn read_packet(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
) -> Result<(PacketHeader, Vec<u8>)> {
    let mut buf = [0u8; PacketHeader::SIZE];
    stream.read_exact(&mut buf).await?;
    let hdr = PacketHeader::from_bytes(&buf);
    anyhow::ensure!(
        hdr.flags == 0,
        "unsupported packet flags: 0x{:04X}",
        hdr.flags
    );
    if hdr.payload_length > MAX_PAYLOAD {
        return Err(anyhow::anyhow!("payload too large: {}", hdr.payload_length));
    }
    let mut payload = vec![0u8; hdr.payload_length as usize];
    if !payload.is_empty() {
        stream.read_exact(&mut payload).await?;
    }
    Ok((hdr, payload))
}

/// Send one session frame. The sequence number never wraps inside a connection.
pub async fn send_frame(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    id: PacketId,
    seq: &mut u32,
    payload: &[u8],
) -> Result<()> {
    anyhow::ensure!(*seq < u32::MAX, "session sequence exhausted");
    send_packet(stream, id, seq, payload).await
}

/// Forward a pre-encoded broadcast packet (`header || payload`) re-sequenced for this session.
pub async fn deliver_frame(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    raw_data: &[u8],
) -> Result<()> {
    if raw_data.len() < PacketHeader::SIZE {
        return Err(anyhow::anyhow!("deliver: packet too short"));
    }
    let raw_hdr = PacketHeader::from_bytes(
        raw_data[..PacketHeader::SIZE]
            .try_into()
            .map_err(|_| anyhow::anyhow!("deliver: bad header"))?,
    );
    let pid = PacketId::from_u16(raw_hdr.packet_id)
        .ok_or_else(|| anyhow::anyhow!("deliver: unknown packet id 0x{:04X}", raw_hdr.packet_id))?;
    send_frame(stream, pid, seq, &raw_data[PacketHeader::SIZE..]).await
}

/// Incremental framing state survives cancellation by broadcast delivery.
pub struct FrameReader {
    bytes: Vec<u8>,
    expected_sequence: u32,
}
impl Default for FrameReader {
    fn default() -> Self {
        Self {
            bytes: Vec::new(),
            // The client AUTH used sequence 0, the first session frame is 1.
            expected_sequence: 1,
        }
    }
}
impl FrameReader {
    pub async fn read(
        &mut self,
        stream: &mut (impl AsyncRead + Unpin),
    ) -> Result<(PacketHeader, Vec<u8>)> {
        loop {
            let needed = if self.bytes.len() < PacketHeader::SIZE {
                PacketHeader::SIZE
            } else {
                let header: [u8; PacketHeader::SIZE] = self.bytes[..PacketHeader::SIZE]
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("short header"))?;
                let hdr = PacketHeader::from_bytes(&header);
                anyhow::ensure!(hdr.flags == 0, "unsupported frame flags");
                anyhow::ensure!(
                    hdr.payload_length <= MAX_PAYLOAD,
                    "payload too large: {}",
                    hdr.payload_length
                );
                anyhow::ensure!(
                    hdr.sequence == self.expected_sequence && hdr.sequence < u32::MAX,
                    "invalid packet sequence"
                );
                PacketHeader::SIZE + hdr.payload_length as usize
            };
            if self.bytes.len() == needed && self.bytes.len() >= PacketHeader::SIZE {
                let header: [u8; PacketHeader::SIZE] = self.bytes[..PacketHeader::SIZE]
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("short header"))?;
                let hdr = PacketHeader::from_bytes(&header);
                let payload = self.bytes[PacketHeader::SIZE..].to_vec();
                self.bytes.clear();
                self.expected_sequence += 1;
                return Ok((hdr, payload));
            }
            let mut chunk = [0u8; 8192];
            let limit = (needed - self.bytes.len()).min(chunk.len());
            let count = stream.read(&mut chunk[..limit]).await?;
            anyhow::ensure!(count > 0, "connection closed during frame");
            self.bytes.extend_from_slice(&chunk[..count]);
        }
    }
}

#[cfg(test)]
mod reader_tests {
    use super::*;

    fn frame(seq: u32, flags: u16, body: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(PacketId::Ping as u16).to_be_bytes());
        bytes.extend_from_slice(&flags.to_be_bytes());
        bytes.extend_from_slice(&seq.to_be_bytes());
        bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    #[tokio::test]
    async fn cancelled_partial_read_preserves_framing_and_rejects_replay() {
        let bytes = frame(1, 0, b"ping");
        let (mut server, mut peer) = tokio::io::duplex(128);
        let mut reader = FrameReader::default();
        peer.write_all(&bytes[..5]).await.unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(2),
                reader.read(&mut server)
            )
            .await
            .is_err()
        );
        peer.write_all(&bytes[5..]).await.unwrap();
        let (_, body) = reader.read(&mut server).await.unwrap();
        assert_eq!(body, b"ping");
        peer.write_all(&bytes).await.unwrap();
        assert!(reader.read(&mut server).await.is_err());
    }

    #[tokio::test]
    async fn legacy_encrypted_flag_is_rejected() {
        let bytes = frame(1, crate::proto::flags::ENCRYPTED, b"0123456789abcdef");
        let (mut server, mut peer) = tokio::io::duplex(128);
        peer.write_all(&bytes).await.unwrap();
        let error = FrameReader::default().read(&mut server).await.unwrap_err();
        assert!(error.to_string().contains("flags"));
    }

    #[tokio::test]
    async fn out_of_order_sequence_is_rejected() {
        let bytes = frame(2, 0, b"");
        let (mut server, mut peer) = tokio::io::duplex(128);
        peer.write_all(&bytes).await.unwrap();
        assert!(FrameReader::default().read(&mut server).await.is_err());
    }
}
