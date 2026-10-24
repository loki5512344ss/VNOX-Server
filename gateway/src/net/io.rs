use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::proto::{
    ErrorCode, ErrorPayload, PacketHeader, PacketId, SessionCrypto, encode_packet, flags,
    to_payload,
};

const MAX_PAYLOAD: u32 = 4 * 1024 * 1024;

pub async fn send_packet(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    id: PacketId,
    seq: &mut u32,
    payload: &[u8],
) -> Result<()> {
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

pub async fn read_packet(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
) -> Result<(PacketHeader, Vec<u8>)> {
    let mut buf = [0u8; PacketHeader::SIZE];
    stream.read_exact(&mut buf).await?;
    let hdr = PacketHeader::from_bytes(&buf);
    if hdr.flags & !flags::KNOWN_MASK != 0 {
        return Err(anyhow::anyhow!("unknown packet flags: 0x{:04X}", hdr.flags));
    }
    if hdr.payload_length > MAX_PAYLOAD {
        return Err(anyhow::anyhow!("payload too large: {}", hdr.payload_length));
    }
    let mut payload = vec![0u8; hdr.payload_length as usize];
    if !payload.is_empty() {
        stream.read_exact(&mut payload).await?;
    }
    Ok((hdr, payload))
}

pub async fn send_encrypted(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    id: PacketId,
    seq: &mut u32,
    payload: &[u8],
    crypto: &SessionCrypto,
) -> Result<()> {
    anyhow::ensure!(*seq < u32::MAX, "session sequence exhausted");
    anyhow::ensure!(
        payload.len() <= MAX_PAYLOAD as usize - 16,
        "payload too large"
    );
    let flags_val = flags::ENCRYPTED;
    let mut hdr_buf = [0u8; PacketHeader::SIZE];
    hdr_buf[0..2].copy_from_slice(&(id as u16).to_be_bytes());
    hdr_buf[2..4].copy_from_slice(&flags_val.to_be_bytes());
    hdr_buf[4..8].copy_from_slice(&seq.to_be_bytes());
    hdr_buf[8..12].copy_from_slice(&((payload.len() + 16) as u32).to_be_bytes());
    let encrypted = crypto.encrypt_s2c_frame(*seq as u64, payload, &hdr_buf);
    *seq += 1;

    let mut out = Vec::with_capacity(PacketHeader::SIZE + encrypted.len());
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&encrypted);
    stream.write_all(&out).await?;
    Ok(())
}

pub async fn read_encrypted(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    crypto: &SessionCrypto,
) -> Result<(PacketHeader, Vec<u8>)> {
    let mut buf = [0u8; PacketHeader::SIZE];
    stream.read_exact(&mut buf).await?;
    let hdr = PacketHeader::from_bytes(&buf);
    if hdr.flags & !flags::KNOWN_MASK != 0 {
        return Err(anyhow::anyhow!("unknown packet flags: 0x{:04X}", hdr.flags));
    }
    if hdr.flags & flags::ENCRYPTED == 0 {
        return Err(anyhow::anyhow!("packet not encrypted"));
    }
    if hdr.payload_length > MAX_PAYLOAD {
        return Err(anyhow::anyhow!("payload too large: {}", hdr.payload_length));
    }
    let mut encrypted = vec![0u8; hdr.payload_length as usize];
    if !encrypted.is_empty() {
        stream.read_exact(&mut encrypted).await?;
    }
    let payload = crypto.decrypt_c2s_frame(hdr.sequence as u64, &encrypted, &buf)?;
    Ok((hdr, payload))
}

pub async fn deliver_encrypted(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    crypto: &SessionCrypto,
    seq: &mut u32,
    raw_data: &[u8],
) -> Result<()> {
    if raw_data.len() < PacketHeader::SIZE {
        return Err(anyhow::anyhow!("deliver: packet too short"));
    }
    let raw_hdr = PacketHeader::from_bytes(raw_data[..PacketHeader::SIZE].try_into().unwrap());
    let pid = match PacketId::from_u16(raw_hdr.packet_id) {
        Some(p) => p,
        None => {
            return Err(anyhow::anyhow!(
                "deliver: unknown packet id 0x{:04X}",
                raw_hdr.packet_id
            ));
        }
    };
    let payload = &raw_data[PacketHeader::SIZE..];
    send_encrypted(stream, pid, seq, payload, crypto).await
}

/// Incremental framing state survives cancellation by broadcast delivery.
pub struct EncryptedReader {
    bytes: Vec<u8>,
    expected_sequence: u32,
}
impl Default for EncryptedReader {
    fn default() -> Self {
        Self {
            bytes: Vec::new(),
            expected_sequence: 1,
        }
    }
}
impl EncryptedReader {
    pub async fn read(
        &mut self,
        stream: &mut (impl AsyncRead + Unpin),
        crypto: &SessionCrypto,
    ) -> Result<(PacketHeader, Vec<u8>)> {
        loop {
            let needed = if self.bytes.len() < PacketHeader::SIZE {
                PacketHeader::SIZE
            } else {
                let header: &[u8; PacketHeader::SIZE] =
                    self.bytes[..PacketHeader::SIZE].try_into().unwrap();
                let hdr = PacketHeader::from_bytes(header);
                anyhow::ensure!(
                    hdr.flags == flags::ENCRYPTED,
                    "unsupported encrypted frame flags"
                );
                anyhow::ensure!(
                    hdr.payload_length >= 16 && hdr.payload_length <= MAX_PAYLOAD,
                    "invalid encrypted payload size"
                );
                anyhow::ensure!(
                    hdr.sequence == self.expected_sequence && hdr.sequence < u32::MAX,
                    "invalid packet sequence"
                );
                PacketHeader::SIZE + hdr.payload_length as usize
            };
            if self.bytes.len() == needed && needed > PacketHeader::SIZE {
                let header: &[u8; PacketHeader::SIZE] =
                    self.bytes[..PacketHeader::SIZE].try_into().unwrap();
                let hdr = PacketHeader::from_bytes(header);
                let payload = crypto.decrypt_c2s_frame(
                    hdr.sequence as u64,
                    &self.bytes[PacketHeader::SIZE..],
                    header,
                )?;
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
    fn frame(crypto: &SessionCrypto, seq: u32) -> Vec<u8> {
        let mut header = [0u8; 12];
        header[..2].copy_from_slice(&(PacketId::Ping as u16).to_be_bytes());
        header[2..4].copy_from_slice(&flags::ENCRYPTED.to_be_bytes());
        header[4..8].copy_from_slice(&seq.to_be_bytes());
        header[8..].copy_from_slice(&20u32.to_be_bytes());
        let mut bytes = header.to_vec();
        bytes.extend_from_slice(&crypto.encrypt_c2s_frame(seq as u64, b"ping", &header));
        bytes
    }
    #[tokio::test]
    async fn cancelled_partial_read_preserves_framing_and_rejects_replay() {
        let crypto = SessionCrypto::derive(&[7; 32], "fixture");
        let bytes = frame(&crypto, 1);
        let (mut server, mut peer) = tokio::io::duplex(128);
        let mut reader = EncryptedReader::default();
        peer.write_all(&bytes[..5]).await.unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(2),
                reader.read(&mut server, &crypto)
            )
            .await
            .is_err()
        );
        peer.write_all(&bytes[5..]).await.unwrap();
        let (_, body) = reader.read(&mut server, &crypto).await.unwrap();
        assert_eq!(body, b"ping");
        peer.write_all(&bytes).await.unwrap();
        assert!(reader.read(&mut server, &crypto).await.is_err());
    }
    #[tokio::test]
    async fn modifying_authenticated_packet_type_is_rejected() {
        let crypto = SessionCrypto::derive(&[7; 32], "fixture");
        let mut bytes = frame(&crypto, 1);
        bytes[1] ^= 1;
        let (mut server, mut peer) = tokio::io::duplex(128);
        peer.write_all(&bytes).await.unwrap();
        assert!(
            EncryptedReader::default()
                .read(&mut server, &crypto)
                .await
                .is_err()
        );
    }
}
