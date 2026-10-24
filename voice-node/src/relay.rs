use crate::jitter::{BufferedPacket, JitterBuffer};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::debug;

/// Per-channel membership and independent jitter buffers for each sender.
pub struct ChannelState {
    /// member address → last packet time
    pub members: HashMap<SocketAddr, Instant>,
    /// Sender address → jitter buffer; sequence numbers are local to each sender.
    pub streams: HashMap<SocketAddr, JitterBuffer>,
}

/// Maps channel_id → per-channel state.
pub type ChannelMap = Arc<RwLock<HashMap<u64, ChannelState>>>;

pub fn new_channel_map() -> ChannelMap {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Drop members with no packets for longer than `max_idle`.
pub async fn cleanup_stale(channels: &ChannelMap, max_idle: Duration) {
    let cutoff = Instant::now() - max_idle;
    let mut lock = channels.write().await;
    lock.retain(|_, state| {
        state.members.retain(|_, last_seen| *last_seen >= cutoff);
        state
            .streams
            .retain(|sender, _| state.members.contains_key(sender));
        !state.members.is_empty()
    });
}

/// Push a raw voice packet into the jitter buffer for `channel_id`.
pub async fn push_packet(
    channels: &ChannelMap,
    channel_id: u64,
    sender: SocketAddr,
    voice_seq: u32,
    timestamp: u32,
    raw_data: &[u8],
    arrived_at: u64,
) {
    let pkt = BufferedPacket {
        voice_seq,
        timestamp,
        channel_id,
        opus_data: raw_data.to_vec(),
        arrived_at,
    };
    let mut lock = channels.write().await;
    let state = lock.entry(channel_id).or_insert_with(|| ChannelState {
        members: HashMap::new(),
        streams: HashMap::new(),
    });
    state
        .streams
        .entry(sender)
        .or_insert_with(|| JitterBuffer::new(40, true))
        .push(pkt);
}

/// Pop ready packets from every channel's jitter buffer and relay them.
pub async fn pop_and_relay(socket: &UdpSocket, channels: &ChannelMap, now_ms: u64) {
    let mut lock = channels.write().await;
    for state in lock.values_mut() {
        for (sender, jitter) in &mut state.streams {
            while let Some(pkt) = jitter.pop_ready(now_ms) {
                for &addr in state.members.keys() {
                    if addr != *sender
                        && let Err(e) = socket.send_to(&pkt.opus_data, addr).await
                    {
                        debug!("relay send error to {addr}: {e}");
                    }
                }
            }
        }
    }
}

/// Register (or refresh) a sender in the channel member set.
pub async fn touch_member(channels: &ChannelMap, channel_id: u64, addr: SocketAddr) {
    channels
        .write()
        .await
        .entry(channel_id)
        .or_insert_with(|| ChannelState {
            members: HashMap::new(),
            streams: HashMap::new(),
        })
        .members
        .insert(addr, Instant::now());
}

// ─── Gateway-to-voice-node membership bridge ──────────────────────────────────

/// user_id → socket address (the UDP endpoint reported by the gateway).
pub type UserMap = Arc<RwLock<HashMap<String, SocketAddr>>>;

pub fn new_user_map() -> UserMap {
    Arc::new(RwLock::new(HashMap::new()))
}

pub async fn add_user_mapping(map: &UserMap, user_id: String, addr: SocketAddr) {
    map.write().await.insert(user_id, addr);
}

pub async fn remove_user_mapping(map: &UserMap, user_id: &str) -> Option<SocketAddr> {
    map.write().await.remove(user_id)
}

/// Remove `addr` from every channel's member and sender sets,
/// dropping any channel that becomes empty.
pub async fn remove_member_from_all(channels: &ChannelMap, addr: &SocketAddr) {
    let mut lock = channels.write().await;
    lock.retain(|_, state| {
        state.members.remove(addr);
        state.streams.remove(addr);
        !state.members.is_empty()
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::str::FromStr;

    fn test_addr(n: u8) -> SocketAddr {
        SocketAddr::from_str(&format!("127.0.0.{n}:5000")).unwrap()
    }

    #[tokio::test]
    async fn push_and_touch_creates_channel() {
        let channels = new_channel_map();
        let addr = test_addr(1);
        touch_member(&channels, 42, addr).await;
        {
            let lock = channels.read().await;
            let state = lock.get(&42).unwrap();
            assert!(state.members.contains_key(&addr));
            assert!(state.streams.is_empty());
        }
    }

    #[tokio::test]
    async fn push_packet_adds_to_jitter() {
        let channels = new_channel_map();
        let addr = test_addr(1);
        touch_member(&channels, 7, addr).await;
        push_packet(&channels, 7, addr, 1, 1000, b"opus data", 0).await;
        {
            let lock = channels.read().await;
            let state = lock.get(&7).unwrap();
            assert_eq!(state.streams.get(&addr).unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn remove_member_cleans_up_empty_channel() {
        let channels = new_channel_map();
        let addr = test_addr(1);
        touch_member(&channels, 99, addr).await;
        remove_member_from_all(&channels, &addr).await;
        {
            let lock = channels.read().await;
            assert!(lock.is_empty());
        }
    }

    #[tokio::test]
    async fn remove_member_keeps_non_empty_channel() {
        let channels = new_channel_map();
        let addr1 = test_addr(1);
        let addr2 = test_addr(2);
        touch_member(&channels, 99, addr1).await;
        touch_member(&channels, 99, addr2).await;
        remove_member_from_all(&channels, &addr1).await;
        {
            let lock = channels.read().await;
            let state = lock.get(&99).unwrap();
            assert!(!state.members.contains_key(&addr1));
            assert!(state.members.contains_key(&addr2));
        }
    }

    #[tokio::test]
    async fn cleanup_stale_removes_idle_members() {
        let channels = new_channel_map();
        let addr = test_addr(1);
        touch_member(&channels, 5, addr).await;
        cleanup_stale(&channels, Duration::ZERO).await;
        {
            let lock = channels.read().await;
            assert!(lock.is_empty());
        }
    }

    #[tokio::test]
    async fn simultaneous_speakers_with_same_sequence_both_reach_listener() {
        let channels = new_channel_map();
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first = first_socket.local_addr().unwrap();
        let second = second_socket.local_addr().unwrap();
        touch_member(&channels, 7, first).await;
        touch_member(&channels, 7, second).await;
        touch_member(&channels, 7, listener.local_addr().unwrap()).await;
        push_packet(&channels, 7, first, 1, 1000, b"first", 0).await;
        push_packet(&channels, 7, second, 1, 1000, b"second", 0).await;
        pop_and_relay(&relay, &channels, 100).await;

        let mut received = Vec::new();
        for _ in 0..2 {
            let mut buffer = [0; 32];
            let (len, _) =
                tokio::time::timeout(Duration::from_secs(1), listener.recv_from(&mut buffer))
                    .await
                    .expect("both speakers must be relayed")
                    .unwrap();
            received.push(buffer[..len].to_vec());
        }
        received.sort();
        assert_eq!(received, vec![b"first".to_vec(), b"second".to_vec()]);
        for (speaker, expected) in [
            (&first_socket, b"second".as_slice()),
            (&second_socket, b"first".as_slice()),
        ] {
            let mut buffer = [0; 32];
            let (len, _) =
                tokio::time::timeout(Duration::from_secs(1), speaker.recv_from(&mut buffer))
                    .await
                    .expect("speaker must receive the other participant")
                    .unwrap();
            assert_eq!(&buffer[..len], expected);
        }
    }

    #[tokio::test]
    async fn departing_speaker_drops_buffered_audio() {
        let channels = new_channel_map();
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let speaker = test_addr(1);
        touch_member(&channels, 7, speaker).await;
        touch_member(&channels, 7, listener.local_addr().unwrap()).await;
        push_packet(&channels, 7, speaker, 1, 1000, b"departed", 0).await;
        remove_member_from_all(&channels, &speaker).await;
        pop_and_relay(&relay, &channels, 100).await;

        let mut buffer = [0; 32];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.recv_from(&mut buffer))
                .await
                .is_err(),
            "departed speaker must not be relayed"
        );
    }

    #[test]
    fn voice_header_parse_valid() {
        let mut buf = vec![0u8; crate::VOICE_HDR_SIZE];
        buf[0..2].copy_from_slice(&10u16.to_be_bytes());
        buf[4..8].copy_from_slice(&42u32.to_be_bytes());
        buf[12..20].copy_from_slice(&7u64.to_be_bytes());
        let hdr = crate::VoiceHeader::parse(&buf).unwrap();
        assert_eq!(hdr.packet_id, 10);
        assert_eq!(hdr.voice_seq, 42);
        assert_eq!(hdr.channel_id, 7);
    }

    #[test]
    fn voice_header_parse_too_short() {
        assert!(crate::VoiceHeader::parse(&[0; 10]).is_none());
    }
}
