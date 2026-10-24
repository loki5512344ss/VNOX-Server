//! Authenticated per-session UDP transport. No address or room is learned from plaintext.
use crate::wire::VoiceFrame;
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use prost::Message;
use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};
const HEADER: usize = 28;
const MAX_SESSIONS: usize = 4096;
#[derive(Default)]
struct Replay {
    highest: Option<u64>,
    seen: u128,
}
impl Replay {
    fn accept(&mut self, seq: u64) -> bool {
        match self.highest {
            None => {
                self.highest = Some(seq);
                self.seen = 1;
                true
            }
            Some(high) if seq > high => {
                let gap = seq - high;
                self.seen = if gap >= 128 {
                    1
                } else {
                    (self.seen << gap) | 1
                };
                self.highest = Some(seq);
                true
            }
            Some(high) => {
                let gap = high - seq;
                if gap >= 128 || self.seen & (1u128 << gap) != 0 {
                    return false;
                }
                self.seen |= 1u128 << gap;
                true
            }
        }
    }
}
struct Member {
    session: String,
    user: String,
    channel: String,
    c2s: [u8; 32],
    s2c: [u8; 32],
    addr: Option<SocketAddr>,
    replay: Replay,
    out_seq: u64,
    window: Instant,
    count: u32,
    last: Instant,
}
impl Drop for Member {
    fn drop(&mut self) {
        self.c2s.fill(0);
        self.s2c.fill(0);
    }
}
#[derive(Default)]
pub struct Relay {
    members: HashMap<[u8; 16], Member>,
}
fn bytes<const N: usize>(event: &serde_json::Value, key: &str) -> Option<[u8; N]> {
    hex::decode(event[key].as_str()?).ok()?.try_into().ok()
}
fn nonce(seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&seq.to_be_bytes());
    n
}
fn encrypt(route: &[u8; 16], key: &[u8; 32], seq: u64, body: &[u8]) -> Option<Vec<u8>> {
    let mut header = [0u8; HEADER];
    header[..2].copy_from_slice(&0x0010u16.to_be_bytes());
    header[2..4].copy_from_slice(&1u16.to_be_bytes());
    header[4..20].copy_from_slice(route);
    header[20..].copy_from_slice(&seq.to_be_bytes());
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
    let n = Nonce::from(nonce(seq));
    let body = cipher
        .encrypt(
            &n,
            Payload {
                msg: body,
                aad: &header,
            },
        )
        .ok()?;
    let mut packet = header.to_vec();
    packet.extend_from_slice(&body);
    Some(packet)
}
impl Relay {
    pub fn clear(&mut self) {
        self.members.clear();
    }
    pub fn event(&mut self, event: &serde_json::Value) {
        let Some(session) = event["session_id"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 128)
        else {
            return;
        };
        match event["type"].as_str() {
            Some("leave") => {
                self.members.retain(|_, m| m.session != session);
            }
            Some("join") => {
                let (Some(route), Some(c2s), Some(s2c), Some(channel), Some(user)) = (
                    bytes(event, "route_id"),
                    bytes(event, "c2s_key"),
                    bytes(event, "s2c_key"),
                    event["channel_id"].as_str(),
                    event["user_id"].as_str(),
                ) else {
                    return;
                };
                if channel.is_empty() || channel.len() > 128 || user.len() > 128 {
                    return;
                }
                self.members.retain(|_, m| m.session != session);
                if self.members.len() >= MAX_SESSIONS {
                    return;
                }
                self.members.insert(
                    route,
                    Member {
                        session: session.into(),
                        user: user.into(),
                        channel: channel.into(),
                        c2s,
                        s2c,
                        addr: None,
                        replay: Replay::default(),
                        out_seq: 0,
                        window: Instant::now(),
                        count: 0,
                        last: Instant::now(),
                    },
                );
            }
            _ => {}
        }
    }
    /// Verify before updating replay state, endpoint or source attribution.
    pub fn receive(&mut self, packet: &[u8], src: SocketAddr) -> Vec<(SocketAddr, Vec<u8>)> {
        if packet.len() < HEADER + 16
            || packet.len() > crate::MAX_UDP_PACKET
            || packet[..4] != [0, 0x10, 0, 1]
        {
            return vec![];
        }
        let route: [u8; 16] = packet[4..20].try_into().unwrap();
        let seq = u64::from_be_bytes(packet[20..28].try_into().unwrap());
        let Some(member) = self.members.get_mut(&route) else {
            return vec![];
        };
        if member.window.elapsed() >= Duration::from_secs(1) {
            member.window = Instant::now();
            member.count = 0;
        }
        if member.count >= 120 {
            return vec![];
        }

        let cipher = ChaCha20Poly1305::new_from_slice(&member.c2s).expect("key length");
        let n = Nonce::from(nonce(seq));
        let Ok(body) = cipher.decrypt(
            &n,
            Payload {
                msg: &packet[HEADER..],
                aad: &packet[..HEADER],
            },
        ) else {
            return vec![];
        };
        let Ok(mut frame) = VoiceFrame::decode(body.as_slice()) else {
            return vec![];
        };
        if frame.channel_id != member.channel
            || !frame.sender_session_id.is_empty()
            || !frame.sender_user_id.is_empty()
            || frame.opus.len() > 1275
            || seq == u64::MAX
            || !member.replay.accept(seq)
        {
            return vec![];
        }
        member.count += 1;
        member.addr = Some(src);
        member.last = Instant::now();
        if frame.opus.is_empty() {
            return vec![];
        }
        frame.sender_session_id = member.session.clone();
        frame.sender_user_id = member.user.clone();
        let channel = member.channel.clone();
        let body = frame.encode_to_vec();
        let mut output = Vec::new();
        for (target_route, target) in &mut self.members {
            if *target_route == route
                || target.channel != channel
                || target.last.elapsed() > Duration::from_secs(30)
                || target.out_seq == u64::MAX
            {
                continue;
            }
            if let Some(addr) = target.addr
                && let Some(packet) = encrypt(target_route, &target.s2c, target.out_seq, &body)
            {
                target.out_seq += 1;
                if packet.len() <= crate::MAX_UDP_PACKET {
                    output.push((addr, packet));
                }
            }
        }
        output
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn event(session: &str, user: &str, route: u8, key: u8, channel: &str) -> serde_json::Value {
        serde_json::json!({"type":"join","session_id":session,"user_id":user,"route_id":hex::encode([route;16]),"c2s_key":hex::encode([key;32]),"s2c_key":hex::encode([key+1;32]),"channel_id":channel})
    }
    fn packet(route: u8, key: u8, seq: u64, opus: &[u8]) -> Vec<u8> {
        encrypt(
            &[route; 16],
            &[key; 32],
            seq,
            &VoiceFrame {
                voice_seq: seq as u32,
                timestamp: 0,
                channel_id: "voice-uuid".into(),
                sender_session_id: String::new(),
                sender_user_id: String::new(),
                opus: opus.into(),
            }
            .encode_to_vec(),
        )
        .unwrap()
    }
    #[test]
    fn relay_authenticates_reencrypts_stamps_rejects_replay_and_revokes() {
        let mut relay = Relay::default();
        relay.event(&event("a", "alice", 1, 10, "voice-uuid"));
        relay.event(&event("b", "bob", 2, 20, "voice-uuid"));
        relay.event(&event("c", "other", 3, 30, "elsewhere"));
        let a = "127.0.0.1:10001".parse().unwrap();
        let b = "127.0.0.1:10002".parse().unwrap();
        assert!(relay.receive(&packet(2, 20, 0, &[]), b).is_empty());
        assert!(relay.receive(&packet(1, 11, 0, b"bad key"), a).is_empty());
        let good = packet(1, 10, 0, b"opus");
        let out = relay.receive(&good, a);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, b);
        let n = Nonce::from(nonce(0));
        let clear = ChaCha20Poly1305::new_from_slice(&[21; 32])
            .unwrap()
            .decrypt(
                &n,
                Payload {
                    msg: &out[0].1[HEADER..],
                    aad: &out[0].1[..HEADER],
                },
            )
            .unwrap();
        let frame = VoiceFrame::decode(clear.as_slice()).unwrap();
        assert_eq!(frame.sender_session_id, "a");
        assert_eq!(frame.sender_user_id, "alice");
        assert_eq!(frame.opus, b"opus");
        assert!(relay.receive(&good, a).is_empty());
        relay.event(&serde_json::json!({"type":"leave","session_id":"a"}));
        assert!(relay.receive(&packet(1, 10, 1, b"opus"), a).is_empty());
    }
    #[test]
    fn replay_window_allows_reordering_but_never_duplicates_or_old_packets() {
        let mut r = Replay::default();
        assert!(r.accept(100));
        assert!(r.accept(99));
        assert!(!r.accept(99));
        assert!(r.accept(200));
        assert!(!r.accept(1));
        assert!(r.accept(199));
    }
}
