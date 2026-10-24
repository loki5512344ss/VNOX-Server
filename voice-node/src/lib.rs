pub mod secure;
pub mod wire {
    include!(concat!(env!("OUT_DIR"), "/lnex.rs"));
}
pub mod jitter;
pub mod relay;
pub mod runner;
use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub node: NodeConfig,
    pub voice: VoiceConfig,
}

#[derive(Debug, Deserialize)]
pub struct NodeConfig {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct VoiceConfig {
    pub bind: String,
}

pub use runner::run_bind;

pub fn load_config() -> Result<Config> {
    let path = std::env::args()
        .skip_while(|a| a != "--config")
        .nth(1)
        .unwrap_or_else(|| "/etc/vnox/config.toml".into());

    let text = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("cannot read config {path}: {e}"))?;

    toml::from_str(&text).map_err(|e| anyhow::anyhow!("invalid config: {e}"))
}

// ─── Voice packet header ──────────────────────────────────────────────────────

pub const VOICE_HDR_SIZE: usize = 20;
pub const VOICE_PACKET_ID: u16 = 0x0010;
pub const MAX_UDP_PACKET: usize = 1472;
pub const PLAYOUT_INTERVAL_MS: u64 = 5;

pub struct VoiceHeader {
    pub packet_id: u16,
    pub _flags: u16,
    pub voice_seq: u32,
    pub timestamp: u32,
    pub channel_id: u64,
}

impl VoiceHeader {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < VOICE_HDR_SIZE {
            return None;
        }
        Some(Self {
            packet_id: u16::from_be_bytes([buf[0], buf[1]]),
            _flags: u16::from_be_bytes([buf[2], buf[3]]),
            voice_seq: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            timestamp: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            channel_id: u64::from_be_bytes([
                buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19],
            ]),
        })
    }
}
