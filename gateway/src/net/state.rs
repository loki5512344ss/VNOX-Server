use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tokio::sync::{RwLock, broadcast};

use crate::admin::metrics::Metrics;
use crate::bootstrap::server_identity::ServerIdentity;
use crate::domain::rate_limit::RateLimiter;
use crate::domain::{
    channels::ChannelStore, config::Config, session::SessionStore, storage::Storage,
};
use crate::proto::PresenceInfo;

pub type VoiceMemberTx = tokio::sync::broadcast::Sender<String>;

#[derive(Clone)]
pub struct State {
    pub webhooks: Arc<crate::webhooks::Runtime>,
    pub sessions: SessionStore,
    pub channels: ChannelStore,
    pub storage: Arc<Storage>,
    pub config: Arc<Config>,
    pub server_identity: Arc<ServerIdentity>,
    pub broadcast: broadcast::Sender<BroadcastMsg>,
    /// user_id → presence info (Phase 1.2)
    pub presences: Arc<RwLock<HashMap<String, PresenceInfo>>>,
    /// Prometheus-style counters.
    pub metrics: Arc<Metrics>,
    /// Live count of authenticated sessions.
    pub sessions_count: Arc<AtomicUsize>,
    /// Live count of channels with at least one member.
    #[allow(dead_code)]
    pub channels_count: Arc<AtomicUsize>,
    /// Per-session rate limiter (token bucket).
    pub rate_limiter: Arc<RateLimiter>,
    /// Gateway → voice-node membership bridge.
    pub voice_member_tx: Option<VoiceMemberTx>,
    /// E2EE key store: user_id -> X25519 public key bytes
    pub e2ee_keys: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl State {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sessions: SessionStore,
        channels: ChannelStore,
        storage: Arc<Storage>,
        config: Arc<Config>,
        server_identity: Arc<ServerIdentity>,
        broadcast: broadcast::Sender<BroadcastMsg>,
        metrics: Arc<Metrics>,
        sessions_count: Arc<AtomicUsize>,
        channels_count: Arc<AtomicUsize>,
        voice_member_tx: Option<VoiceMemberTx>,
    ) -> Self {
        let rate_per_sec = config.gateway.message_rate_per_sec.unwrap_or(5.0);
        let burst = config.gateway.message_rate_burst.unwrap_or(10);
        let rate_limiter = Arc::new(RateLimiter::new(rate_per_sec, burst));
        Self {
            webhooks: Arc::default(),
            sessions,
            channels,
            storage,
            config,
            server_identity,
            broadcast,
            presences: Arc::new(RwLock::new(HashMap::new())),
            metrics,
            sessions_count,
            channels_count,
            rate_limiter,
            voice_member_tx,
            e2ee_keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[derive(Clone, Debug)]
pub struct BroadcastMsg {
    pub channel_id: Option<String>,
    pub exclude_session: Option<String>,
    pub target_session_id: Option<String>,
    pub data: Vec<u8>,
}
