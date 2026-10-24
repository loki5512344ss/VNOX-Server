//! Bounded authenticated signalling. No media packets or bearer auth endpoints.
use crate::{
    domain::{
        channels::{self, ChannelKind},
        permissions::Permissions,
        session,
    },
    handler::Ctx,
    net::{
        io,
        state::{BroadcastMsg, State},
    },
    proto::{self, MediaControl, MediaEvent, PacketId, encode_packet, to_payload},
};
use anyhow::{Result, bail};
use prost::Message;
use std::collections::{HashMap, HashSet};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Mutex,
};

pub const START: u32 = 1;
pub const STOP: u32 = 2;
pub const WATCH: u32 = 3;
pub const UNWATCH: u32 = 4;
pub const OFFER: u32 = 5;
pub const ANSWER: u32 = 6;
pub const ICE: u32 = 7;
const MAX_VIEWERS: usize = 4;
const MAX_SHARES: usize = 128;

#[derive(Clone)]
struct Share {
    channel: String,
    owner: String,
    user: String,
    viewers: HashSet<String>,
    audio: bool,
    mic: bool,
}
#[derive(Default)]
pub struct Runtime {
    shares: Mutex<HashMap<String, Share>>,
    rates: Mutex<HashMap<String, SignalBudget>>,
}
struct SignalBudget {
    updated: std::time::Instant,
    tokens: f64,
}
impl SignalBudget {
    fn consume(&mut self) -> bool {
        let now = std::time::Instant::now();
        self.tokens =
            (self.tokens + now.duration_since(self.updated).as_secs_f64() * 20.0).min(64.0);
        self.updated = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}
struct Route {
    target: String,
    event: MediaEvent,
}

impl Share {
    fn event(&self, action: u32, id: &str, sender: &str) -> MediaEvent {
        MediaEvent {
            action,
            channel_id: self.channel.clone(),
            share_id: id.into(),
            target_session_id: String::new(),
            body: String::new(),
            mline_index: 0,
            application_audio: self.audio,
            microphone: self.mic,
            sender_session_id: sender.into(),
            publisher_user_id: self.user.clone(),
        }
    }
}
impl Runtime {
    async fn apply(
        &self,
        sender: &str,
        user: &str,
        req: &MediaControl,
        members: &HashSet<String>,
    ) -> Result<Vec<Route>> {
        validate(req)?;
        let mut shares = self.shares.lock().await;
        if req.action == START {
            if shares.len() >= MAX_SHARES
                || shares.contains_key(&req.share_id)
                || shares.values().any(|share| share.owner == sender)
            {
                bail!("share already active or server capacity reached");
            }
            let share = Share {
                channel: req.channel_id.clone(),
                owner: sender.into(),
                user: user.into(),
                viewers: HashSet::new(),
                audio: req.application_audio,
                mic: req.microphone,
            };
            let routes = members
                .iter()
                .map(|target| Route {
                    target: target.clone(),
                    event: share.event(START, &req.share_id, sender),
                })
                .collect();
            shares.insert(req.share_id.clone(), share);
            return Ok(routes);
        }
        // WATCH with an empty share ID requests current announcements, not a subscription.
        if req.action == WATCH && req.share_id.is_empty() {
            return Ok(shares
                .iter()
                .filter(|(_, share)| share.channel == req.channel_id)
                .map(|(id, share)| Route {
                    target: sender.into(),
                    event: share.event(START, id, &share.owner),
                })
                .collect());
        }
        let share = shares
            .get_mut(&req.share_id)
            .ok_or_else(|| anyhow::anyhow!("unknown or expired share"))?;
        if share.channel != req.channel_id {
            bail!("share belongs to another voice channel");
        }
        let mut routes = Vec::new();
        match req.action {
            STOP => {
                if share.owner != sender {
                    bail!("only publisher may stop a share");
                }
                for target in members {
                    routes.push(Route {
                        target: target.clone(),
                        event: share.event(STOP, &req.share_id, sender),
                    });
                }
                shares.remove(&req.share_id);
            }
            WATCH => {
                if share.owner == sender || !members.contains(&share.owner) {
                    bail!("publisher unavailable or self subscription");
                }
                if !share.viewers.contains(sender) && share.viewers.len() >= MAX_VIEWERS {
                    bail!("share viewer limit reached");
                }
                if share.viewers.insert(sender.into()) {
                    routes.push(Route {
                        target: share.owner.clone(),
                        event: share.event(WATCH, &req.share_id, sender),
                    });
                }
                routes.push(Route {
                    target: sender.into(),
                    event: share.event(WATCH, &req.share_id, &share.owner),
                });
            }
            UNWATCH => {
                if !share.viewers.remove(sender) {
                    bail!("subscription not active");
                }
                routes.push(Route {
                    target: share.owner.clone(),
                    event: share.event(UNWATCH, &req.share_id, sender),
                });
                routes.push(Route {
                    target: sender.into(),
                    event: share.event(UNWATCH, &req.share_id, &share.owner),
                });
            }
            OFFER | ANSWER | ICE => {
                let target = req.target_session_id.as_str();
                if target == sender || !members.contains(target) {
                    bail!("target is not a voice peer");
                }
                let publisher_to_viewer = share.owner == sender && share.viewers.contains(target);
                let viewer_to_publisher = share.owner == target && share.viewers.contains(sender);
                if !(publisher_to_viewer || viewer_to_publisher)
                    || req.action == OFFER && !publisher_to_viewer
                    || req.action == ANSWER && !viewer_to_publisher
                {
                    bail!("signal is not authorized for this subscription");
                }
                let mut event = share.event(req.action, &req.share_id, sender);
                event.target_session_id = target.into();
                event.body = req.body.clone();
                event.mline_index = req.mline_index;
                routes.push(Route {
                    target: target.into(),
                    event,
                });
            }
            _ => bail!("unknown media action"),
        }
        Ok(routes)
    }

    /// Revoke all publishing/viewing rights for a leaving or disconnected session.
    pub async fn revoke(&self, state: &State, leaving: &str) {
        self.rates.lock().await.remove(leaving);
        let channels = state.channels.read().await;
        let mut shares = self.shares.lock().await;
        let mut routes = Vec::new();
        shares.retain(|id, share| {
            if share.owner == leaving {
                let mut targets = share.viewers.clone();
                targets.insert(leaving.to_owned());
                if let Some(channel) = channels.get(&share.channel) {
                    targets.extend(channel.members.iter().cloned());
                }
                for target in targets {
                    routes.push(Route {
                        target,
                        event: share.event(STOP, id, leaving),
                    });
                }
                false
            } else {
                if share.viewers.remove(leaving) {
                    routes.push(Route {
                        target: share.owner.clone(),
                        event: share.event(UNWATCH, id, leaving),
                    });
                    routes.push(Route {
                        target: leaving.to_owned(),
                        event: share.event(UNWATCH, id, &share.owner),
                    });
                }
                true
            }
        });
        drop(shares);
        send(state, routes);
    }
}

fn validate(req: &MediaControl) -> Result<()> {
    if req.channel_id.is_empty() || req.channel_id.len() > 128 || req.target_session_id.len() > 64 {
        bail!("invalid media scope");
    }
    if !(req.action == WATCH && req.share_id.is_empty())
        && uuid::Uuid::parse_str(&req.share_id).is_err()
    {
        bail!("share ID must be a UUID");
    }
    match req.action {
        OFFER | ANSWER if req.body.is_empty() || req.body.len() > 65_536 => {
            bail!("SDP size out of bounds")
        }
        ICE if req.body.len() > 2048 || req.mline_index > 2 => bail!("ICE candidate out of bounds"),
        START | STOP | WATCH | UNWATCH
            if !req.body.is_empty() || !req.target_session_id.is_empty() =>
        {
            bail!("unexpected media control data")
        }
        START..=ICE => {}
        _ => bail!("unknown media action"),
    }
    Ok(())
}

fn send(state: &State, routes: Vec<Route>) {
    for route in routes {
        let _ = state.broadcast.send(BroadcastMsg {
            channel_id: None,
            exclude_session: None,
            target_session_id: Some(route.target),
            data: encode_packet(PacketId::MediaEvent, 0, &to_payload(&route.event)),
        });
    }
}

/// Invoked only by authenticated LNEx dispatch, never by an HTTP endpoint.
pub async fn handle<S: AsyncRead + AsyncWrite + Unpin>(
    ctx: &mut Ctx<'_, S>,
    sender: &str,
    payload: &[u8],
) -> Result<()> {
    let outcome = authorize_and_apply(ctx.state, sender, payload).await;
    match outcome {
        Ok(routes) => {
            send(ctx.state, routes);
            Ok(())
        }
        Err(error) => {
            io::send_encrypted(
                ctx.stream,
                PacketId::Error,
                ctx.seq,
                &to_payload(&proto::Error {
                    code: proto::ErrorCode::PermissionDenied as u32,
                    message: format!("media: {error}"),
                }),
                ctx.crypto,
            )
            .await
        }
    }
}
async fn authorize_and_apply(state: &State, sender: &str, payload: &[u8]) -> Result<Vec<Route>> {
    if payload.len() > 67_000 {
        bail!("media control too large");
    }
    let req = MediaControl::decode(payload)?;
    validate(&req)?;
    {
        let mut rates = state.media.rates.lock().await;
        let budget = rates.entry(sender.into()).or_insert(SignalBudget {
            updated: std::time::Instant::now(),
            tokens: 64.0,
        });
        if !budget.consume() {
            bail!("media control rate exceeded");
        }
    }
    // Shared authorization lease covers fresh guild/channel checks and mutation.
    // It is dropped on return before the caller performs any socket I/O.
    let _access = state.access.read().await;
    let session = session::get(&state.sessions, sender)
        .await
        .ok_or_else(|| anyhow::anyhow!("session expired"))?;
    let channel = channels::get_channel(&state.channels, &req.channel_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("voice channel unavailable"))?;
    if channel.kind != ChannelKind::Voice || !channel.members.contains(sender) {
        bail!("voice membership required");
    }
    if let Some(guild) = channel.guild_id.as_deref() {
        if !state
            .storage
            .list_user_guilds(&session.user_id)
            .await?
            .iter()
            .any(|item| item.id == guild)
        {
            bail!("guild membership required");
        }
        if req.action == START {
            let owner = state
                .storage
                .get_guild(guild)
                .await?
                .is_some_and(|g| g.owner_id == session.user_id);
            let perms = state
                .storage
                .get_user_role_perms(guild, &session.user_id)
                .await?;
            if !owner && !Permissions::from_role_perms(&perms).has(Permissions::VOICE_SPEAK) {
                bail!("VOICE_SPEAK permission required");
            }
        }
    }
    // Hold current channel membership through the runtime mutation; leave/revoke
    // uses the same ordering (membership first, then media) to prevent resurrection.
    let channels = state.channels.read().await;
    let channel = channels
        .get(&req.channel_id)
        .ok_or_else(|| anyhow::anyhow!("voice channel unavailable"))?;
    if !channel.members.contains(sender) {
        bail!("voice membership revoked");
    }
    state
        .media
        .apply(sender, &session.user_id, &req, &channel.members)
        .await
}

/// Delivery-time membership check prevents queued SDP/ICE escaping after a leave.
pub async fn may_deliver(state: &State, recipient: &str, payload: &[u8]) -> bool {
    let Ok(event) = MediaEvent::decode(payload) else {
        return false;
    };
    if event.action == STOP || event.action == UNWATCH {
        return true;
    }
    let channels = state.channels.read().await;
    let Some(channel) = channels.get(&event.channel_id) else {
        return false;
    };
    if channel.kind != ChannelKind::Voice
        || !channel.members.contains(recipient)
        || !channel.members.contains(&event.sender_session_id)
    {
        return false;
    }
    let shares = state.media.shares.lock().await;
    let Some(share) = shares.get(&event.share_id) else {
        return false;
    };
    if share.channel != event.channel_id || !channel.members.contains(&share.owner) {
        return false;
    }
    match event.action {
        START => true,
        WATCH | OFFER | ANSWER | ICE => {
            (share.owner == recipient && share.viewers.contains(&event.sender_session_id))
                || (share.owner == event.sender_session_id && share.viewers.contains(recipient))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn req(action: u32, id: &str) -> MediaControl {
        MediaControl {
            action,
            channel_id: "voice".into(),
            share_id: id.into(),
            ..Default::default()
        }
    }
    #[tokio::test]
    async fn only_authorized_subscription_can_exchange_signals() {
        let runtime = Runtime::default();
        let members = ["publisher", "viewer", "other"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let id = uuid::Uuid::new_v4().to_string();
        runtime
            .apply("publisher", "owner-user", &req(START, &id), &members)
            .await
            .expect("start");
        let mut offer = req(OFFER, &id);
        offer.target_session_id = "viewer".into();
        offer.body = "v=0\r\n".into();
        assert!(
            runtime
                .apply("publisher", "owner-user", &offer, &members)
                .await
                .is_err()
        );
        runtime
            .apply("viewer", "viewer-user", &req(WATCH, &id), &members)
            .await
            .expect("watch");
        let routes = runtime
            .apply("publisher", "owner-user", &offer, &members)
            .await
            .expect("authorized offer");
        assert_eq!(routes[0].target, "viewer");
        assert_eq!(routes[0].event.sender_session_id, "publisher");
        assert_eq!(routes[0].event.publisher_user_id, "owner-user");
        assert!(
            runtime
                .apply("viewer", "viewer-user", &offer, &members)
                .await
                .is_err()
        );
        offer.action = ICE;
        offer.target_session_id = "publisher".into();
        assert!(
            runtime
                .apply("other", "other-user", &offer, &members)
                .await
                .is_err()
        );
        runtime
            .apply("viewer", "viewer-user", &req(UNWATCH, &id), &members)
            .await
            .expect("unwatch");
        assert!(
            runtime
                .apply("viewer", "viewer-user", &offer, &members)
                .await
                .is_err()
        );
        assert!(
            runtime
                .apply("viewer", "viewer-user", &req(STOP, &id), &members)
                .await
                .is_err()
        );
        runtime
            .apply("publisher", "owner-user", &req(STOP, &id), &members)
            .await
            .expect("stop");
        assert!(
            runtime
                .apply("viewer", "viewer-user", &req(WATCH, &id), &members)
                .await
                .is_err()
        );
    }
    #[test]
    fn signalling_budget_bounds_bursts_and_refills() {
        let mut budget = SignalBudget {
            updated: std::time::Instant::now(),
            tokens: 64.0,
        };
        for _ in 0..64 {
            assert!(budget.consume());
        }
        assert!(!budget.consume());
        budget.updated = std::time::Instant::now() - std::time::Duration::from_secs(1);
        assert!(budget.consume());
        assert!(budget.tokens < 20.1);
    }
    #[test]
    fn signalling_limits_reject_unbounded_data() {
        let mut signal = req(OFFER, &uuid::Uuid::new_v4().to_string());
        signal.body = "x".repeat(65_537);
        assert!(validate(&signal).is_err());
        signal.action = ICE;
        signal.body = "x".repeat(2049);
        assert!(validate(&signal).is_err());
        signal.body.clear();
        signal.mline_index = 3;
        assert!(validate(&signal).is_err());
    }
}
