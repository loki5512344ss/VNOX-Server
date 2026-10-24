//! The only HTTP webhook surface accepts scoped delivery credentials, never management sessions.
use super::{MAX_BODY, management, now_ms, secrets, valid_content};
use crate::{
    net::state::{BroadcastMsg, State as Gateway},
    proto::{ChatMessagePayload, PacketId, encode_packet, to_payload},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    routing::post,
};
use serde::Deserialize;

pub fn router(state: Gateway) -> Router {
    Router::new()
        .route("/v1/webhooks/{id}", post(deliver))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(state)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    content: String,
}
fn header<'a>(headers: &'a HeaderMap, key: &str) -> Option<&'a str> {
    headers.get(key)?.to_str().ok()
}
fn delivery_id(s: &str) -> bool {
    (8..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}

pub async fn accept(
    state: &Gateway,
    id: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<bool, StatusCode> {
    let _slot = state
        .webhooks
        .deliveries
        .try_acquire()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    if body.len() > MAX_BODY {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let hook = state
        .storage
        .hook(id)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .filter(|h| h.revoked_at.is_none() && h.direction == "incoming")
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let (content, delivery) = if hook.provider == "github" {
        let key = state
            .webhooks
            .key()
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let secret = secrets::open(key, id, &hook.sealed_secret)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if !secrets::verify(
            &secret,
            body,
            header(headers, "x-hub-signature-256").unwrap_or_default(),
        ) {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let delivery = header(headers, "x-github-delivery")
            .ok_or(StatusCode::BAD_REQUEST)?
            .to_owned();
        let event = header(headers, "x-github-event").ok_or(StatusCode::BAD_REQUEST)?;
        if !["push", "pull_request", "issues", "release", "ping"].contains(&event) {
            return Err(StatusCode::UNPROCESSABLE_ENTITY);
        }
        let data: serde_json::Value =
            serde_json::from_slice(body).map_err(|_| StatusCode::BAD_REQUEST)?;
        // Never copy arbitrary descriptions/URLs/mentions into chat: predictable provider summary only.
        let repo = data
            .pointer("/repository/full_name")
            .and_then(|v| v.as_str())
            .unwrap_or("repository");
        let actor = data
            .pointer("/sender/login")
            .and_then(|v| v.as_str())
            .unwrap_or("GitHub");
        if [repo, actor].iter().any(|v| {
            v.len() > 200
                || !v
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_./".contains(&b))
        }) {
            return Err(StatusCode::BAD_REQUEST);
        }
        (format!("GitHub · {repo}: {event} ({actor})"), delivery)
    } else {
        let supplied = header(headers, "authorization")
            .and_then(|v| v.strip_prefix("Bearer "))
            .filter(|v| v.len() == 64)
            .ok_or(StatusCode::UNAUTHORIZED)?;
        use subtle::ConstantTimeEq;
        let actual = secrets::digest(supplied.as_bytes());
        if !bool::from(actual.as_bytes().ct_eq(hook.token_hash.as_bytes())) {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let delivery = header(headers, "idempotency-key")
            .map(str::to_owned)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let payload: Payload = serde_json::from_slice(body).map_err(|_| StatusCode::BAD_REQUEST)?;
        (payload.content, delivery)
    };
    if !delivery_id(&delivery) || !valid_content(&content) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !state.webhooks.consume(id) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    // Permission removal, guild/channel deletion or a changed channel scope disables delivery immediately.
    if management::authorize(state, &hook.creator_id, &hook.channel_id)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .as_deref()
        != Some(hook.guild_id.as_str())
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let msg = ChatMessagePayload {
        message_id: uuid::Uuid::new_v4().to_string(),
        channel_id: hook.channel_id,
        sender_id: format!("webhook:{id}"),
        content,
        timestamp: now_ms(),
        edited: false,
        reply_to: None,
    };
    let added = state
        .storage
        .save_webhook_message(
            &msg,
            Some((id, &delivery, &secrets::digest(body), &hook.token_hash)),
        )
        .await
        .map_err(|e| {
            if e.to_string() == "idempotency conflict" {
                StatusCode::CONFLICT
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            }
        })?;
    if added {
        state.metrics.inc(&state.metrics.messages_sent);
        let _ = state.broadcast.send(BroadcastMsg {
            channel_id: Some(msg.channel_id.clone()),
            exclude_session: None,
            target_session_id: None,
            data: encode_packet(PacketId::ChatMessage, 0, &to_payload(&msg)),
        });
    }
    Ok(added)
}
async fn deliver(
    State(state): State<Gateway>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<serde_json::Value>), StatusCode> {
    let added = accept(&state, &id, &headers, &body).await?;
    Ok((
        if added {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(serde_json::json!({"accepted":true,"duplicate":!added})),
    ))
}
