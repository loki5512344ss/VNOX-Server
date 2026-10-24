use super::*;
use crate::{
    domain::{
        channels, session,
        storage::{Storage, webhooks::Hook},
    },
    net::state::State,
    proto::ChatMessagePayload,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use std::sync::{Arc, atomic::AtomicUsize};

async fn fixture() -> (State, Hook, String) {
    let storage = Storage::connect_sqlite(":memory:").await.unwrap();
    let guild = storage.create_guild("owner", "test").await.unwrap();
    storage
        .create_channel("target", "target", "text", Some(&guild))
        .await
        .unwrap();
    let config = toml::from_str(include_str!("../../../dev/config.toml")).unwrap();
    let dir = std::env::temp_dir().join(format!("vnox-hook-test-{}", uuid::Uuid::new_v4()));
    let identity =
        crate::bootstrap::server_identity::ServerIdentity::load_or_generate(&dir).unwrap();
    std::fs::remove_file(dir.join("server_identity.json")).unwrap();
    std::fs::remove_dir(dir).unwrap();
    let (broadcast, _) = tokio::sync::broadcast::channel(16);
    let state = State::new(
        session::new_store(),
        channels::new_store(),
        Arc::new(storage),
        Arc::new(config),
        Arc::new(identity),
        broadcast,
        crate::admin::metrics::Metrics::new(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicUsize::new(0)),
        None,
    );
    state.webhooks.set_key([7; 32]).unwrap();
    let secret = secrets::new_secret();
    let hook = Hook {
        id: "incoming".into(),
        channel_id: "target".into(),
        guild_id: guild,
        creator_id: "owner".into(),
        name: "CI".into(),
        direction: "incoming".into(),
        provider: "generic".into(),
        endpoint: String::new(),
        token_hash: secrets::digest(secret.as_bytes()),
        sealed_secret: Vec::new(),
        created_at: now_ms(),
        revoked_at: None,
        suspended_reason: None,
    };
    state.storage.insert_hook(&hook).await.unwrap();
    (state, hook, secret)
}
fn headers(secret: &str, id: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {secret}")).unwrap(),
    );
    h.insert("idempotency-key", HeaderValue::from_str(id).unwrap());
    h
}
#[tokio::test]
async fn incoming_auth_scope_identity_and_idempotency() {
    let (s, h, key) = fixture().await;
    let body = br#"{"content":"build passed"}"#;
    assert_eq!(
        incoming::accept(&s, &h.id, &HeaderMap::new(), body).await,
        Err(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(
        incoming::accept(&s, &h.id, &headers(&"0".repeat(64), "delivery1"), body).await,
        Err(StatusCode::UNAUTHORIZED)
    );
    let auth = headers(&key, "delivery1");
    assert_eq!(incoming::accept(&s, &h.id, &auth, body).await, Ok(true));
    assert_eq!(incoming::accept(&s, &h.id, &auth, body).await, Ok(false));
    assert_eq!(
        incoming::accept(&s, &h.id, &auth, br#"{"content":"other"}"#).await,
        Err(StatusCode::CONFLICT)
    );
    let history = s.storage.get_history("target", 100).await.unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].sender_id, "webhook:incoming");
    assert!(
        s.storage
            .get_history("general", 10)
            .await
            .unwrap()
            .is_empty()
    );
}
#[tokio::test]
async fn rejects_impersonation_mentions_large_payloads_and_revoked_keys() {
    let (s, h, key) = fixture().await;
    let auth = headers(&key, "delivery1");
    for body in [
        br#"{"content":"hello","sender_id":"owner"}"#.as_slice(),
        br#"{"content":"@everyone"}"#,
        br#"{"content":"<@123>"}"#,
    ] {
        assert_eq!(
            incoming::accept(&s, &h.id, &auth, body).await,
            Err(StatusCode::BAD_REQUEST)
        );
    }
    assert_eq!(
        incoming::accept(&s, &h.id, &auth, &vec![b' '; MAX_BODY + 1]).await,
        Err(StatusCode::PAYLOAD_TOO_LARGE)
    );
    let rotated = secrets::new_secret();
    s.storage
        .rotate_hook(&h.id, &secrets::digest(rotated.as_bytes()), &[])
        .await
        .unwrap();
    assert_eq!(
        incoming::accept(&s, &h.id, &auth, br#"{"content":"hi"}"#).await,
        Err(StatusCode::UNAUTHORIZED)
    );
    s.storage.revoke_hook(&h.id).await.unwrap();
    assert_eq!(
        incoming::accept(
            &s,
            &h.id,
            &headers(&rotated, "delivery2"),
            br#"{"content":"hi"}"#
        )
        .await,
        Err(StatusCode::UNAUTHORIZED)
    );
}
#[tokio::test]
async fn management_requires_membership_even_with_stale_privileged_role() {
    let (s, h, _) = fixture().await;
    assert!(
        management::authorize(&s, "owner", "target")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        management::authorize(&s, "stranger", "target")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        management::authorize(&s, "owner", "general")
            .await
            .unwrap()
            .is_none()
    );
    s.storage
        .add_guild_member(&h.guild_id, "member")
        .await
        .unwrap();
    assert!(
        management::authorize(&s, "member", "target")
            .await
            .unwrap()
            .is_none()
    );
    if let crate::domain::storage::Pool::Sqlite(p) = &s.storage.pool {
        sqlx::query("INSERT INTO member_roles(guild_id,user_id,role_id) SELECT guild_id,$1,id FROM roles WHERE guild_id=$2").bind("member").bind(&h.guild_id).execute(p).await.unwrap();
    }
    assert!(
        management::authorize(&s, "member", "target")
            .await
            .unwrap()
            .is_some()
    );
    s.storage
        .remove_guild_member(&h.guild_id, "member")
        .await
        .unwrap();
    assert!(
        management::authorize(&s, "member", "target")
            .await
            .unwrap()
            .is_none()
    );
}
#[tokio::test]
async fn outbox_is_transactional_bounded_and_retries_are_finite() {
    let (s, mut h, key) = fixture().await;
    h.id = "outgoing".into();
    h.direction = "outgoing".into();
    h.endpoint = "https://example.com/hook".into();
    h.sealed_secret = secrets::seal(&[7; 32], &h.id, &key).unwrap();
    s.storage.insert_hook(&h).await.unwrap();
    let msg = ChatMessagePayload {
        message_id: "event1".into(),
        channel_id: "target".into(),
        sender_id: "owner".into(),
        content: "hello".into(),
        timestamp: now_ms(),
        edited: false,
        reply_to: None,
    };
    assert!(s.storage.save_webhook_message(&msg, None).await.unwrap());
    assert!(!s.storage.save_webhook_message(&msg, None).await.unwrap());
    let mut jobs = s.storage.due_webhooks().await.unwrap();
    assert_eq!(jobs.len(), 1);
    let job = jobs.pop().unwrap();
    assert!(job.body.contains("message.created"));
    s.storage.finish_webhook(&job, false).await.unwrap();
    assert!(s.storage.due_webhooks().await.unwrap().is_empty());
    let terminal = crate::domain::storage::webhooks::Delivery { attempts: 7, ..job };
    s.storage.finish_webhook(&terminal, false).await.unwrap();
    if let crate::domain::storage::Pool::Sqlite(p) = &s.storage.pool {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM webhook_outbox")
            .fetch_one(p)
            .await
            .unwrap();
        assert_eq!(n, 0);
    }
    for i in 0..130 {
        let mut m = msg.clone();
        m.message_id = format!("event{i}");
        s.storage.save_webhook_message(&m, None).await.unwrap();
    }
    assert_eq!(
        s.storage
            .hook(&h.id)
            .await
            .unwrap()
            .unwrap()
            .suspended_reason
            .as_deref(),
        Some("queue_full")
    );
    if let crate::domain::storage::Pool::Sqlite(p) = &s.storage.pool {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM webhook_outbox")
            .fetch_one(p)
            .await
            .unwrap();
        assert_eq!(n, 128);
    }
    s.storage.revoke_hook(&h.id).await.unwrap();
    assert!(s.storage.due_webhooks().await.unwrap().is_empty());
}
#[tokio::test]
async fn github_requires_valid_raw_body_signature_and_deduplicates() {
    let (s, mut h, key) = fixture().await;
    h.id = "github".into();
    h.provider = "github".into();
    h.sealed_secret = secrets::seal(&[7; 32], &h.id, &key).unwrap();
    s.storage.insert_hook(&h).await.unwrap();
    let body = br#"{"repository":{"full_name":"owner/repo"},"sender":{"login":"alice"}}"#;
    let mut headers = HeaderMap::new();
    headers.insert("x-github-delivery", HeaderValue::from_static("delivery1"));
    headers.insert("x-github-event", HeaderValue::from_static("push"));
    assert_eq!(
        incoming::accept(&s, &h.id, &headers, body).await,
        Err(StatusCode::UNAUTHORIZED)
    );
    headers.insert(
        "x-hub-signature-256",
        HeaderValue::from_str(&format!("sha256={}", secrets::sign(&key, body))).unwrap(),
    );
    assert_eq!(incoming::accept(&s, &h.id, &headers, body).await, Ok(true));
    assert_eq!(incoming::accept(&s, &h.id, &headers, body).await, Ok(false));
    assert_eq!(
        incoming::accept(&s, &h.id, &headers, b"changed").await,
        Err(StatusCode::UNAUTHORIZED)
    );
}

#[tokio::test]
async fn http_delivery_route_enforces_auth_and_streamed_body_limit() {
    let (state, hook, key) = fixture().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, incoming::router(state))
            .await
            .unwrap()
    });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let target = format!("http://{address}/v1/webhooks/{}", hook.id);
    let response = client
        .post(&target)
        .json(&serde_json::json!({"content":"hello"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = client
        .post(&target)
        .bearer_auth(&key)
        .json(&serde_json::json!({"content":"hello"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = client
        .post(&target)
        .bearer_auth(&key)
        .body(vec![b'x'; MAX_BODY + 1])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    task.abort();
    let _ = task.await;
}

#[test]
fn rate_limit_and_content_boundaries() {
    let runtime = Runtime::default();
    for _ in 0..10 {
        assert!(runtime.consume("hook"))
    }
    assert!(!runtime.consume("hook"));
    assert!(runtime.consume("another"));
    assert!(valid_content(&"я".repeat(MAX_CONTENT)));
    assert!(!valid_content(&"я".repeat(MAX_CONTENT + 1)));
    assert!(!valid_content("@EVERYONE hi"));
    assert!(!valid_content("\0"));
    assert!(valid_content("line\nnext\ttab"));
}

#[tokio::test]
async fn lnex_management_rejects_stranger_and_creates_only_for_owner() {
    use crate::proto::{PacketId, WebhookRequest, to_payload};
    let (s, _, _) = fixture().await;
    let req = WebhookRequest {
        id: String::new(),
        channel_id: "target".into(),
        name: "builds".into(),
        direction: "incoming".into(),
        provider: "generic".into(),
        endpoint: String::new(),
        request_id: "request-123".into(),
    };
    for (user, expected) in [
        ("stranger", PacketId::WebhookErrorResult),
        ("owner", PacketId::WebhookResult),
    ] {
        let session = session::create(&s.sessions, user.into(), user.into()).await;
        let (mut stream, mut peer) = tokio::io::duplex(65536);
        let mut seq = 0;
        let mut ctx = crate::handler::Ctx {
            stream: &mut stream,
            seq: &mut seq,
            state: &s,
        };
        management::handle(
            &mut ctx,
            &session.session_id,
            PacketId::WebhookCreate,
            &to_payload(&req),
        )
        .await
        .unwrap();
        let (header, _) = crate::net::io::read_packet(&mut peer).await.unwrap();
        assert_eq!(header.packet_id, expected as u16);
        assert_eq!(
            header.flags, 0,
            "TLS protects the stream; frames carry no flags"
        );
    }
    let hooks = s.storage.hooks("target").await.unwrap();
    assert_eq!(hooks.len(), 2);
    assert!(hooks.iter().all(|h| h.creator_id == "owner"));
}

#[tokio::test]
async fn durable_outbox_and_receipts_survive_database_reopen() {
    let (_, mut hook, secret) = fixture().await;
    let path = std::env::temp_dir().join(format!("vnox-outbox-{}.sqlite", uuid::Uuid::new_v4()));
    let database = Storage::connect_sqlite(path.to_str().unwrap())
        .await
        .unwrap();
    database.insert_hook(&hook).await.unwrap();
    hook.id = "outgoing".into();
    hook.direction = "outgoing".into();
    hook.sealed_secret = secrets::seal(&[7; 32], &hook.id, &secret).unwrap();
    database.insert_hook(&hook).await.unwrap();
    let msg = ChatMessagePayload {
        message_id: "persistent".into(),
        channel_id: "target".into(),
        sender_id: "webhook:incoming".into(),
        content: "hello".into(),
        timestamp: now_ms(),
        edited: false,
        reply_to: None,
    };
    let hash = secrets::digest(b"body");
    let token_hash = secrets::digest(secret.as_bytes());
    database
        .save_webhook_message(&msg, Some(("incoming", "delivery1", &hash, &token_hash)))
        .await
        .unwrap();
    if let crate::domain::storage::Pool::Sqlite(p) = &database.pool {
        p.close().await;
    }
    drop(database);
    let reopened = Storage::connect_sqlite(path.to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(reopened.due_webhooks().await.unwrap().len(), 1);
    assert_eq!(reopened.get_history("target", 10).await.unwrap().len(), 1);
    assert!(
        !reopened
            .save_webhook_message(&msg, Some(("incoming", "delivery1", &hash, &token_hash)))
            .await
            .unwrap()
    );
    if let crate::domain::storage::Pool::Sqlite(p) = &reopened.pool {
        p.close().await;
    }
    drop(reopened);
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn management_lists_active_hooks_after_many_revocations() {
    let (state, mut hook, _) = fixture().await;
    state.storage.revoke_hook(&hook.id).await.unwrap();
    for index in 0..70 {
        hook.id = format!("retired-{index}");
        hook.created_at = index;
        state.storage.insert_hook(&hook).await.unwrap();
        state.storage.revoke_hook(&hook.id).await.unwrap();
    }
    hook.id = "current-integration".into();
    hook.created_at = 100;
    state.storage.insert_hook(&hook).await.unwrap();
    let listed = state.storage.hooks("target").await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, "current-integration");
}
