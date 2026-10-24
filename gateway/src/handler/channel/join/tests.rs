use super::*;
use std::sync::{Arc, atomic::AtomicUsize};

async fn fixture() -> (State, String) {
    let storage = crate::domain::storage::Storage::connect_sqlite(":memory:")
        .await
        .unwrap();
    let config = toml::from_str(include_str!("../../../../../dev/config.toml")).unwrap();
    let identity_dir =
        std::env::temp_dir().join(format!("vnox-join-test-{}", uuid::Uuid::new_v4()));
    let identity =
        crate::bootstrap::server_identity::ServerIdentity::load_or_generate(&identity_dir).unwrap();
    std::fs::remove_file(identity_dir.join("server_identity.json")).unwrap();
    std::fs::remove_dir(identity_dir).unwrap();
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
    let sess = session::create(&state.sessions, "visitor".into(), "Visitor".into()).await;
    channels::join(&state.channels, "general", &sess.session_id).await;
    set_channel(&state, &sess.session_id, Some("general".into())).await;
    (state, sess.session_id)
}

async fn attempt_join(state: &State, session_id: &str, channel_id: &str) {
    let (mut stream, _peer) = tokio::io::duplex(65536);
    join(
        &mut stream,
        &mut 0,
        session_id,
        channel_id,
        &SessionCrypto::derive(&[7; 32], session_id),
        state,
        "127.0.0.1:12345".parse().unwrap(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn missing_channel_keeps_previous_membership() {
    let (state, sid) = fixture().await;
    attempt_join(&state, &sid, "missing").await;
    assert!(
        channels::members(&state.channels, "general")
            .await
            .contains(&sid)
    );
    assert_eq!(
        session::get(&state.sessions, &sid)
            .await
            .unwrap()
            .channel_id
            .as_deref(),
        Some("general")
    );
}

#[tokio::test]
async fn outsider_cannot_join_guild_channel_or_lose_previous_membership() {
    let (state, sid) = fixture().await;
    let guild_id = state
        .storage
        .create_guild("owner", "Private guild")
        .await
        .unwrap();
    channels::create(
        &state.channels,
        "private",
        "Private",
        channels::ChannelKind::Text,
        Some(guild_id),
    )
    .await;
    attempt_join(&state, &sid, "private").await;
    assert!(
        !channels::members(&state.channels, "private")
            .await
            .contains(&sid)
    );
    assert!(
        channels::members(&state.channels, "general")
            .await
            .contains(&sid)
    );
    assert_eq!(
        session::get(&state.sessions, &sid)
            .await
            .unwrap()
            .channel_id
            .as_deref(),
        Some("general")
    );
}

#[tokio::test]
async fn guild_member_can_switch_channels() {
    let (state, sid) = fixture().await;
    let guild_id = state
        .storage
        .create_guild("owner", "Private guild")
        .await
        .unwrap();
    state
        .storage
        .add_guild_member(&guild_id, "visitor")
        .await
        .unwrap();
    channels::create(
        &state.channels,
        "private",
        "Private",
        channels::ChannelKind::Text,
        Some(guild_id),
    )
    .await;
    attempt_join(&state, &sid, "private").await;
    assert!(
        channels::members(&state.channels, "private")
            .await
            .contains(&sid)
    );
    assert!(
        !channels::members(&state.channels, "general")
            .await
            .contains(&sid)
    );
    assert_eq!(
        session::get(&state.sessions, &sid)
            .await
            .unwrap()
            .channel_id
            .as_deref(),
        Some("private")
    );
}
