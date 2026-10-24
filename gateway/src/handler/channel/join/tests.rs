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

#[tokio::test]
async fn text_navigation_preserves_voice_and_leaving_unrelated_channel_is_noop() {
    let (mut state, sid) = fixture().await;
    let (tx, mut rx) = tokio::sync::broadcast::channel(16);
    tokio::spawn(async move { while rx.recv().await.is_ok() {} });
    state.voice_member_tx = Some(tx);
    attempt_join(&state, &sid, "voice").await;
    let sess = session::get(&state.sessions, &sid).await.unwrap();
    assert_eq!(sess.channel_id.as_deref(), Some("general"));
    assert_eq!(sess.voice_channel_id.as_deref(), Some("voice"));
    channels::create(
        &state.channels,
        "other-text",
        "Other",
        channels::ChannelKind::Text,
        None,
    )
    .await;
    attempt_join(&state, &sid, "other-text").await;
    assert!(
        channels::members(&state.channels, "voice")
            .await
            .contains(&sid)
    );
    let (mut stream, _) = tokio::io::duplex(65536);
    super::super::leave(
        &mut stream,
        &mut 0,
        &sid,
        "general",
        &SessionCrypto::derive(&[7; 32], &sid),
        &state,
    )
    .await
    .unwrap();
    let sess = session::get(&state.sessions, &sid).await.unwrap();
    assert_eq!(sess.channel_id.as_deref(), Some("other-text"));
    assert_eq!(sess.voice_channel_id.as_deref(), Some("voice"));
    super::super::leave(
        &mut stream,
        &mut 0,
        &sid,
        "voice",
        &SessionCrypto::derive(&[7; 32], &sid),
        &state,
    )
    .await
    .unwrap();
    let sess = session::get(&state.sessions, &sid).await.unwrap();
    assert_eq!(sess.channel_id.as_deref(), Some("other-text"));
    assert_eq!(sess.voice_channel_id, None);
}

#[tokio::test]
async fn channel_mutations_require_guild_authority_and_deletion_revokes_voice_credentials() {
    use crate::proto::{ChannelDeletePayload, ChannelEditPayload};
    let (mut state, sid) = fixture().await;
    let guild = state
        .storage
        .create_guild("owner", "Private")
        .await
        .unwrap();
    channels::create(
        &state.channels,
        "managed",
        "Managed",
        channels::ChannelKind::Voice,
        Some(guild.clone()),
    )
    .await;
    state
        .storage
        .create_channel("managed", "Managed", "voice", Some(&guild))
        .await
        .unwrap();
    let (mut stream, _peer) = tokio::io::duplex(65536);
    let crypto = SessionCrypto::derive(&[7; 32], &sid);
    crate::handler::channel::handle_channel_edit(
        &mut stream,
        &mut 0,
        &sid,
        &to_payload(&ChannelEditPayload {
            channel_id: "managed".into(),
            channel_name: "stolen".into(),
        }),
        &crypto,
        &state,
    )
    .await
    .unwrap();
    assert_eq!(
        channels::get_channel(&state.channels, "managed")
            .await
            .unwrap()
            .name,
        "Managed"
    );
    crate::handler::channel::handle_channel_delete(
        &mut stream,
        &mut 0,
        &sid,
        &to_payload(&ChannelDeletePayload {
            channel_id: "managed".into(),
        }),
        &crypto,
        &state,
    )
    .await
    .unwrap();
    assert!(
        channels::get_channel(&state.channels, "managed")
            .await
            .is_some()
    );
    assert!(
        !super::super::may_manage(&state, "owner", None)
            .await
            .unwrap()
    );
    let owner = session::create(&state.sessions, "owner".into(), "Owner".into()).await;
    channels::join(&state.channels, "managed", &owner.session_id).await;
    super::super::set_voice_channel(&state, &owner.session_id, Some("managed".into())).await;
    let (tx, mut rx) = tokio::sync::broadcast::channel(8);
    state.voice_member_tx = Some(tx);
    crate::handler::channel::handle_channel_delete(
        &mut stream,
        &mut 0,
        &owner.session_id,
        &to_payload(&ChannelDeletePayload {
            channel_id: "managed".into(),
        }),
        &crypto,
        &state,
    )
    .await
    .unwrap();
    assert!(
        channels::get_channel(&state.channels, "managed")
            .await
            .is_none()
    );
    assert!(
        session::get(&state.sessions, &owner.session_id)
            .await
            .unwrap()
            .voice_channel_id
            .is_none()
    );
    let event: serde_json::Value = serde_json::from_str(&rx.try_recv().unwrap()).unwrap();
    assert_eq!(event["type"], "leave");
    assert_eq!(event["session_id"], owner.session_id);
}

#[tokio::test]
async fn guild_role_handlers_reject_cross_guild_targets_and_privilege_escalation() {
    use crate::domain::permissions::Permissions;
    use crate::proto::{RoleAssignPayload, RoleDeletePayload};
    let (state, sid) = fixture().await;
    let guild = state
        .storage
        .create_guild("visitor", "Owned")
        .await
        .unwrap();
    let other = state
        .storage
        .create_guild("elsewhere", "Other")
        .await
        .unwrap();
    let foreign = state
        .storage
        .create_role(
            &other,
            "foreign",
            "#fff",
            Permissions::ADMINISTRATOR.bits(),
            1,
        )
        .await
        .unwrap();
    let (mut stream, _peer) = tokio::io::duplex(65536);
    let crypto = SessionCrypto::derive(&[7; 32], &sid);
    crate::handler::guild::handle_role_assign(
        &mut stream,
        &mut 0,
        &sid,
        &to_payload(&RoleAssignPayload {
            guild_id: guild.clone(),
            user_id: "visitor".into(),
            role_id: foreign.clone(),
        }),
        &crypto,
        &state,
    )
    .await
    .unwrap();
    crate::handler::guild::handle_role_delete(
        &mut stream,
        &mut 0,
        &sid,
        &to_payload(&RoleDeletePayload {
            guild_id: guild.clone(),
            role_id: foreign.clone(),
        }),
        &crypto,
        &state,
    )
    .await
    .unwrap();
    assert!(
        state
            .storage
            .list_guild_roles(&other)
            .await
            .unwrap()
            .iter()
            .any(|r| r.id == foreign)
    );
    let otherguild = state
        .storage
        .create_guild("owner", "Managed")
        .await
        .unwrap();
    state
        .storage
        .add_guild_member(&otherguild, "visitor")
        .await
        .unwrap();
    let manager = state
        .storage
        .create_role(
            &otherguild,
            "manager",
            "#fff",
            Permissions::MANAGE_ROLES.bits(),
            1,
        )
        .await
        .unwrap();
    state
        .storage
        .assign_role(&otherguild, "visitor", &manager)
        .await
        .unwrap();
    let powerful = state
        .storage
        .create_role(
            &otherguild,
            "admin",
            "#fff",
            Permissions::ADMINISTRATOR.bits(),
            2,
        )
        .await
        .unwrap();
    crate::handler::guild::handle_role_assign(
        &mut stream,
        &mut 0,
        &sid,
        &to_payload(&RoleAssignPayload {
            guild_id: otherguild.clone(),
            user_id: "visitor".into(),
            role_id: powerful,
        }),
        &crypto,
        &state,
    )
    .await
    .unwrap();
    let actual = Permissions::from_role_perms(
        &state
            .storage
            .get_user_role_perms(&otherguild, "visitor")
            .await
            .unwrap(),
    );
    assert!(!actual.contains(Permissions::ADMINISTRATOR));
}

#[tokio::test]
async fn removing_voice_role_revokes_existing_udp_membership() {
    use crate::domain::permissions::Permissions;
    use crate::proto::RoleAssignPayload;
    let (mut state, sid) = fixture().await;
    let guild = state
        .storage
        .create_guild("owner", "Private")
        .await
        .unwrap();
    state
        .storage
        .add_guild_member(&guild, "visitor")
        .await
        .unwrap();
    let role = state
        .storage
        .create_role(
            &guild,
            "speaker",
            "#fff",
            Permissions::VOICE_SPEAK.bits(),
            1,
        )
        .await
        .unwrap();
    state
        .storage
        .assign_role(&guild, "visitor", &role)
        .await
        .unwrap();
    channels::create(
        &state.channels,
        "managed",
        "Managed",
        channels::ChannelKind::Voice,
        Some(guild.clone()),
    )
    .await;
    channels::join(&state.channels, "managed", &sid).await;
    super::super::set_voice_channel(&state, &sid, Some("managed".into())).await;
    let owner = session::create(&state.sessions, "owner".into(), "Owner".into()).await;
    let (tx, mut rx) = tokio::sync::broadcast::channel(8);
    state.voice_member_tx = Some(tx);
    let (mut stream, _peer) = tokio::io::duplex(65536);
    crate::handler::guild::handle_role_unassign(
        &mut stream,
        &mut 0,
        &owner.session_id,
        &to_payload(&RoleAssignPayload {
            guild_id: guild,
            user_id: "visitor".into(),
            role_id: role,
        }),
        &SessionCrypto::derive(&[7; 32], &owner.session_id),
        &state,
    )
    .await
    .unwrap();
    assert!(
        session::get(&state.sessions, &sid)
            .await
            .unwrap()
            .voice_channel_id
            .is_none()
    );
    assert!(
        !channels::members(&state.channels, "managed")
            .await
            .contains(&sid)
    );
    let event: serde_json::Value = serde_json::from_str(&rx.try_recv().unwrap()).unwrap();
    assert_eq!(event["type"], "leave");
    assert_eq!(event["session_id"], sid);
}

#[tokio::test]
async fn private_channel_notifications_target_members_and_acknowledge_editor() {
    use crate::proto::{ChannelCreatePayload, ChannelDeletePayload, ChannelEditPayload};
    let (state, owner_sid) = fixture().await;
    let guild = state
        .storage
        .create_guild("visitor", "Private")
        .await
        .unwrap();
    state
        .storage
        .add_guild_member(&guild, "member")
        .await
        .unwrap();
    let member = session::create(&state.sessions, "member".into(), "Member".into()).await;
    let outsider = session::create(&state.sessions, "outsider".into(), "Outsider".into()).await;
    let mut events = state.broadcast.subscribe();
    let crypto = SessionCrypto::derive(&[7; 32], &owner_sid);
    let (mut stream, _peer) = tokio::io::duplex(65536);
    let creation = ChannelCreatePayload {
        channel_id: "private-notification".into(),
        channel_name: "Private name".into(),
        kind: "text".into(),
        guild_id: Some(guild.clone()),
    };
    crate::handler::channel::handle_channel_create(
        &mut stream,
        &mut 0,
        &owner_sid,
        &to_payload(&creation),
        &crypto,
        &state,
    )
    .await
    .unwrap();
    crate::handler::channel::handle_channel_edit(
        &mut stream,
        &mut 0,
        &owner_sid,
        &to_payload(&ChannelEditPayload {
            channel_id: creation.channel_id.clone(),
            channel_name: "Renamed privately".into(),
        }),
        &crypto,
        &state,
    )
    .await
    .unwrap();
    crate::handler::channel::handle_channel_delete(
        &mut stream,
        &mut 0,
        &owner_sid,
        &to_payload(&ChannelDeletePayload {
            channel_id: creation.channel_id.clone(),
        }),
        &crypto,
        &state,
    )
    .await
    .unwrap();
    let mut notifications = Vec::new();
    while let Ok(event) = events.try_recv() {
        notifications.push(event)
    }
    assert_eq!(notifications.len(), 5);
    assert!(notifications.iter().all(|event|matches!(event.target_session_id.as_deref(),Some(id) if id==owner_sid || id==member.session_id)));
    assert!(
        notifications
            .iter()
            .all(|event| event.target_session_id.as_deref() != Some(&outsider.session_id))
    );
    assert!(
        notifications.iter().any(
            |event| event.target_session_id.as_deref() == Some(&owner_sid)
                && crate::proto::PacketHeader::from_bytes(event.data[..12].try_into().unwrap())
                    .packet_id
                    == PacketId::ChannelEdit as u16
        )
    );
    assert!(
        super::super::may_deliver_metadata(
            &state,
            &member.session_id,
            PacketId::ChannelCreate,
            &to_payload(&creation)
        )
        .await
    );
    state
        .storage
        .remove_guild_member(&guild, "member")
        .await
        .unwrap();
    assert!(
        !super::super::may_deliver_metadata(
            &state,
            &member.session_id,
            PacketId::ChannelCreate,
            &to_payload(&creation)
        )
        .await
    );
}

#[tokio::test]
async fn queued_targeted_history_is_rechecked_after_leave_or_guild_revoke() {
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    let (state, sid) = fixture().await;
    let crypto = SessionCrypto::derive(&[7; 32], &sid);
    let history = |channel: &str| BroadcastMsg {
        channel_id: Some(channel.into()),
        exclude_session: None,
        target_session_id: Some(sid.clone()),
        data: encode_packet(
            PacketId::ChatHistory,
            0,
            &to_payload(&ChatHistoryPayload {
                channel_id: channel.into(),
                messages: vec![],
            }),
        ),
    };
    // The same queued target/channel envelope is deliverable while subscribed.
    let (mut stream, mut peer) = tokio::io::duplex(65536);
    let mut seq = 2;
    crate::handler::deliver::deliver_encrypted(
        &mut stream,
        &mut seq,
        &sid,
        &history("general"),
        &crypto,
        &state,
    )
    .await
    .unwrap();
    let mut first = [0u8; 12];
    peer.read_exact(&mut first).await.unwrap();
    assert_eq!(
        u16::from_be_bytes(first[..2].try_into().unwrap()),
        PacketId::ChatHistory as u16
    );
    assert_eq!(seq, 3);

    super::super::leave(&mut stream, &mut seq, &sid, "general", &crypto, &state)
        .await
        .unwrap();
    let (mut stream, mut peer) = tokio::io::duplex(65536);
    crate::handler::deliver::deliver_encrypted(
        &mut stream,
        &mut seq,
        &sid,
        &history("general"),
        &crypto,
        &state,
    )
    .await
    .unwrap();
    assert_eq!(
        seq, 3,
        "discarded history cannot consume an encryption sequence"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(15), peer.read_u8())
            .await
            .is_err()
    );

    let guild = state
        .storage
        .create_guild("owner", "Private history")
        .await
        .unwrap();
    state
        .storage
        .add_guild_member(&guild, "visitor")
        .await
        .unwrap();
    channels::create(
        &state.channels,
        "private-history",
        "Private",
        channels::ChannelKind::Text,
        Some(guild.clone()),
    )
    .await;
    attempt_join(&state, &sid, "private-history").await;
    let queued = history("private-history");
    {
        let _access = state.access.write().await;
        state
            .storage
            .remove_guild_member(&guild, "visitor")
            .await
            .unwrap();
        super::super::revoke_guild_access(&state, &guild, Some("visitor")).await;
    }
    let (mut stream, mut peer) = tokio::io::duplex(65536);
    crate::handler::deliver::deliver_encrypted(
        &mut stream,
        &mut seq,
        &sid,
        &queued,
        &crypto,
        &state,
    )
    .await
    .unwrap();
    assert_eq!(seq, 3);
    assert!(
        tokio::time::timeout(Duration::from_millis(15), peer.read_u8())
            .await
            .is_err(),
        "history queued before a guild kick must not be delivered afterwards"
    );
}
