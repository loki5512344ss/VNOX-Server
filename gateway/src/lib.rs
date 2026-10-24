pub mod admin;
pub mod bootstrap;
pub mod domain;
pub mod handler;
pub mod media;
pub mod net;
pub mod proto;
pub mod webhooks;

use anyhow::Result;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use domain::{channels, config, session, storage};
use net::state::{BroadcastMsg, State, VoiceMemberTx};
use proto::{PacketId, PresenceEventPayload, PresenceInfo, encode_packet, to_payload};

struct ConnGuard(Arc<AtomicUsize>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

pub async fn run(cfg: Arc<config::Config>, voice_member_tx: Option<VoiceMemberTx>) -> Result<()> {
    let private_mode = cfg.is_private();
    if private_mode {
        info!("private mode enabled, federation disabled");
    } else {
        info!("federation enabled");
    }
    info!(
        "VNOX Gateway — node: {} addr: {} bind: {}",
        cfg.node.name, cfg.node.address, cfg.gateway.bind
    );
    let max_connections = cfg.gateway.max_connections;
    let conn_count = Arc::new(AtomicUsize::new(0));
    if let Some(limit) = max_connections {
        info!("max_connections configured: {limit}");
    }
    let storage = match cfg.storage.backend.as_deref().unwrap_or("sqlite") {
        "postgres" => {
            let url = cfg
                .storage
                .postgres_url
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("postgres_url required for postgres backend"))?;
            storage::Storage::connect_postgres(url).await?
        }
        _ => {
            let sqlite = cfg
                .storage
                .sqlite_path
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| "./dev/data/vnox.db".into());
            storage::Storage::connect_sqlite(&sqlite).await?
        }
    };

    let server_identity = Arc::new(
        bootstrap::server_identity::ServerIdentity::load_or_generate(&cfg.storage.data_dir)?,
    );
    let server_pubkey = server_identity.pubkey_hex();
    info!(
        "server identity: {}…",
        &server_pubkey[..8.min(server_pubkey.len())]
    );

    let (tx, _) = broadcast::channel(256);
    let metrics = admin::metrics::Metrics::new();
    let sessions_count = Arc::new(AtomicUsize::new(0));
    let channels_count = Arc::new(AtomicUsize::new(0));
    let state = State::new(
        session::new_store(),
        channels::new_store(),
        Arc::new(storage),
        cfg.clone(),
        server_identity,
        tx,
        metrics.clone(),
        sessions_count.clone(),
        channels_count.clone(),
        voice_member_tx,
    );

    state
        .storage
        .load_channels_to_cache(&state.channels)
        .await?;
    state.webhooks.configure_from_env()?;
    tokio::spawn(webhooks::outgoing::run(state.clone()));

    if let Ok(rows) = state.storage.load_all_presences().await {
        let mut presences = state.presences.write().await;
        for row in rows {
            presences.insert(
                row.user_id.clone(),
                PresenceInfo {
                    user_id: row.user_id,
                    nickname: row.nickname,
                    status: row.status,
                    activity_type: row.activity_type,
                    activity_text: row.activity_text,
                },
            );
        }
        info!("loaded {} presences from storage", presences.len());
    }

    let admin_bind = cfg
        .gateway
        .admin_bind
        .clone()
        .unwrap_or_else(|| "0.0.0.0:7601".to_string());
    let admin_state = admin::AdminState {
        started_at: std::time::Instant::now(),
        node_name: cfg.node.name.clone(),
        node_address: cfg.node.address.clone(),
        private_mode,
        metrics: metrics.clone(),
        sessions_count,
        channels_count,
    };
    tokio::spawn(admin::run(admin_bind, admin_state, state.clone()));

    let listener = TcpListener::bind(&cfg.gateway.bind).await?;
    info!("listening on {}", cfg.gateway.bind);

    if cfg.gateway.tls_enabled {
        run_tls(listener, cfg, state, max_connections, conn_count).await
    } else {
        run_plain(listener, state, max_connections, conn_count).await
    }
}

async fn run_tls(
    listener: TcpListener,
    cfg: Arc<config::Config>,
    state: State,
    max_connections: Option<usize>,
    conn_count: Arc<AtomicUsize>,
) -> Result<()> {
    let (certs, key) = load_or_generate_tls_certs(&cfg.gateway)?;
    if cfg.gateway.tls_cert_path.is_none() {
        warn!("using self-signed TLS certificate — clients must accept it manually");
    }
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let current = conn_count.load(std::sync::atomic::Ordering::Relaxed);
                if let Some(limit) = max_connections
                    && current >= limit
                {
                    warn!("connection rejected from {addr}: at max_connections ({limit})");
                    drop(stream);
                    continue;
                }
                conn_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                info!("connection from {addr} (TLS)");
                state.metrics.inc(&state.metrics.connections_total);
                let s = state.clone();
                let acceptor = acceptor.clone();
                let conn_count_clone = conn_count.clone();
                tokio::spawn(async move {
                    let _guard = ConnGuard(conn_count_clone);
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            if let Err(e) = handle(tls_stream, addr, s).await {
                                debug!("{addr} closed: {e}");
                            }
                        }
                        Err(e) => error!("TLS accept error from {addr}: {e}"),
                    }
                });
            }
            Err(e) => error!("accept: {e}"),
        }
    }
}

async fn run_plain(
    listener: TcpListener,
    state: State,
    max_connections: Option<usize>,
    conn_count: Arc<AtomicUsize>,
) -> Result<()> {
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let current = conn_count.load(std::sync::atomic::Ordering::Relaxed);
                if let Some(limit) = max_connections
                    && current >= limit
                {
                    warn!("connection rejected from {addr}: at max_connections ({limit})");
                    drop(stream);
                    continue;
                }
                conn_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                info!("connection from {addr}");
                state.metrics.inc(&state.metrics.connections_total);
                let s = state.clone();
                let conn_count_clone = conn_count.clone();
                tokio::spawn(async move {
                    let _guard = ConnGuard(conn_count_clone);
                    if let Err(e) = handle(stream, addr, s).await {
                        debug!("{addr} closed: {e}");
                    }
                });
            }
            Err(e) => error!("accept: {e}"),
        }
    }
}

async fn handle<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut stream: S,
    addr: std::net::SocketAddr,
    state: State,
) -> Result<()> {
    let mut seq = 0u32;
    let (sess, crypto) = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        net::handshake::run(&mut stream, addr, &state, &mut seq),
    )
    .await??;
    let sid = sess.session_id.clone();
    state
        .sessions_count
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut bcast_rx = state.broadcast.subscribe();

    let result = handler::run_session(
        &mut stream,
        addr,
        &mut seq,
        &sid,
        &crypto,
        &state,
        &mut bcast_rx,
    )
    .await;
    if result.is_err() {
        let p = proto::DisconnectPayload {
            reason: "session closed".into(),
        };
        let _ = net::io::send_encrypted(
            &mut stream,
            proto::PacketId::Disconnect,
            &mut seq,
            &proto::to_payload(&p),
            &crypto,
        )
        .await;
    }

    let user_id = session::get(&state.sessions, &sid)
        .await
        .map(|s| s.user_id.clone());

    if let Some(ref uid) = user_id {
        state.presences.write().await.insert(
            uid.clone(),
            PresenceInfo {
                user_id: uid.clone(),
                nickname: String::new(),
                status: "OFFLINE".into(),
                activity_type: None,
                activity_text: None,
            },
        );
        let _ = state
            .storage
            .save_presence(uid, "", "OFFLINE", None, None)
            .await;
        let event = PresenceEventPayload {
            user_id: uid.clone(),
            nickname: String::new(),
            status: "OFFLINE".into(),
            activity_type: None,
            activity_text: None,
        };
        let _ = state.broadcast.send(BroadcastMsg {
            channel_id: None,
            exclude_session: Some(sid.clone()),
            target_session_id: None,
            data: encode_packet(PacketId::PresenceEvent, 0, &to_payload(&event)),
        });
    }

    if let Some(sess) = session::get(&state.sessions, &sid).await {
        for ch in [sess.channel_id, sess.voice_channel_id]
            .into_iter()
            .flatten()
        {
            let is_voice = channels::get_channel(&state.channels, &ch)
                .await
                .is_some_and(|c| c.kind == channels::ChannelKind::Voice);
            channels::leave(&state.channels, &ch, &sid).await;
            handler::channel::broadcast_leave(&state, &ch, &sid).await;
            if is_voice
                && let Some(tx) = &state.voice_member_tx
                && let Some(ref uid) = user_id
            {
                let _ = tx.send(
                    serde_json::json!({"type":"leave","session_id":sid,"channel_id":ch,"user_id":uid}).to_string(),
                );
            }
        }
    }
    state.media.revoke(&state, &sid).await;
    session::remove(&state.sessions, &sid).await;
    state
        .sessions_count
        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    state.rate_limiter.remove(&sid);
    debug!("{addr} cleaned up");
    result
}

fn load_or_generate_tls_certs(
    cfg: &config::GatewayConfig,
) -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    match (&cfg.tls_cert_path, &cfg.tls_key_path) {
        (Some(cert_path), Some(key_path)) => {
            let cert_pem = std::fs::read_to_string(cert_path)?;
            let key_pem = std::fs::read_to_string(key_path)?;
            let cert = CertificateDer::from_pem_reader(&mut cert_pem.as_bytes())?;
            let key = PrivateKeyDer::from_pem_reader(&mut key_pem.as_bytes())?;
            Ok((vec![cert], key))
        }
        _ => {
            info!("No TLS cert/key configured, generating self-signed certificate");
            let certified_key = rcgen::generate_simple_self_signed(vec!["VNOX Server".into()])?;
            let cert_der = certified_key.cert.der().clone();
            let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
                certified_key.signing_key.serialize_der(),
            ));
            Ok((vec![cert_der], key_der))
        }
    }
}
