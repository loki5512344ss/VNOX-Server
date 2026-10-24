//! HTTP admin server — exposes `/health` and `/metrics` endpoints.
//!
//! Runs on a separate TCP port (default 7601) so it does not interfere
//! with the LNEx control plane on 7600. All endpoints are unauthenticated
//! and intended for orchestrators (k8s liveness probes, Prometheus scrapers).

use std::sync::Arc;
use std::time::Instant;

use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::admin::metrics::Metrics;

pub mod metrics;

#[derive(Clone)]
pub struct AdminState {
    pub started_at: Instant,
    pub node_name: String,
    pub node_address: String,
    pub private_mode: bool,
    pub metrics: Arc<Metrics>,
    pub sessions_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    pub channels_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

pub async fn run(bind: String, state: AdminState, gateway: crate::net::state::State) {
    let app = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/version", get(version))
        .with_state(state)
        .merge(crate::webhooks::incoming::router(gateway));

    let listener = match TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            error!("admin server failed to bind {bind}: {e}");
            return;
        }
    };
    info!("admin HTTP listening on {bind}");
    if let Err(e) = axum::serve(listener, app).await {
        error!("admin server: {e}");
    }
}

async fn health(State(s): State<AdminState>) -> impl IntoResponse {
    let uptime = s.started_at.elapsed().as_secs();
    let body = serde_json::json!({
        "status": "ok",
        "uptime_seconds": uptime,
        "node": s.node_name,
        "address": s.node_address,
        "private_mode": s.private_mode,
    });
    (StatusCode::OK, axum::Json(body))
}

async fn version(State(_s): State<AdminState>) -> impl IntoResponse {
    let body = serde_json::json!({
        "name": "vnox-gateway",
        "version": env!("CARGO_PKG_VERSION"),
        "lnex_version": "1",
    });
    (StatusCode::OK, axum::Json(body))
}

async fn metrics(State(s): State<AdminState>) -> impl IntoResponse {
    let body = s.metrics.render_prometheus(&s);
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
}
