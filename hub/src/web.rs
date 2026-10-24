use std::{sync::Arc, time::Instant};

use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::{HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{Html, Response},
    routing::get,
};
use serde_json::{Value, json};
use sqlx::SqlitePool;

use crate::identity::Issuer;

pub struct HubState {
    pub database: SqlitePool,
    pub auth: Arc<crate::auth::AuthService>,
    pub issuer: Issuer,
    pub smtp_configured: bool,
    pub started: Instant,
}

pub fn router(state: Arc<HubState>) -> Router {
    Router::new()
        .merge(crate::auth::router())
        .route("/", get(index))
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/version", get(version))
        .route("/v1/info", get(info))
        .route("/assets/vnox-mark.svg", get(logo))
        .route("/assets/vnox-mark.png", get(logo_png))
        .fallback(|| async { (StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))) })
        .layer(middleware::from_fn(headers))
        .with_state(state)
}

async fn health() -> Json<Value> {
    Json(json!({"status": "ok", "service": "vnox-hub"}))
}

async fn ready(State(state): State<Arc<HubState>>) -> (StatusCode, Json<Value>) {
    match sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(&state.database)
        .await
    {
        Ok(1) => (
            StatusCode::OK,
            Json(json!({"status": "ready", "database": "ready", "issuer": "loaded"})),
        ),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "not_ready"})),
        ),
    }
}

async fn version() -> Json<Value> {
    Json(json!({
        "service": "vnox-hub",
        "version": env!("CARGO_PKG_VERSION"),
        "api_version": 1,
        "stage": "foundation"
    }))
}

async fn info(State(state): State<Arc<HubState>>) -> Json<Value> {
    Json(json!({
        "service": "vnox-hub",
        "stage": "foundation",
        "issuer_id": state.issuer.id,
        "issuer_public_key": state.issuer.public_key,
        "uptime_seconds": state.started.elapsed().as_secs(),
        "smtp": {"configured": state.smtp_configured, "public_send_endpoint": false},
        "capabilities": {
            "email_auth": if state.auth.email_enabled() { "enabled" } else { "not_enabled" },
            "github_auth": if state.auth.configured() { "enabled" } else { "not_enabled" },
            "server_registry": "not_enabled",
            "friends": "not_enabled",
            "direct_messages": "not_enabled",
            "marketplace": "not_enabled"
        },
        "retention_plan": {"dm_days": 7, "attachment_days": 4, "attachment_max_bytes": 20000000}
    }))
}

async fn logo() -> ([(&'static str, &'static str); 1], &'static str) {
    (
        [("content-type", "image/svg+xml; charset=utf-8")],
        include_str!("../assets/vnox-mark.svg"),
    )
}

async fn logo_png() -> ([(&'static str, &'static str); 1], &'static [u8]) {
    (
        [("content-type", "image/png")],
        include_bytes!("../assets/vnox-mark.png"),
    )
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../assets/index.html"))
}

async fn headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    // Handlers that set their own cache policy or CSP (avatar delivery) keep them.
    for (name, value) in [
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        (
            "content-security-policy",
            "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; frame-ancestors 'none'",
        ),
    ] {
        let present = response.headers().contains_key(name);
        if present && matches!(name, "cache-control" | "content-security-policy") {
            continue;
        }
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
    response
}
