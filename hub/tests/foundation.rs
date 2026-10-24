use std::{collections::HashMap, sync::Arc, time::Instant};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tempfile::TempDir;
use tower::ServiceExt;
use vnox_hub::{
    config::Config,
    database,
    identity::Issuer,
    web::{self, HubState},
};

fn private_directory() -> TempDir {
    let directory = TempDir::new().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    directory
}

fn config(values: &[(&str, &str)]) -> anyhow::Result<Config> {
    let values = values
        .iter()
        .map(|(key, value)| (*key, *value))
        .collect::<HashMap<_, _>>();
    Config::from_lookup(|key| values.get(key).map(|value| (*value).to_owned()))
}

#[test]
fn rejects_public_binding_and_untrusted_origins() {
    assert!(config(&[("HUB_BIND", "0.0.0.0:18000")]).is_err());
    for origin in [
        "http://central.example",
        "https://a.example/path",
        "https://a.example?token=x",
        "https://user:secret@a.example",
        "https://a.example/#fragment",
    ] {
        assert!(config(&[("PUBLIC_BASE_URL", origin)]).is_err(), "{origin}");
    }
    assert!(config(&[("PUBLIC_BASE_URL", "https://central.example")]).is_ok());
}

#[test]
fn rejects_incomplete_smtp_config_instead_of_silently_disabling_mail() {
    assert!(config(&[("SMTP_PASSWORD", "not-a-real-secret")]).is_err());
    assert!(config(&[("SMTP_HOST", "smtp.example"), ("SMTP_USER", "test")]).is_err());
    assert!(config(&[("SMTP_HOST", "smtp.example"), ("SMTP_PORT", "0")]).is_err());
    assert!(config(&[("SMTP_HOST", "smtp://smtp.example")]).is_err());
}

#[test]
fn issuer_identity_is_stable_and_private() {
    let directory = private_directory();
    let first = Issuer::load_or_create(directory.path()).unwrap();
    let second = Issuer::load_or_create(directory.path()).unwrap();
    assert_eq!(first.id, second.id);
    assert_eq!(first.public_key, second.public_key);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = directory.path().join("issuer.json");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Issuer::load_or_create(directory.path()).is_err());
    }
}

#[test]
fn corrupt_identity_does_not_get_replaced_with_a_new_issuer() {
    let directory = private_directory();
    let issuer = Issuer::load_or_create(directory.path()).unwrap();
    let path = directory.path().join("issuer.json");
    let original = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, original.replace(&issuer.public_key, &"0".repeat(64))).unwrap();
    assert!(Issuer::load_or_create(directory.path()).is_err());
    assert!(
        std::fs::read_to_string(path)
            .unwrap()
            .contains(&"0".repeat(64))
    );
}

async fn state() -> (TempDir, Arc<HubState>) {
    let directory = private_directory();
    let issuer = Issuer::load_or_create(directory.path()).unwrap();
    let pool = database::open(directory.path(), &issuer).await.unwrap();
    (
        directory,
        Arc::new(HubState {
            auth: Arc::new(
                vnox_hub::auth::AuthService::new(
                    pool.clone(),
                    url::Url::parse("https://central.loki-code.dev").unwrap(),
                    None,
                )
                .unwrap(),
            ),
            database: pool,
            issuer,
            smtp_configured: true,
            started: Instant::now(),
        }),
    )
}

#[tokio::test]
async fn database_migrations_persist_and_refuse_a_different_issuer() {
    let (directory, state) = state().await;
    let tables: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('accounts','devices','servers')")
        .fetch_one(&state.database).await.unwrap();
    assert_eq!(tables, 3);
    state.database.close().await;
    let pool = database::open(directory.path(), &state.issuer)
        .await
        .unwrap();
    pool.close().await;
    let other_dir = private_directory();
    let other = Issuer::load_or_create(other_dir.path()).unwrap();
    assert!(database::open(directory.path(), &other).await.is_err());
}

#[tokio::test]
async fn readiness_reflects_database_failure() {
    let (_directory, state) = state().await;
    let app = web::router(state.clone());
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    state.database.close().await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn capabilities_and_routes_do_not_pretend_authentication_is_ready() {
    let (_directory, state) = state().await;
    let app = web::router(state);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/info")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body = axum::body::to_bytes(response.into_body(), 8192)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    for capability in [
        "email_auth",
        "github_auth",
        "server_registry",
        "friends",
        "direct_messages",
        "marketplace",
    ] {
        assert_eq!(value["capabilities"][capability], "not_enabled");
    }
    assert_eq!(value["smtp"]["public_send_endpoint"], false);
    assert!(value.get("secret_key").is_none());
    // Email sign-in exists but stays closed until SMTP is configured; there is still no
    // route that sends arbitrary mail.
    for path in ["/v1/auth/email/start", "/v1/auth/email/verify"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
    for path in ["/v1/servers/register", "/v1/mail/send"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[cfg(unix)]
#[test]
fn refuses_a_world_readable_data_directory() {
    use std::os::unix::fs::PermissionsExt;
    let directory = private_directory();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Issuer::load_or_create(directory.path()).is_err());
    assert!(!directory.path().join("issuer.json").exists());
}
