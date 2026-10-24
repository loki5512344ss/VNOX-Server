use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use oauth2::{CsrfToken, PkceCodeChallenge};
use std::sync::Arc;
use tower::ServiceExt;
use vnox_hub::{
    auth::{
        self,
        provider::{GitHubProfile, IdentityProvider, ProviderError},
        store,
    },
    database,
    identity::Issuer,
    web::{self, HubState},
};
struct Fake;
impl IdentityProvider for Fake {
    fn authorize(&self, state: CsrfToken, _: PkceCodeChallenge) -> url::Url {
        let mut u = url::Url::parse("https://github.com/login/oauth/authorize").unwrap();
        u.query_pairs_mut().append_pair("state", state.secret());
        u
    }
    fn identify<'a>(
        &'a self,
        code: &'a str,
        verifier: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<GitHubProfile, ProviderError>> + Send + 'a>,
    > {
        Box::pin(async move {
            assert_eq!(code, "code");
            assert!(!verifier.is_empty());
            Ok(GitHubProfile {
                id: 123,
                login: "person".into(),
                name: Some("Person".into()),
                avatar_url: None,
            })
        })
    }
}
async fn setup(enabled: bool) -> (tempfile::TempDir, Arc<HubState>) {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let issuer = Issuer::load_or_create(dir.path()).unwrap();
    let pool = database::open(dir.path(), &issuer).await.unwrap();
    let auth = auth::AuthService::with_provider(
        pool.clone(),
        url::Url::parse("https://central.loki-code.dev").unwrap(),
        if enabled { Some(Arc::new(Fake)) } else { None },
    );
    (
        dir,
        Arc::new(HubState {
            database: pool,
            auth: Arc::new(auth),
            issuer,
            smtp_configured: false,
            started: std::time::Instant::now(),
        }),
    )
}
#[tokio::test]
async fn login_browser_binding_replay_session_and_csrf() {
    let (_dir, state) = setup(true).await;
    let app = web::router(state.clone());
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/auth/github/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let browser = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert!(
        response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("HttpOnly")
    );
    let redirect = url::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
    let csrf = redirect
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .to_string();
    let callback = format!("/v1/auth/github/callback?code=code&state={csrf}");
    let rejected = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&callback)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&callback)
                .header("cookie", &browser)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()["location"],
        "https://central.loki-code.dev/account"
    );
    let session = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .find(|v| v.to_str().unwrap().starts_with("__Host-vnox_session="))
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let replay = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&callback)
                .header("cookie", browser)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/auth/session")
                .header("cookie", &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(json["authenticated"], true);
    let rejected = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/logout")
                .header("cookie", &session)
                .header("origin", "https://central.loki-code.dev")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    let ok = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/logout")
                .header("cookie", &session)
                .header("origin", "https://central.loki-code.dev")
                .header("x-csrf-token", json["csrf_token"].as_str().unwrap())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM web_sessions")
            .fetch_one(&state.database)
            .await
            .unwrap(),
        0
    );
}
#[tokio::test]
async fn expired_attempt_and_identity_stability() {
    let (_dir, state) = setup(false).await;
    store::create_attempt(&state.database, "state", "browser", "verifier")
        .await
        .unwrap();
    assert!(
        store::consume_attempt(&state.database, "state", "wrong")
            .await
            .unwrap()
            .is_none()
    );
    sqlx::query("UPDATE oauth_attempts SET expires_at=0")
        .execute(&state.database)
        .await
        .unwrap();
    assert!(
        store::consume_attempt(&state.database, "state", "browser")
            .await
            .unwrap()
            .is_none()
    );
    let mut profile = GitHubProfile {
        id: 987,
        login: "old".into(),
        name: None,
        avatar_url: None,
    };
    let a = store::upsert_identity(&state.database, &profile)
        .await
        .unwrap();
    profile.login = "changed".into();
    let b = store::upsert_identity(&state.database, &profile)
        .await
        .unwrap();
    assert_eq!(a.user_id, b.user_id);
    let response = web::router(state)
        .oneshot(
            Request::builder()
                .uri("/v1/auth/github/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn blocked_login_ip_cannot_spend_other_visitors_global_budget() {
    let (_dir, state) = setup(false).await;
    for _ in 0..20 {
        assert!(state.auth.allow("192.0.2.1"));
    }
    for _ in 0..400 {
        assert!(!state.auth.allow("192.0.2.1"));
    }
    assert!(state.auth.allow("192.0.2.2"));
}

#[test]
fn production_provider_uses_fixed_callback_and_s256_without_repository_scopes() {
    let origin = url::Url::parse("https://central.loki-code.dev").unwrap();
    let provider = auth::provider::GitHubProvider::new(
        &auth::GitHubConfig {
            client_id: "public-fixture-id".into(),
            client_secret: "fixture-secret-not-real".into(),
        },
        &origin,
    )
    .unwrap();
    let (challenge, _) = PkceCodeChallenge::new_random_sha256();
    let target = provider.authorize(CsrfToken::new("fixture-state".into()), challenge);
    assert_eq!(target.host_str(), Some("github.com"));
    let pairs = target
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(
        pairs["redirect_uri"],
        "https://central.loki-code.dev/v1/auth/github/callback"
    );
    assert_eq!(pairs["code_challenge_method"], "S256");
    assert!(!pairs["code_challenge"].is_empty());
    assert_eq!(pairs["state"], "fixture-state");
    assert!(!pairs.contains_key("scope"));
    assert!(!target.as_str().contains("fixture-secret-not-real"));
}

#[tokio::test]
async fn persisted_session_is_hashed_and_expiry_is_enforced_without_cleanup() {
    let (_dir, state) = setup(false).await;
    let user = store::upsert_identity(
        &state.database,
        &GitHubProfile {
            id: 456,
            login: "fixture".into(),
            name: None,
            avatar_url: None,
        },
    )
    .await
    .unwrap();
    let (raw, _) = store::create_session(&state.database, &user.user_id)
        .await
        .unwrap();
    let persisted: String = sqlx::query_scalar("SELECT token_hash FROM web_sessions")
        .fetch_one(&state.database)
        .await
        .unwrap();
    assert_eq!(persisted, store::hash(&raw));
    assert_ne!(persisted, raw);
    assert!(
        store::get_session(&state.database, &raw)
            .await
            .unwrap()
            .is_some()
    );
    sqlx::query("UPDATE web_sessions SET expires_at=0")
        .execute(&state.database)
        .await
        .unwrap();
    assert!(
        store::get_session(&state.database, &raw)
            .await
            .unwrap()
            .is_none()
    );
}
