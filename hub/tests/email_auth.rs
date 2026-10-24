//! Email one-time-code sign-in. Delivery is replaced by an in-memory recorder: no SMTP
//! connection is opened and no message ever leaves the process.

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, Response, StatusCode},
};
use serde_json::{Value, json};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};
use tower::ServiceExt;
use vnox_hub::{
    auth::{
        self,
        email::{CodeSender, EmailAuth, EmailLimits},
        provider::GitHubProfile,
        store,
    },
    database,
    identity::Issuer,
    mail::templates::Email,
    web::{self, HubState},
};

const ORIGIN: &str = "https://central.loki-code.dev";

#[derive(Default)]
struct Recorder {
    sent: Mutex<Vec<(String, Email)>>,
    fail: bool,
}
impl CodeSender for Recorder {
    fn send<'a>(
        &'a self,
        recipient: &'a str,
        email: Email,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            if self.fail {
                anyhow::bail!("simulated outage");
            }
            self.sent
                .lock()
                .unwrap()
                .push((recipient.to_owned(), email));
            Ok(())
        })
    }
}
impl Recorder {
    fn last_code(&self) -> String {
        let sent = self.sent.lock().unwrap();
        let text = &sent.last().expect("a message was recorded").1.text;
        let digits: Vec<&str> = text
            .split(|c: char| !c.is_ascii_digit())
            .filter(|part| part.len() == 8)
            .collect();
        assert_eq!(digits.len(), 1, "exactly one code in the message");
        digits[0].to_owned()
    }
    fn count(&self) -> usize {
        self.sent.lock().unwrap().len()
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    state: Arc<HubState>,
    app: Router,
    mail: Arc<Recorder>,
}

async fn harness_with(limits: EmailLimits, fail: bool, enabled: bool) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let issuer = Issuer::load_or_create(dir.path()).unwrap();
    let pool = database::open(dir.path(), &issuer).await.unwrap();
    let mail = Arc::new(Recorder {
        fail,
        ..Default::default()
    });
    let mut auth =
        auth::AuthService::with_provider(pool.clone(), url::Url::parse(ORIGIN).unwrap(), None);
    if enabled {
        let mut email = EmailAuth::new([42; 32], mail.clone());
        email.limits = limits;
        auth = auth.with_email(email);
    }
    let state = Arc::new(HubState {
        database: pool,
        auth: Arc::new(auth),
        issuer,
        smtp_configured: enabled,
        started: std::time::Instant::now(),
    });
    Harness {
        _dir: dir,
        app: web::router(state.clone()),
        state,
        mail,
    }
}

fn relaxed() -> EmailLimits {
    EmailLimits {
        address_cooldown: 0,
        per_address_hour: 1000,
        per_source_hour: 1000,
        global_hour: 1000,
    }
}

async fn harness() -> Harness {
    harness_with(relaxed(), false, true).await
}

struct Post<'a> {
    path: &'a str,
    body: Value,
    cookie: Option<&'a str>,
    origin: Option<&'a str>,
    ip: &'a str,
}
fn post<'a>(path: &'a str, body: Value) -> Post<'a> {
    Post {
        path,
        body,
        cookie: None,
        origin: Some(ORIGIN),
        ip: "198.51.100.7",
    }
}
impl Post<'_> {
    fn request(&self) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri(self.path)
            .header("content-type", "application/json")
            .header("x-forwarded-for", self.ip);
        if let Some(origin) = self.origin {
            builder = builder.header("origin", origin);
        }
        if let Some(cookie) = self.cookie {
            builder = builder.header("cookie", cookie);
        }
        builder.body(Body::from(self.body.to_string())).unwrap()
    }
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, Vec<String>, String) {
    let response: Response<Body> = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let cookies = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect();
    let body = String::from_utf8(
        to_bytes(response.into_body(), 65536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    (status, cookies, body)
}

fn pair(cookies: &[String], name: &str) -> String {
    cookies
        .iter()
        .find(|c| c.starts_with(&format!("{name}=")))
        .unwrap_or_else(|| panic!("{name} cookie missing"))
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

/// Requests a code; returns the browser-binding cookie pair.
async fn start(h: &Harness, email: &str) -> String {
    let (status, cookies, _) = send(
        &h.app,
        post("/v1/auth/email/start", json!({"email": email})).request(),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    pair(&cookies, "__Host-vnox_email")
}

async fn verify(
    h: &Harness,
    cookie: Option<&str>,
    email: &str,
    code: &str,
) -> (StatusCode, Vec<String>, String) {
    let mut request = post(
        "/v1/auth/email/verify",
        json!({"email": email, "code": code}),
    );
    request.cookie = cookie;
    send(&h.app, request.request()).await
}

#[tokio::test]
async fn full_flow_creates_neutral_account_and_session() {
    let h = harness().await;
    let (status, cookies, body) = send(
        &h.app,
        post(
            "/v1/auth/email/start",
            json!({"email": "  Alice.Secret@Example.COM "}),
        )
        .request(),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let browser_cookie = cookies
        .iter()
        .find(|c| c.starts_with("__Host-vnox_email="))
        .unwrap();
    for attribute in [
        "Secure",
        "HttpOnly",
        "SameSite=Lax",
        "Path=/",
        "Max-Age=600",
    ] {
        assert!(browser_cookie.contains(attribute), "{attribute}");
    }
    assert!(!browser_cookie.contains("Domain"));
    let browser = pair(&cookies, "__Host-vnox_email");
    let code = h.mail.last_code();
    // The code reaches the user only by mail, never in any part of the HTTP response.
    assert!(!body.contains(&code));
    assert!(!cookies.iter().any(|c| c.contains(&code)));
    {
        let sent = h.mail.sent.lock().unwrap();
        assert_eq!(sent[0].0, "alice.secret@example.com");
        // Only the bare site origin appears (footer); no link carries a path, query or code.
        let html = &sent[0].1.html;
        assert_eq!(html.matches("href=\"").count(), 1);
        assert!(html.contains(&format!("href=\"{ORIGIN}\"")));
        for url in sent[0]
            .1
            .text
            .split_whitespace()
            .filter(|w| w.starts_with("http"))
        {
            assert_eq!(url, ORIGIN);
        }
        assert!(!html.contains(&format!("{ORIGIN}/")) || html.contains("/assets/vnox-mark.png"));
    }
    // Only keyed MACs are stored.
    let row: (String, String) = sqlx::query_as("SELECT email_mac,code_mac FROM email_attempts")
        .fetch_one(&h.state.database)
        .await
        .unwrap();
    assert_ne!(row.1, store::hash(&code));
    assert_ne!(row.1, code);
    assert!(!row.0.contains("alice"));
    let (status, cookies, body) =
        verify(&h, Some(&browser), "alice.secret@example.com ", &code).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let session_cookie = cookies
        .iter()
        .find(|c| c.starts_with("__Host-vnox_session="))
        .unwrap();
    for attribute in [
        "Secure",
        "HttpOnly",
        "SameSite=Lax",
        "Path=/",
        "Max-Age=604800",
    ] {
        assert!(session_cookie.contains(attribute), "{attribute}");
    }
    let json: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["authenticated"], true);
    assert_eq!(json["user"]["display_name"], "Vnox user");
    let handle = json["user"]["handle"].as_str().unwrap();
    assert!(handle.starts_with("u_") && !handle.contains("alice"));
    assert!(!body.to_lowercase().contains("alice"));
    assert!(!json["csrf_token"].as_str().unwrap().is_empty());
    // The same session endpoint now reports the user, with the same format.
    let (status, _, session_body) = send(
        &h.app,
        Request::builder()
            .uri("/v1/auth/session")
            .header("cookie", pair(&cookies, "__Host-vnox_session"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let session: Value = serde_json::from_str(&session_body).unwrap();
    assert_eq!(session, json);
    let identity: (String, String) =
        sqlx::query_as("SELECT provider,subject FROM external_identities")
            .fetch_one(&h.state.database)
            .await
            .unwrap();
    assert_eq!(
        identity,
        ("email".into(), "alice.secret@example.com".into())
    );
    let ttl: i64 = sqlx::query_scalar("SELECT expires_at-created_at FROM web_sessions")
        .fetch_one(&h.state.database)
        .await
        .unwrap();
    assert_eq!(ttl, 7 * 24 * 60 * 60);
    // Same address signs in again to the same account.
    let again = start(&h, "ALICE.secret@example.com").await;
    let code = h.mail.last_code();
    let (_, _, body) = verify(&h, Some(&again), "alice.secret@example.com", &code).await;
    let second: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(second["user"]["user_id"], json["user"]["user_id"]);
}

#[tokio::test]
async fn wrong_code_is_rejected_and_attempts_are_exhausted() {
    let h = harness().await;
    let browser = start(&h, "a@example.com").await;
    let code = h.mail.last_code();
    let wrong = if code == "00000000" {
        "11111111"
    } else {
        "00000000"
    };
    for _ in 0..4 {
        let (status, cookies, body) = verify(&h, Some(&browser), "a@example.com", wrong).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid_code"));
        assert!(!cookies.iter().any(|c| c.starts_with("__Host-vnox_session")));
    }
    // The fifth try uses the last allowed attempt; a wrong guess burns it ...
    let (status, ..) = verify(&h, Some(&browser), "a@example.com", wrong).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // ... so even the correct code is now refused, with the same answer.
    let (status, _, body) = verify(&h, Some(&browser), "a@example.com", &code).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("invalid_code"));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM accounts")
            .fetch_one(&h.state.database)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn correct_code_still_works_after_some_failures() {
    let h = harness().await;
    let browser = start(&h, "a@example.com").await;
    let code = h.mail.last_code();
    let wrong = if code == "00000000" {
        "11111111"
    } else {
        "00000000"
    };
    for _ in 0..4 {
        verify(&h, Some(&browser), "a@example.com", wrong).await;
    }
    let (status, ..) = verify(&h, Some(&browser), "a@example.com", &code).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn code_is_single_use_and_wrong_address_does_not_pass() {
    let h = harness().await;
    let browser = start(&h, "a@example.com").await;
    let code = h.mail.last_code();
    let (status, ..) = verify(&h, Some(&browser), "other@example.com", &code).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, ..) = verify(&h, Some(&browser), "a@example.com", &code).await;
    assert_eq!(status, StatusCode::OK);
    let (status, ..) = verify(&h, Some(&browser), "a@example.com", &code).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "replay");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM email_attempts")
            .fetch_one(&h.state.database)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn parallel_redemption_of_one_code_has_exactly_one_winner() {
    let h = harness().await;
    let browser = start(&h, "a@example.com").await;
    let code = h.mail.last_code();
    let results = futures_join(
        (0..4)
            .map(|_| {
                let app = h.app.clone();
                let browser = browser.clone();
                let code = code.clone();
                tokio::spawn(async move {
                    let mut request = post(
                        "/v1/auth/email/verify",
                        json!({"email": "a@example.com", "code": code}),
                    );
                    request.cookie = Some(&browser);
                    send(&app, request.request()).await.0
                })
            })
            .collect(),
    )
    .await;
    assert_eq!(results.iter().filter(|s| **s == StatusCode::OK).count(), 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM accounts")
            .fetch_one(&h.state.database)
            .await
            .unwrap(),
        1
    );
}

async fn futures_join(handles: Vec<tokio::task::JoinHandle<StatusCode>>) -> Vec<StatusCode> {
    let mut out = Vec::new();
    for handle in handles {
        out.push(handle.await.unwrap());
    }
    out
}

#[tokio::test]
async fn expired_code_is_rejected() {
    let h = harness().await;
    let browser = start(&h, "a@example.com").await;
    let code = h.mail.last_code();
    sqlx::query("UPDATE email_attempts SET expires_at=0")
        .execute(&h.state.database)
        .await
        .unwrap();
    let (status, ..) = verify(&h, Some(&browser), "a@example.com", &code).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn code_is_bound_to_the_requesting_browser() {
    let h = harness().await;
    let browser = start(&h, "a@example.com").await;
    let code = h.mail.last_code();
    let stranger = format!("__Host-vnox_email={}", "ab".repeat(32));
    assert_eq!(
        verify(&h, None, "a@example.com", &code).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        verify(&h, Some(&stranger), "a@example.com", &code).await.0,
        StatusCode::BAD_REQUEST
    );
    // Strangers neither consumed the code nor spent its tries.
    assert_eq!(
        verify(&h, Some(&browser), "a@example.com", &code).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn resend_replaces_the_previous_code_of_that_browser() {
    let h = harness().await;
    let first_browser = start(&h, "a@example.com").await;
    let first = h.mail.last_code();
    let mut request = post("/v1/auth/email/start", json!({"email": "a@example.com"}));
    request.cookie = Some(&first_browser);
    let (status, cookies, _) = send(&h.app, request.request()).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let second_browser = pair(&cookies, "__Host-vnox_email");
    let second = h.mail.last_code();
    assert_eq!(h.mail.count(), 2);
    if first != second {
        assert_eq!(
            verify(&h, Some(&first_browser), "a@example.com", &first)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        verify(&h, Some(&second_browser), "a@example.com", &second)
            .await
            .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn start_responds_identically_for_existing_and_new_addresses() {
    let h = harness().await;
    let browser = start(&h, "known@example.com").await;
    let code = h.mail.last_code();
    assert_eq!(
        verify(&h, Some(&browser), "known@example.com", &code)
            .await
            .0,
        StatusCode::OK
    );
    let mut shapes = Vec::new();
    for address in ["known@example.com", "stranger@example.com"] {
        let (status, cookies, body) = send(
            &h.app,
            post("/v1/auth/email/start", json!({"email": address})).request(),
        )
        .await;
        let attributes: Vec<String> = cookies
            .iter()
            .map(|c| c.split_once('=').unwrap().0.to_owned() + &c[c.find(';').unwrap()..])
            .collect();
        shapes.push((status, body, attributes));
    }
    assert_eq!(shapes[0], shapes[1]);
    assert_eq!(shapes[0].0, StatusCode::ACCEPTED);
    // Both addresses really did receive a code message.
    assert_eq!(h.mail.count(), 3);
}

#[tokio::test]
async fn start_rejects_bad_addresses_and_cross_site_or_malformed_requests() {
    let h = harness().await;
    for bad in [
        "",
        "no-at",
        "a@b",
        "a b@example.com",
        "x@y.com\r\nBcc: z@y.com",
    ] {
        let (status, cookies, body) = send(
            &h.app,
            post("/v1/auth/email/start", json!({"email": bad})).request(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid_email"));
        assert!(cookies.is_empty());
    }
    let mut request = post("/v1/auth/email/start", json!({"email": "a@example.com"}));
    request.origin = None;
    assert_eq!(
        send(&h.app, request.request()).await.0,
        StatusCode::FORBIDDEN
    );
    let mut request = post("/v1/auth/email/start", json!({"email": "a@example.com"}));
    request.origin = Some("https://evil.example");
    assert_eq!(
        send(&h.app, request.request()).await.0,
        StatusCode::FORBIDDEN
    );
    let mut request = post(
        "/v1/auth/email/verify",
        json!({"email": "a@example.com", "code": "12345678"}),
    );
    request.origin = Some("https://evil.example");
    assert_eq!(
        send(&h.app, request.request()).await.0,
        StatusCode::FORBIDDEN
    );
    // Form posts, unknown fields and oversized bodies never reach the handler logic.
    let form = Request::builder()
        .method("POST")
        .uri("/v1/auth/email/start")
        .header("origin", ORIGIN)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("email=a@example.com"))
        .unwrap();
    assert_eq!(send(&h.app, form).await.0, StatusCode::BAD_REQUEST);
    let extra = post(
        "/v1/auth/email/start",
        json!({"email": "a@example.com", "x": 1}),
    );
    assert_eq!(
        send(&h.app, extra.request()).await.0,
        StatusCode::BAD_REQUEST
    );
    let big = post("/v1/auth/email/start", json!({"email": "a".repeat(5000)}));
    assert_eq!(send(&h.app, big.request()).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(h.mail.count(), 0);
    // Malformed code shape is refused before touching any attempt.
    let browser = start(&h, "a@example.com").await;
    for bad in ["1234567", "123456789", "1234abcd", "１２３４５６７８"] {
        assert_eq!(
            verify(&h, Some(&browser), "a@example.com", bad).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    let failures: i64 = sqlx::query_scalar("SELECT failures FROM email_attempts")
        .fetch_one(&h.state.database)
        .await
        .unwrap();
    assert_eq!(failures, 0);
}

#[tokio::test]
async fn address_cooldown_and_hourly_limits() {
    let h = harness_with(EmailLimits::default(), false, true).await;
    start(&h, "a@example.com").await;
    let (status, ..) = send(
        &h.app,
        post("/v1/auth/email/start", json!({"email": "A@Example.com"})).request(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "cooldown applies to the normalized address"
    );
    assert_eq!(h.mail.count(), 1);
    // Hourly cap: pretend the earlier sends happened a few minutes ago.
    sqlx::query("UPDATE email_send_log SET sent_at=sent_at-120")
        .execute(&h.state.database)
        .await
        .unwrap();
    for i in 0..4 {
        let (status, ..) = send(
            &h.app,
            post("/v1/auth/email/start", json!({"email": "a@example.com"})).request(),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "send {i}");
        sqlx::query("UPDATE email_send_log SET sent_at=sent_at-120")
            .execute(&h.state.database)
            .await
            .unwrap();
    }
    let (status, ..) = send(
        &h.app,
        post("/v1/auth/email/start", json!({"email": "a@example.com"})).request(),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(h.mail.count(), 5);
}

#[tokio::test]
async fn source_and_global_limits() {
    let h = harness_with(
        EmailLimits {
            address_cooldown: 0,
            per_address_hour: 100,
            per_source_hour: 3,
            global_hour: 5,
        },
        false,
        true,
    )
    .await;
    let attempt = |i: usize, ip: &'static str| {
        let app = h.app.clone();
        async move {
            let mut request = post(
                "/v1/auth/email/start",
                json!({"email": format!("user{i}@example.com")}),
            );
            request.ip = ip;
            send(&app, request.request()).await.0
        }
    };
    for i in 0..3 {
        assert_eq!(attempt(i, "203.0.113.1").await, StatusCode::ACCEPTED);
    }
    assert_eq!(
        attempt(3, "203.0.113.1").await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(attempt(4, "203.0.113.2").await, StatusCode::ACCEPTED);
    assert_eq!(attempt(5, "203.0.113.2").await, StatusCode::ACCEPTED);
    assert_eq!(
        attempt(6, "203.0.113.3").await,
        StatusCode::TOO_MANY_REQUESTS,
        "global budget"
    );
    assert_eq!(h.mail.count(), 5);
}

#[tokio::test]
async fn source_hashes_not_addresses_are_ledgered() {
    let h = harness().await;
    start(&h, "private.person@example.com").await;
    let row: (String, String) = sqlx::query_as("SELECT email_mac,source_mac FROM email_send_log")
        .fetch_one(&h.state.database)
        .await
        .unwrap();
    assert!(!row.0.contains("private") && !row.1.contains("198.51"));
    assert_eq!(row.0.len(), 64);
}

#[tokio::test]
async fn delivery_failure_reports_unavailable_and_leaves_no_attempt() {
    let h = harness_with(relaxed(), true, true).await;
    let (status, cookies, _) = send(
        &h.app,
        post("/v1/auth/email/start", json!({"email": "a@example.com"})).request(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(cookies.is_empty());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM email_attempts")
            .fetch_one(&h.state.database)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn capability_follows_configuration_and_disabled_endpoints_refuse() {
    let enabled = harness().await;
    let disabled = harness_with(relaxed(), false, false).await;
    for (h, expected) in [(&enabled, "enabled"), (&disabled, "not_enabled")] {
        let (_, _, body) = send(
            &h.app,
            Request::builder()
                .uri("/v1/info")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let info: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(info["capabilities"]["email_auth"], expected);
        assert_eq!(info["smtp"]["public_send_endpoint"], false);
    }
    let (status, ..) = send(
        &disabled.app,
        post("/v1/auth/email/start", json!({"email": "a@example.com"})).request(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(disabled.mail.count(), 0);
}

#[tokio::test]
async fn email_never_merges_with_a_github_account() {
    let h = harness().await;
    let github = store::upsert_identity(
        &h.state.database,
        &GitHubProfile {
            id: 77,
            login: "same-person".into(),
            name: Some("Same Person".into()),
            avatar_url: None,
        },
    )
    .await
    .unwrap();
    let browser = start(&h, "same-person@example.com").await;
    let code = h.mail.last_code();
    let (_, _, body) = verify(&h, Some(&browser), "same-person@example.com", &code).await;
    let json: Value = serde_json::from_str(&body).unwrap();
    assert_ne!(json["user"]["user_id"].as_str().unwrap(), github.user_id);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM accounts")
            .fetch_one(&h.state.database)
            .await
            .unwrap(),
        2
    );
}

#[tokio::test]
async fn new_login_replaces_an_existing_session() {
    let h = harness().await;
    let user = store::upsert_email_identity(&h.state.database, "old@example.com")
        .await
        .unwrap();
    let (old, _) = store::create_session(&h.state.database, &user.user_id)
        .await
        .unwrap();
    let browser = start(&h, "new@example.com").await;
    let code = h.mail.last_code();
    let mut request = post(
        "/v1/auth/email/verify",
        json!({"email": "new@example.com", "code": code}),
    );
    let cookie = format!("{browser}; __Host-vnox_session={old}");
    request.cookie = Some(&cookie);
    assert_eq!(send(&h.app, request.request()).await.0, StatusCode::OK);
    assert!(
        store::get_session(&h.state.database, &old)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn expired_attempts_and_old_ledger_rows_are_pruned() {
    let h = harness().await;
    start(&h, "a@example.com").await;
    sqlx::query("UPDATE email_attempts SET expires_at=0")
        .execute(&h.state.database)
        .await
        .unwrap();
    sqlx::query("UPDATE email_send_log SET sent_at=0")
        .execute(&h.state.database)
        .await
        .unwrap();
    store::cleanup(&h.state.database).await.unwrap();
    for sql in [
        "SELECT COUNT(*) FROM email_attempts",
        "SELECT COUNT(*) FROM email_send_log",
    ] {
        let n: i64 = sqlx::query_scalar(sql)
            .fetch_one(&h.state.database)
            .await
            .unwrap();
        assert_eq!(n, 0, "{sql}");
    }
}
