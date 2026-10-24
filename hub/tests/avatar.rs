use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, Response, StatusCode},
};
use image::{ExtendedColorType, ImageEncoder, RgbImage};
use std::sync::Arc;
use tower::ServiceExt;
use vnox_hub::{
    auth::{
        self,
        provider::GitHubProfile,
        store::{self, User},
    },
    database,
    identity::Issuer,
    web::{self, HubState},
};

const ORIGIN: &str = "https://central.loki-code.dev";
const GITHUB_AVATAR: &str = "https://avatars.githubusercontent.com/u/123?v=4";

struct Session {
    user: User,
    token: String,
    csrf: String,
}

struct Fixture {
    _dir: tempfile::TempDir,
    state: Arc<HubState>,
    app: Router,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let issuer = Issuer::load_or_create(dir.path()).unwrap();
    let pool = database::open(dir.path(), &issuer).await.unwrap();
    let auth = auth::AuthService::with_provider(pool.clone(), ORIGIN.parse().unwrap(), None);
    let state = Arc::new(HubState {
        database: pool,
        auth: Arc::new(auth),
        issuer,
        smtp_configured: false,
        started: std::time::Instant::now(),
    });
    Fixture {
        _dir: dir,
        app: web::router(state.clone()),
        state,
    }
}

impl Fixture {
    async fn email_user(&self, address: &str) -> Session {
        let user = store::upsert_email_identity(&self.state.database, address)
            .await
            .unwrap();
        self.session(user).await
    }
    async fn github_user(&self) -> Session {
        let profile = GitHubProfile {
            id: 123,
            login: "person".into(),
            name: Some("Person".into()),
            avatar_url: Some(GITHUB_AVATAR.into()),
        };
        let user = store::upsert_identity(&self.state.database, &profile)
            .await
            .unwrap();
        self.session(user).await
    }
    async fn session(&self, user: User) -> Session {
        let (token, csrf) = store::create_session(&self.state.database, &user.user_id)
            .await
            .unwrap();
        Session { user, token, csrf }
    }
    async fn send(&self, request: Request<Body>) -> Response<Body> {
        self.app.clone().oneshot(request).await.unwrap()
    }
    /// A well-formed request; callers override pieces to break it.
    fn change<'a>(
        &'a self,
        method: Method,
        session: Option<&Session>,
        csrf: Option<&str>,
        origin: Option<&str>,
        content_type: &str,
        body: Vec<u8>,
    ) -> impl std::future::Future<Output = Response<Body>> + use<'a> {
        let mut request = Request::builder()
            .method(method)
            .uri("/v1/account/avatar")
            .header("content-type", content_type);
        if let Some(session) = session {
            request = request.header("cookie", format!("__Host-vnox_session={}", session.token));
        }
        if let Some(csrf) = csrf {
            request = request.header("x-csrf-token", csrf);
        }
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        self.send(request.body(Body::from(body)).unwrap())
    }
    async fn upload(&self, session: &Session, content_type: &str, body: Vec<u8>) -> Response<Body> {
        self.change(
            Method::POST,
            Some(session),
            Some(&session.csrf),
            Some(ORIGIN),
            content_type,
            body,
        )
        .await
    }
    async fn remove(&self, session: &Session) -> Response<Body> {
        self.change(
            Method::DELETE,
            Some(session),
            Some(&session.csrf),
            Some(ORIGIN),
            "application/json",
            Vec::new(),
        )
        .await
    }
    async fn get(&self, path: &str) -> Response<Body> {
        self.send(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
    }
    async fn session_avatar(&self, session: &Session) -> serde_json::Value {
        let response = self
            .send(
                Request::builder()
                    .uri("/v1/auth/session")
                    .header("cookie", format!("__Host-vnox_session={}", session.token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        json(response).await["user"]["avatar_url"].clone()
    }
    async fn avatar_rows(&self) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM avatars")
            .fetch_one(&self.state.database)
            .await
            .unwrap()
    }
}

async fn json(response: Response<Body>) -> serde_json::Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1 << 20).await.unwrap()).unwrap()
}
async fn bytes(response: Response<Body>) -> Vec<u8> {
    to_bytes(response.into_body(), 1 << 22)
        .await
        .unwrap()
        .to_vec()
}

fn picture(width: u32, height: u32) -> RgbImage {
    RgbImage::from_fn(width, height, |x, y| {
        image::Rgb([(x % 256) as u8, (y % 256) as u8, ((x + y) % 256) as u8])
    })
}
fn png(width: u32, height: u32) -> Vec<u8> {
    let mut out = Vec::new();
    image::codecs::png::PngEncoder::new(&mut out)
        .write_image(
            picture(width, height).as_raw(),
            width,
            height,
            ExtendedColorType::Rgb8,
        )
        .unwrap();
    out
}
fn jpeg(width: u32, height: u32) -> Vec<u8> {
    let mut out = Vec::new();
    image::codecs::jpeg::JpegEncoder::new(&mut out)
        .write_image(
            picture(width, height).as_raw(),
            width,
            height,
            ExtendedColorType::Rgb8,
        )
        .unwrap();
    out
}
fn webp(width: u32, height: u32) -> Vec<u8> {
    let mut out = Vec::new();
    image::codecs::webp::WebPEncoder::new_lossless(&mut out)
        .write_image(
            picture(width, height).as_raw(),
            width,
            height,
            ExtendedColorType::Rgb8,
        )
        .unwrap();
    out
}
/// Inserts an EXIF APP1 segment carrying `marker` right after the JPEG start marker.
fn with_exif(jpeg: &[u8], marker: &str) -> Vec<u8> {
    let mut payload = b"Exif\0\0".to_vec();
    payload.extend_from_slice(marker.as_bytes());
    let mut out = jpeg[..2].to_vec();
    out.extend_from_slice(&[0xFF, 0xE1]);
    out.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
    out.extend_from_slice(&payload);
    out.extend_from_slice(&jpeg[2..]);
    out
}
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}
/// Inserts an ancillary chunk before IEND.
fn with_chunk(png: &[u8], kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let end = png.len() - 12;
    let mut out = png[..end].to_vec();
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    let mut body = kind.to_vec();
    body.extend_from_slice(data);
    out.extend_from_slice(&body);
    out.extend_from_slice(&crc32(&body).to_be_bytes());
    out.extend_from_slice(&png[end..]);
    out
}
/// Rewrites the IHDR size of a PNG and fixes its CRC: a tiny file that claims huge pixels.
fn claim_size(png: &[u8], width: u32, height: u32) -> Vec<u8> {
    let mut out = png.to_vec();
    out[16..20].copy_from_slice(&width.to_be_bytes());
    out[20..24].copy_from_slice(&height.to_be_bytes());
    let crc = crc32(&out[12..29]);
    out[29..33].copy_from_slice(&crc.to_be_bytes());
    out
}
fn chunk_names(png: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let mut at = 8;
    while at + 8 <= png.len() {
        let length = u32::from_be_bytes(png[at..at + 4].try_into().unwrap()) as usize;
        names.push(String::from_utf8_lossy(&png[at + 4..at + 8]).into_owned());
        at += 12 + length;
    }
    names
}
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

async fn assert_error(response: Response<Body>, status: StatusCode, code: &str) {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(json(response).await["error"], code);
}

#[tokio::test]
async fn upload_reencodes_to_a_square_png_and_serves_it_with_safe_headers() {
    let fx = fixture().await;
    let alice = fx.email_user("alice@example.com").await;
    assert_eq!(fx.session_avatar(&alice).await, serde_json::Value::Null);

    let response = fx.upload(&alice, "image/png", png(600, 300)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let url = json(response).await["avatar_url"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(url.starts_with("/v1/avatars/"));
    assert_eq!(url.len(), "/v1/avatars/".len() + 64);
    assert_eq!(fx.session_avatar(&alice).await, url);

    let served = fx.get(&url).await;
    assert_eq!(served.status(), StatusCode::OK);
    let h = served.headers();
    assert_eq!(h["content-type"], "image/png");
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["cache-control"], "public, max-age=31536000, immutable");
    assert!(
        h["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("default-src 'none'")
    );
    assert!(h.get("set-cookie").is_none());
    let body = bytes(served).await;
    let decoded = image::load_from_memory(&body).unwrap();
    assert_eq!((decoded.width(), decoded.height()), (256, 256));
    // The id is the content hash.
    assert_eq!(
        url,
        format!("/v1/avatars/{}", vnox_hub::avatar::content_id(&body))
    );
}

#[tokio::test]
async fn jpeg_and_webp_are_accepted_and_exif_and_png_text_chunks_are_removed() {
    let fx = fixture().await;
    let alice = fx.email_user("alice@example.com").await;

    let tagged = with_exif(&jpeg(200, 200), "SECRET-GPS-48.8566N");
    assert!(contains(&tagged, b"SECRET-GPS"));
    let response = fx.upload(&alice, "image/jpeg", tagged).await;
    assert_eq!(response.status(), StatusCode::OK);
    let url = json(response).await["avatar_url"]
        .as_str()
        .unwrap()
        .to_owned();
    let body = bytes(fx.get(&url).await).await;
    assert!(!contains(&body, b"SECRET"));
    assert!(!contains(&body, b"Exif"));
    assert_eq!(chunk_names(&body), ["IHDR", "IDAT", "IEND"]);

    let marked = with_chunk(&png(100, 100), b"tEXt", b"Comment\0SECRET-AUTHOR");
    let marked = with_chunk(&marked, b"eXIf", b"SECRET-EXIF");
    assert!(contains(&marked, b"SECRET-AUTHOR"));
    let response = fx.upload(&alice, "image/png", marked).await;
    assert_eq!(response.status(), StatusCode::OK);
    let url = json(response).await["avatar_url"]
        .as_str()
        .unwrap()
        .to_owned();
    let body = bytes(fx.get(&url).await).await;
    assert!(!contains(&body, b"SECRET"));
    assert_eq!(chunk_names(&body), ["IHDR", "IDAT", "IEND"]);

    let response = fx.upload(&alice, "image/webp", webp(120, 90)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let url = json(response).await["avatar_url"]
        .as_str()
        .unwrap()
        .to_owned();
    let served = fx.get(&url).await;
    assert_eq!(served.headers()["content-type"], "image/png");
    let decoded = image::load_from_memory(&bytes(served).await).unwrap();
    assert_eq!((decoded.width(), decoded.height()), (256, 256));
}

#[tokio::test]
async fn changes_need_session_csrf_and_exact_origin() {
    let fx = fixture().await;
    let alice = fx.email_user("alice@example.com").await;
    let image = png(64, 64);

    for method in [Method::POST, Method::DELETE] {
        let go = |session, csrf: Option<&str>, origin: Option<&str>| {
            fx.change(
                method.clone(),
                session,
                csrf,
                origin,
                "image/png",
                image.clone(),
            )
        };
        assert_error(
            go(None, Some(&alice.csrf), Some(ORIGIN)).await,
            StatusCode::UNAUTHORIZED,
            "not_authenticated",
        )
        .await;
        assert_error(
            go(Some(&alice), None, Some(ORIGIN)).await,
            StatusCode::FORBIDDEN,
            "invalid_csrf",
        )
        .await;
        assert_error(
            go(Some(&alice), Some("0".repeat(64).as_str()), Some(ORIGIN)).await,
            StatusCode::FORBIDDEN,
            "invalid_csrf",
        )
        .await;
        for origin in [
            None,
            Some("https://evil.example"),
            Some("http://central.loki-code.dev"),
            Some("https://central.loki-code.dev:8443"),
            Some("null"),
        ] {
            assert_error(
                go(Some(&alice), Some(&alice.csrf), origin).await,
                StatusCode::FORBIDDEN,
                "invalid_origin",
            )
            .await;
        }
    }
    assert_eq!(fx.avatar_rows().await, 0);
}

#[tokio::test]
async fn another_account_cannot_change_or_remove_my_avatar() {
    let fx = fixture().await;
    let alice = fx.email_user("alice@example.com").await;
    let bob = fx.email_user("bob@example.com").await;
    let response = fx.upload(&alice, "image/png", png(64, 64)).await;
    let alice_url = json(response).await["avatar_url"]
        .as_str()
        .unwrap()
        .to_owned();

    // Bob's session with Alice's CSRF token, and Alice's cookie with Bob's token.
    let mixed = [
        fx.change(
            Method::DELETE,
            Some(&bob),
            Some(&alice.csrf),
            Some(ORIGIN),
            "x/y",
            vec![],
        )
        .await,
        fx.change(
            Method::POST,
            Some(&bob),
            Some(&alice.csrf),
            Some(ORIGIN),
            "image/png",
            png(64, 64),
        )
        .await,
        fx.change(
            Method::DELETE,
            Some(&alice),
            Some(&bob.csrf),
            Some(ORIGIN),
            "x/y",
            vec![],
        )
        .await,
    ];
    for response in mixed {
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    assert_eq!(fx.session_avatar(&alice).await, alice_url);
    assert_eq!(fx.session_avatar(&bob).await, serde_json::Value::Null);

    // Bob acting as himself only affects Bob.
    assert_eq!(
        fx.upload(&bob, "image/png", png(80, 80)).await.status(),
        StatusCode::OK
    );
    assert_eq!(fx.remove(&bob).await.status(), StatusCode::OK);
    assert_eq!(fx.session_avatar(&alice).await, alice_url);
    assert_eq!(fx.get(&alice_url).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn wrong_types_and_swapped_extensions_are_refused() {
    let fx = fixture().await;
    let alice = fx.email_user("alice@example.com").await;
    let gif = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;".to_vec();
    let svg = br#"<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64"><script>alert(1)</script></svg>"#.to_vec();

    for (declared, body, code) in [
        ("image/gif", gif.clone(), "unsupported_type"),
        ("image/png", gif, "unsupported_type"),
        ("image/svg+xml", svg.clone(), "unsupported_type"),
        ("image/png", svg, "unsupported_type"),
        ("text/plain", b"hello".to_vec(), "unsupported_type"),
        ("application/json", b"{}".to_vec(), "unsupported_type"),
        (
            "image/png",
            b"not an image at all".to_vec(),
            "unsupported_type",
        ),
        // A JPEG sent as a PNG, a PNG sent as a JPEG, WebP sent as PNG: the name does not matter.
        ("image/png", jpeg(64, 64), "type_mismatch"),
        ("image/jpeg", png(64, 64), "type_mismatch"),
        ("image/png", webp(64, 64), "type_mismatch"),
    ] {
        assert_error(
            fx.upload(&alice, declared, body).await,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            code,
        )
        .await;
    }
    // No content type at all.
    let response = fx
        .send(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/account/avatar")
                .header("cookie", format!("__Host-vnox_session={}", alice.token))
                .header("x-csrf-token", &alice.csrf)
                .header("origin", ORIGIN)
                .body(Body::from(png(64, 64)))
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(fx.avatar_rows().await, 0);
}

#[tokio::test]
async fn oversized_bodies_are_refused() {
    let fx = fixture().await;
    let alice = fx.email_user("alice@example.com").await;
    let mut big = png(64, 64);
    big.resize(2 * 1024 * 1024 + 1, 0);
    // Without a Content-Length (chunked), the read itself stops at the limit.
    assert_error(
        fx.upload(&alice, "image/png", big.clone()).await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "too_large",
    )
    .await;
    // With an announced length, it is refused before reading.
    let response = fx
        .send(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/account/avatar")
                .header("cookie", format!("__Host-vnox_session={}", alice.token))
                .header("x-csrf-token", &alice.csrf)
                .header("origin", ORIGIN)
                .header("content-type", "image/png")
                .header("content-length", big.len())
                .body(Body::from(big))
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    // Unauthenticated callers never get their body read or decoded.
    let response = fx
        .change(
            Method::POST,
            None,
            None,
            Some(ORIGIN),
            "image/png",
            vec![0; 3 << 20],
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(fx.avatar_rows().await, 0);
}

#[tokio::test]
async fn decompression_bomb_and_odd_dimensions_are_refused_before_decoding() {
    let fx = fixture().await;
    let alice = fx.email_user("alice@example.com").await;

    // Tiny files whose headers claim huge or oversized pictures.
    for (w, h) in [(60_000, 60_000), (4097, 64), (64, 4097), (u32::MAX >> 1, 1)] {
        let lie = claim_size(&png(64, 64), w, h);
        assert!(lie.len() < 100_000);
        assert_error(
            fx.upload(&alice, "image/png", lie).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "bad_dimensions",
        )
        .await;
    }
    // Real, merely oversized or undersized pictures.
    assert_error(
        fx.upload(&alice, "image/png", png(4097, 40)).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "bad_dimensions",
    )
    .await;
    assert_error(
        fx.upload(&alice, "image/jpeg", jpeg(16, 16)).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "bad_dimensions",
    )
    .await;
    // Truncated and corrupted data.
    let mut cut = png(300, 300);
    cut.truncate(cut.len() / 2);
    assert_error(
        fx.upload(&alice, "image/png", cut).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid_image",
    )
    .await;
    let mut cut = jpeg(300, 300);
    cut.truncate(60);
    let response = fx.upload(&alice, "image/jpeg", cut).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(fx.avatar_rows().await, 0);
}

#[tokio::test]
async fn a_new_upload_replaces_the_old_one() {
    let fx = fixture().await;
    let alice = fx.email_user("alice@example.com").await;
    let first = json(fx.upload(&alice, "image/png", png(100, 100)).await).await["avatar_url"]
        .as_str()
        .unwrap()
        .to_owned();
    let second = json(fx.upload(&alice, "image/jpeg", jpeg(150, 150)).await).await["avatar_url"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(first, second);
    assert_eq!(fx.avatar_rows().await, 1);
    assert_eq!(fx.get(&first).await.status(), StatusCode::NOT_FOUND);
    assert_eq!(fx.get(&second).await.status(), StatusCode::OK);
    assert_eq!(fx.session_avatar(&alice).await, second);
}

#[tokio::test]
async fn delete_returns_the_provider_avatar_or_the_default() {
    let fx = fixture().await;
    let github = fx.github_user().await;
    assert_eq!(fx.session_avatar(&github).await, GITHUB_AVATAR);

    let url = json(fx.upload(&github, "image/png", png(64, 64)).await).await["avatar_url"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(fx.session_avatar(&github).await, GITHUB_AVATAR);

    let response = fx.remove(&github).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(json(response).await["avatar_url"], GITHUB_AVATAR);
    assert_eq!(fx.session_avatar(&github).await, GITHUB_AVATAR);
    assert_eq!(fx.get(&url).await.status(), StatusCode::NOT_FOUND);
    assert_eq!(fx.avatar_rows().await, 0);

    // Removing again is harmless, and an email account falls back to the default (null).
    assert_eq!(fx.remove(&github).await.status(), StatusCode::OK);
    let alice = fx.email_user("alice@example.com").await;
    fx.upload(&alice, "image/png", png(64, 64)).await;
    let response = fx.remove(&alice).await;
    assert_eq!(json(response).await["avatar_url"], serde_json::Value::Null);
    assert_eq!(fx.session_avatar(&alice).await, serde_json::Value::Null);
}

#[tokio::test]
async fn avatar_urls_are_validated_and_unknown_ids_are_not_found() {
    let fx = fixture().await;
    for path in [
        "/v1/avatars/".to_owned(),
        "/v1/avatars/abc".to_owned(),
        format!("/v1/avatars/{}", "0".repeat(64)),
        format!("/v1/avatars/{}", "G".repeat(64)),
        format!("/v1/avatars/{}", "A".repeat(64)),
        "/v1/avatars/..%2F..%2Fhub.sqlite3".to_owned(),
    ] {
        let response = fx.get(&path).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
}

#[tokio::test]
async fn upload_rate_limit_applies_per_account() {
    let fx = fixture().await;
    let alice = fx.email_user("alice@example.com").await;
    let bob = fx.email_user("bob@example.com").await;
    let image = png(64, 64);
    for _ in 0..10 {
        assert_eq!(
            fx.upload(&alice, "image/png", image.clone()).await.status(),
            StatusCode::OK
        );
    }
    assert_error(
        fx.upload(&alice, "image/png", image.clone()).await,
        StatusCode::TOO_MANY_REQUESTS,
        "try_later",
    )
    .await;
    assert_error(
        fx.remove(&alice).await,
        StatusCode::TOO_MANY_REQUESTS,
        "try_later",
    )
    .await;
    // Another account from the same source still has its own budget.
    assert_eq!(
        fx.upload(&bob, "image/png", image).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn upload_rate_limit_applies_per_source() {
    let fx = fixture().await;
    let image = png(64, 64);
    let mut accepted = 0;
    for n in 0..40 {
        let user = fx.email_user(&format!("user{n}@example.com")).await;
        let response = fx
            .send(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/account/avatar")
                    .header("cookie", format!("__Host-vnox_session={}", user.token))
                    .header("x-csrf-token", &user.csrf)
                    .header("origin", ORIGIN)
                    .header("x-forwarded-for", "203.0.113.9")
                    .header("content-type", "image/png")
                    .body(Body::from(image.clone()))
                    .unwrap(),
            )
            .await;
        match response.status() {
            StatusCode::OK => accepted += 1,
            StatusCode::TOO_MANY_REQUESTS => break,
            other => panic!("unexpected {other}"),
        }
    }
    assert_eq!(accepted, 30);
}

#[tokio::test]
async fn deleting_an_account_removes_its_avatar() {
    let fx = fixture().await;
    let alice = fx.email_user("alice@example.com").await;
    fx.upload(&alice, "image/png", png(64, 64)).await;
    sqlx::query("DELETE FROM accounts WHERE user_id=?")
        .bind(&alice.user.user_id)
        .execute(&fx.state.database)
        .await
        .unwrap();
    assert_eq!(fx.avatar_rows().await, 0);
}
