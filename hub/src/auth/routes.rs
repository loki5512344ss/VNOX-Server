use super::{AuthService, store};
use crate::web::HubState;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use cookie::{Cookie, SameSite};
use oauth2::{CsrfToken, PkceCodeChallenge};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use subtle::ConstantTimeEq;
const BROWSER: &str = "__Host-vnox_oauth";
const SESSION: &str = "__Host-vnox_session";
pub fn router() -> Router<Arc<HubState>> {
    Router::new()
        .route("/v1/auth/github/start", get(start))
        .route("/v1/auth/github/callback", get(callback))
        .route("/v1/auth/session", get(session))
        .route("/v1/auth/logout", post(logout))
}
fn failure(status: StatusCode, code: &'static str) -> Response {
    (status, Json(json!({"error":code}))).into_response()
}
fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut found = None;
    let mut size = 0;
    for value in headers.get_all(header::COOKIE) {
        size += value.len();
        if size > 8192 {
            return None;
        }
        for part in value.to_str().ok()?.split(';') {
            let parsed = Cookie::parse(part.trim().to_owned()).ok()?;
            if parsed.name() == name {
                if found.is_some()
                    || parsed.value().len() != 64
                    || !parsed.value().bytes().all(|c| c.is_ascii_hexdigit())
                {
                    return None;
                }
                found = Some(parsed.value().to_owned());
            }
        }
    }
    found
}
fn set_cookie(response: &mut Response, name: &'static str, value: String, ttl: i64) {
    let value = Cookie::build((name, value))
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(cookie::time::Duration::seconds(ttl))
        .build()
        .to_string();
    response
        .headers_mut()
        .append(header::SET_COOKIE, value.parse().expect("generated cookie"));
}
fn allowed(auth: &AuthService, headers: &HeaderMap) -> bool {
    // The loopback-only service trusts only the reverse proxy, which overwrites this header.
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<std::net::IpAddr>().ok())
        .map(|v| v.to_string())
        .unwrap_or_else(|| "local".into());
    auth.allow(&ip)
}
async fn start(State(state): State<Arc<HubState>>, headers: HeaderMap) -> Response {
    let auth = &state.auth;
    let Some(provider) = &auth.provider else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "github_not_configured");
    };
    if !allowed(auth, &headers) {
        return failure(StatusCode::TOO_MANY_REQUESTS, "try_later");
    }
    let csrf = CsrfToken::new_random();
    let browser = store::token();
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    if store::create_attempt(&auth.pool, csrf.secret(), &browser, verifier.secret())
        .await
        .is_err()
    {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "try_later");
    }
    let mut response = Redirect::to(provider.authorize(csrf, challenge).as_str()).into_response();
    set_cookie(&mut response, BROWSER, browser, store::LOGIN_TTL);
    response
}
#[derive(Deserialize)]
struct Callback {
    code: Option<String>,
    state: Option<String>,
}
async fn callback(
    State(state): State<Arc<HubState>>,
    headers: HeaderMap,
    Query(query): Query<Callback>,
) -> Response {
    let auth = &state.auth;
    let Some(provider) = &auth.provider else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "github_not_configured");
    };
    if !allowed(auth, &headers) {
        return failure(StatusCode::TOO_MANY_REQUESTS, "try_later");
    }
    let (Some(code), Some(csrf), Some(browser)) =
        (query.code, query.state, cookie(&headers, BROWSER))
    else {
        return failure(StatusCode::BAD_REQUEST, "invalid_login");
    };
    if code.is_empty() || code.len() > 1024 || csrf.len() > 256 {
        return failure(StatusCode::BAD_REQUEST, "invalid_login");
    }
    let Ok(Some(verifier)) = store::consume_attempt(&auth.pool, &csrf, &browser).await else {
        return failure(StatusCode::BAD_REQUEST, "invalid_login");
    };
    let Ok(profile) = provider.identify(&code, &verifier).await else {
        return failure(StatusCode::BAD_GATEWAY, "github_login_failed");
    };
    let Ok(user) = store::upsert_identity(&auth.pool, &profile).await else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "try_later");
    };
    let Ok((token, _)) = store::create_session(&auth.pool, &user.user_id).await else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "try_later");
    };
    if let Some(old) = cookie(&headers, SESSION) {
        let _ = sqlx::query("DELETE FROM web_sessions WHERE token_hash=?")
            .bind(store::hash(&old))
            .execute(&auth.pool)
            .await;
    }
    let mut response =
        Redirect::to(auth.origin.join("account").expect("fixed path").as_str()).into_response();
    set_cookie(&mut response, SESSION, token, store::SESSION_TTL);
    set_cookie(&mut response, BROWSER, String::new(), 0);
    response
}
async fn session(State(state): State<Arc<HubState>>, headers: HeaderMap) -> Response {
    if let Some(token) = cookie(&headers, SESSION) {
        match store::get_session(&state.auth.pool, &token).await {
            Ok(Some((user, csrf))) => {
                return Json(json!({"authenticated":true,"user":user,"csrf_token":csrf}))
                    .into_response();
            }
            Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE, "try_later"),
            _ => {}
        }
    }
    Json(json!({"authenticated":false})).into_response()
}
async fn logout(State(state): State<Arc<HubState>>, headers: HeaderMap) -> Response {
    let origin = state.auth.origin.origin().ascii_serialization();
    if headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(origin.as_str()) {
        return failure(StatusCode::FORBIDDEN, "invalid_origin");
    }
    let Some(token) = cookie(&headers, SESSION) else {
        return failure(StatusCode::UNAUTHORIZED, "not_authenticated");
    };
    let Ok(Some((_, csrf))) = store::get_session(&state.auth.pool, &token).await else {
        return failure(StatusCode::UNAUTHORIZED, "not_authenticated");
    };
    let supplied = headers
        .get("x-csrf-token")
        .map(|v| v.as_bytes())
        .unwrap_or_default();
    if !bool::from(csrf.as_bytes().ct_eq(supplied)) {
        return failure(StatusCode::FORBIDDEN, "invalid_csrf");
    }
    if sqlx::query("DELETE FROM web_sessions WHERE token_hash=?")
        .bind(store::hash(&token))
        .execute(&state.auth.pool)
        .await
        .is_err()
    {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "try_later");
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    set_cookie(&mut response, SESSION, String::new(), 0);
    response
}
