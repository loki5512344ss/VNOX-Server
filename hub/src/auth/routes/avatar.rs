//! Own-avatar endpoints. Changing requires an authenticated web session, the exact `Origin`
//! and the session's `X-CSRF-Token` (the same gate as logout). Serving is public.

use super::{HeaderMap, StatusCode, allowed_avatar, authorized, failure};
use crate::{avatar, web::HubState};
use axum::{
    Json,
    body::{Body, to_bytes},
    extract::{Path, State},
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::sync::Arc;

/// `POST /v1/account/avatar`: body is the raw image, `Content-Type` its type.
pub(super) async fn upload(
    State(state): State<Arc<HubState>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let user = match authorized(&state, &headers).await {
        Ok((user, _)) => user,
        Err(response) => return *response,
    };
    let declared = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .unwrap_or_default();
    if !matches!(declared.as_str(), "image/png" | "image/jpeg" | "image/webp") {
        return failure(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_type");
    }
    if !allowed_avatar(&state.auth, &user.user_id, &headers) {
        return failure(StatusCode::TOO_MANY_REQUESTS, "try_later");
    }
    // Reject by announced size first; the read below enforces the limit for chunked bodies.
    let announced = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    if announced.is_some_and(|n| n > avatar::MAX_UPLOAD_BYTES) {
        return failure(StatusCode::PAYLOAD_TOO_LARGE, "too_large");
    }
    let Ok(data) = to_bytes(body, avatar::MAX_UPLOAD_BYTES).await else {
        return failure(StatusCode::PAYLOAD_TOO_LARGE, "too_large");
    };
    let Ok(permit) = state.auth.avatar_decoding.try_acquire() else {
        return failure(StatusCode::TOO_MANY_REQUESTS, "try_later");
    };
    let processed = tokio::task::spawn_blocking(move || avatar::normalize(&declared, &data)).await;
    drop(permit);
    let png = match processed {
        Ok(Ok(png)) => png,
        Ok(Err(avatar::AvatarError::UnsupportedType)) => {
            return failure(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_type");
        }
        Ok(Err(avatar::AvatarError::TypeMismatch)) => {
            return failure(StatusCode::UNSUPPORTED_MEDIA_TYPE, "type_mismatch");
        }
        Ok(Err(avatar::AvatarError::BadDimensions)) => {
            return failure(StatusCode::UNPROCESSABLE_ENTITY, "bad_dimensions");
        }
        Ok(Err(avatar::AvatarError::Invalid)) => {
            return failure(StatusCode::UNPROCESSABLE_ENTITY, "invalid_image");
        }
        Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE, "try_later"),
    };
    match avatar::replace(&state.auth.pool, &user.user_id, &png).await {
        Ok(url) => Json(json!({"avatar_url": url})).into_response(),
        Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "try_later"),
    }
}

/// `DELETE /v1/account/avatar`: drops the own photo; the answer carries the avatar now in
/// effect (the provider's, or null for the default).
pub(super) async fn remove(State(state): State<Arc<HubState>>, headers: HeaderMap) -> Response {
    let user = match authorized(&state, &headers).await {
        Ok((user, _)) => user,
        Err(response) => return *response,
    };
    if !allowed_avatar(&state.auth, &user.user_id, &headers) {
        return failure(StatusCode::TOO_MANY_REQUESTS, "try_later");
    }
    let pool = &state.auth.pool;
    if avatar::remove(pool, &user.user_id).await.is_err() {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "try_later");
    }
    match avatar::provider_url(pool, &user.user_id).await {
        Ok(url) => Json(json!({"avatar_url": url})).into_response(),
        Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "try_later"),
    }
}

/// `GET /v1/avatars/<id>`: public and immutable, because the id is the content hash.
pub(super) async fn serve(State(state): State<Arc<HubState>>, Path(id): Path<String>) -> Response {
    if !avatar::valid_id(&id) {
        return failure(StatusCode::NOT_FOUND, "not_found");
    }
    let (content_type, bytes) = match avatar::fetch(&state.auth.pool, &id).await {
        Ok(Some(found)) => found,
        Ok(None) => return failure(StatusCode::NOT_FOUND, "not_found"),
        Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE, "try_later"),
    };
    let mut response = bytes.into_response();
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&content_type) {
        headers.insert(header::CONTENT_TYPE, value);
    }
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; sandbox; frame-ancestors 'none'"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("inline; filename=\"avatar.png\""),
    );
    if let Ok(value) = HeaderValue::from_str(&format!("\"{id}\"")) {
        headers.insert(header::ETAG, value);
    }
    response
}
