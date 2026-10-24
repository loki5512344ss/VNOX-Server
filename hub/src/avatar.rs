//! Own-avatar processing and storage.
//!
//! Uploads are never stored as received. The bytes are sniffed (PNG, JPEG or WebP only),
//! the header dimensions are checked before any pixel buffer exists, the image is fully
//! decoded under a memory limit, rotated by its EXIF orientation, cropped to a square,
//! resized and written again as a fresh PNG. A fresh PNG carries no EXIF, GPS, ICC, text or
//! other ancillary chunks from the source, so metadata cannot survive.

use std::io::Cursor;

use image::{
    DynamicImage, ImageDecoder, ImageEncoder, ImageFormat, Limits, codecs::png::PngEncoder,
    imageops::FilterType,
};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

/// Request body limit (2 MiB).
pub const MAX_UPLOAD_BYTES: usize = 2 * 1024 * 1024;
/// Largest accepted source side, checked from the header before decoding.
pub const MAX_SOURCE_SIDE: u32 = 4096;
/// Smallest accepted source side.
pub const MIN_SOURCE_SIDE: u32 = 32;
/// Side of the stored square.
pub const OUTPUT_SIDE: u32 = 256;
/// Decoder allocation budget; a 4096x4096 RGBA frame is 64 MiB.
const MAX_DECODE_ALLOC: u64 = 128 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum AvatarError {
    /// Not PNG, JPEG or WebP (SVG, GIF and everything else included).
    UnsupportedType,
    /// Declared and detected types differ.
    TypeMismatch,
    /// Larger than 4096 on a side, or smaller than 32.
    BadDimensions,
    /// Looks like a supported image but does not decode.
    Invalid,
}

/// The MIME type of a supported format.
pub fn mime_for(format: ImageFormat) -> Option<&'static str> {
    match format {
        ImageFormat::Png => Some("image/png"),
        ImageFormat::Jpeg => Some("image/jpeg"),
        ImageFormat::WebP => Some("image/webp"),
        _ => None,
    }
}

/// Validates and re-encodes an upload. `declared` is the request `Content-Type` without
/// parameters. CPU and memory heavy: call from a blocking thread.
pub fn normalize(declared: &str, data: &[u8]) -> Result<Vec<u8>, AvatarError> {
    let format = image::guess_format(data).map_err(|_| AvatarError::UnsupportedType)?;
    let detected = mime_for(format).ok_or(AvatarError::UnsupportedType)?;
    if detected != declared {
        return Err(AvatarError::TypeMismatch);
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_SOURCE_SIDE);
    limits.max_image_height = Some(MAX_SOURCE_SIDE);
    limits.max_alloc = Some(MAX_DECODE_ALLOC);
    let mut reader = image::ImageReader::with_format(Cursor::new(data), format);
    reader.limits(limits);
    let mut decoder = reader.into_decoder().map_err(|error| match error {
        image::ImageError::Limits(_) => AvatarError::BadDimensions,
        _ => AvatarError::Invalid,
    })?;
    // Header-only: nothing has been allocated for pixels yet.
    let (width, height) = decoder.dimensions();
    if width > MAX_SOURCE_SIDE
        || height > MAX_SOURCE_SIDE
        || width < MIN_SOURCE_SIDE
        || height < MIN_SOURCE_SIDE
    {
        return Err(AvatarError::BadDimensions);
    }
    let orientation = decoder.orientation().map_err(|_| AvatarError::Invalid)?;
    let mut picture = DynamicImage::from_decoder(decoder).map_err(|_| AvatarError::Invalid)?;
    picture.apply_orientation(orientation);
    let square = picture.resize_to_fill(OUTPUT_SIDE, OUTPUT_SIDE, FilterType::Lanczos3);
    let mut out = Vec::new();
    let encoder = PngEncoder::new(&mut out);
    let written = if square.color().has_alpha() {
        let pixels = square.to_rgba8();
        encoder.write_image(
            pixels.as_raw(),
            OUTPUT_SIDE,
            OUTPUT_SIDE,
            image::ExtendedColorType::Rgba8,
        )
    } else {
        let pixels = square.to_rgb8();
        encoder.write_image(
            pixels.as_raw(),
            OUTPUT_SIDE,
            OUTPUT_SIDE,
            image::ExtendedColorType::Rgb8,
        )
    };
    written.map_err(|_| AvatarError::Invalid)?;
    Ok(out)
}

/// Public identifier: hex SHA-256 of the stored bytes.
pub fn content_id(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// True for a 64 character lowercase hex identifier.
pub fn valid_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// Replaces the account's avatar atomically and returns its URL path.
pub async fn replace(pool: &SqlitePool, user_id: &str, png: &[u8]) -> anyhow::Result<String> {
    let id = content_id(png);
    sqlx::query(
        "INSERT INTO avatars(user_id,id,content_type,bytes,created_at) VALUES(?,?,?,?,?) \
         ON CONFLICT(user_id) DO UPDATE SET id=excluded.id,content_type=excluded.content_type,\
         bytes=excluded.bytes,created_at=excluded.created_at",
    )
    .bind(user_id)
    .bind(&id)
    .bind("image/png")
    .bind(png)
    .bind(crate::auth::store::now())
    .execute(pool)
    .await?;
    Ok(url_path(&id))
}

/// Deletes the account's own avatar; true if one existed.
pub async fn remove(pool: &SqlitePool, user_id: &str) -> anyhow::Result<bool> {
    let done = sqlx::query("DELETE FROM avatars WHERE user_id=?")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(done.rows_affected() > 0)
}

/// Content type and bytes for a public avatar id.
pub async fn fetch(pool: &SqlitePool, id: &str) -> anyhow::Result<Option<(String, Vec<u8>)>> {
    Ok(
        sqlx::query_as("SELECT content_type,bytes FROM avatars WHERE id=? LIMIT 1")
            .bind(id)
            .fetch_optional(pool)
            .await?,
    )
}

/// The provider avatar kept on the account, if any.
pub async fn provider_url(pool: &SqlitePool, user_id: &str) -> anyhow::Result<Option<String>> {
    Ok(
        sqlx::query_scalar("SELECT avatar_url FROM accounts WHERE user_id=?")
            .bind(user_id)
            .fetch_optional(pool)
            .await?
            .flatten(),
    )
}

pub fn url_path(id: &str) -> String {
    format!("/v1/avatars/{id}")
}
