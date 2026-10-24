use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use uuid::Uuid;

use super::provider::GitHubProfile;

pub const LOGIN_TTL: i64 = 600;
pub const SESSION_TTL: i64 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct User {
    pub user_id: String,
    pub handle: String,
    pub display_name: String,
    pub avatar_url: Option<String>,
}

pub fn hash(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}
pub fn token() -> String {
    use rand::Rng;
    let mut bytes = [0; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub async fn cleanup(pool: &SqlitePool) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM oauth_attempts WHERE expires_at<=?")
        .bind(now())
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM web_sessions WHERE expires_at<=?")
        .bind(now())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn create_attempt(
    pool: &SqlitePool,
    state: &str,
    browser: &str,
    verifier: &str,
) -> anyhow::Result<()> {
    cleanup(pool).await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oauth_attempts")
        .fetch_one(pool)
        .await?;
    anyhow::ensure!(count < 4096, "login capacity reached");
    sqlx::query("INSERT INTO oauth_attempts(state_hash,browser_hash,pkce_verifier,expires_at) VALUES(?,?,?,?)")
        .bind(hash(state)).bind(hash(browser)).bind(verifier).bind(now()+LOGIN_TTL).execute(pool).await?;
    Ok(())
}

pub async fn consume_attempt(
    pool: &SqlitePool,
    state: &str,
    browser: &str,
) -> anyhow::Result<Option<String>> {
    Ok(sqlx::query_scalar("DELETE FROM oauth_attempts WHERE state_hash=? AND browser_hash=? AND expires_at>? RETURNING pkce_verifier")
        .bind(hash(state)).bind(hash(browser)).bind(now()).fetch_optional(pool).await?)
}

pub async fn upsert_identity(pool: &SqlitePool, profile: &GitHubProfile) -> anyhow::Result<User> {
    let subject = profile.id.to_string();
    if let Some(user) = lookup_identity(pool, &subject).await? {
        return Ok(user);
    }
    let id = Uuid::new_v4();
    // Generated stable handle avoids claiming a privileged/reused handle from another provider.
    let handle = format!("u_{}", id.simple());
    let name = profile
        .name
        .as_deref()
        .unwrap_or(&profile.login)
        .chars()
        .take(100)
        .collect::<String>();
    let avatar = profile.avatar_url.as_deref().filter(|value| {
        url::Url::parse(value).is_ok_and(|url| {
            url.scheme() == "https"
                && url.host_str() == Some("avatars.githubusercontent.com")
                && url.username().is_empty()
                && url.password().is_none()
        })
    });
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT INTO accounts(user_id,handle,created_at,display_name,avatar_url) VALUES(?,?,?,?,?)",
    )
    .bind(id.to_string())
    .bind(handle)
    .bind(now())
    .bind(name)
    .bind(avatar)
    .execute(&mut *transaction)
    .await?;
    let inserted = sqlx::query("INSERT INTO external_identities(provider,subject,user_id,linked_at) VALUES('github.com',?,?,?) ON CONFLICT(provider,subject) DO NOTHING")
        .bind(&subject).bind(id.to_string()).bind(now()).execute(&mut *transaction).await?;
    if inserted.rows_affected() == 0 {
        transaction.rollback().await?;
    } else {
        transaction.commit().await?;
    }
    lookup_identity(pool, &subject)
        .await?
        .ok_or_else(|| anyhow::anyhow!("identity transaction failed"))
}

async fn lookup_identity(pool: &SqlitePool, subject: &str) -> anyhow::Result<Option<User>> {
    Ok(sqlx::query_as("SELECT a.user_id,a.handle,a.display_name,a.avatar_url FROM accounts a JOIN external_identities e ON e.user_id=a.user_id WHERE e.provider='github.com' AND e.subject=?")
        .bind(subject).fetch_optional(pool).await?)
}

pub async fn create_session(pool: &SqlitePool, user_id: &str) -> anyhow::Result<(String, String)> {
    let session = token();
    let csrf = token();
    sqlx::query("INSERT INTO web_sessions(token_hash,user_id,csrf_token,created_at,expires_at) VALUES(?,?,?,?,?)")
        .bind(hash(&session)).bind(user_id).bind(&csrf).bind(now()).bind(now()+SESSION_TTL).execute(pool).await?;
    Ok((session, csrf))
}

pub async fn get_session(
    pool: &SqlitePool,
    session: &str,
) -> anyhow::Result<Option<(User, String)>> {
    #[derive(sqlx::FromRow)]
    struct Row {
        user_id: String,
        handle: String,
        display_name: String,
        avatar_url: Option<String>,
        csrf_token: String,
    }
    let row: Option<Row> = sqlx::query_as("SELECT a.user_id,a.handle,a.display_name,a.avatar_url,s.csrf_token FROM web_sessions s JOIN accounts a ON a.user_id=s.user_id WHERE s.token_hash=? AND s.expires_at>?")
        .bind(hash(session)).bind(now()).fetch_optional(pool).await?;
    Ok(row.map(|r| {
        (
            User {
                user_id: r.user_id,
                handle: r.handle,
                display_name: r.display_name,
                avatar_url: r.avatar_url,
            },
            r.csrf_token,
        )
    }))
}
