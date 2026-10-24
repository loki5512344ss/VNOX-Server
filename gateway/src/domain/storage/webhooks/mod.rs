//! Persistent webhook configuration and transactional, bounded delivery queues.
use super::{Pool, Storage};
use crate::proto::ChatMessagePayload;
use anyhow::Result;

#[derive(Clone, sqlx::FromRow)]
pub struct Hook {
    pub id: String,
    pub channel_id: String,
    pub guild_id: String,
    pub creator_id: String,
    pub name: String,
    pub direction: String,
    pub provider: String,
    pub endpoint: String,
    pub token_hash: String,
    pub sealed_secret: Vec<u8>,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
    pub suspended_reason: Option<String>,
}
#[derive(sqlx::FromRow)]
pub struct Delivery {
    pub id: String,
    pub hook_id: String,
    pub body: String,
    pub attempts: i64,
}

macro_rules! db {
    ($s:expr, $p:ident, $body:expr) => {
        match &$s.pool {
            Pool::Sqlite($p) => $body,
            Pool::Postgres($p) => $body,
        }
    };
}
impl Storage {
    pub async fn migrate_webhooks(&self) -> Result<()> {
        let ddl = "CREATE TABLE IF NOT EXISTS webhooks (id TEXT PRIMARY KEY, channel_id TEXT NOT NULL, guild_id TEXT NOT NULL, creator_id TEXT NOT NULL, name TEXT NOT NULL, direction TEXT NOT NULL, provider TEXT NOT NULL, endpoint TEXT NOT NULL, token_hash TEXT NOT NULL, sealed_secret BLOB NOT NULL, created_at BIGINT NOT NULL, revoked_at BIGINT, suspended_reason TEXT); CREATE INDEX IF NOT EXISTS hooks_channel ON webhooks(channel_id); CREATE TABLE IF NOT EXISTS webhook_receipts (hook_id TEXT NOT NULL, delivery_id TEXT NOT NULL, body_hash TEXT NOT NULL, message_id TEXT NOT NULL, created_at BIGINT NOT NULL, PRIMARY KEY(hook_id,delivery_id)); CREATE TABLE IF NOT EXISTS webhook_outbox (id TEXT PRIMARY KEY, hook_id TEXT NOT NULL, body TEXT NOT NULL, attempts BIGINT NOT NULL DEFAULT 0, next_at BIGINT NOT NULL); CREATE INDEX IF NOT EXISTS outbox_due ON webhook_outbox(next_at);";
        match &self.pool {
            Pool::Sqlite(p) => {
                sqlx::raw_sql(ddl).execute(p).await?;
            }
            Pool::Postgres(p) => {
                sqlx::raw_sql("CREATE TABLE IF NOT EXISTS webhooks (id TEXT PRIMARY KEY, channel_id TEXT NOT NULL, guild_id TEXT NOT NULL, creator_id TEXT NOT NULL, name TEXT NOT NULL, direction TEXT NOT NULL, provider TEXT NOT NULL, endpoint TEXT NOT NULL, token_hash TEXT NOT NULL, sealed_secret BYTEA NOT NULL, created_at BIGINT NOT NULL, revoked_at BIGINT, suspended_reason TEXT); CREATE INDEX IF NOT EXISTS hooks_channel ON webhooks(channel_id); CREATE TABLE IF NOT EXISTS webhook_receipts (hook_id TEXT NOT NULL, delivery_id TEXT NOT NULL, body_hash TEXT NOT NULL, message_id TEXT NOT NULL, created_at BIGINT NOT NULL, PRIMARY KEY(hook_id,delivery_id)); CREATE TABLE IF NOT EXISTS webhook_outbox (id TEXT PRIMARY KEY, hook_id TEXT NOT NULL, body TEXT NOT NULL, attempts BIGINT NOT NULL DEFAULT 0, next_at BIGINT NOT NULL); CREATE INDEX IF NOT EXISTS outbox_due ON webhook_outbox(next_at);").execute(p).await?;
            }
        }
        Ok(())
    }
    pub async fn webhook_scope(
        &self,
        channel: &str,
        user: &str,
    ) -> Result<Option<(String, String, i64)>> {
        Ok(db!(self,p,sqlx::query_as::<_,(String,String,i64)>("SELECT c.guild_id,g.owner_id,(SELECT COUNT(*) FROM guild_members m WHERE m.guild_id=g.id AND m.user_id=$2) FROM channels c JOIN guilds g ON g.id=c.guild_id WHERE c.id=$1 AND c.kind='text'").bind(channel).bind(user).fetch_optional(p).await?))
    }
    pub async fn hook(&self, id: &str) -> Result<Option<Hook>> {
        Ok(db!(
            self,
            p,
            sqlx::query_as::<_, Hook>("SELECT * FROM webhooks WHERE id=$1")
                .bind(id)
                .fetch_optional(p)
                .await?
        ))
    }
    pub async fn hooks(&self, channel: &str) -> Result<Vec<Hook>> {
        Ok(db!(
            self,
            p,
            sqlx::query_as::<_, Hook>(
                "SELECT * FROM webhooks WHERE channel_id=$1 AND revoked_at IS NULL ORDER BY created_at LIMIT 64"
            )
            .bind(channel)
            .fetch_all(p)
            .await?
        ))
    }
    pub async fn insert_hook(&self, h: &Hook) -> Result<()> {
        macro_rules! insert { ($p:expr,$lock:literal) => {{
            let mut tx = $p.begin().await?;
            sqlx::query($lock).execute(&mut *tx).await?;
                    sqlx::query("INSERT INTO webhooks(id,channel_id,guild_id,creator_id,name,direction,provider,endpoint,token_hash,sealed_secret,created_at) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11 WHERE (SELECT COUNT(*) FROM webhooks WHERE channel_id=$2 AND revoked_at IS NULL)<32")
            .bind(&h.id).bind(&h.channel_id).bind(&h.guild_id).bind(&h.creator_id).bind(&h.name).bind(&h.direction).bind(&h.provider).bind(&h.endpoint).bind(&h.token_hash).bind(&h.sealed_secret).bind(h.created_at).execute(&mut *tx).await?.rows_affected().eq(&1).then_some(()).ok_or_else(||anyhow::anyhow!("channel webhook limit reached"))?;
            tx.commit().await?;
            Ok(())
        }}; }
        match &self.pool {
            Pool::Sqlite(p) => insert!(p, "UPDATE webhooks SET created_at=created_at WHERE id=''"),
            Pool::Postgres(p) => insert!(p, "SELECT pg_advisory_xact_lock(75678021)"),
        }
    }

    pub async fn rotate_hook(&self, id: &str, hash: &str, secret: &[u8]) -> Result<()> {
        db!(self,p,sqlx::query("UPDATE webhooks SET token_hash=$2,sealed_secret=$3,suspended_reason=NULL WHERE id=$1 AND revoked_at IS NULL").bind(id).bind(hash).bind(secret).execute(p).await?.rows_affected());
        Ok(())
    }
    pub async fn revoke_hook(&self, id: &str) -> Result<()> {
        db!(
            self,
            p,
            sqlx::query(
                "UPDATE webhooks SET revoked_at=$2,token_hash='',sealed_secret=$3 WHERE id=$1"
            )
            .bind(id)
            .bind(crate::webhooks::now_ms())
            .bind(Vec::<u8>::new())
            .execute(p)
            .await?
            .rows_affected()
        );
        db!(
            self,
            p,
            sqlx::query("DELETE FROM webhook_outbox WHERE hook_id=$1")
                .bind(id)
                .execute(p)
                .await?
                .rows_affected()
        );
        Ok(())
    }
    /// Incoming receipt, message and outgoing events commit together. Same ID with a different body is rejected.
    pub async fn save_webhook_message(
        &self,
        msg: &ChatMessagePayload,
        receipt: Option<(&str, &str, &str, &str)>,
    ) -> Result<bool> {
        let event_id = uuid::Uuid::new_v4().to_string();
        let event=serde_json::json!({"type":"message.created","id":event_id,"occurred_at":crate::webhooks::now_ms(),"message":{"id":msg.message_id.chars().take(128).collect::<String>(),"id_truncated":msg.message_id.chars().count()>128,"channel_id":msg.channel_id,"sender_id":msg.sender_id,"content":msg.content.chars().take(8000).collect::<String>(),"content_truncated":msg.content.chars().count()>8000,"timestamp":msg.timestamp}}).to_string();
        macro_rules! save { ($p:expr,$lock:literal) => {{
                let mut tx = $p.begin().await?;
                // Serialize capacity checks and receipt inserts across concurrent publishers.
                sqlx::query($lock).execute(&mut *tx).await?;
                if let Some((hook, delivery, hash, token_hash)) = receipt {
                    // Lock and revalidate the credential immediately before persistence, so rotation/revocation cannot race a waiting delivery.
                    let active=sqlx::query("UPDATE webhooks SET created_at=created_at WHERE id=$1 AND token_hash=$2 AND channel_id=$3 AND revoked_at IS NULL AND direction='incoming'").bind(hook).bind(token_hash).bind(&msg.channel_id).execute(&mut *tx).await?.rows_affected();
                    anyhow::ensure!(active == 1, "webhook credential no longer active");
                    let found = sqlx::query_as::<_, (String,)>(
                        "SELECT body_hash FROM webhook_receipts WHERE hook_id=$1 AND delivery_id=$2",
                    )
                    .bind(hook)
                    .bind(delivery)
                    .fetch_optional(&mut *tx)
                    .await?;
                    if let Some((old,)) = found {
                        anyhow::ensure!(old == hash, "idempotency conflict");
                        return Ok(false);
                    }
                    // Keep at most 4096 receipts per hook; expiration bounds disk usage and the replay window.
                    sqlx::query("DELETE FROM webhook_receipts WHERE hook_id=$1 AND created_at<$2")
                        .bind(hook)
                        .bind(crate::webhooks::now_ms() - 86_400_000)
                        .execute(&mut *tx)
                        .await?;
                    let (count,): (i64,) =
                        sqlx::query_as("SELECT COUNT(*) FROM webhook_receipts WHERE hook_id=$1")
                            .bind(hook)
                            .fetch_one(&mut *tx)
                            .await?;
                    anyhow::ensure!(count < 4096, "receipt capacity reached");
                    sqlx::query("INSERT INTO webhook_receipts(hook_id,delivery_id,body_hash,message_id,created_at) VALUES($1,$2,$3,$4,$5)").bind(hook).bind(delivery).bind(hash).bind(&msg.message_id).bind(crate::webhooks::now_ms()).execute(&mut *tx).await?;
                }
                let inserted=sqlx::query("INSERT INTO messages(id,channel_id,sender_id,content,timestamp,reply_to) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO NOTHING").bind(&msg.message_id).bind(&msg.channel_id).bind(&msg.sender_id).bind(&msg.content).bind(msg.timestamp).bind(&msg.reply_to).execute(&mut *tx).await?.rows_affected()>0;
                if inserted {
                    let hooks=sqlx::query_as::<_,(String,)>("SELECT id FROM webhooks WHERE channel_id=$1 AND direction='outgoing' AND revoked_at IS NULL AND suspended_reason IS NULL LIMIT 32").bind(&msg.channel_id).fetch_all(&mut *tx).await?;
                    for (hook,) in hooks {
                        let (total,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM webhook_outbox")
                            .fetch_one(&mut *tx)
                            .await?;
                        let (own,): (i64,) =
                            sqlx::query_as("SELECT COUNT(*) FROM webhook_outbox WHERE hook_id=$1")
                                .bind(&hook)
                                .fetch_one(&mut *tx)
                                .await?;
                        if total >= 2048 || own >= 128 {
                            sqlx::query("UPDATE webhooks SET suspended_reason='queue_full' WHERE id=$1")
                                .bind(&hook)
                                .execute(&mut *tx)
                                .await?;
                            continue;
                        }
                        sqlx::query("INSERT INTO webhook_outbox(id,hook_id,body,next_at) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO NOTHING").bind(format!("{}:{}",hook,event_id)).bind(&hook).bind(&event).bind(crate::webhooks::now_ms()).execute(&mut *tx).await?;
                    }
                }
                tx.commit().await?;
                Ok(inserted)
        }}; }
        match &self.pool {
            Pool::Sqlite(p) => save!(p, "UPDATE webhooks SET created_at=created_at WHERE id=''"),
            Pool::Postgres(p) => save!(p, "SELECT pg_advisory_xact_lock(75678021)"),
        }
    }
    pub async fn due_webhooks(&self) -> Result<Vec<Delivery>> {
        Ok(db!(self,p,sqlx::query_as::<_,Delivery>("SELECT id,hook_id,body,attempts FROM webhook_outbox WHERE next_at<=$1 ORDER BY next_at LIMIT 16").bind(crate::webhooks::now_ms()).fetch_all(p).await?))
    }
    pub async fn finish_webhook(&self, d: &Delivery, success: bool) -> Result<()> {
        if success || d.attempts >= 7 {
            db!(
                self,
                p,
                sqlx::query("DELETE FROM webhook_outbox WHERE id=$1")
                    .bind(&d.id)
                    .execute(p)
                    .await?
                    .rows_affected()
            );
        } else {
            let next =
                crate::webhooks::now_ms() + 1000 * (1_i64 << ((d.attempts + 1).min(10) as u32));
            db!(
                self,
                p,
                sqlx::query("UPDATE webhook_outbox SET attempts=attempts+1,next_at=$2 WHERE id=$1")
                    .bind(&d.id)
                    .bind(next)
                    .execute(p)
                    .await?
                    .rows_affected()
            );
        }
        Ok(())
    }
}
