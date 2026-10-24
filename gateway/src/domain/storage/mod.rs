pub mod dm_unread;
pub mod dms;
pub mod e2ee_dms;
pub mod guilds;
pub mod messages;
pub mod presence;
pub mod social;

use anyhow::Result;
use sqlx::{PgPool, SqlitePool};
use tracing::info;

pub enum Pool {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

pub struct Storage {
    pub pool: Pool,
}

impl Storage {
    pub async fn connect_sqlite(path: &str) -> Result<Self> {
        if let Some(p) = std::path::Path::new(path).parent() {
            tokio::fs::create_dir_all(p).await?;
        }
        let pool = SqlitePool::connect(&format!("sqlite://{}?mode=rwc", path)).await?;
        let s = Self {
            pool: Pool::Sqlite(pool),
        };
        s.migrate().await?;
        info!("storage (sqlite): {path}");
        Ok(s)
    }

    pub async fn connect_postgres(url: &str) -> Result<Self> {
        let pool = PgPool::connect(url).await?;
        let s = Self {
            pool: Pool::Postgres(pool),
        };
        s.migrate().await?;
        info!("storage (postgres): connected");
        Ok(s)
    }

    async fn migrate(&self) -> Result<()> {
        match &self.pool {
            Pool::Sqlite(p) => {
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS messages (
                        id TEXT PRIMARY KEY, channel_id TEXT NOT NULL,
                        sender_id TEXT NOT NULL, content TEXT NOT NULL,
                        timestamp INTEGER NOT NULL
                     );
                     CREATE INDEX IF NOT EXISTS idx_msg_ch ON messages (channel_id, timestamp);
                     CREATE TABLE IF NOT EXISTS users (
                        pubkey TEXT PRIMARY KEY, nickname TEXT NOT NULL, first_seen INTEGER NOT NULL
                     );
                     CREATE TABLE IF NOT EXISTS channels (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        kind TEXT NOT NULL DEFAULT 'text',
                        guild_id TEXT,
                        created_at INTEGER NOT NULL
                     );
                     CREATE TABLE IF NOT EXISTS bans (
                        pubkey TEXT PRIMARY KEY, reason TEXT, banned_at INTEGER NOT NULL
                     );
                     CREATE TABLE IF NOT EXISTS direct_messages (
                        id TEXT PRIMARY KEY,
                        user1_id TEXT NOT NULL,
                        user2_id TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        last_message_at INTEGER,
                        unread_count_1 INTEGER NOT NULL DEFAULT 0,
                        unread_count_2 INTEGER NOT NULL DEFAULT 0,
                        UNIQUE(user1_id, user2_id)
                     );
                     CREATE TABLE IF NOT EXISTS dm_messages (
                        id TEXT PRIMARY KEY,
                        dm_id TEXT NOT NULL REFERENCES direct_messages(id),
                        sender_id TEXT NOT NULL,
                        body TEXT NOT NULL,
                        created_at INTEGER NOT NULL
                     );
                     CREATE INDEX IF NOT EXISTS idx_dm_msg_dm ON dm_messages(dm_id, created_at);
                     CREATE TABLE IF NOT EXISTS guilds (
                        id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, name TEXT NOT NULL,
                        created_at INTEGER NOT NULL
                     );
                     CREATE TABLE IF NOT EXISTS guild_members (
                        guild_id TEXT NOT NULL, user_id TEXT NOT NULL,
                        joined_at INTEGER NOT NULL, PRIMARY KEY(guild_id, user_id)
                     );
                     CREATE INDEX IF NOT EXISTS idx_gm_user ON guild_members(user_id);
                     CREATE TABLE IF NOT EXISTS roles (
                        id TEXT PRIMARY KEY, guild_id TEXT NOT NULL, name TEXT NOT NULL,
                        color TEXT NOT NULL DEFAULT '#ffffff',
                        permissions INTEGER NOT NULL DEFAULT 0,
                        position INTEGER NOT NULL DEFAULT 0,
                        created_at INTEGER NOT NULL
                     );
                     CREATE INDEX IF NOT EXISTS idx_roles_guild ON roles(guild_id);
                     CREATE TABLE IF NOT EXISTS invites (
                        id TEXT PRIMARY KEY, guild_id TEXT NOT NULL, creator_id TEXT NOT NULL,
                        code TEXT NOT NULL UNIQUE, max_uses INTEGER,
                        uses INTEGER NOT NULL DEFAULT 0,
                        expires_at INTEGER, created_at INTEGER NOT NULL
                     );
                     CREATE INDEX IF NOT EXISTS idx_invites_code ON invites(code);
                     CREATE TABLE IF NOT EXISTS member_roles (
                        guild_id TEXT NOT NULL, user_id TEXT NOT NULL, role_id TEXT NOT NULL,
                        PRIMARY KEY(guild_id, user_id, role_id)
                     );
                     CREATE TABLE IF NOT EXISTS friend_requests (
                        id TEXT PRIMARY KEY, from_user_id TEXT NOT NULL, to_user_id TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'PENDING', created_at INTEGER NOT NULL,
                        UNIQUE(from_user_id, to_user_id)
                     );
                     CREATE TABLE IF NOT EXISTS friendships (
                        user_id_1 TEXT NOT NULL, user_id_2 TEXT NOT NULL,
                        created_at INTEGER NOT NULL, PRIMARY KEY(user_id_1, user_id_2)
                     );
                     CREATE TABLE IF NOT EXISTS read_receipts (
                        channel_id TEXT NOT NULL, user_id TEXT NOT NULL,
                        last_read_message_id TEXT NOT NULL, updated_at INTEGER NOT NULL,
                        PRIMARY KEY(channel_id, user_id)
                     );
                     CREATE TABLE IF NOT EXISTS e2ee_dm_messages (
                        id TEXT PRIMARY KEY,
                        dm_id TEXT NOT NULL,
                        sender_id TEXT NOT NULL,
                        ciphertext BLOB NOT NULL,
                        created_at INTEGER NOT NULL
                     );
                     CREATE INDEX IF NOT EXISTS idx_e2ee_dm_msg_dm ON e2ee_dm_messages(dm_id, created_at);
                     CREATE TABLE IF NOT EXISTS blocks (
                        blocker_id TEXT NOT NULL, blocked_id TEXT NOT NULL,
                        created_at INTEGER NOT NULL, PRIMARY KEY(blocker_id, blocked_id)
                     );
                     CREATE TABLE IF NOT EXISTS reactions (
                        message_id TEXT, user_id TEXT, emoji TEXT, created_at INTEGER,
                        PRIMARY KEY(message_id, user_id, emoji)
                     );
                     CREATE TABLE IF NOT EXISTS audit_logs (
                        id TEXT PRIMARY KEY, guild_id TEXT NOT NULL, actor_id TEXT NOT NULL,
                        action TEXT NOT NULL, target_id TEXT,
                        target_type TEXT, reason TEXT, changes TEXT,
                        created_at INTEGER NOT NULL
                     );
                     CREATE INDEX IF NOT EXISTS idx_audit_guild ON audit_logs(guild_id, created_at);
                     CREATE TABLE IF NOT EXISTS presences (
                        user_id TEXT PRIMARY KEY,
                        nickname TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'OFFLINE',
                        activity_type TEXT,
                        activity_text TEXT,
                        last_seen INTEGER NOT NULL
                     );",
                )
                .execute(p)
                .await?;
            }
            Pool::Postgres(p) => {
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS messages (
                        id TEXT PRIMARY KEY, channel_id TEXT NOT NULL,
                        sender_id TEXT NOT NULL, content TEXT NOT NULL,
                        timestamp BIGINT NOT NULL
                     );
                     CREATE INDEX IF NOT EXISTS idx_msg_ch ON messages (channel_id, timestamp);
                     CREATE TABLE IF NOT EXISTS users (
                        pubkey TEXT PRIMARY KEY, nickname TEXT NOT NULL, first_seen BIGINT NOT NULL
                     );
                     CREATE TABLE IF NOT EXISTS channels (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        kind TEXT NOT NULL DEFAULT 'text',
                        guild_id TEXT,
                        created_at BIGINT NOT NULL
                     );
                     CREATE TABLE IF NOT EXISTS bans (
                        pubkey TEXT PRIMARY KEY, reason TEXT, banned_at BIGINT NOT NULL
                     );
                     CREATE TABLE IF NOT EXISTS direct_messages (
                        id TEXT PRIMARY KEY,
                        user1_id TEXT NOT NULL,
                        user2_id TEXT NOT NULL,
                        created_at BIGINT NOT NULL,
                        last_message_at BIGINT,
                        unread_count_1 BIGINT NOT NULL DEFAULT 0,
                        unread_count_2 BIGINT NOT NULL DEFAULT 0,
                        UNIQUE(user1_id, user2_id)
                     );
                     CREATE TABLE IF NOT EXISTS dm_messages (
                        id TEXT PRIMARY KEY,
                        dm_id TEXT NOT NULL REFERENCES direct_messages(id),
                        sender_id TEXT NOT NULL,
                        body TEXT NOT NULL,
                        created_at BIGINT NOT NULL
                     );
                     CREATE INDEX IF NOT EXISTS idx_dm_msg_dm ON dm_messages(dm_id, created_at);
                     CREATE TABLE IF NOT EXISTS guilds (
                        id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, name TEXT NOT NULL,
                        created_at BIGINT NOT NULL
                     );
                     CREATE TABLE IF NOT EXISTS guild_members (
                        guild_id TEXT NOT NULL, user_id TEXT NOT NULL,
                        joined_at BIGINT NOT NULL, PRIMARY KEY(guild_id, user_id)
                     );
                     CREATE INDEX IF NOT EXISTS idx_gm_user ON guild_members(user_id);
                     CREATE TABLE IF NOT EXISTS roles (
                        id TEXT PRIMARY KEY, guild_id TEXT NOT NULL, name TEXT NOT NULL,
                        color TEXT NOT NULL DEFAULT '#ffffff',
                        permissions BIGINT NOT NULL DEFAULT 0,
                        position INTEGER NOT NULL DEFAULT 0,
                        created_at BIGINT NOT NULL
                     );
                     CREATE INDEX IF NOT EXISTS idx_roles_guild ON roles(guild_id);
                     CREATE TABLE IF NOT EXISTS invites (
                        id TEXT PRIMARY KEY, guild_id TEXT NOT NULL, creator_id TEXT NOT NULL,
                        code TEXT NOT NULL UNIQUE, max_uses BIGINT,
                        uses BIGINT NOT NULL DEFAULT 0,
                        expires_at BIGINT, created_at BIGINT NOT NULL
                     );
                     CREATE INDEX IF NOT EXISTS idx_invites_code ON invites(code);
                     CREATE TABLE IF NOT EXISTS member_roles (
                        guild_id TEXT NOT NULL, user_id TEXT NOT NULL, role_id TEXT NOT NULL,
                        PRIMARY KEY(guild_id, user_id, role_id)
                     );
                     CREATE TABLE IF NOT EXISTS friend_requests (
                        id TEXT PRIMARY KEY, from_user_id TEXT NOT NULL, to_user_id TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'PENDING', created_at BIGINT NOT NULL,
                        UNIQUE(from_user_id, to_user_id)
                     );
                     CREATE TABLE IF NOT EXISTS friendships (
                        user_id_1 TEXT NOT NULL, user_id_2 TEXT NOT NULL,
                        created_at BIGINT NOT NULL, PRIMARY KEY(user_id_1, user_id_2)
                     );
                     CREATE TABLE IF NOT EXISTS read_receipts (
                        channel_id TEXT NOT NULL, user_id TEXT NOT NULL,
                        last_read_message_id TEXT NOT NULL, updated_at BIGINT NOT NULL,
                        PRIMARY KEY(channel_id, user_id)
                     );
                     CREATE TABLE IF NOT EXISTS e2ee_dm_messages (
                        id TEXT PRIMARY KEY,
                        dm_id TEXT NOT NULL,
                        sender_id TEXT NOT NULL,
                        ciphertext BYTEA NOT NULL,
                        created_at BIGINT NOT NULL
                     );
                     CREATE INDEX IF NOT EXISTS idx_e2ee_dm_msg_dm ON e2ee_dm_messages(dm_id, created_at);
                     CREATE TABLE IF NOT EXISTS blocks (
                        blocker_id TEXT NOT NULL, blocked_id TEXT NOT NULL,
                        created_at BIGINT NOT NULL, PRIMARY KEY(blocker_id, blocked_id)
                     );
                     CREATE TABLE IF NOT EXISTS reactions (
                        message_id TEXT, user_id TEXT, emoji TEXT, created_at BIGINT,
                        PRIMARY KEY(message_id, user_id, emoji)
                     );
                     CREATE TABLE IF NOT EXISTS audit_logs (
                        id TEXT PRIMARY KEY, guild_id TEXT NOT NULL, actor_id TEXT NOT NULL,
                        action TEXT NOT NULL, target_id TEXT,
                        target_type TEXT, reason TEXT, changes TEXT,
                        created_at BIGINT NOT NULL
                     );
                     CREATE INDEX IF NOT EXISTS idx_audit_guild ON audit_logs(guild_id, created_at);
                     CREATE TABLE IF NOT EXISTS presences (
                        user_id TEXT PRIMARY KEY,
                        nickname TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'OFFLINE',
                        activity_type TEXT,
                        activity_text TEXT,
                        last_seen BIGINT NOT NULL
                     );",
                )
                .execute(p)
                .await?;
            }
        }

        self.ensure_column("messages", "reply_to", "TEXT").await?;
        Ok(())
    }

    async fn ensure_column(
        &self,
        table: &'static str,
        col: &'static str,
        decl: &'static str,
    ) -> Result<()> {
        match &self.pool {
            Pool::Sqlite(p) => {
                use sqlx::AssertSqlSafe;
                type PragmaRow = (i64, String, String, i64, Option<String>, i64);
                let pragma = format!("PRAGMA table_info({table})");
                let rows: Result<Vec<PragmaRow>, _> =
                    sqlx::query_as::<_, PragmaRow>(AssertSqlSafe(pragma.clone()))
                        .fetch_all(p)
                        .await;
                let rows = match rows {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!("ensure_column: PRAGMA failed: {e}");
                        return Ok(());
                    }
                };
                if rows.iter().any(|(_, name, _, _, _, _)| name == col) {
                    return Ok(());
                }
                let alter = format!("ALTER TABLE {table} ADD COLUMN {col} {decl}");
                sqlx::query(AssertSqlSafe(alter)).execute(p).await?;
                info!("storage: added column {table}.{col}");
                Ok(())
            }
            Pool::Postgres(p) => {
                use sqlx::AssertSqlSafe;
                let exists: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name=$1 AND column_name=$2)",
                )
                .bind(table)
                .bind(col)
                .fetch_one(p)
                .await?;
                if !exists {
                    let alter = format!("ALTER TABLE {table} ADD COLUMN {col} {decl}");
                    sqlx::query(AssertSqlSafe(alter)).execute(p).await?;
                    info!("storage: added column {table}.{col}");
                }
                Ok(())
            }
        }
    }

    pub async fn upsert_user(&self, pubkey: &str, nickname: &str) -> Result<()> {
        match &self.pool {
            Pool::Sqlite(p) => {
                sqlx::query(
                    "INSERT OR IGNORE INTO users (pubkey,nickname,first_seen) VALUES (?,?,?)",
                )
                .bind(pubkey)
                .bind(nickname)
                .bind(now_ms())
                .execute(p)
                .await?;
            }
            Pool::Postgres(p) => {
                sqlx::query(
                    "INSERT INTO users (pubkey,nickname,first_seen) VALUES ($1,$2,$3) ON CONFLICT (pubkey) DO NOTHING",
                )
                .bind(pubkey)
                .bind(nickname)
                .bind(now_ms())
                .execute(p)
                .await?;
            }
        }
        Ok(())
    }

    pub async fn is_banned(&self, pubkey: &str) -> Result<bool> {
        match &self.pool {
            Pool::Sqlite(p) => Ok(sqlx::query_as::<_, (String,)>(
                "SELECT pubkey FROM bans WHERE pubkey=?",
            )
            .bind(pubkey)
            .fetch_optional(p)
            .await?
            .is_some()),
            Pool::Postgres(p) => Ok(sqlx::query_as::<_, (String,)>(
                "SELECT pubkey FROM bans WHERE pubkey=$1",
            )
            .bind(pubkey)
            .fetch_optional(p)
            .await?
            .is_some()),
        }
    }

    pub async fn append_audit_log(
        &self,
        guild_id: &str,
        actor_id: &str,
        action: &str,
        target_id: Option<&str>,
        target_type: Option<&str>,
        reason: Option<&str>,
    ) -> Result<()> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_ms();
        match &self.pool {
            Pool::Sqlite(p) => {
                sqlx::query(
                    "INSERT INTO audit_logs (id,guild_id,actor_id,action,target_id,target_type,reason,created_at) \
                     VALUES (?,?,?,?,?,?,?,?)",
                )
                .bind(&id)
                .bind(guild_id)
                .bind(actor_id)
                .bind(action)
                .bind(target_id)
                .bind(target_type)
                .bind(reason)
                .bind(now)
                .execute(p)
                .await?;
            }
            Pool::Postgres(p) => {
                sqlx::query(
                    "INSERT INTO audit_logs (id,guild_id,actor_id,action,target_id,target_type,reason,created_at) \
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
                )
                .bind(&id)
                .bind(guild_id)
                .bind(actor_id)
                .bind(action)
                .bind(target_id)
                .bind(target_type)
                .bind(reason)
                .bind(now)
                .execute(p)
                .await?;
            }
        }
        Ok(())
    }
}

pub(crate) fn generate_invite_code() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let hash = RandomState::new().build_hasher().finish();
    format!("{:08x}", hash % 0x100000000u64)
}

use crate::domain::channels::{ChannelKind, ChannelStore};

#[derive(Debug, Clone)]
pub struct ChannelRecord {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub guild_id: Option<String>,
    pub created_at: i64,
}

impl Storage {
    pub async fn create_channel(
        &self,
        id: &str,
        name: &str,
        kind: &str,
        guild_id: Option<&str>,
    ) -> Result<bool> {
        match &self.pool {
            Pool::Sqlite(p) => {
                let result = sqlx::query(
                    "INSERT OR IGNORE INTO channels (id, name, kind, guild_id, created_at) VALUES (?, ?, ?, ?, ?)",
                )
                .bind(id)
                .bind(name)
                .bind(kind)
                .bind(guild_id)
                .bind(now_ms())
                .execute(p)
                .await?;
                Ok(result.rows_affected() > 0)
            }
            Pool::Postgres(p) => {
                let result = sqlx::query(
                    "INSERT INTO channels (id, name, kind, guild_id, created_at) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO NOTHING",
                )
                .bind(id)
                .bind(name)
                .bind(kind)
                .bind(guild_id)
                .bind(now_ms())
                .execute(p)
                .await?;
                Ok(result.rows_affected() > 0)
            }
        }
    }

    pub async fn update_channel(&self, id: &str, name: &str) -> Result<bool> {
        match &self.pool {
            Pool::Sqlite(p) => {
                let result = sqlx::query("UPDATE channels SET name=? WHERE id=?")
                    .bind(name)
                    .bind(id)
                    .execute(p)
                    .await?;
                Ok(result.rows_affected() > 0)
            }
            Pool::Postgres(p) => {
                let result = sqlx::query("UPDATE channels SET name=$1 WHERE id=$2")
                    .bind(name)
                    .bind(id)
                    .execute(p)
                    .await?;
                Ok(result.rows_affected() > 0)
            }
        }
    }

    pub async fn delete_channel(&self, id: &str) -> Result<bool> {
        match &self.pool {
            Pool::Sqlite(p) => {
                let result = sqlx::query("DELETE FROM channels WHERE id=?")
                    .bind(id)
                    .execute(p)
                    .await?;
                Ok(result.rows_affected() > 0)
            }
            Pool::Postgres(p) => {
                let result = sqlx::query("DELETE FROM channels WHERE id=$1")
                    .bind(id)
                    .execute(p)
                    .await?;
                Ok(result.rows_affected() > 0)
            }
        }
    }

    pub async fn list_channels(&self) -> Result<Vec<ChannelRecord>> {
        let rows = match &self.pool {
            Pool::Sqlite(p) => {
                sqlx::query_as::<_, (String, String, String, Option<String>, i64)>(
                    "SELECT id, name, kind, guild_id, created_at FROM channels",
                )
                .fetch_all(p)
                .await?
            }
            Pool::Postgres(p) => {
                sqlx::query_as::<_, (String, String, String, Option<String>, i64)>(
                    "SELECT id, name, kind, guild_id, created_at FROM channels",
                )
                .fetch_all(p)
                .await?
            }
        };
        Ok(rows
            .into_iter()
            .map(|(id, name, kind, guild_id, created_at)| ChannelRecord {
                id,
                name,
                kind,
                guild_id,
                created_at,
            })
            .collect())
    }

    pub async fn load_channels_to_cache(&self, channel_store: &ChannelStore) -> Result<()> {
        let channels = self.list_channels().await?;
        for ch in channels {
            let kind = match ch.kind.as_str() {
                "voice" => ChannelKind::Voice,
                _ => ChannelKind::Text,
            };
            crate::domain::channels::create(channel_store, &ch.id, &ch.name, kind, ch.guild_id)
                .await;
        }
        Ok(())
    }
}

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
