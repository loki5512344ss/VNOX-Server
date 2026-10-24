use std::{path::Path, time::Duration};

use anyhow::{Context, Result, bail};
use sqlx::{SqlitePool, sqlite::SqliteConnectOptions};

use crate::identity::Issuer;

pub async fn open(directory: &Path, issuer: &Issuer) -> Result<SqlitePool> {
    let options = SqliteConnectOptions::new()
        .filename(directory.join("hub.sqlite3"))
        .create_if_missing(true)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await
        .context("opening Hub database")?;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("migrating Hub database")?;
    let mut transaction = pool.begin().await?;
    for (name, value) in [
        ("issuer_id", issuer.id.to_string()),
        ("issuer_public_key", issuer.public_key.clone()),
    ] {
        sqlx::query("INSERT OR IGNORE INTO hub_metadata(key,value) VALUES (?,?)")
            .bind(name)
            .bind(&value)
            .execute(&mut *transaction)
            .await?;
        let existing: String = sqlx::query_scalar("SELECT value FROM hub_metadata WHERE key=?")
            .bind(name)
            .fetch_one(&mut *transaction)
            .await?;
        if existing != value {
            bail!("Hub database and issuer identity do not match; restore them together");
        }
    }
    transaction.commit().await?;
    Ok(pool)
}
