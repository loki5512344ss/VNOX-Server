pub mod email;
pub mod provider;
mod routes;
pub mod store;

use sqlx::SqlitePool;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use url::Url;

use provider::{GitHubProvider, IdentityProvider};
pub use routes::router;

/// Secrets are never Debug/Serialize and never sent to browser or community nodes.
pub struct GitHubConfig {
    pub client_id: String,
    pub client_secret: String,
}

pub struct AuthService {
    pub pool: SqlitePool,
    pub origin: Url,
    pub provider: Option<Arc<dyn IdentityProvider>>,
    /// Present only when a mail transport is configured.
    pub email: Option<email::EmailAuth>,
    limits: Mutex<HashMap<String, (i64, u32)>>,
    avatar_events: Mutex<HashMap<String, Vec<i64>>>,
    /// Bounds concurrent image decodes, which are the most expensive thing a session can ask for.
    pub avatar_decoding: tokio::sync::Semaphore,
}

/// Avatar changes (upload or removal) per account and per source within one hour.
const AVATAR_PER_USER_HOUR: usize = 10;
const AVATAR_PER_SOURCE_HOUR: usize = 30;
const AVATAR_WINDOW: i64 = 3600;
const AVATAR_TRACKED_KEYS: usize = 8192;

impl AuthService {
    pub fn new(
        pool: SqlitePool,
        origin: Url,
        config: Option<&GitHubConfig>,
    ) -> anyhow::Result<Self> {
        let provider = config
            .map(|config| {
                GitHubProvider::new(config, &origin)
                    .map(|provider| Arc::new(provider) as Arc<dyn IdentityProvider>)
            })
            .transpose()?;
        Ok(Self::with_provider(pool, origin, provider))
    }
    pub fn with_provider(
        pool: SqlitePool,
        origin: Url,
        provider: Option<Arc<dyn IdentityProvider>>,
    ) -> Self {
        Self {
            pool,
            origin,
            provider,
            email: None,
            limits: Mutex::new(HashMap::new()),
            avatar_events: Mutex::new(HashMap::new()),
            avatar_decoding: tokio::sync::Semaphore::new(2),
        }
    }
    /// Enables email sign-in. Callers do this only when SMTP is configured (or a test sender).
    pub fn with_email(mut self, email: email::EmailAuth) -> Self {
        self.email = Some(email);
        self
    }
    pub fn email_enabled(&self) -> bool {
        self.email.is_some()
    }
    pub fn configured(&self) -> bool {
        self.provider.is_some()
    }
    pub fn allow(&self, ip: &str) -> bool {
        let Ok(mut limits) = self.limits.lock() else {
            return false;
        };
        let now = store::now();
        limits.retain(|_, (start, _)| now - *start < 60);
        if limits.len() > 4096 {
            return false;
        }
        if limits.get(ip).is_some_and(|(_, count)| *count >= 20) {
            return false;
        }
        let global = limits.entry("global".into()).or_insert((now, 0));
        if global.1 >= 300 {
            return false;
        }
        global.1 += 1;
        limits.entry(ip.to_owned()).or_insert((now, 0)).1 += 1;
        true
    }
    /// Records one avatar change attempt for `user` and `source` and reports whether both
    /// budgets still had room. A refused attempt is not recorded, so a blocked client does
    /// not extend its own block.
    pub fn allow_avatar(&self, user: &str, source: &str) -> bool {
        let Ok(mut events) = self.avatar_events.lock() else {
            return false;
        };
        let now = store::now();
        events.retain(|_, times| {
            times.retain(|at| now - *at < AVATAR_WINDOW);
            !times.is_empty()
        });
        let user_key = format!("u:{user}");
        let source_key = format!("s:{source}");
        let count = |key: &str| events.get(key).map_or(0, Vec::len);
        if count(&user_key) >= AVATAR_PER_USER_HOUR
            || count(&source_key) >= AVATAR_PER_SOURCE_HOUR
            || events.len() + 2 > AVATAR_TRACKED_KEYS
        {
            return false;
        }
        events.entry(user_key).or_default().push(now);
        events.entry(source_key).or_default().push(now);
        true
    }
}
