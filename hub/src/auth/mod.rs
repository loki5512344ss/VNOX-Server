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
    limits: Mutex<HashMap<String, (i64, u32)>>,
}

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
            limits: Mutex::new(HashMap::new()),
        }
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
}
