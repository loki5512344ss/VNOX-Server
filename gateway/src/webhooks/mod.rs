//! Channel-scoped incoming integrations and bounded signed outgoing delivery.
pub mod incoming;
pub mod management;
pub mod outgoing;
pub mod policy;
pub mod secrets;

use anyhow::{Result, bail};
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::Instant,
};

pub const MAX_BODY: usize = 64 * 1024;
pub const MAX_CONTENT: usize = 4000;

/// Secrets are intentionally not Debug and never enter request URLs or logs.
pub struct Runtime {
    deliveries: tokio::sync::Semaphore,
    key: OnceLock<[u8; 32]>,
    rates: Mutex<HashMap<String, (f64, Instant)>>,
}

impl Default for Runtime {
    fn default() -> Self {
        Self {
            deliveries: tokio::sync::Semaphore::new(64),
            key: OnceLock::new(),
            rates: Mutex::new(HashMap::new()),
        }
    }
}

impl Runtime {
    pub fn configure_from_env(&self) -> Result<()> {
        if let Ok(encoded) = std::env::var("VNOX_WEBHOOK_SECRET_KEY") {
            let raw = hex::decode(encoded.trim())
                .ok()
                .and_then(|v| v.try_into().ok());
            let Some(key) = raw else {
                bail!("VNOX_WEBHOOK_SECRET_KEY must contain exactly 32 hex-encoded bytes")
            };
            self.set_key(key)?;
        }
        Ok(())
    }

    pub fn set_key(&self, key: [u8; 32]) -> Result<()> {
        self.key
            .set(key)
            .map_err(|_| anyhow::anyhow!("webhook master key already configured"))
    }

    pub fn key(&self) -> Option<&[u8; 32]> {
        self.key.get()
    }

    pub fn consume(&self, id: &str) -> bool {
        let Ok(mut rates) = self.rates.lock() else {
            return false;
        };
        if rates.len() >= 4096 {
            rates.retain(|_, (_, at)| at.elapsed().as_secs() < 300);
            if !rates.contains_key(id) && rates.len() >= 4096 {
                return false;
            }
        }
        let (tokens, last) = rates.entry(id.into()).or_insert((10.0, Instant::now()));
        *tokens = (*tokens + last.elapsed().as_secs_f64() * 2.0).min(10.0);
        *last = Instant::now();
        if *tokens < 1.0 {
            return false;
        }
        *tokens -= 1.0;
        true
    }
}

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub(crate) fn valid_content(content: &str) -> bool {
    let lowered = content.to_lowercase();
    !content.trim().is_empty()
        && content.chars().count() <= MAX_CONTENT
        && !lowered.contains("@everyone")
        && !lowered.contains("@here")
        && !lowered.contains("<@")
        && !content
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
}

#[cfg(test)]
mod tests;
