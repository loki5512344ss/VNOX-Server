//! Single-process durable worker. Every attempt validates and pins all DNS results.
use super::{management, now_ms, policy, secrets};
use crate::{
    domain::storage::webhooks::{Delivery, Hook},
    net::state::State,
};
use std::time::Duration;

pub async fn run(state: State) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        interval.tick().await;
        let jobs = match state.storage.due_webhooks().await {
            Ok(j) => j,
            Err(_) => {
                tracing::warn!("webhook outbox read failed");
                continue;
            }
        };
        for job in jobs {
            let hook = match state.storage.hook(&job.hook_id).await {
                Ok(Some(h)) if h.revoked_at.is_none() => h,
                Ok(_) => {
                    let _ = state.storage.finish_webhook(&job, true).await;
                    continue;
                }
                Err(_) => {
                    tracing::warn!("webhook configuration read failed");
                    continue;
                }
            };
            // Never forward channel contents after the integration creator loses permission.
            let authorized = management::authorize(&state, &hook.creator_id, &hook.channel_id)
                .await
                .ok()
                .flatten()
                .as_deref()
                == Some(hook.guild_id.as_str());
            let success = authorized && attempt(&state, &hook, &job).await.is_ok();
            if state.storage.finish_webhook(&job, success).await.is_err() {
                tracing::warn!("webhook outbox update failed")
            }
        }
    }
}
async fn attempt(state: &State, hook: &Hook, job: &Delivery) -> anyhow::Result<()> {
    let key = state
        .webhooks
        .key()
        .ok_or_else(|| anyhow::anyhow!("signing unavailable"))?;
    let secret = secrets::open(key, &hook.id, &hook.sealed_secret)?;
    let url = policy::endpoint(&hook.endpoint)?;
    let addresses = policy::resolve(&url).await?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("missing host"))?;
    let client = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .resolve_to_addrs(host, &addresses)
        .build()?;
    let timestamp = (now_ms() / 1000).to_string();
    let signed = format!("{timestamp}.{}", job.body);
    let response = client
        .post(url)
        .header("content-type", "application/json")
        .header("x-vnox-delivery", &job.id)
        .header("x-vnox-timestamp", timestamp)
        .header(
            "x-vnox-signature",
            format!("sha256={}", secrets::sign(&secret, signed.as_bytes())),
        )
        .body(job.body.clone())
        .send()
        .await?;
    anyhow::ensure!(response.status().is_success(), "delivery not accepted");
    // The response body is deliberately never buffered or logged.
    Ok(())
}
