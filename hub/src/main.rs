use std::{path::PathBuf, sync::Arc, time::Instant};

use anyhow::{Context, Result, bail};
use vnox_hub::{config::Config, database, identity::Issuer, mail, web};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vnox_hub=info".into()),
        )
        .init();
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args == ["--help"] {
        println!(
            "vnox-hub [--check-smtp | --render-email-preview DIRECTORY]\nConfiguration is read from the protected service environment. No send-email CLI is exposed."
        );
        return Ok(());
    }
    let config = Config::from_env()?;
    if args == ["--check-smtp"] {
        let smtp = config.smtp.as_ref().context("SMTP is not configured")?;
        mail::Mailer::new(smtp)?.check_connection().await?;
        println!("SMTP TLS and authentication verified; no email was sent.");
        return Ok(());
    }
    if args
        .first()
        .is_some_and(|arg| arg == "--render-email-preview")
        && args.len() == 2
    {
        mail::templates::write_previews(&PathBuf::from(&args[1]), &config.origin)?;
        println!(
            "Generated three HTML/plain-text previews with dummy credentials; no email was sent."
        );
        return Ok(());
    }
    if !args.is_empty() {
        bail!("unknown arguments; use --help");
    }
    let issuer = Issuer::load_or_create(&config.data_dir)?;
    let database = database::open(&config.data_dir, &issuer).await?;
    // Validate configured SMTP eagerly without making startup depend on the
    // availability of an external provider. There is no public mail endpoint.
    if let Some(smtp) = &config.smtp {
        mail::Mailer::new(smtp)?;
    }
    let state = Arc::new(web::HubState {
        database,
        issuer,
        smtp_configured: config.smtp.is_some(),
        started: Instant::now(),
    });
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .context("binding Hub listener")?;
    tracing::info!(address = %listener.local_addr()?, "Vnox Hub foundation listening");
    axum::serve(listener, web::router(state.clone()))
        .with_graceful_shutdown(shutdown())
        .await
        .context("serving Hub HTTP")?;
    state.database.close().await;
    Ok(())
}

async fn shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
