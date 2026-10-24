pub mod layout;
pub mod templates;

use std::time::Duration;

use anyhow::{Context, Result, bail};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Tokio1Executor,
    message::{Mailbox, Message, MultiPart},
    transport::smtp::authentication::Credentials,
};

use crate::config::SmtpConfig;

/// TLS-only SMTP transport, deliberately without Debug or credential logging.
pub struct Mailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl Mailer {
    pub fn new(config: &SmtpConfig) -> Result<Self> {
        let builder = if config.port == 465 {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
        }
        .context("invalid SMTP TLS hostname")?;
        let mut builder = builder
            .port(config.port)
            .timeout(Some(Duration::from_secs(15)));
        if !config.user.is_empty() {
            builder = builder.credentials(Credentials::new(
                config.user.clone(),
                config.password.clone(),
            ));
        }
        Ok(Self {
            transport: builder.build(),
            from: config.from.parse().context("MAIL_FROM must be a mailbox")?,
        })
    }

    /// Connect, negotiate TLS, authenticate and issue NOOP; never sends a message.
    pub async fn check_connection(&self) -> Result<()> {
        match self.transport.test_connection().await {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => bail!("SMTP TLS/authentication check failed"),
        }
    }

    /// Internal transport only. There is intentionally no public send-email HTTP endpoint.
    pub async fn deliver(&self, recipient: &str, email: templates::Email) -> Result<()> {
        let message = Message::builder()
            .from(self.from.clone())
            .to(recipient.parse().context("invalid recipient mailbox")?)
            .subject(email.subject)
            .multipart(MultiPart::alternative_plain_html(email.text, email.html))?;
        self.transport
            .send(message)
            .await
            .map_err(|_| anyhow::anyhow!("SMTP delivery failed"))?;
        Ok(())
    }
}
