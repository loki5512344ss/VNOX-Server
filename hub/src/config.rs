use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result, bail};
use url::Url;

/// Public deployment configuration. Secret-bearing SMTP fields are intentionally not Debug.
pub struct Config {
    pub bind: SocketAddr,
    pub data_dir: PathBuf,
    pub origin: Url,
    pub smtp: Option<SmtpConfig>,
    pub github: Option<crate::auth::GitHubConfig>,
}

/// SMTP credentials are only read from the service environment, never command arguments.
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub from: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let bind = get("HUB_BIND")
            .unwrap_or_else(|| "127.0.0.1:17843".into())
            .parse::<SocketAddr>()
            .context("HUB_BIND must be an IP address and port")?;
        if !bind.ip().is_loopback() {
            bail!("HUB_BIND must be loopback; terminate HTTPS at the reverse proxy");
        }
        let origin = parse_origin(
            &get("PUBLIC_BASE_URL").unwrap_or_else(|| "https://central.loki-code.dev".into()),
        )?;
        let smtp_host = get("SMTP_HOST").unwrap_or_default();
        let smtp = if smtp_host.trim().is_empty() {
            if ["SMTP_USER", "SMTP_PASSWORD", "SMTP_PORT"]
                .iter()
                .any(|name| get(name).is_some_and(|value| !value.trim().is_empty()))
            {
                bail!("SMTP credentials/port require SMTP_HOST");
            }
            None
        } else {
            let port = get("SMTP_PORT")
                .unwrap_or_else(|| "587".into())
                .parse::<u16>()
                .context("SMTP_PORT must be a number")?;
            let user = get("SMTP_USER").unwrap_or_default();
            let password = get("SMTP_PASSWORD").unwrap_or_default();
            if user.is_empty() != password.is_empty() {
                bail!("SMTP_USER and SMTP_PASSWORD must be configured together");
            }
            if smtp_host.chars().any(char::is_whitespace)
                || smtp_host.contains('/')
                || smtp_host.contains('@')
            {
                bail!("SMTP_HOST must be a hostname, not a URL");
            }
            if port == 0 {
                bail!("SMTP_PORT cannot be zero");
            }
            Some(SmtpConfig {
                host: smtp_host,
                port,
                user,
                password,
                from: get("MAIL_FROM").unwrap_or_else(|| "Vnox <noreply@loki-code.dev>".into()),
            })
        };
        let github = match (get("GITHUB_CLIENT_ID"), get("GITHUB_CLIENT_SECRET")) {
            (None, None) => None,
            (Some(id), Some(secret))
                if !id.is_empty()
                    && !secret.is_empty()
                    && !id.chars().any(char::is_whitespace)
                    && !secret.chars().any(char::is_whitespace) =>
            {
                Some(crate::auth::GitHubConfig {
                    client_id: id,
                    client_secret: secret,
                })
            }
            _ => bail!("GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET must be configured together"),
        };
        Ok(Self {
            github,
            bind,
            origin,
            smtp,
            data_dir: get("HUB_DATA_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("./dev/hub-data")),
        })
    }
}

pub fn parse_origin(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("PUBLIC_BASE_URL must be an HTTPS origin")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        bail!("PUBLIC_BASE_URL must be an HTTPS origin without credentials, path or query");
    }
    Ok(url)
}
