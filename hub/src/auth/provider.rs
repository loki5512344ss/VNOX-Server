use std::{future::Future, pin::Pin, time::Duration};

use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet,
    EndpointSet, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, TokenResponse, TokenUrl,
    basic::BasicClient,
};
use serde::Deserialize;
use url::Url;

use super::GitHubConfig;

#[derive(Clone, Deserialize)]
pub struct GitHubProfile {
    pub id: u64,
    pub login: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug)]
pub struct ProviderError;
impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GitHub authentication failed")
    }
}
impl std::error::Error for ProviderError {}

pub trait IdentityProvider: Send + Sync {
    fn authorize(&self, state: CsrfToken, challenge: PkceCodeChallenge) -> Url;
    fn identify<'a>(
        &'a self,
        code: &'a str,
        verifier: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<GitHubProfile, ProviderError>> + Send + 'a>>;
}

type Client = BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;
pub struct GitHubProvider {
    oauth: Client,
    http: reqwest::Client,
}

impl GitHubProvider {
    pub fn new(config: &GitHubConfig, origin: &Url) -> anyhow::Result<Self> {
        let callback = origin.join("/v1/auth/github/callback")?;
        Ok(Self {
            oauth: BasicClient::new(ClientId::new(config.client_id.clone()))
                .set_client_secret(ClientSecret::new(config.client_secret.clone()))
                .set_auth_type(AuthType::RequestBody)
                .set_auth_uri(AuthUrl::new(
                    "https://github.com/login/oauth/authorize".into(),
                )?)
                .set_token_uri(TokenUrl::new(
                    "https://github.com/login/oauth/access_token".into(),
                )?)
                .set_redirect_uri(RedirectUrl::new(callback.to_string())?),
            http: reqwest::Client::builder()
                .https_only(true)
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(15))
                .user_agent("Vnox-Central/0.1")
                .build()?,
        })
    }
}

impl IdentityProvider for GitHubProvider {
    fn authorize(&self, state: CsrfToken, challenge: PkceCodeChallenge) -> Url {
        // Public identity only: no repository/private-email/offline access scopes.
        self.oauth
            .authorize_url(|| state)
            .set_pkce_challenge(challenge)
            .url()
            .0
    }

    fn identify<'a>(
        &'a self,
        code: &'a str,
        verifier: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<GitHubProfile, ProviderError>> + Send + 'a>> {
        Box::pin(async move {
            let http = self.http.clone();
            let transport = move |request: oauth2::HttpRequest| {
                let http = http.clone();
                async move {
                    let (parts, body) = request.into_parts();
                    let response = http
                        .request(parts.method, parts.uri.to_string())
                        .headers(parts.headers)
                        .body(body)
                        .send()
                        .await
                        .map_err(|_| ProviderError)?;
                    let mut builder = oauth2::http::Response::builder().status(response.status());
                    for (name, value) in response.headers() {
                        builder = builder.header(name, value);
                    }
                    let body = bounded_body(response, 32 * 1024).await?;
                    builder.body(body).map_err(|_| ProviderError)
                }
            };
            let token = self
                .oauth
                .exchange_code(AuthorizationCode::new(code.into()))
                .set_pkce_verifier(PkceCodeVerifier::new(verifier.into()))
                .request_async(&transport)
                .await
                .map_err(|_| ProviderError)?;
            let response = self
                .http
                .get("https://api.github.com/user")
                .header(reqwest::header::ACCEPT, "application/vnd.github+json")
                .bearer_auth(token.access_token().secret())
                .send()
                .await
                .map_err(|_| ProviderError)?;
            if !response.status().is_success() {
                return Err(ProviderError);
            }
            let profile: GitHubProfile =
                serde_json::from_slice(&bounded_body(response, 64 * 1024).await?)
                    .map_err(|_| ProviderError)?;
            if profile.id == 0 || profile.login.is_empty() || profile.login.len() > 100 {
                return Err(ProviderError);
            }
            Ok(profile)
            // Provider tokens are dropped: no permanent storage or forwarding to clients/nodes.
        })
    }
}

async fn bounded_body(
    mut response: reqwest::Response,
    maximum: usize,
) -> Result<Vec<u8>, ProviderError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(ProviderError);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ProviderError)? {
        if body.len().saturating_add(chunk.len()) > maximum {
            return Err(ProviderError);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
