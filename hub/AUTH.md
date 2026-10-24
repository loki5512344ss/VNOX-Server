# GitHub sign-in

Configure `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` together in the protected service environment. GitHub Apps and OAuth Apps both support this user authorization flow; the GitHub App private signing key is unnecessary at runtime. Register this exact callback:

`https://central.loki-code.dev/v1/auth/github/callback`

The configured `PUBLIC_BASE_URL` determines redirects. Request headers and arbitrary return URLs cannot change them. No repository, private email or installation permission is requested.

## Browser contract

- Navigate to `GET /v1/auth/github/start` to begin authorization.
- `GET /v1/auth/github/callback` consumes a matching, browser-bound attempt and redirects to `/account`.
- `GET /v1/auth/session` returns `{authenticated:false}` or `{authenticated:true,user,csrf_token}`. Use same-origin credentials and never persist this response in local storage.
- `POST /v1/auth/logout` requires the exact `Origin` and the session's `X-CSRF-Token`.

All responses are `no-store`. Cookies use `__Host-` names, Secure, HttpOnly, Path=/ and SameSite=Lax. Login attempts expire after ten minutes and use random state and S256 PKCE. Attempts are consumed atomically before exchanging authorization codes. Sessions expire seven days after creation; SQLite stores only token hashes. GitHub access tokens are used once to fetch `/user`, then discarded.

Accounts bind to GitHub's numeric user ID. Renaming a GitHub account cannot move it to another Vnox account. Email addresses never implicitly link accounts. This web session currently does not replace the desktop client's local cryptographic identity.

## Operation

The Hub binds only to loopback. Its reverse proxy must overwrite `X-Forwarded-For`; it supplies the login rate-limit identity. Use the supplied Nginx configuration: authentication paths disable access/error logging to prevent callback codes and state entering logs. Do not enable request-body, query-string, Authorization or Cookie tracing in application logs.

Back up SQLite with the issuer identity, protect backups as credentials, and apply the account-deletion policy to them. Expired attempts/sessions are pruned on new login attempts; expiry is independently enforced on every consumption/read. Revoking a GitHub authorization does not currently revoke an already created Vnox session; sign out or delete its database session to revoke it.

`cargo test -p vnox-hub` exercises the complete local browser flow against an injected provider, wrong-browser/replay/expiry rejection and logout CSRF. A real GitHub login requires the account owner to authorize in their browser; automated tests never impersonate consent.
