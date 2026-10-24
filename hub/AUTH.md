# Hub sign-in: GitHub and email code

## GitHub

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

Provider reference: [GitHub App user authorization and PKCE](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app). GitHub App resource permissions are configured by its owner; this flow adds no OAuth scopes and only calls the public user endpoint.

## Email sign-in (one-time code)

Available only when SMTP is configured (`SMTP_HOST` etc., see `deploy/central/hub.env.example`); `GET /v1/info` reports `capabilities.email_auth` as `"enabled"` exactly then, otherwise `"not_enabled"` and both endpoints answer `503 email_not_configured`. No other setting is needed: the code MAC key is generated on first start as `email-auth.key` (hex, 0600) in the private data directory.

### Browser contract

- `POST /v1/auth/email/start` with JSON `{"email": "...", "lang": "ru"|"en"}` (`lang` optional, default `ru`, unknown values fall back to `ru`). Answers `202 {"status":"code_requested","expires_in":600,"resend_after":60}` and sets the browser-binding cookie `__Host-vnox_email` (HttpOnly, Secure, SameSite=Lax, 10 minutes). The answer is identical for addresses with and without an account: start never looks up accounts, and the code is never in the response.
- `POST /v1/auth/email/verify` with JSON `{"email": "...", "code": "12345678"}` and that cookie. On success: `200` with the same body as `GET /v1/auth/session` (`{authenticated:true,user,csrf_token}`) and the same `__Host-vnox_session` cookie (7 days, CSRF token) as GitHub. Any failure (no attempt, expired, exhausted, wrong address, wrong code, wrong browser) is the same `400 {"error":"invalid_code"}`.
- Other errors: `400 invalid_email` / `invalid_request`, `403 invalid_origin`, `429 try_later`, `503 try_later`.

### CSRF and browser binding

These are unauthenticated POSTs, so there is no session CSRF token to compare. They are protected by three layers: the exact `Origin` must equal `PUBLIC_BASE_URL`'s origin (as for logout); the body must be JSON with no unknown fields and at most 1 KiB (not a form a foreign page can submit without a CORS preflight); and the code is bound to a random 256-bit `__Host-` cookie created by `start`, stored only as a SHA-256 hash with the attempt. A code can be redeemed only in the browser that requested it, so a cross-site request can neither plant an attacker's login in a victim's browser nor redeem a victim's code. A new `start` from the same browser replaces its previous attempt.

### Codes

Eight digits from the OS CSPRNG with rejection sampling, valid for ten minutes, five verification tries. The stored value is `HMAC-SHA256(server_key, attempt_id, address_mac, code)` (length-prefixed fields), not a bare hash; a database leak alone does not allow guessing the 10^8 code space offline. Comparison is constant-time. The try counter is incremented by the same atomic `UPDATE ... RETURNING` that selects the attempt, so parallel guesses cannot exceed the limit; a correct code is consumed by an atomic `DELETE ... RETURNING`, so exactly one request wins. Pending attempts hold only the address MAC, never the address.

### Rate limits (SQLite ledger of MACs, atomic check-and-record)

Per address 1 per 60 s and 5 per hour; per source (`X-Forwarded-For`, as GitHub login) 10 per hour, where IPv6 sources are grouped by /64 and IPv4-mapped IPv6 counts as IPv4 (so rotating host bits does not dodge the limit; an attacker with a larger prefix or many networks still can); globally 300 per hour for new sign-ins plus a separate reserve of 100 per hour that only resends can spend, meaning requests carrying the `__Host-vnox_email` cookie of a still-live pending attempt. Flooding the general budget therefore cannot cut off people who are already mid sign-in. It does not protect people who start after the budget is exhausted, and an attacker who first collects live attempts can spend the reserve too (bounded by the per-address and per-source limits). Budget is spent when a request passes validation, even if delivery later fails. The in-memory per-IP limiter used by GitHub (20 per minute, 300 global) also applies to both endpoints. At most 4096 attempts are pending.

### Address handling and accounts

Addresses are trimmed and lowercased; only ASCII, a local part of `[a-z0-9._%+-]` without leading/trailing/double dots, at most 64 characters, a multi-label hostname whose last label is alphabetic, at most 254 characters in total. `+tag` is not stripped and Gmail dots are not folded. Unusual legal addresses are rejected on purpose.

The identity is `external_identities(provider='email', subject=<normalized address>)`, reusing the existing table so one address maps to one account, and it can never collide with `github.com` subjects. A matching GitHub account or email is never merged automatically. A first successful verification creates an account with a generated `u_<uuid>` handle and the neutral display name `Vnox user`; the local part of the address is never used. Choosing a handle, display name and avatar after registration is not implemented yet (see `design/accounts-and-avatars.md`). The address is kept in plain normalized form in `external_identities` because later features (security notices, adding a second sign-in method) need it; it is used for nothing except sending codes today.

### Mail and logging

The message is rendered by `mail::templates::render_email_code` (Russian or English) and contains the code but no button and no link. Delivery uses the existing TLS-only `Mailer` through the internal `CodeSender` trait; there is no endpoint to send arbitrary mail. Codes, addresses, cookies and request bodies are never logged by the application, and the Nginx `/v1/auth/` location writes no access or error logs. A delivery failure returns `503 try_later` and removes the attempt.

### Known limits

- A third party can use up an address's hourly budget and delay that person's email sign-in (GitHub still works). Accepted trade-off of per-address limits.
- Email proves control of a mailbox only; it is not strong authentication (see design notes on later MFA/passkeys).
- Rate-limit counters for the in-memory limiter reset on restart; the email ledger persists.
- Access to the mailbox, or to the SQLite file together with `email-auth.key` during the ten-minute window, defeats the code.
- Tests use an injected sender; real SMTP delivery has not been exercised from tests.
