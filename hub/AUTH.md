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

Per address 1 per 60 s and 5 per hour; per source (`X-Forwarded-For`, as GitHub login) 10 per hour, where IPv6 sources are grouped by /64 and IPv4-mapped IPv6 counts as IPv4 (so rotating host bits does not dodge the limit; an attacker with a larger prefix or many networks still can); globally 300 per hour for new sign-ins plus a separate reserve of 100 per hour that only qualifying resends can spend. A resend qualifies when its `__Host-vnox_email` cookie belongs to a live attempt for the same normalized address with fewer than 5 failed tries, fewer than 3 earlier resends in its chain, and a chain younger than 30 minutes. The attempt is claimed by deleting it inside the same SQLite transaction that checks and records the send budgets, so the check and the reservation are atomic: parallel resends cannot both claim one attempt, chains cannot branch, and a refused request rolls the claim back. The chain counter and start time are carried to the replacement attempt. Flooding the general budget therefore cannot cut off people who are already mid sign-in, and one live attempt cannot be turned into a stream of reserve-funded mail to other addresses. It does not help people who start after the budget is exhausted; a resend that no longer qualifies, once it passes the normal budget, starts a fresh chain (each such reset costs a normal-budget send). Budget is spent when a request passes validation, even if delivery later fails. The in-memory per-IP limiter used by GitHub (20 per minute, 300 global) also applies to both endpoints. At most 4096 attempts are pending.

### Address handling and accounts

Addresses are trimmed and lowercased; only ASCII, a local part of `[a-z0-9._%+-]` without leading/trailing/double dots, at most 64 characters, a multi-label hostname whose last label is alphabetic, at most 254 characters in total. `+tag` is not stripped and Gmail dots are not folded. Unusual legal addresses are rejected on purpose.

The identity is `external_identities(provider='email', subject=<normalized address>)`, reusing the existing table so one address maps to one account, and it can never collide with `github.com` subjects. A matching GitHub account or email is never merged automatically. A first successful verification creates an account with a generated `u_<uuid>` handle and the neutral display name `Vnox user`; the local part of the address is never used. Choosing a handle and display name after registration is not implemented yet (an own avatar can be uploaded, see below) (see `design/accounts-and-avatars.md`). The address is kept in plain normalized form in `external_identities` because later features (security notices, adding a second sign-in method) need it; it is used for nothing except sending codes today.

### Mail and logging

The message is rendered by `mail::templates::render_email_code` (Russian or English) and contains the code but no button and no link. Delivery uses the existing TLS-only `Mailer` through the internal `CodeSender` trait; there is no endpoint to send arbitrary mail. Codes, addresses, cookies and request bodies are never logged by the application, and the Nginx `/v1/auth/` location writes no access or error logs. A delivery failure returns `503 try_later` and removes the attempt.

### Known limits

- A third party can use up an address's hourly budget and delay that person's email sign-in (GitHub still works). Accepted trade-off of per-address limits.
- Email proves control of a mailbox only; it is not strong authentication (see design notes on later MFA/passkeys).
- Rate-limit counters for the in-memory limiter reset on restart; the email ledger persists.
- Access to the mailbox, or to the SQLite file together with `email-auth.key` during the ten-minute window, defeats the code.
- Tests use an injected sender; real SMTP delivery has not been exercised from tests.

## Own avatar

A signed-in web session can set its own photo. Without one, `avatar_url` in `GET /v1/auth/session` (and in the email verify answer) is the provider's avatar (GitHub) or `null`; with one it is the same-origin path `/v1/avatars/<id>`.

### Contract

- `POST /v1/account/avatar`: the body is the raw image, `Content-Type` is `image/png`, `image/jpeg` or `image/webp`. Answers `200 {"avatar_url":"/v1/avatars/<id>"}`.
- `DELETE /v1/account/avatar`: removes the own photo. Answers `200 {"avatar_url": <provider URL or null>}`; repeating it is harmless.
- `GET /v1/avatars/<id>`: public. `<id>` is 64 lowercase hex characters, the SHA-256 of the stored bytes. `Cache-Control: public, max-age=31536000, immutable`, `Content-Type: image/png`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; sandbox; frame-ancestors 'none'`, `ETag`. Unknown or malformed ids give a `404` JSON error. After a replacement or removal the old URL gives `404` (browser caches may still hold it until they evict it).
- The two changing endpoints require the exact `Origin`, the session cookie and `X-CSRF-Token`, checked in that order, exactly as logout (shared `authorized` gate). All their responses, errors included, are `no-store`.
- Errors: `401 not_authenticated`, `403 invalid_origin` / `invalid_csrf`, `413 too_large`, `415 unsupported_type` / `type_mismatch`, `422 bad_dimensions` / `invalid_image`, `429 try_later`, `503 try_later`.

### Upload pipeline

1. Authentication, Origin and CSRF are checked before the body is read.
2. The declared `Content-Type` must be one of the three types. A cheap refusal here does not spend rate-limit budget.
3. Rate limit, in memory: 10 changes per hour per account and 30 per hour per source (`X-Forwarded-For`, /64 grouping for IPv6, as above). Uploads and removals both count; a refused request is not recorded. At most two decodes run at the same time, the rest get `429`.
4. Body limit 2 MiB: refused from `Content-Length` when announced, and the read itself stops at the limit for chunked bodies.
5. Magic bytes decide the real format (PNG, JPEG, WebP; SVG, GIF and everything else are `unsupported_type`). A different declared type is `type_mismatch`, so a renamed file does not pass.
6. The header is read first: more than 4096 or fewer than 32 pixels on a side is `bad_dimensions` before any pixel buffer exists (decoder limits: 4096 per side, 128 MiB allocation). A small file that claims 60000x60000 never allocates.
7. The image is fully decoded (corrupt or truncated data is `invalid_image`), rotated by its EXIF orientation, center-cropped to a square, resized to 256x256 (Lanczos3) and written as a new PNG (RGB, or RGBA when the source has transparency). Nothing from the source file is copied, so EXIF, GPS, ICC profiles, text chunks and trailing data are gone. The decode runs on a blocking thread. Animated sources yield a single still frame or are refused.
8. The row is written with `INSERT ... ON CONFLICT(user_id) DO UPDATE`, so there is one avatar per account and the old bytes are overwritten in the same statement. The original upload is never stored.

### Storage

SQLite BLOB in table `avatars` (migration `0005_avatars.sql`), keyed by `user_id` with `ON DELETE CASCADE`. Reasons: a normalized avatar is small (typically 20 to 150 KB), so the database stays small; replacement and account deletion are transactional with the account row; there is no second directory whose permissions, orphan files or backup consistency need care; the existing data-directory rules and the existing backup (database plus issuer together) cover it with no new moving parts. Files stay `0600` because they are inside the private data directory like the database itself. If avatars ever grow in number or size, serving can move to files or object storage behind the same URLs.

The provider avatar URL stays on `accounts.avatar_url` and is the fallback after removal.

### Known limits

- Rate-limit counters are in memory and reset on restart.
- Avatars are public to anyone who knows the id; ids are not secret but are not listed anywhere. Identical images from two accounts share an id.
- Deleted photos can remain in database backups. The project owner decided that backups keep deleted data for up to 30 days; this needs backup rotation to be implemented and is not enforced by the Hub.
- Decoding uses the `image` crate with only the `png`, `jpeg` and `webp` features. `cargo audit` reported no advisories when this was added. Decoder bugs in these crates are the main residual risk; decoding is bounded in size, memory and concurrency.
