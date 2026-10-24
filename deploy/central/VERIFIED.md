# Vnox Central: deployment verification

- Endpoint: https://central.loki-code.dev
- Service: vnox-central (systemd enabled/active, dedicated user).
- Internal listener: 127.0.0.1:37623; external access goes through Nginx443.
- Release source: a811de590a76; static Linux-musl binary SHA256 1cff8bb453eabb5320020b37401cbdbb16f051c87c288823f0be35da8de21487.
- Certificate: central.loki-code.dev, expires2027-01-22; Certbot timer active, renewal staging simulation passed.
- /health, /ready, /version, /v1/info: verifiedHTTPS200.
- Persistent issuer survives service restart; issuer file0600, data dir0700, root-owned environment0600.
- Private initial paired SQLite/issuer backup created on the VPS. No external backup destination configured.
- SMTP TLS/auth/NOOP verified with existing provider credentials, sender Vnox <noreply@loki-code.dev>; no real mail sent.
- Other existing Nginx hosts still respond; production SMTP values were never printed or committed.
- Registered public issuer ID: 47a921b4-b12b-4bb8-864a-a1b76c13714a.

## Boundaries

This deployment is a real foundation service, not complete global authentication/social functionality. Email/GitHub auth, server registry, friends, DM and marketplace are explicitly not_enabled. No public send-email endpoint exists. Email HTML previews use dummy tokens and their future verification routes are not active.

Approved logo is the V connection mark. The Hub serves SVG and PNG; mail uses a PNG with text fallback.

## GitHub authorization update — 2026-10-24

- Source: `ff9c8f330e15`, release `ff9c8f330e15-ca84d4e4b6fa`.
- Static binary SHA256: `ca84d4e4b6fa6c9aa0f6852e9f1af22465cac1f6e088a1ac93692877a3b10db3`.
- Paired private database/issuer backup created before migration; service restarted and readiness returned 200.
- GitHub client configuration stored only in protected service environment. App metadata/client identity was verified through GitHub API; private signing key is unnecessary in the running Hub.
- Authentication paths disable Nginx access/error logging before OAuth was enabled.
- Public `/v1/info` reports GitHub enabled; `/v1/auth/session` reports anonymous without a cookie. Live start endpoint returns 303 to GitHub with the configured callback, state, S256 PKCE and a Secure/HttpOnly/SameSite cookie.
- Workspace tests: 66 passed; all-target Clippy with `-D warnings`, formatting and dependency audit passed (zero vulnerabilities/warnings).
- Complete provider authorization/code exchange still requires an account owner's browser consent. Automated checks verify the local callback/session flow with an injected provider, not real user consent.
