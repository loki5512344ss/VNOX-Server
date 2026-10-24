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
