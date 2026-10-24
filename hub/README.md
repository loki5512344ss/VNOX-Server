# Vnox Hub foundation

`vnox-hub` is the central service foundation. It starts as one HTTP service behind
an HTTPS reverse proxy and stores its issuer identity and SQLite database locally.
Community messages and voice never pass through this process.

## Implemented

- `/health`: process liveness.
- `/ready`: database readiness after successful migrations and issuer validation.
- `/version`: binary version and explicit `foundation` stage.
- `/v1/info`: public issuer ID/key and honest feature availability.
- `/`: deployment status page; `/assets/vnox-mark.svg`: approved V connection mark.
- Durable SQLite schema and issuer identity with a private `0600` key file.
- Own avatar for signed-in web sessions: `POST`/`DELETE /v1/account/avatar`, public `GET /v1/avatars/<id>` (re-encoded 256x256 PNG in SQLite, see `AUTH.md`).
- TLS-only SMTP transport and HTML/plain-text transactional email templates.

GitHub OAuth and email one-time-code sign-in are implemented (`AUTH.md`); email sign-in
is reported as enabled in `/v1/info` only when SMTP is configured. Server
registration/discovery, friends, DM storage and marketplace API are **not enabled**.
There is no public endpoint for sending mail. Other schema tables are foundations.
Links in the older verify/new-device templates are previews of future routes; they do
not create working tokens.

## Configuration

Set these in a protected systemd `EnvironmentFile` outside Git. Use a dedicated
service user, a private `0700` data directory, restrictive umask and loopback-only HTTP.

```ini
HUB_BIND=127.0.0.1:17843
HUB_DATA_DIR=/var/lib/vnox-hub
PUBLIC_BASE_URL=https://central.loki-code.dev
SMTP_HOST=smtp.provider.example
SMTP_PORT=587
SMTP_USER=provider-user
SMTP_PASSWORD=replace-outside-git
MAIL_FROM="Vnox <noreply@loki-code.dev>"
RUST_LOG=vnox_hub=info
```

`SMTP_HOST` may be omitted to disable the transport. Partially configured
credentials cause startup validation errors instead of silent fallback. Port465
uses implicit TLS; all other ports require STARTTLS with certificate validation.
No plaintext downgrade is supported. SMTP construction validates configuration;
readiness does not claim SMTP delivery was tested. Configure an external monitor
for `/ready` and perform SMTP connectivity checks separately.

`PUBLIC_BASE_URL` must be an HTTPS origin with no path, query, credentials or
fragment. It is the only source for email links; request Host headers are ignored.
Do not configure an untrusted hostname as the public origin.

## Run and verify

Run commands from `VNOX-Server/`:

```sh
cargo run -p vnox-hub
cargo run -p vnox-hub -- --check-smtp
cargo run -p vnox-hub -- --render-email-preview /tmp/vnox-mail-preview
cargo test -p vnox-hub
cargo clippy -p vnox-hub --all-targets -- -D warnings
```

`--check-smtp` connects, validates TLS/authentication and issues an SMTP NOOP. It
never sends mail. `--render-email-preview` writes three HTML/plain-text pairs with
dummy token/code values and never contacts SMTP. Do not use example values as
real verification credentials. Secrets must not be passed as command arguments.

## Deployment and backup

Terminate HTTPS at Nginx, keep the random Hub listener on loopback, and expose only
443/80 as required for HTTPS/ACME. Check configuration before reloading Nginx.
Use the supplied parent deployment configuration once reviewed. The process
handles SIGTERM/Ctrl-C with graceful HTTP shutdown and closes its SQLite pool.

Keep `issuer.json` and `hub.sqlite3` together in backup/restore. If their identities
differ, startup fails; it must never silently replace the issuer of an existing
Hub. An invalid/malformed issuer file likewise fails closed. Protect the entire
data directory, not only the JSON file. Additional account/device revocation,
registry authorization, mailbox lifecycle and storage policies require their own
implementation and security review before those capabilities are enabled.
