# Central Hub deployment

Current target: `central.loki-code.dev`, Ubuntu22.04, Nginx443 terminating HTTPS;
Hub listener `127.0.0.1:37623` (randomly selected free port). The foundation has no
public email-send/auth/registry/friends/DM endpoints. See `hub/README.md` for exact
capability status. SMTP sender display name is Vnox, address `noreply@loki-code.dev`.

## Layout

- `/opt/vnox-central/releases/<git-revision>-<binary-hash>/vnox-hub`: immutable release.
- `/opt/vnox-central/current`: symlink to selected release.
- `/etc/vnox-central/hub.env`: real config, root-owned0600, outside Git.
- `/var/lib/vnox-central/`: private service data0700, issuer0600 and SQLite.
- `/etc/systemd/system/vnox-central.service`: dedicated non-login service user.
- `/etc/nginx/sites-available/central.loki-code.dev`: dedicated virtual host.

Only copy explicitly authorized SMTP keys from the existing service in-process.
Do not dump Docker environment/config, source secrets into shell logs, add them to
command arguments, publish them in preview pages or commit them. Displaying a
successful SMTP test is enough; it does not require revealing credentials.

## Build and publish

Build from `VNOX-Server/`, after tests/review, on the installed Rust toolchain:

```sh
CC_x86_64_unknown_linux_musl=musl-gcc cargo build --locked --release \
  --target x86_64-unknown-linux-musl -p vnox-hub
sha256sum target/x86_64-unknown-linux-musl/release/vnox-hub
```

The static musl build avoids depending on a newer local glibc than Ubuntu22.04.
Build and verify before uploading. Install into a new revision/hash directory,
verify its remote SHA256, switch `current` atomically, restart only
`vnox-central`, and verify readiness before pointing/reloading the Nginx proxy.
Keep the preceding release for rollback; do not replace identity or DB on update.

Install the service/config templates with local paths/port adjusted as needed.
Create `vnox-central` system user and private state dir first. SMTP credentials
are supplied only in protected `hub.env`; example credentials do not work.

## Certificate and renewal

Provision HTTP ACME webroot before requesting the cert:

```sh
certbot certonly --webroot -w /var/www/vnox-acme -d central.loki-code.dev \
  --non-interactive --agree-tos
nginx -t
systemctl reload nginx
```

Keep the ACME path available after enabling the HTTP→HTTPS redirect. Certbot's
timer handles renewal; a deploy hook validates/reloads Nginx after renewal.
Check certificate chain/hostname from outside the VPS, not only with `nginx -t`.
Run renewal staging checks without unnecessary random sleep when unattended.

## Verification

```sh
systemctl is-active vnox-central
curl --fail http://127.0.0.1:37623/ready
curl --fail https://central.loki-code.dev/ready
curl --fail https://central.loki-code.dev/v1/info
```

Use a transient systemd service with the same protected EnvironmentFile to run
`vnox-hub --check-smtp` as the service user. It connects/authenticates and issues
NOOP without sending a message. Actual delivery needs a separately authorized
recipient/test. Previews use dummy tokens and must not be mistaken for working
verification links.

Restart once and verify the issuer ID/public key remain unchanged and `/ready`
returns200. Confirm the backend listener is loopback-only, key/env modes are
private, other Nginx virtual hosts still work, and SIGTERM exits cleanly.

Back up issuer and SQLite consistently (SQLite backup API/checkpoint or stopped
service), with encrypted/private storage; test paired restore. Do not back up
only DB and silently generate a new issuer if its key is missing. Future DM
payload/attachment backup policy is separate from account/registry state.
