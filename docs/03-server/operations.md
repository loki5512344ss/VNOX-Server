# Operations

## Health check

```bash
curl http://localhost:7600/health
```

```json
{
  "status": "ok",
  "version": "LNEx v1",
  "node": "my-node",
  "uptime_seconds": 86400,
  "connections": 12,
  "voice_sessions": 4
}
```

---

## Logs

### View live logs

```bash
# systemd
journalctl -u vnox-gateway -f
journalctl -u vnox-voice-node -f

# Docker
docker compose logs -f gateway
docker compose logs -f voice-node
```

### Log levels

Set in `config.toml` under `[logging] level` or via `VNOX_LOGGING_LEVEL`:

```
error   — only errors
warn    — errors + warnings
info    — normal operation (default)
debug   — detailed internal events
trace   — everything including packet events (very verbose)
```

For production: `info`.
For debugging a specific issue: `debug`.
Never run `trace` in production — it logs packet contents.

### Useful log patterns

```bash
# Auth failures
journalctl -u vnox-gateway | grep "AUTH_FAILED"

# New connections
journalctl -u vnox-gateway | grep "SESSION"

# Voice node errors
journalctl -u vnox-voice-node | grep "ERROR"

# Rate limit events
journalctl -u vnox-gateway | grep "RATE_LIMITED"
```

---

## Metrics (Prometheus)

Enable in `config.toml`:

```toml
[metrics]
enabled = true
bind    = "127.0.0.1:9090"
path    = "/metrics"
```

Available metrics:

```
vnox_connections_total          # total connections since start
vnox_connections_active         # current active connections
vnox_auth_success_total         # successful authentications
vnox_auth_failure_total         # failed authentications
vnox_messages_total             # text messages delivered
vnox_voice_sessions_active      # current voice sessions
vnox_voice_packets_total        # voice packets relayed
vnox_voice_packet_loss_ratio    # packet loss (rolling average)
vnox_federation_links_active    # active federation connections (Phase 3)
vnox_gateway_latency_ms         # gateway processing latency histogram
```

Scrape config for `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: vnox
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 15s
```

---

## Backup

### What to back up

| Path | Contents | Priority |
|------|----------|---------|
| `/var/lib/vnox/node.key` | Node identity keypair | **Critical** |
| `/var/lib/vnox/vnox.db` | Message history, user records | High |
| `/etc/vnox/config.toml` | Node configuration | Medium |

Losing `node.key` means the node loses its federated identity.
Other nodes that trusted this node's pubkey will not recognize the replacement.

### Backup node.key

```bash
# Copy to secure location
cp /var/lib/vnox/node.key /backup/vnox-node-$(date +%Y%m%d).key
chmod 600 /backup/vnox-node-*.key
```

Store this file encrypted, offline, and in multiple locations.

### Backup SQLite database

```bash
# While gateway is running — SQLite WAL-safe copy
sqlite3 /var/lib/vnox/vnox.db ".backup /backup/vnox-$(date +%Y%m%d).db"

# Or stop gateway first for a simple copy
systemctl stop vnox-gateway
cp /var/lib/vnox/vnox.db /backup/vnox-$(date +%Y%m%d).db
systemctl start vnox-gateway
```

### Restore

```bash
systemctl stop vnox-gateway vnox-voice-node

cp /backup/vnox-node-20260101.key /var/lib/vnox/node.key
cp /backup/vnox-20260101.db       /var/lib/vnox/vnox.db

chown vnox:vnox /var/lib/vnox/node.key /var/lib/vnox/vnox.db
chmod 600 /var/lib/vnox/node.key

systemctl start vnox-gateway vnox-voice-node
```

---

## Upgrades

### Check current version

```bash
vnox-gateway --version
# VNOX Gateway 0.2.0 (LNEx v1)
```

### Docker upgrade

```bash
docker compose pull
docker compose up -d
```

### systemd upgrade

```bash
# Download new binary
VERSION=0.2.0
curl -L https://github.com/vnox/vnox/releases/download/v${VERSION}/vnox-linux-x86_64.tar.gz \
  | tar xz -C /tmp/vnox-upgrade/

# Validate config against new binary
/tmp/vnox-upgrade/vnox-gateway --config /etc/vnox/config.toml --check

# Replace binaries
systemctl stop vnox-gateway vnox-voice-node
cp /tmp/vnox-upgrade/vnox-gateway     /usr/local/bin/
cp /tmp/vnox-upgrade/vnox-voice-node  /usr/local/bin/
systemctl start vnox-gateway vnox-voice-node
```

### LNEx protocol upgrades

When a new LNEx version is released:

- old clients can still connect if the gateway supports multiple versions
- the gateway advertises supported versions in `HELLO`
- both sides negotiate the highest mutually supported version
- a grace period is announced before old versions are dropped

Breaking changes in LNEx are rare and will be documented in the changelog
with a migration guide.

---

## Security hardening checklist

- [ ] Gateway runs as unprivileged user (`vnox`, not root)
- [ ] `node.key` is `chmod 600`, owned by `vnox`
- [ ] Metrics endpoint is not exposed publicly (bound to `127.0.0.1`)
- [ ] Firewall: only TCP 7600 and UDP 7700 are open externally
- [ ] Log retention policy configured (rotate logs, don't fill disk)
- [ ] `node.key` backup exists and is stored securely
- [ ] `VNOX_LOGGING_LEVEL` is `info` or `warn` in production (not `trace`)
- [ ] `[gateway.rate_limits]` are configured appropriately for your user base
- [ ] TLS: either a CA certificate (`tls_cert_path`/`tls_key_path`) or the self-signed fingerprint (`data_dir/tls/fingerprint.txt`) is published to users; no TLS-terminating proxy in front of TCP 7600
- [ ] Federation disabled if not needed (`[federation] enabled = false`)
