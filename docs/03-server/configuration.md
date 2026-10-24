# Configuration

All configuration lives in a single `config.toml` file.
Path: `/etc/vnox/config.toml` (or passed via `--config`).

For local development, see [dev/README.md](../../dev/README.md) and `dev/config.toml`.

Environment variables prefixed with `VNOX_` override any config file value.
Example: `VNOX_NODE_NAME=my-node` overrides `[node] name`.

---

## Full reference

```toml
# ─── NODE ──────────────────────────────────────────────────────────────────

[node]
# Human-readable name shown to connecting clients.
name = "my-node"

# Public address of this node. Used by federation and relay routing.
# Can be domain name or IP address.
address = "my-node.example.com"

# LNEx protocol version this node advertises.
# Do not change unless you know what you're doing.
lnex_version = "v1"


# ─── GATEWAY ───────────────────────────────────────────────────────────────

[gateway]
# Address and port to listen for TCP client connections.
bind = "0.0.0.0:7600"

# Maximum concurrent client connections.
max_connections = 1000

# Idle session timeout in seconds. Sessions older than this
# without activity are terminated.
session_timeout = 300

# Maximum message size in bytes (text chat).
max_message_size = 4096

# Rate limits
[gateway.rate_limits]
auth_attempts_per_minute    = 5     # per IP
messages_per_second         = 10    # per user
connections_per_ip          = 4     # concurrent


# ─── VOICE ─────────────────────────────────────────────────────────────────

[voice]
# Address and port to listen for UDP voice packets.
bind = "0.0.0.0:7700"

# Maximum concurrent voice sessions.
max_sessions = 500

# Jitter buffer default size in milliseconds.
# Clients may override this locally.
jitter_buffer_ms = 40

# Maximum relay packet rate per user (packets per second).
# At 20ms frames: 50 pps. Increase only for 10ms frame configs.
max_pps_per_user = 60


# ─── IDENTITY / TLS ────────────────────────────────────────────────────────

[identity]
# Path to the node's keypair file (Ed25519).
# Generated automatically on first start if not present.
keypair_path = "/var/lib/vnox/node.key"

# TLS 1.3 is always on (LNEx v3). TLS keys live in the [gateway] section:
#   tls_cert_path = "/etc/letsencrypt/live/chat.example.org/fullchain.pem"
#   tls_key_path  = "/etc/letsencrypt/live/chat.example.org/privkey.pem"
# Both unset: a self-signed certificate is generated in <data_dir>/tls/ and its
# fingerprint is logged. See docs/02-protocol/tls.md.


# ─── CHANNELS ──────────────────────────────────────────────────────────────

[channels]
# Default channels created on first start.
# After that, channels are managed via the admin API or client.
defaults = [
  { name = "general", type = "text" },
  { name = "lobby",   type = "voice" },
]

# Maximum channels per node.
max_channels = 256

# Maximum users per voice channel.
max_voice_per_channel = 50


# ─── PERMISSIONS ───────────────────────────────────────────────────────────

[permissions]
# Default permission level for new users connecting for the first time.
# Options: guest | member | moderator | admin
default_role = "member"

# If true, new connections are allowed by default.
# If false, users must be explicitly whitelisted.
open = true


# ─── STORAGE ───────────────────────────────────────────────────────────────

[storage]
# Directory for persistent data (message history, user records, etc.)
data_dir = "/var/lib/vnox"

# Database backend.
# Options: sqlite (default), postgres
backend = "sqlite"

# SQLite database path (used if backend = "sqlite")
sqlite_path = "/var/lib/vnox/vnox.db"

# PostgreSQL connection string (used if backend = "postgres")
# postgres_url = "postgresql://user:pass@localhost/vnox"

# Message history retention in days. 0 = keep forever.
history_retention_days = 90


# ─── FEDERATION ────────────────────────────────────────────────────────────

[federation]
# Enable federation with other nodes.
# Phase 3 feature — disabled by default.
enabled = false

# Static list of trusted nodes to connect to on startup.
# bootstrap = [
#   "relay.other-node.example.com",
#   "192.168.1.20:7700",
# ]

# Maximum incoming federation connections.
max_incoming = 16

# Maximum bridged channels.
max_bridges = 64

# Message rate limit per federation link (messages per second).
rate_limit_msgs = 100

# Denylist — nodes that will never be allowed to federate.
# denylist = ["bad-node.example.com"]


# ─── RELAY ─────────────────────────────────────────────────────────────────

[relay]
# This node acts as a relay for other nodes' voice traffic.
# Useful for nodes behind NAT.
enabled = false

# relay_secret = "shared-secret-with-trusted-nodes"


# ─── LOGGING ───────────────────────────────────────────────────────────────

[logging]
# Log level: error | warn | info | debug | trace
level = "info"

# Log format: text | json
format = "text"

# Log file path. If not set, logs go to stdout.
# file = "/var/log/vnox/gateway.log"

# Log voice packet events (very verbose, debug only).
log_voice_packets = false


# ─── METRICS ───────────────────────────────────────────────────────────────

[metrics]
# Expose Prometheus metrics endpoint.
enabled = false
bind    = "127.0.0.1:9090"
path    = "/metrics"
```

---

## Environment variable overrides

Any config key can be overridden with an env var using the pattern:
`VNOX_` + section + `_` + key, uppercased, dots replaced with `_`.

Examples:

```bash
VNOX_NODE_NAME=my-node
VNOX_GATEWAY_BIND=0.0.0.0:7600
VNOX_LOGGING_LEVEL=debug
VNOX_STORAGE_BACKEND=postgres
VNOX_STORAGE_POSTGRES_URL=postgresql://user:pass@db/vnox
```

---

## Validating config

```bash
vnox-gateway --config /etc/vnox/config.toml --check
```

Exits 0 if config is valid, prints errors otherwise.
