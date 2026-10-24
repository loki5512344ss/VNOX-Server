# VNOX — Server

> Self-hosted voice and chat server. No cloud. No tracking. Your hardware, your rules.

**Not Discord. Not TeamSpeak. Not someone else's cloud.**

[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.94%2B-orange.svg)](https://www.rust-lang.org/)
[![Status: Phase 1](https://img.shields.io/badge/status-phase%201%20%E2%80%94%20implemented-yellow.svg)](docs/00-status.md)

---

## What is VNOX?

VNOX is a self-hosted, real-time voice and text communication platform built entirely in Rust. It runs on your own server, uses a custom low-latency protocol (LNEx), and has no dependency on any third-party infrastructure.

The architecture is deliberately split into two components:

- **Gateway** — TCP server: authentication, channels, text chat, guilds, roles, permissions, DMs, invites, audit log
- **Voice Node** — UDP relay: Opus audio, jitter buffer, per-channel packet routing

Both are written in Rust on top of Tokio. The client is a separate native application at [`VNOX-Client/`](../VNOX-Client/).

---

## Why Rust?

- Tokio async runtime handles thousands of concurrent connections with minimal overhead
- No GC pauses during active voice sessions
- Memory safety without a garbage collector
- Single cross-platform binary — Windows, macOS, Linux

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    VNOX Client                       │
│              (Rust + Slint UI)                       │
└──────────────────────┬───────────────────────────────┘
                       │ LNEx v1
            ┌──────────┴──────────┐
            │ TCP                 │ UDP
            ▼                     ▼
┌─────────────────────┐   ┌──────────────────────┐
│      Gateway        │   │     Voice Node        │
│   (Rust / Tokio)    │   │      (Rust)           │
│                     │   │                        │
│  auth (Ed25519)     │   │  Opus relay           │
│  channels           │   │  jitter buffer        │
│  sessions           │   │  packet routing       │
│  guilds, roles      │   │  member tracking      │
│  permissions        │   └──────────────────────┘
│  DMs, invites       │
│  audit log          │
│  rate limiting      │
│  Prometheus metrics │
└──────────┬──────────┘
           │ SQLite
           ▼
      ┌──────────┐
      │ Storage  │
      └──────────┘
```

Full architecture details: [docs/01-architecture.md](docs/01-architecture.md)

---

## Features

### Implemented
- **Auth:** Ed25519 challenge-response, session tokens, reconnect with backoff
- **Encryption:** TLS 1.3 (rustls) on TCP with SPKI pinning, ChaCha20-Poly1305 on UDP voice
- **Channels:** Create, delete, list; text and voice channel types
- **Text chat:** Persistent history via SQLite, reactions, replies, edit, delete, typing indicators, read receipts
- **Direct Messages:** 1:1 DMs with persistent history, unread badges, search
- **Guilds:** Create, list, delete, settings
- **Roles:** u64 permission bits, channel overrides, owner bypass
- **Invites:** Permanent and temporary, accept/decline
- **Friends:** Requests, accept/decline, Online/All/Pending/Blocked tabs
- **Presence:** Online/Idle/DND/Invisible, custom status text, activity display
- **Rate limiting:** Per-session token bucket on chat + DMs
- **Metrics:** Prometheus (messages, DMs, voice packets, connections, auth failures, guilds, sessions)
- **Admin HTTP:** `GET /health`, `GET /version`, `GET /metrics`
- **Audit log:** All guild mutations logged
- **Identity vault:** Optional Argon2id + ChaCha20-Poly1305 keyfile encryption at rest
- **Keyfile export/import:** Encrypted or plain JSON keyfile with passphrase

### Planned
- Protobuf wire format (Phase 2)
- PostgreSQL backend (Phase 2)
- Federation protocol (Phase 3)
- Plugin runtime (Phase 3)

---

## Status

Phase 1 is implemented. Not production ready.

| Component      | Status                                               |
|----------------|------------------------------------------------------|
| Gateway        | TCP listener, LNEx handshake, channels, chat, SQLite |
| Voice node     | UDP relay, voice packet routing, jitter buffer       |
| Desktop client | Slint UI, net layer, audio pipeline (partial)        |
| LNEx protocol  | Specified and implemented (JSON in Phase 1)          |
| Encryption     | TLS 1.3 (TCP) + ChaCha20-Poly1305 (UDP voice) - DONE  |
| Federation     | Planned (Phase 3)                                    |
| Mobile client  | Planned (Phase 3)                                    |

See [docs/00-status.md](docs/00-status.md) for a full breakdown.

---

## Quick start

**Requirements:** Rust 1.94+, a running [VNOX Client](../VNOX-Client/)

```bash
# Terminal 1 — gateway
cargo run -p vnox-gateway -- --config dev/config.toml

# Terminal 2 — voice node
cargo run -p vnox-voice-node -- --config dev/config.toml
```

The client connects to `127.0.0.1:7600` by default. Config reference: [dev/README.md](dev/README.md).

### Docker

```bash
docker-compose up
```

### Build dependencies

Gateway builds require `protoc` (for example, `protobuf-compiler` on Ubuntu).
The voice relay forwards encoded packets and does not require libopus; the codec is a client dependency.

---

## Protocol: LNEx

LNEx is a custom application-layer protocol for low-latency federated communication. Sits above TCP and UDP, defines packet framing, encryption, and routing.

Phase 1 uses JSON framing; Phase 2 will migrate to Protobuf.

The specification is **CC0** (public domain) — anyone can implement a compatible client or server.

Details: [docs/02-protocol/README.md](docs/02-protocol/README.md)

---

## Project structure

```
gateway/          # TCP gateway (auth, channels, chat, guilds)
  ├── src/
  │   ├── proto/      # LNEx protocol: packets, crypto, framing
  │   ├── net/        # I/O, handshake, session state
  │   ├── handler/    # Packet handlers (chat, channel, guild, etc.)
  │   ├── domain/     # Business logic: auth, storage, rate limiting
  │   ├── admin/      # HTTP admin server (health, metrics)
  │   └── bootstrap/  # Startup, config, server identity
  └── Cargo.toml

voice-node/       # UDP voice relay
  ├── src/
  │   ├── jitter/    # Jitter buffer (adaptive + fixed modes)
  │   ├── relay.rs   # Per-channel relay, member tracking
  │   └── runner.rs  # UDP listener loop
  └── Cargo.toml

serverd/          # Unified server daemon (bundles gateway + voice)
docs/             # Documentation
dev/              # Local development config
```

---

## Links

- [Architecture](docs/01-architecture.md)
- [Protocol](docs/02-protocol/README.md)
- [Current status and limitations](docs/00-status.md)
- [Server setup](docs/03-server/deployment.md)
- [Local dev config](dev/README.md)
- [Contributing](docs/community/contributing.md)
- [Changelog](CHANGELOG.md)

---

## License

Server code: **GPL-3.0** — see [LICENSE](LICENSE)  
LNEx protocol specification: **CC0** (public domain)
