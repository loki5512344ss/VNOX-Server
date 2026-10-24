# Current status (Phase 2 prep / v0.1.x)

This file describes what the repository actually does today.
Protocol and security docs may describe future phases. When in doubt, trust this file.

Last updated: 2026-10-24.

---

## Update 2026-10 (protocol v2)

- Signed v2 handshake and protobuf payloads between client and gateway (verified by `VNOX-Client/tests/gateway_interop.rs`).
- Authenticated, encrypted UDP voice relay in voice-node.
- Voice access is revoked when a channel is deleted, a member is kicked or permissions change.
- Senders get acknowledgements for their own chat messages.
- Channel webhooks, GitHub sign-in, hub service, screen sharing and media broadcast.
- `cargo audit`: no known vulnerabilities in both workspaces (2026-10-24).

---

## What works

- **Gateway (TCP):** Ed25519 client auth, sessions, channel join/leave, text chat, SQLite history, guilds, roles, permissions, invites, audit log, rate limiting.
- **Gateway (HTTP admin):** `GET /health`, `GET /version`, `GET /metrics` (Prometheus exposition). Default bind 0.0.0.0:7601.
- **Voice node (UDP):** relay between clients in the same channel; members expire after 30 s idle; jitter buffer wired into relay path.
- **Client:** connect UI, channel list, text chat, net layer, voice capture/playback wired to UI, friends/DM panel, guild bar with create + invite-accept popups, right-side member list panel, message context menu (react/edit/delete/reply/copy), custom status + activity status, block list, channel create UI, encrypted identity vault.
- **Server identity:** gateway generates or loads `server_identity.json` in the configured data directory.
- **UI refactoring:** modular structure (`app/`, `chat/`, `connect/`, `sidebar/`, `members/`, `state/`, `settings/`).
- **Session management:** reconnect with exponential backoff, node switching.
- **Audio pipeline:** PTT / VAD / always-on modes, configurable bitrate, jitter buffer.
- **Noise suppression:** RNNoise (feature-gated, off by default).
- **Bookmarks:** save/remove nodes in connect screen.
- **Docker:** multi-stage builds for gateway + voice-node, docker-compose.
- **UDP voice encryption:** ChaCha20-Poly1305 AEAD on voice packets (Phase 1.1 — DONE).
- **Direct Messages:** 1:1 DM with persistent history, canonical DM ID format (Phase 1.1 — DONE).
  - Protocol: DmStart (0x0060), DmMessage (0x0061), DmHistory (0x0062), DmReadAck, DmSearch.
  - Database: `direct_messages` and `dm_messages` tables with indexes.
  - Handlers: dm_start, dm_send, dm_history with server-authoritative timestamps and sender validation.
  - Delivery: targeted broadcast to online recipient; offline messages persisted to DB.
  - Last 50 messages returned on DM open and history fetch.
  - UI: sidebar DM list with unread badges, DM conversation panel, search bar.
- **Community model (Phase 1.2 — DONE):** guilds, roles with permission bits, invites (permanent + temporary), guild member kick, audit log on every guild mutation.
- **Friends system (Phase 1.2 — DONE):** friend requests, accept/decline, friend list with Online/All/Pending/Blocked tabs, pending count badge, Add Friend popup, per-friend DM shortcut and remove.
- **Block list (Phase 1.3 — DONE):** block/unblock commands wired end-to-end, Blocked tab UI with input + Unblock button.
- **Presence system (Phase 1.2/1.3 — DONE):** ONLINE / IDLE / DND / INVISIBLE status cycler in user bar, custom status text, activity type (playing/listening/watching/streaming) + activity text, broadcast on change, presence sync on connect.
- **Phase 1.3 chat polish:** message reactions (emoji), message editing (with "(edited)" marker), message deletion, typing indicators (multi-user), read receipts, **replies** (with italic reply indicator showing original author + snippet), **context menu** (quick-react, reply, copy, edit, delete).
- **Speaking indicators (Phase 1.3 — DONE):** green dot/ring on local user when transmitting (PTT/VAD), green highlight on remote voice panel members when voice packets arrive, voice activity banner with speaker attribution ("🔊 alice is talking").
- **Per-user speaking attribution (Phase 1.3 — DONE):** voice packet plaintext extended with sender_id (raw Ed25519 pubkey), receivers attribute activity to specific user.
- **Right-side member list panel:** shows online members of the active text channel with avatars and status dots.
- **Rate limiting (Phase 2 — DONE):** per-session token bucket on chat/DM messages (default 5/s, burst 10), `ErrorCode::RateLimited` reply on exceed.
- **Prometheus metrics (Phase 2 — DONE):** counters for messages, DMs, voice packets, connections, auth failures, rate-limited events, errors, guilds, friends requests, sessions, channels, uptime.
- **Identity encryption at rest (Phase 2 — DONE):** Argon2id passphrase + ChaCha20-Poly1305 AEAD, opt-in via passphrase; backward-compatible with legacy plain `identity.json`.
- **Channel creation UI (Phase 1.3 — DONE):** "Create a Channel" popup with name + type (text/voice) selector — adds channel to local sidebar.

---

## Implemented in code but incomplete

| Area | Reality |
|------|---------|
| Voice capture/playback | Starts when a voice channel is selected; Opus over UDP via net layer, encrypted. |
| SDK crate | Present as a stub; not a usable public API yet. |
| Federation crate | Stub only (`// TODO`). |
| RNNoise | Feature-gated, no-op stub by default. Enable with `--features rnnoise`. |
| Slint migration | Done. The client UI is Slint (RU/EN localization, themes, settings). |
| Server-side channel creation | Client-side channels work locally; gateway still needs `ChannelCreate` packet + storage (Phase 2). |
| Identity export/import UI | Vault API is ready (`identity::save(identity, Some(passphrase))`), but no UI modal yet. |

---

## Specified in docs, not implemented yet

| Feature | Target phase |
|---------|--------------|
| TLS 1.3 on TCP | Phase 2 |
| Seed phrase / encrypted keyfile export UI | Phase 2 |
| Gateway to voice-node membership signaling | Phase 2 |
| Protobuf payloads (replacing JSON) | Phase 2 |
| `/health` HTTP endpoint on gateway | ✅ DONE |
| Rate limiting | ✅ DONE |
| Prometheus metrics | ✅ DONE |
| Identity keypair encryption at rest (Argon2id passphrase) | ✅ DONE |
| Published Docker images (`ghcr.io/vnox/...`) | Not published yet |
| Server-side channel create/edit/delete | Phase 2 |
| Federation protocol spec | Phase 3 |

---

## Security notes

- **TCP control plane:** Encrypted with ChaCha20-Poly1305 (✅ Phase 1.1)
- **UDP voice data:** Encrypted with ChaCha20-Poly1305 (✅ Phase 1.1)
- **Client auth:** Ed25519 challenge-response; identity proven, transport encrypted.
- **Server pubkey:** Real (Ed25519), verified during handshake.
- **Ephemeral keys:** X25519 ECDH with HKDF-SHA256 key derivation for forward secrecy.
- **Voice node:** Transparent relay (does not decrypt voice — encrypted end-to-end between clients).
- **Identity at rest:** Optional Argon2id passphrase + ChaCha20-Poly1305 AEAD vault (✅ Phase 2).
- **Rate limiting:** Per-session token bucket on chat + DM (✅ Phase 2).

---

## Local development

Use `dev/config.toml`. See [dev/README.md](../dev/README.md).

Quick start:

```sh
cargo run -p vnox-gateway -- --config dev/config.toml
cargo run -p vnox-voice-node -- --config dev/config.toml
cargo run -p vnox-client
```

Automated voice relay check (gateway + voice-node must already be running):

```sh
cargo run -p vnox-client --bin vnox-e2e-voice
```

---

## Where to read more

- Architecture: [01-architecture.md](01-architecture.md)
- Protocol (target design): [02-protocol/README.md](02-protocol/README.md)
- Community Model: [07-community-model.md](07-community-model.md)
- Gateway Events: [08-gateway-events.md](08-gateway-events.md)
- Database Schema: [10-database.md](10-database.md)
- Roadmap: [06-roadmap.md](06-roadmap.md)
- Releases: [CHANGELOG.md](../CHANGELOG.md)
