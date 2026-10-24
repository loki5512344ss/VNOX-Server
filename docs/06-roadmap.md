# Roadmap

---

## Phase 1 — MVP

Goal: a working voice + chat system you can actually use.

### Server
- [x] LNEx v1 protocol spec
- [x] Gateway: auth, sessions, channels, text chat
- [x] Voice node: UDP relay (jitter buffer code exists, not wired into relay yet)
- [x] SQLite storage: message history, user records
- [x] Docker + systemd deployment ([Dockerfile](../Dockerfile), [docker-compose.yml](../docker-compose.yml))
- [x] config.toml reference ([configuration.md](../03-server/configuration.md), [dev/README.md](../../dev/README.md))

### Client
- [x] Identity: keypair generation, Ed25519 auth
- [x] Node switcher — bookmarks with save/remove
- [x] Channel list: text + voice
- [x] Text chat
- [x] Voice chat: push-to-talk, VAD, always-on modes
- [x] Noise suppression (RNNoise, feature-gated)
- [x] Settings: voice, audio, network, identity, keybinds
- [x] Latency indicator

### Protocol
- [x] Packet format finalized (JSON framing in Phase 1)
- [x] Error codes documented

---

## Phase 1.1 — Hardening & Core Features

Goal: production-safe for small private communities.

### Encryption (Priority 1) ✅ DONE
- [x] Replace plaintext with ChaCha20-Poly1305 on all packets
- [x] X25519 ECDH key exchange during HELLO handshake
- [x] HKDF-SHA256 key derivation (client→server / server→client keys)
- [x] Encrypted TCP (control) + UDP (voice) paths
- [x] Forward secrecy via ephemeral session keys
- [x] Session nonce management for replay protection

All traffic is now encrypted. See [features/encryption.md](05-features/encryption.md).

### Direct Messages ✅ DONE
- [x] New packet type: `DM_MESSAGE` (separate from `CHAT_MESSAGE`)
- [x] Gateway routing: create private DM channel on first message
- [x] DB schema: `direct_messages` + `dm_messages` tables
- [x] UI: DM list in sidebar (like Discord)
- [x] Unread count tracking
- [x] Message sync to both participants
- [x] DM history search bar

See [features/direct-messages.md](05-features/direct-messages.md). **Backend and UI complete.**

### Private Mode ✅ DONE
- [x] Config flag: `[federation] enabled = false` / `[server] mode = "private"`
- [x] Server cannot see or reach other servers when private
- [x] No federation packets sent
- [x] Makes VNOX safe for single-server deployment (OwnCord-style)

### UI Refresh
- [x] Evaluate Slint vs egui: migrated to Slint
- [x] Custom dark theme with accent color support (#E67E22 orange)
- [x] Redesigned channel list and user bar
- [x] Consistency pass across all settings panels
- [x] Slint migration done (client UI is native Slint)

### Client Polish
- [x] Audio device labels in settings (live cpal enumeration)
- [x] Opus bitrate slider (8–128 kbps)
- [x] Jitter buffer size and adaptive mode
- [x] Per-user volume control (client-side mix)
- [x] Keybind recording UI (capture keystroke, not type string)

---

## Phase 1.2 — Community Foundation

Goal: guilds, roles, permissions, presence layer.

### Community Model (Priority 1) ✅ DONE
- [x] Guild system: create, list, delete, settings
- [x] Role system with permission bits (u64)
- [x] Permission resolution (owner → admin → roles → channel overrides)
- [x] Invite system: permanent and temporary
- [x] Guild member management: join, leave, kick
- [x] Audit log for admin actions
- [x] Invite accept popup dialog
- [x] Guild header with member count and Leave button

### Direct Messages UI ✅ DONE
- [x] DM list in sidebar (per-user, not per-guild)
- [x] DM conversation panel (similar to channel chat)
- [x] Unread badges and notification dots
- [x] Search DM history
- [x] Per-conversation volume controls

### Presence System ✅ DONE
- [x] Status types: ONLINE, IDLE, DO_NOT_DISTURB, OFFLINE, INVISIBLE
- [ ] Activity status: playing, listening, watching, streaming — **deferred**
- [ ] Custom status text — **deferred**
- [x] Broadcast on login/logout
- [x] Clickable status cycler in user bar

### Friends System ✅ DONE
- [x] Friend requests
- [x] Friends list with Online / All / Pending / Blocked tabs
- [x] Pending count badge on Friends tab
- [x] Block list (placeholder UI)
- [x] Friend notifications (incoming request badge)
- [x] Add Friend popup with user-id input
- [x] Per-friend DM shortcut and remove button

### UI Refresh ✅ DONE
- [x] Sidebar restructure for guilds + DMs
- [x] Guild switcher (vertical icons on left)
- [x] Role color display in user mentions
- [x] Category collapsing
- [x] Right-hand member list panel (online/offline per channel)

---

## Phase 1.3 — Advanced Features

Goal: typing indicators, read receipts, typing states.

### Typing & Read Status ✅ DONE
- [x] Typing indicators in text channels
- [x] Read receipts per message
- [x] Last read pointer storage
- [x] Multi-user typing indicator ("Alice and Bob are typing...")

### Voice Improvements ✅ DONE
- [x] Speaking indicators with volume levels
- [x] Voice activity detection (local visualization — green dot/border on speaking)
- [x] Adaptive bitrate negotiation
- [x] Voice activity banner ("you are talking" / "someone is talking")

### Client Polish ✅ DONE
- [x] Message reactions (emoji)
- [x] Message editing (with "(edited)" marker)
- [x] Message deletion with confirmation
- [x] Per-user volume control (client-side mix)

---

## Phase 2

Goal: scalability, federation preparation, advanced security.

### Server
- [ ] TLS 1.3 on TCP control plane
- [ ] Permission system enforcement in gateway
- [ ] Rate limiting refinement
- [ ] PostgreSQL backend (sqlx support ready, config not exposed yet)
- [ ] Prometheus metrics on gateway and voice-node
- [ ] Gateway admin API (HTTP endpoint)
- [ ] Identity keypair encryption at rest (Argon2id passphrase)

### Protocol
- [ ] Protobuf schemas (replacing JSON)
- [ ] E2EE for direct messages (optional)
- [ ] E2EE for private channels (opt-in)
- [ ] Voice regions: Warsaw, Frankfurt, Amsterdam, London, New York, Singapore

### Client
- [ ] Seed phrase backup UI
- [ ] Keyfile export / import
- [ ] Per-user volume control (client-side mix)
- [ ] Overlay: Windows, Linux X11, speaking indicators, mute/deafen state

### Federation Foundation
- [ ] LNEx federation protocol spec
- [ ] Node-to-node handshake and mutual auth
- [ ] Federation discovery (DNS SRV)

### Plugins Foundation
- [ ] Plugin runtime (Deno or QuickJS — decision required)
- [ ] WebSocket RPC API v1
- [ ] Plugin manifest and permissions
- [ ] Example plugins: moderation bot, music bot

---

## Phase 3

Goal: federation ecosystem and mobile clients.

### Federation
- [ ] Text chat bridging between nodes
- [ ] Voice relay across nodes
- [ ] Channel bridging
- [ ] Federation admin controls (trust levels, denylist)
- [ ] Shared user directory

### Plugins Ecosystem
- [ ] Plugin installer in client
- [ ] Community plugin registry (basic)
- [ ] Advanced plugins: relay-switcher, analytics, moderation suite

### Mobile
- [ ] Stack decision (Flutter / React Native / Native)
- [ ] MVP: connect, text, voice, push-to-talk
- [ ] Identity import from desktop (QR / keyfile)

---

## Future ideas (unscheduled)

Spatial audio for games, adaptive bitrate relay, distributed mesh,
VNOX SDK (Rust → TypeScript → Python), offline message queue.
