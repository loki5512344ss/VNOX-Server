# Architecture

## High-level layout

```
┌─────────────────────────────────────────────────────┐
│                    VNOX Client                      │
│              (Rust + Slint)                   │
└────────────────────┬────────────────────────────────┘
                     │ LNEx v1
          ┌──────────┴──────────┐
          │ TCP                 │ UDP
          ▼                     ▼
┌─────────────────┐   ┌──────────────────┐
│    Gateway      │   │   Voice Node     │
│  (Rust/Tokio)   │   │    (Rust)        │
│                 │   │                  │
│  auth           │   │  Opus encode     │
│  channels       │   │  UDP relay       │
│  sessions       │   │  jitter buffer   │
│  permissions    │   │  packet seq      │
│  federation     │   │  audio routing   │
└────────┬────────┘   └──────────────────┘
         │
         │ LNEx Federation (Phase 3)
         ▼
┌─────────────────┐
│  Other nodes    │
│  (federated)    │
└─────────────────┘
```

---

## Hybrid networking model

VNOX uses two transports simultaneously. They serve different purposes and
are never mixed.

### TCP — control plane

Used for everything that requires ordering and reliability:

- authentication and session setup
- channel join / leave events
- text chat messages
- permission checks
- federation routing signals

### UDP — data plane

Used for everything where latency matters more than reliability:

- voice packets (Opus frames)
- realtime presence state

Voice packets that are lost are not retransmitted. Loss is handled by
Opus packet loss concealment and the jitter buffer.

### LNEx layer

LNEx sits above both transports. It defines:

- packet format and framing
- compression
- encryption (ChaCha20, see `02-protocol/security.md`)
- routing between nodes
- federation identity resolution

LNEx is not tied to a specific transport. The same packet schema is used
over both TCP and UDP, with transport-appropriate flags.

---

## Modules

### gateway

Language: Rust
Runtime: Tokio (async)

Responsibilities:
- client authentication via identity keypair
- channel and session management
- permission enforcement
- federation routing (Phase 3)
- text chat delivery

Entry point for all TCP connections from clients.

### voice-node

Language: Rust

Responsibilities:
- receive UDP voice packets from clients
- decode Opus frames
- apply jitter buffer
- relay to other clients in the same channel
- handle packet sequencing and reordering

Can run on the same machine as the gateway or separately.

### client

Language: Rust
UI: Slint
Renderer: wgpu
Audio: cpal + rodio + opus
Networking: tokio

The desktop application. Connects to a gateway via TCP (LNEx) and to a
voice-node via UDP (LNEx). Handles all UI, audio capture, Opus encoding,
and local identity management.

Web client: not planned. Native only.

### overlay

Language: Rust (separate process or injected)
Status: Phase 2

In-game HUD showing:
- who is speaking
- current channel
- latency
- hotkey state

### plugins

Language: TypeScript / JavaScript
Runtime: Deno or QuickJS (not finalized)
API: WebSocket RPC

Sandboxed plugin environment. Plugins cannot access internals directly —
only through the documented RPC API.

### federation (Phase 3)

Handles cross-node communication:
- node discovery
- identity bridging
- voice relay across nodes
- channel bridging

---

## Tech stack summary

| Component | Language | Key deps |
|-----------|----------|----------|
| Gateway | Rust | Tokio, serde, sqlx |
| Voice node | Rust | opus, tokio |
| Client | Rust | Slint, cpal, tokio |
| Overlay | Rust | TBD |
| Plugins | TypeScript | Deno / QuickJS |

### Why Rust

- async performance via Tokio: handles thousands of concurrent connections
- memory safety without GC: no pauses during voice transmission
- strong UDP networking ecosystem
- cross-platform native binary: Windows, macOS, Linux from one codebase
- no Electron: the client is a real native application

### Serialization

JSON for Phase 1 LNEx packets — simple, debuggable, no build-time codegen.
Protobuf schemas live in `protocol/` and will replace JSON in Phase 2
without changing the wire framing (header stays identical).

---

## File structure

```
vnox/
├── client/          # Desktop client (Rust + Slint)
├── gateway/         # TCP gateway (Rust + Tokio)
├── voice-node/      # UDP voice relay (Rust)
├── federation/      # Federation layer (Phase 3)
├── protocol/        # LNEx .proto schemas + spec
├── plugins/         # Plugin runtime + example plugins
├── sdk/             # Client SDK
└── docs/            # This documentation
```

---

## Source layout conventions

### Rules

- **≤ 200 lines per file.** If a file grows past that, split it.
- **≤ 6 files per directory.** If a directory has more, introduce a subdirectory.
- **KISS / DRY / SOLID.** One file = one clear responsibility.
- Subdirectory always has a `mod.rs` that re-exports the public surface.
  Internal files are `pub(super)` or `pub(crate)` — never `pub` unless
  they are part of the module's public API.

### gateway/src

```
gateway/src/
├── main.rs              # startup: config, storage, TCP listener, spawn tasks
├── domain/              # pure business logic, no I/O
│   ├── mod.rs
│   ├── auth.rs          # Ed25519 verify, challenge generation
│   ├── channels.rs      # ChannelStore: join/leave/members
│   ├── config.rs        # Config structs + load()
│   ├── session.rs       # SessionStore: create/get/remove
│   └── storage.rs       # SQLite via sqlx: messages, users, bans
├── net/                 # network I/O
│   ├── mod.rs
│   ├── handshake.rs     # HELLO → AUTH → SESSION exchange
│   ├── io.rs            # send_packet / read_packet / send_error
│   └── state.rs         # State (shared Arc clone) + BroadcastMsg
├── proto/               # wire protocol
│   ├── mod.rs           # re-exports everything
│   ├── packet.rs        # PacketId, ErrorCode, PacketHeader
│   ├── payloads.rs      # all JSON payload structs
│   └── framing.rs       # encode_packet, to_payload
└── handler/             # per-connection request handling
    ├── mod.rs           # run_session loop + dispatch + deliver
    ├── channel.rs       # JOIN_CHANNEL / LEAVE_CHANNEL / broadcast_leave
    └── chat.rs          # CHAT_MESSAGE persist + broadcast
```

**Dependency direction:** `main` → `net` → `domain` + `proto`.
`handler` → `net` + `domain` + `proto`. No cycles.

### voice-node/src

```
voice-node/src/
├── main.rs              # config, UdpSocket::bind, recv loop
├── relay.rs             # relay_packet, add_member, remove_member
└── jitter.rs            # JitterBuffer (reorder by voice_seq)
```

Small crate — no subdirectories needed yet.

### client/src

```
client/src/
├── main.rs              # tokio runtime, identity load, eframe::run_native
├── identity.rs          # keypair gen/load, Identity struct
├── net/                 # LNEx TCP + UDP networking
│   ├── mod.rs           # NetHandle, spawn(), session_loop
│   ├── types.rs         # NetCommand, NetEvent, MemberInfo, ChatMsg
│   ├── wire.rs          # PID_* constants + all wire payload structs
│   ├── framing.rs       # read() / write() raw packets over TcpStream
│   ├── handshake.rs     # HELLO → AUTH → SESSION
│   ├── dispatch.rs      # incoming packet → NetEvent mapping
│   └── voice.rs         # build_packet(), spawn_recv() UDP loop
├── audio/               # cpal + Opus pipeline
│   ├── mod.rs           # start(), AudioPipeline, EncodedFrame, DecodedFrame
│   ├── config.rs        # find() best StreamConfig for device
│   ├── capture.rs       # cpal input → Opus encode → EncodedFrame channel
│   └── playback.rs      # Opus decode → cpal output
└── ui/                  # Slint layout
    ├── mod.rs           # VnoxApp, eframe::App impl, poll_net()
    ├── state.rs         # UiState, ConnState, Channel, ChatMessage
    ├── theme.rs         # color constants (BG_BASE, ACCENT, …)
    ├── widgets.rs       # channel_row(), message_row(), fmt_ts()
    ├── sidebar.rs       # node switcher strip + channel list panel
    ├── chat.rs          # chat area: header, scroll, input box
    └── connect.rs       # connect screen (shown when disconnected)
```

**Dependency direction:** `main` → `net` + `audio` + `ui`.
`ui` → `net::types` (read-only). `audio` is standalone.
`net` → `identity`. No cycles.

### Adding a new feature — checklist

1. Decide which crate owns it (`gateway`, `voice-node`, `client`).
2. Decide which layer it belongs to:
   - pure logic with no I/O → `domain/`
   - network I/O → `net/`
   - UI rendering → `ui/`
   - audio → `audio/`
3. Create a new file in the right subdirectory.
4. If the subdirectory now has > 6 files, split into a deeper level.
5. Re-export from `mod.rs` only what callers actually need.
6. Keep the file under 200 lines. If it grows, extract a helper module.
7. Run `cargo check` before committing.

### What goes where — quick reference

| Thing | File |
|-------|------|
| New packet type | `gateway/src/proto/payloads.rs` + `client/src/net/wire.rs` |
| New gateway handler | `gateway/src/handler/` (new file if > 200 lines) |
| New domain rule (ban, rate limit…) | `gateway/src/domain/` |
| New UI panel | `client/src/ui/` (new file) |
| New audio processing step | `client/src/audio/` (new file) |
| Config field | `gateway/src/domain/config.rs` |
| DB schema change | `gateway/src/domain/storage.rs` → `migrate()` |
