# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed (breaking): LNEx v3, TLS 1.3 on the TCP control plane
- The custom X25519 + HKDF + ChaCha20-Poly1305 layer on TCP is removed. The gateway listens with TLS 1.3 only (rustls, ALPN `vnox-lnex/3`); there is no plaintext, TLS 1.2 or LNEx v2 mode.
- Protocol version bumped `v2` to `v3`. `Hello.server_eph_pubkey` and `Auth.client_eph_pubkey` are reserved. Old clients cannot connect and old gateways are refused by new clients with an explicit error.
- Ed25519 server HELLO and client AUTH signatures now cover a TLS exporter value (channel binding) and cannot be replayed on another connection.
- Certificate: auto generated on first start in `data_dir/tls/self-signed.pem` using the server identity key (fingerprint stable, no extra secret), or `tls_cert_path` / `tls_key_path` for a CA certificate. The SPKI SHA-256 fingerprint is logged and written to `data_dir/tls/fingerprint.txt`.
- `gateway.tls_enabled = false` is now a startup error. UDP voice is unchanged.
- Design: `docs/02-protocol/tls.md`.

### Added — Phase 2 guild member list + identity export/import + channel rate limit (fourth batch)

#### Phase 2 guild member list with kick / role-assign UI (Phase E4)
- **New PacketIds:** `GuildMemberListFetch` (0x010E), `GuildMemberList` (0x010F), `GuildRoleAssign` (0x0110), `GuildRoleUnassign` (0x0111), `GuildRoleListFetch` (0x0112), `GuildRoleList` (0x0113).
- **New storage methods:**
  - `Storage::list_guild_members(guild_id)` — returns each member's nickname, joined_at, highest-role color + name (via SQL subqueries on `member_roles`/`roles`).
  - `Storage::assign_role(guild_id, user_id, role_id)` — idempotent insert into `member_roles`.
  - `Storage::remove_role_from_user(guild_id, user_id, role_id)`.
  - `Storage::list_guild_roles(guild_id)` — full role rows with permissions + position.
- **New gateway handlers:** `handle_member_list_fetch`, `handle_role_assign`, `handle_role_unassign`, `handle_role_list_fetch`.
  - Role assign/unassign require `MANAGE_ROLES` permission (or owner bypass) and append to the audit log.
- **Client wiring:** `NetCommand::{GuildMemberListFetch, GuildRoleAssign, GuildRoleUnassign, GuildRoleListFetch}` + `NetEvent::{GuildMemberList, GuildRoleList}` + dispatch + UI handling.
- **👥 button in guild bar** — opens the guild members modal (disabled when no guild is selected). On open, fetches both member list and role list in parallel.
- **Guild members modal:**
  - Member rows with role-colored avatar ring + nickname + role name + truncated user ID.
  - 👑 crown indicator for the guild owner.
  - 👢 kick button (hidden for owner) — calls `GuildMemberKick` and auto-refreshes the list after 200 ms.
  - "+ role" combo — lists all guild roles; clicking a role name calls `GuildRoleAssign`.
  - ↻ refresh button.
  - "N members" header with close button.

#### Phase 2 server-side channel rate limit (Phase E6)
- `handle_channel_create` now consumes a token from the per-session rate limiter (same bucket as chat/DM messages).
  - When exceeded, replies `ErrorPayload{ RateLimited }` with message "slow down — too many channel operations".
  - Bumps `rate_limited_events_total` counter.
- Default channels ("general", "voice") remain protected from deletion (already in place from previous batch).

#### Phase 2 identity export / import to keyfile (Phase E7)
- **`identity::export_keyfile(identity, passphrase)`** — serializes the identity to JSON, seals it with the same Argon2id + ChaCha20-Poly1305 scheme as the on-disk vault, returns the keyfile JSON string. Passphrase is optional (empty = plain JSON).
- **`identity::import_keyfile(keyfile_json, passphrase)`** — opens a keyfile and returns the deserialized identity (without persisting — caller calls `save()` separately).
- **Export keyfile modal** in Settings → Identity:
  - Optional passphrase + confirm field (with mismatch check).
  - "Generate keyfile" button produces the JSON output.
  - Output shown in a scrollable multiline text box.
  - "⧉ Copy" button to clipboard.
  - "Save to disk" button writes to `~/Documents/vnox-<nickname>-<pubkey8>.vnoxkey`.
- **Import keyfile modal:**
  - Multiline paste area for the keyfile JSON.
  - Optional passphrase field.
  - "Import & Replace Identity" button — calls `import_keyfile` + `save(identity, None)`.
  - Warning that the current identity will be replaced; restart required.
- New `UiState` fields: `export_keyfile_open`, `export_keyfile_pass`, `export_keyfile_confirm`, `export_keyfile_output`, `export_keyfile_error`, `import_keyfile_open`, `import_keyfile_input`, `import_keyfile_pass`, `import_keyfile_error`.

### Build verification

- `cargo clippy --workspace` — 0 warnings.
- `cargo test --workspace` — 41/41 tests pass.

### Added — Phase 2 server-side channels + identity vault UI + audit log (third batch, kept for history)

#### Phase 2 server-side channel management
- **`ChannelCreate` packet (0x0033)** — register a new channel in the gateway's channel store.
  - Validates `kind` ("text" or "voice"); rejects empty `channel_id`.
  - Returns `ChannelState` to the creator and broadcasts `ChannelCreate` to all other sessions.
  - Returns `ErrorPayload{ ChannelNotFound }` (reused code) if a channel with the same id exists.
- **`ChannelDelete` packet (0x0034)** — remove a channel from the store.
  - Protects default channels ("general", "voice") with `PermissionDenied`.
  - Broadcasts `ChannelDelete` to all sessions; client removes it from sidebar and clears cached messages.
- **`ChannelList` packet (0x0035)** — fetch all known channels. Client replaces its local list with the server-authoritative one (preserving member lists for channels already joined).
- New `channels::create` / `channels::delete` / `channels::list` ops on the gateway.
- Client wiring: `NetCommand::{ChannelCreate, ChannelDelete, ChannelList}` + `NetEvent::{ChannelCreated, ChannelDeleted, ChannelListEvent}` + dispatch + UI handling.
- **Channel create popup** now sends `ChannelCreate` to the gateway instead of adding locally — sidebar updates come back through the broadcast.
- **Channel delete context menu** — right-click any non-default channel in the sidebar to delete it.

#### Phase 2 identity vault UI
- **Set-passphrase modal** in Settings → Identity:
  - Two passphrase fields with match check + min-8-char warning.
  - Calls `identity::save(identity, Some(passphrase))` to encrypt the keypair at rest with Argon2id + ChaCha20-Poly1305.
  - Shows error messages on save failure.
- **Remove-passphrase modal** — type `REMOVE` to confirm; calls `identity::save(identity, None)` to revert to plain JSON.
- **Vault status block** — shows current encryption state (🔒 encrypted / 🔓 plain) with explanatory text.
- **Copy pubkey button** — copies the hex pubkey to clipboard via `egui::Context::copy_text`.
- New `UiState` fields: `vault_set_open`, `vault_remove_open`, `vault_passphrase_input`, `vault_passphrase_confirm`, `vault_error`.

#### Phase 2 audit log viewer
- **`GuildAuditLogFetch` packet (0x010C)** — admin-only endpoint; requires `MANAGE_GUILD` permission (or owner).
  - Returns last 50 audit log entries (clamped 1..=200) via `GuildAuditLogPayload`.
- New storage method `Storage::get_audit_log(guild_id, limit)` — newest first.
- Client wiring: `NetCommand::GuildAuditLogFetch`, `NetEvent::GuildAuditLog`, dispatch, `UiState.audit_log_entries`.
- **📋 button in guild bar** — opens the audit log modal for the active guild (disabled when no guild is selected).
- **Audit log modal** — scrollable list of entries with:
  - Action-specific icons (🏗 create, 🗑 delete, 👢 kick, 🏷 role, 🔗 invite, ✓ accept).
  - Actor ID (truncated to 8 hex chars), target ID, reason (italic).
  - Relative timestamp ("2m ago", "3h ago", "5d ago").
  - Empty state with explanation.

### Fixed

- Renumbered `PID_FRIEND_EVENT` from 0x0155 to 0x0158 to avoid collision with server `BlockUser=0x0155` (already done in previous batch, re-confirmed here).

### Build verification (third batch)

- `cargo clippy --workspace` — 0 warnings.
- `cargo test --workspace` — 41/41 tests pass.

### Added — Phase 2 hardening + Phase 1.3 polish (second batch, kept for history)

#### Phase 2 server hardening
- **Admin HTTP server (axum) on gateway.** Default bind `0.0.0.0:7601`, configurable via `[gateway] admin_bind`.
  - `GET /health` — JSON `{status, uptime_seconds, node, address, private_mode}` for orchestrator liveness probes.
  - `GET /version` — `{name, version, lnex_version}`.
  - `GET /metrics` — Prometheus text exposition format v0.0.4 with counters/gauges for messages, DMs, voice packets, connections, auth failures, rate-limited events, errors, guilds, friends requests, sessions, channels, uptime.
- **Per-session token-bucket rate limiting** on chat and DM messages.
  - Configurable via `[gateway] message_rate_per_sec` (default 5) and `message_rate_burst` (default 10).
  - When a session exceeds the limit, server replies `ErrorPayload{ code: RateLimited }` and bumps `rate_limited_events_total` counter.
  - Idle buckets are pruned on session disconnect via `RateLimiter::remove()`.
- **Prometheus metrics module** (`gateway/src/admin/metrics.rs`) with lock-free atomic counters shared across all session tasks.
- **`ensure_column` idempotent migration helper** — adds new SQLite columns on existing databases without dropping data. Used to add `messages.reply_to` for the reply feature.

#### Phase 2 identity security
- **Encrypted identity vault** (`client/src/identity_vault.rs`) — Argon2id passphrase + ChaCha20-Poly1305 AEAD.
  - Vault format: `{version, scheme, salt, nonce, ciphertext, plaintext}` (JSON).
  - When passphrase is set, identity is encrypted at rest with Argon2id (m=64 MiB, t=3, p=4) for KDF + ChaCha20-Poly1305 AEAD.
  - When passphrase is empty, falls back to plain JSON (legacy behavior preserved).
  - Backward-compatible: legacy `identity.json` is auto-migrated to `identity.vault.json` on next save.
  - `is_vault_encrypted()` for UI to show lock state.
  - Unit tests: roundtrip encrypted, wrong passphrase fails, plaintext roundtrip, empty passphrase treated as plain.

#### Phase 1.3 chat UX
- **Message context menu** (right-click on any message row):
  - Quick-reactions row (👍 ❤️ 😂 🎉 👀 🤔) — toggles reaction on click.
  - Reply — sets `replying_to` state, preview bar shown above chat input.
  - Copy text — copies message content to clipboard via `egui::Context::copy_text`.
  - Edit (own messages only) — fills chat input with current content, switches to edit mode.
  - Delete (own messages only) — sends MessageDelete to gateway.
- **Reply feature** end-to-end:
  - Wire protocol: `ChatMessagePayload.reply_to: Option<String>` (optional message_id).
  - DB schema: `messages.reply_to TEXT` column (added via `ensure_column` migration).
  - `NetCommand::SendChat { reply_to: Option<String> }` carries the reference through the network layer.
  - UI: italic "↳ alice: <snippet>" preview above the message body when `reply_to` is set.
- **Custom status + activity status UI**:
  - Right-click on user-bar status label opens a context menu.
  - Status picker: Online / Idle / DND / Invisible (with color dots).
  - Custom status text editor (Discord-style "what's on your mind?").
  - Activity type combo (Playing / Listening / Watching / Streaming) + activity text input.
  - All changes sync to gateway via `PresenceUpdate` with `activity_type`/`activity_text`/`custom_status` fields.
  - User bar displays: voice state → custom status → activity (icon + text) → online/latency.

#### Phase 1.3 block list (was: placeholder)
- **Block / Unblock commands** wired end-to-end:
  - Client: `NetCommand::BlockUser`, `UnblockUser`, `BlockList` + payloads + PID constants (0x0155-0x0157).
  - Server handlers (already present) now reachable.
  - Client events: `NetEvent::BlockList`, `BlockedUser`, `UnblockedUser` dispatched to `social::handle`.
  - `blocked_users: Vec<String>` field on `UiState`.
  - Friends panel "Blocked" tab now shows: input row to block by user ID, list of blocked users with "Unblock" button.
  - Auto-fetches block list on first open of the Blocked tab.

#### Phase 1.3 per-user speaking attribution
- **Voice packet protocol extended** — plaintext now includes `[sender_id:32]` (raw Ed25519 pubkey) between channel_id and opus data.
  - `voice::build_packet()` accepts `sender_pubkey: &[u8; 32]`.
  - `voice::spawn_recv()` parses sender_id and emits hex-encoded `sender_id` in `NetEvent::VoicePacket`.
  - Legacy packets (no sender_id) gracefully handled — empty `sender_id` string.
  - Unit test `build_packet_header_layout` updated to verify sender_id roundtrip.
- **Per-user speaking indicator in voice panel**:
  - `last_remote_speaker_id` field on `UiState`, updated on every received voice packet.
  - Voice panel matches `last_remote_speaker_id` against channel members and highlights only the speaking member (green border, name, 🔊 emoji).
  - Voice activity banner now shows the speaker's nickname: "🔊 alice is talking" instead of generic "someone is talking".
  - Speaker ID decays after 500 ms of silence (driven by `remote_speaking(500)`).

#### Phase 1.3 channel creation UI
- **"Create a Channel" popup** — accessible from the channel list header via the "+" button.
  - Input: channel name (free text).
  - Type selector: Text (`#`) or Voice (`🔊`).
  - Creates the channel in the local `s.channels` list so it appears in the sidebar immediately.
  - Future JoinChannel attempt will register with the gateway (server-side channel-create is Phase 2 backend work).

### Fixed

- **NetEvent dispatch bug (from previous commit):** `GuildMemberKicked`, `InviteCreated/Accepted/Deleted`, `RoleCreated/Deleted` were silently dropped — now routed to `social::handle`.
- **`FriendAccepted` handler (from previous commit):** now uses `user_id` and adds the friend to the list.
- **PID collision:** `PID_FRIEND_EVENT` was 0x0155, conflicting with server `BlockUser=0x0155`. Renumbered: `BlockUser=0x0155`, `UnblockUser=0x0156`, `BlockList=0x0157`, `FriendEvent=0x0158`.
- **PresenceUpdate wire format mismatch:** client was sending `{custom_status, activity}` but server expected `{activity_type, activity_text}`. Now the client serializes `activity_type`/`activity_text`/`custom_status` correctly, matching the gateway's `PresenceUpdatePayload`.

### Documentation

- `docs/00-status.md` and `docs/06-roadmap.md` updated in previous commit — Phase 1.1/1.2/1.3 marked DONE where implemented.
- `CHANGELOG.md` expanded with all new entries.

### Build verification (second batch)

- `cargo clippy --workspace` — 0 warnings.
- `cargo test --workspace` — 41/41 tests pass (22 in client lib incl. new rate_limit + vault tests, 10 in gateway, 9 in voice-node).

## [0.1.0] - 2025-05-21

### Added

- Initial workspace: gateway, voice-node, client, sdk stub, federation stub.
- LNEx Phase 1 over TCP (JSON payloads): auth, channels, text chat.
- UDP voice relay between clients in the same channel.
- SQLite message history and user records.
- Desktop client shell with egui UI and net layer.

[Unreleased]: https://github.com/loki5512344ss/VNOX-Server/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/loki5512344ss/VNOX-Server/releases/tag/v0.1.0
