# LNEx Protocol

> **Phase 1:** JSON over plain TCP, raw Opus over UDP. Wire encryption is Phase 2.
> See [00-status.md](../00-status.md).

LNEx (Loki Network Exchange) is the networking protocol used by VNOX.

It is a custom application-layer protocol that runs over TCP and UDP.
It defines how VNOX clients and servers communicate — packet format,
encryption, routing, identity, and federation.

---

## Design goals

- low latency for voice packets (UDP path)
- reliable delivery for control messages (TCP path)
- encrypted by default in production (Phase 2 target; plaintext in v0.1.x dev builds)
- identity without central authority: keypair-based, no email, no server account registry
- federation between independent nodes (Phase 3)

## Non-goals

- backward compatibility with Discord, TeamSpeak, or Matrix
- browser / WebSocket native support (use a gateway adapter if needed)
- guaranteed ordering on the UDP voice path

---

## Version

Current version: `LNEx v3` (TCP runs inside TLS 1.3, see [tls.md](tls.md)). There is no negotiation with older versions.

Version is negotiated during handshake. Clients and servers advertise
their supported versions. If no common version exists, the connection
is rejected with `ERR_VERSION_MISMATCH`.

LNEx versioning is independent from VNOX client and server versioning.
A new VNOX release may or may not bump the LNEx version.

---

## Transport mapping

| Path | Transport | Used for |
|------|-----------|---------|
| Control | TCP | auth, chat, channels, events, federation |
| Voice | UDP | audio frames, realtime state |

Both paths use LNEx packet framing. The packet format is the same;
the transport-specific behavior (ordering, retransmit) is left to TCP/UDP.

---

## Connection lifecycle

```
Client                          Gateway
  │                                │
  │──── TCP connect ───────────────▶│
  │◀─── HELLO (server pubkey) ──────│
  │──── AUTH (client pubkey + sig) ─▶│
  │◀─── SESSION (session_id, token) ─│
  │                                │
  │   [control channel established] │
  │                                │
  │──── JOIN_CHANNEL ──────────────▶│
  │◀─── CHANNEL_STATE ──────────────│
  │                                │
  │   [UDP voice path]             │
  │──── UDP VOICE_PACKET ──────────▶│ Voice Node
  │◀─── UDP VOICE_PACKET ───────────│
```

Full state machine: see individual spec files.

---

## Sections

- [packets.md](packets.md) — packet format, base and voice packets, Protobuf schema
- [voice-pipeline.md](voice-pipeline.md) — Opus codec, UDP relay, jitter buffer
- [federation/README.md](federation/README.md) — node discovery, cross-node routing
- [identity.md](identity.md) — keypair model, auth flow, permissions
- [security.md](security.md) — encryption, threat model
- [tls.md](tls.md) — TLS 1.3 control plane, trust model, LNEx v3 handshake
