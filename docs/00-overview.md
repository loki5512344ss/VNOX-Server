# Overview

> Start with [00-status.md](00-status.md) for what is implemented in v0.1.x vs what is only specified.

## What is VNOX

VNOX is a **self-hosted, federated, encrypted, plugin-first** realtime communication platform for communities and gamers.
It handles voice, text chat, and presence — without requiring any central infrastructure.

Every VNOX deployment is a node. Nodes can federate with each other.
You own your data, your identity, your infrastructure.

## What is LNEx

LNEx (Loki Network Exchange) is the protocol layer VNOX runs on.

It sits above TCP and UDP and handles:

- packet structure and framing
- encryption
- routing between nodes
- federation identity

LNEx is versioned independently from VNOX clients and server implementations.
Current version: `LNEx v1`.

## What VNOX is not

VNOX is not a Discord clone. It does not have a central server, centralized accounts,
or a cloud dashboard. There is no VNOX Inc. managing your community.

VNOX is not a TeamSpeak clone. The architecture is different:
federated, modular, and built for modern async networking.

VNOX is not SaaS. There is no subscription. There is no hosted version.
You run it, you own it.

---

## What does VNOX mean

**Self-hosted** — you run it, you own it. No cloud, no vendor lock-in, no subscription.

**Federated** — nodes can talk to each other. Your community isn't an island (Phase 3).

**Encrypted** - the control plane runs over TLS 1.3, voice over per-route ChaCha20-Poly1305 keys. Forward secrecy by default.

**Plugin-first** — extend the platform with plugins via WebSocket RPC. Bots, moderation, automations. Sandboxed by design.

---

## Core Philosophy

### 1. Self-hosted first

Users host their own nodes. There is no required central infrastructure.
A VNOX network can exist entirely between privately operated machines.

Typical deployment:
- community server (gateway + voice node)
- private relay node
- federation gateway (Phase 3)

### 2. Realtime first

Voice latency is the primary performance target. Everything else is secondary.

Targets:
- end-to-end voice latency < 50ms on local network
- jitter buffer adaptive, default 40ms
- packet loss concealment via Opus

### 3. Modular architecture

Every function is a separate module:

```
gateway      — auth, channels, sessions, permissions, federation routing
voice-node   — Opus encoding, UDP relay, jitter buffer, packet sequencing
overlay      — in-game HUD, speaking indicators
plugins      — bots, automations, moderation
```

Modules can be deployed together or separately.

### 4. Developer-first

VNOX ships with:
- protocol specification (LNEx)
- plugin API (WebSocket RPC)
- SDK
- full configuration reference

Third-party clients and server implementations are explicitly supported.

---

## Branding

### Product names

```
VNOX          — the platform
VNOX Client   — desktop application
VNOX Node     — server / gateway instance
VNOX Overlay  — in-game HUD
LNEx          — the protocol layer
LNEx v1       — current protocol version
LNEx Relay    — relay node
LNEx Federation — cross-node federation
```

### URL scheme

```
vnox://server/channel     — connect to channel
lnex://node               — raw node address
```

### Identity format

```
user@node                 — federated identity
4f3a8b2c…                 — local pubkey short form
```

---

## Comparison

| | VNOX | Discord | TeamSpeak | Mumble | Matrix |
|---|---|---|---|---|---|
| Self-hosted | required | no | yes | yes | yes |
| Federated | Phase 3 | no | no | no | yes |
| No central accounts | yes | no | no | yes | no |
| Native client | yes | custom desktop stack | yes | yes | Electron |
| Plugin API | yes | yes | yes | no | no |
| Voice codec | Opus | Opus | Opus | Opus | Opus |
| Protocol | LNEx (custom) | proprietary | proprietary | MUMBLE | Matrix |
| Open source | yes | no | no | yes | yes |

### Use cases

**Gaming clan / CS2 / shooter community**
Low latency voice, push-to-talk, overlay, private node. Phase 1 covers this fully.

**OSS project community**
Self-hosted, no vendor dependency, plugin API for bots and CI integrations.

**Private team / corp**
On-premise deployment, no data leaving your infrastructure, identity without email.
