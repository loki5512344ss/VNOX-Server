# Packets

> **Phase 1 note:** TCP control payloads are serialized as **JSON**, not Protobuf.
> Protobuf is the Phase 2 target. See [01-architecture.md](../01-architecture.md).

## Base packet

All LNEx packets share a common header, regardless of transport.

```
┌──────────────┬──────────────┬──────────────┬────────────────┬─────────┐
│  packet_id   │    flags     │   sequence   │ payload_length │ payload │
│   (2 bytes)  │  (2 bytes)   │  (4 bytes)   │   (4 bytes)    │  (var)  │
└──────────────┴──────────────┴──────────────┴────────────────┴─────────┘
```

### Fields

`packet_id` — identifies the packet type. See packet type registry below.

`flags` — bitmask:

```
bit 0  — COMPRESSED   payload is zstd compressed
bit 1  — ENCRYPTED    reserved; must be 0 on TCP since LNEx v3 (TLS protects the stream)
bit 2  — FRAGMENTED   this is a fragment of a larger payload
bit 3  — LAST_FRAG    this is the last fragment
bit 4  — ACK_REQ      sender requests acknowledgement (TCP path only)
bit 5-15 — reserved
```

`sequence` — monotonically increasing per-session counter.
On the UDP voice path, gaps in sequence indicate packet loss.

`payload_length` — byte length of the payload that follows.

`payload` - packet-type-specific data. **Phase 1:** JSON. **Phase 2:** Protobuf (planned).

---

## Voice packet

Voice packets are sent over UDP. They extend the base header with
audio-specific fields before the Opus payload.

```
┌──────────────┬──────────────┬──────────────┬────────────────┬────────────────┬────────────┐
│  packet_id   │    flags     │ voice_seq    │  timestamp     │   channel_id   │ opus_data  │
│  = 0x0010    │  (2 bytes)   │  (4 bytes)   │  (4 bytes)     │   (8 bytes)    │   (var)    │
└──────────────┴──────────────┴──────────────┴────────────────┴────────────────┴────────────┘
```

### Fields

`voice_seq` — separate sequence counter for the voice stream.
Resets per channel join. Used by jitter buffer for reordering.

`timestamp` — RTP-style timestamp in samples (48000 Hz clock).
Used for jitter buffer and playout scheduling.

`channel_id` — identifies which voice channel this frame belongs to.
Allows a single UDP socket to carry multiple channels.

`opus_data` — raw Opus-encoded frame. Length derived from `payload_length`
minus the fixed voice header (16 bytes).

---

## Packet type registry

```
0x0001  HELLO           server → client on connect
0x0002  AUTH            client → server, identity + signature
0x0003  SESSION         server → client, session established
0x0004  PING            either direction
0x0005  PONG            reply to PING

0x0010  VOICE_PACKET    UDP, client ↔ voice-node
0x0011  VOICE_STATE     speaking / silent / muted

0x0020  CHAT_MESSAGE    text message in channel
0x0021  CHAT_HISTORY    batch of historical messages

0x0030  JOIN_CHANNEL    client → gateway
0x0031  LEAVE_CHANNEL   client → gateway
0x0032  CHANNEL_STATE   gateway → client, full channel snapshot

0x0040  USER_JOIN       broadcast to channel members
0x0041  USER_LEAVE      broadcast to channel members

0x0050  PERMISSION_CHECK  gateway → client
0x0051  PERMISSION_DENY   gateway → client

0x0060  DM_START        client → gateway, initiate 1:1 DM conversation
0x0061  DM_MESSAGE      client ↔ gateway, individual DM message
0x0062  DM_HISTORY      client → gateway, fetch last 50 messages

0x0100  GUILD_CREATE     client → gateway
0x0101  GUILD_DELETE     client → gateway
0x0102  GUILD_LIST       client → gateway
0x0103  GUILD_MEMBER_JOIN    client → gateway
0x0104  GUILD_MEMBER_LEAVE   client → gateway
0x0105  GUILD_MEMBER_KICK    client → gateway
0x0106  ROLE_CREATE      client → gateway
0x0107  ROLE_DELETE      client → gateway
0x0108  INVITE_CREATE    client → gateway
0x0109  INVITE_ACCEPT    client → gateway
0x010A  INVITE_DELETE    client → gateway

0x0140  PRESENCE_UPDATE  client → gateway
0x0141  PRESENCE_SYNC    gateway → client
0x0142  PRESENCE_EVENT   gateway → client

0x0150  FRIEND_REQUEST   client → gateway
0x0151  FRIEND_ACCEPT    client → gateway
0x0152  FRIEND_DECLINE   client → gateway
0x0153  FRIEND_REMOVE     client → gateway
0x0154  FRIEND_LIST       client → gateway
0x0155  BLOCK_USER       client → gateway
0x0156  UNBLOCK_USER     client → gateway
0x0157  BLOCK_LIST       client → gateway

0x00F0  ERROR           any direction, see error codes
0x00FF  DISCONNECT      graceful close
```

---

## Direct Messages (Phase 1.1)

DM support enables 1:1 private messaging with persistent history. DMs are identified by a canonical ID format:
`dm_{lexicographically_smaller_uid}_{larger_uid}`. This ensures both participants reference the same conversation.

### DmStart (0x0060)

Client initiates or opens an existing DM conversation with another user.

```json
{
  "target_user_id": "user_pubkey_b64"
}
```

Response (server sends back as 0x0060):

```json
{
  "dm_id": "dm_userid1_userid2",
  "other_user_id": "user_pubkey_b64",
  "other_nickname": "Alice",
  "messages": [
    {
      "dm_id": "dm_userid1_userid2",
      "sender_id": "user_pubkey_b64",
      "content": "Hello!",
      "timestamp": 1234567890000
    }
  ]
}
```

### DmMessage (0x0061)

Send a new DM or receive one from another user.

```json
{
  "dm_id": "dm_userid1_userid2",
  "sender_id": "user_pubkey_b64",
  "content": "Hello Alice!",
  "timestamp": 1234567890000
}
```

Server-authoritative: sender_id and timestamp are set by the server based on the authenticated session.

### DmHistory (0x0062)

Fetch historical messages from a DM.

Request:
```json
{
  "dm_id": "dm_userid1_userid2"
}
```

Response:
```json
{
  "dm_id": "dm_userid1_userid2",
  "messages": [
    { "dm_id": "...", "sender_id": "...", "content": "...", "timestamp": 1234567890000 }
  ]
}
```

---

## Protobuf schema

Payload of each packet is a serialized Protobuf message.
Schemas live in `protocol/` at the repository root.

Example — `ChatMessage`:

```protobuf
syntax = "proto3";

message ChatMessage {
  string  message_id  = 1;  // UUID v4
  string  channel_id  = 2;
  string  sender_id   = 3;  // sender pubkey (short form)
  string  content     = 4;
  int64   timestamp   = 5;  // Unix ms
}
```

Example — `VoiceState`:

```protobuf
message VoiceState {
  string user_id   = 1;
  string channel_id = 2;

  enum State {
    SILENT  = 0;
    SPEAKING = 1;
    MUTED   = 2;
    DEAFENED = 3;
  }

  State state = 3;
}
```

Full schema reference: `protocol/*.proto`

---

## Fragmentation

Payloads larger than 1400 bytes on the UDP path are fragmented.
Each fragment carries the same `sequence`, with `FRAGMENTED` and optionally
`LAST_FRAG` flags set. The receiver reassembles before passing to the
application layer.

On TCP, fragmentation is not used — TCP handles it at the transport layer.

---

## Error codes

```
0x01  ERR_VERSION_MISMATCH     unsupported LNEx version
0x02  ERR_AUTH_FAILED          invalid signature or unknown identity
0x03  ERR_SESSION_EXPIRED      session token no longer valid
0x04  ERR_PERMISSION_DENIED    insufficient permissions for action
0x05  ERR_CHANNEL_NOT_FOUND    channel does not exist on this node
0x06  ERR_RATE_LIMITED         too many packets in window
0x07  ERR_INVALID_PACKET       malformed header or payload
0x08  ERR_NODE_UNAVAILABLE     federation target node unreachable
0x09  ERR_GUILD_NOT_FOUND      guild does not exist
0x0A  ERR_BLOCKED              you are blocked by this user
0xFF  ERR_INTERNAL             server-side error
```
