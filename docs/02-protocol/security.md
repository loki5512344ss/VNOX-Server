# Security

> **LNEx v3 status.** TCP traffic runs over TLS 1.3.
> UDP voice path is still plaintext (Phase 2). See
> [features/encryption.md](../05-features/encryption.md) for details.

## Threat model

VNOX is designed for self-hosted deployments where the node operator is trusted.
The threat model covers:

| Threat | Mitigated by |
|--------|--------------|
| MITM on client-server connection | TLS 1.3 with SPKI pinning / public CA, channel-bound Ed25519 auth |
| MITM on UDP voice path | LNEx packet encryption (Phase 2; not active in v0.1.x) |
| Rogue node in federation | Mutual keypair authentication on federation handshake (Phase 3) |
| Identity spoofing | Ed25519 signature on every auth (challenge-response) |
| Metadata leakage (who talks to whom) | Phase 2 |
| Passive voice interception | Packet encryption (Phase 2; not active in v0.1.x) |
| Replay attacks | Sequence number + nonce per packet (Phase 2 wire encryption) |
| Brute-force on session | Sessions are short-lived, token is not a password |

### Out of scope

- Physical access to the server
- Compromised node operator (they own the node, this is by design)
- E2EE between clients (planned Phase 2, not in v1)
- Anonymity / traffic analysis resistance

---

## Encryption

TCP control traffic is protected by **TLS 1.3** (rustls, ALPN `vnox-lnex/3`). The earlier
LNEx v2 per-frame ChaCha20-Poly1305 layer is removed. Trust model, certificate handling,
channel binding and version bump: see [tls.md](tls.md).

- Self-hosted servers: self-signed certificate (key = server identity), client pins the SPKI
  SHA-256 fingerprint on first use and blocks any change.
- Public CA certificates are accepted without a prompt.
- Ed25519 client authentication is signed over a TLS exporter value so it cannot be relayed.
- A TLS-terminating reverse proxy is not supported (it breaks the channel binding); use TCP passthrough.

### UDP transport

UDP has no TLS. LNEx packet encryption (ChaCha20-Poly1305) is the only
protection layer on the voice path. This is standard practice for
real-time voice protocols (SRTP, DTLS-SRTP follow the same model).

---

## E2EE (Phase 2)

In v1, encryption is between client and server (node). The node operator
can theoretically decrypt voice and text in transit.

Phase 2 will introduce optional end-to-end encryption for:
- direct messages
- private channels (opt-in)

E2EE for voice is significantly harder (requires key distribution to all
channel members in real time) and is a Phase 4 design question.

---

## Identity verification

When user A sees a message from `raven@nightcore.lnex`, how do they know
it's the same raven they spoke to yesterday?

In v1: the gateway enforces that a connected user's pubkey matches their
asserted identity. The client can verify the server's claim by checking
the pubkey shown in the UI against a known value.

Future: out-of-band key verification (QR code, safety number, similar to Signal).

---

## Rate limiting and anti-flood

Applied at the gateway level:

| Limit | Default | Configurable |
|-------|---------|-------------|
| Auth attempts per IP | 5 / minute | yes |
| Messages per user per second | 10 | yes |
| Voice packet rate per user | ~50/s (20ms frames) | no (codec-determined) |
| Federation connection attempts | 3 / minute per remote | yes |
| Max concurrent connections per IP | 4 | yes |

Exceeding a rate limit returns `ERR_RATE_LIMITED` and may trigger a
temporary ban depending on node configuration.

---

## Node operator notes

### What the operator can see

- IP addresses of connected clients
- usernames (nicknames) and pubkeys
- channel activity (who joined when)
- message content (in v1, no E2EE)

### What the operator cannot do (by design)

- impersonate a user's identity (requires their private key)
- forge signatures on behalf of a user

### Recommended hardening

- if a proxy is used, pass TCP through (no TLS termination)
- restrict UDP port to known IP ranges if possible
- enable fail2ban or equivalent on auth failure logs
- back up the node keypair (used for federation identity)
- rotate node keypair on suspected compromise

See `03-server/operations.md` for hardening checklist.
