# TLS 1.3 for the TCP control plane (LNEx v3)

> Status: design accepted and implemented together with this document.
> This is a **breaking change**: LNEx v2 (custom X25519 + HKDF + ChaCha20-Poly1305
> layer on TCP) is removed. The protocol version is bumped to `v3`.
> UDP voice is **not** affected (see [Voice](#voice-udp-is-unchanged)).

## Goals

1. Replace the home-grown encrypted framing on the TCP control plane with standard
   TLS 1.3 ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)) implemented by `rustls`
   (no OpenSSL).
2. Work for self-hosted servers that have no public CA certificate, without asking
   users to click through "accept anything" warnings.
3. Keep the existing Ed25519 identity model: the server identity (`server_identity.json`)
   and the client identity keep their meaning.
4. No silent fallback: no plaintext mode, no TLS 1.2, no LNEx v2 handshake.

## Non-goals

- Changing the UDP voice relay or its keys.
- Federation (node to node) TLS. This document covers client to gateway only.
- Mutual TLS with client certificates. The client is authenticated at the LNEx layer
  with its Ed25519 key (see [Client authentication](#client-authentication-over-tls)).

## Summary of decisions

| # | Decision |
|---|----------|
| D1 | `rustls` 0.23 with the `aws_lc_rs` provider, **TLS 1.3 only** on both sides. ALPN `vnox-lnex/3` is required. |
| D2 | The server certificate is either user supplied (`tls_cert_path` / `tls_key_path`, for example Let's Encrypt) or **auto generated** on first start and stored in `data_dir/tls/self-signed.pem`. |
| D3 | The auto generated certificate uses the **server identity Ed25519 key as its TLS key**. Therefore the certificate fingerprint is a pure function of the identity key, survives certificate regeneration, and no second private key is stored. |
| D4 | The **pin** is `SHA-256(SubjectPublicKeyInfo DER)` of the leaf certificate (the "SPKI fingerprint"). It is the trust anchor for self-signed servers. |
| D5 | Client trust is **pin first**: stored pin wins over everything. No pin: try normal WebPKI validation (bundled Mozilla roots, hostname must match). If that fails, **TOFU**: the user sees the fingerprint and must confirm before anything is sent. |
| D6 | A changed fingerprint is a **hard block** with a warning. There is no "connect anyway". The only way forward is an explicit "forget this server" followed by a new trust decision. |
| D7 | The Ed25519 client authentication stays, but its signature covers a **TLS exporter value (channel binding)**, so it cannot be relayed over another TLS connection. The server HELLO is signed with its identity key over the same binding. |
| D8 | The X25519 + HKDF + ChaCha20-Poly1305 layer on TCP, the `ENCRYPTED` packet flag on TCP and the ephemeral key fields in `Hello` and `Auth` are removed. |
| D9 | LNEx version is bumped from `v2` to `v3`. Old clients and old servers fail with an explicit error. Downgrade is impossible by construction. |

## Threat model

| Threat | Mitigation |
|--------|-----------|
| Passive network observer | TLS 1.3 (AEAD, forward secrecy). |
| Active MITM terminating TLS with its own certificate | Pin mismatch (known server) or TOFU prompt showing a different fingerprint (new server). Even if the user accepted a wrong fingerprint, the MITM cannot produce the server's Ed25519 signature over this connection's exporter, and the client rejects a server identity that differs from the stored one. |
| MITM relaying the server's HELLO to the client | HELLO signature covers the exporter of the TLS session between the client and the relay, which differs from the relay to server session. Verification fails. |
| Malicious server relaying a client's AUTH to another server | AUTH signature covers the exporter of the connection to the malicious server. Another server computes a different value and rejects it. |
| Downgrade to plaintext, TLS 1.2 or LNEx v2 | The client never opens a plaintext socket, the rustls configs list only TLS 1.3, the server requires ALPN `vnox-lnex/3`, and the version string `v3` is inside the signed transcripts. |
| First connection MITM (TOFU weakness) | Unavoidable without a CA or out of band data. Mitigation: the server prints its fingerprint at startup and writes it to `data_dir/tls/fingerprint.txt`; owners should publish it with the invitation, users compare before confirming. Public CA certificates skip TOFU. |
| Compromised or replaced server key | Fingerprint changes, clients block (D6). |

Out of scope: a compromised server host, a user who ignores a fingerprint mismatch and
explicitly forgets the server.

## Server

### Certificate sources

```toml
[gateway]
bind = "0.0.0.0:7600"
# Optional. Both or none. PEM certificate chain (leaf first) and PKCS#8/SEC1/PKCS#1 key.
# tls_cert_path = "/etc/letsencrypt/live/chat.example.org/fullchain.pem"
# tls_key_path  = "/etc/letsencrypt/live/chat.example.org/privkey.pem"
```

- Neither set: the gateway loads `data_dir/tls/self-signed.pem`. If the file is missing,
  unreadable or its public key does not match the server identity, it is regenerated
  (it contains no secret, the key is the identity key). SAN entries: `node.address`,
  `localhost`, `127.0.0.1`, `::1`. Validity is long (the client does not use expiry for
  pinned servers).
- Both set: the chain and key are loaded at start, validated to match, and used as is.
  Renewal requires a gateway restart (hot reload is a possible follow-up).
- Only one set: startup error.
- `tls_enabled` is deprecated. `true` is accepted with a warning, `false` is a startup
  error: **plaintext is no longer supported**.

At startup the gateway logs `TLS SPKI SHA-256 fingerprint: <hex>` and writes it to
`data_dir/tls/fingerprint.txt` (public information).

### TLS parameters

- Protocol versions: TLS 1.3 only (`rustls::version::TLS13`).
- Cipher suites: the rustls defaults for TLS 1.3 (AES-GCM, ChaCha20-Poly1305).
- ALPN: `vnox-lnex/3`. A connection without the negotiated ALPN is dropped before any
  LNEx byte is read.
- No client certificates.
- Handshake timeouts: 15 seconds for the TLS handshake and 15 seconds for the LNEx HELLO/AUTH/SESSION exchange.

### Reverse proxies

The exporter binding (below) is computed per TLS session. A proxy that **terminates**
TLS breaks authentication by design. If a proxy is used it must forward the TCP stream
(`stream`/SNI passthrough, HAProxy `mode tcp`) and must not terminate TLS.

### Legacy and plaintext clients

The server peeks at the first byte of a new connection (up to 2 seconds).
A TLS client sends a handshake record (`0x16`) immediately. Anything else (a v2 client
waits for the server HELLO and sends nothing, a plaintext client sends LNEx bytes)
receives one plaintext LNEx `Error` frame, `ErrorCode::VersionMismatch`, with the message
`TLS 1.3 required (LNEx v3): update your client`, and the connection is closed. This
frame is the only plaintext the gateway ever writes and it contains no secrets.

## Client

### Trust store

File: `<config dir>/vnox/known_servers.json` (Linux: `~/.config/vnox/`), written atomically
with mode `0600` on Unix.

```json
{
  "version": 1,
  "servers": {
    "chat.example.org:7600": {
      "trust": "pin",
      "spki_sha256": "9f...64 hex chars...",
      "identity": "ab...64 hex chars (Ed25519 server key)...",
      "first_seen": 1790000000
    }
  }
}
```

The key is the lower-cased `host:port` (default port 7600). `trust` is `pin` or `ca`.
`spki_sha256` exists only for `pin`. `identity` is stored after the first successful
authenticated handshake.

Bookmarks (the "saved servers" list) are only address labels; trust decisions are
independent of them and keyed by `host:port`, so removing a bookmark does not revoke trust.

### Connection algorithm

```
parse address (scheme lnexs:// or lnex:// is cosmetic, both mean TLS 1.3)
rec = trust_store[host:port]

TLS 1.3 handshake with a custom ServerCertVerifier:
  rec.trust == pin : cert SPKI sha256 must equal rec.spki_sha256
                       else ERROR FingerprintChanged (hard block, D6)
  rec.trust == ca  : WebPKI chain + hostname validation must succeed
                       else ERROR CertificateInvalid (hard block, no TOFU downgrade)
  no record        : WebPKI validation succeeds        -> trust = ca
                     otherwise                           -> probe: finish the TLS
                       handshake, send NOTHING, close, and report
                       UntrustedServer { fingerprint } to the UI
  (in every case the TLS 1.3 CertificateVerify signature is verified by rustls)

UI on UntrustedServer: show host, fingerprint (grouped hex), "Trust" / "Cancel".
  Trust  -> trust_store[host:port] = { pin, fingerprint }, reconnect.

LNEx v3 handshake inside the tunnel (see below)
  after a valid server HELLO:
    rec.identity set and != server_pubkey -> ERROR IdentityChanged (hard block)
    otherwise store identity (TOFU of the identity inside an already trusted channel)
```

Because the probe finishes the TLS handshake without sending application data, the
client's Ed25519 signature and nickname are never sent to an unverified endpoint.

The client uses the bundled Mozilla root set (`webpki-roots`), not the operating system
store, so behaviour is identical on all platforms. Servers with a private CA use the
pin path.

### Fingerprint changes

When a pinned server presents another SPKI the client:

1. aborts the connection before sending any LNEx data,
2. does **not** retry automatically (auto reconnect is suspended for this error),
3. shows a warning with the expected and the received fingerprint,
4. offers "Forget this server". After forgetting, the next connect starts a fresh
   TOFU decision. This is deliberate friction: it is the only path for a legitimate
   server migration (for example moving from a self-signed certificate to Let's Encrypt
   or restoring a server without its `server_identity.json`).

## LNEx v3 handshake inside TLS

The 12 byte packet header and protobuf payloads are unchanged. Frames are written
directly into the TLS stream. The `flags` field must be `0` on the TCP control plane
(the `ENCRYPTED` flag is rejected).

```
Client                                   Gateway
  | -- TCP + TLS 1.3 handshake (ALPN) ---> |
  |    both sides: binding = Export("EXPORTER-VNOX-LNEx-v3-channel-binding", no context, 32)
  | <------ HELLO (seq 0) ---------------- |  lnex_version="v3", server_pubkey, challenge_nonce,
  |                                        |  node_name, private_mode, server_signature
  | ------- AUTH (seq 0) ----------------> |  client_pubkey, nickname, lnex_version="v3", signature
  | <------ SESSION (seq 1) -------------- |  session_id, token, expires_at
```

Signatures (Ed25519, strict verification):

```
server_signature = Sign(server_key,
    "VNOX-LNEx-v3-server-hello\0" || binding || protobuf(Hello with server_signature empty))

client signature = Sign(client_key,
    "VNOX-LNEx-v3-client-auth\0" || binding
    || u32be(len(signed_hello)) || signed_hello
    || protobuf(Auth with signature empty))
```

`binding` is unique per TLS session (RFC 8446 section 7.5, RFC 5705), so a signature made on
one connection fails on every other connection. The client signature also covers the
signed HELLO, which carries the server challenge and server key, so the client proves
"I am talking to this server key on this channel".

### What stays from v2

- Ed25519 client identity and challenge-response authentication (now channel bound).
- Server Ed25519 identity and signed HELLO (now channel bound, identity is the stable
  anchor that survives certificate changes).
- `Session` packet with `session_id` and `token`.
- Ban check, rate limiting, protobuf payloads, packet ids, packet header, sequence
  numbers (kept as a cheap ordering sanity check, no longer part of a nonce).

### What is removed

- `Hello.server_eph_pubkey` (field 5) and `Auth.client_eph_pubkey` (field 5) are reserved
  in `lnex.proto`.
- `SessionCrypto` (X25519 ECDH, HKDF-SHA256, ChaCha20-Poly1305 per frame) on the gateway and
  the client, and the `ENCRYPTED` flag on TCP frames.
- The optional, off by default `tls_enabled` listener that wrapped the old protocol.
- The client's plaintext loopback shortcut and the `lnex://` plaintext scheme.

### Voice (UDP) is unchanged

Voice keys are not derived from the TCP handshake. The gateway creates per route random
`c2s_key` and `s2c_key` and delivers them in the `VoiceSession` packet over the control
connection. Previously they were protected by the LNEx layer, now by TLS 1.3. The UDP
format, nonces and the voice node are untouched. `vnox-e2e-voice` keeps working and only
needs the client to trust the gateway certificate (`--trust-first-use` or `--fingerprint`).

## Version bump and incompatibility behaviour

| Client | Server | Result |
|--------|--------|--------|
| v3 | v3 | works |
| v2 (old) | v3 | server sends a plaintext `Error(VersionMismatch)` "TLS 1.3 required (LNEx v3): update your client"; an old client shows a handshake error or times out. Nothing is negotiated. |
| v3 | v2 (old) | the server answers the TLS ClientHello with LNEx bytes. The client maps the rustls decode failure to "The server does not speak TLS 1.3 (LNEx v3). It is probably an outdated server, ask the owner to update." No retry in plaintext. |
| v3, TLS 1.2 only peer | v3 | handshake failure, protocol version alert, same explicit message. |
| v3 | v3 with `lnex_version` other than `v3` in HELLO/AUTH | `VersionMismatch`, connection closed. |

There is no version negotiation and no compatibility window: the old handshake is not
implemented in the new binaries.

## Operations: enabling it on a server

1. Update the gateway (and `serverd`) to the LNEx v3 build. Remove `tls_enabled = false`
   if present.
2. Self-signed: nothing to configure. Start the gateway, read the fingerprint from the
   log or `data_dir/tls/fingerprint.txt`, publish it to your users.
   CA certificate: set `tls_cert_path` and `tls_key_path`, restart after renewals.
3. Make sure the firewall allows TCP 7600 as before and that no TLS terminating proxy is
   in front of it.
4. Update all clients. Old clients cannot connect.
5. Users: on the first connection compare the shown fingerprint with the published one
   and press "Trust".

## Test plan

- Fingerprint extraction from a certificate (DER SPKI) and formatting.
- Pin accepted, changed pin rejected, unknown server reported with its fingerprint,
  CA-mode failure not downgraded to TOFU.
- A TLS 1.2 only client is rejected by the gateway listener.
- A client without ALPN is rejected.
- A plaintext or v2 client receives the explicit version error.
- A client signature made for connection A is rejected on connection B.
- A server HELLO signature made for connection A is rejected by a client on connection B.
- Full interoperability test `tests/gateway_interop.rs` against the real gateway binary,
  including the TOFU prompt flow.
- `vnox-e2e-voice` against `vnox-serverd` still relays voice.
