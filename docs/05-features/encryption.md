# Encryption

> **Status (LNEx v3):** the TCP control plane is protected by **TLS 1.3** (rustls).
> The UDP voice path is protected by per route ChaCha20-Poly1305 keys delivered over the
> TLS control connection. The earlier custom X25519 + HKDF + ChaCha20-Poly1305 layer on
> TCP (LNEx v2) was removed. Design and trust model: [02-protocol/tls.md](../02-protocol/tls.md).

## Layers

| Path | Protection | Keys |
|------|------------|------|
| TCP control (chat, channels, auth) | TLS 1.3, ALPN `vnox-lnex/3`, no fallback | TLS handshake, server cert pinned by SPKI SHA-256 (TOFU) or a public CA |
| Server authenticity | Ed25519 server identity signs HELLO over the TLS exporter (channel binding) | `server_identity.json` |
| Client authenticity | Ed25519 client key signs AUTH over the same exporter | client identity |
| UDP voice | ChaCha20-Poly1305 AEAD per route | random `c2s_key` / `s2c_key` sent in `VoiceSession` over TLS |
| Direct messages E2EE (optional) | X25519 + HKDF + ChaCha20-Poly1305 between clients | per conversation keys, unchanged |

## What changed from v2

- Removed: ephemeral X25519 exchange in HELLO/AUTH, HKDF session key derivation for TCP,
  per frame ChaCha20-Poly1305 with the `ENCRYPTED` flag, `SessionCrypto` in gateway and client.
- Added: mandatory TLS 1.3 listener and connector, certificate management, client trust store,
  channel bound Ed25519 signatures.
- Unchanged: UDP voice packet format, voice node, E2EE for direct messages, Ed25519 identities.

## Why TLS instead of a custom layer

- Reviewed, widely deployed handshake and record layer instead of a protocol we maintain.
- Standard tooling and key lifecycle (Let's Encrypt works out of the box).
- Forward secrecy, key updates and replay protection are provided by TLS 1.3.

## Voice keys

`VoiceSession` is delivered after the channel authorization check. Keys are random per
route and never derived from the TCP session, so the UDP implementation did not need to
change when the TCP layer was replaced.

## Testing

- Unit: SPKI fingerprint extraction, pin match and mismatch, unknown server, TLS 1.2 client
  rejected, plaintext/v2 client gets an explicit error, channel binding signature replay rejected.
- Integration: `VNOX_GATEWAY_BIN=... cargo test --test gateway_interop -- --ignored`
  in `VNOX-Client`, including the first trust flow.
- Voice: `cargo run --bin vnox-e2e-voice -- 127.0.0.1:7600 --trust-first-use` against `vnox-serverd`.
