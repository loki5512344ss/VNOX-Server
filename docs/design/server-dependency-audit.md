# Server dependency refresh

Rust edition 2024; installed rustc1.99.0; declared workspace+children rust-version1.94 (SQLx0.9.0 requires1.94). Old declaration1.85 was already false. Older1.94 toolchain not independently tested.

| Dependency | Old lock versions | New lock versions |
|---|---|---|
| anyhow | 1.0.103 | 1.0.104 |
| argon2 | 0.5.3 | removed |
| axum | 0.8.9 | 0.8.9 |
| bitflags | 2.13.0 | 2.13.2 |
| chacha20poly1305 | 0.10.1 | 0.11.0 |
| ed25519-dalek | 2.2.0 | 3.0.0 |
| hex | 0.4.3 | 0.4.3 |
| hkdf | 0.13.0 | 0.13.0 |
| opus | 0.3.1 | removed |
| prost | 0.13.5 | 0.14.4 |
| prost-build | 0.13.5 | 0.14.4 |
| rand | 0.8.6, 0.9.4, 0.10.2 | 0.10.3 |
| rcgen | 0.13.2 | 0.14.10 |
| rustls | 0.23.41 | 0.23.46 |
| rustls-pki-types | 1.15.0 | 1.15.1 |
| serde | 1.0.228 | 1.0.229 |
| serde_json | 1.0.150 | 1.0.154 |
| sha2 | 0.10.9, 0.11.0 | 0.10.9, 0.11.1 |
| sqlx | 0.9.0 | 0.9.0 |
| thiserror | 2.0.18 | 2.0.21 |
| tokio | 1.52.3 | 1.54.1 |
| tokio-rustls | 0.26.4 | 0.26.6 |
| toml | 1.1.2+spec-1.1.0 | 1.1.8+spec-1.1.0 |
| tower | 0.5.3 | 0.5.3 |
| tracing | 0.1.44 | 0.1.44 |
| tracing-subscriber | 0.3.23 | 0.3.23 |
| uuid | 1.23.4 | 1.29.0 |
| x25519-dalek | 2.0.1 | 3.0.0 |

Removed unused direct declarations: argon2, opus, thiserror, tower, rustls-pki-types; serverd serde/serde_json. tower/pki-types/thiserror remain transitively where needed. Removed unused Axum ws feature; trimmed Tokio full to fs/io-util/macros/net/rt-multi-thread/sync/time.

Crypto/RCGen migrations: rand rng/trait updates, Key/Nonce owned array conversions, CertifiedKey.signing_key. Two crypto regression tests check independent Python-cryptography fixture and tamper rejection. No wire/algorithm semantics changes.

Verified: cargo check --workspace; cargo test --workspace (33 tests); cargo build --workspace; cargo clippy --all-targets -- -D warnings; cargo fmt --check; git diff --check. cargo audit --no-fetch --json:0 vulnerabilities,0 warnings (before7 vulnerabilities plus unsound/yanked warnings). Advisory DB was freshly fetched immediately before baseline.

Limitations: no end-to-end network runtime test, no older MSRV toolchain run, no assurance against unknown vulnerabilities. Existing u32 nonce counter space/rekey limitation remains protocol follow-up.

Keep Axum for admin HTTP/Hub, Tokio for runtime+raw TCP/UDP, SQLx for SQLite/PostgreSQL, rustls and RustCrypto/Dalek libraries rather than reimplement. Main gateway is LNEx over raw TCP, not Axum WebSocket.

Registry discrepancy: crates.io API reported old toml0.9.8 while Cargo registry resolved existing1.1 line to1.1.8+spec-1.1.0; no downgrade made.

Sources: https://docs.rs/axum/latest/axum/ https://docs.rs/prost/latest/prost/ https://rustsec.org/ and crates.io API/Cargo registry metadata.

Docker builder images updated from Rust1.85 to verified available rust:1.99-slim-bookworm; builds use --locked. Removed unnecessary libopus/libssl packages, added protobuf-compiler. Docker images were not built during this task. Official stable toolchain manifest currently reports1.99.1; local validations used installed1.99.0, without changing workstation-global Rust.
