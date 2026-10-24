# ─── Stage 1: Build ───────────────────────────────────────────────────────────
FROM rust:1.99-slim-bookworm AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config cmake protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

RUN cargo build --locked --release --package vnox-gateway

# ─── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/vnox-gateway /usr/local/bin/vnox-gateway

EXPOSE 7600/tcp

ENTRYPOINT ["vnox-gateway"]
