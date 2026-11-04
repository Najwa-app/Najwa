# Multi-stage build for the Najwa mailbox server (S16).
#
# Build:  docker build -t najwa-mailbox -f scripts/deployment/Dockerfile .
# (context must be the repository root)
#
# The server crate needs no Arti. Its rusqlite uses the workspace's vendored
# SQLCipher + OpenSSL build (the server opens its database without a key), so
# the builder needs a C toolchain and Perl, which the rust image provides.

# --- Stage 1: Build ---
FROM rust:1.98.1-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cargo resolves every workspace member, including when building one package.
# Copy the complete workspace and fail on dependency or compiler errors.
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY apps/local-web/ apps/local-web/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --locked --release -p najwa-mailbox && \
    strip target/release/najwa-mailbox

# --- Stage 2: Runtime ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged user; data dir 0700 (S16 §12).
RUN groupadd -r najwa && useradd -r -g najwa -d /var/lib/najwa-mailbox -s /sbin/nologin najwa && \
    mkdir -p /var/lib/najwa-mailbox /var/log/najwa-mailbox /etc/najwa-mailbox && \
    chown -R najwa:najwa /var/lib/najwa-mailbox /var/log/najwa-mailbox && \
    chmod 700 /var/lib/najwa-mailbox

COPY --from=builder /build/target/release/najwa-mailbox /usr/local/bin/najwa-mailbox
COPY scripts/deployment/config/mailbox.toml /etc/najwa-mailbox/mailbox.toml

USER najwa

EXPOSE 8080 9090

# Curl the health port directly — the old `--health-check` flag spawned a
# second full server (port conflict) and never served a health response.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://127.0.0.1:9090/v1/health || exit 1

ENTRYPOINT ["/usr/local/bin/najwa-mailbox"]
CMD ["/etc/najwa-mailbox/mailbox.toml"]
