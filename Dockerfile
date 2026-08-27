FROM rust:1-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY nekoguard/ nekoguard/
COPY certd/ certd/

# Diagnostic: print resolved features to stderr
RUN echo "=== RUSTLS FEATURES ===" 1>&2 && \
    cargo tree -p nekoguard-certd -f '{p} features={f}' 1>&2 | grep "rustls " && \
    echo "=== AWS-LC-RS CHECK ===" 1>&2 && \
    (cargo tree -p nekoguard-certd -i aws-lc-rs 1>&2 || echo "aws-lc-rs NOT IN TREE" 1>&2) && \
    echo "=== DONE ===" 1>&2

RUN cargo build --release --workspace

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -s /bin/false nekoguard

COPY --from=builder /app/target/release/nekoguard /usr/local/bin/
COPY --from=builder /app/target/release/nekoguard-certd /usr/local/bin/

RUN mkdir -p /etc/nekoguard /var/log/nekoguard && \
    chown -R nekoguard:nekoguard /etc/nekoguard /var/log/nekoguard

USER nekoguard

EXPOSE 443 80 8443

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -sf http://localhost:8443/health || exit 1
