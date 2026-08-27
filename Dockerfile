FROM rust:1.81-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY nekoguard/ nekoguard/
COPY certd/ certd/

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
    CMD ["/usr/local/bin/nekoguard-certd", "--health"] || exit 1
