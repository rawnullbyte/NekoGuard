<img width="1408" height="936" src="https://github.com/user-attachments/assets/701aedb5-1c9f-4349-9c06-9e5c260dcaa0" />

# NekoGuard

A reverse proxy in Rust that protects backend services from automated bot traffic by forcing clients to solve a Proof-of-Work challenge before access is granted. Replaces nginx as the TLS edge — routes by domain, and blocks bots.

---

## Workspace

```
nekoguard/           # Reverse proxy binary (this crate)
certd/               # Certificate daemon (separate binary)
```

Build both: `cargo build --workspace`
Build one: `cargo build -p nekoguard` or `cargo build -p nekoguard-certd`

> [!TIP]
> `nekoguard-certd` handles all ACME certificate issuance/renewal and stores certs in Redis. NekoGuard reads certs from Redis on startup — no ACME code in the proxy itself.

---

## Features

| Feature                     | Description                                                             |
| --------------------------- | ----------------------------------------------------------------------- |
| 🔒 **Proof-of-Work**        | Clients solve a SHA-256 challenge before access is granted              |
| 🍪 **Signed Sessions**      | HMAC-SHA256 signed cookies with IP binding (no replayable tokens)       |
| ⚡ **Rate Limiting**        | Per-IP token bucket with configurable rps/rpm/burst, per-site overrides |
| 📊 **Redis State**          | Signing secret and rate limits stored in Redis — works across replicas  |
| 🛡️ **SNI Allowlist**        | Unknown domains are refused at the TLS handshake level                  |
| 🔄 **WebSocket Proxy**      | Full WS proxying through the TLS edge with bidirectional piping         |
| 📝 **Configurable Logging** | File output, request logging with timing, configurable levels           |

---

## Architecture

```mermaid
flowchart TB
    Browser([Browser]) --> LB[Load Balancer]
    LB -->|SNI| NG[NekoGuard 1]
    LB -->|SNI| NG2[NekoGuard 2]
    LB -->|SNI| NG3[NekoGuard 3]
    NG --- Redis[(Redis)]
    NG2 --- Redis
    NG3 --- Redis
    NG --> Services
    NG2 --> Services
    NG3 --> Services
```

> [!IMPORTANT]
> NekoGuard handles TLS termination, domain routing, and bot protection. The load balancer distributes traffic across replicas using TCP passthrough (SNI-based routing). Redis stores session state and signing secrets shared across all replicas.

---

## How It Works

1. **TLS Termination** — NekoGuard terminates TLS using auto-managed Let's Encrypt certificates
2. **SNI Routing** — Traffic is routed to the correct backend based on the domain
3. **PoW Challenge** — First-time visitors solve a SHA-256 challenge (difficulty 14 bits ≈ 16k attempts)
4. **Signed Session** — After solving PoW, a signed cookie is issued (HMAC-SHA256, IP-bound, 30-minute TTL)
5. **Rate Limiting** — Token bucket per IP with configurable limits (rps/rpm/burst)
6. **Proxying** — Authenticated traffic is proxied to the configured upstream

---

## Configuration

> [!NOTE]
> Scalar keys (`contact`, `cache_dir`, `staging`, `port`, `log`, `session`, `rate_limit`) must appear **before** any `[[sites]]` block in the TOML file. This is a TOML language requirement.

### Full Config Example

```toml
# ── ACME ──────────────────────────────────────────────────────────
contact = ["you@example.com"]         # ACME account contacts
cache_dir = "./acme-cache"            # certificate cache directory
staging = false                       # true = LE staging; false = production

# ── TLS ───────────────────────────────────────────────────────────
port = 443                            # TLS listen port

# ── Whitelist ─────────────────────────────────────────────────────
whitelist = ["127.0.0.1"]             # permanent IPs that bypass PoW

# ── Session ───────────────────────────────────────────────────────
[session]
cookie_name = "nekoguard_session"     # session cookie name
ttl = 1800                           # session duration (seconds)

# ── Rate Limiting ─────────────────────────────────────────────────
[rate_limit]
enabled = true
rps = 10                              # requests per second
rpm = 600                             # requests per minute
burst = 20                            # burst capacity

# ── Logging ───────────────────────────────────────────────────────
[log]
level = "info"                        # error, warn, info, debug
file = "/var/log/nekoguard.log"       # omit = stdout only
requests = true                      # log each request with timing

# ── Redis ─────────────────────────────────────────────────────────
[redis]
url = "redis://127.0.0.1:6379"        # session state + signing secret

# ── Backend Sites ─────────────────────────────────────────────────
[[sites]]
domain = "example.com"
upstream = "http://10.0.0.5:2368"
bypass = ["^/api/.*"]                 # skip PoW for API routes

  [[sites.sub]]
  name = "app"                        # app.example.com
  upstream = "http://10.0.0.6:8080"

  [[sites.sub]]
  name = "www"                        # inherits parent's upstream

  # Subdomain with rate limit override
  [[sites.sub]]
  name = "api"
  upstream = "http://10.0.0.7:9000"
  [site.rate_limit]
  rps = 100
  rpm = 10000
  burst = 50
```

> [!TIP]
> The `bypass` regexes are matched against the request path. Use `["^/api/.*"]` to exempt API routes, or `[".*"]` to disable PoW for an entire site. A sub's `bypass = []` overrides the parent's list and fully protects the sub.

> [!WARNING]
> Bypassed requests skip PoW entirely and are exposed to bots. Anchor patterns with `^` rather than loose substrings.

### Rate Limiting

> [!NOTE]
> Rate limits are enforced **after** a successful PoW solve. Each IP gets a token bucket that refills at `rps` tokens/second. If `rpm` is set, it acts as an additional per-minute ceiling.

Rate limits cascade: **global → domain → subdomain**. Non-zero values override:

```toml
# Global (all sites)
[rate_limit]
rps = 10
rpm = 600
burst = 20

# Domain override (applies to all subs)
[[sites]]
domain = "example.com"
upstream = "http://10.0.0.5:2368"
[site.rate_limit]
rps = 50
rpm = 5000
burst = 30

  # Sub override (overrides both global AND domain)
  [[sites.sub]]
  name = "admin"
  upstream = "http://10.0.0.8:8080"
  [site.rate_limit]
  rps = 5
  rpm = 100
  burst = 3

  # Sub without rate_limit → inherits parent domain (example.com)
  [[sites.sub]]
  name = "api"
  upstream = "http://10.0.0.7:9000"
```

### Environment Variables

| Variable    | Description                                              |
| ----------- | -------------------------------------------------------- |
| `NG_CONFIG` | Path to the TOML config file (default: `nekoguard.toml`) |

### Defaults

| Setting        | Value                                |
| -------------- | ------------------------------------ |
| TLS port       | 443 (+ :80 for http→https redirects) |
| PoW difficulty | 14 bits (~16k hash attempts)         |
| Challenge TTL  | 5 minutes                            |
| Session TTL    | 30 minutes                           |
| Rate limit     | Disabled by default                  |

---

## Deployment

### Single Server

```bash
# Build both binaries
cargo build --release --workspace

# Start Redis
redis-server &

# Start certd (handles ACME, issues certs)
NG_CERTD_CONFIG=certd.toml ./target/release/nekoguard-certd

# Start nekoguard (reads certs from Redis)
sudo setcap 'cap_net_bind_service=+ep' target/release/nekoguard
NG_CONFIG=nekoguard.toml ./target/release/nekoguard
```

> [!CAUTION]
> NekoGuard binds ports 80 and 443 directly. Run with `CAP_NET_BIND_SERVICE`, as root, or via `setcap`.

### Multi-Replica with Load Balancer

```mermaid
flowchart LR
    DNS[DNS] --> LB[Load Balancer]
    LB -->|SNI: example.com| R1[NekoGuard 1]
    LB -->|SNI: other.com| R2[NekoGuard 2]
    R1 --- Redis[(Redis)]
    R2 --- Redis
    R1 --> S1[example.com server]
    R2 --> S2[other.com server]
```

> [!TIP]
> Use TCP passthrough (`stream { ssl_preread on; }` in nginx) on the load balancer — NekoGuard handles TLS itself. SNI-based routing in the LB distributes connections to the correct NekoGuard instance.

#### nginx Load Balancer Config

```nginx
stream {
    map $ssl_preread_server_name $backend {
        example.com    nekoguard_1;
        other.com      nekoguard_2;
        default        nekoguard_1;
    }

    upstream nekoguard_1 { server 10.0.0.1:443; }
    upstream nekoguard_2 { server 10.0.0.2:443; }

    server {
        listen 443;
        listen [::]:443;
        proxy_pass $backend;
        ssl_preread on;
    }
}
```

> [!IMPORTANT]
> The load balancer must use **TCP passthrough** (not HTTP termination) so NekoGuard can handle TLS itself and Let's Encrypt can validate via TLS-ALPN-01.

---

## Redis

> [!NOTE]
> Redis stores session state, signing secrets, and rate limits. Required for multi-replica deployments.

```toml
[redis]
url = "redis://127.0.0.1:6379"
```

**What Redis stores:**

- `nekoguard:secret` — HMAC signing secret (shared across all replicas)
- `nekoguard:rl:<ip>` — Rate limit token bucket per IP (1 hour TTL)
- `nekoguard:cert:<domain>` — Certs from certd (loaded on NekoGuard startup)

---

## TLS Certificates

Certificates are managed by `nekoguard-certd` and stored in Redis. NekoGuard reads them on startup and holds them in memory.

- certd handles issuance, renewal, and ACME challenges (via HTTP-01)
- Certs are stored in Redis, shared across all NekoGuard replicas
- NekoGuard loads certs from Redis on startup — no local cache needed
- Unknown domains are refused at the TLS handshake level

---

## Rate Limiting Details

After solving PoW, each IP gets a **token bucket** with configured capacity. Tokens refill at `rps` rate. If `rpm` is set, it acts as a per-minute ceiling.

| Parameter | Default | Description              |
| --------- | ------- | ------------------------ |
| `enabled` | false   | Enable rate limiting     |
| `rps`     | 10      | Max requests per second  |
| `rpm`     | 600     | Max requests per minute  |
| `burst`   | 20      | Burst capacity above rps |

When exceeded: `429 Too Many Requests`

---

## Certificate Daemon (certd)

`nekoguard-certd` is a standalone service that handles all ACME certificate operations. It runs independently — once it issues a cert, it stores it in Redis, and all NekoGuard instances pick it up.

### Architecture

```mermaid
flowchart LR
    LE[Let's Encrypt] -->|TLS-ALPN-01| CD[certd]
    CD -->|cert + key| Redis[(Redis)]
    Redis -->|cert| NG1[NekoGuard 1]
    Redis -->|cert| NG2[NekoGuard 2]
    Redis -->|cert| NG3[NekoGuard 3]
```

> [!IMPORTANT]
> certd is a **single process** — no distributed locks needed. NekoGuard instances just read certs from Redis on startup.

### Configuration

```toml
# certd.toml

# Domains to manage certificates for
domains = ["root-workspace.net", "immich.root-workspace.net"]

# ACME account contacts (expiry notices)
contacts = ["you@example.com"]

# Certificate cache directory (local fallback)
cache_dir = "./acme-cache"

# Use Let's Encrypt staging while testing
staging = false

# Listen port for NekoGuard to query (internal use)
port = 8443

# Redis connection
redis_url = "redis://127.0.0.1:6379"
```

Set the config path via environment variable:

```bash
NG_CERTD_CONFIG=/etc/nekoguard/certd.toml ./nekoguard-certd
```

### Running

```bash
# Build both binaries
cargo build --workspace --release

# Run certd (handles ACME)
NG_CERTD_CONFIG=/etc/nekoguard/certd.toml ./target/release/nekoguard-certd

# Run nekoguard (reads certs from Redis)
NG_CONFIG=/etc/nekoguard/nekoguard.toml ./target/release/nekoguard
```

### API Reference

| Endpoint | Method | Description | Response |
|----------|--------|-------------|----------|
| `/health` | `GET` | Health check | `{"status":"ok"}` |
| `/certs` | `GET` | List all managed certs | `[[domain, {cert_pem, key_pem}]]` |
| `/certs/<domain>` | `GET` | Get cert for a specific domain | `{cert_pem, key_pem}` |
| `/issue` | `POST` | Force certificate issuance for all domains | `{"status":"issued"}` |

Example: check if a cert exists

```bash
curl http://localhost:8443/certs/root-workspace.net
```

```json
{
  "cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "key_pem": "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
}
```

### How NekoGuard uses certd

On startup, NekoGuard:
1. Checks Redis for existing certs for each configured domain
2. If found → writes to local DirCache for fast TLS handshakes
3. If not found → waits for certd to issue (certd runs independently)
4. Caches certs locally so NekoGuard doesn't hit Redis on every TLS handshake

NekoGuard does **not** communicate with certd directly over HTTP — it reads certs from Redis. certd just stores them there after issuance.

### Redis storage

| Key | Value | TTL |
|-----|-------|-----|
| `nekoguard:cert:<domain>` | JSON `{cert_pem, key_pem}` | None (persists) |
| `nekoguard:secret` | HMAC signing secret | None (persists) |
| `nekoguard:rl:<ip>` | Rate limit bucket `{tokens, last_refill_ms}` | 1 hour |

---

## Session Cookies

Sessions are signed with **HMAC-SHA256** and bound to the client IP:

```
nekoguard_session=<ip>.<expiry_hex>.<nonce_hex>.<hmac_hex>
```

- **IP-bound** — cookie is invalid from a different IP
- **Time-limited** — expires after `session.ttl` seconds (default: 1800)
- **Cryptographically signed** — prevents forgery
- **Secret stored in Redis** — shared across replicas

> [!CAUTION]
> The signing secret is generated once and stored in Redis. Deleting the `nekoguard:secret` key invalidates all sessions — all users must re-solve PoW.
