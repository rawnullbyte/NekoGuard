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
> Scalar keys (`port`, `log`, `session`, `rate_limit`, `redis`) must appear **before** any `[[sites]]` block in the TOML file. This is a TOML language requirement.

### Full Config Example

```toml
# ── Shared (both certd and nekoguard) ─────────────────────────────
[redis]
url = "redis://127.0.0.1:6379"

[rate_limit]
enabled = true
rps = 10
rpm = 600
burst = 20

[log]
level = "info"
file = "/var/log/nekoguard.log"
requests = true

# ── Sites (both binaries read these) ─────────────────────────────
[[sites]]
domain = "root-workspace.net"
upstream = "http://10.1.3.16:2283"
bypass = ["^/api/.*"]

  [[sites.sub]]
  name = "immich"
  upstream = "http://10.1.3.16:2283"

# ── NekoGuard-specific ────────────────────────────────────────────
[nekoguard]
port = 443
whitelist = ["127.0.0.1"]
catchall = { upstream = "http://10.0.0.5:2368", bypass = [".*"] }

[nekoguard.session]
ttl = 1800

# ── Certd-specific ────────────────────────────────────────────────
[certd]
port = 8443
renewal_interval = 86400
contact_email = "you@example.com"
cloudflare_api_token = "your-cloudflare-api-token"
```

### Path Bypass

> [!TIP]
> The `bypass` regexes are matched against the request path. Use `["^/api/.*"]` to exempt API routes, or `[".*"]` to disable PoW for an entire site. A sub's `bypass = []` overrides the parent's list and fully protects the sub.

> [!WARNING]
> Bypassed requests skip PoW entirely and are exposed to bots. Anchor patterns with `^` rather than loose substrings.

### Rate Limiting

Rate limits cascade: **global → domain → subdomain**. Non-zero values override:

```toml
# Global defaults (applies to all sites)
[nekoguard.rate_limit]
rps = 10
rpm = 600
burst = 20

# Per-site override
[[nekoguard.sites]]
domain = "api.example.com"
upstream = "http://10.0.0.5:2368"
[nekoguard.sites.rate_limit]
rps = 100
rpm = 10000
burst = 50
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

### Quick Start (Docker Compose)

```bash
git clone https://github.com/rawnullbyte/NekoGuard.git
cd NekoGuard

# Edit nekoguard.toml with your domains, Redis, Cloudflare credentials

docker compose up -d
```

This starts Redis, certd, and NekoGuard in one command.

### Manual Setup

```bash
# 1. Build
cargo build --release --workspace

# 2. Start Redis
redis-server &

# 3. Start certd (issues certs via DNS-01)
NG_CONFIG=nekoguard.toml ./target/release/nekoguard-certd &

# 4. Wait for certd to issue certs (check: redis-cli GET nekoguard:cert:your-domain)

# 5. Start NekoGuard
sudo setcap 'cap_net_bind_service=+ep' target/release/nekoguard
NG_CONFIG=nekoguard.toml ./target/release/nekoguard
```

### Kubernetes

> [!WARNING]
> After any `docker build`, you **must** run `docker save nekoguard:latest | k3s ctr images import -` to push the image into k3s's containerd. Without this, k3s silently runs the old image. Use `./deploy.sh` to handle this automatically.

```bash
# 1. Build and import into k3s
docker build --no-cache -t nekoguard:latest .
docker save nekoguard:latest | k3s ctr images import -

# 2. Apply manifests
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/redis.yaml
kubectl apply -f k8s/certd.yaml
kubectl apply -f k8s/nekoguard.yaml

# 3. Check status
kubectl get pods -n nekoguard
kubectl logs -f deployment/nekoguard-certd -n nekoguard
```

### Auto-Scaling NekoGuard

NekoGuard is stateless — all state lives in Redis. Scale based on CPU or connections:

```bash
kubectl autoscale deployment nekoguard \
  --namespace nekoguard \
  --min=2 --max=10 \
  --cpu-percent=70
```

Or with HorizontalPodAutoscaler YAML in `k8s/`:

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

- certd handles issuance, renewal, and ACME challenges (via DNS-01 + Cloudflare API)
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
    LE[Let's Encrypt] -->|DNS-01| CD[certd]
    CD -->|cert + key| Redis[(Redis)]
    Redis -->|cert| NG1[NekoGuard 1]
    Redis -->|cert| NG2[NekoGuard 2]
    Redis -->|cert| NG3[NekoGuard 3]
```

> [!IMPORTANT]
> certd is a **single process** — no distributed locks needed. NekoGuard instances just read certs from Redis on startup.

### Configuration

```toml
# Shared nekoguard.toml (same file both binaries read)

# certd uses: domains, redis_url, contact_email, cloudflare_*
# + [certd] section for port and renewal_interval
```

```bash
NG_CONFIG=/etc/nekoguard/nekoguard.toml ./nekoguard-certd
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

---

## Docker

Build and run with Docker Compose:

```bash
docker compose up -d
```

Or build standalone:

```bash
docker build -t nekoguard .
docker run -p 443:443 -p 80:80 \
  -v ./nekoguard.toml:/etc/nekoguard/nekoguard.toml:ro \
  -e NG_CONFIG=/etc/nekoguard/nekoguard.toml \
  nekoguard
```

> [!NOTE]
> The Dockerfile builds both `nekoguard` and `nekoguard-certd` binaries in a multi-stage build.

---

## Kubernetes (k3s)

> [!CAUTION]
> **k3s uses containerd, not Docker.** `docker build` only updates Docker's image store — k3s has its own separate image cache. If you run `docker build` and then `kubectl rollout restart`, k3s will keep running the **old cached image** and your changes won't take effect.

### Deploying

Use the deploy script (handles both Docker build and k3s containerd import):

```bash
./deploy.sh
```

Or manually step by step:

```bash
# 1. Build the Docker image
docker build --no-cache -t nekoguard:latest .

# 2. Import into k3s containerd (THIS IS THE CRITICAL STEP)
docker save nekoguard:latest | k3s ctr images import -

# 3. Apply manifests (first time only)
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/redis.yaml
kubectl apply -f k8s/certd.yaml
kubectl apply -f k8s/nekoguard.yaml

# 4. Restart deployments to pick up the new image
kubectl rollout restart deployment -n nekoguard

# 5. Verify
kubectl get pods -n nekoguard
```

> [!WARNING]
> **Never skip step 2.** Without `k3s ctr images import`, k3s will silently use the old image. You'll see pods running but your code changes won't be there.

### Architecture

```mermaid
flowchart TB
    LB[Load Balancer] --> NG[NekoGuard x2]
    NG --> Redis[(Redis)]
    CD[certd] --> Redis
    CD --> LE[Let's Encrypt]
    LE -->|DNS-01| CF[Cloudflare]
    NG --> B1[Service 1]
    NG --> B2[Service 2]
```

| Component | Replicas | Purpose |
|-----------|----------|---------|
| Redis | 1 | Session state + certs |
| certd | 1 | ACME issuance + renewal |
| NekoGuard | 2+ | TLS edge + PoW + proxy |

> [!TIP]
> NekoGuard scales horizontally — add replicas and point your load balancer. All state is in Redis. certd is single-instance (handles ACME lock internally).

Access via NodePort:
- NekoGuard: `https://<NODE_IP>:30443`
- Dashboard: `https://<NODE_IP>:30443`
