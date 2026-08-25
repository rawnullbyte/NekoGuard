# NekoGuard

<img width="1408" height="936" src="https://github.com/user-attachments/assets/701aedb5-1c9f-4349-9c06-9e5c260dcaa0" />

# NekoGuard

NekoGuard is a reverse proxy implemented in Rust designed to protect backend services from automated bot traffic. It achieves this by forcing clients to solve a Proof-of-Work (PoW) challenge before their requests are proxied to the upstream server.

## Features

- **Proof-of-Work Verification:** Clients must compute a SHA-256 hash that meets a predefined difficulty target before access is granted.
- **Asynchronous Architecture:** Built on `hyper` and `tokio` for efficient, non-blocking request handling.
- **Automatic TLS Certificates:** Acts as the HTTPS edge with certificates obtained and renewed automatically via ACME (Let's Encrypt), using TLS-ALPN-01 on port 443.
- **IP Whitelisting:** Supports permanent access for specific IP addresses via the `NG_WHITELIST` environment variable.
- **Session Management:** Uses `DashMap` for concurrent storage of temporary access sessions.
- **Embedded Assets:** Serves necessary frontend challenge files directly from the binary.

## Operational Flow

1. **Request Interception:** Incoming HTTPS requests are intercepted after TLS termination.
2. **Authentication Check:** The system verifies the client IP (`X-Real-IP` if present, else the TCP peer address) against the permanent whitelist or current active sessions.
3. **Challenge Generation:** If unauthenticated, the client is served a challenge page.
4. **Client-Side Computation:** The client's browser performs the work to find a nonce that satisfies the PoW requirement.
5. **Validation:** Upon receiving a valid POST submission, the client's IP is granted access for a set duration (default 30 minutes).
6. **Proxying:** Authenticated traffic is proxied to the upstream configured for the request's domain.

## Configuration

NekoGuard reads a TOML config file at startup — `./nekoguard.toml` by default, overridable with the `NG_CONFIG` environment variable. See `nekoguard.example.toml`.

```toml
contact = ["you@example.com"]    # ACME account contacts
cache_dir = "./acme-cache"       # certificate/account cache location
staging = true                   # LE staging while testing; false = production certs
port = 443                       # TLS listen port

# One entry per protected site: cert issuance, SNI filter, and routing.
# Scalar keys must come BEFORE [[sites]] — TOML assigns later keys to the site.
[[sites]]
domain   = "example.com"
upstream = "http://10.0.0.5:2368"
bypass   = ["^/api/.*"]              # paths skipping the PoW challenge

  # Subdomains nest under their parent; a sub without `upstream` or `bypass`
  # inherits the parent's.
  [[sites.sub]]
  name     = "app"                    # app.example.com
  upstream = "http://10.0.0.6:8080"

  [[sites.sub]]
  name = "www"                       # www.example.com → parent's upstream
```

### Path bypass

The optional per-site `bypass` list holds regexes matched against the request path (including the leading `/`). A match is proxied immediately without a challenge — for APIs and other machine-facing traffic:

- `bypass = ["^/api/.*", "^/webhooks/.*"]` — exempt specific routes.
- `bypass = [".*"]` — disable protection for that site entirely.
- A sub sets its own list to override the parent's; `bypass = []` on a sub means fully protected even when the parent has bypasses.

Bypassed requests skip PoW entirely and are exposed to bots — anchor patterns (`^/api/`) rather than using loose substrings. Upstream TLS certificates are not verified (nginx's `proxy_ssl_verify off` behavior), so self-signed backends work out of the box.

Certificates are requested only for names in `domains`, cached in `cache_dir`, and renewed automatically before expiry. Set `staging = false` once your setup works; Let's Encrypt rate-limits production issuance.

### Logging

NekoGuard uses a configurable logging system with optional file output and size-based rotation:

```toml
[log]
level     = "info"          # error, warn, info, debug
file      = "/var/log/nekoguard.log"  # omit = stdout only
max_size  = 10485760        # rotate at 10MB (default)
max_files = 5               # keep 5 rotated files (default)
requests  = true            # log each request: method, path, status, upstream, duration
```

When `requests = true`, each proxied request is logged with timing:
```
[2026-08-26 14:30:01] [INFO ] GET /api/ping → 200 (immich.nullbyte.rip → http://10.1.3.50:2283) 2ms
```

### Environment Variables

- `NG_CONFIG`: Path to the TOML config file (default `nekoguard.toml`).
- `NG_WHITELIST`: A comma-separated list of IP addresses allowed to bypass the challenge (e.g., `127.0.0.1,10.0.0.1`).

### Defaults

- **TLS port:** 443 (plus :80 for http→https redirects)
- **Difficulty:** 14 bits
- **Challenge TTL:** 5 minutes
- **Access TTL:** 30 minutes

## Deployment Notes

- NekoGuard is a full edge reverse proxy — it replaces nginx entirely: TLS termination with auto-managed certificates, SNI-based site routing, and PoW protection in one process.
- It binds ports 80 and 443, so run it with `CAP_NET_BIND_SERVICE`, as root, or via `setcap 'cap_net_bind_service=+ep' <binary>`.
- DNS for every configured `domain` must point at the machine running NekoGuard — that's how Let's Encrypt validates via TLS-ALPN-01.
- TLS handshakes for unknown domains are refused outright; routing is derived from each request's Host header against the `[[sites]]` table. The client-facing `X-Upstream` header is deliberately not trusted.
- The proxy preserves the browser's `Origin`, `Referer`, and public `Host` headers so origin-checking applications like Ghost accept forwarded requests.
