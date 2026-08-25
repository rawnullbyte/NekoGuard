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
6. **Proxying:** Authenticated traffic is proxied to the upstream resolved from the `X-Upstream` header or the config's Host→upstream map.

## Configuration

NekoGuard reads a TOML config file at startup — `./nekoguard.toml` by default, overridable with the `NG_CONFIG` environment variable. See `nekoguard.example.toml`.

```toml
domains = ["example.com"]        # domains to issue ACME certificates for
contact = ["you@example.com"]    # ACME account contacts
cache_dir = "./acme-cache"       # certificate/account cache location
staging = true                   # LE staging while testing; false = production certs
port = 443                       # TLS listen port

[upstreams]                      # fallback Host -> upstream map
"example.com" = "http://10.0.0.5:2368"
```

Certificates are requested only for names in `domains`, cached in `cache_dir`, and renewed automatically before expiry. Set `staging = false` once your setup works; Let's Encrypt rate-limits production issuance.

### Environment Variables

- `NG_CONFIG`: Path to the TOML config file (default `nekoguard.toml`).
- `NG_WHITELIST`: A comma-separated list of IP addresses allowed to bypass the challenge (e.g., `127.0.0.1,10.0.0.1`).

### Defaults

- **TLS port:** 443 (plus :80 for http→https redirects)
- **Difficulty:** 14 bits
- **Challenge TTL:** 5 minutes
- **Access TTL:** 30 minutes

## Deployment Notes

- NekoGuard binds ports 80 and 443, so run it with `CAP_NET_BIND_SERVICE`, as root, or via `setcap 'cap_net_bind_service=+ep' <binary>`.
- DNS for every domain in `domains` must point at the machine running NekoGuard — that's how Let's Encrypt validates via TLS-ALPN-01.
- When placed behind another reverse proxy instead, terminate TLS there, forward plain HTTP to NekoGuard's redirect listener, and set `X-Upstream`, `Host`, and `X-Forwarded-Proto`; the config `[upstreams]` map then serves purely as a fallback.
- The proxy preserves the browser's `Origin`, `Referer`, and public `Host` headers so origin-checking applications like Ghost accept forwarded requests.
