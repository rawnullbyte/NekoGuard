# NekoGuard

<img width="1694" height="936" src="https://github.com/user-attachments/assets/fa1dd96c-e7f5-47b5-9084-64bf65adfdc0" />

# NekoGuard

NekoGuard is a reverse proxy implemented in Rust designed to protect backend services from automated bot traffic. It achieves this by forcing clients to solve a Proof-of-Work (PoW) challenge before their requests are proxied to the upstream server.

## Features

- **Proof-of-Work Verification:** Clients must compute a SHA-256 hash that meets a predefined difficulty target before access is granted.
- **Asynchronous Architecture:** Built on `hyper` and `tokio` for efficient, non-blocking request handling.
- **IP Whitelisting:** Supports permanent access for specific IP addresses via the `NG_WHITELIST` environment variable.
- **Session Management:** Uses `DashMap` for concurrent storage of temporary access sessions.
- **Embedded Assets:** Serves necessary frontend challenge files directly from the binary.

## Operational Flow

1. **Request Interception:** Incoming HTTP requests are intercepted.
2. **Authentication Check:** The system verifies the `X-Real-IP` against the permanent whitelist or current active sessions.
3. **Challenge Generation:** If unauthenticated, the client is served a challenge page.
4. **Client-Side Computation:** The client's browser performs the work to find a nonce that satisfies the PoW requirement.
5. **Validation:** Upon receiving a valid POST submission, the client's IP is granted access for a set duration (default 30 minutes).
6. **Proxying:** Authenticated traffic is proxied to the destination specified in the `X-Upstream` header.

## Configuration

### Environment Variables

- `NG_WHITELIST`: A comma-separated list of IP addresses allowed to bypass the challenge (e.g., `127.0.0.1,10.0.0.1`).

### Defaults

- **Port:** 3000
- **Difficulty:** 16 bits
- **Challenge TTL:** 5 minutes
- **Access TTL:** 30 minutes
