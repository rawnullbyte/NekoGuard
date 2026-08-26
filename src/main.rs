mod config;
mod ng_log;
mod pow;
mod ratelimit;
mod session;

use bytes::Bytes;
use config::CONFIG;
use futures::StreamExt;


use http_body_util::{combinators::BoxBody, BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{CONTENT_TYPE, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_tls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rust_embed::RustEmbed;
use rustls_acme::{caches::DirCache, is_tls_alpn_challenge, AcmeConfig};
use serde::Deserialize;
use std::collections::HashSet;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::LazyConfigAcceptor;

/// Wraps a reader with a pre-filled prefix consumed first, then delegates
/// to the inner reader. Replays bytes already read during TLS peeking.
struct PrefixedReader<W> {
    prefix: std::io::Cursor<Vec<u8>>,
    inner: W,
}

impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for PrefixedReader<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.prefix.position() < self.prefix.get_ref().len() as u64 {
            return std::pin::Pin::new(&mut self.prefix).poll_read(cx, buf);
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for PrefixedReader<W> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

const CHALLENGE_HTML: &str = include_str!(concat!(env!("OUT_DIR"), "/challenge.min.html"));
const MAX_VERIFY_BODY: usize = 512;
const CHALLENGE_TTL: Duration = Duration::from_secs(300); // 5 min

type RespBody = BoxBody<Bytes, hyper::Error>;
type ProxyClient = Client<HttpsConnector<HttpConnector>, RespBody>;

#[derive(RustEmbed)]
#[folder = "src/assets/"]
struct EmbeddedAssets;

#[derive(Deserialize)]
struct VerifyPayload {
    challenge: String,
    nonce: String,
}

static PERM: LazyLock<HashSet<IpAddr>> = LazyLock::new(|| {
    std::env::var("NG_WHITELIST")
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
        .collect()
});


// Response helpers
fn text_resp(status: StatusCode, body: &'static str) -> Response<RespBody> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from_static(body.as_bytes()))
            .map_err(|e: Infallible| match e {})
            .boxed())
        .unwrap()
}

fn challenge_page(challenge: &str) -> Response<RespBody> {
    let html = CHALLENGE_HTML
        .replace("{{CHALLENGE}}", challenge)
        .replace("{{BITS}}", &pow::DIFFICULTY.to_string());
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .header("cache-control", "no-store, private")
        .body(Full::new(Bytes::from(html))
            .map_err(|e: Infallible| match e {})
            .boxed())
        .unwrap()
}

fn get_mime_type(path: &str) -> &'static str {
    let path = path.to_lowercase();
    if path.ends_with(".png") { "image/png" }
    else if path.ends_with(".jpg") || path.ends_with(".jpeg") { "image/jpeg" }
    else if path.ends_with(".gif") { "image/gif" }
    else if path.ends_with(".svg") { "image/svg+xml" }
    else if path.ends_with(".webp") { "image/webp" }
    else if path.ends_with(".css") { "text/css; charset=utf-8" }
    else if path.ends_with(".js") { "application/javascript; charset=utf-8" }
    else { "application/octet-stream" }
}

fn serve_embedded_asset(file_path: &str) -> Response<RespBody> {
    let safe_path = file_path.replace("..", "");
    let clean_path = safe_path.trim_start_matches('/');

    match EmbeddedAssets::get(clean_path) {
        Some(embedded_file) => {
            let mime = get_mime_type(clean_path);
            let bytes = Bytes::copy_from_slice(&embedded_file.data);

            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, HeaderValue::from_static(mime))
                .body(Full::new(bytes)
                    .map_err(|e: Infallible| match e {})
                    .boxed())
                .unwrap()
        }
        None => text_resp(StatusCode::NOT_FOUND, "Asset not found"),
    }
}

fn strip_cookie_domain(cookie: &str) -> String {
    cookie
        .split(';')
        .enumerate()
        .filter(|(i, part)| *i == 0 || !part.trim().to_lowercase().starts_with("domain="))
        .map(|(_, part)| part)
        .collect::<Vec<_>>()
        .join(";")
}

// Proxy
async fn proxy_to_upstream(
    client: &ProxyClient,
    req: Request<Incoming>,
    upstream: &str,
) -> Response<RespBody> {
    let (mut parts, body) = req.into_parts();

    let upstream_uri: hyper::Uri = match upstream.parse() {
        Ok(u) => u,
        Err(_) => return text_resp(StatusCode::BAD_REQUEST, "Invalid upstream URL"),
    };

    let up_authority = upstream_uri
        .authority()
        .map(|a| a.as_str().to_string())
        .unwrap_or_default();
    let up_scheme = upstream_uri.scheme_str().unwrap_or("https");

    // Public-facing identity as the browser sees it. NekoGuard fronts your own
    // service, so it must present the public host/scheme to the upstream rather
    // than masquerade as the internal upstream address — otherwise origin-checking
    // apps (Ghost, etc.) reject the request as coming from the wrong origin.
    let public_host = parts
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| up_authority.clone());
    let public_scheme = parts
        .headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https".to_string());

    // Route the outbound connection to the internal upstream address...
    let pq = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let target = format!("{}://{}{}", up_scheme, up_authority, pq);
    parts.uri = match target.parse() {
        Ok(u) => u,
        Err(_) => return text_resp(StatusCode::BAD_REQUEST, "Invalid upstream URL"),
    };

    // ...but keep the public Host so the upstream sees its own configured domain.
    if let Ok(val) = HeaderValue::from_str(&public_host) {
        parts.headers.insert("host", val);
    }

    // Standard forwarding headers so the upstream builds correct absolute URLs
    // and treats the request as HTTPS when the edge terminated TLS.
    if let Ok(val) = HeaderValue::from_str(&public_scheme) {
        parts.headers.insert("x-forwarded-proto", val);
    }
    if let Ok(val) = HeaderValue::from_str(&public_host) {
        parts.headers.insert("x-forwarded-host", val);
    }

    // Origin and Referer are left exactly as the browser sent them (the public
    // scheme://host form) so CSRF/origin checks on the upstream pass.

    let proxied_req = Request::from_parts(parts, body.map_err(|e| e).boxed());

    match client.request(proxied_req).await {
        Ok(resp) => {
            let (mut rp, rb) = resp.into_parts();

            // WebSocket upgrade: forward the101 as-is. Hyper's body abstraction
            // doesn't pipe raw TCP bytes after an upgrade, so we return the
            // body directly and let the with_upgrades() connection handle it.
            if rp.status == StatusCode::SWITCHING_PROTOCOLS {
                rp.headers.remove("transfer-encoding");
                rp.headers.remove("content-length");
                return Response::from_parts(rp, rb.boxed());
            }

            rp.headers.remove("content-security-policy");
            rp.headers.remove("content-security-policy-report-only");
            rp.headers.remove("transfer-encoding");

            let patched: Vec<HeaderValue> = rp
                .headers
                .get_all("set-cookie")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .map(strip_cookie_domain)
                .filter_map(|s| HeaderValue::from_str(&s).ok())
                .collect();

            if !patched.is_empty() {
                rp.headers.remove("set-cookie");
                for val in patched {
                    rp.headers.append("set-cookie", val);
                }
            }

            Response::from_parts(rp, rb.boxed())
        }
        Err(e) => {
            log::error!("Proxy error: {:?}", e);
            text_resp(StatusCode::BAD_GATEWAY, "Upstream error")
        }
    }
}

// ── WebSocket upgrade proxy ──────────────────────────────────────────
// After a101 Switching Protocols, the connection is raw TCP.  Hyper's body
// abstraction cannot pipe these bytes — it finishes immediately — so we
// bypass it entirely: read the request ourselves, forward to the upstream,
// read back the101, send it to the client, then copy raw bytes both ways.
/// Forward a WS request to the upstream over TCP. Reads the request
/// from `client_tcp`, rewrites Host, sends to upstream, relays101,
/// then pipes bidirectionally.
async fn proxy_ws_upgrade_buf(client_tcp: &mut tokio::net::TcpStream, upstream_addr: &str) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Read the full request from the client TCP stream.
    let mut buf = Vec::with_capacity(4096);
    {
        let mut tmp = [0u8; 4096];
        loop {
            match client_tcp.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.ends_with(b"\r\n\r\n") { break; }
                }
            }
        }
    }
    let req_text = String::from_utf8_lossy(&buf);
    let first_line = req_text.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    let path = if parts.len() >= 2 { parts[1] } else { "/" };

    // Forward to upstream over TCP. Strip the scheme prefix if present.
    let upstream_host = upstream_addr
        .strip_prefix("http://")
        .or_else(|| upstream_addr.strip_prefix("https://"))
        .unwrap_or(upstream_addr);
    let upstream: std::net::SocketAddr = match tokio::net::lookup_host(upstream_host)
        .await
        .ok()
        .and_then(|mut addrs| addrs.next())
    {
        Some(a) => a,
        None => {
            log::error!("[ws] upstream lookup failed: {upstream_addr}");
            return;
        }
    };

    let mut upstream_tcp = match tokio::net::TcpStream::connect(upstream).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("[ws] upstream connect failed: {e}");
            return;
        }
    };
    upstream_tcp.set_nodelay(true).ok();

    // Rewrite request line + ALL headers. Only rewrite Host.
    let auth = upstream_addr.strip_prefix("http://")
        .or_else(|| upstream_addr.strip_prefix("https://"))
        .unwrap_or(upstream_addr)
        .split(':').next().unwrap_or(upstream_addr);
    let mut rewritten = format!("{} {} HTTP/1.1\r\n", parts[0], path);
    for line in req_text[req_text.find("\r\n").unwrap_or(0) + 2..]
        .lines().take_while(|l| !l.is_empty())
    {
        if line.to_ascii_lowercase().starts_with("host:") {
            rewritten.push_str(&format!("Host: {auth}\r\n"));
        } else {
            rewritten.push_str(&format!("{line}\r\n"));
        }
    }
    rewritten.push_str("\r\n");

    if let Err(e) = upstream_tcp.write_all(rewritten.as_bytes()).await {
        log::error!("[ws] upstream write failed: {e}");
        return;
    }

    // Read101 from upstream.
    let mut resp_buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    loop {
        match upstream_tcp.read(&mut tmp).await {
            Ok(0) | Err(_) => {
                log::error!("[ws] upstream EOF before101");
                return;
            }
            Ok(n) => resp_buf.extend_from_slice(&tmp[..n]),
        }
        if resp_buf.windows(4).any(|w| w == b"\r\n\r\n") { break; }
    }
    let resp_preview = String::from_utf8_lossy(&resp_buf);
    log::info!("[ws] upstream responded: {}", resp_preview.lines().next().unwrap_or(""));
    if !resp_buf.starts_with(b"HTTP/1.1 101") { return; }

    // Send101 to client and start bidirectional copy.
    if let Err(e) = client_tcp.write_all(&resp_buf).await {
        log::error!("[ws] client write101 failed: {e}");
        return;
    }
    let (mut client_read, mut client_write) = tokio::io::split(&mut *client_tcp);
    let (mut ur, mut uw) = upstream_tcp.into_split();
    let c2u = tokio::io::copy(&mut client_read, &mut uw);
    let u2c = tokio::io::copy(&mut ur, &mut client_write);
    let _ = tokio::join!(c2u, u2c);
    log::info!("[ws] bidirectional copy ended");
}

// Main handler
async fn handle(
    req: Request<Incoming>,
    client: Arc<ProxyClient>,
    session: Arc<session::SessionManager>,
    peer_ip: IpAddr,
) -> Result<Response<RespBody>, Infallible> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let start = std::time::Instant::now();
    let host_header = req.headers().get("host").and_then(|v| v.to_str().ok()).unwrap_or("-").to_string();
    let _upstream_header = req.headers().get("x-upstream").and_then(|v| v.to_str().ok()).unwrap_or("-").to_string();

    // /__ng/* routes are always handled locally, before any auth or proxy logic.
    if (path == "/__ng/version") && method == Method::GET {
        return Ok(text_resp(StatusCode::OK, env!("CARGO_PKG_VERSION")));
    }

    if path.starts_with("/__ng/assets/") && method == Method::GET {
        let asset_subpath = &path["/__ng/assets/".len()..];
        return Ok(serve_embedded_asset(asset_subpath));
    }

    // Prefer X-Real-IP from a trusted front proxy; otherwise the TCP peer
    // address (NekoGuard is the direct edge).
    let real_ip: Option<IpAddr> = req
        .headers()
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .or(Some(peer_ip));

    // Routing is config-only: resolve the site from the request Host. The
    // client-controlled X-Upstream header is deliberately ignored — trusting it
    // would let anyone turn the proxy into an open proxy.
    let upstream = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .and_then(|h| CONFIG.site_for_host(h))
        .map(|s| s.upstream.clone());

    if path == "/__ng/verify" && method == Method::POST {
        let bytes = match Limited::new(req.into_body(), MAX_VERIFY_BODY).collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => return Ok(text_resp(StatusCode::BAD_REQUEST, "Bad request")),
        };
        let payload: VerifyPayload = match serde_json::from_slice::<VerifyPayload>(&bytes) {
            Ok(p) if !p.challenge.is_empty() && !p.nonce.is_empty() => p,
            _ => return Ok(text_resp(StatusCode::BAD_REQUEST, "Bad request")),
        };

        if !pow::check_pow(&payload.challenge, &payload.nonce) {
            return Ok(text_resp(StatusCode::FORBIDDEN, "Invalid solution"));
        }

        // PoW valid — create a signed session cookie
        if let Some(ip) = real_ip {
            let cookie_val = session.create_cookie(ip);
            let resp = text_resp(StatusCode::OK, "OK");
            let cookie_header = format!(
                "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
                session.cookie_name(), cookie_val, session.ttl().as_secs()
            );
            let mut resp = resp;
            resp.headers_mut().insert(
                "set-cookie",
                HeaderValue::from_str(&cookie_header).unwrap(),
            );
            return Ok(resp);
        }
        return Ok(text_resp(StatusCode::OK, "OK"));
    }

    // Check session cookie — extract, verify signature, check IP, check expiry
    let session_valid = req.headers()
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|c| {
            c.split(';')
                .find(|part| part.trim().starts_with(&format!("{}=", session.cookie_name())))
                .map(|part| part.trim().splitn(2, '=').nth(1).unwrap_or(""))
        })
        .and_then(|val| {
            let ip = real_ip?;
            session.verify_cookie(val, ip).ok()
        })
        .is_some();

    // Also allow permanent whitelist IPs
    let allowed = session_valid || real_ip.map(|ip| PERM.contains(&ip)).unwrap_or(false);

    // Path bypass: requests whose path matches one of the site's bypass
    // regexes are proxied without the challenge (APIs and machine routes).
    let host = req.headers().get("host").and_then(|v| v.to_str().ok());
    let bypass_match = host
        .and_then(|h| CONFIG.site_for_host(h))
        .and_then(|site| {
            let req_path = req.uri().path();
            if site.bypass.iter().any(|re| re.is_match(req_path)) {
                Some(site)
            } else {
                None
            }
        });

    if allowed || bypass_match.is_some() {
        // Rate limit check (only for cookie-authenticated, not bypass)
        if allowed && !bypass_match.is_some() {
            if let Some(ip) = real_ip {
                let site_rl = bypass_match
                    .map(|s| &s.rate_limit)
                    .unwrap_or(&CONFIG.rate_limit);
                if !ratelimit::allow(ip, site_rl) {
                    ng_log::request_log(method.as_str(), &path, 429, &host_header, "rate-limited", start.elapsed().as_millis() as u64);
                    return Ok(text_resp(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded"));
                }
            }
        }

        return match upstream {
            Some(u) => {
                let resp = proxy_to_upstream(&client, req, &u).await;
                ng_log::request_log(method.as_str(), &path, resp.status().as_u16(), &host_header, &u, start.elapsed().as_millis() as u64);
                Ok(resp)
            }
            None => Ok(text_resp(
                StatusCode::BAD_REQUEST,
                "No upstream configured for this Host",
            )),
        };
    }

    let resp = challenge_page(&pow::new_challenge(CHALLENGE_TTL));
    ng_log::request_log(method.as_str(), &path, 200, &host_header, "challenge", start.elapsed().as_millis() as u64);
    Ok(resp)
}

// Redirect all plaintext :80 traffic to https so ACME http clients and stray
// http visitors are sent to the TLS edge. TLS-ALPN-01 challenges are handled on
// :443 by rustls-acme itself, so :80 only needs to redirect.
async fn redirect_to_https(
    req: Request<Incoming>,
) -> Result<Response<RespBody>, Infallible> {
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string());

    let location = match host {
        Some(h) => {
            let pq = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
            format!("https://{h}{pq}")
        }
        None => "https://".to_string(),
    };

    let resp = Response::builder()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header("location", location)
        .body(
            Full::new(Bytes::from_static(b"Redirecting to https"))
                .map_err(|e: Infallible| match e {})
                .boxed(),
        )
        .unwrap();
    Ok(resp)
}

async fn run_http_redirect() {
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 80));
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            log::warn!("could not bind :80 for http->https redirect: {e}");
            return;
        }
    };
    loop {
        let (tcp, _) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                log::error!("accept(:80): {e}");
                continue;
            }
        };
        let io = TokioIo::new(tcp);
        tokio::spawn(async move {
            let _ = http1::Builder::new()
                .serve_connection(io, service_fn(redirect_to_https))
                .await;
        });
    }
}

// Server: NekoGuard is the TLS edge. Certificates for the configured domains are
// obtained and renewed automatically via ACME (Let's Encrypt) using TLS-ALPN-01,
// and cached on disk so they persist across restarts.
fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("nekoguard")
        .build()
        .expect("failed to create tokio runtime");

    runtime.block_on(async {
        main_inner().await;
    });
}

async fn main_inner() {
    // Initialize logging before anything else so startup messages are captured.
    let _ = ng_log::init(&CONFIG.log);

    // rustls needs a process-wide crypto provider installed before any TLS use.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    // Upstream pool. Like nginx's default (proxy_ssl_verify off), upstream
    // certificates are NOT verified: NekoGuard fronts its own TLS for visitors,
    // and internal backends commonly run self-signed certs on the LAN.
    let trust_tls = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("failed to build trusting TLS connector");
    // enforce_http is on by default and would reject https:// upstream URLs
    // before the TLS layer ever sees them.
    let mut http_connector = HttpConnector::new();
    http_connector.enforce_http(false);
    let client: ProxyClient = Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(15))
        .pool_max_idle_per_host(64)
        .http1_title_case_headers(true)
        .build(HttpsConnector::from((http_connector, trust_tls.into())));
    let client = Arc::new(client);

    // Initialize Redis + session manager
    let redis_url = std::env::var("NG_REDIS_URL")
        .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let redis_client = redis::Client::open(redis_url.as_str())
        .expect("failed to connect to Redis");
    let sess = Arc::new(
        session::SessionManager::new_with_config(
            &redis_client,
            &CONFIG.session.cookie_name,
            Duration::from_secs(CONFIG.session.ttl),
        ).await,
    );
    log::info!("[session] session manager ready");

    // Cleanup sweep: expire challenges and stale rate-limit buckets
    tokio::spawn(async {
        let mut tick = tokio::time::interval(Duration::from_secs(600));
        loop {
            tick.tick().await;
            pow::sweep();
            ratelimit::sweep();
        }
    });

    tokio::spawn(run_http_redirect());
    if let Some(http_port) = CONFIG.port_http {
        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], http_port));
        if let Ok(http_listener) = TcpListener::bind(addr).await {
            log::info!("HTTP test listener on :{http_port}");
            let client = Arc::clone(&client);
            let sess = Arc::clone(&sess);
            tokio::spawn(async move {
                loop {
                    let (mut tcp, peer) = match http_listener.accept().await {
                        Ok(c) => c,
                        Err(e) => {
                            log::error!("accept(http): {e}");
                            continue;
                        }
                    };
                    tcp.set_nodelay(true).ok();
                    let peer_ip = peer.ip();
                    let client = Arc::clone(&client);
                    let sess_c = Arc::clone(&sess);
                    tokio::spawn(async move {
                        let sess = sess_c;
                        // Peek at the raw bytes to detect WebSocket upgrade
                        // before hyper consumes them.
                        let mut peek_buf = [0u8; 4096];
                        let peek_len = tcp.peek(&mut peek_buf).await.unwrap_or(0);
                        let lower = String::from_utf8_lossy(&peek_buf[..peek_len]).to_ascii_lowercase();
                        let is_ws = lower.contains("upgrade: websocket");
                        log::info!("[http-ws] peek {} bytes, is_ws={}, first 80: {:?}",
                            peek_len, is_ws,
                            String::from_utf8_lossy(&peek_buf[..peek_len.min(80)]));

                        if is_ws {
                            // Extract Host header from peek buffer to resolve upstream.
                            let host = String::from_utf8_lossy(&peek_buf[..peek_len])
                                .lines()
                                .find(|l| l.to_ascii_lowercase().starts_with("host:"))
                                .and_then(|l| l.split_once(':').map(|x| x.1))
                                .map(|v| v.trim().to_string())
                                .unwrap_or_default();
                            let upstream = CONFIG.site_for_host(&host)
                                .map(|s| s.upstream.clone());
                            match upstream {
                                Some(u) => {
                                    log::info!("[ws] {} /ws -> {}", host, u);
                                    proxy_ws_upgrade_buf(&mut tcp, &u).await;
                                }
                                None => {
                                    log::warn!("[ws] no upstream for host {host}");
                                }
                            }
                            return;
                        }

                        let io = TokioIo::new(tcp);
                        let conn = http1::Builder::new().serve_connection(
                            io,
                            service_fn(move |req| {
                                handle(req, Arc::clone(&client), Arc::clone(&sess), peer_ip)
                            }),
                        );
                        let _ = conn.with_upgrades().await;
                    });
                }
            });
        } else {
            log::warn!("could not bind HTTP test port {http_port}");
        }
    }

    let port = CONFIG.port;
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await.unwrap();

    // Build the ACME state for the fixed domain list. tokio_incoming would hide
    // the peer address, so we drive the low-level state ourselves and keep the
    // TCP peer IP for the allowlist fallback.
    let mut acme_state = AcmeConfig::new(CONFIG.sites.iter().map(|s| s.domain.clone()))
        .contact(CONFIG.acme_contacts())
        .cache(DirCache::new(CONFIG.cache_dir.clone()))
        .directory_lets_encrypt(!CONFIG.staging)
        .state();

    // challenge config answers TLS-ALPN-01 validation; default config serves the
    // real certificates for normal traffic.
    let challenge_rustls_config = acme_state.challenge_rustls_config();
    let default_rustls_config = acme_state.default_rustls_config();

    // Drive the ACME event loop (issuance + renewal) in the background.
    tokio::spawn(async move {
        loop {
            match acme_state.next().await {
                Some(Ok(ok)) => log::info!("acme: {ok:?}"),
                Some(Err(err)) => log::error!("acme error: {err:?}"),
                None => break,
            }
        }
    });

    log::info!(
        "NekoGuard :{port} TLS edge — {} site(s), {} permanent IP(s){}",
        CONFIG.sites.len(),
        PERM.len(),
        if CONFIG.staging { " [staging]" } else { "" }
    );

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                log::error!("accept: {e}");
                continue;
            }
        };
        tcp.set_nodelay(true).ok();
        let peer_ip = peer.ip();
        let challenge_rustls_config = challenge_rustls_config.clone();
        let default_rustls_config = default_rustls_config.clone();
        let client = Arc::clone(&client);
        let sess = Arc::clone(&sess);

        tokio::spawn(async move {
            let start_handshake = match LazyConfigAcceptor::new(Default::default(), tcp).await {
                Ok(h) => h,
                Err(e) => {
                    log::error!("tls accept: {e}");
                    return;
                }
            };

            // TLS-ALPN-01 validation requests are answered with the challenge
            // config and then closed; they never carry an HTTP request.
            if is_tls_alpn_challenge(&start_handshake.client_hello()) {
                if let Ok(mut tls) = start_handshake.into_stream(challenge_rustls_config).await {
                    let _ = tls.shutdown().await;
                }
                return;
            }

            // SNI allowlist: refuse handshakes for names we don't serve,
            // mirroring nginx's unhandled-server_name behavior. (LE validation
            // connections above are exempt — they arrive with the ACME ALPN.)
            match start_handshake.client_hello().server_name() {
                Some(name) if CONFIG.is_known_domain(name) => {}
                _ => {
                    log::warn!(
                        "tls: refused handshake for unknown/absent SNI from {peer_ip}"
                    );
                    return;
                }
            }

            let mut tls = match start_handshake.into_stream(default_rustls_config).await {
                Ok(s) => s,
                Err(e) => {
                    log::error!("tls handshake: {e}");
                    return;
                }
            };

            // Read request headers byte-by-byte from the TLS stream to detect
            // WebSocket upgrade. Reads directly from the TLS stream (no BufReader)
            // so the stream position is correct for both WS (raw TCP) and non-WS
            // (PrefixedReader replay for hyper).
            let mut header_bytes = Vec::with_capacity(1024);
            {
                let mut one_byte = [0u8; 1];
                loop {
                    match tls.read(&mut one_byte).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            header_bytes.push(one_byte[0]);
                            if header_bytes.ends_with(b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
            }
            let is_ws = String::from_utf8_lossy(&header_bytes)
                .to_ascii_lowercase()
                .contains("upgrade: websocket");

            if is_ws {
                // WS: use raw TLS stream directly for bidirectional copy.
                // No PrefixedReader — it breaks Arc Mutex in tokio::io::split.
                // header_bytes has consumed the request; tls is past them.
                let host = String::from_utf8_lossy(&header_bytes)
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("host:"))
                    .and_then(|l| l.split_once(':').map(|x| x.1))
                    .map(|v| v.trim().to_string())
                    .unwrap_or_default();
                if let Some(site) = CONFIG.site_for_host(&host) {
                    let upstream = site.upstream.clone();

                    // Forward the WS upgrade to upstream over TCP.
                    let upstream_host = upstream
                        .strip_prefix("http://")
                        .or_else(|| upstream.strip_prefix("https://"))
                        .unwrap_or(&upstream);
                    let upstream_sock: std::net::SocketAddr =
                        match tokio::net::lookup_host(upstream_host).await.ok()
                            .and_then(|mut a| a.next()) {
                            Some(a) => a,
                            None => {
                                log::error!("[ws] upstream lookup failed: {upstream}");
                                return;
                            }
                        };
                    let mut upstream_tcp = match tokio::net::TcpStream::connect(upstream_sock).await {
                        Ok(s) => s,
                        Err(e) => {
                            log::error!("[ws] upstream connect failed: {e}");
                            return;
                        }
                    };
                    upstream_tcp.set_nodelay(true).ok();

                    // Forward ALL headers to upstream. Only rewrite Host.
                    let hdr_text = String::from_utf8_lossy(&header_bytes);
                    let first_line = hdr_text.lines().next().unwrap_or("");
                    let fl_parts: Vec<&str> = first_line.split_whitespace().collect();
                    let ws_path = if fl_parts.len() >= 2 { fl_parts[1] } else { "/" };
                    let mut rewritten = format!("{} {} HTTP/1.1\r\n", fl_parts[0], ws_path);
                    let auth = upstream.split(':').next().unwrap_or(&upstream);
                    for line in hdr_text[hdr_text.find("\r\n").unwrap_or(0) + 2..]
                        .lines().take_while(|l| !l.is_empty())
                    {
                        if line.to_lowercase().starts_with("host:") {
                            rewritten.push_str(&format!("Host: {auth}\r\n"));
                        } else {
                            rewritten.push_str(&format!("{line}\r\n"));
                        }
                    }
                    rewritten.push_str("\r\n");
                    log::info!("[ws] rewritten request:\n{}", rewritten.replace('\r', ""));

                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    if let Err(e) = upstream_tcp.write_all(rewritten.as_bytes()).await {
                        log::error!("[ws-tls] upstream write failed: {e}");
                        return;
                    }

                    // Read101 from upstream (NOT from the TLS client stream).
                    let mut resp_buf = Vec::with_capacity(1024);
                    let mut tmp = [0u8; 1024];
                    loop {
                        match upstream_tcp.read(&mut tmp).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => resp_buf.extend_from_slice(&tmp[..n]),
                        }
                        if resp_buf.windows(4).any(|w| w == b"\r\n\r\n") { break; }
                    }
                    let resp_preview = String::from_utf8_lossy(&resp_buf);
                    log::info!("[ws-tls] upstream responded: {}", resp_preview.lines().next().unwrap_or(""));
                    if !resp_buf.starts_with(b"HTTP/1.1 101") { return; }

                    // Split the TLS stream for bidirectional copy. The client
                    // already received its own request bytes; it's waiting for
                    // the101 response, not a replay of its request.
                    let (mut client_read, mut client_write) = tokio::io::split(tls);
                    let _ = client_write.write_all(&resp_buf).await;
                    let (mut ur, mut uw) = upstream_tcp.into_split();
                    let c2u = tokio::io::copy(&mut client_read, &mut uw);
                    let u2c = tokio::io::copy(&mut ur, &mut client_write);
                    let _ = tokio::join!(c2u, u2c);
                    log::debug!("[ws-tls] bidirectional copy ended");
                } else {
                    log::warn!("[ws] no upstream for host {host}");
                }
                return;
            }

            // Non-upgrade: wrap the TLS stream in PrefixedReader to replay
            // the consumed headers back to hyper. The TLS stream position
            // is past the headers, so hyper would miss them without this.
            let prefixed = PrefixedReader {
                prefix: std::io::Cursor::new(header_bytes),
                inner: tls,
            };
            let io = TokioIo::new(prefixed);
            let conn = http1::Builder::new().serve_connection(
                io,
                service_fn(move |req| handle(req, Arc::clone(&client), Arc::clone(&sess), peer_ip)),
            );
            let _ = conn.with_upgrades().await;
        });
    }
}