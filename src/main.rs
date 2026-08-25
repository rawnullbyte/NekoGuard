mod config;
mod pow;

use bytes::Bytes;
use config::CONFIG;
use dashmap::DashMap;
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
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_rustls::LazyConfigAcceptor;

const CHALLENGE_HTML: &str = include_str!(concat!(env!("OUT_DIR"), "/challenge.min.html"));
const MAX_VERIFY_BODY: usize = 512;
const CHALLENGE_TTL: Duration = Duration::from_secs(300); // 5 min
const TEMP_TTL: Duration = Duration::from_secs(1800); // 30 min

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

static TEMP: LazyLock<DashMap<IpAddr, Instant>> = LazyLock::new(DashMap::new);

fn is_allowed(ip: IpAddr) -> bool {
    if PERM.contains(&ip) {
        return true;
    }
    let expiry = match TEMP.get(&ip) {
        Some(r) => *r,
        None => return false,
    };
    if Instant::now() <= expiry {
        return true;
    }
    TEMP.remove(&ip);
    false
}

fn allow_ip(ip: IpAddr) {
    TEMP.insert(ip, Instant::now() + TEMP_TTL);
}


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

            rp.headers.remove("content-security-policy");
            rp.headers.remove("content-security-policy-report-only");
            rp.headers.remove("transfer-encoding");

            let patched: Vec<HeaderValue> = rp
                .headers
                .get_all("set-cookie")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .map(|s| strip_cookie_domain(s))
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
            eprintln!("Proxy error: {:?}", e);
            text_resp(StatusCode::BAD_GATEWAY, "Upstream error")
        }
    }
}

// Main handler
async fn handle(
    req: Request<Incoming>,
    client: Arc<ProxyClient>,
    peer_ip: IpAddr,
) -> Result<Response<RespBody>, Infallible> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    // /__ng/* routes are always handled locally, before any auth or proxy logic.
    if (path == "/__ng/version") && method == Method::GET {
        return Ok(text_resp(StatusCode::OK, env!("CARGO_PKG_VERSION")));
    }

    if path.starts_with("/__ng/assets/") && method == Method::GET {
        let asset_subpath = &path["/__ng/assets/".len()..];
        return Ok(serve_embedded_asset(asset_subpath));
    }

    // Prefer X-Real-IP from a trusted front proxy; otherwise fall back to the
    // TCP peer address (NekoGuard is the direct edge).
    let real_ip: Option<IpAddr> = req
        .headers()
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .or(Some(peer_ip));

    // Prefer an explicit X-Upstream header; otherwise resolve the upstream from
    // the config's Host->upstream map so NekoGuard can route on its own.
    let upstream = req
        .headers()
        .get("x-upstream")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| {
            req.headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .and_then(|h| CONFIG.upstream_for_host(h))
                .map(str::to_string)
        });

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

        if let Some(ip) = real_ip {
            allow_ip(ip);
        }
        return Ok(text_resp(StatusCode::OK, "OK"));
    }

    if real_ip.map(is_allowed).unwrap_or(false) {
        return match upstream {
            Some(u) => Ok(proxy_to_upstream(&client, req, &u).await),
            None => Ok(text_resp(StatusCode::BAD_REQUEST, "Missing X-Upstream header")),
        };
    }

    Ok(challenge_page(&pow::new_challenge(CHALLENGE_TTL)))
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
            eprintln!("warning: could not bind :80 for http->https redirect: {e}");
            return;
        }
    };
    loop {
        let (tcp, _) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("accept(:80): {e}");
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
#[tokio::main]
async fn main() {
    // rustls needs a process-wide crypto provider installed before any TLS use.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let client: ProxyClient =
        Client::builder(TokioExecutor::new()).build(HttpsConnector::new());
    let client = Arc::new(client);

    tokio::spawn(async {
        let mut tick = tokio::time::interval(Duration::from_secs(600));
        loop {
            tick.tick().await;
            pow::sweep();
            let now = Instant::now();
            TEMP.retain(|_, exp| now < *exp);
        }
    });

    tokio::spawn(run_http_redirect());

    let port = CONFIG.port;
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await.unwrap();

    // Build the ACME state for the fixed domain list. tokio_incoming would hide
    // the peer address, so we drive the low-level state ourselves and keep the
    // TCP peer IP for the allowlist fallback.
    let mut acme_state = AcmeConfig::new(CONFIG.domains.clone())
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
                Some(Ok(ok)) => println!("acme: {ok:?}"),
                Some(Err(err)) => eprintln!("acme error: {err:?}"),
                None => break,
            }
        }
    });

    println!(
        "NekoGuard [:{port}] TLS edge — {} domain(s), {} permanent IP(s){}",
        CONFIG.domains.len(),
        PERM.len(),
        if CONFIG.staging { " [staging]" } else { "" }
    );

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("accept: {e}");
                continue;
            }
        };
        tcp.set_nodelay(true).ok();
        let peer_ip = peer.ip();
        let challenge_rustls_config = challenge_rustls_config.clone();
        let default_rustls_config = default_rustls_config.clone();
        let client = Arc::clone(&client);

        tokio::spawn(async move {
            let start_handshake = match LazyConfigAcceptor::new(Default::default(), tcp).await {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("tls accept: {e}");
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

            let tls = match start_handshake.into_stream(default_rustls_config).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("tls handshake: {e}");
                    return;
                }
            };

            let io = TokioIo::new(tls);
            let _ = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| handle(req, Arc::clone(&client), peer_ip)),
                )
                .await;
        });
    }
}