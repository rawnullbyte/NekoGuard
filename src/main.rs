mod pow;

use bytes::Bytes;
use dashmap::DashMap;
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
use serde::Deserialize;
use std::collections::HashSet;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

const CHALLENGE_HTML: &str = include_str!(concat!(env!("OUT_DIR"), "/challenge.min.html"));
const PORT: u16 = 3000;
const MAX_VERIFY_BODY: usize = 512;
const CHALLENGE_TTL: Duration = Duration::from_secs(300);
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

// Proxy
async fn proxy_to_upstream(
    client: &ProxyClient,
    req: Request<Incoming>,
    upstream: &str,
) -> Response<RespBody> {
    let pq = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let target = format!("{}{}", upstream.trim_end_matches('/'), pq);

    let target_uri: hyper::Uri = match target.parse() {
        Ok(u) => u,
        Err(_) => return text_resp(StatusCode::BAD_REQUEST, "Bad upstream URI"),
    };

    let (mut parts, body) = req.into_parts();
    parts.uri = target_uri;
    parts.headers.remove("x-upstream");
    parts.headers.remove("host"); 

    match client.request(Request::from_parts(parts, body.boxed())).await {
        Ok(resp) => {
            let (mut rp, rb) = resp.into_parts();
            rp.headers.remove("transfer-encoding");
            Response::from_parts(rp, rb.boxed())
        }
        Err(_) => text_resp(StatusCode::BAD_GATEWAY, "Upstream unavailable"),
    }
}

// Main handler
async fn handle(
    req: Request<Incoming>,
    client: Arc<ProxyClient>,
) -> Result<Response<RespBody>, Infallible> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    let real_ip: Option<IpAddr> = req
        .headers()
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    let upstream = req
        .headers()
        .get("x-upstream")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    if real_ip.map(is_allowed).unwrap_or(false) {
        return match upstream {
            Some(u) => Ok(proxy_to_upstream(&client, req, &u).await),
            None => Ok(text_resp(StatusCode::BAD_REQUEST, "Missing X-Upstream header")),
        };
    }

    // Unauthenticated Flow
    if (path == "/__ng/version") && method == Method::GET {
        return Ok(text_resp(StatusCode::OK, env!("CARGO_PKG_VERSION")));
    }

    if path.starts_with("/__ng/assets/") && method == Method::GET {
        let asset_subpath = &path["/__ng/assets/".len()..];
        return Ok(serve_embedded_asset(asset_subpath));
    }

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

    Ok(challenge_page(&pow::new_challenge(CHALLENGE_TTL)))
}

// Server
#[tokio::main]
async fn main() {
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

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], PORT));
    let listener = TcpListener::bind(addr).await.unwrap();

    if PERM.is_empty() {
        println!("NekoGuard [:{PORT}]");
    } else {
        println!("NekoGuard [:{PORT}] — {} permanent IP(s)", PERM.len());
    }

    loop {
        let (tcp, _) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => { eprintln!("accept: {e}"); continue }
        };
        tcp.set_nodelay(true).ok();
        let io = TokioIo::new(tcp);
        let client = Arc::clone(&client);

        tokio::spawn(async move {
            let _ = http1::Builder::new()
                .serve_connection(io, service_fn(move |req| handle(req, Arc::clone(&client))))
                .await;
        });
    }
}