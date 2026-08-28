mod acme;
mod config;

use config::CONFIG;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use std::convert::Infallible;
use tokio::net::TcpListener;

type RespBody = http_body_util::Full<bytes::Bytes>;

fn json_resp(status: StatusCode, body: &str) -> Response<RespBody> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(http_body_util::Full::new(bytes::Bytes::from(body.to_string())))
        .unwrap()
}

async fn handle(
    req: Request<Incoming>,
) -> Result<Response<RespBody>, Infallible> {
    let path = req.uri().path();
    let method = req.method();

    match (method, path) {
        (&Method::GET, "/health") => {
            Ok(json_resp(StatusCode::OK, r#"{"status":"ok"}"#))
        }

        (&Method::GET, "/certs") => {
            let mut conn = redis::Client::open(CONFIG.redis.url.as_str())
                .expect("redis connect")
                .get_connection_manager()
                .await
                .expect("redis conn manager");
            let domains: Vec<String> = CONFIG.sites.iter().map(|s| s.domain.clone()).collect();
            let certs = acme::get_all_certs(&mut conn, &domains).await;
            let json = serde_json::to_string(&certs).unwrap_or_else(|_| "[]".to_string());
            Ok(json_resp(StatusCode::OK, &json))
        }

        (&Method::GET, p) if p.starts_with("/certs/") => {
            let domain = &p[7..];
            let mut conn = redis::Client::open(CONFIG.redis.url.as_str())
                .expect("redis connect")
                .get_connection_manager()
                .await
                .expect("redis conn manager");
            match acme::load_cert(&mut conn, domain).await {
                Some(cert) => {
                    let json = serde_json::to_string(&cert).unwrap_or_default();
                    Ok(json_resp(StatusCode::OK, &json))
                }
                None => Ok(json_resp(StatusCode::NOT_FOUND, r#"{"error":"cert not found"}"#)),
            }
        }

        _ => Ok(json_resp(StatusCode::NOT_FOUND, r#"{"error":"not found"}"#)),
    }
}

#[tokio::main]
async fn main() {
    // Simple stderr logger
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    // Install rustls crypto provider before any TLS operations.
    match rustls::crypto::ring::default_provider().install_default() {
        Ok(()) => log::info!("[certd] rustls crypto provider installed"),
        Err(_) => log::info!("[certd] rustls crypto provider: already installed"),
    }

    log::info!("nekoguard-certd starting on :{}", CONFIG.certd.port);

    // Start ACME issuance/renewal loop in background
    let mut domains: Vec<String> = Vec::new();
    for site in &CONFIG.sites {
        domains.push(site.domain.clone());
        if site.wildcard {
            domains.push(format!("*.{}", site.domain));
        }
    }
    let redis_url = CONFIG.redis.url.clone();
    tokio::spawn(async move {
        let _ = acme::run_acme_loop(&redis_url, &domains).await;
    });

    // HTTP server for cert queries
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], CONFIG.certd.port));
    let listener = TcpListener::bind(addr).await.expect("bind failed");
    log::info!("nekoguard-certd ready on :{}", CONFIG.certd.port);

    loop {
        let (tcp, _) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => { log::error!("accept: {e}"); continue; }
        };
        tokio::spawn(async move {
            let io = hyper_util::rt::TokioIo::new(tcp);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service_fn(handle))
                .await;
        });
    }
}
