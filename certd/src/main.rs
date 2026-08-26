mod acme;
mod config;

use config::CONFIG;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use std::convert::Infallible;
use std::sync::Arc;
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
    req: Request<hyper::body::Incoming>,
    acme: Arc<acme::AcmeManager>,
) -> Result<Response<RespBody>, Infallible> {
    let path = req.uri().path();
    let method = req.method();

    match (method, path) {
        (&Method::GET, "/health") => {
            Ok(json_resp(StatusCode::OK, r#"{"status":"ok"}"#))
        }

        (&Method::GET, "/certs") => {
            // Return all certs
            let certs = acme.get_all_certs().await;
            let json = serde_json::to_string(&certs).unwrap_or_else(|_| "[]".to_string());
            Ok(json_resp(StatusCode::OK, &json))
        }

        (&Method::GET, p) if p.starts_with("/certs/") => {
            let domain = &p[7..]; // strip "/certs/"
            match acme.get_cert(domain).await {
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
    // Simple stderr logger for certd
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();
    log::info!("nekoguard-certd starting on :{}", CONFIG.port);

    let acme = Arc::new(acme::AcmeManager::new().await);
    let acme_clone = Arc::clone(&acme);

    // Start ACME event loop
    tokio::spawn(async move {
        acme_clone.run_event_loop().await;
    });

    // HTTP server
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], CONFIG.port));
    let listener = TcpListener::bind(addr).await.expect("bind failed");
    log::info!("nekoguard-certd ready on :{}", CONFIG.port);

    loop {
        let (tcp, _) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => { log::error!("accept: {e}"); continue; }
        };
        let acme = Arc::clone(&acme);
        tokio::spawn(async move {
            let io = hyper_util::rt::TokioIo::new(tcp);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service_fn(move |req| handle(req, Arc::clone(&acme))))
                .await;
        });
    }
}
