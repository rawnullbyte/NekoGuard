use crate::config::CONFIG;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, BytesBody, BytesResponse,
    ChallengeType, HttpClient, Identifier, LetsEncrypt, NewAccount, NewOrder, RetryPolicy,
};
use serde::{Deserialize, Serialize};
use std::sync::Once;
use tokio::time::Duration;

/// Ensure exactly one rustls crypto provider (ring) is installed.
fn ensure_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        match rustls::crypto::ring::default_provider().install_default() {
            Ok(()) => log::info!("[certd] rustls crypto provider: ring installed"),
            Err(_) => log::info!("[certd] rustls crypto provider: already installed"),
        }
    });
}

const CERT_PREFIX: &str = "nekoguard:cert:";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertData {
    pub cert_pem: String,
    pub key_pem: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

// ── Buffered body: returns pre-read bytes instantly, no I/O ──────

struct BufferedBody(bytes::Bytes);

#[async_trait::async_trait]
impl BytesBody for BufferedBody {
    async fn into_bytes(
        &mut self,
    ) -> Result<bytes::Bytes, Box<dyn std::error::Error + Send + Sync + 'static>> {
        log::info!("[buffered-body] into_bytes called, {}B ready", self.0.len());
        Ok(std::mem::take(&mut self.0))
    }
}

// ── Reqwest-based HTTP client for instant-acme ───────────────────
// instant-acme's DefaultClient uses try_with_platform_verifier() which
// hangs in minimal containers. We wrap reqwest (which has its own
// cert store) and implement the HttpClient trait instead.

struct ReqwestAcmeClient(reqwest::Client);

impl HttpClient for ReqwestAcmeClient {
    fn request(
        &self,
        req: http::Request<instant_acme::BodyWrapper<bytes::Bytes>>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<BytesResponse, instant_acme::Error>>
                + Send,
        >,
    > {
        let client = self.0.clone();
        Box::pin(async move {
            let (parts, mut body) = req.into_parts();

            // Pre-buffer request body
            let body_bytes = {
                use http_body_util::BodyExt;
                body.collect()
                    .await
                    .map_err(|e| instant_acme::Error::Other(Box::new(e)))?
                    .to_bytes()
            };

            log::info!("[acme-http] {} {}", parts.method, parts.uri);

            let url = parts.uri.to_string();
            let method = parts.method.clone();
            let mut rb = match method {
                http::Method::GET => client.get(&url),
                http::Method::POST => client.post(&url),
                http::Method::PUT => client.put(&url),
                http::Method::HEAD => client.head(&url),
                http::Method::DELETE => client.delete(&url),
                _ => client.request(method, &url),
            };

            for (key, value) in parts.headers.iter() {
                rb = rb.header(key, value);
            }

            if !body_bytes.is_empty() {
                rb = rb.body(body_bytes);
            }

            // Send and fully buffer response (avoids BodyWrapper::into_bytes hang)
            let response = rb
                .send()
                .await
                .map_err(|e| instant_acme::Error::Other(Box::new(e)))?;

            let status = response.status();
            let resp_headers = response.headers().clone();
            let resp_body = response
                .bytes()
                .await
                .map_err(|e| instant_acme::Error::Other(Box::new(e)))?;

            log::info!("[acme-http] {} → {status} ({}B)", parts.uri, resp_body.len());
            if !status.is_success() {
                log::info!("[acme-http] error body: {}", String::from_utf8_lossy(&resp_body));
            }

            // Build BytesResponse with BufferedBody — no BodyWrapper, no hang.
            // Clone body (cheap ref-count bump) so we can extract Parts from a response.
            let body_clone = resp_body.clone();
            let mut builder = http::Response::builder().status(status);
            for (key, value) in resp_headers.iter() {
                builder = builder.header(key, value);
            }
            let (resp_parts, _) = builder.body(resp_body).expect("infallible").into_parts();

            Ok(BytesResponse {
                parts: resp_parts,
                body: Box::new(BufferedBody(body_clone)),
            })
        })
    }
}

// ── ACME loop ───────────────────────────────────────────────────

pub async fn run_acme_loop(
    redis_url: &str,
    domains: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_crypto_provider();

    let cache_dir = std::env::temp_dir().join("nekoguard-certd");
    std::fs::create_dir_all(&cache_dir).ok();

    let cf_client = CloudflareDns::new(&CONFIG.certd.cloudflare_api_token);

    // Create reqwest-based ACME client (avoids platform-verifier hang)
    let http_client = ReqwestAcmeClient(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?,
    );

    // Create or load ACME account
    let creds_path = cache_dir.join("account_credentials.json");

    let account = if creds_path.exists() {
        let creds_json = std::fs::read_to_string(&creds_path).unwrap_or_default();
        let creds: AccountCredentials =
            serde_json::from_str(&creds_json).expect("invalid stored account credentials");
        log::info!("[certd] loading existing ACME account");
        Account::builder_with_http(Box::new(http_client))
            .from_credentials(creds)
            .await
            .expect("ACME account restore failed")
    } else {
        log::info!("[certd] creating new ACME account");
        let builder = Account::builder_with_http(Box::new(http_client));
        let (account, credentials) = builder
            .create(
                &NewAccount {
                    contact: &[&CONFIG.certd.contact_email],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                LetsEncrypt::Production.url().to_owned(),
                None,
            )
            .await?;
        log::info!("[certd] ACME account created");
        let creds_json = serde_json::to_string_pretty(&credentials).unwrap();
        let _ = std::fs::write(&creds_path, &creds_json);
        account
    };

    // Initial issuance
    for domain in domains {
        issue_or_renew(&account, &cf_client, redis_url, domain).await;
    }

    // Renewal loop
    loop {
        tokio::time::sleep(Duration::from_secs(CONFIG.certd.renewal_interval)).await;
        log::info!("[certd] checking renewals...");
        let mut redis = redis::Client::open(redis_url)
            .expect("redis connect")
            .get_connection_manager()
            .await
            .expect("redis conn manager");
        for domain in domains {
            if let Some(cert) = load_cert(&mut redis, domain).await {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if cert.expires_at > 0 && cert.expires_at < now + 30 * 86400 {
                    log::info!("[certd] renewing cert for {domain}");
                    issue_or_renew(&account, &cf_client, redis_url, domain).await;
                }
            }
        }
    }
}

async fn issue_or_renew(
    account: &Account,
    cf: &CloudflareDns,
    redis_url: &str,
    domain: &str,
) {
    log::info!("[certd] issuing cert for {domain}");

    let identifiers = vec![Identifier::Dns(domain.to_string())];
    let mut order = account
        .new_order(&NewOrder::new(identifiers.as_slice()))
        .await
        .expect("ACME order creation failed");

    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result.expect("authorization failed");

        match authz.status {
            AuthorizationStatus::Valid => continue,
            AuthorizationStatus::Pending => {}
            _ => continue,
        }

        if let Some(mut challenge) = authz.challenge(ChallengeType::Dns01) {
            let key_auth = challenge.key_authorization();
            let dns_value = key_auth.dns_value();
            let dns_name = format!("_acme-challenge.{domain}");

            log::info!("[certd] setting DNS record: {dns_name} = {dns_value}");
            cf.set_txt_record(domain, &dns_name, &dns_value)
                .await
                .expect("failed to set DNS record");

            challenge.set_ready().await.expect("challenge ready failed");
            log::info!("[certd] challenge ready for {domain}");
        }
    }

    order
        .poll_ready(&RetryPolicy::default())
        .await
        .expect("order not ready");

    let private_key_pem = order.finalize().await.expect("finalize failed");
    let cert_chain_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .expect("cert fetch failed");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let cert = CertData {
        cert_pem: cert_chain_pem,
        key_pem: private_key_pem,
        issued_at: now,
        expires_at: now + 90 * 86400,
    };

    let mut redis = redis::Client::open(redis_url)
        .expect("redis connect")
        .get_connection_manager()
        .await
        .expect("redis conn manager");
    store_cert(&mut redis, domain, &cert).await;

    let _: () = redis::cmd("PUBLISH")
        .arg("nekoguard:cert:update")
        .arg(domain)
        .query_async(&mut redis)
        .await
        .ok()
        .unwrap_or_default();

    log::info!("[certd] cert issued and stored for {domain}");
}

// ── Cloudflare DNS-01 helper ────────────────────────────────────

struct CloudflareDns {
    client: reqwest::Client,
    api_token: String,
}

impl CloudflareDns {
    fn new(api_token: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_token: api_token.to_string(),
        }
    }

    async fn get_zone_id(&self, domain: &str) -> Result<String, Box<dyn std::error::Error>> {
        let parts: Vec<&str> = domain.rsplitn(3, '.').collect();
        let root_domain = if parts.len() >= 2 {
            format!("{}.{}", parts[1], parts[0])
        } else {
            domain.to_string()
        };

        let url = format!(
            "https://api.cloudflare.com/client/v4/zones?name={}",
            root_domain
        );

        let resp = self
            .client
            .get(&url)
            .header(
                "Authorization",
                format!("Bearer {}", self.api_token),
            )
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("Cloudflare API error: {text}").into());
        }

        let data: serde_json::Value = resp.json().await?;
        let zones = data["result"].as_array().ok_or("no zones found")?;
        let zone_id = zones
            .first()
            .and_then(|z| z["id"].as_str())
            .ok_or("zone ID not found")?
            .to_string();

        log::info!("[certd] resolved zone for {domain}: {zone_id}");
        Ok(zone_id)
    }

    async fn set_txt_record(
        &self,
        domain: &str,
        name: &str,
        value: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let zone_id = self.get_zone_id(domain).await?;
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            zone_id
        );

        let body = serde_json::json!({
            "type": "TXT",
            "name": name,
            "content": value,
            "ttl": 120
        });

        let resp = self
            .client
            .post(&url)
            .header(
                "Authorization",
                format!("Bearer {}", self.api_token),
            )
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("Cloudflare API error: {text}").into());
        }
        Ok(())
    }
}

// ── Redis cert storage ──────────────────────────────────────────

async fn store_cert(
    redis: &mut redis::aio::ConnectionManager,
    domain: &str,
    cert: &CertData,
) {
    let key = format!("{CERT_PREFIX}{domain}");
    let data = serde_json::to_vec(cert).unwrap_or_default();
    let _: () = redis::cmd("SET")
        .arg(&key)
        .arg(&data)
        .query_async(redis)
        .await
        .ok()
        .unwrap_or_default();
}

pub async fn load_cert(
    redis: &mut redis::aio::ConnectionManager,
    domain: &str,
) -> Option<CertData> {
    let key = format!("{CERT_PREFIX}{domain}");
    let data: Result<Vec<u8>, _> = redis::cmd("GET")
        .arg(&key)
        .query_async(redis)
        .await;
    data.ok().and_then(|d| serde_json::from_slice(&d).ok())
}

pub async fn get_all_certs(
    redis: &mut redis::aio::ConnectionManager,
    domains: &[String],
) -> Vec<(String, CertData)> {
    let mut result = Vec::new();
    for domain in domains {
        if let Some(cert) = load_cert(redis, domain).await {
            result.push((domain.clone(), cert));
        }
    }
    result
}
