
use crate::config::CONFIG;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType,
    Identifier, LetsEncrypt, NewAccount, NewOrder, RetryPolicy,
};
use serde::{Deserialize, Serialize};
use std::sync::Once;
use tokio::time::Duration;

/// Ensure exactly one rustls crypto provider (ring) is installed.
/// Called at the top of the ACME loop so it runs on the tokio worker thread.
fn ensure_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        eprintln!("[certd] ensure_crypto_provider: calling install_default...");
        match rustls::crypto::ring::default_provider().install_default() {
            Ok(()) => {
                eprintln!("[certd] ensure_crypto_provider: OK");
                log::info!("[certd] rustls crypto provider: ring installed");
            }
            Err(_) => {
                eprintln!("[certd] ensure_crypto_provider: FAILED");
                log::warn!("[certd] rustls crypto provider: already installed or conflicting");
            }
        }
    });
    eprintln!("[certd] ensure_crypto_provider: Once completed");
}

const CERT_PREFIX: &str = "nekoguard:cert:";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertData {
    pub cert_pem: String,
    pub key_pem: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Run the ACME loop: issue/renew certs for all domains, store in Redis.
pub async fn run_acme_loop(redis_url: &str, domains: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    ensure_crypto_provider();

    let cache_dir = std::env::temp_dir().join("nekoguard-certd");
    std::fs::create_dir_all(&cache_dir).ok();

    let cf_client = CloudflareDns::new(&CONFIG.certd.cloudflare_api_token);

    // Create or load ACME account
    let creds_path = cache_dir.join("account_credentials.json");

    let account = if creds_path.exists() {
        let creds_json = std::fs::read_to_string(&creds_path).unwrap_or_default();
        let creds: AccountCredentials = serde_json::from_str(&creds_json)
            .expect("invalid stored account credentials");
        log::info!("[certd] loading existing ACME account");
        Account::builder()?
            .from_credentials(creds)
            .await
            .expect("ACME account restore failed")
    } else {
        log::info!("[certd] creating new ACME account");
        let (account, credentials) = Account::builder()?
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
        let creds_json = serde_json::to_string_pretty(&credentials).unwrap();
        let _ = std::fs::write(&creds_path, &creds_json);
        log::info!("[certd] ACME account created");
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

    // Process authorizations
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
            cf.set_txt_record(domain, &dns_name, &dns_value).await
                .expect("failed to set DNS record");

            challenge.set_ready().await.expect("challenge ready failed");
            log::info!("[certd] challenge ready for {domain}");
        }
    }

    // Wait for order to be ready
    order
        .poll_ready(&RetryPolicy::default())
        .await
        .expect("order not ready");

    // Finalize and get cert
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

    // Notify NekoGuard replicas via Redis Pub/Sub
    let _: () = redis::cmd("PUBLISH")
        .arg("nekoguard:cert:update")
        .arg(domain)
        .query_async(&mut redis)
        .await
        .ok()
        .unwrap_or_default();

    log::info!("[certd] cert issued and stored for {domain}");
}

// ── Cloudflare DNS-01 helper ──────────────────────────────────────

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

    /// Look up the Cloudflare zone ID for a domain.
    async fn get_zone_id(&self, domain: &str) -> Result<String, Box<dyn std::error::Error>> {
        // Extract the root domain (e.g. "foo.bar.example.com" → "example.com")
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

        let resp = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("Cloudflare API error: {text}").into());
        }

        let data: serde_json::Value = resp.json().await?;
        let zones = data["result"].as_array().ok_or("no zones found")?;
        let zone_id = zones.first()
            .and_then(|z| z["id"].as_str())
            .ok_or("zone ID not found")?
            .to_string();

        log::info!("[certd] resolved zone for {domain}: {zone_id}");
        Ok(zone_id)
    }

    async fn set_txt_record(&self, domain: &str, name: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
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

        let resp = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
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

// ── Redis cert storage ────────────────────────────────────────────

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
