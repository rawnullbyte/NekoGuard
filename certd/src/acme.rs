use crate::config::CONFIG;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::{SigningKey, signature::Signer};
use p256::EncodedPoint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

const CERT_PREFIX: &str = "nekoguard:cert:";
const LE_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertData {
    pub cert_pem: String,
    pub key_pem: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

// ── JWK / JWS helpers ───────────────────────────────────────────

fn b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn b64str(s: &str) -> String {
    b64(s.as_bytes())
}

fn jwk_public(key: &SigningKey) -> serde_json::Value {
    let public: EncodedPoint = key.verifying_key().to_encoded_point(false);
    let x = public.x().unwrap();
    let y = public.y().unwrap();
    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": b64(x.as_slice()),
        "y": b64(y.as_slice()),
    })
}

fn jwk_thumbprint(key: &SigningKey) -> String {
    let jwk = jwk_public(key);
    // Canonical form: lexicographic order, no whitespace
    let canonical = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        jwk["x"], jwk["y"]
    );
    let hash = Sha256::digest(canonical.as_bytes());
    b64(&hash)
}

fn sign_es256(key: &SigningKey, data: &[u8]) -> String {
    let sig: p256::ecdsa::Signature = key.sign(data);
    // JWS uses raw R||S (64 bytes), NOT DER
    let (r, s) = sig.split_bytes();
    let mut raw = [0u8; 64];
    raw[..32].copy_from_slice(&r);
    raw[32..].copy_from_slice(&s);
    b64(&raw)
}

fn jws_payload(
    key: &SigningKey,
    nonce: &str,
    url: &str,
    jwk: Option<&serde_json::Value>,
    kid: Option<&str>,
    payload: &[u8],
) -> serde_json::Value {
    let mut header = serde_json::json!({
        "alg": "ES256",
        "nonce": nonce,
        "url": url,
    });
    if let Some(jwk) = jwk {
        header["jwk"] = jwk.clone();
    } else if let Some(kid) = kid {
        header["kid"] = serde_json::Value::String(kid.to_string());
    }

    let protected = b64(serde_json::to_string(&header).unwrap().as_bytes());
    let payload_b64 = b64(payload);
    let signing_input = format!("{protected}.{payload_b64}");
    let signature = sign_es256(key, signing_input.as_bytes());

    serde_json::json!({
        "protected": protected,
        "payload": payload_b64,
        "signature": signature,
    })
}

// ── ACME client ──────────────────────────────────────────────────

struct AcmeClient {
    http: reqwest::Client,
    key: SigningKey,
    directory: DirectoryUrls,
    account_url: Option<String>,
    nonce: String,
    thumbprint: String,
}

#[derive(Deserialize)]
struct DirectoryUrls {
    newNonce: String,
    newAccount: String,
    newOrder: String,
}

impl AcmeClient {
    async fn new(email: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        // Generate P-256 key
        use p256::elliptic_curve::rand_core::OsRng;
        let key = SigningKey::random(&mut OsRng);
        let thumbprint = jwk_thumbprint(&key);

        // Fetch directory
        log::info!("[acme] fetching directory...");
        let dir: DirectoryUrls = http.get(LE_DIRECTORY).send().await?.json().await?;

        // Get nonce
        log::info!("[acme] fetching nonce...");
        let resp = http.head(&dir.newNonce).send().await?;
        let nonce = resp
            .headers()
            .get("replay-nonce")
            .ok_or("missing Replay-Nonce header")?
            .to_str()?
            .to_string();

        let mut client = AcmeClient {
            http,
            key,
            directory: dir,
            account_url: None,
            nonce,
            thumbprint,
        };

        // Create account
        let account_url = client.create_account(email).await?;
        client.account_url = Some(account_url);

        Ok(client)
    }

    async fn get_nonce(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let resp = self.http.head(&self.directory.newNonce).send().await?;
        self.nonce = resp
            .headers()
            .get("replay-nonce")
            .ok_or("missing Replay-Nonce")?
            .to_str()?
            .to_string();
        Ok(())
    }

    async fn post_jws(
        &mut self,
        url: &str,
        payload: &[u8],
        use_jwk: bool,
    ) -> Result<reqwest::Response, Box<dyn std::error::Error + Send + Sync>> {
        self.get_nonce().await?;
        let jwk = if use_jwk {
            Some(jwk_public(&self.key))
        } else {
            None
        };
        let nonce = self.nonce.clone();
        let kid = self.account_url.clone();
        let body = jws_payload(
            &self.key,
            &nonce,
            url,
            jwk.as_ref(),
            kid.as_deref(),
            payload,
        );
        let resp = self
            .http
            .post(url)
            .header("Content-Type", "application/jose+json")
            .json(&body)
            .send()
            .await?;

        // Capture new nonce from response
        if let Some(nonce) = resp.headers().get("replay-nonce") {
            if let Ok(n) = nonce.to_str() {
                self.nonce = n.to_string();
            }
        }

        Ok(resp)
    }

    async fn post_as_get(
        &mut self,
        url: &str,
    ) -> Result<reqwest::Response, Box<dyn std::error::Error + Send + Sync>> {
        self.post_jws(url, b"", false).await
    }

    async fn create_account(
        &mut self,
        email: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        log::info!("[acme] creating account for {email}");
        let payload = serde_json::json!({
            "termsOfServiceAgreed": true,
            "contact": [format!("mailto:{email}")]
        });
        let url = self.directory.newAccount.clone();
        let resp = self
            .post_jws(
                &url,
                serde_json::to_vec(&payload)?.as_slice(),
                true,
            )
            .await?;

        let status = resp.status();
        let location = resp
            .headers()
            .get("location")
            .ok_or("missing Location header")?
            .to_str()?
            .to_string();

        if status == 200 || status == 201 {
            log::info!("[acme] account: {location}");
            Ok(location)
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(format!("account creation failed ({status}): {body}").into())
        }
    }

    async fn issue_cert(
        &mut self,
        domain: &str,
    ) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
        // Step 1: New order
        log::info!("[acme] creating order for {domain}");
        let order_payload = serde_json::json!({
            "identifiers": [{"type": "dns", "value": domain}]
        });
        let url = self.directory.newOrder.clone();
        let resp = self
            .post_jws(
                &url,
                serde_json::to_vec(&order_payload)?.as_slice(),
                false,
            )
            .await?;

        // Capture order URL from Location header before consuming response
        let order_url = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let order: serde_json::Value = resp.json().await?;
        let auth_url = order["authorizations"][0]
            .as_str()
            .ok_or("no authorizations")?
            .to_string();
        let finalize_url = order["finalize"]
            .as_str()
            .ok_or("no finalize URL")?
            .to_string();

        // Step 2: Get authorization → find dns-01 challenge
        log::info!("[acme] fetching authorization");
        let auth_resp = self.post_as_get(&auth_url).await?;
        let auth: serde_json::Value = auth_resp.json().await?;

        let challenge = auth["challenges"]
            .as_array()
            .ok_or("no challenges")?
            .iter()
            .find(|c| c["type"] == "dns-01")
            .ok_or("no dns-01 challenge")?;

        let token = challenge["token"]
            .as_str()
            .ok_or("no challenge token")?
            .to_string();
        let challenge_url = challenge["url"]
            .as_str()
            .ok_or("no challenge url")?
            .to_string();

        // Step 3: Compute DNS-01 challenge value
        let key_auth = format!("{token}.{}", self.thumbprint);
        let txt_value = b64(&Sha256::digest(key_auth.as_bytes()));
        log::info!("[acme] set TXT _acme-challenge.{domain} = {txt_value}");

        // Step 4: Set DNS record via Cloudflare
        set_cloudflare_txt(domain, &txt_value).await?;

        // Step 5: Wait for DNS propagation (Cloudflare can take 60s+)
        log::info!("[acme] waiting 30s for DNS propagation...");
        tokio::time::sleep(Duration::from_secs(30)).await;

        // Step 6: Respond to challenge
        log::info!("[acme] responding to challenge");
        let resp = self
            .post_jws(challenge_url.as_str(), b"{}", false)
            .await?;
        log::info!(
            "[acme] challenge response: {}",
            resp.status()
        );

        // Step 7: Poll order until ready
        log::info!("[acme] polling order status...");
        let poll_url = order_url.clone();
        for attempt in 0..30 {
            let resp = self.post_as_get(&poll_url).await?;
            let status: serde_json::Value = resp.json().await?;
            let state = status["status"].as_str().unwrap_or("");
            log::info!("[acme] order status: {state} (attempt {attempt})");

            match state {
                "ready" => break,
                "valid" => break,
                "invalid" => {
                    return Err(format!("order invalid: {status}").into());
                }
                _ => {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }

        // Step 8: Finalize with CSR
        log::info!("[acme] finalizing order with CSR");
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let params = rcgen::CertificateParams::new(vec![domain.to_string()])?;
        let csr = params.serialize_request(&key_pair)?;
        let csr_der = csr.der().to_vec();
        let csr_b64 = b64(&csr_der);

        let finalize_payload = serde_json::json!({ "csr": csr_b64 });
        let resp = self
            .post_jws(
                &finalize_url,
                serde_json::to_vec(&finalize_payload)?.as_slice(),
                false,
            )
            .await?;
        log::info!("[acme] finalize: {}", resp.status());

        // Step 9: Poll for certificate
        let finalize_resp: serde_json::Value = resp.json().await?;
        let cert_url = finalize_resp["certificate"]
            .as_str()
            .ok_or("no certificate URL in finalize response")?
            .to_string();

        for attempt in 0..30 {
            let resp = self.post_as_get(&cert_url).await?;
            if resp.status() == 200 {
                let cert_pem = resp.text().await?;
                log::info!("[acme] certificate issued for {domain}");

                // Generate private key PEM
                let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
                let key_pem = key_pair.serialize_pem();

                return Ok((cert_pem, key_pem));
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        Err("certificate not ready after 150s".into())
    }
}

// ── Cloudflare DNS helper ────────────────────────────────────────

async fn resolve_zone_id(
    http: &reqwest::Client,
    api_token: &str,
    domain: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let parts: Vec<&str> = domain.rsplitn(3, '.').collect();
    let root = if parts.len() >= 2 {
        format!("{}.{}", parts[1], parts[0])
    } else {
        domain.to_string()
    };

    let url = format!(
        "https://api.cloudflare.com/client/v4/zones?name={root}"
    );
    let resp = http
        .get(&url)
        .header("Authorization", format!("Bearer {api_token}"))
        .send()
        .await?;

    let data: serde_json::Value = resp.json().await?;
    let zones = data["result"].as_array().ok_or("no zones found")?;
    zones
        .first()
        .and_then(|z| z["id"].as_str())
        .map(|s| s.to_string())
        .ok_or("zone ID not found".into())
}

async fn set_cloudflare_txt(
    domain: &str,
    value: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let http = reqwest::Client::new();
    let token = &CONFIG.certd.cloudflare_api_token;
    let zone_id = resolve_zone_id(&http, token, domain).await?;

    let dns_name = format!("_acme-challenge.{domain}");
    let url = format!(
        "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    );

    // Delete existing TXT records for this name
    let list_url = format!("{url}?type=TXT&name={dns_name}");
    if let Ok(resp) = http
        .get(&list_url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
    {
        if let Ok(data) = resp.json::<serde_json::Value>().await {
            if let Some(records) = data["result"].as_array() {
                for rec in records {
                    if let Some(id) = rec["id"].as_str() {
                        let del_url = format!("{url}/{id}");
                        let _ = http
                            .delete(&del_url)
                            .header("Authorization", format!("Bearer {token}"))
                            .send()
                            .await;
                    }
                }
            }
        }
    }

    // Create new TXT record
    let body = serde_json::json!({
        "type": "TXT",
        "name": dns_name,
        "content": value,
        "ttl": 120,
    });
    let resp = http
        .post(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await?;

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("Cloudflare DNS error: {text}").into());
    }
    Ok(())
}

// ── Redis cert storage ───────────────────────────────────────────

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

// ── Main ACME loop ───────────────────────────────────────────────

pub async fn run_acme_loop(
    redis_url: &str,
    domains: &[String],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    log::info!("[certd] connecting to Let's Encrypt...");
    let mut client = AcmeClient::new(&CONFIG.certd.contact_email).await?;

    // Issue certs for all domains
    for domain in domains {
        match client.issue_cert(domain).await {
            Ok((cert_pem, key_pem)) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs();
                let cert = CertData {
                    cert_pem,
                    key_pem,
                    issued_at: now,
                    expires_at: now + 80 * 86400, // ~80 days
                };

                let mut redis = redis::Client::open(redis_url)?
                    .get_connection_manager()
                    .await?;
                store_cert(&mut redis, domain, &cert).await;

                // Notify NekoGuard via Redis Pub/Sub
                let _: () = redis::cmd("PUBLISH")
                    .arg("nekoguard:cert:update")
                    .arg(domain)
                    .query_async(&mut redis)
                    .await
                    .ok()
                    .unwrap_or_default();

                log::info!("[certd] cert issued and stored for {domain}");
            }
            Err(e) => {
                log::error!("[certd] failed to issue cert for {domain}: {e}");
            }
        }
    }

    // Renewal loop
    loop {
        tokio::time::sleep(Duration::from_secs(CONFIG.certd.renewal_interval)).await;
        log::info!("[certd] checking renewals...");
        let mut redis = redis::Client::open(redis_url)?
            .get_connection_manager()
            .await?;
        for domain in domains {
            if let Some(cert) = load_cert(&mut redis, domain).await {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs();
                if cert.expires_at > 0 && cert.expires_at < now + 30 * 86400 {
                    log::info!("[certd] renewing cert for {domain}");
                    match client.issue_cert(domain).await {
                        Ok((cert_pem, key_pem)) => {
                            let new_cert = CertData {
                                cert_pem,
                                key_pem,
                                issued_at: now,
                                expires_at: now + 80 * 86400,
                            };
                            store_cert(&mut redis, domain, &new_cert).await;
                            let _: () = redis::cmd("PUBLISH")
                                .arg("nekoguard:cert:update")
                                .arg(domain)
                                .query_async(&mut redis)
                                .await
                                .ok()
                                .unwrap_or_default();
                            log::info!("[certd] cert renewed for {domain}");
                        }
                        Err(e) => {
                            log::error!("[certd] renewal failed for {domain}: {e}");
                        }
                    }
                }
            }
        }
    }
}
