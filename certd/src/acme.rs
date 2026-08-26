use std::path::PathBuf;

use crate::config::CONFIG;
use futures::StreamExt;
use rustls_acme::{caches::DirCache, AcmeConfig};
use serde::{Deserialize, Serialize};

const CERT_PREFIX: &str = "nekoguard:cert:";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertData {
    pub cert_pem: String,
    pub key_pem: String,
}

#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct CertStatus {
    pub domain: String,
    pub has_cert: bool,
}

#[allow(dead_code)]
pub struct AcmeManager {
    redis_url: String,
}

impl AcmeManager {
    pub async fn new() -> Self {
        // Load any existing certs from Redis into DirCache
        let mut redis = redis::Client::open(CONFIG.redis_url.as_str())
            .expect("redis connect")
            .get_connection_manager()
            .await
            .expect("redis conn manager");

        let cache_dir = PathBuf::from(&CONFIG.cache_dir);
        std::fs::create_dir_all(&cache_dir).ok();

        for domain in &CONFIG.domains {
            if let Some(cert) = Self::load_cert_from_redis(&mut redis, domain).await {
                let cert_path = cache_dir.join(format!("{domain}.crt"));
                let key_path = cache_dir.join(format!("{domain}.key"));
                let _ = std::fs::write(&cert_path, &cert.cert_pem);
                let _ = std::fs::write(&key_path, &cert.key_pem);
                log::info!("[certd] loaded cert from Redis: {domain}");
            }
        }

        log::info!("[certd] manager ready for {} domains", CONFIG.domains.len());
        Self {
            redis_url: CONFIG.redis_url.clone(),
        }
    }

    /// Run the ACME event loop. This is spawned as a background task.
    /// It drives rustls-acme's internal state machine which handles
    /// issuance, renewal, and challenge responses automatically.
    pub async fn run_event_loop(&self) {
        let cache_dir = PathBuf::from(&CONFIG.cache_dir);
        std::fs::create_dir_all(&cache_dir).ok();

        let mut acme_state = AcmeConfig::new(CONFIG.domains.clone())
            .contact(CONFIG.contacts.clone())
            .cache(DirCache::new(cache_dir.clone()))
            .directory_lets_encrypt(!CONFIG.staging)
            .state();

        log::info!("[certd] ACME event loop started for {} domains", CONFIG.domains.len());

        let mut redis = redis::Client::open(self.redis_url.as_str())
            .expect("redis connect")
            .get_connection_manager()
            .await
            .expect("redis conn manager");

        loop {
            match acme_state.next().await {
                Some(Ok(ok)) => {
                    log::info!("[certd] acme: {ok:?}");
                    // Store cert in Redis after issuance/renewal
                    for domain in &CONFIG.domains {
                        let cert_path = cache_dir.join(format!("{domain}.crt"));
                        let key_path = cache_dir.join(format!("{domain}.key"));
                        if cert_path.exists() && key_path.exists() {
                            if let (Ok(cert_pem), Ok(key_pem)) = (
                                std::fs::read_to_string(&cert_path),
                                std::fs::read_to_string(&key_path),
                            ) {
                                let cert = CertData { cert_pem, key_pem };
                                Self::store_cert_to_redis(&mut redis, domain, &cert).await;
                            }
                        }
                    }
                }
                Some(Err(err)) => log::error!("[certd] acme error: {err:?}"),
                None => {
                    log::info!("[certd] acme stream ended");
                    break;
                }
            }
        }
    }

    pub async fn get_cert(&self, domain: &str) -> Option<CertData> {
        let mut redis = redis::Client::open(self.redis_url.as_str())
            .ok()?
            .get_connection_manager()
            .await
            .ok()?;
        Self::load_cert_from_redis(&mut redis, domain).await
    }

    pub async fn get_all_certs(&self) -> Vec<(String, CertData)> {
        let mut redis = match redis::Client::open(self.redis_url.as_str()) {
            Ok(c) => match c.get_connection_manager().await {
                Ok(r) => r,
                Err(_) => return vec![],
            },
            Err(_) => return vec![],
        };

        let mut result = Vec::new();
        for domain in &CONFIG.domains {
            if let Some(cert) = Self::load_cert_from_redis(&mut redis, domain).await {
                result.push((domain.clone(), cert));
            }
        }
        result
    }

    async fn store_cert_to_redis(
        redis: &mut redis::aio::ConnectionManager,
        domain: &str,
        cert: &CertData,
    ) {
        let key = format!("{CERT_PREFIX}{domain}");
        let data = serde_json::to_vec(cert).unwrap_or_default();
        let _: () = redis::cmd("SET")
            .arg(&key)
            .arg(&data)
            .query_async(&mut *redis)
            .await
            .ok()
            .unwrap_or_default();
        log::info!("[certd] cert stored in Redis: {domain}");
    }

    async fn load_cert_from_redis(
        redis: &mut redis::aio::ConnectionManager,
        domain: &str,
    ) -> Option<CertData> {
        let key = format!("{CERT_PREFIX}{domain}");
        let data: Result<Vec<u8>, _> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut *redis)
            .await;
        data.ok().and_then(|d| serde_json::from_slice(&d).ok())
    }
}
