use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use rand::Rng;
use tokio::sync::Mutex;

const LOCK_KEY: &str = "nekoguard:acme:lock";
const CERT_PREFIX: &str = "nekoguard:cert:";
#[allow(dead_code)]
const CHALLENGE_PREFIX: &str = "nekoguard:acme:challenge:";
const LOCK_TTL: u64 = 120; // seconds
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const WAIT_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes

/// Coordinates ACME certificate management across replicas via Redis.
pub struct AcmeSync {
    conn: Arc<Mutex<redis::aio::ConnectionManager>>,
    instance_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertData {
    pub cert_pem: String,
    pub key_pem: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl AcmeSync {
    pub fn new(conn: Arc<Mutex<redis::aio::ConnectionManager>>) -> Self {
        let instance_id: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(12)
            .map(char::from)
            .collect();
        Self { conn, instance_id }
    }

    /// Try to acquire the ACME lock. Returns true if this instance won.
    pub async fn acquire_lock(&self) -> bool {
        let mut conn = self.conn.lock().await;
        let lock_value = format!("{}.{}", self.instance_id, LOCK_TTL);
        let result: Result<String, _> = redis::cmd("SET")
            .arg(LOCK_KEY)
            .arg(&lock_value)
            .arg("NX")
            .arg("EX")
            .arg(LOCK_TTL)
            .query_async(&mut *conn)
            .await;
        result.is_ok() && result.unwrap() == "OK"
    }

    /// Release the ACME lock (only if we hold it).
    #[allow(dead_code)]
    pub async fn release_lock(&self) {
        let mut conn = self.conn.lock().await;
        let current: Result<String, _> = redis::cmd("GET")
            .arg(LOCK_KEY)
            .query_async(&mut *conn)
            .await;
        if let Ok(val) = current {
            if val.starts_with(&self.instance_id) {
                let _: () = redis::cmd("DEL")
                    .arg(LOCK_KEY)
                    .query_async(&mut *conn)
                    .await
                    .ok()
                    .unwrap_or_default();
            }
        }
    }

    /// Wait for a certificate to appear in Redis. Returns None on timeout.
    pub async fn wait_for_cert(&self, domain: &str) -> Option<CertData> {
        let deadline = tokio::time::Instant::now() + WAIT_TIMEOUT;
        while tokio::time::Instant::now() < deadline {
            if let Some(cert) = self.load_cert(domain).await {
                return Some(cert);
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
        log::warn!("[acme] timed out waiting for cert for {domain}");
        None
    }

    /// Store a certificate in Redis.
    pub async fn store_cert(&self, domain: &str, cert: &CertData) {
        let key = format!("{CERT_PREFIX}{domain}");
        let data = serde_json::to_vec(cert).unwrap_or_default();
        let _: () = redis::cmd("SET")
            .arg(&key)
            .arg(&data)
            .query_async(&mut *self.conn.lock().await)
            .await
            .ok()
            .unwrap_or_default();
        log::info!("[acme] cert stored in Redis for {domain}");
    }

    /// Load a certificate from Redis.
    pub async fn load_cert(&self, domain: &str) -> Option<CertData> {
        let key = format!("{CERT_PREFIX}{domain}");
        let data: Result<Vec<u8>, _> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut *self.conn.lock().await)
            .await;
        data.ok().and_then(|d| serde_json::from_slice(&d).ok())
    }

    /// Store an ACME challenge response in Redis for other replicas to use.
    #[allow(dead_code)]
    pub async fn store_challenge(&self, token: &str, response: &str) {
        let key = format!("{CHALLENGE_PREFIX}{token}");
        let _: () = redis::cmd("SETEX")
            .arg(&key)
            .arg(600) // 10 minutes
            .arg(response)
            .query_async(&mut *self.conn.lock().await)
            .await
            .ok()
            .unwrap_or_default();
    }

    /// Retrieve an ACME challenge response from Redis.
    #[allow(dead_code)]
    pub async fn get_challenge(&self, token: &str) -> Option<String> {
        let key = format!("{CHALLENGE_PREFIX}{token}");
        let data: Result<String, _> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut *self.conn.lock().await)
            .await;
        data.ok()
    }
}
