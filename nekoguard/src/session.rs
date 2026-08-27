use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SECRET_KEY: &str = "nekoguard:secret";
const SECRET_LEN: usize = 32;

/// A validated session from a signed cookie.
#[derive(Debug, Clone)]
pub struct Session {
    #[allow(dead_code)]
    pub ip: IpAddr,
    #[allow(dead_code)]
    pub expiry: Instant,
    #[allow(dead_code)]
    pub cookie: String,
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum SessionError {
    Missing,
    Malformed,
    InvalidSignature,
    Expired,
    IpMismatch,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "no session cookie"),
            Self::Malformed => write!(f, "malformed session cookie"),
            Self::InvalidSignature => write!(f, "invalid session signature"),
            Self::Expired => write!(f, "session expired"),
            Self::IpMismatch => write!(f, "session IP mismatch"),
        }
    }
}

/// Manages signed session cookies using SHA-256 with HMAC-like keying.
/// The signing secret is stored in Redis for cross-replica sharing.
#[allow(dead_code)]
pub struct SessionManager {
    secret: Vec<u8>,
    cookie_name: String,
    ttl: Duration,
}

impl SessionManager {
    /// Create a new SessionManager. The secret is loaded from Redis.
    /// If Redis doesn't have a secret yet, one is generated and stored.
    #[allow(dead_code)]
    pub async fn new(redis: &redis::Client) -> Self {
        let mut conn = redis.get_multiplexed_async_connection().await.expect("redis connect");
        let secret = Self::get_or_create_secret(&mut conn).await;
        Self {
            secret,
            cookie_name: "nekoguard_session".to_string(),
            ttl: Duration::from_secs(1800),
        }
    }

    /// Create a new SessionManager with custom cookie name and TTL.
    pub async fn new_with_config(
        redis: &redis::Client,
        cookie_name: &str,
        ttl: Duration,
    ) -> Self {
        let mut conn = redis.get_multiplexed_async_connection().await.expect("redis connect");
        let secret = Self::get_or_create_secret(&mut conn).await;
        Self {
            secret,
            cookie_name: cookie_name.to_string(),
            ttl,
        }
    }

    /// Get or create the signing secret in Redis.
    async fn get_or_create_secret(conn: &mut redis::aio::MultiplexedConnection) -> Vec<u8> {
        use rand::RngCore;
        let existing: Result<Vec<u8>, _> = redis::cmd("GET")
            .arg(SECRET_KEY)
            .query_async(conn)
            .await;

        match existing {
            Ok(secret) if !secret.is_empty() => {
                log::debug!("[session] loaded signing secret from Redis");
                secret
            }
            _ => {
                let mut secret = vec![0u8; SECRET_LEN];
                rand::thread_rng().fill_bytes(&mut secret);
                let _: () = redis::cmd("SET")
                    .arg(SECRET_KEY)
                    .arg(&secret)
                    .arg("NX")
                    .query_async(conn)
                    .await
                    .expect("redis SET secret");

                // Re-read to handle race where another worker won the NX
                let final_secret: Vec<u8> = redis::cmd("GET")
                    .arg(SECRET_KEY)
                    .query_async(conn)
                    .await
                    .expect("redis GET secret");

                log::info!("[session] signing secret ready");
                final_secret
            }
        }
    }

    /// Sign a message using HMAC-SHA256. Prevents length extension attacks
    /// that plain SHA256(secret || message) is vulnerable to.
    fn sign(&self, message: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret)
            .expect("HMAC accepts any key length");
        mac.update(message);
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    /// Verify an HMAC signature against a message.
    fn verify(&self, message: &[u8], sig_b64: &str) -> bool {
        let sig_bytes = match URL_SAFE_NO_PAD.decode(sig_b64) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret)
            .expect("HMAC accepts any key length");
        mac.update(message);
        mac.verify_slice(&sig_bytes).is_ok()
    }

    /// Create a signed session cookie for the given IP.
    pub fn create_cookie(&self, ip: IpAddr) -> String {
        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + self.ttl.as_secs();

        let nonce: u64 = rand::random();
        let ip_str = ip.to_string();
        let expiry_hex = format!("{:x}", expiry);
        let nonce_hex = format!("{:x}", nonce);

        let payload = format!("{ip_str}.{expiry_hex}.{nonce_hex}");
        let sig = self.sign(payload.as_bytes());
        format!("{payload}.{sig}")
    }

    /// Verify a session cookie. Returns a Session on success.
    pub fn verify_cookie(&self, cookie_value: &str, peer_ip: IpAddr) -> Result<Session, SessionError> {
        let parts: Vec<&str> = cookie_value.split('.').collect();
        if parts.len() != 4 {
            return Err(SessionError::Malformed);
        }

        let ip_str = parts[0];
        let expiry_hex = parts[1];
        let nonce_hex = parts[2];
        let sig_b64 = parts[3];

        // Verify signature
        let payload = format!("{ip_str}.{expiry_hex}.{nonce_hex}");
        if !self.verify(payload.as_bytes(), sig_b64) {
            return Err(SessionError::InvalidSignature);
        }

        // Check IP
        let cookie_ip: IpAddr = ip_str.parse().map_err(|_| SessionError::Malformed)?;
        if cookie_ip != peer_ip {
            return Err(SessionError::IpMismatch);
        }

        // Check expiry
        let expiry_secs: u64 = u64::from_str_radix(expiry_hex, 16).map_err(|_| SessionError::Malformed)?;
        let expiry_time = UNIX_EPOCH + Duration::from_secs(expiry_secs);
        if SystemTime::now() > expiry_time {
            return Err(SessionError::Expired);
        }

        Ok(Session {
            ip: cookie_ip,
            expiry: Instant::now() + self.ttl,
            cookie: cookie_value.to_string(),
        })
    }

    pub fn cookie_name(&self) -> &str {
        &self.cookie_name
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}
