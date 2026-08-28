use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SECRET_KEY: &str = "nekoguard:secret";
const SECRET_LEN: usize = 32;
const NONCE_LEN: usize = 12;

/// A validated session from a sealed cookie.
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

/// Payload sealed inside the cookie. The client never sees these fields.
#[derive(Serialize, Deserialize)]
struct SessionPayload {
    ip: String,
    exp: u64,
}

/// Manages sealed session cookies. The client sees one opaque base64url
/// blob; only the server (holding the Redis AES-256 key) can read the
/// IP and expiry inside. No field separators needed — no dot/colon bugs.
#[allow(dead_code)]
pub struct SessionManager {
    key: [u8; 32],
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
            key: secret,
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
            key: secret,
            cookie_name: cookie_name.to_string(),
            ttl,
        }
    }

    /// Get or create the 256-bit sealing key in Redis.
    async fn get_or_create_secret(conn: &mut redis::aio::MultiplexedConnection) -> [u8; 32] {
        use rand::RngCore;
        let existing: Result<Vec<u8>, _> = redis::cmd("GET")
            .arg(SECRET_KEY)
            .query_async(conn)
            .await;

        let secret: Vec<u8> = match existing {
            Ok(secret) if !secret.is_empty() => {
                log::debug!("[session] loaded sealing secret from Redis");
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

                log::info!("[session] sealing secret ready");
                final_secret
            }
        };

        let mut key = [0u8; 32];
        let n = secret.len().min(32);
        key[..n].copy_from_slice(&secret[..n]);
        key
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new_from_slice(&self.key).expect("AES-256 accepts 32-byte key")
    }

    /// Create a sealed session cookie for the given IP.
    pub fn create_cookie(&self, ip: IpAddr) -> String {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + self.ttl.as_secs();

        let payload = SessionPayload {
            ip: ip.to_string(),
            exp,
        };
        let plaintext = serde_json::to_vec(&payload).expect("serialize session");

        // Random 12-byte nonce prepended to ciphertext
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let ciphertext = self.cipher()
            .encrypt(&nonce, plaintext.as_ref())
            .expect("encrypt session");

        // blob = nonce || ciphertext (ciphertext includes the GCM tag)
        let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);

        URL_SAFE_NO_PAD.encode(&blob)
    }

    /// Verify a session cookie. Returns a Session on success.
    pub fn verify_cookie(&self, cookie_value: &str, peer_ip: IpAddr) -> Result<Session, SessionError> {
        let blob = URL_SAFE_NO_PAD.decode(cookie_value).map_err(|_| SessionError::Malformed)?;
        if blob.len() <= NONCE_LEN {
            return Err(SessionError::Malformed);
        }

        let nonce_bytes: [u8; NONCE_LEN] = blob[..NONCE_LEN]
            .try_into()
            .map_err(|_| SessionError::Malformed)?;
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = &blob[NONCE_LEN..];

        let plaintext = self.cipher()
            .decrypt(&nonce, ciphertext)
            .map_err(|_| SessionError::InvalidSignature)?;

        let payload: SessionPayload =
            serde_json::from_slice(&plaintext).map_err(|_| SessionError::Malformed)?;

        let cookie_ip: IpAddr = payload.ip.parse().map_err(|_| SessionError::Malformed)?;
        if cookie_ip != peer_ip {
            return Err(SessionError::IpMismatch);
        }

        if SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() > payload.exp {
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