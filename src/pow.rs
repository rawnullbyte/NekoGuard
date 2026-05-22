use dashmap::DashMap;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

pub const DIFFICULTY: u32 = 14;

static MAP: LazyLock<DashMap<String, Instant>> = LazyLock::new(DashMap::new);

fn meets_target(hash: &[u8; 32], bits: u32) -> bool {
    for i in 0..bits as usize {
        if (hash[i / 8] >> (7 - (i % 8) as u32)) & 1 != 0 {
            return false;
        }
    }
    true
}

pub fn new_challenge(ttl: Duration) -> String {
    let bytes: [u8; 16] = rand::thread_rng().gen();
    let c = hex::encode(bytes);
    MAP.insert(c.clone(), Instant::now() + ttl);
    c
}

pub fn check_pow(challenge: &str, nonce: &str) -> bool {
    let (_, expiry) = match MAP.remove(challenge) {
        Some(e) => e,
        None => return false,
    };
    if Instant::now() > expiry {
        return false;
    }
    let mut h = Sha256::new();
    h.update(challenge.as_bytes());
    h.update(nonce.as_bytes());
    let hash: [u8; 32] = h.finalize().into();
    meets_target(&hash, DIFFICULTY)
}

pub fn sweep() {
    let now = Instant::now();
    MAP.retain(|_, exp| now < *exp);
}
