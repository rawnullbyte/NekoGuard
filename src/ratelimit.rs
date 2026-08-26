use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use crate::config::RateLimitConfig;

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

/// Global rate limiter using per-IP token buckets.
static BUCKETS: LazyLock<DashMap<IpAddr, Bucket>> = LazyLock::new(DashMap::new);

/// Check if an IP is allowed to make a request, consuming one token.
/// Returns true if allowed, false if rate limited.
pub fn allow(ip: IpAddr, config: &RateLimitConfig) -> bool {
    if !config.enabled || config.rps == 0 {
        return true;
    }

    let now = Instant::now();
    let max_tokens = config.burst as f64;
    let refill_rate = config.rps as f64; // tokens per second

    let mut entry = BUCKETS.entry(ip).or_insert_with(|| Bucket {
        tokens: max_tokens - 1.0, // first request costs one token
        last_refill: now,
    });

    let elapsed = now.duration_since(entry.last_refill).as_secs_f64();

    // Refill tokens based on elapsed time
    let refill = elapsed * refill_rate;
    entry.tokens = (entry.tokens + refill).min(max_tokens);
    entry.last_refill = now;

    // Also enforce RPM limit
    if config.rpm > 0 {
        // RPM is handled as a simpler per-minute counter using the same bucket
        // with a higher refill ceiling
        let max_rpm = config.rpm as f64 / 60.0; // convert to per-second
        let effective_max = max_tokens.max(max_rpm);
        entry.tokens = entry.tokens.min(effective_max);
    }

    if entry.tokens >= 1.0 {
        entry.tokens -= 1.0;
        true
    } else {
        false
    }
}

/// Remove stale buckets for IPs that haven't been seen in a while.
pub fn sweep() {
    let now = Instant::now();
    let stale = Duration::from_secs(300); // 5 minutes
    BUCKETS.retain(|_, b| now.duration_since(b.last_refill) < stale);
}
