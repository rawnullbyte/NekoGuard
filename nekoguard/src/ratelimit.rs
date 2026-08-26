use crate::config::RateLimitConfig;

const KEY_PREFIX: &str = "nekoguard:rl:";

/// Check if an IP is allowed to make a request, consuming one token.
/// Uses Redis for state so it works across replicas.
pub async fn allow(
    conn: &mut redis::aio::ConnectionManager,
    ip: std::net::IpAddr,
    config: &RateLimitConfig,
) -> bool {
    if !config.enabled || config.rps == 0 {
        return true;
    }

    let key = format!("{}{}", KEY_PREFIX, ip);
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Read current bucket state
    let bucket: Option<(u64, u64)> = redis::cmd("HMGET")
        .arg(&key)
        .arg("tokens")
        .arg("last_refill_ms")
        .query_async(conn)
        .await
        .ok();

    let (tokens, last_refill_ms) = bucket.unwrap_or((config.burst as u64, now_ms));

    // Refill tokens based on elapsed time
    let elapsed_ms = now_ms.saturating_sub(last_refill_ms);
    let refill = (elapsed_ms as f64 / 1000.0) * config.rps as f64;
    let new_tokens = ((tokens as f64 + refill).min(config.burst as f64)).floor() as u64;

    // Also enforce RPM limit
    let max_rpm_tokens = if config.rpm > 0 {
        config.rpm as u64
    } else {
        u64::MAX
    };

    if new_tokens >= 1 && new_tokens <= max_rpm_tokens {
        // Consume one token
        let new_tokens = new_tokens - 1;
        let _: () = redis::cmd("HMSET")
            .arg(&key)
            .arg("tokens")
            .arg(new_tokens)
            .arg("last_refill_ms")
            .arg(now_ms)
            .query_async(conn)
            .await
            .ok()
            .unwrap_or_default();
        // Set expiry so keys don't grow forever (1 hour TTL)
        let _: () = redis::cmd("EXPIRE")
            .arg(&key)
            .arg(3600)
            .query_async(conn)
            .await
            .ok()
            .unwrap_or_default();
        true
    } else {
        // Rate limited — still update last_refill_ms so tokens refill correctly
        let _: () = redis::cmd("HMSET")
            .arg(&key)
            .arg("tokens")
            .arg(new_tokens.min(max_rpm_tokens))
            .arg("last_refill_ms")
            .arg(now_ms)
            .query_async(conn)
            .await
            .ok()
            .unwrap_or_default();
        let _: () = redis::cmd("EXPIRE")
            .arg(&key)
            .arg(3600)
            .query_async(conn)
            .await
            .ok()
            .unwrap_or_default();
        false
    }
}
