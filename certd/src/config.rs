use serde::Deserialize;
use std::sync::LazyLock;

const CONFIG_PATH_ENV: &str = "NG_CERTD_CONFIG";
const DEFAULT_CONFIG_PATH: &str = "certd.toml";

#[derive(Debug, Deserialize)]
pub struct Config {
    pub domains: Vec<String>,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_redis_url")]
    pub redis_url: String,
    /// ACME contact email for Let's Encrypt account.
    pub contact_email: String,
    /// Cloudflare API token for DNS-01 challenges.
    pub cloudflare_api_token: String,
    /// Cloudflare Zone ID for the domain.
    pub cloudflare_zone_id: String,
    /// Renewal interval in seconds (default: 24h).
    #[serde(default = "default_renewal_interval")]
    pub renewal_interval: u64,
}

fn default_port() -> u16 { 8443 }
fn default_redis_url() -> String { "redis://127.0.0.1:6379".to_string() }
fn default_certbot() -> String { "certbot".to_string() }
fn default_le_dir() -> String { "/etc/letsencrypt".to_string() }
fn default_renewal_interval() -> u64 { 86400 }

pub static CONFIG: LazyLock<Config> = LazyLock::new(|| {
    let path = std::env::var(CONFIG_PATH_ENV).unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string());
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read config '{path}': {e}"));
    toml::from_str(&raw)
        .unwrap_or_else(|e| panic!("failed to parse config '{path}': {e}"))
});
