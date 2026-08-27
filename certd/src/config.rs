use serde::Deserialize;
use std::sync::LazyLock;

const CONFIG_PATH_ENV: &str = "NG_CONFIG";
const DEFAULT_CONFIG_PATH: &str = "nekoguard.toml";

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Shared fields (from root of nekoguard.toml)
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default = "default_redis_url")]
    pub redis_url: String,
    #[serde(default = "default_contact_email")]
    pub contact_email: String,
    #[serde(default)]
    pub cloudflare_api_token: String,
    #[serde(default)]
    pub cloudflare_zone_id: String,

    /// Certd-specific fields (from [certd] section)
    #[serde(default, rename = "certd")]
    pub certd: CertdConfig,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct CertdConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_renewal_interval")]
    pub renewal_interval: u64,
}

fn default_port() -> u16 { 8443 }
fn default_redis_url() -> String { "redis://127.0.0.1:6379".to_string() }
fn default_contact_email() -> String { "you@example.com".to_string() }
fn default_renewal_interval() -> u64 { 86400 }

pub static CONFIG: LazyLock<Config> = LazyLock::new(|| {
    let path = std::env::var(CONFIG_PATH_ENV).unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string());
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read config '{path}': {e}"));
    toml::from_str(&raw)
        .unwrap_or_else(|e| panic!("failed to parse config '{path}': {e}"))
});
