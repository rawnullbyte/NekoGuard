use serde::Deserialize;
use std::sync::LazyLock;

const CONFIG_PATH_ENV: &str = "NG_CERTD_CONFIG";
const DEFAULT_CONFIG_PATH: &str = "certd.toml";

#[derive(Debug, Deserialize)]
pub struct Config {
    pub domains: Vec<String>,
    pub contacts: Vec<String>,
    #[serde(default = "default_cache_dir")]
    pub cache_dir: String,
    #[serde(default)]
    pub staging: bool,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_redis_url")]
    pub redis_url: String,
}

fn default_cache_dir() -> String { "./acme-cache".to_string() }
fn default_port() -> u16 { 8443 }
fn default_redis_url() -> String { "redis://127.0.0.1:6379".to_string() }

pub static CONFIG: LazyLock<Config> = LazyLock::new(|| {
    let path = std::env::var(CONFIG_PATH_ENV).unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string());
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read config '{path}': {e}"));
    toml::from_str(&raw)
        .unwrap_or_else(|e| panic!("failed to parse config '{path}': {e}"))
});
