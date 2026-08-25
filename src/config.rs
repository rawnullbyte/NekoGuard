use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::sync::LazyLock;

const DEFAULT_PORT: u16 = 443;
const DEFAULT_CACHE_DIR: &str = "./acme-cache";
const CONFIG_PATH_ENV: &str = "NG_CONFIG";
const DEFAULT_CONFIG_PATH: &str = "nekoguard.toml";

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Domains to obtain ACME certificates for. Certificates are only ever
    /// requested for names in this fixed list.
    #[serde(default)]
    pub domains: Vec<String>,

    /// Contact addresses for the ACME account (email addresses; the
    /// `mailto:` prefix is added automatically if missing).
    #[serde(default)]
    pub contact: Vec<String>,

    /// Directory where issued certificates and the ACME account key are
    /// cached so they survive restarts and renew in place.
    #[serde(default = "default_cache_dir")]
    pub cache_dir: String,

    /// Use the Let's Encrypt staging environment. Set true while testing to
    /// avoid burning production rate limits; false issues real certificates.
    #[serde(default)]
    pub staging: bool,

    /// TLS listen port. Defaults to 443.
    #[serde(default = "default_port")]
    pub port: u16,

    /// Fallback Host -> upstream URL map, used when a request arrives without
    /// an `X-Upstream` header (i.e. NekoGuard is the direct TLS edge rather
    /// than sitting behind an nginx that injects the header).
    #[serde(default)]
    pub upstreams: HashMap<String, String>,
}

fn default_cache_dir() -> String {
    DEFAULT_CACHE_DIR.to_string()
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

impl Config {
    /// Normalized contact list with `mailto:` prefixes for rustls-acme.
    pub fn acme_contacts(&self) -> Vec<String> {
        self.contact
            .iter()
            .map(|c| {
                if c.contains(':') {
                    c.clone()
                } else {
                    format!("mailto:{c}")
                }
            })
            .collect()
    }

    /// Look up the configured upstream for a given request Host header.
    /// The host may include a port, which is stripped before matching.
    pub fn upstream_for_host(&self, host: &str) -> Option<&str> {
        let bare = host.split(':').next().unwrap_or(host);
        self.upstreams
            .get(bare)
            .or_else(|| self.upstreams.get(host))
            .map(String::as_str)
    }
}

pub static CONFIG: LazyLock<Config> = LazyLock::new(|| {
    let path = std::env::var(CONFIG_PATH_ENV).unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string());
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read config '{path}': {e}"));
    let cfg: Config =
        toml::from_str(&raw).unwrap_or_else(|e| panic!("failed to parse config '{path}': {e}"));
    if cfg.domains.is_empty() {
        panic!("config '{path}': at least one domain is required under `domains`");
    }
    cfg
});
