use serde::Deserialize;
use std::fs;
use std::sync::LazyLock;

const DEFAULT_PORT: u16 = 443;
const DEFAULT_CACHE_DIR: &str = "./acme-cache";
const CONFIG_PATH_ENV: &str = "NG_CONFIG";
const DEFAULT_CONFIG_PATH: &str = "nekoguard.toml";

/// One protected site: gets a certificate issued, answers its SNI handshakes,
/// and routes its authenticated traffic to `upstream`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Site {
    pub domain: String,
    pub upstream: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub sites: Vec<Site>,

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
}

fn default_cache_dir() -> String {
    DEFAULT_CACHE_DIR.to_string()
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

/// Lowercase, strip any :port suffix and trailing dot so Host/SNI values
/// compare consistently against configured domains.
fn normalize_host(host: &str) -> String {
    host.split(':')
        .next()
        .unwrap_or(host)
        .trim_end_matches('.')
        .to_ascii_lowercase()
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

    /// Find the site a request Host header belongs to.
    pub fn site_for_host(&self, host: &str) -> Option<&Site> {
        let want = normalize_host(host);
        self.sites.iter().find(|s| s.domain == want)
    }

    /// Whether a TLS handshake's SNI names a configured site. Unknown names
    /// are refused at the handshake, mirroring nginx's unhandled-server_name
    /// drop.
    pub fn is_known_domain(&self, name: &str) -> bool {
        let want = normalize_host(name);
        self.sites.iter().any(|s| s.domain == want)
    }
}

pub static CONFIG: LazyLock<Config> = LazyLock::new(|| {
    let path = std::env::var(CONFIG_PATH_ENV).unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string());
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read config '{path}': {e}"));
    let mut cfg: Config =
        toml::from_str(&raw).unwrap_or_else(|e| panic!("failed to parse config '{path}': {e}"));
    if cfg.sites.is_empty() {
        panic!("config '{path}': at least one [[sites]] entry is required");
    }
    // Normalize domains once at load so runtime comparisons are exact.
    for site in &mut cfg.sites {
        site.domain = normalize_host(&site.domain);
    }
    cfg
});
