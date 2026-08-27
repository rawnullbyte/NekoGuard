use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;
use std::sync::LazyLock;

const DEFAULT_PORT: u16 = 443;
const CONFIG_PATH_ENV: &str = "NG_CONFIG";
const DEFAULT_CONFIG_PATH: &str = "nekoguard.toml";

/// One protected site: gets a certificate issued, answers its SNI handshakes,
/// and routes its authenticated traffic to `upstream`.
#[derive(Debug)]
pub struct Site {
    pub domain: String,
    pub upstream: String,

    /// Request paths matching any of these (against the full path,
    /// including the leading `/`) are proxied WITHOUT the PoW challenge —
    /// for APIs and other machine-facing routes. Empty = protect everything.
    pub bypass: Vec<regex::Regex>,

    /// Effective rate limit for this site (global defaults + per-site overrides).
    pub rate_limit: RateLimitConfig,
}

/// On-disk shape of a `[[sites]]` block: the parent domain plus optional
/// nested subdomains.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SiteToml {
    domain: String,

    /// Empty or omitted = the site is skipped entirely: no certificate is
    /// requested and SNI handshakes for it are refused. Useful for domains
    /// whose DNS doesn't point at NekoGuard yet.
    #[serde(default)]
    upstream: String,

    /// Regexes matched against the request path; matching requests skip the
    /// PoW challenge. `[".*"]` disables protection for this site entirely.
    #[serde(default)]
    bypass: Vec<String>,

    /// Per-site rate limit overrides (inherits global defaults for unset fields).
    #[serde(default)]
    rate_limit: Option<RateLimitConfig>,

    /// Subdomains of `domain`. Each expands to `<name>.<domain>`; a sub
    /// without its own upstream inherits the parent's.
    #[serde(default)]
    sub: Vec<SubSiteToml>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubSiteToml {
    /// Label(s) prepended to the parent domain, e.g. `nekobox` under
    /// `root-workspace.net` serves `nekobox.root-workspace.net`.
    name: String,

    /// Upstream for this subdomain. Defaults to the parent's upstream so
    /// aliases like `www` need no extra configuration.
    #[serde(default)]
    upstream: Option<String>,

    /// Bypass regexes for this subdomain; replaces the parent list when set.
    #[serde(default)]
    bypass: Option<Vec<String>>,

    /// Per-site rate limit overrides; inherits parent if not set.
    #[serde(default)]
    rate_limit: Option<RateLimitConfig>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    /// Minimum log level: error, warn, info, debug. Default: info.
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Optional log file path. Omit for stdout-only.
    #[serde(default)]
    pub file: Option<String>,

    /// Truncate the log file when it exceeds this size in bytes.
    /// 0 = never truncate. Default: 10MB.
    #[serde(default = "default_max_size")]
    pub max_size: u64,

    /// Log each HTTP request (method, path, status, upstream, duration).
    #[serde(default = "default_true")]
    #[allow(dead_code)]
    pub requests: bool,
}

fn default_log_level() -> String { "info".to_string() }
fn default_max_size() -> u64 { 10 * 1024 * 1024 }
fn default_true() -> bool { true }

/// Session cookie configuration.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SessionConfig {
    /// Cookie name. Default: "nekoguard_session".
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,

    /// Session duration in seconds. Default: 1800 (30 min).
    #[serde(default = "default_session_ttl")]
    pub ttl: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self { cookie_name: default_cookie_name(), ttl: default_session_ttl() }
    }
}

fn default_cookie_name() -> String { "nekoguard_session".to_string() }
fn default_session_ttl() -> u64 { 1800 }

/// Rate limit configuration. Can be set globally and overridden per-site.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Enable rate limiting. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Max requests per second (0 = unlimited). Default: 10.
    #[serde(default = "default_rps")]
    pub rps: u32,

    /// Max requests per minute (0 = unlimited). Default: 600.
    #[serde(default = "default_rpm")]
    pub rpm: u32,

    /// Burst capacity (tokens above the rps rate). Default: 20.
    #[serde(default = "default_burst")]
    pub burst: u32,
}

fn default_rps() -> u32 { 10 }
fn default_rpm() -> u32 { 600 }
fn default_burst() -> u32 { 20 }

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self { enabled: false, rps: default_rps(), rpm: default_rpm(), burst: default_burst() }
    }
}

#[derive(Debug, Deserialize)]
struct ConfigToml {
    #[serde(default)]
    sites: Vec<SiteToml>,

    #[serde(default)]
    redis: RedisConfig,

    #[serde(default)]
    rate_limit: RateLimitConfig,

    #[serde(default)]
    log: LogConfig,

    #[serde(default)]
    whitelist: Vec<String>,

    #[serde(default)]
    catchall: Option<CatchallConfig>,

    #[serde(default)]
    nekoguard: NekoguardSub,

    #[serde(default)]
    certd: CertdSub,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct NekoguardSub {
    #[serde(default = "default_port")]
    port: u16,
    #[serde(default)]
    port_http: Option<u16>,
    #[serde(default)]
    whitelist: Vec<String>,
    #[serde(default)]
    session: SessionConfig,
    #[serde(default)]
    catchall: Option<CatchallConfig>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct CertdSub {
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    renewal_interval: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CatchallConfig {
    pub upstream: String,
    #[serde(default)]
    pub bypass: Vec<String>,
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
}

/// Runtime config: the on-disk shape with `[[sites.sub]]` entries expanded
/// into a flat list of (domain, upstream) pairs.
#[derive(Debug)]
pub struct Config {
    pub sites: Vec<Site>,
    pub rate_limit: RateLimitConfig,
    pub log: LogConfig,
    pub whitelist: Vec<IpAddr>,
    pub catchall: Option<CatchallConfig>,
    pub catchall_bypass: Vec<regex::Regex>,
    pub port: u16,
    pub port_http: Option<u16>,
    pub session: SessionConfig,
    pub redis: RedisConfig,
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

fn default_redis_url() -> String {
    "redis://127.0.0.1:6379".to_string()
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct RedisConfig {
    #[serde(default = "default_redis_url")]
    pub url: String,
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

/// Expand the on-disk config into runtime form: flatten every `[[sites.sub]]`
/// into a full domain entry, inheriting the parent upstream where absent.
fn expand(raw: ConfigToml, path: &str) -> Config {
    let global_rl = raw.rate_limit;
    let mut sites: Vec<Site> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Compile bypass patterns once at load; a bad regex fails startup naming
    // the site rather than failing requests at runtime.
    fn compile_bypass(domain: &str, patterns: &[String], path: &str) -> Vec<regex::Regex> {
        patterns
            .iter()
            .map(|p| {
                regex::Regex::new(p).unwrap_or_else(|e| {
                    panic!("config '{path}': site '{domain}': bad bypass regex '{p}': {e}")
                })
            })
            .collect()
    }

    // Merge a per-site RateLimitConfig on top of the global defaults.
    // Only non-default fields override (0/0/0 means "use global").
    fn merge_rl(global: &RateLimitConfig, override_rl: &RateLimitConfig) -> RateLimitConfig {
        RateLimitConfig {
            enabled: global.enabled || override_rl.enabled,
            rps: if override_rl.rps > 0 { override_rl.rps } else { global.rps },
            rpm: if override_rl.rpm > 0 { override_rl.rpm } else { global.rpm },
            burst: if override_rl.burst > 0 { override_rl.burst } else { global.burst },
        }
    }

    let mut push = |domain: String, upstream: String, bypass: Vec<regex::Regex>, rl: RateLimitConfig| {
        let domain = normalize_host(&domain);
        if !seen.insert(domain.clone()) {
            panic!("config '{path}': duplicate site '{domain}'");
        }
        sites.push(Site { domain, upstream, bypass, rate_limit: rl });
    };

    for s in raw.sites {
        if !s.upstream.is_empty() {
            let bypass = compile_bypass(&s.domain, &s.bypass, path);
            let rl = s.rate_limit.as_ref()
                .map(|r| merge_rl(&global_rl, r))
                .unwrap_or_else(|| global_rl.clone());
            push(s.domain.clone(), s.upstream.clone(), bypass, rl);
        }

        for sub in s.sub {
            let Some(upstream) = Some(sub.upstream.unwrap_or_else(|| s.upstream.clone()))
                .filter(|u| !u.is_empty())
            else {
                continue; // no upstream here or inherited: skip the whole site
            };
            let full = format!("{}.{}", sub.name, s.domain);
            let bypass = match sub.bypass {
                Some(list) => compile_bypass(&full, &list, path),
                None => compile_bypass(&full, &s.bypass, path),
            };
            let rl = sub.rate_limit.as_ref()
                .map(|r| merge_rl(&global_rl, r))
                .unwrap_or_else(|| global_rl.clone());
            push(full, upstream, bypass, rl);
        }
    }

    if sites.is_empty() {
        panic!(
            "config '{path}': no usable sites — every [[sites]] entry needs a non-empty upstream"
        );
    }

    sites.sort_by(|a, b| a.domain.cmp(&b.domain));

    let whitelist: Vec<IpAddr> = raw.whitelist.iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .collect();

    Config {
        sites,
        rate_limit: global_rl,
        log: raw.log,
        whitelist,
        catchall: raw.catchall.clone(),
        catchall_bypass: raw.catchall.as_ref().map(|c| {
            c.bypass.iter().map(|p| {
                regex::Regex::new(p).unwrap_or_else(|e| panic!("bad catchall bypass '{p}': {e}"))
            }).collect()
        }).unwrap_or_default(),
        port: raw.nekoguard.port,
        port_http: raw.nekoguard.port_http,
        session: raw.nekoguard.session,
        redis: raw.redis,
    }
}

pub static CONFIG: LazyLock<Config> = LazyLock::new(|| {
    let path = std::env::var(CONFIG_PATH_ENV).unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string());
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read config '{path}': {e}"));
    let parsed: ConfigToml = toml::from_str(&raw)
        .unwrap_or_else(|e| panic!("failed to parse config '{path}': {e}"));
    expand(parsed, &path)
});
