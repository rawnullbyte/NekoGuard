use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::sync::LazyLock;

const DEFAULT_PORT: u16 = 443;
const DEFAULT_CACHE_DIR: &str = "./acme-cache";
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
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigToml {
    #[serde(default)]
    sites: Vec<SiteToml>,
    #[serde(default)]
    contact: Vec<String>,
    #[serde(default = "default_cache_dir")]
    cache_dir: String,
    #[serde(default)]
    staging: bool,
    #[serde(default = "default_port")]
    port: u16,
}

/// Runtime config: the on-disk shape with `[[sites.sub]]` entries expanded
/// into a flat list of (domain, upstream) pairs.
#[derive(Debug)]
pub struct Config {
    /// Fully expanded site list (parent domains plus every `[[sites.sub]]`
    /// flattened into its own entry). Sorted by domain for stable logs.
    pub sites: Vec<Site>,
    pub contact: Vec<String>,
    pub cache_dir: String,
    pub staging: bool,
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

/// Expand the on-disk config into runtime form: flatten every `[[sites.sub]]`
/// into a full domain entry, inheriting the parent upstream where absent.
fn expand(raw: ConfigToml, path: &str) -> Config {
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

    let mut push = |domain: String, upstream: String, bypass: Vec<regex::Regex>| {
        let domain = normalize_host(&domain);
        if !seen.insert(domain.clone()) {
            panic!("config '{path}': duplicate site '{domain}'");
        }
        sites.push(Site {
            domain,
            upstream,
            bypass,
        });
    };

    for s in raw.sites {
        if !s.upstream.is_empty() {
            let bypass = compile_bypass(&s.domain, &s.bypass, path);
            push(s.domain.clone(), s.upstream.clone(), bypass);
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
                None => compile_bypass(&full, &s.bypass, path), // inherit parent
            };
            push(full, upstream, bypass);
        }
    }

    if sites.is_empty() {
        panic!(
            "config '{path}': no usable sites — every [[sites]] entry needs a non-empty upstream"
        );
    }

    sites.sort_by(|a, b| a.domain.cmp(&b.domain));

    Config {
        sites,
        contact: raw.contact,
        cache_dir: raw.cache_dir,
        staging: raw.staging,
        port: raw.port,
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
