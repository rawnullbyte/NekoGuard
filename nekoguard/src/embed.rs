//! Origin metadata for the PoW interstitial.
//!
//! A visitor waiting on the challenge is looking at NekoGuard's own document,
//! served from the site's origin. Crawlers and link unfurlers (search engines,
//! Discord, X, Slack…) never solve the challenge — they read that document and
//! move on — so without help they index and embed the placeholder instead of
//! the site behind it.
//!
//! To avoid that, a small set of metadata assets is lifted from the origin
//! through a per-host cache and inlined into the interstitial: `<title>`,
//! descriptive `<meta>` tags (description, OpenGraph, Twitter cards) and the
//! favicon.
//!
//! Everything here is best-effort. A failure at any step just leaves the
//! interstitial looking exactly as it did before.

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::header::{HeaderValue, CONTENT_TYPE};
use hyper::{Request, StatusCode};
use regex::{NoExpand, Regex};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::config::normalize_host;
use crate::{ProxyClient, RespBody};

/// How long one origin's metadata is reused before it's fetched again.
const CACHE_TTL: Duration = Duration::from_secs(300);

/// Ceiling on a single upstream request, and on the whole fetch.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest origin document scanned, and largest favicon kept.
const MAX_HTML: usize = 512 * 1024;
const MAX_ICON: usize = 2 * 1024 * 1024;

/// Titles are re-emitted into the page's only heading-ish element; one long
/// enough to be a document of its own is not a title.
const MAX_TITLE: usize = 200;

/// Same-origin redirects followed while retrieving the root document.
const MAX_HOPS: usize = 3;

/// One `<title>…</title>`, so the placeholder's own title can be swapped for
/// the origin's. The text is captured rather than the whole tag, so callers
/// don't have to know where it starts.
static TITLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<title[^>]*>(.*?)</title\s*>").unwrap()
});

/// A `<meta …>` tag with at least one attribute.
static META_TAG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<meta\s[^>]*>").unwrap()
});

/// A `<link …>` tag, which is where a favicon is declared.
static LINK_TAG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<link\s[^>]*>").unwrap()
});

/// Any `name="value"` pair inside a tag (either quote style).
static ATTR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)\s([a-z][a-z0-9:_-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')"#).unwrap()
});

/// Metadata lifted out of one origin's `<head>`.
#[derive(Clone, Default)]
struct Meta {
    title: Option<String>,
    tags: Vec<String>,

    /// Icon URL as declared by the origin, resolved at fetch time.
    icon_url: Option<String>,

    /// Icon bytes plus the content type to serve them with.
    icon: Option<(Bytes, &'static str)>,
}

/// The serialisable half of `Meta`: what Redis carries between replicas.
///
/// The icon is stored as raw bytes and restored with its type; the scraping
/// pipeline only ever emits the handful of raster types `icon_mime` admits.
#[derive(Serialize, Deserialize)]
struct CachedMeta {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    icon: Option<Vec<u8>>,
    #[serde(default)]
    icon_mime: Option<String>,
}

/// Redis key holding one origin's metadata.
fn cache_key(host: &str) -> String {
    format!("nekoguard:embed:{host}")
}

impl From<&Meta> for CachedMeta {
    fn from(meta: &Meta) -> Self {
        let (icon, icon_mime) = match &meta.icon {
            Some((bytes, mime)) => (Some(bytes.to_vec()), Some((*mime).to_string())),
            None => (None, None),
        };
        Self { title: meta.title.clone(), tags: meta.tags.clone(), icon, icon_mime }
    }
}

impl CachedMeta {
    /// Rebuild a `Meta`. An icon whose type is missing or unrecognised is
    /// dropped rather than served under a guessed content type.
    fn into_meta(self) -> Meta {
        let icon = self
            .icon
            .zip(self.icon_mime.as_deref())
            .and_then(|(bytes, mime)| icon_mime(mime).map(|mime| (Bytes::from(bytes), mime)));

        Meta { title: self.title, tags: self.tags, icon_url: None, icon }
    }
}

/// One origin's metadata and the moment this process loaded it.
struct Cached {
    meta: Arc<Meta>,
    fetched: Instant,
}

/// Process-local tier in front of Redis. An at-capacity instance renders an
/// interstitial for every visitor, so going to Redis on each render would put
/// a round trip on the hot path for data that changes at most every 5 minutes.
/// Entries are only ever as old as the Redis TTL, so serving them can't
/// outlive the origin's window; the worst case is a replica being slightly
/// cold after a restart, which costs one fetch.
static LOCAL: LazyLock<Mutex<HashMap<String, Cached>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Single-flight per host, so a burst of visitors for one origin triggers one
/// fetch rather than many. Held across the fetch; the map lock below never is.
static INFLIGHT: LazyLock<Mutex<HashMap<String, Arc<Mutex<()>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Clone)]
pub(crate) struct EmbedCtx {
    /// Reuses the process-wide pool rather than opening a connection per
    /// request.
    redis: redis::aio::ConnectionManager,
}

impl EmbedCtx {
    pub(crate) fn new(redis: redis::aio::ConnectionManager) -> Self {
        Self { redis }
    }
}

/// A Redis error means "cache unavailable", not "no metadata": callers carry
/// on to the origin rather than surfacing a failure.
async fn redis_get(redis: &mut redis::aio::ConnectionManager, host: &str) -> Option<Arc<Meta>> {
    let raw: Option<String> = redis::cmd("GET")
        .arg(cache_key(host))
        .query_async(redis)
        .await
        .map_err(|e| log::debug!("[embed] redis GET failed for {host}: {e}"))
        .ok()?;
    let raw = raw?;

    serde_json::from_str::<CachedMeta>(&raw)
        .map_err(|e| log::warn!("[embed] unreadable cache entry for {host}: {e}"))
        .ok()
        .map(|cached| Arc::new(cached.into_meta()))
}

/// Write through to Redis with the window as its TTL, so the entry expires on
/// its own and the next reader refetches.
async fn redis_set(
    redis: &mut redis::aio::ConnectionManager,
    host: &str,
    meta: &Meta,
) -> Option<()> {
    let payload = serde_json::to_string(&CachedMeta::from(meta))
        .map_err(|e| log::warn!("[embed] could not serialize metadata for {host}: {e}"))
        .ok()?;

    redis::cmd("SET")
        .arg(cache_key(host))
        .arg(payload)
        .arg("EX")
        .arg(CACHE_TTL.as_secs())
        .query_async::<()>(redis)
        .await
        .map_err(|e| log::warn!("[embed] redis SET failed for {host}: {e}"))
        .ok()
}

/// The favicon link the interstitial advertises when the origin has an icon;
/// it maps back to this host's own `/__ng/favicon.ico`.
const FAVICON_LINK: &str = r#"<link rel="icon" href="/__ng/favicon.ico">"#;

/// Splice the origin's metadata into a rendered interstitial page: the
/// origin's title, its descriptive `<meta>` tags in place of `{{NG_META}}`,
/// and a favicon link when the origin has one.
///
/// This owns the `{{NG_META}}` marker and clears it unconditionally, so the
/// template can never leak the marker into a served page.
pub(crate) async fn inline_into(
    page: String,
    ctx: Option<&EmbedCtx>,
    client: &ProxyClient,
    host: &str,
    upstream: &str,
) -> String {
    let host = normalize_host(host);
    let meta = load(&host, ctx, client, upstream, true).await;

    let mut inject = String::new();
    if let Some(meta) = &meta {
        for tag in &meta.tags {
            inject.push_str(tag);
        }
        if meta.icon.is_some() {
            inject.push_str(FAVICON_LINK);
        }
    }

    // A missing title renders as a blank link, so fall back to the bare host
    // rather than to the placeholder's own title.
    let title = meta
        .and_then(|meta| meta.title.clone())
        .unwrap_or_else(|| host.clone());

    replace_title(&page, &title).replacen("{{NG_META}}", &inject, 1)
}

/// Clear the `{{NG_META}}` marker from a page that was rendered without the
/// origin metadata, so it never reaches a client.
pub(crate) fn clear_marker(page: String) -> String {
    page.replace("{{NG_META}}", "")
}

/// The origin's favicon, for the interstitial to advertise as
/// `/__ng/favicon.ico`. `None` when the origin declares none.
pub(crate) async fn favicon(
    ctx: Option<&EmbedCtx>,
    client: &ProxyClient,
    host: &str,
    upstream: &str,
) -> Option<(Bytes, &'static str)> {
    let host = normalize_host(host);
    // A miss means this host hasn't served an interstitial within the window,
    // so fetching now would be work nothing asked for.
    load(&host, ctx, client, upstream, false).await?.icon.clone()
}

/// Metadata for `host`: from the local tier, else Redis, else freshly fetched
/// and written back with a 5-minute TTL.
///
/// `fetch_on_miss` is what the caller wants to happen when neither cache has
/// the host. The interstitial says yes: rendering full metadata for a host
/// nothing has fetched yet is the entire feature. The favicon route says no,
/// so a crawler asking for an icon it was never advertised can't drive traffic
/// to an origin that has never served an interstitial.
async fn load(
    host: &str,
    ctx: Option<&EmbedCtx>,
    client: &ProxyClient,
    upstream: &str,
    fetch_on_miss: bool,
) -> Option<Arc<Meta>> {
    if let Some(meta) = local_get(host).await {
        return Some(meta);
    }

    let mut conn = ctx.map(|ctx| ctx.redis.clone());

    // Read-through: another replica, or this one before a restart, may have
    // already fetched within the window.
    if let Some(conn) = conn.as_mut() {
        if let Some(meta) = redis_get(conn, host).await {
            local_put(host, Arc::clone(&meta)).await;
            return Some(meta);
        }
    }

    if !fetch_on_miss {
        return None;
    }

    // Serialise the fetch per host, so a burst for one origin makes a single
    // request rather than one per visitor. Replicas still fetch in parallel —
    // this only covers the visitors landing on one instance.
    let lock = inflight_lock(host).await;
    let _guard = lock.lock().await;

    // A peer may have finished while this task waited for the lock.
    if let Some(meta) = local_get(host).await {
        return Some(meta);
    }
    if let Some(conn) = conn.as_mut() {
        if let Some(meta) = redis_get(conn, host).await {
            local_put(host, Arc::clone(&meta)).await;
            return Some(meta);
        }
    }

    let meta = Arc::new(fetch(client, host, upstream).await?);
    local_put(host, Arc::clone(&meta)).await;
    if let Some(conn) = conn.as_mut() {
        redis_set(conn, host, &meta).await;
    }
    Some(meta)
}

/// A locally cached copy, discarded once it's as old as the Redis window — so
/// a serving replica can never outlive the entry it was minted from.
async fn local_get(host: &str) -> Option<Arc<Meta>> {
    let mut cache = LOCAL.lock().await;
    match cache.get(host) {
        Some(entry) if entry.fetched.elapsed() < CACHE_TTL => Some(Arc::clone(&entry.meta)),
        Some(_) => {
            cache.remove(host);
            None
        }
        None => None,
    }
}

async fn local_put(host: &str, meta: Arc<Meta>) {
    LOCAL
        .lock()
        .await
        .insert(host.to_string(), Cached { meta, fetched: Instant::now() });
}

/// Resolve the per-host fetch lock, so a burst for one origin makes one
/// request rather than one per visitor.
async fn inflight_lock(host: &str) -> Arc<Mutex<()>> {
    let mut inflight = INFLIGHT.lock().await;
    Arc::clone(
        inflight
            .entry(host.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(()))),
    )
}

/// Fetch and scrape one origin. `None` means the document could not be
/// retrieved; a document that merely lacks metadata is still `Some`.
async fn fetch(client: &ProxyClient, host: &str, upstream: &str) -> Option<Meta> {
    let document = match fetch_html(client, host, upstream).await {
        Some(document) => document,
        None => {
            log::debug!("[embed] no origin document for {host}");
            return None;
        }
    };

    let mut meta = scrape(&document);
    if let Some(url) = meta.icon_url.take() {
        match fetch_icon(client, host, upstream, &url).await {
            Some(icon) => meta.icon = Some(icon),
            None => log::debug!("[embed] favicon {url} unusable for {host}"),
        }
    }
    Some(meta)
}

/// Retrieve the origin's root document as HTML, following up to `MAX_HOPS`
/// same-origin redirects — `/` → `/en/` and friends are common.
async fn fetch_html(client: &ProxyClient, host: &str, upstream: &str) -> Option<String> {
    let mut path = "/".to_string();

    for _ in 0..MAX_HOPS {
        let req = build_get(host, upstream, &path)?;
        let resp = tokio::time::timeout(FETCH_TIMEOUT, client.request(req))
            .await
            .ok()?
            .ok()?;

        if resp.status().is_redirection() {
            let location = resp.headers().get("location").and_then(|v| v.to_str().ok())?;
            // Refuses anything that leaves the origin, so a redirect can't
            // steer the fetch at another internal host.
            path = same_origin_path(location, host)?;
            continue;
        }
        if resp.status() != StatusCode::OK {
            log::debug!("[embed] origin {host}{path} answered {}", resp.status());
            return None;
        }
        if !is_html(resp.headers().get(CONTENT_TYPE)) {
            return None;
        }

        let body = tokio::time::timeout(
            FETCH_TIMEOUT,
            Limited::new(resp.into_body(), MAX_HTML).collect(),
        )
        .await
        .ok()?
        .ok()?;
        return String::from_utf8(body.to_bytes().to_vec()).ok();
    }
    None
}

/// Fetch the declared favicon. Only same-origin URLs are retrieved, and only
/// raster types are kept: an SVG can carry script, and would then be served
/// from the origin NekoGuard is protecting.
async fn fetch_icon(
    client: &ProxyClient,
    host: &str,
    upstream: &str,
    url: &str,
) -> Option<(Bytes, &'static str)> {
    if let Some(rest) = url.strip_prefix("data:") {
        return decode_data_uri(rest);
    }

    let path = same_origin_path(url, host)?;
    let req = build_get(host, upstream, &path)?;
    let resp = tokio::time::timeout(FETCH_TIMEOUT, client.request(req))
        .await
        .ok()?
        .ok()?;
    if resp.status() != StatusCode::OK {
        return None;
    }

    let mime = icon_mime(resp.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or(""))?;
    let body = tokio::time::timeout(
        FETCH_TIMEOUT,
        Limited::new(resp.into_body(), MAX_ICON).collect(),
    )
    .await
    .ok()?
    .ok()?;
    Some((body.to_bytes(), mime))
}

/// A GET for `path`, addressed to the upstream but carrying the public
/// host — the same identity the proxy presents, so host-validating origins
/// (Ghost, etc.) answer with the document a visitor would get.
fn build_get(host: &str, upstream: &str, path: &str) -> Option<Request<RespBody>> {
    let up: hyper::Uri = upstream.parse().ok()?;
    let authority = up.authority()?.as_str();
    let scheme = up.scheme_str().unwrap_or("https");
    let uri: hyper::Uri = format!("{scheme}://{authority}{path}").parse().ok()?;

    let mut builder = Request::builder()
        .method("GET")
        .uri(uri)
        // Reuse upstream caching rules rather than being treated as a hit on
        // the origin's own page counters.
        .header("cache-control", "no-cache");
    if let Ok(public) = HeaderValue::from_str(host) {
        builder = builder
            .header("host", public.clone())
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-host", public);
    }
    builder.body(empty()).ok()
}

fn empty() -> RespBody {
    Empty::<Bytes>::new()
        .map_err(|e: Infallible| match e {})
        .boxed()
}

/// Reduce a document-declared URL to a path on this origin. Anything naming a
/// different host is dropped rather than fetched.
///
/// Parsing is done on the string rather than through `hyper::Uri`, because a
/// bare relative reference like `favicon.ico` is not a valid URI at all — it
/// parses as *authority* form, which would read "favicon.ico" as a host.
fn same_origin_path(url: &str, host: &str) -> Option<String> {
    let (authority, rest) = if let Some(rest) = url.strip_prefix("//") {
        // Protocol-relative: keep the origin's own scheme, but the host it
        // names has to be this one.
        match rest.find(['/', '?', '#']) {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, ""),
        }
    } else if let Some((scheme, rest)) = url.split_once(':') {
        let scheme = scheme.to_ascii_lowercase();
        if !scheme.is_empty()
            && scheme.chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
        {
            // An absolute URL, or a `data:`/`javascript:`/`mailto:` value that
            // must be refused outright.
            if scheme != "http" && scheme != "https" {
                return None;
            }
            let rest = rest.trim_start_matches("//");
            match rest.find(['/', '?', '#']) {
                Some(at) => (&rest[..at], &rest[at..]),
                None => (rest, ""),
            }
        } else {
            // A relative path that merely contains a colon ("/a:b/c.png").
            ("", url)
        }
    } else {
        // A root-absolute or relative path: only this origin can be meant.
        ("", url)
    };

    if !authority.is_empty() {
        let authority = authority
            .rsplit('@')
            .next()
            .unwrap_or(authority)
            .trim_end_matches('.');
        let authority = authority
            .split(':')
            .next()
            .unwrap_or(authority);
        if !authority.eq_ignore_ascii_case(host) {
            return None;
        }
    }

    // A fragment never reaches a server, and a bare "favicon.ico" is relative
    // to the root — the root NekoGuard is the origin for.
    let rest = rest.split('#').next().unwrap_or("");
    if rest.is_empty() || rest == "/" {
        Some("/".to_string())
    } else if rest.starts_with('/') || rest == "?" {
        Some(rest.to_string())
    } else {
        Some(format!("/{rest}"))
    }
}

/// Lift the metadata out of an origin document: the head's `<title>` and
/// descriptive `<meta>` tags, plus any declared favicon.
fn scrape(document: &str) -> Meta {
    // Only the head, so a `<meta>` inside the body can't shadow the real
    // metadata. Documents with no head are scanned from the top instead.
    let head = match document.find("<head") {
        Some(start) => {
            let after_tag = document[start..].find('>').map_or(start, |i| start + i + 1);
            &document[after_tag..]
        }
        None => document,
    };
    // to_ascii_lowercase preserves byte offsets, so the index stays valid.
    let end = head.to_ascii_lowercase().find("</head>").unwrap_or(head.len());
    let head = &head[..end];

    let mut meta = Meta::default();
    for tag in META_TAG_RE.find_iter(head) {
        render_tag(&mut meta, tag.as_str());
    }
    // Scraped separately: `<link>` isn't a `<meta>` tag, but it's declared in
    // the same head.
    for tag in LINK_TAG_RE.find_iter(head) {
        note_icon(&mut meta, tag.as_str());
    }
    if meta.title.is_none() {
        meta.title = TITLE_RE
            .captures(head)
            .map(|c| decode(&c[1]).trim().to_string())
            .filter(|t| !t.is_empty())
            .map(|t| t.chars().take(MAX_TITLE).collect());
    }
    meta
}

/// Keep the origin's descriptive metadata, drop everything else: `charset`,
/// `viewport`, `theme-color` and `http-equiv` refresh/CSP all describe a page
/// NekoGuard isn't rendering.
fn render_tag(meta: &mut Meta, tag: &str) {
    // The attribute a tag is keyed by, in the order an embedder prefers:
    // `name` then `property`. Tags keyed by neither (`charset`, `viewport`,
    // `http-equiv="refresh"`) describe a page NekoGuard isn't rendering, so
    // they are dropped along with everything they'd otherwise match.
    let (key, value) = if let Some(name) = attribute(tag, "name") {
        ("name", name)
    } else if let Some(property) = attribute(tag, "property") {
        ("property", property)
    } else {
        return;
    };
    let lower = value.to_ascii_lowercase();

    let wanted = match key {
        "name" => lower == "description" || lower.starts_with("twitter:"),
        "property" => lower.starts_with("og:") || lower.starts_with("article:"),
        _ => false,
    };
    if !wanted {
        return;
    }

    // Content is needed to re-emit the tag or to decide on the card; without
    // it the key alone isn't worth forwarding.
    let Some(content) = attribute(tag, "content") else {
        return;
    };
    if content.is_empty() {
        return;
    }

    // A URL the origin declares about itself can't be trusted to name the
    // public address — an origin configured with an internal hostname will
    // publish that. NekoGuard answers canonical links itself, via the
    // `Link: …; rel="canonical"` header.
    if lower == "og:url" || lower == "twitter:url" {
        return;
    }
    // The origin's own card type is usually too small for the embed it lands
    // in; the interstitial is a full page, so prefer the large card.
    if lower == "twitter:card" {
        meta.tags.push(r#"<meta name="twitter:card" content="summary_large_image">"#.to_string());
        return;
    }

    // Decode before escaping: origins write plain characters as entities
    // (`&#x27;` for an apostrophe), and escaping without decoding first would
    // publish that entity as visible text.
    meta.tags.push(format!(
        r#"<meta {key}="{}" content="{}">"#,
        html_escape(&decode(value)),
        html_escape(&decode(content))
    ));
}

/// Note the origin's favicon as declared. Relation tokens are matched whole,
/// so `apple-touch-icon` and `mask-icon` don't count — only a real `icon`.
fn note_icon(meta: &mut Meta, tag: &str) {
    if meta.icon_url.is_some() {
        return;
    }
    let Some(rel) = attribute(tag, "rel") else {
        return;
    };
    if !rel
        .to_ascii_lowercase()
        .split_whitespace()
        .any(|token| token == "icon")
    {
        return;
    }
    let Some(href) = attribute(tag, "href") else {
        return;
    };
    if !href.is_empty() {
        meta.icon_url = Some(href.to_string());
    }
}

/// Read one quoted attribute out of a raw tag string. The quoted form is
/// required so a value can never contain the quote delimiting it — values are
/// re-emitted into HTML below, and that is what keeps them from escaping.
fn attribute<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    ATTR_RE
        .captures_iter(tag)
        .find(|caps| caps[1].eq_ignore_ascii_case(name))
        .and_then(|caps| caps.get(2).or_else(|| caps.get(3)))
        .map(|m| m.as_str())
}

/// Swap the page's title for `title`, escaping it on the way in: it arrives
/// from the origin document, which makes it attacker-influenced data.
fn replace_title(page: &str, title: &str) -> String {
    let tag = format!("<title>{}</title>", html_escape(title));
    // NoExpand: a title containing `$` must not be read as a capture group.
    TITLE_RE.replace(page, NoExpand(tag.as_str())).into_owned()
}

fn is_html(content_type: Option<&HeaderValue>) -> bool {
    let ct = content_type
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    ct.starts_with("text/html") || ct.starts_with("application/xhtml+xml")
}

/// Map an upstream content type onto the static we're willing to serve.
/// Raster formats only — SVG can carry script, and would be served from the
/// origin NekoGuard exists to shield.
fn icon_mime(content_type: &str) -> Option<&'static str> {
    let ct = content_type.to_ascii_lowercase();
    if ct.starts_with("image/png") {
        Some("image/png")
    } else if ct.starts_with("image/x-icon") || ct.starts_with("image/vnd.microsoft.icon") {
        Some("image/x-icon")
    } else if ct.starts_with("image/jpeg") {
        Some("image/jpeg")
    } else if ct.starts_with("image/gif") {
        Some("image/gif")
    } else if ct.starts_with("image/webp") {
        Some("image/webp")
    } else {
        None
    }
}

/// Inline a `data:` favicon, which needs no fetch and stays within the page.
fn decode_data_uri(rest: &str) -> Option<(Bytes, &'static str)> {
    use base64::Engine;

    let (meta, payload) = rest.split_once(',')?;
    let mime = icon_mime(meta.split(';').next().unwrap_or(""))?;
    if !meta.to_ascii_lowercase().contains(";base64") {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(payload.trim())
        .ok()?;
    if decoded.is_empty() || decoded.len() > MAX_ICON {
        return None;
    }
    Some((Bytes::from(decoded), mime))
}

/// Resolve character references in a scraped value, one pass left to right.
///
/// Origins routinely write plain apostrophes as `&#x27;`, and a value that is
/// escaped without being decoded first would carry that straight through into
/// an embed as visible `&#x27;` text. Single-pass is what keeps a literal
/// `&amp;#x27;` (an escaped entity the author meant to display) intact.
fn decode(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;

    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let tail = &rest[amp + 1..];
        // Entities are short; a `;` further out than this isn't one, so a
        // stray `&` in prose can't swallow the text after it.
        let entity = tail.find(';').filter(|end| *end <= 8).map(|end| &tail[..end]);

        match entity.and_then(decode_entity) {
            Some(decoded) => {
                out.push(decoded);
                rest = &tail[entity.unwrap().len() + 1..];
            }
            None => {
                out.push('&');
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    out
}

fn decode_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some('\u{a0}'),
        // Numeric: `&#x27;` and `&#39;` are the same character.
        _ => char::from_u32(
            entity
                .strip_prefix("#x")
                .or_else(|| entity.strip_prefix("#X"))
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                .or_else(|| entity.strip_prefix('#').and_then(|dec| dec.parse().ok()))?,
        ),
    }
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_cross_origin_and_non_http_urls() {
        // Absolute, scheme-relative and relative same-origin forms.
        assert_eq!(same_origin_path("/favicon.ico", "example.com").as_deref(), Some("/favicon.ico"));
        assert_eq!(same_origin_path("favicon.ico", "example.com").as_deref(), Some("/favicon.ico"));
        assert_eq!(
            same_origin_path("https://example.com/a/b.png", "example.com").as_deref(),
            Some("/a/b.png")
        );
        assert_eq!(
            same_origin_path("//example.com/a.png", "example.com").as_deref(),
            Some("/a.png")
        );
        // A redirect must not be able to steer the fetch at another host,
        // least of all an internal one.
        assert_eq!(same_origin_path("http://10.0.0.5:9090/admin", "example.com"), None);
        assert_eq!(same_origin_path("//169.254.169.254/latest/meta-data/", "example.com"), None);
        assert_eq!(same_origin_path("http://209.177.145.76/favicon.ico", "example.com"), None);
        // A port on the origin's own host is still the origin.
        assert_eq!(
            same_origin_path("http://example.com:8080/a.png", "example.com").as_deref(),
            Some("/a.png")
        );
        assert_eq!(same_origin_path("file:///etc/passwd", "example.com"), None);
        // "favicon.ico" parses as authority form (host "favicon.ico"), not as
        // a relative path — it must not be mistaken for one.
        assert_eq!(same_origin_path("favicon.ico", "example.com").as_deref(), Some("/favicon.ico"));
    }

    #[test]
    fn attribute_requires_a_quoted_value() {
        let tag = r#"<meta property="og:image" content="https://x/y.png" name='description'>"#;
        assert_eq!(attribute(tag, "PROPERTY"), Some("og:image"));
        assert_eq!(attribute(tag, "content"), Some("https://x/y.png"));
        assert_eq!(attribute(tag, "name"), Some("description"));
        assert_eq!(attribute(tag, "missing"), None);
        // Unquoted values can swallow the delimiter that would contain them.
        assert_eq!(attribute(r#"<meta content=https://x/ onload=alert(1)>"#, "content"), None);
    }

    #[test]
    fn keeps_descriptive_tags_only() {
        let mut meta = Meta::default();
        render_tag(&mut meta, r#"<meta charset="UTF-8">"#);
        render_tag(&mut meta, r#"<meta name="viewport" content="width=device-width">"#);
        render_tag(&mut meta, r#"<meta http-equiv="refresh" content="0;url=/x">"#);
        render_tag(&mut meta, r##"<meta name="theme-color" content="#fff">"##);
        assert!(meta.tags.is_empty(), "non-descriptive tags leaked: {:?}", meta.tags);

        render_tag(&mut meta, r#"<meta name="description" content="A blog">"#);
        render_tag(&mut meta, r#"<meta property="og:title" content="Home">"#);
        render_tag(&mut meta, r#"<meta name="twitter:description" content="hi">"#);
        render_tag(&mut meta, r#"<meta property="article:published_time" content="2026-01-01">"#);
        assert_eq!(meta.tags.len(), 4);
    }

    #[test]
    fn og_url_is_dropped_and_twitter_card_is_upgraded() {
        let mut meta = Meta::default();
        render_tag(&mut meta, r#"<meta property="og:url" content="http://10.0.0.5:2368/">"#);
        assert!(meta.tags.is_empty(), "origin canonical leaked into the embed");

        render_tag(&mut meta, r#"<meta name="twitter:card" content="summary">"#);
        assert_eq!(meta.tags.len(), 1);
        assert!(meta.tags[0].contains("summary_large_image"));
    }

    #[test]
    fn attribute_values_cannot_escape_their_tag() {
        let mut meta = Meta::default();
        render_tag(
            &mut meta,
            r#"<meta property="og:title" content="x&quot;><script>alert(1)</script>">"#,
        );
        assert_eq!(meta.tags.len(), 1);
        let tag = &meta.tags[0];

        // Decoding `&quot;` and then escaping restores `&quot;`, so the value
        // stays inside its attribute — the part after it never becomes a new
        // attribute.
        assert!(!tag.contains(r#"x" onload"#), "broke out of the attribute: {tag}");
        // `<script>` from `&lt;script&gt;` round-trips to the same entity, so
        // it can never become markup.
        assert!(!tag.contains("<script>"), "raw markup survived: {tag}");
        assert!(tag.contains("&lt;script&gt;"), "{tag}");
        // No raw metacharacter may appear in the emitted tag's value.
        let value = &tag[tag.find("content=").unwrap()..];
        assert!(!value.contains('"') || value.matches('"').count() == 2, "{tag}");
    }

    #[test]
    fn urls_the_origin_declares_are_dropped() {
        let mut meta = Meta::default();
        render_tag(&mut meta, r#"<meta property="og:url" content="http://10.0.0.5:2368/">"#);
        render_tag(&mut meta, r#"<meta name="twitter:url" content="http://10.0.0.5:2368/">"#);
        assert!(meta.tags.is_empty(), "an origin-declared URL leaked: {:?}", meta.tags);

        // Matching is exact, so a prefixed sibling like `og:image:url` — which
        // is a legitimate property — survives.
        render_tag(&mut meta, r#"<meta property="og:image:url" content="/share.png">"#);
        assert_eq!(meta.tags.len(), 1, "{:?}", meta.tags);
    }

    #[test]
    fn title_substitution_escapes_and_does_not_expand_captures() {
        let page = "<title>Verifying your connection</title><style>a{}</style>";
        let out = replace_title(page, r#"$1 Ben & Jerry's <b>"#);
        assert!(!out.contains("<b>"));
        // The replacement is literal: `$1` must survive rather than expand to
        // the placeholder title it would otherwise reference.
        assert!(!out.contains("Verifying your connection"), "capture expanded: {out}");
        assert!(out.contains("$1"));
        assert!(out.contains("Ben &amp; Jerry's"));
        assert_eq!(out.matches("<title>").count(), 1);
    }

    #[test]
    fn scrape_pulls_title_metadata_and_favicon() {
        let doc = r#"<!doctype html><html><head>
            <meta charset="utf-8">
            <title>  My Site  </title>
            <meta name="description" content="A description">
            <meta property="og:image" content="/share.png">
            <link rel="stylesheet" href="/app.css">
            <link rel="apple-touch-icon" href="/apple.png">
            <link rel="shortcut icon" href="/favicon.ico">
        </head><body><meta property="og:title" content="body decoy"></body></html>"#;
        let meta = scrape(doc);
        assert_eq!(meta.title.as_deref(), Some("My Site"));
        assert!(meta.tags.iter().any(|t| t.contains("og:image") && t.contains("/share.png")));
        // A <meta> in the body must not leak in.
        assert!(!meta.tags.iter().any(|t| t.contains("body decoy")), "{:?}", meta.tags);
        // The first real icon wins; apple-touch-icon is not the favicon.
        assert_eq!(meta.icon_url.as_deref(), Some("/favicon.ico"));
    }

    /// Metadata is only lifted from a document the origin actually declares as
    /// HTML — a JSON API or an image sitting at `/` must never be parsed as
    /// markup.
    #[test]
    fn is_html_admits_only_html_media_types() {
        let h = |s: &str| is_html(Some(&HeaderValue::from_str(s).unwrap()));

        assert!(h("text/html"));
        assert!(h("text/html; charset=utf-8"));
        assert!(h("TEXT/HTML; CHARSET=UTF-8"));
        assert!(h("  text/html  "));
        assert!(h("application/xhtml+xml"));

        assert!(!h("application/json"));
        assert!(!h("text/plain"));
        assert!(!h("application/xml"));
        assert!(!h("image/png"));
        assert!(!h("image/svg+xml"));
        assert!(!h(""));
        // Absent content type: nothing to vouch for it, so refuse.
        assert!(!is_html(None));
    }

    #[test]
    fn icon_mime_admits_raster_only() {
        assert_eq!(icon_mime("image/png"), Some("image/png"));
        assert_eq!(icon_mime("image/x-icon"), Some("image/x-icon"));
        assert_eq!(icon_mime("image/vnd.microsoft.icon"), Some("image/x-icon"));
        assert_eq!(icon_mime("image/svg+xml"), None);
        assert_eq!(icon_mime("text/html"), None);
    }

    #[test]
    fn data_uri_icons_decode() {
        // 1x1 gif.
        let uri = "image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";
        let (bytes, mime) = decode_data_uri(uri).expect("decodes");
        assert_eq!(mime, "image/gif");
        assert_eq!(&bytes[..3], b"GIF");
        assert!(decode_data_uri("image/svg+xml;base64,PHN2Zz4=").is_none());
        assert!(decode_data_uri("image/png;base64,!!!").is_none());
    }

    #[test]
    fn entity_decoding_is_applied_once() {
        assert_eq!(decode("Ben &amp; Jerry"), "Ben & Jerry");
        // A literal "&amp;lt;" is an author writing "&lt;", not markup.
        assert_eq!(decode("&amp;lt;script&amp;gt;"), "&lt;script&gt;");
        assert_eq!(decode("a &lt;b&gt; c"), "a <b> c");
        // The form Ghost writes apostrophes in, seen on a live origin.
        assert_eq!(
            decode("We&#x27;re an independent group"),
            "We're an independent group"
        );
        assert_eq!(decode("&#39;"), "'");
        assert_eq!(decode("&#8212;"), "\u{2014}");
        // A bare ampersand in prose must not eat the following text.
        assert_eq!(decode("Tom & Jerry & Co."), "Tom & Jerry & Co.");
        assert_eq!(decode("5 &lt; 6 & 7"), "5 < 6 & 7");
        assert_eq!(decode("&notanentity; &"), "&notanentity; &");
    }

    /// The page shape that shipped broken: `main.rs` cleared the marker and
    /// `inline_into` then tried to fill it, so nothing was ever injected.
    #[test]
    fn marker_is_filled_even_though_the_template_carries_it() {
        let page = "<html><head><title>Verifying your connection</title>{{NG_META}}</head></html>";
        let mut meta = Meta::default();
        render_tag(&mut meta, r#"<meta name="description" content="desc">"#);
        meta.icon = Some((Bytes::from_static(b"x"), "image/png"));

        // The template's own marker must survive rendering: only inline_into
        // may consume it.
        let rendered = crate::challenge_html("chal");
        assert!(
            rendered.contains("{{NG_META}}"),
            "challenge_html consumed the marker inline_into needs"
        );

        let out = fill_for_test(page, &meta, "example.com");
        assert!(out.contains(r#"name="description""#), "{out}");
        assert!(out.contains(FAVICON_LINK), "{out}");
        assert!(!out.contains("{{NG_META}}"), "{out}");
    }

    /// Mirrors `inline_into`'s splice without the network.
    fn fill_for_test(page: &str, meta: &Meta, host: &str) -> String {
        let mut inject = String::new();
        for tag in &meta.tags {
            inject.push_str(tag);
        }
        if meta.icon.is_some() {
            inject.push_str(FAVICON_LINK);
        }
        let title = meta.title.clone().unwrap_or_else(|| host.to_string());
        replace_title(page, &title).replacen("{{NG_META}}", &inject, 1)
    }

    #[test]
    fn clear_marker_removes_it_without_the_origin() {
        let page = "<head>{{NG_META}}</head>".to_string();
        assert_eq!(clear_marker(page), "<head></head>");
    }
}

/// End-to-end coverage of the fetch path: a real `ProxyClient` against a real
/// HTTP origin, so redirect handling, request shaping and caching are exercised
/// rather than mocked. Each test uses its own host, since the cache is global.
#[cfg(test)]
mod fetch_tests {
    use super::*;
    use http_body_util::Full;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::Response;
    use hyper_tls::HttpsConnector;
    use hyper_util::client::legacy::{connect::HttpConnector, Client};
    use hyper_util::rt::{TokioExecutor, TokioIo};

    const HTML: &str = r#"<!doctype html><html><head>
        <meta charset="utf-8"><title>Origin Title</title>
        <meta name="description" content="An origin description">
        <meta property="og:description" content="An og description">
        <link rel="icon" href="/favicon.ico">
        <link rel="stylesheet" href="/app.css">
    </head><body>Hello from the origin</body></html>"#;

    const ICON: &[u8] = b"\x89PNG\r\n\x1a\nfake-icon-bytes";

    /// A running origin, plus every request it received.
    struct Origin {
        port: u16,
        hits: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl Origin {
        fn upstream(&self) -> String {
            format!("http://127.0.0.1:{}", self.port)
        }

        async fn hits(&self) -> Vec<(String, String)> {
            self.hits.lock().await.clone()
        }

        /// Paths requested so far, in order.
        async fn paths(&self) -> Vec<String> {
            self.hits.lock().await.iter().map(|(p, _)| p.clone()).collect()
        }
    }

    type Route = (u16, Vec<(&'static str, String)>, Vec<u8>);

    async fn start_origin<F>(respond: F) -> Origin
    where
        F: Fn(&str) -> Route + Send + Sync + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let respond = Arc::new(respond);
        let recorded = Arc::clone(&hits);

        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let respond = Arc::clone(&respond);
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    let service = service_fn(
                        move |req: hyper::Request<hyper::body::Incoming>| {
                            let respond = Arc::clone(&respond);
                            let recorded = Arc::clone(&recorded);
                            async move {
                                let path = req.uri().path().to_string();
                                let host = req
                                    .headers()
                                    .get("host")
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("")
                                    .to_string();
                                recorded.lock().await.push((path.clone(), host));

                                let (status, headers, body) = respond(&path);
                                let mut builder = Response::builder().status(status);
                                for (name, value) in headers {
                                    builder = builder.header(name, value);
                                }
                                Ok::<_, Infallible>(
                                    builder.body(Full::new(Bytes::from(body))).unwrap(),
                                )
                            }
                        },
                    );
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(tcp), service)
                        .await;
                });
            }
        });

        Origin { port, hits }
    }

    /// The same client the proxy builds, so request shaping matches production.
    fn test_client() -> ProxyClient {
        let tls = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        Client::builder(TokioExecutor::new()).build(HttpsConnector::from((http, tls.into())))
    }

    fn page() -> String {
        "<html><head><title>Verifying your connection</title>{{NG_META}}</head><body>x</body></html>"
            .to_string()
    }

    #[tokio::test]
    async fn inlines_origin_metadata_and_caches_it() {
        let origin = start_origin(|path| match path {
            "/" => (
                200,
                vec![("content-type", "text/html; charset=utf-8".into())],
                HTML.as_bytes().to_vec(),
            ),
            "/favicon.ico" => (
                200,
                vec![("content-type", "image/x-icon".into())],
                ICON.to_vec(),
            ),
            _ => (404, vec![], Vec::new()),
        })
        .await;

        let client = test_client();
        let host = "inline.example";
        let upstream = origin.upstream();

        let out = inline_into(page(), None, &client, host, &upstream).await;

        assert!(out.contains("<title>Origin Title</title>"), "{out}");
        assert!(out.contains("og:description"), "{out}");
        assert!(out.contains("An origin description"), "{out}");
        assert!(
            out.contains(r#"<link rel="icon" href="/__ng/favicon.ico">"#),
            "{out}"
        );
        assert!(!out.contains("{{NG_META}}"), "marker left behind: {out}");
        assert!(!out.contains("-- bits"), "challenge placeholders unresolved: {out}");

        // Addressed by the public host, exactly as the proxy does it.
        let hits = origin.hits().await;
        assert_eq!(hits.len(), 2, "{hits:?}");
        assert!(hits.iter().all(|(_, h)| h == host), "{hits:?}");

        // The favicon is cached alongside the rest.
        let (icon, mime) = favicon(None, &client, host, &upstream).await.expect("favicon");
        assert_eq!(mime, "image/x-icon");
        assert_eq!(icon.as_ref(), ICON);

        // A second render inside the window must not touch the origin again.
        let _ = inline_into(page(), None, &client, host, &upstream).await;
        assert_eq!(origin.hits().await.len(), 2, "cache missed on re-render");
    }

    #[tokio::test]
    async fn follows_same_origin_redirect() {
        let origin = start_origin(|path| match path {
            "/" => (
                302,
                vec![("location", "/en/".into())],
                Vec::new(),
            ),
            "/en/" => (
                200,
                vec![("content-type", "text/html".into())],
                HTML.as_bytes().to_vec(),
            ),
            _ => (404, vec![], Vec::new()),
        })
        .await;

        let client = test_client();
        let host = "redirect.example";
        let out = inline_into(page(), None, &client, &host, &origin.upstream()).await;

        assert!(out.contains("<title>Origin Title</title>"), "{out}");
        // The document, the redirect target, then the favicon it declares.
        assert_eq!(origin.paths().await, vec!["/", "/en/", "/favicon.ico"]);
    }

    #[tokio::test]
    async fn refuses_cross_origin_redirect() {
        let origin = start_origin(|path| match path {
            "/" => (
                302,
                vec![("location", "http://169.254.169.254/latest/meta-data/".into())],
                Vec::new(),
            ),
            _ => (200, vec![("content-type", "text/html".into())], HTML.as_bytes().to_vec()),
        })
        .await;

        let client = test_client();
        let host = "crossorigin.example";
        // Unreachable origins aren't cached, so this returns promptly with
        // the host as the title rather than the placeholder's.
        let out = inline_into(page(), None, &client, host, &origin.upstream()).await;

        assert!(out.contains(&format!("<title>{host}</title>")), "{out}");
        assert_eq!(origin.paths().await, vec!["/"], "redirect was followed off-origin");
    }

    #[tokio::test]
    async fn drops_svg_favicon() {
        let origin = start_origin(|path| match path {
            "/" => (
                200,
                vec![("content-type", "text/html".into())],
                HTML.replace("/favicon.ico", "/icon.svg").into_bytes(),
            ),
            "/icon.svg" => (
                200,
                vec![("content-type", "image/svg+xml".into())],
                b"<svg onload=\"alert(1)\"/>".to_vec(),
            ),
            _ => (404, vec![], Vec::new()),
        })
        .await;

        let client = test_client();
        let host = "svgicon.example";
        let upstream = origin.upstream();

        let out = inline_into(page(), None, &client, host, &upstream).await;
        assert!(!out.contains("/__ng/favicon.ico"), "svg served as favicon: {out}");
        assert!(favicon(None, &client, host, &upstream).await.is_none());
    }

    #[tokio::test]
    async fn non_html_origin_yields_no_metadata() {
        // Markup that *would* scrape, served under a non-HTML media type: the
        // content type alone must stop it.
        let markup = HTML.as_bytes().to_vec();
        let origin = start_origin(move |_| {
            (200, vec![("content-type", "application/json".into())], markup.clone())
        })
        .await;

        let client = test_client();
        let host = "jsononly.example";
        let out = inline_into(page(), None, &client, host, &origin.upstream()).await;
        assert!(
            out.contains(&format!("<title>{host}</title>")),
            "metadata was scraped from a non-HTML response: {out}"
        );
        assert!(!out.contains("Origin Title"), "{out}");
        assert!(!out.contains("og:description"), "{out}");
    }

    #[tokio::test]
    async fn missing_content_type_yields_no_metadata() {
        let markup = HTML.as_bytes().to_vec();
        let origin = start_origin(move |_| (200, vec![], markup.clone())).await;

        let client = test_client();
        let host = "notype.example";
        let out = inline_into(page(), None, &client, host, &origin.upstream()).await;
        assert!(
            out.contains(&format!("<title>{host}</title>")),
            "metadata was scraped without a declared content type: {out}"
        );
    }

    /// The favicon is fetched from the origin too, so an HTML body served at
    /// the icon URL must not be turned into an `image/*` response.
    #[tokio::test]
    async fn html_served_as_favicon_is_refused() {
        let origin = start_origin(|path| match path {
            "/" => (
                200,
                vec![("content-type", "text/html".into())],
                HTML.replace("/favicon.ico", "/icon").into_bytes(),
            ),
            "/icon" => (
                200,
                vec![("content-type", "text/html".into())],
                b"<html><body>not an icon</body></html>".to_vec(),
            ),
            _ => (404, vec![], Vec::new()),
        })
        .await;

        let client = test_client();
        let host = "htmlicon.example";
        let upstream = origin.upstream();

        let out = inline_into(page(), None, &client, host, &upstream).await;
        assert!(!out.contains("/__ng/favicon.ico"), "served HTML as an icon: {out}");
        assert!(favicon(None, &client, host, &upstream).await.is_none());
    }
}

/// Reproduces the live `root-workspace.net` interstitial end to end, from the
/// origin head captured off the wire, through the fetch-independent half of
/// `inline_into`. This is the case that shipped broken: the marker was cleared
/// before it could be filled, and `&#x27;` rendered literally.
#[cfg(test)]
mod live_regression {
    use super::*;

    /// The real `<head>` of root-workspace.net's root document (Ghost 6.41).
    const REAL_HEAD: &str = r#"<head>

    <title>root://workspace</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="We&#x27;re an independent group making hardware, software, and security tools for tech enthusiasts.">
    <meta name="referrer" content="no-referrer-when-downgrade">
    <meta property="og:site_name" content="root://workspace">
    <meta property="og:type" content="website">
    <meta property="og:title" content="root://workspace">
    <meta property="og:description" content="We&#x27;re an independent group making hardware, software, and security tools for tech enthusiasts.">
    <meta property="og:url" content="https://root-workspace.net/">
    <meta name="twitter:card" content="summary">
    <meta name="twitter:title" content="root://workspace">
    <meta name="twitter:description" content="We&#x27;re an independent group making hardware, software, and security tools for tech enthusiasts.">
    <meta name="twitter:url" content="https://root-workspace.net/">
    <meta name="generator" content="Ghost 6.41">
    <link rel="icon" href="https://root-workspace.net/content/images/size/w256h256/2026/01/Untitled-design_rounded.png" type="image/png">
</head>"#;

    #[test]
    fn real_origin_produces_a_usable_embed() {
        let meta = scrape(REAL_HEAD);

        assert_eq!(meta.title.as_deref(), Some("root://workspace"));
        // Ghost serves the icon as an absolute same-origin URL.
        assert_eq!(
            meta.icon_url.as_deref(),
            Some("https://root-workspace.net/content/images/size/w256h256/2026/01/Untitled-design_rounded.png")
        );
        assert_eq!(
            same_origin_path(meta.icon_url.as_deref().unwrap(), "root-workspace.net").as_deref(),
            Some("/content/images/size/w256h256/2026/01/Untitled-design_rounded.png")
        );

        // The rendered page must carry the metadata the marker was meant to
        // hold. `icon` is set here as the fetch would.
        let mut meta = meta;
        meta.icon = Some((Bytes::from_static(b"png"), "image/png"));
        let page = crate::challenge_html("deadbeef");
        let out = inject_for_test(page, &meta, "root-workspace.net");

        assert!(out.contains("<title>root://workspace</title>"), "{out}");
        assert!(!out.contains("{{NG_META}}"), "marker reached the client: {out}");
        assert!(
            out.contains(r#"<link rel="icon" href="/__ng/favicon.ico">"#),
            "favicon not advertised: {out}"
        );

        // The description must render as prose, not as an entity.
        assert!(out.contains("We're an independent group"), "{out}");
        assert!(!out.contains("&#x27;"), "raw entity reached the embed: {out}");
        // ...and it must be escaped for its attribute context.
        assert!(out.contains(r#"content="We're an independent group"#), "{out}");

        // Non-descriptive tags stay out.
        assert!(!out.contains("charset=utf-8"), "{out}");
        assert!(!out.contains("generator"), "{out}");
        assert!(!out.contains("twitter:url"), "{out}");
        // The origin's intra-site canonical is dropped for NekoGuard's own.
        assert!(!out.contains(r#"property="og:url""#), "{out}");
        // The small card is upgraded so the embed renders large.
        assert!(out.contains(r#"content="summary_large_image""#), "{out}");
        assert!(!out.contains(r#"content="summary""#), "{out}");
    }

    /// `inline_into` minus the network: same splice, same fallbacks.
    fn inject_for_test(page: String, meta: &Meta, host: &str) -> String {
        let mut inject = String::new();
        for tag in &meta.tags {
            inject.push_str(tag);
        }
        if meta.icon.is_some() {
            inject.push_str(FAVICON_LINK);
        }
        let title = meta.title.clone().unwrap_or_else(|| host.to_string());
        replace_title(&page, &title).replacen("{{NG_META}}", &inject, 1)
    }
}


/// Exercises the Redis path against a fake server speaking enough RESP to
/// answer the commands `embed` issues. The cache wiring — key shape, the TTL
/// it sets, the JSON it stores, and the read-through order — is what the
/// replication story rests on, and none of it runs with `ctx: None`.
#[cfg(test)]
mod redis_tests {
    use super::*;
    use http_body_util::Full;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::Response;
    use hyper_tls::HttpsConnector;
    use hyper_util::client::legacy::{connect::HttpConnector, Client};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const HTML_ONE: &str = r#"<head><title>First Title</title>
        <meta name="description" content="first description">
        <link rel="icon" href="/favicon.ico"></head>"#;

    const HTML_TWO: &str = r#"<head><title>Second Title</title>
        <meta name="description" content="second description">
        <link rel="icon" href="/favicon.ico"></head>"#;

    /// What the fake Redis saw, and what it holds.
    #[derive(Default)]
    struct Store {
        data: Mutex<std::collections::HashMap<String, String>>,
        log: Mutex<Vec<Vec<String>>>,
    }

    impl Store {
        async fn commands(&self) -> Vec<Vec<String>> {
            self.log.lock().await.clone()
        }
        async fn keys_set(&self) -> Vec<String> {
            self.commands()
                .await
                .into_iter()
                .filter(|c| c.first().map(|s| s.eq_ignore_ascii_case("set")).unwrap_or(false))
                .map(|c| c[1].clone())
                .collect()
        }
        async fn get(&self, key: &str) -> Option<String> {
            self.data.lock().await.get(key).cloned()
        }
        async fn seed(&self, key: &str, value: &str) {
            self.data.lock().await.insert(key.to_string(), value.to_string());
        }
    }

    fn encode_bulk(s: &str) -> Vec<u8> {
        format!("${}\r\n{}\r\n", s.len(), s).into_bytes()
    }

    /// Read one RESP array of bulk strings.
    async fn read_command<R: AsyncReadExt + Unpin>(r: &mut R) -> Option<Vec<String>> {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        // Header line: *<count>. Push before testing, or the byte that
        // completes the line is tested against the previous one and eaten.
        loop {
            if r.read(&mut byte).await.ok()? == 0 {
                return None;
            }
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n") {
                break;
            }
        }
        let count: usize = String::from_utf8_lossy(&buf[1..buf.len() - 2]).parse().ok()?;

        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let mut len_line = Vec::new();
            loop {
                if r.read(&mut byte).await.ok()? == 0 {
                    return None;
                }
                len_line.push(byte[0]);
                if len_line.ends_with(b"\r\n") {
                    break;
                }
            }
            let len: usize = String::from_utf8_lossy(&len_line[1..len_line.len() - 2])
                .parse()
                .ok()?;
            let mut val = vec![0u8; len + 2];
            r.read_exact(&mut val).await.ok()?;
            val.truncate(len);
            out.push(String::from_utf8_lossy(&val).to_string());
        }
        Some(out)
    }

    /// Serves RESP over TCP; returns its address and the shared store.
    async fn start_redis() -> (SocketAddr, Arc<Store>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let store = Arc::new(Store::default());
        let shared = Arc::clone(&store);

        tokio::spawn(async move {
            loop {
                let Ok((mut tcp, _)) = listener.accept().await else {
                    return;
                };
                let store = Arc::clone(&shared);
                tokio::spawn(async move {
                    while let Some(cmd) = read_command(&mut tcp).await {
                        if cmd.is_empty() {
                            continue;
                        }
                        store.log.lock().await.push(cmd.clone());
                        let verb = cmd[0].to_ascii_uppercase();
                        let reply: Vec<u8> = match verb.as_str() {
                            "GET" => match store.data.lock().await.get(&cmd[1]) {
                                Some(v) => encode_bulk(v),
                                None => b"$-1\r\n".to_vec(),
                            },
                            "SET" => {
                                store.data.lock().await.insert(cmd[1].clone(), cmd[2].clone());
                                b"+OK\r\n".to_vec()
                            }
                            // Handshake and anything else: succeed quietly.
                            _ => b"+OK\r\n".to_vec(),
                        };
                        if tcp.write_all(&reply).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });

        (addr, store)
    }

    async fn ctx_for(addr: SocketAddr) -> EmbedCtx {
        let client = redis::Client::open(format!("redis://{addr}")).expect("redis url");
        let manager = client.get_connection_manager().await.expect("connect to fake redis");
        EmbedCtx::new(manager)
    }

    /// An HTTP origin whose body can be swapped between requests.
    async fn start_origin() -> (String, Arc<Mutex<&'static str>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let body: Arc<Mutex<&'static str>> = Arc::new(Mutex::new(HTML_ONE));
        let shared = Arc::clone(&body);

        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let body = Arc::clone(&shared);
                tokio::spawn(async move {
                    let service = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let body = Arc::clone(&body);
                        async move {
                            let path = req.uri().path().to_string();
                            let (ct, bytes) = if path == "/favicon.ico" {
                                ("image/png", b"icon".to_vec())
                            } else {
                                ("text/html; charset=utf-8", body.lock().await.as_bytes().to_vec())
                            };
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .header("content-type", ct)
                                    .body(Full::new(Bytes::from(bytes)))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(tcp), service)
                        .await;
                });
            }
        });

        (format!("http://127.0.0.1:{port}"), body)
    }

    fn test_client() -> ProxyClient {
        let tls = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        Client::builder(TokioExecutor::new()).build(HttpsConnector::from((http, tls.into())))
    }

    fn page() -> String {
        "<html><head><title>Verifying your connection</title>{{NG_META}}</head><body>x</body></html>"
            .to_string()
    }

    #[tokio::test]
    async fn writes_a_five_minute_entry_under_a_host_scoped_key() {
        let (redis, store) = start_redis().await;
        let (upstream, _) = start_origin().await;
        let ctx = ctx_for(redis).await;
        let client = test_client();
        let host = "writes.example";

        let _ = inline_into(page(), Some(&ctx), &client, host, &upstream).await;

        let set = store
            .commands()
            .await
            .into_iter()
            .find(|c| c[0].eq_ignore_ascii_case("SET"))
            .expect("no SET reached redis");

        assert_eq!(set[1], format!("nekoguard:embed:{host}"));
        // TTL is passed as the trailing EX argument.
        assert_eq!(set[3].to_ascii_uppercase(), "EX");
        assert_eq!(set[4], "300");

        let stored = store.get(&set[1]).await.expect("entry absent");
        let parsed: CachedMeta = serde_json::from_str(&stored).expect("entry not JSON");
        assert_eq!(parsed.title.as_deref(), Some("First Title"));
        assert!(parsed.tags.iter().any(|t| t.contains("first description")));
        assert_eq!(parsed.icon.as_deref(), Some(b"icon".as_slice()));
        assert_eq!(parsed.icon_mime.as_deref(), Some("image/png"));
    }

    /// The point of the change: a replica that has never fetched still renders
    /// full metadata, because another replica put it in Redis.
    #[tokio::test]
    async fn a_cold_replica_renders_from_redis_without_fetching() {
        let (redis, store) = start_redis().await;
        let (upstream, body) = start_origin().await;
        let ctx = ctx_for(redis).await;
        let client = test_client();
        let host = "coldreplica.example";

        // Another replica's entry, already in Redis.
        let seeded = CachedMeta {
            title: Some("Seeded Title".into()),
            tags: vec![r#"<meta name="description" content="seeded description">"#.into()],
            icon: Some(b"icon".into()),
            icon_mime: Some("image/png".into()),
        };
        store
            .seed(&cache_key(host), &serde_json::to_string(&seeded).unwrap())
            .await;

        // Origin is serving *different* content; if it were consulted the
        // title would give it away.
        *body.lock().await = HTML_TWO;

        let out = inline_into(page(), Some(&ctx), &client, host, &upstream).await;

        assert!(out.contains("<title>Seeded Title</title>"), "{out}");
        assert!(out.contains("seeded description"), "{out}");
        assert!(out.contains(FAVICON_LINK), "{out}");
        assert!(!out.contains("Second Title"), "origin was fetched: {out}");
        assert!(
            store.keys_set().await.is_empty(),
            "cold replica wrote instead of reading through"
        );
    }

    /// A cold replica asked for the favicon serves the cached icon and does
    /// not fetch one of its own.
    #[tokio::test]
    async fn cold_replica_serves_the_cached_icon() {
        let (redis, store) = start_redis().await;
        let (upstream, _) = start_origin().await;
        let ctx = ctx_for(redis).await;
        let client = test_client();
        let host = "coldicon.example";

        store
            .seed(
                &cache_key(host),
                &serde_json::to_string(&CachedMeta {
                    title: Some("T".into()),
                    tags: vec![],
                    icon: Some(b"cached-icon".into()),
                    icon_mime: Some("image/png".into()),
                })
                .unwrap(),
            )
            .await;

        let (bytes, mime) = favicon(Some(&ctx), &client, host, &upstream)
            .await
            .expect("favicon from cache");
        assert_eq!(&bytes[..], b"cached-icon");
        assert_eq!(mime, "image/png");
    }

    /// With nothing in either cache, the favicon route must not fetch — a
    /// crawler asking for an icon it was never told about shouldn't be able to
    /// drive traffic to the origin.
    #[tokio::test]
    async fn favicon_without_a_cache_entry_does_not_fetch() {
        let (redis, store) = start_redis().await;
        let (upstream, _) = start_origin().await;
        let ctx = ctx_for(redis).await;
        let client = test_client();

        assert!(favicon(Some(&ctx), &client, "neverfetched.example", &upstream)
            .await
            .is_none());
        assert!(store.keys_set().await.is_empty(), "an unrequested fetch was cached");
    }

    /// An entry whose icon type is unrecognised is dropped on read rather than
    /// being served under a guessed content type.
    #[tokio::test]
    async fn unreadable_icon_type_is_dropped_not_guessed() {
        let (redis, store) = start_redis().await;
        let (upstream, _) = start_origin().await;
        let ctx = ctx_for(redis).await;
        let client = test_client();
        let host = "badmime.example";

        store
            .seed(
                &cache_key(host),
                &serde_json::to_string(&CachedMeta {
                    title: Some("T".into()),
                    tags: vec![r#"<meta name="description" content="d">"#.into()],
                    icon: Some(b"<svg onload=alert(1)/>".into()),
                    icon_mime: Some("image/svg+xml".into()),
                })
                .unwrap(),
            )
            .await;

        assert!(favicon(Some(&ctx), &client, host, &upstream).await.is_none());
        // The rest of the entry still renders.
        let out = inline_into(page(), Some(&ctx), &client, host, &upstream).await;
        assert!(out.contains("<title>T</title>"), "{out}");
        assert!(!out.contains(FAVICON_LINK), "{out}");
    }

    /// A corrupt entry is a miss, not a crash, and is replaced by a fetch.
    #[tokio::test]
    async fn corrupt_entry_is_refetched() {
        let (redis, store) = start_redis().await;
        let (upstream, _) = start_origin().await;
        let ctx = ctx_for(redis).await;
        let client = test_client();
        let host = "corrupt.example";

        store.seed(&cache_key(host), "{not json").await;

        let out = inline_into(page(), Some(&ctx), &client, host, &upstream).await;
        assert!(out.contains("First Title"), "{out}");
        // ...and the bad value is overwritten with a good one.
        let stored = store.get(&cache_key(host)).await.unwrap();
        assert!(serde_json::from_str::<CachedMeta>(&stored).is_ok());
    }

    /// With Redis unreachable, the interstitial still renders from the origin
    /// rather than failing closed.
    #[tokio::test]
    async fn unreachable_redis_falls_through_to_the_origin() {
        let (upstream, _) = start_origin().await;
        let client = test_client();

        // A port nothing is listening on.
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = dead.local_addr().unwrap();
        drop(dead);

        let redis_client = redis::Client::open(format!("redis://{addr}")).unwrap();
        let manager = match redis_client.get_connection_manager().await {
            Ok(m) => m,
            // ConnectionManager connects lazily; a failure here is equally fine.
            Err(_) => {
                let out = inline_into(page(), None, &client, "deadredis.example", &upstream).await;
                assert!(out.contains("First Title"), "{out}");
                return;
            }
        };
        let ctx = EmbedCtx::new(manager);

        let out = inline_into(page(), Some(&ctx), &client, "deadredis.example", &upstream).await;
        assert!(out.contains("First Title"), "{out}");
    }

    #[test]
    fn cached_meta_round_trips() {
        let mut meta = Meta::default();
        meta.title = Some("Toolbox & Co.".into());
        meta.tags = vec![r#"<meta name="description" content="a test">"#.into()];
        meta.icon = Some((Bytes::from_static(b"\x89PNG"), "image/png"));

        let json = serde_json::to_string(&CachedMeta::from(&meta)).unwrap();
        let back = serde_json::from_str::<CachedMeta>(&json).unwrap().into_meta();

        assert_eq!(back.title, meta.title);
        assert_eq!(back.tags, meta.tags);
        assert_eq!(back.icon.as_ref().map(|(b, m)| (b.as_ref(), *m)), Some((b"\x89PNG".as_slice(), "image/png")));
        // The declared URL is fetch-time state and is not carried.
        assert!(back.icon_url.is_none());
    }

    #[test]
    fn cache_key_is_namespaced_and_host_scoped() {
        assert_eq!(cache_key("example.com"), "nekoguard:embed:example.com");
        assert_ne!(cache_key("a.example"), cache_key("b.example"));
    }
}
