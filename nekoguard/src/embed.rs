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
#[derive(Default)]
struct Meta {
    title: Option<String>,
    tags: Vec<String>,

    /// Icon URL as declared by the origin, resolved at fetch time.
    icon_url: Option<String>,

    /// Icon bytes plus the content type to serve them with.
    icon: Option<(Bytes, &'static str)>,
}

/// One origin's metadata, with the time it was fetched so it can go stale.
struct Cached {
    meta: Arc<Meta>,
    fetched: Instant,
}

/// Per-host metadata cache. Each host is locked across its own fetch, so
/// concurrent visitors solving the challenge for one origin cause a single
/// request rather than a stampede, while a slow origin holds up only itself.
static CACHE: LazyLock<Mutex<HashMap<String, Arc<Mutex<Option<Cached>>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Splice the origin's metadata into a rendered interstitial page: the
/// origin's title, its descriptive `<meta>` tags in place of `{{NG_META}}`,
/// and a favicon link when the origin has one.
///
/// A page with no `{{NG_META}}` marker is returned with only its title
/// replaced, so the interstitial still renders if the marker is ever lost.
pub(crate) async fn inline_into(
    page: String,
    client: &ProxyClient,
    host: &str,
    upstream: &str,
) -> String {
    let host = normalize_host(host);

    // A page with no usable <title> renders as a blank link, so fall back to
    // the bare host rather than to the placeholder's title.
    let Some(meta) = load(&host, client, upstream).await else {
        return replace_title(&page, &host);
    };

    let mut inject = String::new();
    for tag in &meta.tags {
        inject.push_str(tag);
    }
    if meta.icon.is_some() {
        inject.push_str(r#"<link rel="icon" href="/__ng/favicon.ico">"#);
    }
    let title = meta.title.clone().unwrap_or_else(|| host.clone());

    replace_title(&page, &title).replacen("{{NG_META}}", &inject, 1)
}

/// The origin's favicon, for the interstitial to advertise as
/// `/__ng/favicon.ico`. `None` when the origin declares none.
pub(crate) async fn favicon(
    client: &ProxyClient,
    host: &str,
    upstream: &str,
) -> Option<(Bytes, &'static str)> {
    let host = normalize_host(host);
    load(&host, client, upstream).await?.icon.clone()
}

/// Cached metadata for `host`, refetched once `CACHE_TTL` has passed so the
/// origin is touched at most once per window instead of once per visitor.
async fn load(host: &str, client: &ProxyClient, upstream: &str) -> Option<Arc<Meta>> {
    let slot = {
        let mut cache = CACHE.lock().await;
        // The map lock is held only long enough to find or create the slot.
        Arc::clone(
            cache
                .entry(host.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(None))),
        )
    };

    let mut slot = slot.lock().await;
    if let Some(entry) = slot.as_ref() {
        if entry.fetched.elapsed() < CACHE_TTL {
            return Some(Arc::clone(&entry.meta));
        }
    }

    // An unreachable origin is not cached: the next visitor retries rather
    // than being handed five minutes of nothing.
    let meta = Arc::new(fetch(client, host, upstream).await?);
    *slot = Some(Cached { meta: Arc::clone(&meta), fetched: Instant::now() });
    Some(meta)
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

    // NekoGuard answers canonical links itself, pointing at the protected
    // origin; the origin's own value would name an address the embedder can't
    // reach.
    if lower == "og:url" {
        return;
    }
    // The origin's own card type is usually too small for the embed it lands
    // in; the interstitial is a full page, so prefer the large card.
    if lower == "twitter:card" {
        meta.tags.push(r#"<meta name="twitter:card" content="summary_large_image">"#.to_string());
        return;
    }

    meta.tags.push(format!(
        r#"<meta {key}="{}" content="{}">"#,
        html_escape(value),
        html_escape(content)
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

fn decode(html: &str) -> String {
    let escaped = html
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'");
    // `&amp;` last so "&amp;lt;" doesn't come out as "<".
    escaped.replace("&amp;", "&")
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
        assert!(!meta.tags[0].contains("<script>"), "raw markup survived: {}", meta.tags[0]);
        // The entity is inert text, so it is escaped rather than decoded.
        assert!(meta.tags[0].contains("&amp;quot;&gt;&lt;script&gt;"), "{}", meta.tags[0]);
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
        assert_eq!(decode("&amp;lt;script&amp;gt;"), "&lt;script&gt;");
        assert_eq!(decode("a &lt;b&gt; c"), "a <b> c");
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

        let out = inline_into(page(), &client, host, &upstream).await;

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
        let (icon, mime) = favicon(&client, host, &upstream).await.expect("favicon");
        assert_eq!(mime, "image/x-icon");
        assert_eq!(icon.as_ref(), ICON);

        // A second render inside the window must not touch the origin again.
        let _ = inline_into(page(), &client, host, &upstream).await;
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
        let out = inline_into(page(), &client, &host, &origin.upstream()).await;

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
        let out = inline_into(page(), &client, host, &origin.upstream()).await;

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

        let out = inline_into(page(), &client, host, &upstream).await;
        assert!(!out.contains("/__ng/favicon.ico"), "svg served as favicon: {out}");
        assert!(favicon(&client, host, &upstream).await.is_none());
    }

    #[tokio::test]
    async fn non_html_origin_yields_no_metadata() {
        let origin = start_origin(|_| {
            (200, vec![("content-type", "application/json".into())], b"{}".to_vec())
        })
        .await;

        let client = test_client();
        let host = "jsononly.example";
        let out = inline_into(page(), &client, host, &origin.upstream()).await;
        assert!(out.contains(&format!("<title>{host}</title>")), "{out}");
    }
}
