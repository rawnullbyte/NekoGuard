//! Renewal-script injection into proxied HTML.
//!
//! A clearance cookie expires after `session.ttl`. Once it does, NekoGuard
//! answers the next request — including a background AJAX call such as Ghost's
//! draft autosave — with the PoW interstitial: a `200 text/html` document
//! where the caller expected JSON. The save fails.
//!
//! To stop that, a small renewal script is spliced into HTML documents the
//! origin serves. It renews the clearance in the background and queues
//! requests only while the session is genuinely invalid. The client half lives
//! in `src/assets/guard.js`.
//!
//! The origin almost always compresses HTML, and a script cannot be spliced
//! into compressed bytes, so a document is decoded here, mutated, and
//! re-encoded to whatever the client asked for. Everything else — JSON, JS,
//! CSS, images, unknown encodings, oversized bodies — is passed through
//! untouched, which is both the fast path and the safe one.

use flate2::read::{DeflateDecoder, GzDecoder};
use flate2::write::{DeflateEncoder, GzEncoder};
use flate2::Compression;
use std::io::{Read, Write};

/// Ceiling on a decoded document.
///
/// Enforced *while* decoding rather than after: a few tens of kilobytes of
/// Brotli can expand to gigabytes, so a check on the finished buffer would
/// already have exhausted memory. Bodies that would exceed this are left
/// untouched rather than truncated.
pub(crate) const MAX_DECOMPRESSED: usize = 4 * 1024 * 1024;

/// Brotli quality for re-encoding. Matches what origins typically serve;
/// higher costs CPU per response for no visible gain on text this size.
const BROTLI_QUALITY: u32 = 5;

/// Content encodings this module can round-trip. Anything else means the body
/// is passed through untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Encoding {
    Identity,
    Gzip,
    Deflate,
    Brotli,
}

impl Encoding {
    /// Parse a `Content-Encoding` header value.
    ///
    /// Only a single, recognised encoding round-trips; `br, gzip` stacked
    /// encodings and unknown tokens (`zstd`) return `None` so the caller
    /// leaves the body alone rather than guessing.
    pub(crate) fn from_header(value: Option<&str>) -> Option<Self> {
        // An absent header means the body is not encoded at all — identity,
        // not "unknown encoding". Only a present-but-unrecognised token is
        // treated as unhandled.
        let raw = value.unwrap_or("").trim();
        if raw.is_empty() {
            return Some(Self::Identity);
        }
        match raw.to_ascii_lowercase().as_str() {
            "identity" => Some(Self::Identity),
            "gzip" | "x-gzip" => Some(Self::Gzip),
            "deflate" => Some(Self::Deflate),
            "br" => Some(Self::Brotli),
            _ => None,
        }
    }
}

/// Whether this response is a document we should splice the script into.
///
/// Content type is the only gate that is never negotiable: injecting into a
/// JSON or JavaScript response would corrupt it, and injecting into an image
/// would be nonsense. The remaining conditions are cost and safety gates.
pub(crate) fn should_inject(
    content_type: Option<&str>,
    has_body: bool,
    within_cap: bool,
    encoding_supported: bool,
    site_bypassed: bool,
) -> bool {
    is_html(content_type) && has_body && within_cap && encoding_supported && !site_bypassed
}

/// `text/html` / `application/xhtml+xml`, exactly as elsewhere in the codebase.
fn is_html(content_type: Option<&str>) -> bool {
    let ct = content_type.unwrap_or("").trim().to_ascii_lowercase();
    ct.starts_with("text/html") || ct.starts_with("application/xhtml+xml")
}

/// Decode a document body. `None` on unsupported encoding, a corrupt stream,
/// or a decoded size over `MAX_DECOMPRESSED`.
pub(crate) fn decompress(body: &[u8], encoding: Encoding) -> Option<Vec<u8>> {
    // Identity still needs the cap applied: an uncompressed document can be
    // oversized too, and every later stage assumes the bound holds.
    if encoding == Encoding::Identity {
        return (body.len() <= MAX_DECOMPRESSED).then(|| body.to_vec());
    }

    let reader: Box<dyn Read + '_> = match encoding {
        Encoding::Gzip => Box::new(GzDecoder::new(body)),
        Encoding::Deflate => Box::new(DeflateDecoder::new(body)),
        Encoding::Brotli => Box::new(brotli::Decompressor::new(body, 4096)),
        Encoding::Identity => unreachable!("handled above"),
    };

    read_capped(reader)
}

/// Read a stream to the end, refusing to exceed `MAX_DECOMPRESSED`.
///
/// Reads one byte past the limit so a body of exactly the cap is accepted
/// while anything larger is rejected. A corrupt stream that errors partway is
/// also rejected, so a truncated result can never be re-encoded and served.
fn read_capped(reader: Box<dyn Read + '_>) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut limited = reader.take(MAX_DECOMPRESSED as u64 + 1);
    limited.read_to_end(&mut out).ok()?;
    (out.len() <= MAX_DECOMPRESSED).then_some(out)
}

/// Re-encode a document to the encoding the client accepted.
pub(crate) fn compress(body: Vec<u8>, encoding: Encoding) -> Option<Vec<u8>> {
    match encoding {
        Encoding::Identity => Some(body),
        Encoding::Gzip => {
            let mut out = Vec::new();
            let mut encoder = GzEncoder::new(&mut out, Compression::default());
            encoder.write_all(&body).ok()?;
            encoder.finish().ok()?;
            Some(out)
        }
        Encoding::Deflate => {
            let mut out = Vec::new();
            let mut encoder = DeflateEncoder::new(&mut out, Compression::default());
            encoder.write_all(&body).ok()?;
            encoder.finish().ok()?;
            Some(out)
        }
        Encoding::Brotli => {
            let mut out = Vec::new();
            let mut writer = brotli::CompressorWriter::new(&mut out, 4096, BROTLI_QUALITY, 22);
            writer.write_all(&body).ok()?;
            // Flush through the writer's lifetime, then take the bytes back.
            drop(writer);
            Some(out)
        }
    }
}

/// Splice `snippet` into an HTML document immediately before `</body>`.
///
/// Falls back to `</html>`, then to appending. Returns `None` only when the
/// insertion would be a no-op the caller should treat as a failure — i.e.
/// never, but the signature keeps the caller honest about handling it.
pub(crate) fn inject_into_html(html: &str, snippet: &str) -> String {
    // `to_ascii_lowercase` preserves byte offsets, so an index found in the
    // folded copy is valid in the original — the same trick `embed.rs` uses.
    let lowered = html.to_ascii_lowercase();

    if let Some(at) = lowered.rfind("</body>") {
        let mut out = String::with_capacity(html.len() + snippet.len());
        out.push_str(&html[..at]);
        out.push_str(snippet);
        out.push_str(&html[at..]);
        return out;
    }
    if let Some(at) = lowered.rfind("</html>") {
        let mut out = String::with_capacity(html.len() + snippet.len());
        out.push_str(&html[..at]);
        out.push_str(snippet);
        out.push_str(&html[at..]);
        return out;
    }

    // A fragment with no closing tags: append, so the script still runs.
    let mut out = String::with_capacity(html.len() + snippet.len());
    out.push_str(html);
    out.push_str(snippet);
    out
}

/// Whether a decoded document looks like HTML rather than, say, a stray
/// protobuf or a PDF that arrived under a `text/html` label.
///
/// A cheap sanity check before mutating: if the decode produced something that
/// isn't text, re-encoding it would serve corruption.
pub(crate) fn looks_like_html(body: &[u8]) -> bool {
    match std::str::from_utf8(body) {
        Ok(text) => {
            let head = text.trim_start().to_ascii_lowercase();
            head.starts_with("<!doctype")
                || head.starts_with("<html")
                || head.starts_with("<?xml")
                || text.contains('<')
        }
        Err(_) => false,
    }
}

/// Build the `<script>` tag that carries the renewal script.
///
/// `</script>` inside the payload would close the tag early and turn the rest
/// of the script into markup, so any occurrence is escaped before splicing.
/// The payload is the server's own asset, but escaping here means a future
/// edit to `guard.js` can't silently introduce an XSS.
pub(crate) fn script_tag(source: &str) -> String {
    let safe = source.replace("</script", "<\\/script");
    format!("<script>{safe}</script>")
}

#[cfg(test)]
mod tests {
    use super::*;

    const HTML: &str = "<!doctype html><html><head><title>T</title></head><body><p>hi</p></body></html>";

    fn round_trip(html: &str, encoding: Encoding) -> String {
        let encoded = compress(html.as_bytes().to_vec(), encoding).expect("compress");
        let decoded = decompress(&encoded, encoding).expect("decompress");
        String::from_utf8(decoded).expect("utf8")
    }

    #[test]
    fn compresses_round_trip_for_every_encoding() {
        for encoding in [Encoding::Identity, Encoding::Gzip, Encoding::Deflate, Encoding::Brotli] {
            assert_eq!(round_trip(HTML, encoding), HTML, "round trip failed for {encoding:?}");
        }
    }

    #[test]
    fn brotli_round_trips_real_ghost_markup() {
        // Ghost serves a large, highly-repetitive document; the encoding must
        // survive a body that actually compresses well.
        let big = format!("<!doctype html><html><body>{}</body></html>", "<p>hello</p>".repeat(2000));
        assert_eq!(round_trip(&big, Encoding::Brotli), big);
        assert_eq!(round_trip(&big, Encoding::Gzip), big);
    }

    #[test]
    fn encoding_header_parsing() {
        assert_eq!(Encoding::from_header(Some("gzip")), Some(Encoding::Gzip));
        assert_eq!(Encoding::from_header(Some("GZIP")), Some(Encoding::Gzip));
        assert_eq!(Encoding::from_header(Some(" x-gzip ")), Some(Encoding::Gzip));
        assert_eq!(Encoding::from_header(Some("br")), Some(Encoding::Brotli));
        assert_eq!(Encoding::from_header(Some("deflate")), Some(Encoding::Deflate));
        assert_eq!(Encoding::from_header(Some("identity")), Some(Encoding::Identity));
        assert_eq!(Encoding::from_header(Some("")), Some(Encoding::Identity));
        assert_eq!(Encoding::from_header(None), Some(Encoding::Identity));

        // Stacked and unknown encodings must not be guessed at.
        assert_eq!(Encoding::from_header(Some("br, gzip")), None);
        assert_eq!(Encoding::from_header(Some("zstd")), None);
        assert_eq!(Encoding::from_header(Some("compress")), None);
    }

    #[test]
    fn only_html_with_a_body_is_eligible() {
        let ok = |ct: Option<&str>| should_inject(ct, true, true, true, false);
        assert!(ok(Some("text/html")));
        assert!(ok(Some("text/html; charset=utf-8")));
        assert!(ok(Some("TEXT/HTML; CHARSET=UTF-8")));
        assert!(ok(Some("application/xhtml+xml")));

        // Never inject into anything else, whatever the other flags say.
        assert!(!ok(Some("application/json")));
        assert!(!ok(Some("text/javascript")));
        assert!(!ok(Some("text/css")));
        assert!(!ok(Some("image/png")));
        assert!(!ok(Some("image/svg+xml")));
        assert!(!ok(None));

        // Each remaining gate is independently binding.
        assert!(!should_inject(Some("text/html"), false, true, true, false));
        assert!(!should_inject(Some("text/html"), true, false, true, false));
        assert!(!should_inject(Some("text/html"), true, true, false, false));
        assert!(!should_inject(Some("text/html"), true, true, true, true));
    }

    #[test]
    fn sniffs_out_non_html_decoded_bodies() {
        assert!(looks_like_html(HTML.as_bytes()));
        assert!(looks_like_html(b"  \n<!DOCTYPE html><p>x"));
        assert!(looks_like_html(b"<p>fragment</p>"));
        // A decode bug serving binary must not be re-encoded as text.
        assert!(!looks_like_html(&[0xff, 0xfe, 0x00, 0x01, 0x02]));
        assert!(!looks_like_html(b"not markup at all"));
    }

    #[test]
    fn splices_before_the_closing_body_tag() {
        let out = inject_into_html(HTML, "<script>x</script>");
        assert!(out.contains("<p>hi</p><script>x</script></body>"), "{out}");
        assert!(out.ends_with("</html>"), "{out}");
        // The original document is otherwise unchanged.
        assert_eq!(out.matches("<title>").count(), 1);
    }

    #[test]
    fn splice_falls_back_through_html_then_append() {
        let no_body = "<html><head></head></html>";
        let out = inject_into_html(no_body, "<script>x</script>");
        assert!(out.contains("<script>x</script></html>"), "{out}");

        let fragment = "<p>just a fragment</p>";
        let out = inject_into_html(fragment, "<script>x</script>");
        assert!(out.ends_with("<p>just a fragment</p><script>x</script>"), "{out}");
    }

    #[test]
    fn splice_uses_the_last_closing_body_tag() {
        // A document quoting `</body>` in a script must still splice at the
        // real end, not inside the quoted text.
        let tricky = "<html><body><script>var s = '</body>';</script><p>x</p></body></html>";
        let out = inject_into_html(tricky, "MARK");
        let marker = out.find("MARK").expect("marker");
        let p = out.find("<p>x</p>").expect("paragraph");
        assert!(marker > p, "spliced too early: {out}");
        assert!(out.ends_with("MARK</body></html>"), "{out}");
    }

    #[test]
    fn splice_is_case_insensitive() {
        let out = inject_into_html("<HTML><BODY>x</body></HTML>", "MARK");
        assert!(out.contains("xMARK</body>"), "{out}");
    }

    #[test]
    fn script_tag_cannot_be_closed_early_by_its_payload() {
        let tag = script_tag("var a = 1; </script><img src=x onerror=alert(1)>");

        // Exactly one real terminator, at the very end: the parser cannot be
        // tricked into ending the script early.
        assert_eq!(tag.matches("</script>").count(), 1, "{tag}");
        assert!(tag.ends_with("</script>"));

        // The payload's own terminator is escaped. Markup like `<img>` may
        // remain, but inside a `<script>` element the content is raw text, so
        // it never becomes an element — closing the tag is the only escape.
        let body = &tag["<script>".len()..tag.len() - "</script>".len()];
        assert!(!body.contains("</script"), "raw terminator left in payload: {body}");
        assert!(body.contains(r#"<\/script"#), "{body}");
    }

    #[test]
    fn oversize_documents_are_refused_not_truncated() {
        // Brotli of a highly repetitive buffer: small compressed, huge decoded.
        let bomb = "<p>a</p>".repeat(1_500_000); // ~11 MB decoded
        let compressed = compress(bomb.into_bytes(), Encoding::Brotli).expect("compress");
        assert!(compressed.len() < 100_000, "test needs a real expansion, got {}", compressed.len());
        assert!(
            decompress(&compressed, Encoding::Brotli).is_none(),
            "decompression bomb was accepted"
        );
    }

    #[test]
    fn identity_is_capped_too() {
        let at_cap = vec![b'a'; MAX_DECOMPRESSED];
        assert!(decompress(&at_cap, Encoding::Identity).is_some(), "exactly the cap is allowed");

        let over = vec![b'a'; MAX_DECOMPRESSED + 1];
        assert!(decompress(&over, Encoding::Identity).is_none());
    }

    #[test]
    fn corrupt_streams_are_refused() {
        assert!(decompress(b"\x1b\x02not really brotli", Encoding::Brotli).is_none());
        assert!(decompress(b"\x1f\x8b garbage", Encoding::Gzip).is_none());
    }

    #[test]
    fn injected_script_survives_a_full_round_trip() {
        // The end-to-end shape: decode an encoded document, splice, re-encode,
        // decode again, and confirm the script is intact and the body valid.
        let script = script_tag("window.__ng=1;");
        let mutated = inject_into_html(HTML, &script);

        for encoding in [Encoding::Identity, Encoding::Gzip, Encoding::Deflate, Encoding::Brotli] {
            let served = compress(mutated.as_bytes().to_vec(), encoding).expect("compress");
            let received = decompress(&served, encoding).expect("decompress");
            let received = String::from_utf8(received).expect("utf8");
            assert!(received.contains("window.__ng=1;"), "script lost under {encoding:?}");
            assert!(received.contains("<p>hi</p>"), "body lost under {encoding:?}");
        }
    }
}
