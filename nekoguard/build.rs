use std::{env, fs};
use std::path::Path;
use minify_html::{minify, Cfg};

fn main() {
    println!("cargo:rerun-if-changed=src/challenge.html");
    println!("cargo:rerun-if-changed=src/assets/guard.js");

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR environment variable missing");
    let out = Path::new(&out_dir);

    minify_challenge(out);
    minify_guard(out);
}

/// The PoW interstitial. Minified as HTML, which also collapses its inline
/// CSS and JS.
fn minify_challenge(out: &Path) {
    let html_bytes = fs::read("src/challenge.html")
        .expect("challenge.html not found");

    let mut cfg = Cfg::new();
    cfg.minify_js = true;
    cfg.minify_css = true;
    let minified_bytes = minify(&html_bytes, &cfg);

    fs::write(out.join("challenge.min.html"), minified_bytes)
        .expect("Failed to write minified HTML to destination");
}

/// The clearance-renewal script, which is spliced into every proxied document.
///
/// Shipped minified because its size is paid on every page load — the source
/// is commented for the people reading it in the repository, not for browsers.
fn minify_guard(out: &Path) {
    let source = fs::read("src/assets/guard.js").expect("guard.js not found");

    // `Global` rather than `Module`: the file is a plain script wrapped in an
    // IIFE, with no import/export, which is how it is delivered.
    let session = minify_js::Session::new();
    let mut minified = Vec::new();

    match minify_js::minify(
        &session,
        minify_js::TopLevelMode::Global,
        &source,
        &mut minified,
    ) {
        Ok(()) => {}
        Err(err) => {
            // Always fail the build. Falling back to the unminified source
            // would silently ship the commented original, and a minifier that
            // chokes on this file is something to fix, not paper over.
            panic!("minify-js rejected src/assets/guard.js: {err:?}");
        }
    }

    // A minifier that returns the input unchanged (or nearly) is a bug worth
    // catching here rather than discovering as excess page weight.
    assert!(
        minified.len() < source.len(),
        "minify-js did not shrink guard.js ({} -> {})",
        source.len(),
        minified.len()
    );

    fs::write(out.join("guard.min.js"), minified)
        .expect("Failed to write minified JS to destination");
}
