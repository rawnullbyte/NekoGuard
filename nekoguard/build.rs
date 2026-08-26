use std::{env, fs};
use std::path::Path;
use minify_html::{minify, Cfg};

fn main() {
    println!("cargo:rerun-if-changed=src/challenge.html");

    let html_bytes = fs::read("src/challenge.html")
        .expect("challenge.html not found");

    let mut cfg = Cfg::new();
    cfg.minify_js = true;
    cfg.minify_css = true;
    let minified_bytes = minify(&html_bytes, &cfg);

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR environment variable missing");
    let dest = Path::new(&out_dir).join("challenge.min.html");
    
    fs::write(dest, minified_bytes)
        .expect("Failed to write minified HTML to destination");
}