//! Makes sure the directory the web UI is embedded from exists, so the
//! backend compiles (and its tests run) on a fresh checkout without a
//! frontend build; web.rs then serves a hint instead of the UI. Also makes
//! cargo rebuild the binary when the UI build changes.

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let dist = std::path::Path::new(&manifest).join("ui").join("dist");
    if let Err(e) = std::fs::create_dir_all(&dist) {
        println!("cargo:warning=could not create {}: {e}", dist.display());
    }
    println!("cargo:rerun-if-changed=ui/dist");
}
