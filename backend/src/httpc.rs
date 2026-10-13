//! Outbound HTTP clients. rustls needs a process-wide crypto provider; it is
//! installed once here so every client (notifications, plugin downloads,
//! scans) can be built from any thread.

use std::sync::Once;
use std::time::Duration;

static INIT: Once = Once::new();

/// Installs the ring crypto provider (idempotent).
pub fn init_tls() {
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub const USER_AGENT: &str = concat!("Caddymium/", env!("CARGO_PKG_VERSION"));

/// A client builder with the panel's defaults.
pub fn builder() -> reqwest::ClientBuilder {
    init_tls();
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
}

/// A client with the panel's defaults.
#[allow(dead_code)]
pub fn client() -> reqwest::Client {
    builder().build().expect("http client")
}
