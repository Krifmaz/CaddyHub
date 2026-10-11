use serde::Serialize;
use std::collections::BTreeMap;

use super::DNS_PROVIDERS;
use super::version::Version;

/// Describes the running Caddy binary.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Capabilities {
    #[serde(skip)]
    pub version: Version,
    #[serde(rename = "version")]
    pub version_s: String,
    #[serde(skip)]
    pub modules: std::collections::HashSet<String>,
    /// Maps module ID -> "package@version" when known.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub packages: BTreeMap<String, String>,
    pub detected: bool,
}

impl Capabilities {
    /// Reports whether a module is compiled in. If capabilities were never
    /// detected (Caddy unreachable), everything is assumed present so the
    /// generator doesn't silently drop config; validation will catch errors.
    pub fn has_module(&self, id: &str) -> bool {
        if !self.detected {
            return true;
        }
        self.modules.contains(id)
    }

    /// Sorted module IDs.
    #[allow(dead_code)]
    pub fn module_list(&self) -> Vec<String> {
        let mut out: Vec<String> = self.modules.iter().cloned().collect();
        out.sort();
        out
    }

    /// Evaluates a feature against capabilities.
    pub fn check(&self, f: &Feature) -> FeatureStatus {
        let mut st = FeatureStatus {
            feature: f.clone(),
            available: true,
            reason: String::new(),
        };
        if !self.version.at_least(f.min_version) {
            st.available = false;
            st.reason = format!("requires Caddy {} or newer", f.min_version);
            return st;
        }
        for m in f.modules {
            if !self.has_module(m) {
                st.available = false;
                st.reason = if !f.plugin.is_empty() {
                    format!("module {m} not installed (plugin {})", f.plugin)
                } else {
                    format!("module {m} not available in this Caddy build")
                };
                return st;
            }
        }
        st
    }

    /// Convenience for generator checks.
    pub fn has(&self, feature_id: &str) -> bool {
        match feature_by_id(feature_id) {
            Some(f) => self.check(f).available,
            None => false,
        }
    }

    /// Every feature with availability.
    pub fn all_feature_status(&self) -> Vec<FeatureStatus> {
        FEATURES.iter().map(|f| self.check(f)).collect()
    }

    /// Non-standard packages compiled into the binary: package path ->
    /// version (as reported by `caddy list-modules --packages --versions`).
    pub fn plugin_packages(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for pv in self.packages.values() {
            let (path, ver) = match pv.rsplit_once('@') {
                Some((p, v)) => (p.to_string(), v.to_string()),
                None => (pv.clone(), String::new()),
            };
            if path == "github.com/caddyserver/caddy/v2" || path.is_empty() {
                continue;
            }
            // Major-version suffixes (hetzner/v2) are a Go module detail; the
            // download service and the UI use the bare path.
            out.entry(strip_major(&path).to_string()).or_insert(ver);
        }
        out
    }
}

/// An optional GUI capability backed by a directive/module.
#[derive(Debug, Clone, Serialize)]
pub struct Feature {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub min_version: &'static str,
    /// all required
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub modules: &'static [&'static str],
    /// package path for the download API / xcaddy if not standard
    #[serde(skip_serializing_if = "str::is_empty")]
    pub plugin: &'static str,
}

/// A feature annotated with availability.
#[derive(Debug, Clone, Serialize)]
pub struct FeatureStatus {
    #[serde(flatten)]
    pub feature: Feature,
    pub available: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

const fn f(id: &'static str, name: &'static str, modules: &'static [&'static str]) -> Feature {
    Feature {
        id,
        name,
        description: "",
        min_version: "",
        modules,
        plugin: "",
    }
}

/// The registry of optional features. Standard directives are listed too,
/// with module requirements, so that a future Caddy that drops or renames
/// something is detected rather than producing broken config.
pub static FEATURES: &[Feature] = &[
    f(
        "reverse_proxy",
        "Reverse proxy",
        &["http.handlers.reverse_proxy"],
    ),
    f(
        "file_server",
        "Static files",
        &["http.handlers.file_server"],
    ),
    f(
        "encode_zstd",
        "Zstandard compression",
        &["http.encoders.zstd"],
    ),
    f("encode_gzip", "Gzip compression", &["http.encoders.gzip"]),
    Feature {
        min_version: "v2.8.0",
        ..f(
            "basic_auth",
            "Basic auth",
            &["http.handlers.authentication"],
        )
    },
    f(
        "forward_auth",
        "Forward auth",
        &["http.handlers.reverse_proxy"],
    ),
    Feature {
        min_version: "v2.7.0",
        ..f(
            "client_ip",
            "Client IP matcher",
            &["http.matchers.client_ip"],
        )
    },
    Feature {
        min_version: "v2.10.0",
        ..f("metrics", "Prometheus metrics", &["admin.api.metrics"])
    },
    Feature {
        min_version: "v2.8.0",
        ..f("file_placeholder", "{file.*} placeholder for secrets", &[])
    },
    Feature {
        description: "Per-site request rate limits (caddy-ratelimit)",
        plugin: "github.com/mholt/caddy-ratelimit",
        ..f("rate_limit", "Rate limiting", &["http.handlers.rate_limit"])
    },
    Feature {
        description: "Block IPs using CrowdSec decisions",
        plugin: "github.com/hslatman/caddy-crowdsec-bouncer",
        ..f(
            "crowdsec",
            "CrowdSec bouncer",
            &["crowdsec", "http.handlers.crowdsec"],
        )
    },
    Feature {
        plugin: "github.com/mholt/caddy-l4",
        ..f("layer4", "Layer 4 (TCP/UDP) proxy", &["layer4"])
    },
    Feature {
        description: "HTTP(S) forward proxy with optional authentication (forwardproxy)",
        plugin: "github.com/caddyserver/forwardproxy",
        ..f(
            "forward_proxy",
            "Forward proxy",
            &["http.handlers.forward_proxy"],
        )
    },
    Feature {
        description: "Keep DNS records pointed at this server's public IP (caddy-dynamicdns)",
        plugin: "github.com/mholt/caddy-dynamicdns",
        ..f("dynamic_dns", "Dynamic DNS", &["dynamic_dns"])
    },
];

/// Returns a feature by id.
pub fn feature_by_id(id: &str) -> Option<&'static Feature> {
    FEATURES.iter().find(|f| f.id == id)
}

/// A curated, installable module for the plugin manager. The live catalog
/// from caddyserver.com is merged with these for descriptions and
/// categories.
#[derive(Debug, Clone, Serialize)]
pub struct Plugin {
    /// package path for the download API / xcaddy --with
    pub path: String,
    pub name: String,
    /// dns, security, proxy, other
    pub category: String,
    /// a module ID it registers (for detection)
    pub module: String,
    pub description: String,
}

fn p(path: &str, name: &str, category: &str, module: &str, description: &str) -> Plugin {
    Plugin {
        path: path.into(),
        name: name.into(),
        category: category.into(),
        module: module.into(),
        description: description.into(),
    }
}

/// The curated catalog: every DNS provider plus featured extras.
pub fn plugins() -> Vec<Plugin> {
    let mut out = vec![
        p(
            "github.com/mholt/caddy-dynamicdns",
            "Dynamic DNS",
            "network",
            "dynamic_dns",
            "Keeps your DNS records updated with this server's public IP (configure under Dynamic DNS)",
        ),
        p(
            "github.com/caddyserver/forwardproxy",
            "Forward proxy",
            "proxy",
            "http.handlers.forward_proxy",
            "HTTP(S) forward proxy with authentication, ACLs and probe resistance (a “Forward proxy” site type)",
        ),
        p(
            "github.com/mholt/caddy-ratelimit",
            "Rate limit",
            "security",
            "http.handlers.rate_limit",
            "Per-site request rate limits",
        ),
        p(
            "github.com/hslatman/caddy-crowdsec-bouncer",
            "CrowdSec bouncer",
            "security",
            "http.handlers.crowdsec",
            "Block IPs using CrowdSec decisions, plus the AppSec WAF component",
        ),
        p(
            "github.com/mholt/caddy-l4",
            "Layer 4",
            "proxy",
            "layer4",
            "TCP/UDP proxying (use raw global options to configure)",
        ),
        p(
            "github.com/caddyserver/transform-encoder",
            "Transform log encoder",
            "other",
            "caddy.logging.encoders.transform",
            "Custom log formats",
        ),
        p(
            "github.com/caddyserver/cache-handler",
            "Cache",
            "other",
            "http.handlers.cache",
            "HTTP caching (Souin)",
        ),
        p(
            "github.com/caddyserver/replace-response",
            "Replace response",
            "other",
            "http.handlers.replace_response",
            "Rewrite response bodies",
        ),
        p(
            "github.com/greenpau/caddy-security",
            "Security (auth portal)",
            "security",
            "http.handlers.authenticator",
            "Authentication portal, OAuth/OIDC, SAML, JWT",
        ),
        p(
            "github.com/mholt/caddy-webdav",
            "WebDAV",
            "other",
            "http.handlers.webdav",
            "Serve a folder over WebDAV",
        ),
    ];
    for d in DNS_PROVIDERS {
        out.push(p(
            d.plugin,
            &format!("{} DNS", d.name),
            "dns",
            &d.module(),
            "DNS-01 challenge provider (also usable for Dynamic DNS)",
        ));
    }
    out
}

/// Looks up a curated catalog entry.
#[allow(dead_code)]
pub fn plugin_by_path(path: &str) -> Option<Plugin> {
    plugins().into_iter().find(|p| p.path == path)
}

/// Removes a Go major-version suffix ("…/hetzner/v2" -> "…/hetzner").
pub fn strip_major(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some((base, last))
            if last.len() > 1
                && last.starts_with('v')
                && last[1..].chars().all(|c| c.is_ascii_digit()) =>
        {
            base
        }
        _ => path,
    }
}
