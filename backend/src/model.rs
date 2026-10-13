//! The structured configuration that Caddymium owns. The SQLite store
//! persists these types and the generator turns them into a Caddyfile.
//! Nothing here is specific to any particular deployment.
//!
//! JSON field names and omission rules match the API the web UI expects.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// Site kinds.
pub const KIND_PROXY: &str = "proxy";
pub const KIND_STATIC: &str = "static";
pub const KIND_REDIRECT: &str = "redirect";
pub const KIND_RESPOND: &str = "respond";
/// An HTTP(S) forward proxy (forwardproxy plugin).
pub const KIND_FORWARD_PROXY: &str = "forward_proxy";
/// No structured handler: everything is in the raw snippet (used for
/// imported sites the importer could only partially map).
pub const KIND_NONE: &str = "none";

pub const ALL_KINDS: &[&str] = &[
    KIND_PROXY,
    KIND_STATIC,
    KIND_REDIRECT,
    KIND_RESPOND,
    KIND_FORWARD_PROXY,
    KIND_NONE,
];

// TLS modes.
pub const TLS_AUTO: &str = "auto";
pub const TLS_INTERNAL: &str = "internal";
pub const TLS_CUSTOM: &str = "custom";
pub const TLS_OFF: &str = "off";

// ACME challenge types per domain.
pub const CHALLENGE_HTTP: &str = "http-01";
pub const CHALLENGE_TLS_ALPN: &str = "tls-alpn-01";
pub const CHALLENGE_DNS: &str = "dns-01";

fn is_false(b: &bool) -> bool {
    !*b
}
fn is_zero(n: &i64) -> bool {
    *n == 0
}

/// One entry in the GUI: a set of hostnames with a handler.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Site {
    pub id: i64,
    pub name: String,
    pub hosts: Vec<String>,
    pub kind: String,
    pub enabled: bool,
    pub position: i64,
    pub tags: Vec<String>,
    pub config: SiteConfig,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Every per-site option. Stored as JSON so new options can be added
/// without schema changes; zero values mean "default".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SiteConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<ProxyConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#static: Option<StaticConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<RedirectConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub respond: Option<RespondConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forward_proxy: Option<ForwardProxyConfig>,

    /// Extra path-based routes evaluated (in order) before the main handler.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<Route>,

    pub tls: TlsConfig,
    /// None = true (Caddy default).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_redirect: Option<bool>,
    /// "", "to_www", "to_apex".
    #[serde(skip_serializing_if = "String::is_empty")]
    pub www_redirect: String,
    /// e.g. ["zstd","gzip"].
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub compression: Vec<String>,

    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub headers_set: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub headers_remove: Vec<String>,

    /// e.g. "10MB".
    #[serde(skip_serializing_if = "String::is_empty")]
    pub max_body_size: String,

    /// Names of reusable snippets to import.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub snippets: Vec<String>,

    pub access: AccessConfig,
    #[serde(skip_serializing_if = "is_false")]
    pub maintenance: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub maintenance_body: String,

    /// None = true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_log: Option<bool>,

    /// Raw Caddyfile appended inside the site block (escape hatch).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub raw: String,
}

/// A path-matched handler inside a site.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Route {
    /// e.g. /api/*
    pub path: String,
    #[serde(skip_serializing_if = "is_false")]
    pub strip_prefix: bool,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<ProxyConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#static: Option<StaticConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<RedirectConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub respond: Option<RespondConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    /// host:port or scheme://host:port
    pub upstreams: Vec<String>,

    #[serde(skip_serializing_if = "String::is_empty")]
    pub lb_policy: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub lb_retries: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub lb_try_duration: String,

    // Active health checks
    #[serde(skip_serializing_if = "String::is_empty")]
    pub health_uri: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub health_interval: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub health_timeout: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub health_status: String,

    // Passive health checks
    #[serde(skip_serializing_if = "String::is_empty")]
    pub fail_duration: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub max_fails: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub unhealthy_status: String,

    #[serde(skip_serializing_if = "is_false")]
    pub tls_skip_verify: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tls_server_name: String,
    /// gRPC over cleartext / h2c upstreams
    #[serde(skip_serializing_if = "is_false")]
    pub h2c: bool,
    /// force HTTP/2 to TLS upstreams (gRPC)
    #[serde(skip_serializing_if = "is_false")]
    pub http2: bool,

    #[serde(skip_serializing_if = "String::is_empty")]
    pub dial_timeout: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub response_header_timeout: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub read_timeout: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub write_timeout: String,

    /// "-1" for streaming
    #[serde(skip_serializing_if = "String::is_empty")]
    pub flush_interval: String,
    /// None = true (Caddy default)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass_host_header: Option<bool>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub header_up: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub header_down: BTreeMap<String, String>,
    /// Websockets are proxied transparently by Caddy; the flag only adds
    /// streaming-friendly settings and documents intent.
    #[serde(skip_serializing_if = "is_false")]
    pub websocket: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StaticConfig {
    pub root: String,
    #[serde(skip_serializing_if = "is_false")]
    pub browse: bool,
    /// try_files {path} /index.html
    #[serde(skip_serializing_if = "is_false")]
    pub spa: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RedirectConfig {
    pub to: String,
    /// default 302
    #[serde(skip_serializing_if = "is_zero")]
    pub code: i64,
    #[serde(skip_serializing_if = "is_false")]
    pub keep_path: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RespondConfig {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub body: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub status: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub content_type: String,
}

/// Settings of a forward proxy site (github.com/caddyserver/forwardproxy).
/// Credentials are plain text, exactly as the plugin needs them in the
/// Caddyfile; it does not support hashed passwords.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ForwardProxyConfig {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub basic_auth: Vec<ForwardProxyUser>,
    /// Do not send X-Forwarded-For.
    #[serde(skip_serializing_if = "is_false")]
    pub hide_ip: bool,
    /// Do not send the Via header.
    #[serde(skip_serializing_if = "is_false")]
    pub hide_via: bool,
    /// Secret hostname that reveals the proxy; everything else sees a 400.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub probe_resistance: String,
    /// Serve a PAC file at this path (e.g. /proxy.pac).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub serve_pac: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub dial_timeout: String,
    /// Destination ports clients may connect to (empty = any).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<i64>,
    /// Access list rules, in order: "allow 10.0.0.0/8", "deny all" ...
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub acl: Vec<String>,
    /// Chain to another proxy, e.g. https://user:pass@host:port.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub upstream: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ForwardProxyUser {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    /// auto (default), internal, custom, off
    #[serde(skip_serializing_if = "String::is_empty")]
    pub mode: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cert_file: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub key_file: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AccessConfig {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub basic_auth: Vec<BasicAuthUser>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allow_cidrs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deny_cidrs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forward_auth: Option<ForwardAuth>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimit>,
    /// Legacy per-site CrowdSec switch; `shields.crowdsec` supersedes it.
    #[serde(skip_serializing_if = "is_false")]
    pub crowdsec: bool,
    /// Overrides of the protections set for all sites on the Security page.
    pub shields: ShieldOverrides,
}

/// Protections that can be turned on for every site at once (Security
/// page) and overridden per site.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Shields {
    /// Block IPs CrowdSec has flagged (needs CrowdSec on the Security page).
    pub crowdsec: bool,
    /// Block AI crawlers and scrapers by user agent (and every known
    /// crawler with `SecuritySettings.bots_block_all`).
    pub bots: bool,
    /// Limit requests per visitor (numbers on the Security page).
    pub rate_limit: bool,
    /// Only allow visitors from the home networks.
    pub home_only: bool,
    /// Login wall: "" (none), "basic" (shared accounts) or "sso" (sign-in
    /// with Caddymium accounts and two-factor).
    pub login: String,
    /// Keep the site out of search engines and AI datasets (robots.txt,
    /// X-Robots-Tag) and send privacy headers.
    pub privacy: bool,
}

/// Per-site overrides of `Shields`: None follows the default.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ShieldOverrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crowdsec: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bots: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy: Option<bool>,
    /// Accounts allowed through the sign-in wall; empty = every account.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sso_users: Vec<String>,
    /// How phone/TV apps reach the site past the login wall: "" (they
    /// don't; the wall covers everything), a preset (vaultwarden, jellyfin,
    /// plex, immich) or "custom".
    #[serde(skip_serializing_if = "String::is_empty")]
    pub apps: String,
    /// For "custom": "except" (wall everywhere but `app_paths`) or "only"
    /// (wall only on `app_paths`).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub app_mode: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub app_paths: Vec<String>,
}

/// The Security page: defaults for every site plus shared settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecuritySettings {
    /// Protections every site gets unless it overrides them.
    pub defaults: Shields,
    /// Networks that count as home (home-only access, rate-limit exemption).
    pub home_networks: Vec<String>,
    /// Also count Tailscale addresses as home.
    pub tailscale_is_home: bool,
    /// Requests per visitor per window when rate limiting is on.
    pub rate_limit_events: i64,
    pub rate_limit_window: String,
    /// Never rate-limit visitors from the home networks.
    pub rate_limit_exempt_home: bool,
    /// Shared accounts for the "basic" login wall (bcrypt hashes).
    pub basic_auth_users: Vec<BasicAuthUser>,
    pub sso: SsoSettings,
    /// Besides AI crawlers, also block search engines and SEO crawlers.
    pub bots_block_all: bool,
    /// User-agent fragments that are never blocked (e.g. an uptime monitor).
    pub bots_allow: Vec<String>,
}

impl Default for SecuritySettings {
    fn default() -> Self {
        SecuritySettings {
            defaults: Shields {
                crowdsec: true,
                bots: true,
                rate_limit: false,
                home_only: false,
                login: String::new(),
                privacy: true,
            },
            home_networks: vec![
                "10.0.0.0/8".into(),
                "172.16.0.0/12".into(),
                "192.168.0.0/16".into(),
                "127.0.0.0/8".into(),
                "fc00::/7".into(),
                "::1/128".into(),
            ],
            tailscale_is_home: true,
            rate_limit_events: 600,
            rate_limit_window: "1m".into(),
            rate_limit_exempt_home: true,
            basic_auth_users: Vec::new(),
            sso: SsoSettings::default(),
            bots_block_all: false,
            bots_allow: Vec::new(),
        }
    }
}

/// Sign-in with Caddymium accounts in front of sites (forward auth to the
/// panel), with two-factor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SsoSettings {
    /// Hostname of the sign-in page, e.g. auth.example.com. It must share a
    /// parent domain with the protected sites.
    pub portal_host: String,
    /// Domain the sign-in cookie is valid for; empty = the portal's parent
    /// domain (auth.example.com -> example.com).
    pub cookie_domain: String,
    /// How long a sign-in lasts.
    pub session_hours: i64,
    /// Accounts without two-factor can't sign in.
    pub require_2fa: bool,
}

impl Default for SsoSettings {
    fn default() -> Self {
        SsoSettings {
            portal_host: String::new(),
            cookie_domain: String::new(),
            session_hours: 24 * 7,
            require_2fa: true,
        }
    }
}

impl SsoSettings {
    /// The cookie domain in effect.
    pub fn effective_cookie_domain(&self) -> String {
        let d = self.cookie_domain.trim().trim_start_matches('.');
        if !d.is_empty() {
            return d.to_ascii_lowercase();
        }
        let p = self.portal_host.trim().to_ascii_lowercase();
        match p.split_once('.') {
            Some((_, rest)) if rest.contains('.') => rest.to_string(),
            _ => p,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BasicAuthUser {
    pub username: String,
    /// A bcrypt hash (what Caddy's basic_auth expects). Plaintext is never
    /// stored; the API hashes on write.
    pub hash: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ForwardAuth {
    /// authelia, authentik, custom
    #[serde(skip_serializing_if = "String::is_empty")]
    pub preset: String,
    pub upstream: String,
    pub uri: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub copy_headers: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimit {
    pub events: i64,
    pub window: String,
    /// default {remote_host}
    #[serde(skip_serializing_if = "String::is_empty")]
    pub key: String,
}

/// A base domain (zone) the user manages certificates for.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Domain {
    pub id: i64,
    /// e.g. example.com
    pub name: String,
    pub challenge: String,
    /// DNS credential for dns-01
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<i64>,
    /// issue *.name (dns-01 only), off by default
    pub wildcard: bool,
    // Optional overrides; empty means use global settings.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub propagation_delay: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub propagation_timeout: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub resolvers: Vec<String>,
    pub created_at: DateTime<Utc>,
}

/// A DNS provider account. Field values are encrypted at rest; a value may
/// also be a reference: "env:NAME" or "file:/path".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsCredential {
    pub id: i64,
    pub name: String,
    pub provider: String,
    /// decrypted, never serialized
    #[serde(skip)]
    pub fields: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
}

/// A reusable Caddyfile fragment, imported by sites.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Snippet {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub body: String,
}

/// Top-level Caddyfile text kept verbatim (e.g. unparsed import).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RawBlock {
    pub id: i64,
    pub name: String,
    pub body: String,
    pub enabled: bool,
    pub position: i64,
    /// "import" or "user"
    pub source: String,
}

/// Global options. Stored as a single JSON document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub setup_complete: bool,
    pub acme_email: String,
    /// preset id or "custom"
    pub acme_ca: String,
    /// custom directory URL
    pub acme_ca_url: String,
    /// path to PEM for custom/internal CA
    pub acme_ca_root: String,
    /// for ZeroSSL / custom CAs
    pub acme_eab_key_id: String,
    /// secret ref (encrypted in secrets table)
    pub acme_eab_mac_ref: String,

    /// DNS propagation check resolvers
    pub resolvers: Vec<String>,
    /// quad9, cloudflare, google, custom, system
    pub resolver_preset: String,
    pub propagation_delay: String,
    pub propagation_timeout: String,

    pub trusted_proxies: TrustedProxies,

    pub metrics: bool,
    pub default_access_log: bool,
    pub log_roll_size: String,
    pub log_roll_keep: i64,

    pub crowdsec: CrowdSecSettings,

    pub cert_alert_days: Vec<i64>,

    /// optional: serve the panel itself through Caddy
    pub panel_domain: String,

    /// pre-selected base domain for new sites (UI only)
    pub default_domain: String,
    /// extra LAN ranges for "Find app", e.g. 10.0.1.0/24
    pub scan_ranges: Vec<String>,

    /// global "always dry-run" safety toggle
    pub dry_run: bool,

    pub backup: BackupSettings,
    pub oidc: OidcSettings,
    pub session_timeout_minutes: i64,

    pub discovery: bool,

    /// Caddy update checker and automatic updates (see updates.rs).
    pub updates: UpdateSettings,

    /// Dynamic DNS (caddy-dynamicdns plugin).
    pub ddns: DdnsSettings,

    /// Site protections (Security page).
    pub security: SecuritySettings,

    /// Verbatim text placed inside the global options block (e.g. options
    /// the importer could not map). Validated before apply.
    pub raw_global: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TrustedProxies {
    pub enabled: bool,
    /// cloudflare, fastly, private
    pub presets: Vec<String>,
    pub custom: Vec<String>,
    pub strict: bool,
    pub client_ip_headers: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CrowdSecSettings {
    /// Use an external CrowdSec (api_url + key).
    pub enabled: bool,
    /// Run CrowdSec inside Caddymium (crowdsec.rs); takes precedence over
    /// an external one.
    pub builtin: bool,
    pub api_url: String,
    /// "env:NAME", "file:/path" or "secret:<name>"
    pub api_key_ref: String,
    pub ticker_interval: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BackupSettings {
    pub enabled: bool,
    /// "daily" | "weekly" | duration like "12h"
    pub schedule: String,
    pub retention: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OidcSettings {
    pub enabled: bool,
    pub preset: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret_ref: String,
    pub redirect_url: String,
    pub scopes: Vec<String>,
    pub groups_claim: String,
    pub admin_groups: Vec<String>,
    pub editor_groups: Vec<String>,
    pub auto_create: bool,
    pub default_role: String,
    pub button_label: String,
}

/// Dynamic DNS: keep A/AAAA records of the listed names pointed at this
/// server's public address, through a DNS provider account.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DdnsSettings {
    pub enabled: bool,
    /// DNS provider account used to update records.
    pub credential_id: Option<i64>,
    pub domains: Vec<DdnsDomain>,
    /// Checked in order; the first that answers wins.
    pub ip_sources: Vec<DdnsIpSource>,
    /// e.g. "5m"
    pub check_interval: String,
    pub ipv4: bool,
    pub ipv6: bool,
    /// Record TTL, e.g. "1h" (empty = provider default)
    pub ttl: String,
    /// Also update every hostname Caddy serves.
    pub dynamic_domains: bool,
    /// Only update records that already exist.
    pub update_only: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DdnsDomain {
    /// e.g. example.com
    pub zone: String,
    /// Names inside the zone: "@" for the zone itself, "www", "home" ...
    pub names: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DdnsIpSource {
    /// simple_http, upnp, interface, static
    pub kind: String,
    /// endpoint URL, interface name or static address(es); empty for upnp
    pub value: String,
}

impl Default for Settings {
    /// Safe defaults for a fresh install.
    fn default() -> Self {
        Settings {
            setup_complete: false,
            acme_email: String::new(),
            acme_ca: "letsencrypt".into(),
            acme_ca_url: String::new(),
            acme_ca_root: String::new(),
            acme_eab_key_id: String::new(),
            acme_eab_mac_ref: String::new(),
            resolvers: vec!["9.9.9.9".into(), "149.112.112.112".into()],
            resolver_preset: "quad9".into(),
            propagation_delay: String::new(),
            propagation_timeout: String::new(),
            trusted_proxies: TrustedProxies::default(),
            metrics: true,
            default_access_log: true,
            log_roll_size: "10MiB".into(),
            log_roll_keep: 5,
            crowdsec: CrowdSecSettings {
                enabled: false,
                builtin: false,
                api_url: "http://crowdsec:8080".into(),
                api_key_ref: String::new(),
                ticker_interval: "15s".into(),
            },
            cert_alert_days: vec![14, 7],
            panel_domain: String::new(),
            default_domain: String::new(),
            scan_ranges: Vec::new(),
            dry_run: false,
            backup: BackupSettings {
                enabled: true,
                schedule: "daily".into(),
                retention: 7,
            },
            oidc: OidcSettings {
                scopes: vec![
                    "openid".into(),
                    "profile".into(),
                    "email".into(),
                    "groups".into(),
                ],
                groups_claim: "groups".into(),
                default_role: "viewer".into(),
                ..Default::default()
            },
            session_timeout_minutes: 60,
            discovery: false,
            updates: UpdateSettings::default(),
            security: SecuritySettings::default(),
            ddns: DdnsSettings {
                check_interval: "5m".into(),
                ipv4: true,
                ..Default::default()
            },
            raw_global: String::new(),
        }
    }
}

/// A snapshot of a generated Caddyfile and its apply result.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ConfigVersion {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub user: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub caddyfile: String,
    /// applied, failed, rolled_back, dry_run, validated
    pub status: String,
    pub message: String,
    pub good: bool,
    pub caddy_version: String,
    /// Snapshot of the editable configuration at apply time (backup.rs);
    /// internal, never sent to the UI.
    #[serde(skip)]
    pub model: String,
    /// Whether such a snapshot exists (Discard / Revert can use it).
    pub snapshot: bool,
}

/// Caddy update checker and automatic updates (see updates.rs).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateSettings {
    /// Look for new Caddy releases in the background.
    pub check: bool,
    /// Install a new release without asking (same safe path as Update Caddy).
    pub auto: bool,
    /// Hours between checks.
    pub check_every_hours: i64,
    /// Daily window for automatic installs in the server's local time
    /// ("HH:MM"); both empty = any time.
    pub window_start: String,
    pub window_end: String,
}

impl Default for UpdateSettings {
    fn default() -> Self {
        UpdateSettings {
            check: true,
            auto: false,
            check_every_hours: 6,
            window_start: String::new(),
            window_end: String::new(),
        }
    }
}

impl UpdateSettings {
    /// The check interval, kept between an hour and a week.
    pub fn interval_hours(&self) -> i64 {
        self.check_every_hours.clamp(1, 24 * 7)
    }
}
