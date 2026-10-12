//! Configuration comes entirely from environment variables (and `*_FILE`
//! Docker secrets). Defaults match the shipped docker-compose.yml; nothing is
//! specific to any one deployment.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Config {
    pub listen: String,
    pub data_dir: PathBuf,
    pub secret_key: String,
    pub secret_key_file: String,

    /// Binary used for adapt/validate (shared from the caddy container).
    pub caddy_bin: PathBuf,
    /// Address the panel uses to reach the admin API.
    pub caddy_admin: String,
    /// Address Caddy's admin endpoint binds to (written into the config).
    pub admin_listen: String,
    /// Allowed admin origins.
    pub admin_origins: Vec<String>,
    /// Persisted Caddyfile Caddy starts from.
    pub caddyfile_path: PathBuf,
    /// Shared secrets directory (same path in both containers).
    pub secrets_dir: PathBuf,
    /// Caddy log directory (same path in both containers).
    pub log_dir: String,
    /// Caddy's data dir mounted into the panel (certificates).
    pub caddy_data_dir: PathBuf,
    /// Caddy's config dir mounted read-only (autosave.json, for import).
    pub caddy_config_dir: PathBuf,
    /// Optional old Caddyfile mounted for import.
    pub import_caddyfile: PathBuf,
    /// Caddy listeners to probe after apply.
    pub probe_addrs: Vec<String>,
    /// How Caddy reaches the panel (when proxying the panel).
    pub panel_upstream: String,
    /// CPU architecture of the Caddy container for the plugin installer
    /// (amd64, arm64, ...). Empty = detect from the Caddy binary.
    pub caddy_arch: String,

    /// All-in-one mode: the panel starts and supervises Caddy itself
    /// instead of talking to a separate container.
    pub manage_caddy: bool,
    /// The Caddy binary shipped in the image (used when no custom build is
    /// installed), in all-in-one mode.
    pub caddy_image_bin: PathBuf,

    /// Public URL of the panel (cookies).
    pub base_url: String,
    /// Trust X-Forwarded-For from Caddy for client IPs.
    pub trust_proxy_headers: bool,
    /// Optional fixed setup token.
    pub setup_token: String,
    pub initial_admin_user: String,
    pub initial_admin_pass: String,

    /// Optional, raises GitHub API rate limits for update checks.
    pub github_token: String,

    /// Never set in production; for local UI development only.
    pub dev_no_auth: bool,
}

fn env(key: &str, def: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => def.to_string(),
    }
}

/// Reads KEY, or the file named by KEY_FILE (Docker secrets).
fn env_secret(key: &str) -> String {
    if let Ok(v) = std::env::var(key) {
        if !v.is_empty() {
            return v;
        }
    }
    if let Ok(f) = std::env::var(format!("{key}_FILE")) {
        if !f.is_empty() {
            if let Ok(b) = std::fs::read_to_string(&f) {
                return b.trim().to_string();
            }
        }
    }
    String::new()
}

fn env_list(key: &str, def: &str) -> Vec<String> {
    env(key, def)
        .split(',')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(String::from)
        .collect()
}

fn env_bool(key: &str, def: bool) -> bool {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => match v.to_ascii_lowercase().as_str() {
            "1" | "t" | "true" | "yes" | "y" | "on" => true,
            "0" | "f" | "false" | "no" | "n" | "off" => false,
            _ => def,
        },
        _ => def,
    }
}

impl Config {
    /// Reads configuration from the environment.
    ///
    /// Defaults depend on the deployment layout. In all-in-one mode
    /// (CADDYHUB_MANAGE_CADDY=true, the default image) everything lives
    /// under the data dir and Caddy's admin API is on localhost; in the
    /// two-container layout the paths are the volumes shared with the caddy
    /// container.
    pub fn load() -> Config {
        let manage_caddy = env_bool("CADDYHUB_MANAGE_CADDY", false);
        let data_dir = PathBuf::from(env("CADDYHUB_DATA_DIR", "/data"));
        let d = |rel: &str| data_dir.join(rel).to_string_lossy().replace('\\', "/");
        let (
            def_admin,
            def_bin,
            def_caddyfile,
            def_secrets,
            def_logs,
            def_cdata,
            def_cconfig,
            def_probe,
            def_upstream,
        ) = if manage_caddy {
            (
                "127.0.0.1:2019".to_string(),
                d("caddy/bin/caddy"),
                d("caddy/Caddyfile"),
                d("caddy/secrets"),
                d("caddy/logs"),
                d("caddy-data"),
                d("caddy-config"),
                "127.0.0.1:80",
                "127.0.0.1:8080",
            )
        } else {
            (
                "caddy-admin:2019".to_string(),
                "/caddy-bin/caddy".into(),
                "/etc/caddyhub/Caddyfile".into(),
                "/run/caddyhub/secrets".into(),
                "/var/log/caddy".into(),
                "/caddy-data".into(),
                "/caddy-config".into(),
                "caddy:80",
                "panel:8080",
            )
        };
        let caddy_admin = env("CADDYHUB_CADDY_ADMIN", &def_admin);
        let admin_listen = env("CADDYHUB_ADMIN_LISTEN", &caddy_admin);
        let mut admin_origins = env_list("CADDYHUB_ADMIN_ORIGINS", &caddy_admin);
        if admin_listen.starts_with("unix/") {
            admin_origins = Vec::new();
        }
        Config {
            listen: env("CADDYHUB_LISTEN", ":8080"),
            data_dir,
            secret_key: std::env::var("CADDYHUB_SECRET_KEY").unwrap_or_default(),
            secret_key_file: std::env::var("CADDYHUB_SECRET_KEY_FILE").unwrap_or_default(),

            caddy_bin: PathBuf::from(env("CADDYHUB_CADDY_BIN", &def_bin)),
            caddy_admin,
            admin_listen,
            admin_origins,
            caddyfile_path: PathBuf::from(env("CADDYHUB_CADDYFILE", &def_caddyfile)),
            secrets_dir: PathBuf::from(env("CADDYHUB_SECRETS_DIR", &def_secrets)),
            log_dir: env("CADDYHUB_LOG_DIR", &def_logs),
            caddy_data_dir: PathBuf::from(env("CADDYHUB_CADDY_DATA", &def_cdata)),
            caddy_config_dir: PathBuf::from(env("CADDYHUB_CADDY_CONFIG", &def_cconfig)),
            import_caddyfile: PathBuf::from(env("CADDYHUB_IMPORT_CADDYFILE", "/import/Caddyfile")),
            probe_addrs: env_list("CADDYHUB_PROBE", def_probe),
            panel_upstream: env("CADDYHUB_PANEL_UPSTREAM", def_upstream),
            caddy_arch: env("CADDYHUB_CADDY_ARCH", ""),
            manage_caddy,
            caddy_image_bin: PathBuf::from(env("CADDYHUB_CADDY_IMAGE_BIN", "/usr/bin/caddy")),

            base_url: std::env::var("CADDYHUB_BASE_URL")
                .unwrap_or_default()
                .trim_end_matches('/')
                .to_string(),
            trust_proxy_headers: env_bool("CADDYHUB_TRUST_PROXY_HEADERS", false),
            setup_token: env_secret("CADDYHUB_SETUP_TOKEN"),
            initial_admin_user: std::env::var("CADDYHUB_INITIAL_ADMIN_USER").unwrap_or_default(),
            initial_admin_pass: env_secret("CADDYHUB_INITIAL_ADMIN_PASSWORD"),

            github_token: env_secret("CADDYHUB_GITHUB_TOKEN"),
            dev_no_auth: env_bool("CADDYHUB_DEV_NO_AUTH", false),
        }
    }

    /// Returns a path inside the data directory.
    pub fn path(&self, name: &str) -> PathBuf {
        Path::new(&self.data_dir).join(name)
    }
}
