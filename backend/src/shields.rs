//! Site protections ("shields"): the defaults set for every site on the
//! Security page, per-site overrides, app presets that keep phone and TV
//! apps working behind a login wall, and the crawler lists.
//!
//! AI crawlers come from the community-maintained ai.robots.txt list,
//! refreshed daily (with a built-in copy as fallback); CrowdSec does not
//! block them because they don't behave like attackers. Search engines and
//! SEO crawlers come from a curated list here; the large public crawler
//! lists also match HTTP libraries such as okhttp that phone apps use.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::model::{AccessConfig, SecuritySettings};
use crate::store::Store;

/// What a site actually gets after applying its overrides to the defaults.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Effective {
    pub crowdsec: bool,
    pub bots: bool,
    pub rate_limit: bool,
    pub home_only: bool,
    /// "", "basic" or "sso"
    pub login: String,
    pub privacy: bool,
}

pub const LOGIN_BASIC: &str = "basic";
pub const LOGIN_SSO: &str = "sso";

pub fn valid_login(s: &str) -> bool {
    matches!(s, "" | LOGIN_BASIC | LOGIN_SSO)
}

/// Resolves a site's protections.
pub fn effective(sec: &SecuritySettings, a: &AccessConfig) -> Effective {
    let d = &sec.defaults;
    let o = &a.shields;
    Effective {
        // The legacy per-site switch counts as an explicit "on".
        crowdsec: o
            .crowdsec
            .or(a.crowdsec.then_some(true))
            .unwrap_or(d.crowdsec),
        bots: o.bots.unwrap_or(d.bots),
        rate_limit: o.rate_limit.unwrap_or(d.rate_limit),
        home_only: o.home_only.unwrap_or(d.home_only),
        login: o.login.clone().unwrap_or_else(|| d.login.clone()),
        privacy: o.privacy.unwrap_or(d.privacy),
    }
}

/// The home networks in effect (with Tailscale's ranges when enabled).
pub fn home_networks(sec: &SecuritySettings) -> Vec<String> {
    let mut v: Vec<String> = sec
        .home_networks
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if sec.tailscale_is_home {
        for r in ["100.64.0.0/10", "fd7a:115c:a1e0::/48"] {
            if !v.iter().any(|x| x == r) {
                v.push(r.to_string());
            }
        }
    }
    v
}

// ---------------------------------------------------------------- validation

fn valid_window(w: &str) -> bool {
    let w = w.trim();
    let digits: String = w.chars().take_while(|c| c.is_ascii_digit()).collect();
    !digits.is_empty() && matches!(&w[digits.len()..], "s" | "m" | "h" | "ms")
}

fn valid_network(s: &str) -> bool {
    s.parse::<ipnet::IpNet>().is_ok() || s.parse::<std::net::IpAddr>().is_ok()
}

/// Checks and tidies the Security page settings.
pub fn validate_security(sec: &mut SecuritySettings) -> Result<(), String> {
    if !valid_login(&sec.defaults.login) {
        return Err(format!("unknown login wall {:?}", sec.defaults.login));
    }
    let mut nets: Vec<String> = Vec::new();
    for n in &sec.home_networks {
        let n = n.trim().to_string();
        if n.is_empty() || nets.contains(&n) {
            continue;
        }
        if !valid_network(&n) {
            return Err(format!(
                "{n:?} is not an IP address or network (e.g. 10.0.1.0/24)"
            ));
        }
        nets.push(n);
    }
    sec.home_networks = nets;
    if sec.rate_limit_events <= 0 {
        sec.rate_limit_events = 600;
    }
    sec.rate_limit_events = sec.rate_limit_events.min(1_000_000);
    sec.rate_limit_window = sec.rate_limit_window.trim().to_string();
    if sec.rate_limit_window.is_empty() {
        sec.rate_limit_window = "1m".into();
    }
    if !valid_window(&sec.rate_limit_window) {
        return Err(format!(
            "rate limit window {:?} must look like 30s, 1m or 1h",
            sec.rate_limit_window
        ));
    }
    let sso = &mut sec.sso;
    sso.portal_host = sso
        .portal_host
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    sso.cookie_domain = sso
        .cookie_domain
        .trim()
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if !sso.portal_host.is_empty() {
        if !crate::importer::valid_host(&sso.portal_host) || sso.portal_host.contains('*') {
            return Err(format!(
                "{:?} is not a valid sign-in page host",
                sso.portal_host
            ));
        }
        let d = sso.effective_cookie_domain();
        if !(sso.portal_host == d || sso.portal_host.ends_with(&format!(".{d}"))) {
            return Err(format!(
                "the sign-in page {} must be inside the sign-in domain {d}",
                sso.portal_host
            ));
        }
    }
    sso.session_hours = sso.session_hours.clamp(1, 24 * 90);
    for u in &mut sec.basic_auth_users {
        u.username = u.username.trim().to_string();
        if u.username.is_empty()
            || u.username.contains(':')
            || u.username.contains(char::is_whitespace)
        {
            return Err(format!("{:?} is not a valid login name", u.username));
        }
        if !u.hash.starts_with("$2") {
            return Err(format!("login {:?} has no password", u.username));
        }
    }
    let mut seen = std::collections::HashSet::new();
    for u in &sec.basic_auth_users {
        if !seen.insert(u.username.to_ascii_lowercase()) {
            return Err(format!("login {:?} appears twice", u.username));
        }
    }
    sec.bots_allow = sec
        .bots_allow
        .iter()
        .map(|s| s.trim().replace('`', ""))
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(80).collect())
        .collect();
    Ok(())
}

/// Checks and tidies a site's overrides.
pub fn validate_overrides(o: &mut crate::model::ShieldOverrides) -> Result<(), String> {
    if let Some(l) = &o.login {
        if !valid_login(l) {
            return Err(format!("unknown login wall {l:?}"));
        }
    }
    if !(o.apps.is_empty() || o.apps == "custom" || app_preset(&o.apps).is_some()) {
        return Err(format!("unknown app preset {:?}", o.apps));
    }
    if !matches!(o.app_mode.as_str(), "" | "except" | "only") {
        return Err(format!("unknown app mode {:?}", o.app_mode));
    }
    o.app_paths = o
        .app_paths
        .iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    for p in &o.app_paths {
        if !(p.starts_with('/') || p.starts_with('*')) || p.contains(char::is_whitespace) {
            return Err(format!("{p:?} is not a path (it should start with /)"));
        }
    }
    o.sso_users = o
        .sso_users
        .iter()
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
        .collect();
    Ok(())
}

// ---------------------------------------------------------------- app presets

/// Paths phone/TV apps of a known service use, so the login wall can leave
/// them to the app's own sign-in (and two-factor).
#[derive(Debug, Clone, Serialize)]
pub struct AppPreset {
    pub id: &'static str,
    pub name: &'static str,
    /// "except": wall everywhere but these paths; "only": wall only here.
    pub mode: &'static str,
    pub paths: &'static [&'static str],
    pub note: &'static str,
}

pub const APP_PRESETS: &[AppPreset] = &[
    AppPreset {
        id: "vaultwarden",
        name: "Vaultwarden / Bitwarden apps",
        mode: "except",
        paths: &[
            "/api/*",
            "/identity/*",
            "/notifications/*",
            "/icons/*",
            "/attachments/*",
            "/events/*",
            "*-connector.html",
            "/app-id.json",
            "/.well-known/*",
        ],
        note: "The web vault and /admin get the login wall. The Bitwarden apps and browser extension talk to the API directly and use your vault's own two-factor.",
    },
    AppPreset {
        id: "jellyfin",
        name: "Jellyfin apps",
        mode: "only",
        paths: &["/web", "/web/*"],
        note: "The browser interface gets the login wall. Phone and TV apps use Jellyfin's own sign-in.",
    },
    AppPreset {
        id: "plex",
        name: "Plex apps",
        mode: "only",
        paths: &["/web", "/web/*"],
        note: "The browser interface gets the login wall. Plex apps sign in through plex.tv (turn on its two-factor).",
    },
    AppPreset {
        id: "immich",
        name: "Immich apps",
        mode: "except",
        paths: &["/api/*", "/.well-known/immich"],
        note: "The web interface gets the login wall. The Immich app uses the API with its own sign-in.",
    },
];

pub fn app_preset(id: &str) -> Option<&'static AppPreset> {
    APP_PRESETS.iter().find(|p| p.id == id)
}

/// The login-wall scope for a site: (mode, paths). An empty mode means the
/// wall covers the whole site.
pub fn login_scope(a: &AccessConfig) -> (String, Vec<String>) {
    let o = &a.shields;
    if let Some(p) = app_preset(&o.apps) {
        return (
            p.mode.to_string(),
            p.paths.iter().map(|s| s.to_string()).collect(),
        );
    }
    if o.apps == "custom" {
        let paths: Vec<String> = o
            .app_paths
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !paths.is_empty() {
            let mode = if o.app_mode == "only" {
                "only"
            } else {
                "except"
            };
            return (mode.to_string(), paths);
        }
    }
    (String::new(), Vec::new())
}

// ---------------------------------------------------------------- crawlers

const BOT_LIST_KEY: &str = "ai_bot_list";
const AI_LIST_URL: &str =
    "https://raw.githubusercontent.com/ai-robots-txt/ai.robots.txt/main/robots.json";

/// Names in the AI list that are ordinary words and would match normal
/// clients (e.g. "Visual Studio Code").
const GENERIC_NAMES: &[&str] = &["Code", "Cursor", "Devin", "LCC", "Anomura"];

/// Built-in copy of the ai.robots.txt list (October 2026, 173 names), used until the
/// first refresh succeeds.
pub const AI_BOTS_BUILTIN: &[&str] = &[
    "AddSearchBot",
    "AgentDataBot",
    "AgentTimes",
    "AI2Bot",
    "AI2Bot-DeepResearchEval",
    "Ai2Bot-Dolma",
    "aiHitBot",
    "AIWebIndex",
    "amazon-kendra",
    "amazon-QBusiness",
    "Amazonbot",
    "AmazonBuyForMe",
    "Amzn-SearchBot",
    "Amzn-User",
    "Andibot",
    "anthropic-ai",
    "ApifyBot",
    "ApifyWebsiteContentCrawler",
    "Applebot",
    "Applebot-Extended",
    "Aranet-SearchBot",
    "atlassian-bot",
    "Awario",
    "AzureAI-SearchBot",
    "bedrockbot",
    "bigsur.ai",
    "BixelBot",
    "Bravebot",
    "Brightbot",
    "Brightbot 1.0",
    "BuddyBot",
    "Bytespider",
    "CCBot",
    "Channel3Bot",
    "ChatGLM-Spider",
    "ChatGPT Agent",
    "ChatGPT-User",
    "Claude-Code",
    "Claude-SearchBot",
    "Claude-User",
    "Claude-Web",
    "ClaudeBot",
    "Cloudflare-AutoRAG",
    "CloudflareBrowserRenderingCrawler",
    "CloudVertexBot",
    "cohere-ai",
    "cohere-training-data-crawler",
    "Cotoyogi",
    "CragCrawler",
    "Crawl4AI",
    "Crawlspace",
    "Datenbank Crawler",
    "DeepSeekBot",
    "Diffbot",
    "Diffbot-User",
    "DoubaoBot",
    "DuckAssistBot",
    "Echobot Bot",
    "EchoboxBot",
    "ERNIEBot",
    "ExaBot",
    "ExaSearchBot",
    "FacebookBot",
    "facebookexternalhit",
    "Factset_spyderbot",
    "FirecrawlAgent",
    "FriendlyCrawler",
    "GeistHaus-PageFetcher",
    "Gemini-Deep-Research",
    "Google-Agent",
    "Google-CloudVertexBot",
    "Google-Extended",
    "Google-Firebase",
    "Google-Gemini-CLI",
    "Google-NotebookLM",
    "GoogleAgent-Mariner",
    "GoogleAgent-URLContext",
    "GoogleOther",
    "GoogleOther-Image",
    "GoogleOther-Video",
    "GPTBot",
    "HenkBot",
    "iAskBot",
    "iaskspider",
    "iaskspider/2.0",
    "ICC-Crawler",
    "ImagesiftBot",
    "imageSpider",
    "img2dataset",
    "ISSCyberRiskCrawler",
    "kagi-fetcher",
    "Kangaroo Bot",
    "KeenableBot",
    "Kimi-Agent",
    "Kimi-SearchBot",
    "Kimi-User",
    "KimiBot",
    "KlaviyoAIBot",
    "KunatoCrawler",
    "laion-huggingface-processor",
    "LAIONDownloader",
    "Lightpanda",
    "LinerBot",
    "Linguee Bot",
    "LinkupBot",
    "Manus-User",
    "meta-externalagent",
    "meta-externalfetcher",
    "meta-webindexer",
    "MistralAI-Index",
    "MistralAI-Training",
    "MistralAI-User",
    "MistralAI-User/1.0",
    "Mozilla-Tabstack",
    "MyCentralAIScraperBot",
    "NagetBot",
    "netEstate Imprint Crawler",
    "newsai",
    "NotebookLM",
    "NovaAct",
    "OAI-AdsBot",
    "OAI-SearchBot",
    "omgili",
    "omgilibot",
    "OpenAI",
    "opencode",
    "Operator",
    "PanguBot",
    "Panscient",
    "panscient.com",
    "Perplexity-User",
    "PerplexityBot",
    "PetalBot",
    "PhindBot",
    "Poggio-Citations",
    "Poseidon Research Crawler",
    "qodercli",
    "QualifiedBot",
    "Querit-SearchBot",
    "QueritBot",
    "QuillBot",
    "quillbot.com",
    "QwenBot",
    "Reflectionbot",
    "SBIntuitionsBot",
    "Scrapy",
    "SemrushBot-OCOB",
    "SemrushBot-SWA",
    "Shap-User",
    "ShapBot",
    "Sidetrade indexer bot",
    "Spider",
    "TavilyBot",
    "Terra Cotta",
    "TerraCotta",
    "Thinkbot",
    "TikTokSpider",
    "Timpibot",
    "TongyiBot",
    "Trae",
    "TwinAgent",
    "UseAI",
    "VelenPublicWebCrawler",
    "WARDBot",
    "Webzio-Extended",
    "wpbot",
    "WRTNBot",
    "YaK",
    "YandexAdditional",
    "YandexAdditionalBot",
    "YiyanBot",
    "YouBot",
    "ZanistaBot",
];

/// Search engines, SEO tools, archivers and other crawlers (opt-in).
pub const OTHER_CRAWLERS: &[&str] = &[
    "Googlebot",
    "Google-InspectionTool",
    "Storebot-Google",
    "AdsBot-Google",
    "Mediapartners-Google",
    "bingbot",
    "BingPreview",
    "msnbot",
    "adidxbot",
    "Slurp",
    "DuckDuckBot",
    "DuckDuckGo-Favicons-Bot",
    "Baiduspider",
    "YandexBot",
    "YandexImages",
    "Sogou",
    "Exabot",
    "SeznamBot",
    "Qwantify",
    "Qwantbot",
    "MojeekBot",
    "Yeti",
    "Naverbot",
    "coccocbot",
    "AhrefsBot",
    "AhrefsSiteAudit",
    "SemrushBot",
    "MJ12bot",
    "DotBot",
    "BLEXBot",
    "DataForSeoBot",
    "serpstatbot",
    "Barkrowler",
    "SeekportBot",
    "ZoominfoBot",
    "Screaming Frog",
    "SiteAuditBot",
    "MegaIndex",
    "linkdexbot",
    "rogerbot",
    "SEOkicks",
    "Seekport",
    "ia_archiver",
    "archive.org_bot",
    "Wayback Machine",
    "heritrix",
    "CensysInspect",
    "Expanse",
    "InternetMeasurement",
    "Nuclei",
    "zgrab",
    "masscan",
    "BitSightBot",
    "Turnitin",
    "Pinterestbot",
    "Twitterbot",
    "LinkedInBot",
    "Slackbot",
    "Discordbot",
    "TelegramBot",
    "WhatsApp",
    "redditbot",
    "Embedly",
    "Iframely",
    "SkypeUriPreview",
];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BotList {
    pub names: Vec<String>,
    pub fetched_at: Option<DateTime<Utc>>,
}

/// The current AI crawler names (refreshed list, else the built-in copy).
pub fn ai_bots(store: &Store) -> (Vec<String>, Option<DateTime<Utc>>) {
    match store.kv_get_json::<BotList>(BOT_LIST_KEY) {
        Some(l) if !l.names.is_empty() => (l.names, l.fetched_at),
        _ => (
            AI_BOTS_BUILTIN.iter().map(|s| s.to_string()).collect(),
            None,
        ),
    }
}

/// Parses ai.robots.txt's robots.json (an object keyed by agent name).
pub fn parse_ai_list(json: &str) -> anyhow::Result<Vec<String>> {
    let v: serde_json::Map<String, serde_json::Value> = serde_json::from_str(json)?;
    let mut names: Vec<String> = v
        .keys()
        .map(|k| k.trim().to_string())
        .filter(|k| k.len() >= 3 && !GENERIC_NAMES.contains(&k.as_str()))
        .filter(|k| !k.contains('`'))
        .collect();
    names.sort_by_key(|s| s.to_ascii_lowercase());
    names.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    if names.len() < 20 {
        anyhow::bail!(
            "the AI crawler list looks incomplete ({} names)",
            names.len()
        );
    }
    Ok(names)
}

/// Downloads the AI crawler list. Returns true when it changed.
pub async fn refresh_ai_list(store: &Store) -> anyhow::Result<bool> {
    let body = crate::httpc::builder()
        .timeout(Duration::from_secs(30))
        .build()?
        .get(AI_LIST_URL)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let names = parse_ai_list(&body)?;
    let old: Option<BotList> = store.kv_get_json(BOT_LIST_KEY);
    let changed = old.as_ref().map(|o| o.names != names).unwrap_or(true);
    store.kv_set_json(
        BOT_LIST_KEY,
        &BotList {
            names,
            fetched_at: Some(Utc::now()),
        },
    )?;
    Ok(changed)
}

/// Refreshes the AI crawler list shortly after start and then daily. A
/// changed list goes live right away when nothing else is waiting for
/// review; otherwise it goes out with the next apply.
pub async fn refresh_loop(
    store: std::sync::Arc<Store>,
    pipeline: std::sync::Arc<crate::apply::Pipeline>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut wait = Duration::from_secs(120);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = shutdown.changed() => return,
        }
        wait = Duration::from_secs(24 * 3600);
        let fresh = ai_list_fetched_at(&store)
            .is_some_and(|t| Utc::now() - t < chrono::Duration::hours(20));
        if fresh {
            continue;
        }
        let was_pending = pipeline.pending();
        match refresh_ai_list(&store).await {
            Ok(true) => {
                pipeline
                    .apply_if_clean(was_pending, "AI crawler list updated")
                    .await;
            }
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(err = %e, "could not refresh the AI crawler list");
                wait = Duration::from_secs(3600);
            }
        }
    }
}

/// When the list was last refreshed.
pub fn ai_list_fetched_at(store: &Store) -> Option<DateTime<Utc>> {
    store
        .kv_get_json::<BotList>(BOT_LIST_KEY)
        .and_then(|l| l.fetched_at)
}

fn regex_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 4);
    for c in s.chars() {
        if "\\.^$|?*+()[]{}".contains(c) {
            o.push('\\');
        }
        o.push(c);
    }
    o
}

/// A case-insensitive regexp matching any of the names (substring match,
/// as user agents embed the name: "Mozilla/5.0 (compatible; GPTBot/1.2)").
pub fn names_regex(names: &[String]) -> String {
    let mut parts: Vec<String> = names
        .iter()
        .map(|n| n.trim())
        .filter(|n| !n.is_empty())
        .map(regex_escape)
        .collect();
    parts.sort();
    parts.dedup();
    format!("(?i)(?:{})", parts.join("|"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ShieldOverrides, Shields};

    #[test]
    fn overrides_win_over_defaults() {
        let mut sec = SecuritySettings {
            defaults: Shields {
                bots: true,
                login: "sso".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut a = AccessConfig::default();
        let e = effective(&sec, &a);
        assert!(e.bots && e.login == "sso" && !e.home_only);
        a.shields = ShieldOverrides {
            bots: Some(false),
            login: Some(String::new()),
            home_only: Some(true),
            ..Default::default()
        };
        let e = effective(&sec, &a);
        assert!(!e.bots && e.login.is_empty() && e.home_only);
        // legacy per-site CrowdSec switch
        sec.defaults.crowdsec = false;
        a.crowdsec = true;
        assert!(effective(&sec, &a).crowdsec);
        a.shields.crowdsec = Some(false);
        assert!(!effective(&sec, &a).crowdsec);
    }

    #[test]
    fn home_networks_add_tailscale() {
        let mut sec = SecuritySettings::default();
        assert!(home_networks(&sec).contains(&"100.64.0.0/10".to_string()));
        sec.tailscale_is_home = false;
        assert!(!home_networks(&sec).contains(&"100.64.0.0/10".to_string()));
    }

    #[test]
    fn app_scopes() {
        let mut a = AccessConfig::default();
        assert_eq!(login_scope(&a), (String::new(), vec![]));
        a.shields.apps = "jellyfin".into();
        let (m, p) = login_scope(&a);
        assert_eq!(m, "only");
        assert!(p.contains(&"/web/*".to_string()));
        a.shields.apps = "custom".into();
        a.shields.app_paths = vec![" /api/* ".into(), "".into()];
        assert_eq!(login_scope(&a), ("except".into(), vec!["/api/*".into()]));
        a.shields.app_mode = "only".into();
        assert_eq!(login_scope(&a).0, "only");
    }

    #[test]
    fn ai_list_parsing_and_regex() {
        let json =
            r#"{"GPTBot": {}, "ClaudeBot": {}, "Code": {}, "Brightbot 1.0": {}, "a.b(c)": {}}"#;
        assert!(parse_ai_list(json).is_err(), "too short a list is refused");
        let mut obj = serde_json::Map::new();
        for i in 0..25 {
            obj.insert(format!("Bot{i}"), serde_json::json!({}));
        }
        obj.insert("Code".into(), serde_json::json!({}));
        obj.insert("GPTBot".into(), serde_json::json!({}));
        let names = parse_ai_list(&serde_json::to_string(&obj).unwrap()).unwrap();
        assert!(names.contains(&"GPTBot".to_string()));
        assert!(
            !names.contains(&"Code".to_string()),
            "generic words dropped"
        );
        let re = names_regex(&["a.b(c)".to_string(), "GPTBot".to_string()]);
        assert_eq!(re, r"(?i)(?:GPTBot|a\.b\(c\))");
        assert!(!AI_BOTS_BUILTIN.iter().any(|n| GENERIC_NAMES.contains(n)));
    }

    #[test]
    fn cookie_domain_from_portal() {
        let mut s = crate::model::SsoSettings {
            portal_host: "auth.example.com".into(),
            ..Default::default()
        };
        assert_eq!(s.effective_cookie_domain(), "example.com");
        s.portal_host = "example.com".into();
        assert_eq!(s.effective_cookie_domain(), "example.com");
        s.cookie_domain = ".Home.Example.com".into();
        assert_eq!(s.effective_cookie_domain(), "home.example.com");
    }
}
