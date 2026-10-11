//! Converts an existing Caddyfile (or Caddy JSON) into structured entries.
//! Whatever it can't map is preserved verbatim (as raw blocks, raw global
//! options, or a site's raw snippet): nothing is ever dropped silently.

mod caddyfile;
mod jsonimport;
mod preview;

pub use caddyfile::{base_domain, import, split_host_port, valid_host};
pub use jsonimport::{compare_fingerprints, fingerprint, import_json};
pub use preview::preview_input;

#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::model::{RawBlock, Site, Snippet};

/// A DNS credential discovered in the config.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Credential {
    /// dedupe key
    pub key: String,
    pub provider: String,
    /// literal secrets or env:/file: refs
    pub fields: BTreeMap<String, String>,
}

/// Links a base domain to a challenge/credential.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DomainSuggestion {
    pub name: String,
    pub challenge: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub credential_key: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub wildcard: bool,
}

/// Explains what happened to each block.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportLine {
    pub block: String,
    /// structured, partial, raw, skipped
    pub status: String,
    pub detail: String,
}

/// The import outcome.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportResult {
    pub sites: Vec<Site>,
    pub snippets: Vec<Snippet>,
    pub raw_blocks: Vec<RawBlock>,
    pub raw_global: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub email: String,
    /// preset id
    #[serde(skip_serializing_if = "String::is_empty")]
    pub acme_ca: String,
    /// when custom
    #[serde(skip_serializing_if = "String::is_empty")]
    pub acme_ca_url: String,
    pub credentials: Vec<Credential>,
    pub domains: Vec<DomainSuggestion>,
    pub report: Vec<ReportLine>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl ImportResult {
    pub(crate) fn report(&mut self, block: &str, status: &str, detail: &str) {
        self.report.push(ReportLine {
            block: block.into(),
            status: status.into(),
            detail: detail.into(),
        });
    }

    /// Maps an acme_ca URL to a preset (or custom).
    pub(crate) fn set_ca(&mut self, u: &str) {
        for (id, url) in crate::generator::CA_PRESETS {
            if !url.is_empty() && *url == u {
                self.acme_ca = id.to_string();
                return;
            }
        }
        if u == "https://acme-v02.api.letsencrypt.org/directory" {
            self.acme_ca = "letsencrypt".into();
            return;
        }
        self.acme_ca = "custom".into();
        self.acme_ca_url = u.to_string();
    }
}

/// Turns placeholders into stored references.
pub(crate) fn ref_value(v: &str) -> String {
    if let Some(n) = v.strip_prefix("{env.").and_then(|r| r.strip_suffix('}')) {
        return format!("env:{n}");
    }
    if let Some(n) = v.strip_prefix("{$").and_then(|r| r.strip_suffix('}')) {
        let name = n.split(':').next().unwrap_or(n);
        return format!("env:{name}");
    }
    if let Some(p) = v.strip_prefix("{file.").and_then(|r| r.strip_suffix('}')) {
        return format!("file:{p}");
    }
    v.to_string()
}

pub(crate) fn append_unique(v: &mut Vec<String>, s: &str) {
    if !v.iter().any(|x| x == s) {
        v.push(s.to_string());
    }
}
