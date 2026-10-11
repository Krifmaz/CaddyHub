use std::collections::{BTreeMap, HashMap};

use super::ImportResult;
use crate::generator::{CredRef, Env, Input};
use crate::model::*;
use crate::registry::Capabilities;

/// Builds generator input as if the import had been committed, so the result
/// can be regenerated and compared before anything is saved. Secret values
/// are replaced by a dummy placeholder; only structure matters.
pub fn preview_input(
    res: &ImportResult,
    settings: Settings,
    env: Env,
    caps: Capabilities,
) -> Input {
    let mut input = Input {
        settings,
        env,
        caps,
        ..Default::default()
    };
    if !res.email.is_empty() {
        input.settings.acme_email = res.email.clone();
    }
    if !res.acme_ca.is_empty() {
        input.settings.acme_ca = res.acme_ca.clone();
        input.settings.acme_ca_url = res.acme_ca_url.clone();
    }
    if !res.raw_global.is_empty() {
        input.settings.raw_global = res.raw_global.clone();
    }
    let mut cred_id: HashMap<String, i64> = HashMap::new();
    for (i, c) in res.credentials.iter().enumerate() {
        let id = (i + 1) as i64;
        cred_id.insert(c.key.clone(), id);
        let mut r = CredRef {
            provider: c.provider.clone(),
            fields: BTreeMap::new(),
        };
        for (k, v) in &c.fields {
            let ph = if let Some(n) = v.strip_prefix("env:") {
                format!("{{env.{n}}}")
            } else if let Some(p) = v.strip_prefix("file:") {
                format!("{{file.{p}}}")
            } else {
                "{env.CADDYHUB_IMPORT_PREVIEW}".to_string()
            };
            r.fields.insert(k.clone(), ph);
        }
        input.credentials.insert(id, r);
    }
    for (i, d) in res.domains.iter().enumerate() {
        let mut dom = Domain {
            id: (i + 1) as i64,
            name: d.name.clone(),
            challenge: d.challenge.clone(),
            wildcard: d.wildcard,
            ..Default::default()
        };
        if let Some(id) = cred_id.get(&d.credential_key) {
            dom.credential_id = Some(*id);
        } else if dom.challenge == CHALLENGE_DNS {
            dom.challenge = CHALLENGE_HTTP.into();
            dom.wildcard = false;
        }
        input.domains.push(dom);
    }
    for (i, s) in res.sites.iter().enumerate() {
        let mut s = s.clone();
        s.id = (i + 1) as i64;
        s.position = (i + 1) as i64;
        input.sites.push(s);
    }
    input.snippets = res.snippets.clone();
    input.raw_blocks = res.raw_blocks.clone();
    input
}
