use axum::extract::{Extension, State};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use super::{ApiError, ApiResult, AppState, Client, JsonBody, Principal, ok};
use crate::generator;
use crate::importer::{self, ImportResult};
use crate::model::*;
use crate::registry::dns_provider_by_id;

/// One place an existing config was found.
#[derive(Serialize)]
struct ImportSource {
    id: String,
    label: String,
    detail: String,
    sites: usize,
    credentials: usize,
    kept: usize,
    hosts: Vec<String>,
}

/// Reads one import source. None when it doesn't exist.
async fn load_source(
    st: &AppState,
    id: &str,
) -> Result<Option<(ImportResult, String)>, anyhow::Error> {
    let read_json = |path: &std::path::Path| -> Result<Option<ImportResult>, anyhow::Error> {
        if path.as_os_str().is_empty() {
            return Ok(None);
        }
        let Ok(b) = std::fs::read(path) else {
            return Ok(None);
        };
        Ok(Some(importer::import_json(&b)?))
    };
    match id {
        "admin" => {
            // The running config only counts until CaddyHub has applied its own.
            if st.store.last_good().is_ok() {
                return Ok(None);
            }
            let raw = match tokio::time::timeout(Duration::from_secs(5), st.admin.config()).await {
                Ok(Ok(r)) => r,
                _ => return Ok(None),
            };
            if raw.is_empty() || raw.as_slice() == b"null" {
                return Ok(None);
            }
            Ok(Some((
                importer::import_json(&raw)?,
                "the running Caddy".into(),
            )))
        }
        "autosave-backup" => Ok(read_json(&st.imports.autosave_backup)?
            .map(|r| (r, "Caddy's saved config from before CaddyHub".into()))),
        "autosave" => {
            Ok(read_json(&st.imports.autosave)?.map(|r| (r, "Caddy's autosave.json".into())))
        }
        "caddyfile" => {
            let p = &st.imports.caddyfile;
            if p.as_os_str().is_empty() {
                return Ok(None);
            }
            let Ok(b) = std::fs::read_to_string(p) else {
                return Ok(None);
            };
            Ok(Some((
                importer::import(&b)?,
                format!("the mounted Caddyfile ({})", p.display()),
            )))
        }
        _ => Err(anyhow::anyhow!("unknown import source")),
    }
}

const SOURCE_ORDER: &[&str] = &["admin", "autosave-backup", "autosave", "caddyfile"];

/// Lists existing configs worth importing, best first.
pub async fn sources(State(st): State<Arc<AppState>>) -> ApiResult {
    let mut out: Vec<ImportSource> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for id in SOURCE_ORDER {
        let Ok(Some((res, label))) = load_source(&st, id).await else {
            continue;
        };
        if res.sites.len() + res.raw_blocks.len() == 0 {
            continue;
        }
        // Skip a source identical to one already listed (e.g. live config = autosave).
        let fp = serde_json::to_string(&importer::fingerprint(&res)).unwrap_or_default();
        if !seen.insert(fp) {
            continue;
        }
        let mut src = ImportSource {
            id: id.to_string(),
            label,
            detail: String::new(),
            sites: res.sites.len(),
            credentials: res.credentials.len(),
            kept: res.raw_blocks.len(),
            hosts: Vec::new(),
        };
        for s in &res.sites {
            src.hosts.extend(s.hosts.iter().cloned());
        }
        let mut parts = vec![format!("{} site(s)", src.sites)];
        if src.credentials > 0 {
            parts.push(format!("{} DNS provider account(s)", src.credentials));
        }
        if src.kept > 0 {
            parts.push(format!("{} block(s) kept for manual review", src.kept));
        }
        src.detail = parts.join(", ");
        out.push(src);
    }
    ok(&out)
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct ImportReq {
    source: String,
    caddyfile: String,
    replace: bool,
    settings: bool,
}

async fn load_import(st: &AppState, req: &ImportReq) -> Result<ImportResult, ApiError> {
    let r = if !req.source.is_empty() {
        match load_source(st, &req.source).await {
            Ok(Some((r, _))) => Ok(r),
            Ok(None) => Err(anyhow::anyhow!("that config is no longer available")),
            Err(e) => Err(e),
        }
    } else if !req.caddyfile.trim().is_empty() {
        let text = req.caddyfile.trim();
        if text.starts_with('{') && serde_json::from_str::<serde_json::Value>(text).is_ok() {
            importer::import_json(text.as_bytes()) // pasted JSON config
        } else {
            importer::import(&req.caddyfile)
        }
    } else {
        Err(anyhow::anyhow!(
            "paste a Caddyfile or pick a detected config"
        ))
    };
    r.map_err(|e| ApiError::bad(e.to_string()))
}

/// The round-trip check: regenerate the imported model, adapt it with Caddy
/// and compare what every host does.
#[derive(Serialize)]
struct VerifyResult {
    checked: bool,
    sites: usize,
    differences: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
}

async fn verify_import(st: &AppState, res: &ImportResult) -> VerifyResult {
    let mut v = VerifyResult {
        checked: false,
        sites: res.sites.len(),
        differences: Vec::new(),
        error: String::new(),
    };
    if !st.runner.available() {
        v.error =
            "Caddy binary not available, so the regenerated config couldn't be checked".into();
        return v;
    }
    let mut env = st.pipeline.env.clone();
    env.log_dir = String::new(); // logs don't affect behavior and need real paths
    let out = generator::generate(&importer::preview_input(
        res,
        st.store.settings(),
        env,
        st.caps(),
    ));
    let adapted = match st.runner.adapt(&out.caddyfile).await {
        Ok(a) => a,
        Err(e) => {
            v.error = format!("the regenerated config didn't pass Caddy's check: {e}");
            return v;
        }
    };
    let back = match importer::import_json(&serde_json::to_vec(&adapted.json).unwrap_or_default()) {
        Ok(b) => b,
        Err(e) => {
            v.error = e.to_string();
            return v;
        }
    };
    v.checked = true;
    v.differences =
        importer::compare_fingerprints(&importer::fingerprint(res), &importer::fingerprint(&back));
    v
}

pub async fn preview(
    State(st): State<Arc<AppState>>,
    JsonBody(req): JsonBody<ImportReq>,
) -> ApiResult {
    let mut res = load_import(&st, &req).await?;
    let verify = verify_import(&st, &res).await;
    for c in &mut res.credentials {
        // never echo secrets back
        for v in c.fields.values_mut() {
            if !v.is_empty() && !v.starts_with("env:") && !v.starts_with("file:") {
                *v = "••••••".into();
            }
        }
    }
    let mut out = serde_json::to_value(&res).unwrap_or_default();
    if let Some(o) = out.as_object_mut() {
        o.insert(
            "verify".into(),
            serde_json::to_value(verify).unwrap_or_default(),
        );
    }
    ok(&out)
}

/// Stores an import. Nothing is applied: the user reviews the result and
/// applies through the normal pipeline. With replace, existing sites,
/// snippets and raw blocks are removed first.
pub async fn commit(
    State(st): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    c: Client,
    JsonBody(req): JsonBody<ImportReq>,
) -> ApiResult {
    let res = load_import(&st, &req).await?;
    if req.replace {
        for s in st.store.sites().unwrap_or_default() {
            let _ = st.store.delete_site(s.id);
        }
        for x in st.store.snippets().unwrap_or_default() {
            let _ = st.store.delete_snippet(x.id);
        }
        for x in st.store.raw_blocks().unwrap_or_default() {
            let _ = st.store.delete_raw_block(x.id);
        }
    }
    let existing_hosts: HashSet<String> = st
        .store
        .sites()
        .unwrap_or_default()
        .iter()
        .flat_map(|s| s.hosts.iter().cloned())
        .collect();
    let mut skipped: Vec<String> = Vec::new();
    let mut n_sites = 0;
    for s in &res.sites {
        if s.hosts.iter().any(|h| existing_hosts.contains(h)) {
            skipped.push(s.hosts.join(", "));
            continue;
        }
        let mut s = s.clone();
        s.id = 0;
        s.position = 0;
        st.store.create_site(s)?;
        n_sites += 1;
    }
    let existing_sn: HashSet<String> = st
        .store
        .snippets()
        .unwrap_or_default()
        .iter()
        .map(|x| x.name.clone())
        .collect();
    for sn in &res.snippets {
        if existing_sn.contains(&sn.name) {
            skipped.push(format!("snippet {}", sn.name));
            continue;
        }
        let mut sn = sn.clone();
        sn.id = 0;
        let _ = st.store.save_snippet(sn);
    }
    for b in &res.raw_blocks {
        let mut b = b.clone();
        b.id = 0;
        let _ = st.store.save_raw_block(b);
    }

    // DNS credentials (encrypted at rest by the store) and domains.
    let mut cred_ids: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    for cr in &res.credentials {
        let name = match dns_provider_by_id(&cr.provider) {
            Some(prov) => format!("{} (imported)", prov.name),
            None => format!("{} (imported)", cr.provider),
        };
        if let Ok(saved) = st.store.save_credential(DnsCredential {
            name,
            provider: cr.provider.clone(),
            fields: cr.fields.clone(),
            ..Default::default()
        }) {
            cred_ids.insert(cr.key.clone(), saved.id);
        }
    }
    let existing_dom: HashSet<String> = st
        .store
        .domains()
        .unwrap_or_default()
        .iter()
        .map(|d| d.name.clone())
        .collect();
    for d in &res.domains {
        if existing_dom.contains(&d.name) {
            continue;
        }
        let mut dom = Domain {
            name: d.name.clone(),
            challenge: d.challenge.clone(),
            wildcard: d.wildcard,
            ..Default::default()
        };
        if let Some(id) = cred_ids.get(&d.credential_key) {
            dom.credential_id = Some(*id);
        } else if dom.challenge == CHALLENGE_DNS {
            dom.challenge = CHALLENGE_HTTP.into();
            dom.wildcard = false;
        }
        let _ = st.store.save_domain(dom);
    }
    if req.settings {
        let _ = st.store.update_settings(|s| {
            if !res.email.is_empty() {
                s.acme_email = res.email.clone();
            }
            if !res.acme_ca.is_empty() {
                s.acme_ca = res.acme_ca.clone();
                s.acme_ca_url = res.acme_ca_url.clone();
            }
            if !res.raw_global.is_empty() {
                s.raw_global = res.raw_global.clone();
            }
        });
    }
    let from = if req.source.is_empty() {
        "pasted config".to_string()
    } else {
        req.source.clone()
    };
    st.audit(
        Some(&p),
        &c,
        "config.import",
        &format!("{n_sites} sites"),
        &format!("from {from}"),
    );
    ok(&serde_json::json!({
        "sites": n_sites, "snippets": res.snippets.len(), "raw_blocks": res.raw_blocks.len(),
        "credentials": res.credentials.len(), "skipped": skipped, "report": res.report, "warnings": res.warnings,
    }))
}
