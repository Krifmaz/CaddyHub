//! The config pipeline:
//!
//!   generate -> caddy adapt -> caddy validate -> diff -> POST /load
//!            -> health check -> persist snapshot (or roll back)
//!
//! The structured model in the store is the source of truth. The applied
//! Caddyfile is persisted to a file Caddy starts from, so restarts keep the
//! same config, and every attempt is recorded in the version history.

use anyhow::{Result, anyhow};
use serde::Serialize;
use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::caddy::runner::err_messages;
use crate::caddy::{AdaptResult, Admin, Message, Runner};
use crate::caddyfile;
use crate::diff;
use crate::generator::{self, CredRef, Env, Input, Output};
use crate::model::*;
use crate::registry::{Capabilities, dns_provider_by_id};
use crate::secrets::{self, Materializer};
use crate::store::Store;

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The subset of the Caddy runner used here (fakeable in tests).
pub trait Validator: Send + Sync {
    fn adapt<'a>(&'a self, caddyfile: &'a str) -> BoxFut<'a, Result<AdaptResult>>;
    fn validate<'a>(&'a self, caddyfile: &'a str) -> BoxFut<'a, Result<()>>;
}

impl Validator for Runner {
    fn adapt<'a>(&'a self, caddyfile: &'a str) -> BoxFut<'a, Result<AdaptResult>> {
        Box::pin(Runner::adapt(self, caddyfile))
    }
    fn validate<'a>(&'a self, caddyfile: &'a str) -> BoxFut<'a, Result<()>> {
        Box::pin(Runner::validate(self, caddyfile))
    }
}

/// The subset of the admin client used here.
pub trait AdminApi: Send + Sync {
    fn load_caddyfile<'a>(&'a self, caddyfile: &'a str, force: bool) -> BoxFut<'a, Result<()>>;
    fn load_json<'a>(&'a self, cfg: &'a [u8]) -> BoxFut<'a, Result<()>>;
    fn config<'a>(&'a self) -> BoxFut<'a, Result<Vec<u8>>>;
    fn ping<'a>(&'a self) -> BoxFut<'a, Result<()>>;
}

impl AdminApi for Admin {
    fn load_caddyfile<'a>(&'a self, caddyfile: &'a str, force: bool) -> BoxFut<'a, Result<()>> {
        Box::pin(Admin::load_caddyfile(self, caddyfile, force))
    }
    fn load_json<'a>(&'a self, cfg: &'a [u8]) -> BoxFut<'a, Result<()>> {
        Box::pin(Admin::load_json(self, cfg))
    }
    fn config<'a>(&'a self) -> BoxFut<'a, Result<Vec<u8>>> {
        Box::pin(Admin::config(self))
    }
    fn ping<'a>(&'a self) -> BoxFut<'a, Result<()>> {
        Box::pin(Admin::ping(self))
    }
}

/// Verifies Caddy after a load.
pub trait HealthChecker: Send + Sync {
    fn check<'a>(&'a self, expect_http: bool) -> BoxFut<'a, Result<()>>;
}

/// Called on failures: (event, message).
pub type Notify = Arc<dyn Fn(&str, &str) + Send + Sync>;

/// Wires everything together.
pub struct Pipeline {
    pub store: Arc<Store>,
    pub validator: Arc<dyn Validator>,
    pub admin: Arc<dyn AdminApi>,
    pub health: Arc<dyn HealthChecker>,
    pub secrets: Option<Arc<Materializer>>,
    pub env: Env,
    /// Caddyfile that Caddy starts from (shared volume); empty = don't persist
    pub persist_path: PathBuf,
    pub caps: Arc<RwLock<Capabilities>>,
    pub notify: Option<Notify>,
    lock: tokio::sync::Mutex<()>,
}

/// The result of generate+adapt+validate+diff.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Plan {
    pub caddyfile: String,
    pub previous: String,
    pub previous_id: i64,
    pub diff: String,
    pub added: usize,
    pub removed: usize,
    pub changed: bool,
    pub warnings: Vec<String>,
    pub adapt_warnings: Vec<String>,
    pub valid: bool,
    /// where it failed
    #[serde(skip_serializing_if = "String::is_empty")]
    pub stage: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<Message>,
}

/// Result of an apply.
#[derive(Debug, Clone, Serialize)]
pub struct ApplyResult {
    pub plan: Plan,
    /// dry_run, applied, invalid, failed, rolled_back
    pub status: String,
    pub message: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub version_id: i64,
    pub rolled_back: bool,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

/// Controls an apply.
#[derive(Debug, Clone, Default)]
pub struct Options {
    pub dry_run: bool,
    pub user: String,
    pub message: String,
}

pub struct PipelineParts {
    pub store: Arc<Store>,
    pub validator: Arc<dyn Validator>,
    pub admin: Arc<dyn AdminApi>,
    pub health: Arc<dyn HealthChecker>,
    pub secrets: Option<Arc<Materializer>>,
    pub env: Env,
    pub persist_path: PathBuf,
    pub caps: Arc<RwLock<Capabilities>>,
    pub notify: Option<Notify>,
}

impl Pipeline {
    pub fn new(p: PipelineParts) -> Pipeline {
        Pipeline {
            store: p.store,
            validator: p.validator,
            admin: p.admin,
            health: p.health,
            secrets: p.secrets,
            env: p.env,
            persist_path: p.persist_path,
            caps: p.caps,
            notify: p.notify,
            lock: tokio::sync::Mutex::new(()),
        }
    }

    fn caps(&self) -> Capabilities {
        self.caps.read().map(|c| c.clone()).unwrap_or_default()
    }

    /// Loads the model and resolves secrets into placeholders.
    pub fn build_input(&self) -> Result<Input> {
        let mut input = Input {
            settings: self.store.settings(),
            sites: self.store.sites()?,
            domains: self.store.domains()?,
            snippets: self.store.snippets()?,
            raw_blocks: self.store.raw_blocks()?,
            caps: self.caps(),
            env: self.env.clone(),
            ..Default::default()
        };
        if let Some(cached) = self
            .store
            .kv_get_json::<BTreeMap<String, Vec<String>>>("trusted_proxy_ranges")
        {
            for (k, v) in cached {
                input.env.trusted_proxy_ranges.insert(k, v);
            }
        }

        let creds = self.store.credentials()?;
        let mut keep: Vec<String> = Vec::new();
        for c in creds {
            let Some(prov) = dns_provider_by_id(&c.provider) else {
                continue;
            };
            let mut r = CredRef {
                provider: c.provider.clone(),
                fields: BTreeMap::new(),
            };
            for f in prov.fields {
                let v = c.fields.get(f.key).cloned().unwrap_or_default();
                if v.is_empty() {
                    continue;
                }
                if let Some(ph) = secrets::ref_placeholder(&v) {
                    r.fields.insert(f.key.to_string(), ph);
                    continue;
                }
                if f.secret {
                    let name = format!("dns-{}-{}", c.id, f.key);
                    let ph = self.materialize(&name, &v)?;
                    keep.push(name);
                    r.fields.insert(f.key.to_string(), ph);
                    continue;
                }
                r.fields.insert(f.key.to_string(), v);
            }
            input.credentials.insert(c.id, r);
        }

        // named secrets used by global options
        if !input.settings.acme_eab_key_id.is_empty() {
            if let Some(v) = self.store.secret("acme_eab_mac") {
                input.env.eab_mac_ref = self.materialize("acme-eab-mac", &v)?;
                keep.push("acme-eab-mac".into());
            }
        }
        if input.settings.crowdsec.enabled {
            if let Some(ph) = secrets::ref_placeholder(&input.settings.crowdsec.api_key_ref) {
                input.env.crowdsec_key_ref = ph;
            } else if let Some(v) = self.store.secret("crowdsec_api_key") {
                input.env.crowdsec_key_ref = self.materialize("crowdsec-api_key", &v)?;
                keep.push("crowdsec-api_key".into());
            }
        }
        if let Some(m) = &self.secrets {
            let _ = m.prune(&keep);
        }
        Ok(input)
    }

    fn materialize(&self, name: &str, value: &str) -> Result<String> {
        match &self.secrets {
            Some(m) => m.file_ref(name, value),
            None => Err(anyhow!("secrets directory not configured")),
        }
    }

    /// Renders the current model.
    pub fn generate(&self) -> Result<(Output, Input)> {
        let input = self.build_input()?;
        Ok((generator::generate(&input), input))
    }

    /// Generates and validates without applying.
    pub async fn plan(&self) -> Result<Plan> {
        let (out, input) = self.generate()?;
        self.plan_text(
            self.validator.as_ref(),
            &out.caddyfile,
            out.warnings,
            Some(&input),
        )
        .await
    }

    /// Generates and validates the current model with a different Caddy
    /// binary (used before switching to a freshly downloaded build).
    pub async fn plan_with(&self, v: &dyn Validator) -> Result<Plan> {
        let (out, input) = self.generate()?;
        self.plan_text(v, &out.caddyfile, out.warnings, Some(&input))
            .await
    }

    /// Validates a given Caddyfile. When input is given, a validation copy is
    /// generated with logs redirected to a temp dir; otherwise (rollback to
    /// an old snapshot) the text is validated with log paths rewritten.
    async fn plan_text(
        &self,
        v: &dyn Validator,
        text: &str,
        warnings: Vec<String>,
        input: Option<&Input>,
    ) -> Result<Plan> {
        let mut plan = Plan {
            caddyfile: text.to_string(),
            warnings,
            ..Default::default()
        };
        if let Ok(prev) = self.store.last_good() {
            plan.previous = prev.caddyfile;
            plan.previous_id = prev.id;
        }
        plan.diff = diff::unified(&plan.previous, text, "applied", "pending", 3);
        let (a, r) = diff::stats(&diff::lines(&plan.previous, text));
        plan.added = a;
        plan.removed = r;
        plan.changed = !plan.diff.is_empty();

        match v.adapt(text).await {
            Ok(ar) => plan.adapt_warnings = ar.warnings,
            Err(e) => {
                plan.stage = "adapt".into();
                plan.errors = err_messages(&e);
                return Ok(plan);
            }
        }

        let tmp_logs = tempfile::Builder::new()
            .prefix("caddymium-validate-logs-")
            .tempdir()?;
        let tmp = secrets::to_slash(tmp_logs.path());
        let vtext = match input {
            Some(input) => {
                let mut vin = input.clone();
                vin.env.log_dir = tmp;
                vin.env.validation_mode = true;
                generator::generate(&vin).caddyfile
            }
            None => validation_copy(text, &self.env.log_dir, &tmp),
        };
        if let Err(e) = v.validate(&vtext).await {
            plan.stage = "validate".into();
            plan.errors = err_messages(&e);
            return Ok(plan);
        }
        plan.valid = true;
        Ok(plan)
    }

    /// Runs the full pipeline for the current model.
    pub async fn apply(&self, opt: Options) -> Result<ApplyResult> {
        let _g = self.lock.lock().await;
        let (out, input) = self.generate()?;
        let plan = self
            .plan_text(
                self.validator.as_ref(),
                &out.caddyfile,
                out.warnings,
                Some(&input),
            )
            .await?;
        let expect_http =
            input.sites.iter().any(|s| s.enabled) || !input.settings.panel_domain.is_empty();
        self.apply_plan(plan, opt, expect_http).await
    }

    /// Re-applies an older version (rollback to version N).
    pub async fn apply_snapshot(&self, version_id: i64, mut opt: Options) -> Result<ApplyResult> {
        let _g = self.lock.lock().await;
        let v = self.store.version(version_id)?;
        // Versions recorded with a snapshot of the editable configuration
        // bring it back too, so the sites match what runs again. The current
        // configuration is kept aside to undo that if the apply fails.
        let before = if v.model.is_empty() {
            String::new()
        } else {
            crate::backup::snapshot_json(&self.store)
        };
        let restored = !v.model.is_empty()
            && match crate::backup::restore_json(&self.store, &v.model) {
                Ok(_) => true,
                Err(e) => {
                    tracing::warn!(err = %e, version_id, "could not restore the configuration snapshot");
                    false
                }
            };
        // Snapshots may reference secret files: make sure they exist.
        self.build_input()?;
        let plan = self
            .plan_text(self.validator.as_ref(), &v.caddyfile, Vec::new(), None)
            .await?;
        if opt.message.is_empty() {
            opt.message = format!("rollback to version {version_id}");
        }
        let expect_http = has_site_blocks(&v.caddyfile);
        let mut res = self.apply_plan(plan, opt, expect_http).await?;
        if restored {
            if res.status == "applied" {
                res.message
                    .push_str("; sites and settings restored from that version");
            } else if let Err(e) = crate::backup::restore_json(&self.store, &before) {
                tracing::error!(err = %e, "could not put the configuration back after a failed rollback");
                res.message.push_str("; WARNING: the sites and settings were changed to that version's and could not be put back");
            }
        }
        Ok(res)
    }

    async fn apply_plan(&self, plan: Plan, opt: Options, expect_http: bool) -> Result<ApplyResult> {
        let version = self.caps().version_s;
        let mut res = ApplyResult {
            plan,
            status: String::new(),
            message: String::new(),
            version_id: 0,
            rolled_back: false,
        };
        let record = |res: &mut ApplyResult, status: &str, msg: &str, good: bool| {
            // A good version also remembers the editable configuration it
            // was generated from, for "Discard changes" and History restores.
            let model = if good {
                crate::backup::snapshot_json(&self.store)
            } else {
                String::new()
            };
            if let Ok(v) = self.store.add_version(ConfigVersion {
                user: opt.user.clone(),
                caddyfile: res.plan.caddyfile.clone(),
                status: status.into(),
                message: msg.into(),
                good,
                caddy_version: version.clone(),
                model,
                ..Default::default()
            }) {
                res.version_id = v.id;
            }
            let _ = self.store.prune_versions(200);
        };

        if !res.plan.valid {
            res.status = "invalid".into();
            res.message = format!(
                "{} failed: {}",
                res.plan.stage,
                join_messages(&res.plan.errors)
            );
            if !opt.dry_run {
                let msg = res.message.clone();
                record(&mut res, "invalid", &msg, false);
                self.notify(
                    "apply_failed",
                    &format!("Config rejected before apply: {msg}"),
                );
            }
            return Ok(res);
        }
        if opt.dry_run {
            res.status = "dry_run".into();
            res.message = "validated; not applied (dry run)".into();
            return Ok(res);
        }

        // Snapshot what's running now so a failed health check can restore
        // the exact previous state, even if it was never applied by the panel.
        let prev_json = self.admin.config().await.ok();

        let load = tokio::time::timeout(
            Duration::from_secs(60),
            self.admin.load_caddyfile(&res.plan.caddyfile, true),
        )
        .await;
        let load = match load {
            Ok(r) => r,
            Err(_) => Err(anyhow!("timed out after 60s")),
        };
        if let Err(e) = load {
            // Caddy rolls back atomically on a failed /load: nothing changed.
            res.status = "failed".into();
            res.message = format!("load rejected by Caddy: {e}");
            let msg = res.message.clone();
            record(&mut res, "failed", &msg, false);
            self.notify("apply_failed", &msg);
            return Ok(res);
        }

        let herr =
            match tokio::time::timeout(Duration::from_secs(45), self.health.check(expect_http))
                .await
            {
                Ok(Ok(())) => None,
                Ok(Err(e)) => Some(e.to_string()),
                Err(_) => Some("health check timed out".to_string()),
            };
        if let Some(herr) = herr {
            res.rolled_back = true;
            let rb = self.rollback(prev_json).await;
            res.status = "rolled_back".into();
            res.message = format!("health check failed after apply: {herr}");
            match rb {
                Err(e) => res.message.push_str(&format!("; ROLLBACK FAILED: {e}")),
                Ok(()) => res.message.push_str("; previous config restored"),
            }
            let msg = res.message.clone();
            record(&mut res, "rolled_back", &msg, false);
            self.notify("apply_failed", &msg);
            return Ok(res);
        }

        if let Err(e) = self.persist(&res.plan.caddyfile) {
            // Running config is fine but not persisted: surface loudly.
            res.status = "applied".into();
            res.message = format!("applied, but persisting the Caddyfile failed: {e}");
            let msg = res.message.clone();
            record(&mut res, "applied", &msg, true);
            self.notify("apply_failed", &msg);
            return Ok(res);
        }
        res.status = "applied".into();
        res.message = if opt.message.is_empty() {
            "applied successfully".into()
        } else {
            opt.message.clone()
        };
        let msg = res.message.clone();
        record(&mut res, "applied", &msg, true);
        Ok(res)
    }

    async fn rollback(&self, prev_json: Option<Vec<u8>>) -> Result<()> {
        let fut = async {
            // Prefer the exact running config captured before the load.
            if let Some(prev) = &prev_json {
                if !prev.is_empty()
                    && prev.as_slice() != b"null"
                    && self.admin.load_json(prev).await.is_ok()
                {
                    return Ok(());
                }
            }
            // Fall back to the last good snapshot.
            if let Ok(lg) = self.store.last_good() {
                return self.admin.load_caddyfile(&lg.caddyfile, true).await;
            }
            // Last resort: the persisted file Caddy started from.
            if let Ok(b) = std::fs::read_to_string(&self.persist_path) {
                return self.admin.load_caddyfile(&b, true).await;
            }
            Err(anyhow!("no previous configuration available"))
        };
        tokio::time::timeout(Duration::from_secs(60), fut)
            .await
            .unwrap_or_else(|_| Err(anyhow!("rollback timed out")))
    }

    /// Writes the applied Caddyfile atomically.
    fn persist(&self, text: &str) -> Result<()> {
        if self.persist_path.as_os_str().is_empty() {
            return Ok(());
        }
        if let Some(dir) = self.persist_path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = self.persist_path.with_extension("tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, &self.persist_path)?;
        Ok(())
    }

    fn notify(&self, event: &str, msg: &str) {
        if let Some(n) = &self.notify {
            n(event, msg);
        }
    }
}

/// Rewrites log paths of an arbitrary snapshot and drops the default global
/// log block so that validation errors reach stderr.
pub fn validation_copy(text: &str, log_dir: &str, tmp: &str) -> String {
    let mut text = text.replace("\r\n", "\n");
    if let Ok(blocks) = caddyfile::parse(&text) {
        if let Some(g) = blocks.first().filter(|b| b.is_global()) {
            let mut src = text.clone();
            for d in g.body.iter().rev() {
                if d.name() == "log" && d.args.len() == 1 {
                    src = format!("{}{}", &src[..d.start], &src[d.end..]);
                }
            }
            text = src;
        }
    }
    if !log_dir.is_empty() {
        text = text.replace(&format!("{log_dir}/"), &format!("{tmp}/"));
    }
    text
}

/// Reports whether a Caddyfile defines any site.
fn has_site_blocks(text: &str) -> bool {
    match caddyfile::parse(text) {
        Ok(blocks) => blocks
            .iter()
            .any(|b| !b.is_global() && !b.is_snippet() && !b.is_named_route()),
        Err(_) => true,
    }
}

fn join_messages(ms: &[Message]) -> String {
    let parts: Vec<&str> = ms
        .iter()
        .filter(|m| m.level != "warn")
        .map(|m| m.text.as_str())
        .collect();
    if parts.is_empty() {
        return ms
            .iter()
            .map(|m| m.text.as_str())
            .collect::<Vec<_>>()
            .join("; ");
    }
    parts.join("; ")
}

// ---------------------------------------------------------------- health

/// Checks the admin API and that Caddy's HTTP listeners accept connections.
/// Upstream availability is deliberately not part of it: an upstream being
/// down is not a reason to roll back Caddy's config.
pub struct DefaultHealth {
    pub admin: Arc<dyn AdminApi>,
    /// host:port listeners to TCP-dial (e.g. caddy:80, caddy:443)
    pub probe_addrs: Vec<String>,
    pub settle: Duration,
}

impl HealthChecker for DefaultHealth {
    fn check<'a>(&'a self, expect_http: bool) -> BoxFut<'a, Result<()>> {
        Box::pin(async move {
            if !self.settle.is_zero() {
                tokio::time::sleep(self.settle).await;
            }
            let mut last = Ok(());
            for _ in 0..10 {
                last = self.once(expect_http).await;
                if last.is_ok() {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            last
        })
    }
}

impl DefaultHealth {
    async fn once(&self, expect_http: bool) -> Result<()> {
        self.admin
            .ping()
            .await
            .map_err(|e| anyhow!("admin API unreachable: {e}"))?;
        let cfg = self
            .admin
            .config()
            .await
            .map_err(|e| anyhow!("cannot read running config: {e}"))?;
        if expect_http {
            let c: serde_json::Value = serde_json::from_slice(&cfg)
                .map_err(|e| anyhow!("running config unreadable: {e}"))?;
            let servers = c
                .pointer("/apps/http/servers")
                .and_then(|v| v.as_object())
                .map(|o| o.len())
                .unwrap_or(0);
            if servers == 0 {
                return Err(anyhow!("running config has no HTTP servers"));
            }
            for a in &self.probe_addrs {
                match tokio::time::timeout(
                    Duration::from_secs(3),
                    tokio::net::TcpStream::connect(a),
                )
                .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        return Err(anyhow!("listener {a} not accepting connections: {e}"));
                    }
                    Err(_) => {
                        return Err(anyhow!("listener {a} not accepting connections: timeout"));
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "apply_tests.rs"]
mod tests;
