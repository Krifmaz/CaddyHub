use anyhow::{Result, anyhow};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};

use super::{Credential, DomainSuggestion, ImportResult, append_unique, base_domain, ref_value};
use crate::model::*;
use crate::registry::dns_provider_by_id;

/// Converts a Caddy JSON config (the admin API's /config/, an autosave.json,
/// or `caddy adapt` output) into the model. Routes it can't express are
/// reported and preserved as disabled raw blocks holding the original JSON
/// as comments, so nothing silently disappears.
pub fn import_json(data: &[u8]) -> Result<ImportResult> {
    let cfg: JConfig =
        serde_json::from_slice(data).map_err(|e| anyhow!("not a Caddy JSON config: {e}"))?;
    let mut im = JsonImporter {
        res: ImportResult::default(),
        pos: 0,
        global: None,
        host_creds: HashMap::new(),
        wildcards: BTreeMap::new(),
        internal_tls: HashSet::new(),
    };
    im.tls_policies(cfg.apps.tls.as_ref());

    let mut names: Vec<&String> = cfg.apps.http.servers.keys().collect();
    names.sort();
    for n in names {
        let srv = &cfg.apps.http.servers[n];
        for r in &srv.routes {
            im.top_route(srv, r);
        }
    }
    im.finish_domains();
    if cfg.storage.is_some() {
        im.res.report(
            "storage",
            "skipped",
            "custom certificate storage is not managed by CaddyHub; Caddy's data volume is used",
        );
    }
    Ok(im.res)
}

// ---------------------------------------------------------------- JSON shapes

#[derive(Default, Deserialize)]
#[serde(default)]
struct JConfig {
    storage: Option<Value>,
    apps: JApps,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct JApps {
    http: JHttp,
    tls: Option<JTls>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct JHttp {
    servers: BTreeMap<String, JServer>,
}

#[derive(Default, Deserialize, Clone)]
#[serde(default)]
struct JServer {
    listen: Vec<String>,
    routes: Vec<JRoute>,
}

impl JServer {
    /// Reports whether a server only serves HTTP: it doesn't listen on the
    /// HTTPS port and has no TLS of its own (e.g. http:// sites, auto_https
    /// off).
    fn plain_http(&self) -> bool {
        if self.listen.iter().any(|l| l.ends_with(":443")) {
            return false;
        }
        !self.listen.is_empty()
    }
}

#[derive(Default, Deserialize, Clone, serde::Serialize)]
#[serde(default)]
struct JRoute {
    #[serde(skip_serializing_if = "String::is_empty")]
    group: String,
    #[serde(rename = "match", skip_serializing_if = "Vec::is_empty")]
    match_: Vec<Map<String, Value>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    handle: Vec<Map<String, Value>>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    terminal: bool,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct JTls {
    automation: Option<JAutomation>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct JAutomation {
    policies: Vec<JPolicy>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct JPolicy {
    subjects: Vec<String>,
    issuers: Vec<Map<String, Value>>,
}

struct JsonImporter {
    res: ImportResult,
    pos: i64,
    /// DNS provider from a policy without subjects
    global: Option<Credential>,
    /// subject -> credential key
    host_creds: HashMap<String, String>,
    /// base domain -> credential key
    wildcards: BTreeMap<String, String>,
    /// subjects using Caddy's internal issuer
    internal_tls: HashSet<String>,
}

fn s(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn num(v: Option<&Value>) -> Option<f64> {
    v.and_then(|v| v.as_f64())
}

/// Renders a Caddy duration (string, or integer nanoseconds).
fn dur(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Number(n)) => {
            let ns = n.as_f64().unwrap_or(0.0);
            if ns <= 0.0 {
                return String::new();
            }
            format_duration(ns as i64)
        }
        _ => String::new(),
    }
}

/// Formats nanoseconds the way Go's time.Duration.String does.
pub fn format_duration(ns: i64) -> String {
    if ns == 0 {
        return "0s".into();
    }
    if ns < 1_000 {
        return format!("{ns}ns");
    }
    if ns < 1_000_000 {
        return format!("{}µs", trim_float(ns as f64 / 1e3));
    }
    if ns < 1_000_000_000 {
        return format!("{}ms", trim_float(ns as f64 / 1e6));
    }
    let total_secs = ns / 1_000_000_000;
    let frac_ns = ns % 1_000_000_000;
    let h = total_secs / 3600;
    let m = (total_secs % 3600) / 60;
    let sec = total_secs % 60;
    let mut out = String::new();
    if h > 0 {
        out.push_str(&format!("{h}h"));
    }
    if h > 0 || m > 0 {
        out.push_str(&format!("{m}m"));
    }
    let secs = sec as f64 + frac_ns as f64 / 1e9;
    out.push_str(&format!("{}s", trim_float(secs)));
    out
}

fn trim_float(f: f64) -> String {
    let s = format!("{f:.9}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    if s.is_empty() {
        "0".into()
    } else {
        s.to_string()
    }
}

fn byte_size(n: i64) -> String {
    if n > 0 && n % 1_000_000_000 == 0 {
        format!("{}GB", n / 1_000_000_000)
    } else if n > 0 && n % 1_000_000 == 0 {
        format!("{}MB", n / 1_000_000)
    } else if n > 0 && n % 1000 == 0 {
        format!("{}KB", n / 1000)
    } else {
        n.to_string()
    }
}

fn uniq(v: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for x in v {
        append_unique(&mut out, x);
    }
    out
}

fn sub_routes(h: &Map<String, Value>) -> Vec<JRoute> {
    h.get("routes")
        .and_then(|r| serde_json::from_value(r.clone()).ok())
        .unwrap_or_default()
}

fn handler_name(h: &Map<String, Value>) -> String {
    s(h.get("handler"))
}

// ---------------------------------------------------------------- TLS

impl JsonImporter {
    fn tls_policies(&mut self, t: Option<&JTls>) {
        let Some(auto) = t.and_then(|t| t.automation.as_ref()) else {
            return;
        };
        for p in &auto.policies {
            let mut cred: Option<Credential> = None;
            let mut internal = false;
            for is in &p.issuers {
                match s(is.get("module")).as_str() {
                    "internal" => internal = true,
                    "acme" | "zerossl" | "" => {
                        let e = s(is.get("email"));
                        if !e.is_empty() && self.res.email.is_empty() {
                            self.res.email = e;
                        }
                        let ca = s(is.get("ca"));
                        if !ca.is_empty()
                            && self.res.acme_ca.is_empty()
                            && ca != "https://acme.zerossl.com/v2/DV90"
                        {
                            self.res.set_ca(&ca);
                        }
                        if let Some(prov) = is
                            .get("challenges")
                            .and_then(|c| c.get("dns"))
                            .and_then(|d| d.get("provider"))
                            .and_then(|p| p.as_object())
                        {
                            if cred.is_none() {
                                cred = self.json_cred(prov);
                            }
                        }
                    }
                    _ => {}
                }
            }
            if p.subjects.is_empty() {
                if let Some(c) = cred {
                    if self.global.is_none() {
                        self.global = Some(c);
                    }
                }
                continue;
            }
            for subj in &p.subjects {
                let subj = subj.to_ascii_lowercase();
                if internal {
                    self.internal_tls.insert(subj.clone());
                }
                if let Some(c) = &cred {
                    self.host_creds.insert(subj, c.key.clone());
                }
            }
        }
    }

    /// Turns {"name": "cloudflare", "api_token": "..."} into a credential.
    /// Literal secrets are kept (they'll be encrypted at rest) but flagged.
    fn json_cred(&mut self, p: &Map<String, Value>) -> Option<Credential> {
        let name = s(p.get("name"));
        let Some(prov) = dns_provider_by_id(&name) else {
            self.res.report(
                &format!("tls dns {name}"),
                "skipped",
                &format!(
                    "DNS provider {name} is not known to CaddyHub; add it under Domains & DNS"
                ),
            );
            return None;
        };
        let mut c = Credential {
            provider: prov.id.to_string(),
            fields: BTreeMap::new(),
            key: String::new(),
        };
        let secret: HashMap<&str, bool> = prov.fields.iter().map(|f| (f.key, f.secret)).collect();
        for (k, v) in p {
            if k == "name" {
                continue;
            }
            let sv = s(Some(v));
            if sv.is_empty() {
                continue;
            }
            let r = ref_value(&sv);
            let literal = r == sv;
            c.fields.insert(k.clone(), r);
            if secret.get(k.as_str()).copied().unwrap_or(false) && literal {
                append_unique(
                    &mut self.res.warnings,
                    &format!(
                        "Your {} {k} was written in plain text in the Caddy config. CaddyHub stores it encrypted and only passes it to Caddy as a {{file.*}} placeholder.",
                        prov.name
                    ),
                );
            }
        }
        if let Some(ex) = self
            .res
            .credentials
            .iter()
            .find(|ex| ex.provider == c.provider && ex.fields == c.fields)
        {
            return Some(ex.clone());
        }
        c.key = format!("{}:{}", prov.id, self.res.credentials.len());
        self.res.credentials.push(c.clone());
        Some(c)
    }

    /// Turns DNS policies into domain entries for imported sites.
    fn finish_domains(&mut self) {
        let mut seen: HashSet<String> = HashSet::new();
        let mut domains: Vec<DomainSuggestion> = Vec::new();
        let mut add = |name: String, key: &str, wildcard: bool| {
            if name.is_empty() || !seen.insert(name.clone()) {
                return;
            }
            domains.push(DomainSuggestion {
                name,
                challenge: CHALLENGE_DNS.into(),
                credential_key: key.to_string(),
                wildcard,
            });
        };
        for (base, key) in &self.wildcards {
            add(base.clone(), key, true);
        }
        let mut hc: Vec<(&String, &String)> = self.host_creds.iter().collect();
        hc.sort();
        for (subj, key) in hc {
            if let Some(base) = subj.strip_prefix("*.") {
                add(base.to_string(), key, true);
            } else {
                add(base_domain(subj), key, false);
            }
        }
        if let Some(g) = &self.global {
            for st in &self.res.sites {
                for h in &st.hosts {
                    add(base_domain(h), &g.key, false);
                }
            }
        }
        domains.sort_by(|a, b| a.name.cmp(&b.name));
        self.res.domains.extend(domains);
    }

    // ---------------------------------------------------------------- routes

    fn top_route(&mut self, srv: &JServer, r: &JRoute) {
        let (hosts, other) = split_match(&r.match_);
        let mut label = hosts.join(", ");
        if label.is_empty() {
            label = format!("listener {}", srv.listen.join(", "));
        }
        if hosts.is_empty() {
            self.manual(&label, r, "routes without a hostname (port-only addresses like :8081) aren't supported as sites");
            return;
        }
        if other {
            self.manual(
                &label,
                r,
                "top-level matchers other than host aren't supported",
            );
            return;
        }

        // A wildcard site whose subroutes each match a host: one site per
        // host, served by a wildcard certificate.
        if hosts.len() == 1 && hosts[0].starts_with("*.") {
            if let Some(split) = host_split(&r.handle) {
                let base = hosts[0].trim_start_matches("*.").to_string();
                let mut key = self.host_creds.get(&hosts[0]).cloned().unwrap_or_default();
                if key.is_empty() {
                    if let Some(g) = &self.global {
                        key = g.key.clone();
                    }
                }
                if !key.is_empty() {
                    self.wildcards.insert(base, key);
                }
                for sr in split {
                    let (sh, _) = split_match(&sr.match_);
                    self.site(&sh, &sr.handle, &sr, false);
                }
                return;
            }
        }
        self.site(&hosts, &r.handle, r, srv.plain_http());
    }

    /// Interprets one site's handler chain.
    fn site(
        &mut self,
        hosts: &[String],
        handle: &[Map<String, Value>],
        orig: &JRoute,
        plain: bool,
    ) {
        let label = hosts.join(", ");
        let mut st = Site {
            name: hosts[0].clone(),
            hosts: hosts.to_vec(),
            enabled: true,
            config: SiteConfig {
                tls: TlsConfig {
                    mode: TLS_AUTO.into(),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        if hosts.iter().any(|h| self.internal_tls.contains(h)) {
            st.config.tls.mode = TLS_INTERNAL.into();
        }
        if plain {
            st.config.tls.mode = TLS_OFF.into();
        }
        let mut dropped: Vec<String> = Vec::new();
        let mut root = String::new();
        let mut spa = false;

        let steps = flatten_steps(handle);
        for step in &steps {
            if !step.match_.is_empty() {
                let path = path_only(&step.match_);
                if spa_rewrite(step) {
                    spa = true;
                    continue;
                }
                let Some(path) = path else {
                    dropped.push(describe(step));
                    continue;
                };
                match path_route(&path, &step.handlers) {
                    Some(rt) => st.config.routes.push(rt),
                    None => dropped.push(format!("route {path}")),
                }
                continue;
            }
            for h in &step.handlers {
                let c = &mut st.config;
                match handler_name(h).as_str() {
                    "headers" => {
                        if !response_headers(h, c) {
                            dropped.push("headers (request)".into());
                        }
                    }
                    "encode" => c.compression = encodings(h),
                    "request_body" => {
                        if let Some(n) = num(h.get("max_size")) {
                            c.max_body_size = byte_size(n as i64);
                        }
                    }
                    "authentication" => {
                        if !basic_auth(h, c) {
                            dropped.push("authentication".into());
                        }
                    }
                    "vars" => {
                        let r = s(h.get("root"));
                        if !r.is_empty() {
                            root = r;
                        }
                    }
                    "file_server" => {
                        st.kind = KIND_STATIC.into();
                        st.config.r#static = Some(StaticConfig {
                            root: root.clone(),
                            browse: h.contains_key("browse"),
                            spa: false,
                        });
                    }
                    "reverse_proxy" => match proxy_config(h) {
                        Some(p) => {
                            st.kind = KIND_PROXY.into();
                            st.config.proxy = Some(p);
                        }
                        None => dropped.push("reverse_proxy (non-HTTP transport)".into()),
                    },
                    "static_response" => {
                        if let Some(red) = redirect(h) {
                            st.kind = KIND_REDIRECT.into();
                            st.config.redirect = Some(red);
                        } else {
                            st.kind = KIND_RESPOND.into();
                            st.config.respond = Some(respond(h));
                        }
                    }
                    other => dropped.push(other.to_string()),
                }
            }
        }
        if let Some(sc) = st.config.r#static.as_mut() {
            if sc.root.is_empty() {
                sc.root = root.clone();
            }
            sc.spa = spa;
        }
        if st.kind.is_empty() {
            self.manual(
                &label,
                orig,
                &format!(
                    "no handler CaddyHub understands ({})",
                    uniq(&dropped).join(", ")
                ),
            );
            return;
        }
        let kind = st.kind.clone();
        self.res.sites.push(st);
        if !dropped.is_empty() {
            self.keep_json(&format!("{label} (unmapped parts)"), orig);
            self.res.report(&label, "partial", &format!("imported as {kind}; not mapped: {}. The original JSON is kept as a disabled raw block.", uniq(&dropped).join(", ")));
            return;
        }
        self.res
            .report(&label, "structured", &format!("{kind} site"));
    }

    /// Keeps a route that can't be modeled, as commented JSON.
    fn manual(&mut self, label: &str, r: &JRoute, why: &str) {
        self.keep_json(label, r);
        self.res.report(
            label,
            "raw",
            &format!("{why}; kept as a disabled raw block with the original JSON for reference"),
        );
    }

    fn keep_json(&mut self, label: &str, r: &JRoute) {
        let b = serde_json::to_string_pretty(r).unwrap_or_default();
        let mut sb = String::new();
        sb.push_str("# Imported from Caddy JSON; CaddyHub could not map this automatically.\n");
        sb.push_str("# Rewrite it as Caddyfile directives (or add it to a site's custom box), then enable this block.\n");
        for l in b.split('\n') {
            sb.push_str("# ");
            sb.push_str(l);
            sb.push('\n');
        }
        self.pos += 1;
        self.res.raw_blocks.push(RawBlock {
            name: label.into(),
            body: sb,
            enabled: false,
            position: self.pos,
            source: "import".into(),
            ..Default::default()
        });
    }
}

/// Reports whether a handler list is a subroute of host-matched routes.
fn host_split(handle: &[Map<String, Value>]) -> Option<Vec<JRoute>> {
    if handle.len() != 1 || handler_name(&handle[0]) != "subroute" {
        return None;
    }
    let mut out = Vec::new();
    for r in sub_routes(&handle[0]) {
        let (hs, other) = split_match(&r.match_);
        if hs.is_empty() || other {
            // tolerate a trailing catch-all such as `handle { abort }`
            if r.match_.is_empty() && only_abort(&r.handle) {
                continue;
            }
            return None;
        }
        out.push(r);
    }
    if out.is_empty() { None } else { Some(out) }
}

fn only_abort(h: &[Map<String, Value>]) -> bool {
    flatten_handlers(h)
        .iter()
        .all(|x| handler_name(x) == "static_response" && x.get("abort") == Some(&Value::Bool(true)))
}

// ---------------------------------------------------------------- handler flattening

struct Step {
    match_: Vec<Map<String, Value>>,
    handlers: Vec<Map<String, Value>>,
}

/// Unwraps unmatched subroutes into a linear list of steps; a matched
/// subroute becomes one step whose handlers are its flattened content.
fn flatten_steps(handle: &[Map<String, Value>]) -> Vec<Step> {
    let mut out: Vec<Step> = Vec::new();
    let mut cur: Vec<Map<String, Value>> = Vec::new();
    for h in handle {
        if handler_name(h) != "subroute" {
            cur.push(h.clone());
            continue;
        }
        if !cur.is_empty() {
            out.push(Step {
                match_: Vec::new(),
                handlers: std::mem::take(&mut cur),
            });
        }
        for r in sub_routes(h) {
            if r.match_.is_empty() {
                out.extend(flatten_steps(&r.handle));
                continue;
            }
            out.push(Step {
                match_: r.match_.clone(),
                handlers: flatten_handlers(&r.handle),
            });
        }
    }
    if !cur.is_empty() {
        out.push(Step {
            match_: Vec::new(),
            handlers: cur,
        });
    }
    out
}

/// Lists all handlers inside nested unmatched subroutes.
fn flatten_handlers(handle: &[Map<String, Value>]) -> Vec<Map<String, Value>> {
    let mut out = Vec::new();
    for h in handle {
        if handler_name(h) == "subroute" {
            for r in sub_routes(h) {
                if r.match_.is_empty() {
                    out.extend(flatten_handlers(&r.handle));
                } else {
                    let mut m = Map::new();
                    m.insert("handler".into(), Value::String("matched_subroute".into()));
                    out.push(m);
                }
            }
            continue;
        }
        out.push(h.clone());
    }
    out
}

fn split_match(ms: &[Map<String, Value>]) -> (Vec<String>, bool) {
    let mut hosts: Vec<String> = Vec::new();
    let mut other = false;
    for m in ms {
        for (k, v) in m {
            if k != "host" {
                other = true;
                continue;
            }
            if let Some(hs) = v.as_array() {
                for h in hs {
                    if let Some(h) = h.as_str() {
                        append_unique(&mut hosts, &h.to_ascii_lowercase());
                    }
                }
            }
        }
    }
    (hosts, other)
}

fn path_only(ms: &[Map<String, Value>]) -> Option<String> {
    if ms.len() != 1 || ms[0].len() != 1 {
        return None;
    }
    let ps = ms[0].get("path")?.as_array()?;
    if ps.len() != 1 {
        return None;
    }
    ps[0].as_str().map(|s| s.to_string())
}

/// Detects `try_files {path} /index.html`.
fn spa_rewrite(st: &Step) -> bool {
    if st.handlers.len() != 1 || handler_name(&st.handlers[0]) != "rewrite" || st.match_.len() != 1
    {
        return false;
    }
    let Some(f) = st.match_[0]
        .get("file")
        .and_then(|f| f.get("try_files"))
        .and_then(|t| t.as_array())
    else {
        return false;
    };
    f.len() == 2 && f[0] == "{http.request.uri.path}" && f[1] == "/index.html"
}

fn describe(st: &Step) -> String {
    let mut keys: Vec<&str> = st
        .match_
        .iter()
        .flat_map(|m| m.keys().map(|k| k.as_str()))
        .collect();
    keys.sort();
    format!("route matching {}", keys.join("+"))
}

fn path_route(path: &str, hs: &[Map<String, Value>]) -> Option<Route> {
    let mut rt = Route {
        path: path.to_string(),
        ..Default::default()
    };
    for h in hs {
        match handler_name(h).as_str() {
            "rewrite" => {
                let p = s(h.get("strip_path_prefix"));
                if !p.is_empty() && path.starts_with(&p) {
                    rt.strip_prefix = true;
                    continue;
                }
                return None;
            }
            "reverse_proxy" => {
                rt.kind = KIND_PROXY.into();
                rt.proxy = Some(proxy_config(h)?);
            }
            "file_server" => {
                rt.kind = KIND_STATIC.into();
                rt.r#static = Some(StaticConfig {
                    root: s(h.get("root")),
                    ..Default::default()
                });
            }
            "static_response" => {
                if let Some(red) = redirect(h) {
                    rt.kind = KIND_REDIRECT.into();
                    rt.redirect = Some(red);
                } else {
                    rt.kind = KIND_RESPOND.into();
                    rt.respond = Some(respond(h));
                }
            }
            _ => return None,
        }
    }
    if rt.kind.is_empty() { None } else { Some(rt) }
}

// ---------------------------------------------------------------- handlers

fn proxy_config(h: &Map<String, Value>) -> Option<ProxyConfig> {
    let mut p = ProxyConfig::default();
    let mut scheme = "";
    if let Some(tr) = h.get("transport").and_then(|t| t.as_object()) {
        let proto = s(tr.get("protocol"));
        if !proto.is_empty() && proto != "http" {
            return None;
        }
        if let Some(tls) = tr.get("tls").and_then(|t| t.as_object()) {
            scheme = "https://";
            p.tls_skip_verify = tls.get("insecure_skip_verify") == Some(&Value::Bool(true));
            p.tls_server_name = s(tls.get("server_name"));
        }
        if let Some(vs) = tr.get("versions").and_then(|v| v.as_array()) {
            if vs.iter().any(|v| s(Some(v)) == "h2c") {
                p.h2c = true;
            }
        }
        p.dial_timeout = dur(tr.get("dial_timeout"));
        p.response_header_timeout = dur(tr.get("response_header_timeout"));
        p.read_timeout = dur(tr.get("read_timeout"));
        p.write_timeout = dur(tr.get("write_timeout"));
    }
    if let Some(ups) = h.get("upstreams").and_then(|u| u.as_array()) {
        for u in ups {
            let d = s(u.get("dial"));
            if !d.is_empty() {
                p.upstreams.push(format!("{scheme}{d}"));
            }
        }
    }
    if p.upstreams.is_empty() {
        return None;
    }
    if let Some(lb) = h.get("load_balancing").and_then(|l| l.as_object()) {
        if let Some(sp) = lb.get("selection_policy").and_then(|x| x.as_object()) {
            p.lb_policy = s(sp.get("policy"));
        }
        if let Some(n) = num(lb.get("retries")) {
            p.lb_retries = n as i64;
        }
        p.lb_try_duration = dur(lb.get("try_duration"));
    }
    if let Some(hc) = h.get("health_checks").and_then(|x| x.as_object()) {
        if let Some(a) = hc.get("active").and_then(|x| x.as_object()) {
            p.health_uri = s(a.get("uri"));
            if p.health_uri.is_empty() {
                p.health_uri = s(a.get("path"));
            }
            p.health_interval = dur(a.get("interval"));
            p.health_timeout = dur(a.get("timeout"));
            if let Some(n) = num(a.get("expect_status")) {
                p.health_status = (n as i64).to_string();
            }
        }
        if let Some(ps) = hc.get("passive").and_then(|x| x.as_object()) {
            p.fail_duration = dur(ps.get("fail_duration"));
            if let Some(n) = num(ps.get("max_fails")) {
                p.max_fails = n as i64;
            }
        }
    }
    if let Some(fi) = h.get("flush_interval") {
        match num(Some(fi)) {
            Some(n) if n < 0.0 => p.flush_interval = "-1".into(),
            _ => p.flush_interval = dur(Some(fi)),
        }
    }
    if let Some(hd) = h.get("headers").and_then(|x| x.as_object()) {
        p.header_up = header_set(hd.get("request"));
        p.header_down = header_set(hd.get("response"));
    }
    Some(p)
}

fn header_set(v: Option<&Value>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(set) = v.and_then(|m| m.get("set")).and_then(|s| s.as_object()) {
        for (k, vals) in set {
            if let Some(first) = vals.as_array().and_then(|vs| vs.first()) {
                out.insert(k.clone(), s(Some(first)));
            }
        }
    }
    out
}

fn response_headers(h: &Map<String, Value>, c: &mut SiteConfig) -> bool {
    if h.contains_key("request") {
        return false;
    }
    let Some(resp) = h.get("response").and_then(|r| r.as_object()) else {
        return false;
    };
    for (k, v) in header_set(Some(&Value::Object(resp.clone()))) {
        c.headers_set.insert(k, v);
    }
    if let Some(del) = resp.get("delete").and_then(|d| d.as_array()) {
        for d in del {
            append_unique(&mut c.headers_remove, &s(Some(d)));
        }
    }
    true
}

fn encodings(h: &Map<String, Value>) -> Vec<String> {
    if let Some(pref) = h.get("prefer").and_then(|p| p.as_array()) {
        return pref.iter().map(|p| s(Some(p))).collect();
    }
    let mut out = Vec::new();
    if let Some(enc) = h.get("encodings").and_then(|e| e.as_object()) {
        for k in ["zstd", "gzip"] {
            if enc.contains_key(k) {
                out.push(k.to_string());
            }
        }
    }
    out
}

fn basic_auth(h: &Map<String, Value>, c: &mut SiteConfig) -> bool {
    let Some(accts) = h
        .get("providers")
        .and_then(|p| p.get("http_basic"))
        .and_then(|b| b.get("accounts"))
        .and_then(|a| a.as_array())
    else {
        return false;
    };
    if accts.is_empty() {
        return false;
    }
    for a in accts {
        c.access.basic_auth.push(BasicAuthUser {
            username: s(a.get("username")),
            hash: s(a.get("password")),
        });
    }
    true
}

fn status_code(h: &Map<String, Value>) -> Option<i64> {
    match h.get("status_code") {
        Some(Value::Number(n)) => n.as_i64(),
        Some(Value::String(x)) => x.parse().ok(),
        _ => None,
    }
}

fn redirect(h: &Map<String, Value>) -> Option<RedirectConfig> {
    let code = status_code(h)?;
    let loc = h
        .get("headers")
        .and_then(|hd| hd.get("Location"))
        .and_then(|l| l.as_array())?;
    if !(300..=399).contains(&code) || loc.len() != 1 {
        return None;
    }
    let mut to = s(loc.first());
    let mut keep = false;
    for suf in ["{http.request.uri}", "{uri}"] {
        if let Some(t) = to.strip_suffix(suf) {
            to = t.to_string();
            keep = true;
        }
    }
    Some(RedirectConfig {
        to,
        code,
        keep_path: keep,
    })
}

fn respond(h: &Map<String, Value>) -> RespondConfig {
    let mut r = RespondConfig {
        body: s(h.get("body")),
        status: 200,
        ..Default::default()
    };
    if let Some(n) = status_code(h) {
        r.status = n;
    }
    if let Some(ct) = h
        .get("headers")
        .and_then(|hd| hd.get("Content-Type"))
        .and_then(|c| c.as_array())
        .and_then(|c| c.first())
    {
        r.content_type = s(Some(ct));
    }
    r
}

// ---------------------------------------------------------------- round trip

/// Summarizes what each host does, for comparing an imported config with
/// what CaddyHub regenerates from it.
pub fn fingerprint(res: &ImportResult) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for st in &res.sites {
        let c = &st.config;
        let mut parts: Vec<String> = Vec::new();
        match st.kind.as_str() {
            KIND_PROXY => {
                let mut ups = c
                    .proxy
                    .as_ref()
                    .map(|p| p.upstreams.clone())
                    .unwrap_or_default();
                ups.sort();
                parts.push(format!("proxy {}", ups.join(",")));
            }
            KIND_STATIC => {
                let sc = c.r#static.clone().unwrap_or_default();
                parts.push(format!(
                    "files {} browse={} spa={}",
                    sc.root, sc.browse, sc.spa
                ));
            }
            KIND_REDIRECT => {
                let r = c.redirect.clone().unwrap_or_default();
                parts.push(format!("redirect {} {} keep={}", r.to, r.code, r.keep_path));
            }
            KIND_RESPOND => {
                let r = c.respond.clone().unwrap_or_default();
                parts.push(format!("respond {} {:?}", r.status, r.body));
            }
            _ => {}
        }
        for r in &c.routes {
            let mut t = r.kind.clone();
            if let Some(p) = &r.proxy {
                t = format!("{t} {}", p.upstreams.join(","));
            }
            parts.push(format!("route {} strip={} {}", r.path, r.strip_prefix, t));
        }
        let mut users: Vec<&str> = c
            .access
            .basic_auth
            .iter()
            .map(|u| u.username.as_str())
            .collect();
        if !users.is_empty() {
            users.sort();
            parts.push(format!("auth {}", users.join(",")));
        }
        let mode = if c.tls.mode.is_empty() {
            TLS_AUTO
        } else {
            c.tls.mode.as_str()
        };
        parts.push(format!("tls {mode}"));
        let fp = parts.join("; ");
        for h in &st.hosts {
            out.insert(h.clone(), fp.clone());
        }
    }
    out
}

/// Lists hosts whose behavior differs between a and b.
pub fn compare_fingerprints(
    a: &BTreeMap<String, String>,
    b: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut diffs = Vec::new();
    for (h, fa) in a {
        match b.get(h) {
            None => diffs.push(format!("{h}: missing after regeneration")),
            Some(fb) if fa != fb => diffs.push(format!("{h}: was {fa:?}, regenerated as {fb:?}")),
            _ => {}
        }
    }
    for h in b.keys() {
        if !a.contains_key(h) {
            diffs.push(format!("{h}: appears only after regeneration"));
        }
    }
    diffs.sort();
    diffs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(format_duration(30_000_000_000), "30s");
        assert_eq!(format_duration(90_000_000_000), "1m30s");
        assert_eq!(format_duration(3_600_000_000_000), "1h0m0s");
        assert_eq!(format_duration(1_500_000_000), "1.5s");
        assert_eq!(format_duration(250_000_000), "250ms");
        assert_eq!(byte_size(10_000_000), "10MB");
    }
}
