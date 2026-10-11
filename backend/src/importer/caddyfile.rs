use anyhow::{Result, anyhow};
use std::collections::{BTreeMap, HashMap, HashSet};

use super::{Credential, DomainSuggestion, ImportResult, append_unique, ref_value};
use crate::caddyfile::{Directive, TopBlock, parse};
use crate::model::*;
use crate::registry::dns_provider_by_id;

struct Importer<'a> {
    src: &'a str,
    res: ImportResult,
    ncreds: usize,
    /// from acme_dns / dns global option
    global: Option<Credential>,
}

/// Parses a Caddyfile.
pub fn import(src: &str) -> Result<ImportResult> {
    let src = src.replace("\r\n", "\n");
    let blocks = parse(&src).map_err(|e| anyhow!("cannot parse Caddyfile: {e}"))?;
    let mut im = Importer {
        src: &src,
        res: ImportResult::default(),
        ncreds: 0,
        global: None,
    };
    let mut pos = 0i64;
    for b in &blocks {
        if b.is_global() {
            im.global_block(b);
        } else if b.is_snippet() {
            let name = b.keys[0]
                .text
                .trim_start_matches('(')
                .trim_end_matches(')')
                .to_string();
            let body = inner_text(b);
            im.res.snippets.push(Snippet {
                name: name.clone(),
                body,
                description: "imported".into(),
                ..Default::default()
            });
            im.res.report(&b.keys[0].text, "structured", "snippet");
        } else if b.is_named_route() {
            pos += 1;
            im.raw(b, pos, "named route kept as raw block");
        } else {
            pos += 1;
            im.site_block(b, pos);
        }
    }
    // apply global DNS provider to all imported domains
    if let Some(g) = im.global.clone() {
        let mut seen: HashSet<String> = im.res.domains.iter().map(|d| d.name.clone()).collect();
        for s in &im.res.sites {
            for h in &s.hosts {
                let bd = base_domain(h);
                if !bd.is_empty() && seen.insert(bd.clone()) {
                    im.res.domains.push(DomainSuggestion {
                        name: bd,
                        challenge: CHALLENGE_DNS.into(),
                        credential_key: g.key.clone(),
                        wildcard: false,
                    });
                }
            }
        }
    }
    Ok(im.res)
}

/// The source between a block's braces.
fn inner_text(b: &TopBlock) -> String {
    let t = &b.text;
    let (Some(i), Some(j)) = (t.find('{'), t.rfind('}')) else {
        return String::new();
    };
    if j <= i {
        return String::new();
    }
    t[i + 1..j].trim_matches('\n').to_string()
}

impl Importer<'_> {
    fn raw(&mut self, b: &TopBlock, pos: i64, why: &str) {
        let name = b.key_strings().join(", ");
        self.res.raw_blocks.push(RawBlock {
            name: name.clone(),
            body: b.text.clone(),
            enabled: true,
            position: pos,
            source: "import".into(),
            ..Default::default()
        });
        self.res.report(&name, "raw", why);
    }

    // ---------------------------------------------------------------- global

    fn global_block(&mut self, b: &TopBlock) {
        let mut raw: Vec<String> = Vec::new();
        for d in &b.body {
            let args = d.arg_strings();
            match d.name() {
                "email" if args.len() == 1 => {
                    self.res.email = args[0].to_string();
                    continue;
                }
                "acme_ca" if args.len() == 1 => {
                    self.res.set_ca(args[0]);
                    continue;
                }
                "admin" => {
                    self.res.report(
                        "global: admin",
                        "skipped",
                        "the panel manages the admin endpoint",
                    );
                    continue;
                }
                "acme_dns" | "dns" => {
                    if let Some(c) = self.dns_cred(d) {
                        let detail =
                            format!("DNS provider {} applied to imported domains", c.provider);
                        self.global = Some(c);
                        self.res
                            .report(&format!("global: {}", d.name()), "structured", &detail);
                        continue;
                    }
                }
                "local_certs" => {
                    self.res.acme_ca = "caddy_internal".into();
                    continue;
                }
                "log" if args.is_empty() => {
                    self.res
                        .report("global: log", "skipped", "the panel manages Caddy's logs");
                    continue;
                }
                _ => {}
            }
            raw.push(d.source(self.src).to_string());
        }
        if !raw.is_empty() {
            self.res.raw_global = raw.join("\n");
            let n = raw.len();
            self.res.report(
                "global options",
                "partial",
                &format!("{n} option(s) kept as raw global options"),
            );
        }
    }

    /// Parses `dns <provider> [token] [{ ... }]`.
    fn dns_cred(&mut self, d: &Directive) -> Option<Credential> {
        let args = d.arg_strings();
        let prov = dns_provider_by_id(args.first()?)?;
        let mut c = Credential {
            provider: prov.id.to_string(),
            fields: BTreeMap::new(),
            key: String::new(),
        };
        if args.len() == 2 {
            // single-argument form maps to the first required field
            if let Some(f) = prov.fields.iter().find(|f| f.required) {
                c.fields.insert(f.key.to_string(), ref_value(args[1]));
            }
        } else if args.len() > 2 {
            return None;
        }
        let known: HashSet<&str> = prov.fields.iter().map(|f| f.key).collect();
        for sub in &d.block {
            let sa = sub.arg_strings();
            if !known.contains(sub.name()) || sa.len() != 1 {
                return None;
            }
            c.fields.insert(sub.name().to_string(), ref_value(sa[0]));
        }
        c.key = format!("{}:{}", prov.id, self.ncreds);
        // dedupe identical credentials
        if let Some(ex) = self
            .res
            .credentials
            .iter()
            .find(|ex| ex.provider == c.provider && ex.fields == c.fields)
        {
            return Some(ex.clone());
        }
        self.ncreds += 1;
        self.res.credentials.push(c.clone());
        Some(c)
    }

    // ---------------------------------------------------------------- sites

    fn site_block(&mut self, b: &TopBlock, pos: i64) {
        let keys = b.key_strings();
        let name = keys.join(", ");
        let mut schemes: HashMap<String, HashSet<String>> = HashMap::new();
        let mut hosts: Vec<String> = Vec::new();
        for k in &keys {
            let Some((h, sc)) = parse_address(k) else {
                self.raw(
                    b,
                    pos,
                    &format!("address {k} is not a plain hostname; kept verbatim"),
                );
                return;
            };
            if !schemes.contains_key(&h) {
                hosts.push(h.clone());
            }
            schemes.entry(h).or_default().insert(sc);
        }
        let mut site = Site {
            name: hosts[0].clone(),
            hosts: hosts.clone(),
            enabled: true,
            position: pos,
            tags: vec!["imported".into()],
            ..Default::default()
        };
        // scheme handling: all http -> TLS off; both http+https -> no redirect
        let mut all_http = true;
        let mut both = false;
        for s in schemes.values() {
            if !s.contains("http") {
                all_http = false;
            }
            if s.contains("http") && (s.contains("https") || s.contains("")) {
                both = true;
            }
        }
        if all_http && !both {
            site.config.tls.mode = TLS_OFF.into();
        } else if both {
            site.config.http_redirect = Some(false);
        }

        let mut raw: Vec<String> = Vec::new();
        let mut mapped = 0;
        let mut static_ = StaticConfig::default();
        let (mut has_root, mut has_fs) = (false, false);
        for d in &b.body {
            let mut ok = true;
            let c = &mut site.config;
            match d.name() {
                "reverse_proxy" => match parse_proxy(d) {
                    Some(p) if site.kind.is_empty() => {
                        site.kind = KIND_PROXY.into();
                        site.config.proxy = Some(p);
                    }
                    _ => ok = false,
                },
                "root" => {
                    let a = d.arg_strings();
                    if a.len() == 2 && a[0] == "*" {
                        static_.root = a[1].to_string();
                        has_root = true;
                    } else if a.len() == 1 && (!a[0].starts_with('/') || !a[0].ends_with('*')) {
                        static_.root = a[0].to_string();
                        has_root = true;
                    } else {
                        ok = false;
                    }
                }
                "file_server" => {
                    let a = d.arg_strings();
                    if d.has_block {
                        ok = false;
                    } else if a.is_empty() {
                        has_fs = true;
                    } else if a.len() == 1 && a[0] == "browse" {
                        has_fs = true;
                        static_.browse = true;
                    } else {
                        ok = false;
                    }
                }
                "try_files" => {
                    let a = d.arg_strings();
                    if a.len() == 2 && a[0] == "{path}" && a[1] == "/index.html" {
                        static_.spa = true;
                    } else {
                        ok = false;
                    }
                }
                "redir" => match parse_redir(d) {
                    Some(r) if site.kind.is_empty() => {
                        site.kind = KIND_REDIRECT.into();
                        site.config.redirect = Some(r);
                    }
                    _ => ok = false,
                },
                "respond" => match parse_respond(d) {
                    Some(r) if site.kind.is_empty() => {
                        site.kind = KIND_RESPOND.into();
                        site.config.respond = Some(r);
                    }
                    _ => ok = false,
                },
                "encode" => {
                    let a = d.arg_strings();
                    if d.has_block || a.is_empty() || a.iter().any(|e| *e != "zstd" && *e != "gzip")
                    {
                        ok = false;
                    } else {
                        c.compression = a.iter().map(|s| s.to_string()).collect();
                    }
                }
                "header" => ok = parse_header(d, c),
                "tls" => ok = self.parse_tls(d, &mut site),
                "log" => self.res.report(
                    &name,
                    "partial",
                    "log directive replaced by panel-managed access logs",
                ),
                "basic_auth" | "basicauth" => {
                    if !d.arg_strings().is_empty() {
                        ok = false;
                    } else {
                        for u in &d.block {
                            let ua = u.arg_strings();
                            if ua.len() != 1 {
                                ok = false;
                                break;
                            }
                            c.access.basic_auth.push(BasicAuthUser {
                                username: u.name().to_string(),
                                hash: ua[0].to_string(),
                            });
                        }
                    }
                }
                "request_body" => {
                    if d.block.len() == 1
                        && d.block[0].name() == "max_size"
                        && d.block[0].arg_strings().len() == 1
                        && d.arg_strings().is_empty()
                    {
                        c.max_body_size = d.block[0].arg_strings()[0].to_string();
                    } else {
                        ok = false;
                    }
                }
                "import" => {
                    let a = d.arg_strings();
                    if a.len() == 1 && !a[0].contains(['/', '*', '.']) {
                        c.snippets.push(a[0].to_string());
                    } else {
                        ok = false;
                    }
                }
                "handle" | "handle_path" => match parse_route(d) {
                    Some(r) => c.routes.push(r),
                    None => ok = false,
                },
                _ => ok = false,
            }
            if ok {
                mapped += 1;
            } else {
                raw.push(d.source(self.src).to_string());
            }
        }
        if has_root && has_fs && site.kind.is_empty() {
            site.kind = KIND_STATIC.into();
            site.config.r#static = Some(static_);
        } else if has_root || has_fs || static_.spa {
            // pieces of a static config without a clean mapping: keep raw
            for d in &b.body {
                if matches!(d.name(), "root" | "file_server" | "try_files") {
                    append_unique(&mut raw, d.source(self.src));
                }
            }
        }
        if site.kind.is_empty() {
            site.kind = KIND_NONE.into();
        }
        if !raw.is_empty() {
            site.config.raw = raw.join("\n");
        }
        let kind = site.kind.clone();
        self.res.sites.push(site);
        if raw.is_empty() {
            self.res
                .report(&name, "structured", &format!("{kind} site"));
        } else if mapped == 0 {
            self.res.report(
                &name,
                "partial",
                "no directives mapped; everything kept in the site's raw snippet",
            );
        } else {
            self.res.report(
                &name,
                "partial",
                &format!("{} directive(s) kept in the site's raw snippet", raw.len()),
            );
        }
    }

    fn parse_tls(&mut self, d: &Directive, s: &mut Site) -> bool {
        let a = d.arg_strings();
        let c = &mut s.config;
        if !d.has_block && a.len() == 1 && a[0] == "internal" {
            c.tls.mode = TLS_INTERNAL.into();
            return true;
        }
        if !d.has_block && a.len() == 2 {
            c.tls = TlsConfig {
                mode: TLS_CUSTOM.into(),
                cert_file: a[0].to_string(),
                key_file: a[1].to_string(),
            };
            return true;
        }
        if !d.has_block && a.len() == 1 && a[0].contains('@') {
            if self.res.email.is_empty() {
                self.res.email = a[0].to_string();
            }
            return true;
        }
        if d.has_block && a.is_empty() {
            // only "dns <provider> ..." plus propagation/resolvers is mapped
            let mut cred: Option<Credential> = None;
            for sub in &d.block {
                match sub.name() {
                    "dns" => match self.dns_cred(sub) {
                        Some(c) => cred = Some(c),
                        None => return false,
                    },
                    // folded into domain/global settings; acceptable loss of
                    // per-site granularity is reported
                    "resolvers" | "propagation_delay" | "propagation_timeout" => {}
                    _ => return false,
                }
            }
            let Some(cred) = cred else { return false };
            for h in &s.hosts {
                let bd = base_domain(h);
                if bd.is_empty() {
                    continue;
                }
                if !self.res.domains.iter().any(|ds| ds.name == bd) {
                    self.res.domains.push(DomainSuggestion {
                        name: bd,
                        challenge: CHALLENGE_DNS.into(),
                        credential_key: cred.key.clone(),
                        wildcard: false,
                    });
                }
            }
            return true;
        }
        false
    }
}

/// Host and scheme for supported site addresses.
fn parse_address(a: &str) -> Option<(String, String)> {
    let (scheme, a) = if let Some(r) = a.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = a.strip_prefix("http://") {
        ("http", r)
    } else {
        ("", a)
    };
    if a.contains('/') || a.starts_with(':') || a.contains('{') {
        return None;
    }
    let mut host = a.to_string();
    if let Some((h, p)) = split_host_port(a) {
        if (p == "443" && scheme != "http") || (p == "80" && scheme == "http") {
            host = h.to_string();
        } else {
            return None;
        }
    }
    if host.starts_with('*') || !valid_host(&host) {
        return None;
    }
    Some((host.to_ascii_lowercase(), scheme.to_string()))
}

/// Splits "host:port" (IPv6 in brackets) into its parts, if it has a port.
pub fn split_host_port(a: &str) -> Option<(&str, &str)> {
    if let Some(r) = a.strip_prefix('[') {
        let i = r.find(']')?;
        let host = &r[..i];
        let rest = &r[i + 1..];
        let port = rest.strip_prefix(':')?;
        if port.is_empty() {
            return None;
        }
        return Some((host, port));
    }
    let i = a.rfind(':')?;
    let (host, port) = (&a[..i], &a[i + 1..]);
    if host.contains(':') || port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((host, port))
}

/// Checks a hostname (no wildcards, no ports).
pub fn valid_host(h: &str) -> bool {
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    if h.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    for l in h.split('.') {
        if l.is_empty() || l.len() > 63 || l.starts_with('-') || l.ends_with('-') {
            return false;
        }
        if !l
            .chars()
            .all(|r| r.is_ascii_alphanumeric() || r == '-' || r == '_')
        {
            return false;
        }
    }
    true
}

/// Guesses the zone of a host: the host itself for two labels, otherwise the
/// host minus its first label. Users can adjust in the wizard.
pub fn base_domain(h: &str) -> String {
    if h.parse::<std::net::IpAddr>().is_ok() || !h.contains('.') {
        return String::new();
    }
    let parts: Vec<&str> = h.split('.').collect();
    if parts.len() <= 2 {
        return h.to_string();
    }
    parts[1..].join(".")
}

fn is_matcher(s: &str) -> bool {
    s.starts_with('@') || s.starts_with('/') || s == "*"
}

const PROXY_SCALAR: &[&str] = &[
    "lb_policy",
    "lb_retries",
    "lb_try_duration",
    "health_uri",
    "health_interval",
    "health_timeout",
    "health_status",
    "fail_duration",
    "max_fails",
    "unhealthy_status",
    "flush_interval",
];

fn parse_proxy(d: &Directive) -> Option<ProxyConfig> {
    let a = d.arg_strings();
    if a.first().is_some_and(|x| is_matcher(x)) {
        return None;
    }
    let mut p = ProxyConfig {
        upstreams: a.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    };
    for s in &d.block {
        let sa = s.arg_strings();
        let n = s.name();
        if n == "to" {
            p.upstreams.extend(sa.iter().map(|x| x.to_string()));
        } else if PROXY_SCALAR.contains(&n) && sa.len() == 1 {
            let v = sa[0].to_string();
            match n {
                "lb_policy" => p.lb_policy = v,
                "lb_retries" => p.lb_retries = v.parse().ok()?,
                "lb_try_duration" => p.lb_try_duration = v,
                "health_uri" => p.health_uri = v,
                "health_interval" => p.health_interval = v,
                "health_timeout" => p.health_timeout = v,
                "health_status" => p.health_status = v,
                "fail_duration" => p.fail_duration = v,
                "max_fails" => p.max_fails = v.parse().ok()?,
                "unhealthy_status" => p.unhealthy_status = v,
                "flush_interval" => p.flush_interval = v,
                _ => {}
            }
        } else if (n == "header_up" || n == "header_down")
            && sa.len() == 2
            && !sa[0].starts_with('+')
            && !sa[0].starts_with('-')
        {
            if n == "header_up" {
                if sa[0].eq_ignore_ascii_case("Host") && sa[1] == "{upstream_hostport}" {
                    p.pass_host_header = Some(false);
                    continue;
                }
                p.header_up.insert(sa[0].to_string(), sa[1].to_string());
            } else {
                p.header_down.insert(sa[0].to_string(), sa[1].to_string());
            }
        } else if n == "transport" && sa.len() == 1 && sa[0] == "http" {
            for t in &s.block {
                let ta = t.arg_strings();
                match (t.name(), ta.len()) {
                    ("tls", 0) => {}
                    ("tls_insecure_skip_verify", 0) => p.tls_skip_verify = true,
                    ("tls_server_name", 1) => p.tls_server_name = ta[0].to_string(),
                    ("versions", _) if ta.join(" ") == "h2c 2" => p.h2c = true,
                    ("versions", _) if ta.join(" ") == "2" => p.http2 = true,
                    ("dial_timeout", 1) => p.dial_timeout = ta[0].to_string(),
                    ("response_header_timeout", 1) => p.response_header_timeout = ta[0].to_string(),
                    ("read_timeout", 1) => p.read_timeout = ta[0].to_string(),
                    ("write_timeout", 1) => p.write_timeout = ta[0].to_string(),
                    _ => return None,
                }
            }
        } else {
            return None;
        }
    }
    if p.upstreams.is_empty() {
        return None;
    }
    Some(p)
}

fn parse_redir(d: &Directive) -> Option<RedirectConfig> {
    let a = d.arg_strings();
    if d.has_block || a.is_empty() || a.len() > 2 || (is_matcher(a[0]) && !a[0].starts_with('/')) {
        return None;
    }
    if a.len() == 2 && a[0].starts_with('/') && !a[1].starts_with('/') && !a[1].contains("://") {
        // "redir /path target" vs "redir target code" ambiguity: be strict
        if a[1].parse::<i64>().is_err()
            && a[1] != "permanent"
            && a[1] != "temporary"
            && a[1] != "html"
        {
            return None;
        }
    }
    let mut r = RedirectConfig {
        to: a[0].to_string(),
        code: 302,
        keep_path: false,
    };
    if let Some(t) = r.to.strip_suffix("{uri}") {
        r.to = t.to_string();
        r.keep_path = true;
    }
    if a.len() == 2 {
        match a[1] {
            "permanent" => r.code = 301,
            "temporary" => r.code = 302,
            other => {
                let n: i64 = other.parse().ok()?;
                if !(300..=399).contains(&n) {
                    return None;
                }
                r.code = n;
            }
        }
    }
    Some(r)
}

fn parse_respond(d: &Directive) -> Option<RespondConfig> {
    let a = d.arg_strings();
    if d.has_block || a.len() > 2 || a.first().is_some_and(|x| is_matcher(x)) {
        return None;
    }
    let mut r = RespondConfig {
        status: 200,
        ..Default::default()
    };
    match a.len() {
        1 => {
            if let Ok(n) = a[0].parse::<i64>() {
                if (100..=999).contains(&n) && !d.args[1].quoted {
                    r.status = n;
                    return Some(r);
                }
            }
            r.body = a[0].to_string();
        }
        2 => {
            r.body = a[0].to_string();
            r.status = a[1].parse().ok()?;
        }
        _ => {}
    }
    Some(r)
}

fn parse_header(d: &Directive, c: &mut SiteConfig) -> bool {
    let a = d.arg_strings();
    if d.has_block {
        if !a.is_empty() {
            return false;
        }
        for s in &d.block {
            let sa = s.arg_strings();
            let n = s.name();
            if let Some(rm) = n.strip_prefix('-') {
                if sa.is_empty() {
                    c.headers_remove.push(rm.to_string());
                    continue;
                }
                return false;
            }
            if !n.starts_with(['+', '>', '?']) && sa.len() == 1 && n != "defer" && n != "match" {
                c.headers_set.insert(n.to_string(), sa[0].to_string());
            } else {
                return false;
            }
        }
        return true;
    }
    if a.len() == 1 {
        if let Some(rm) = a[0].strip_prefix('-') {
            c.headers_remove.push(rm.to_string());
            return true;
        }
    }
    if a.len() == 2 && !is_matcher(a[0]) && !a[0].starts_with(['+', '-', '?', '>']) {
        c.headers_set.insert(a[0].to_string(), a[1].to_string());
        return true;
    }
    false
}

fn parse_route(d: &Directive) -> Option<Route> {
    let a = d.arg_strings();
    if a.len() != 1 || !a[0].starts_with('/') || !d.has_block || d.block.len() != 1 {
        return None;
    }
    let mut r = Route {
        path: a[0].to_string(),
        strip_prefix: d.name() == "handle_path",
        ..Default::default()
    };
    let inner = &d.block[0];
    match inner.name() {
        "reverse_proxy" => {
            r.kind = KIND_PROXY.into();
            r.proxy = Some(parse_proxy(inner)?);
        }
        "redir" => {
            r.kind = KIND_REDIRECT.into();
            r.redirect = Some(parse_redir(inner)?);
        }
        "respond" => {
            r.kind = KIND_RESPOND.into();
            r.respond = Some(parse_respond(inner)?);
        }
        _ => return None,
    }
    Some(r)
}
