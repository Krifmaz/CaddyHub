use axum::extract::{Extension, State};
use axum::http::StatusCode;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;

use super::{ApiError, ApiResult, AppState, Client, OptJson, Principal, ok};
use crate::importer::split_host_port;
use crate::model::ProxyConfig;
use crate::scan;

#[derive(Serialize)]
struct ScanResult {
    #[serde(flatten)]
    found: scan::Found,
    upstream: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct ScanReq {
    target: String,
}

/// Finds web apps for the upstream "quick fill". With an empty target it
/// scans the networks the panel is attached to; otherwise a hostname, IP
/// or /24 range. Private addresses only, one scan at a time.
pub async fn scan(
    State(st): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    c: Client,
    OptJson(req): OptJson<ScanReq>,
) -> ApiResult {
    let Ok(_guard) = st.scan_lock.try_lock() else {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "a scan is already running; try again in a few seconds".into(),
        ));
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let target = req.target.trim().to_string();
    let (found, scanned, timed_out) = if target.is_empty() {
        scan_everywhere(&st, &c, deadline).await?
    } else {
        let ts = scan::resolve(&target).await.map_err(|e| {
            if e.downcast_ref::<scan::PublicAddress>().is_some() {
                ApiError(StatusCode::FORBIDDEN, e.to_string())
            } else {
                ApiError::bad(e.to_string())
            }
        })?;
        let mut o = scan::Options {
            deadline: Some(deadline),
            ..Default::default()
        };
        if ts.len() > 1 {
            // a range: most addresses are empty, so fail fast
            o.dial_timeout = Duration::from_millis(250);
            o.concurrency = 1024;
        }
        let (f, t) = scan::hosts(ts, o).await;
        (f, vec![target.clone()], t)
    };
    let out: Vec<ScanResult> = found
        .into_iter()
        .map(|mut f| {
            if f.source.is_empty() {
                f.source = "lan".into();
            }
            let upstream = f.upstream();
            ScanResult { found: f, upstream }
        })
        .collect();
    st.audit(
        Some(&p),
        &c,
        "scan",
        if target.is_empty() {
            "local networks"
        } else {
            &target
        },
        "",
    );
    ok(&serde_json::json!({"results": out, "scanned": scanned, "timed_out": timed_out}))
}

/// The LAN ranges to scan by default: the configured ones, plus the /24 of
/// the address the panel was opened at when that's a private IP (e.g.
/// http://10.0.1.5:8080 -> 10.0.1.0/24). That address is the Docker host,
/// so its published ports are found too.
fn lan_ranges(st: &AppState, c: &Client) -> (Vec<Ipv4Net>, Option<IpAddr>) {
    let mut ranges: Vec<Ipv4Net> = Vec::new();
    let mut add = |p: Ipv4Net| {
        let p = p.trunc();
        if !ranges.contains(&p) && p.prefix_len() >= 24 && scan::allowed(IpAddr::V4(p.addr())) {
            ranges.push(p);
        }
    };
    for r in st.store.settings().scan_ranges {
        let r = r.trim();
        if let Ok(p) = r.parse::<Ipv4Net>() {
            add(p);
        } else if let Ok(a) = r.parse::<std::net::Ipv4Addr>() {
            add(Ipv4Net::new(a, 32).unwrap());
        }
    }
    let mut host = c.host.as_str();
    if let Some((h, _)) = split_host_port(host) {
        host = h;
    }
    let mut host_ip = None;
    if let Ok(a) = host.trim_matches(['[', ']']).parse::<std::net::Ipv4Addr>() {
        if a.is_private() {
            host_ip = Some(IpAddr::V4(a));
            add(Ipv4Net::new(a, 24).unwrap());
        }
    }
    (ranges, host_ip)
}

/// Scans the Docker networks and the LAN in parallel.
async fn scan_everywhere(
    st: &AppState,
    c: &Client,
    deadline: tokio::time::Instant,
) -> Result<(Vec<scan::Found>, Vec<String>, bool), ApiError> {
    let (lan, host_ip) = lan_ranges(st, c);
    let covered = host_ip.is_some_and(|h| {
        lan.iter().any(|p| match h {
            IpAddr::V4(v) => p.contains(&v),
            _ => false,
        })
    });
    let docker = tokio::spawn(scan::network(
        scan::Options {
            deadline: Some(deadline),
            ..Default::default()
        },
        covered,
    ));
    let lan2 = lan.clone();
    let on_lan = tokio::spawn(async move {
        let mut out: Vec<scan::Found> = Vec::new();
        let mut timed_out = false;
        for p in lan2 {
            let Ok(ts) = scan::resolve(&p.to_string()).await else {
                continue;
            };
            let (f, t) = scan::hosts(
                ts,
                scan::Options {
                    dial_timeout: Duration::from_millis(250),
                    concurrency: 1024,
                    deadline: Some(deadline),
                    ..Default::default()
                },
            )
            .await;
            out.extend(f);
            timed_out |= t;
        }
        scan::name_results(&mut out).await;
        (out, timed_out)
    });
    let docker = docker
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let (on_lan, lan_timed_out) = on_lan
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let mut scanned: Vec<String> = Vec::new();
    if docker.is_ok() {
        scanned.push("Docker networks".into());
    }
    scanned.extend(lan.iter().map(|p| p.to_string()));
    let docker = match docker {
        Ok(d) => d,
        Err(e) if lan.is_empty() => return Err(ApiError::bad(e.to_string())),
        Err(_) => Vec::new(),
    };
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for (src, fs) in [("docker", docker), ("lan", on_lan)] {
        for mut f in fs {
            let k = format!("{}:{}", f.ip, f.port);
            if !seen.insert(k) {
                continue;
            }
            f.source = src.into();
            out.push(f);
        }
    }
    Ok((
        out,
        scanned,
        lan_timed_out || tokio::time::Instant::now() >= deadline,
    ))
}

// ---------------------------------------------------------------- reach

/// Whether an upstream accepts TCP connections.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ReachResult {
    pub upstream: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub error: String,
}

/// Turns "https://host:port", "host:port" or "host" into host:port.
fn upstream_addr(u: &str) -> String {
    let u = u.trim();
    let mut scheme = "";
    let mut hp = u.to_string();
    if let Some(i) = u.find("://") {
        scheme = &u[..i];
        if let Ok(pu) = url::Url::parse(u) {
            if let Some(h) = pu.host_str() {
                hp = match pu.port() {
                    Some(p) => format!("{h}:{p}"),
                    None => h.to_string(),
                };
            }
        }
    }
    if split_host_port(&hp).is_some() {
        return hp;
    }
    let port = if scheme == "https" { 443 } else { 80 };
    if hp.contains(':') {
        format!("[{hp}]:{port}")
    } else {
        format!("{hp}:{port}")
    }
}

/// Turns a dial error into advice a non-expert can act on.
fn explain_dial(addr: &str, err: &str) -> String {
    let host = split_host_port(addr).map(|(h, _)| h).unwrap_or(addr);
    let e = err.to_ascii_lowercase();
    if e.contains("no such host")
        || e.contains("not known")
        || e.contains("failed to lookup")
        || e.contains("nodename")
        || e.contains("no address")
        || e.contains("getaddrinfo")
        || e.contains("dns")
    {
        return format!(
            "name “{host}” not found. If it's a Docker container, Caddy and Caddymium must share a Docker network with it (or use the server's IP and published port instead)"
        );
    }
    if e.contains("refused") {
        return format!(
            "found {host}, but nothing is listening on that port. Check the port number and that the app is running"
        );
    }
    if e.contains("timed out") || e.contains("timeout") {
        return format!("no answer from {host} (wrong IP, app stopped, or a firewall)");
    }
    err.to_string()
}

/// Tests every proxy upstream of every site from the panel. The panel shares
/// Caddy's networks in the shipped compose files, so this tells whether
/// Caddy can reach the app; Caddy's own counters can't (they stay at zero
/// unless health checks are configured).
pub async fn reach(State(st): State<Arc<AppState>>) -> ApiResult {
    let sites = st.store.sites()?;
    let mut ups: Vec<String> = Vec::new();
    let mut add = |p: Option<&ProxyConfig>| {
        if let Some(p) = p {
            for u in &p.upstreams {
                let u = u.trim();
                if !u.is_empty() && !ups.iter().any(|x| x == u) && !u.starts_with("unix/") {
                    ups.push(u.to_string());
                }
            }
        }
    };
    for s in sites.iter().filter(|s| s.enabled) {
        add(s.config.proxy.as_ref());
        for rt in &s.config.routes {
            add(rt.proxy.as_ref());
        }
    }
    let mut set = JoinSet::new();
    for (i, u) in ups.iter().enumerate() {
        let u = u.clone();
        set.spawn(async move {
            let addr = upstream_addr(&u);
            let r = probe_upstream(&u, &addr).await;
            (i, r)
        });
    }
    let mut out: Vec<Option<ReachResult>> = vec![None; ups.len()];
    while let Some(r) = set.join_next().await {
        if let Ok((i, r)) = r {
            out[i] = Some(r);
        }
    }
    ok(&out.into_iter().flatten().collect::<Vec<_>>())
}

/// Resolves the name first (so a DNS failure is reported as such, not as a
/// timeout), then dials the first address.
async fn probe_upstream(u: &str, addr: &str) -> ReachResult {
    let host = split_host_port(addr)
        .map(|(h, _)| h)
        .unwrap_or(addr)
        .to_string();
    let fail = |error: String| ReachResult {
        upstream: u.to_string(),
        ok: false,
        error,
    };
    let resolved: Vec<std::net::SocketAddr> =
        match tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host(addr)).await {
            Ok(Ok(it)) => it.collect(),
            Ok(Err(e)) => return fail(explain_dial(addr, &format!("no such host: {e}"))),
            Err(_) => return fail(format!("looking up the name “{host}” timed out")),
        };
    let Some(sa) = resolved.first() else {
        return fail(explain_dial(addr, "no such host"));
    };
    match tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(sa)).await {
        Ok(Ok(_)) => ReachResult {
            upstream: u.to_string(),
            ok: true,
            error: String::new(),
        },
        Ok(Err(e)) => fail(explain_dial(addr, &e.to_string())),
        Err(_) => fail(explain_dial(addr, "timed out")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_addrs() {
        assert_eq!(upstream_addr("https://host"), "host:443");
        assert_eq!(upstream_addr("host:8096"), "host:8096");
        assert_eq!(upstream_addr("http://10.0.0.5:8006"), "10.0.0.5:8006");
        assert_eq!(upstream_addr("host"), "host:80");
    }
}
