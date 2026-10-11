//! Finds web apps on the local network so the UI can fill in a reverse-proxy
//! upstream: it TCP-connects to common self-hosted app ports, identifies
//! HTTP(S) services by their page title, and names Docker containers via
//! reverse DNS. Only private addresses are ever scanned.

use anyhow::{Result, anyhow};
use ipnet::Ipv4Net;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;
use tokio::time::Instant;

/// Common ports of self-hosted apps, checked by default.
pub const PORTS: &[u16] = &[
    80, 81, 443, 1880, 2283, 2342, 3000, 3001, 3002, 3579, 4000, 4533, 5000, 5001, 5005, 5006,
    5055, 5076, 5173, 5678, 5690, 6767, 6789, 6875, 7474, 7575, 7878, 8000, 8001, 8006, 8008, 8080,
    8081, 8082, 8083, 8084, 8085, 8086, 8088, 8090, 8091, 8096, 8112, 8123, 8181, 8191, 8200, 8265,
    8384, 8443, 8686, 8787, 8800, 8880, 8888, 8920, 8989, 9000, 9001, 9080, 9090, 9091, 9117, 9200,
    9443, 9696, 9925, 10000, 11000, 13378, 19999, 32400, 61208,
];

/// Guesses the app behind a port when the page title doesn't say.
pub const KNOWN_PORTS: &[(u16, &str)] = &[
    (1880, "Node-RED"),
    (2283, "Immich"),
    (2342, "PhotoPrism"),
    (3579, "Ombi"),
    (4533, "Navidrome"),
    (5055, "Overseerr / Jellyseerr"),
    (5076, "NZBHydra"),
    (5690, "Wizarr"),
    (6767, "Bazarr"),
    (6875, "BookStack"),
    (7878, "Radarr"),
    (8006, "Proxmox VE"),
    (8096, "Jellyfin"),
    (8112, "Deluge"),
    (8123, "Home Assistant"),
    (8181, "Tautulli"),
    (8191, "FlareSolverr"),
    (8265, "Tdarr"),
    (8384, "Syncthing"),
    (8686, "Lidarr"),
    (8787, "Readarr"),
    (8920, "Jellyfin (HTTPS)"),
    (8989, "Sonarr"),
    (9091, "Transmission"),
    (9117, "Jackett"),
    (9443, "Portainer"),
    (9696, "Prowlarr"),
    (9925, "Mealie"),
    (13378, "Audiobookshelf"),
    (19999, "Netdata"),
    (32400, "Plex"),
    (61208, "Glances"),
];

fn known_port(p: u16) -> Option<&'static str> {
    KNOWN_PORTS.iter().find(|(k, _)| *k == p).map(|(_, v)| *v)
}

/// One open port.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Found {
    /// container name if known, else IP or the hostname given
    pub host: String,
    /// address that answered
    pub ip: String,
    /// TCP port
    pub port: u16,
    /// "http", "https" or "" (not a web server)
    pub scheme: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub title: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub server: String,
    /// likely app name
    #[serde(skip_serializing_if = "String::is_empty")]
    pub guess: String,
    /// reverse-DNS name of a LAN host (label only)
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// "docker" or "lan"
    pub source: String,
}

impl Found {
    /// The value for a reverse-proxy upstream field.
    pub fn upstream(&self) -> String {
        let hp = join_host_port(&self.host, self.port);
        if self.scheme == "https" {
            format!("https://{hp}")
        } else {
            hp
        }
    }
}

fn join_host_port(h: &str, p: u16) -> String {
    if h.contains(':') {
        format!("[{h}]:{p}")
    } else {
        format!("{h}:{p}")
    }
}

/// Tunes a scan.
#[derive(Debug, Clone, Default)]
pub struct Options {
    pub ports: Vec<u16>,
    pub dial_timeout: Duration,
    pub concurrency: usize,
    /// e.g. the panel itself
    pub skip_ips: HashSet<IpAddr>,
    /// stop starting new probes after this instant
    pub deadline: Option<Instant>,
}

impl Options {
    fn defaults(&mut self) {
        if self.ports.is_empty() {
            self.ports = PORTS.to_vec();
        }
        if self.dial_timeout.is_zero() {
            self.dial_timeout = Duration::from_millis(400);
        }
        if self.concurrency == 0 {
            self.concurrency = 512;
        }
    }
}

/// Returned for targets outside private address space.
#[derive(Debug, thiserror::Error)]
#[error("only private network addresses (LAN, Docker) can be scanned")]
pub struct PublicAddress;

/// Reports whether an address may be scanned.
pub fn allowed(a: IpAddr) -> bool {
    let a = match a {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };
    match a {
        IpAddr::V4(v) => v.is_private() || v.is_loopback() || v.is_link_local(),
        IpAddr::V6(v) => v.is_loopback() || v.is_unique_local() || v.is_unicast_link_local(),
    }
}

/// One host to scan with its display name.
#[derive(Debug, Clone)]
pub struct Target {
    pub name: String,
    pub ip: IpAddr,
}

/// Turns user input into scan targets: a hostname or container name, an IP,
/// or a CIDR (at most /24). Every resolved address must be private.
pub async fn resolve(input: &str) -> Result<Vec<Target>> {
    let input = input.trim();
    if let Ok(p) = input.parse::<Ipv4Net>() {
        let p = p.trunc();
        if p.prefix_len() < 24 {
            return Err(anyhow!("scan at most a /24 IPv4 range, e.g. 10.0.1.0/24"));
        }
        if !allowed(IpAddr::V4(p.addr())) {
            return Err(PublicAddress.into());
        }
        let out = p
            .hosts()
            .filter(|a| {
                let b = a.octets()[3];
                b != 0 && b != 255
            })
            .map(|a| Target {
                name: a.to_string(),
                ip: IpAddr::V4(a),
            })
            .collect();
        return Ok(out);
    }
    if input.contains('/') {
        return Err(anyhow!("scan at most a /24 IPv4 range, e.g. 10.0.1.0/24"));
    }
    if let Ok(a) = input.parse::<IpAddr>() {
        if !allowed(a) {
            return Err(PublicAddress.into());
        }
        return Ok(vec![Target {
            name: a.to_string(),
            ip: unmap(a),
        }]);
    }
    let addrs: Vec<IpAddr> = match tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host(format!("{input}:0")),
    )
    .await
    {
        Ok(Ok(it)) => it.map(|sa| sa.ip()).collect(),
        _ => Vec::new(),
    };
    if addrs.is_empty() {
        return Err(anyhow!("can't find {input:?} on the network"));
    }
    if addrs.iter().any(|a| !allowed(*a)) {
        return Err(PublicAddress.into());
    }
    Ok(vec![Target {
        name: input.to_string(),
        ip: unmap(addrs[0]),
    }])
}

fn unmap(a: IpAddr) -> IpAddr {
    match a {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// The /24 around each private IPv4 address of this machine (in Docker: the
/// networks the panel container is attached to).
pub fn local_networks() -> (Vec<Ipv4Net>, HashSet<IpAddr>) {
    let mut nets: Vec<Ipv4Net> = Vec::new();
    let mut selfs = HashSet::new();
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return (nets, selfs);
    };
    for ifc in ifaces {
        if ifc.is_loopback() {
            continue;
        }
        let IpAddr::V4(a) = ifc.ip() else { continue };
        if !a.is_private() {
            continue;
        }
        selfs.insert(IpAddr::V4(a));
        let p = Ipv4Net::new(a, 24).unwrap().trunc();
        if !nets.contains(&p) {
            nets.push(p);
        }
    }
    (nets, selfs)
}

/// Scans the local networks. Inside Docker, live containers are found
/// through reverse DNS first, so only real hosts are port-scanned. When
/// skip_gateway is set (the host is covered by a LAN scan), the Docker
/// gateway is not scanned, to avoid listing the host's ports twice.
pub async fn network(mut o: Options, skip_gateway: bool) -> Result<Vec<Found>> {
    let (nets, selfs) = local_networks();
    if nets.is_empty() {
        return Err(anyhow!(
            "no private network found to scan; enter an IP or range instead"
        ));
    }
    o.skip_ips.extend(selfs);
    // Look up every network in parallel; Docker's DNS answers instantly,
    // other resolvers may take up to the lookup timeout.
    let mut set = JoinSet::new();
    for n in nets {
        let skip: HashSet<IpAddr> = o.skip_ips.clone();
        set.spawn(async move {
            let mut out = Vec::new();
            if let Ok(ts) = resolve(&n.to_string()).await {
                out.extend(lookup_names(ts).await);
            }
            let gw = IpAddr::V4(Ipv4Addr::from(u32::from(n.addr()) + 1));
            if !skip_gateway && !skip.contains(&gw) {
                out.push(Target {
                    name: gw.to_string(),
                    ip: gw,
                });
            }
            out
        });
    }
    let mut targets = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok(ts) = r {
            targets.extend(ts);
        }
    }
    Ok(hosts(targets, o).await.0)
}

/// Reverse DNS with a timeout (the lookup is blocking; the thread is left
/// to finish on its own when it is slow).
async fn reverse_lookup(ip: IpAddr, timeout: Duration) -> Option<String> {
    let h = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip).ok());
    match tokio::time::timeout(timeout, h).await {
        Ok(Ok(Some(n))) => Some(n),
        _ => None,
    }
}

/// The targets that have a PTR record, named by it.
async fn lookup_names(ts: Vec<Target>) -> Vec<Target> {
    let sem = Arc::new(Semaphore::new(256));
    let mut set = JoinSet::new();
    for t in ts {
        let permit = sem.clone().acquire_owned().await.unwrap();
        set.spawn(async move {
            let _p = permit;
            reverse_lookup(t.ip, Duration::from_millis(800))
                .await
                .map(|n| Target {
                    name: short_name(&n),
                    ip: t.ip,
                })
        });
    }
    let mut out = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok(Some(t)) = r {
            out.push(t);
        }
    }
    out
}

/// Turns Docker's "jellyfin.mystack_default." into "jellyfin".
pub fn short_name(n: &str) -> String {
    let n = n.trim_end_matches('.');
    match n.find('.') {
        Some(i) if i > 0 => n[..i].to_string(),
        _ => n.to_string(),
    }
}

/// Scans the given targets and identifies web servers. Returns the results
/// and whether the deadline cut the scan short.
pub async fn hosts(targets: Vec<Target>, mut o: Options) -> (Vec<Found>, bool) {
    o.defaults();
    let client = identify_client();
    let sem = Arc::new(Semaphore::new(o.concurrency));
    let found = Arc::new(Mutex::new(Vec::<Found>::new()));
    let mut set = JoinSet::new();
    let mut timed_out = false;
    'feed: for t in &targets {
        if o.skip_ips.contains(&t.ip) {
            continue;
        }
        for &port in &o.ports {
            if o.deadline.is_some_and(|d| Instant::now() >= d) {
                timed_out = true;
                break 'feed;
            }
            let permit = sem.clone().acquire_owned().await.unwrap();
            let (t, found, client, dial) =
                (t.clone(), found.clone(), client.clone(), o.dial_timeout);
            set.spawn(async move {
                let _p = permit;
                let addr = std::net::SocketAddr::new(t.ip, port);
                let ok = matches!(
                    tokio::time::timeout(dial, tokio::net::TcpStream::connect(addr)).await,
                    Ok(Ok(_))
                );
                if !ok {
                    return;
                }
                let mut f = Found {
                    host: t.name.clone(),
                    ip: t.ip.to_string(),
                    port,
                    ..Default::default()
                };
                identify(&client, &mut f).await;
                found.lock().await.push(f);
            });
        }
    }
    while set.join_next().await.is_some() {}
    let mut found = Arc::try_unwrap(found)
        .map(|m| m.into_inner())
        .unwrap_or_default();
    found.sort_by(|a, b| {
        let (wa, wb) = (!a.scheme.is_empty(), !b.scheme.is_empty());
        wb.cmp(&wa)
            .then(a.host.cmp(&b.host))
            .then(a.port.cmp(&b.port)) // web servers first
    });
    (found, timed_out)
}

fn identify_client() -> reqwest::Client {
    crate::httpc::builder()
        .timeout(Duration::from_secs(2))
        .danger_accept_invalid_certs(true) // self-signed apps are normal on a LAN
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent("CaddyHub-scan")
        .build()
        .expect("http client")
}

static TITLE_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(?is)<title[^>]*>(.*?)</title>").unwrap());

/// Checks whether the port speaks HTTP or HTTPS and reads the title.
async fn identify(client: &reqwest::Client, f: &mut Found) {
    let order: &[&str] = if matches!(f.port, 443 | 8443 | 9443 | 8006 | 8920) {
        &["https", "http"]
    } else {
        &["http", "https"]
    };
    let hp = join_host_port(&f.ip, f.port);
    for scheme in order {
        let Ok(resp) = client.get(format!("{scheme}://{hp}/")).send().await else {
            continue;
        };
        let status = resp.status();
        let server = resp
            .headers()
            .get("server")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body = read_limited(resp, 64 << 10).await;
        if status.as_u16() == 400
            && *scheme == "http"
            && body.to_ascii_lowercase().contains("https")
        {
            continue; // "plain HTTP request sent to HTTPS port"
        }
        f.scheme = scheme.to_string();
        f.server = server;
        if let Some(m) = TITLE_RE.captures(&body) {
            let t = html_unescape(&m[1]);
            let mut t: String = t.split_whitespace().collect::<Vec<_>>().join(" ");
            if t.len() > 80 {
                t = t.chars().take(80).collect();
            }
            f.title = t;
        }
        break;
    }
    f.guess = guess(f);
}

async fn read_limited(resp: reqwest::Response, max: usize) -> String {
    let b = resp.bytes().await.unwrap_or_default();
    let b = if b.len() > max { &b[..max] } else { &b[..] };
    String::from_utf8_lossy(b).to_string()
}

fn guess(f: &Found) -> String {
    if !f.title.is_empty() && !f.title.eq_ignore_ascii_case("index") {
        return f.title.clone();
    }
    if let Some(g) = known_port(f.port) {
        return g.to_string();
    }
    if f.host != f.ip {
        return f.host.clone();
    }
    String::new()
}

fn html_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
}

/// Adds reverse-DNS names (e.g. "nas.lan" from the router) to results that
/// only have an IP. The name is a label: upstreams keep the IP, since LAN
/// names often don't resolve inside the Caddy container.
pub async fn name_results(found: &mut [Found]) {
    let ips: HashSet<String> = found
        .iter()
        .filter(|f| f.host == f.ip)
        .map(|f| f.ip.clone())
        .collect();
    let mut set = JoinSet::new();
    for ip in ips {
        if let Ok(a) = ip.parse::<IpAddr>() {
            set.spawn(async move {
                reverse_lookup(a, Duration::from_millis(800))
                    .await
                    .map(|n| (ip, n.trim_end_matches('.').to_string()))
            });
        }
    }
    let mut names: HashMap<String, String> = HashMap::new();
    while let Some(r) = set.join_next().await {
        if let Ok(Some((ip, n))) = r {
            names.insert(ip, n);
        }
    }
    for f in found.iter_mut() {
        if f.host == f.ip {
            if let Some(n) = names.get(&f.ip) {
                f.name = n.clone();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hosts_finds_web_app() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 1024];
                    let _ = s.read(&mut buf).await;
                    let body = "<html><head><title> My &amp; App </title></head></html>";
                    let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await;
                });
            }
        });
        let targets = resolve("127.0.0.1").await.unwrap();
        let (found, timed_out) = hosts(
            targets,
            Options {
                ports: vec![port, 1],
                ..Default::default()
            },
        )
        .await;
        assert!(!timed_out);
        assert_eq!(found.len(), 1, "{found:?}");
        let f = &found[0];
        assert_eq!(f.scheme, "http");
        assert_eq!(f.title, "My & App");
        assert_eq!(f.guess, "My & App");
        assert_eq!(f.upstream(), format!("127.0.0.1:{port}"));
    }

    #[tokio::test]
    async fn resolve_rejects_public() {
        for input in ["8.8.8.8", "1.1.1.0/24", "10.0.0.0/16"] {
            assert!(resolve(input).await.is_err(), "{input} should be rejected");
        }
        let ts = resolve("192.168.1.0/24").await.unwrap();
        assert_eq!(ts.len(), 254);
        assert!(
            allowed("172.18.0.5".parse().unwrap()),
            "docker range should be allowed"
        );
    }

    #[test]
    fn short_names() {
        assert_eq!(short_name("jellyfin.media_default."), "jellyfin");
    }
}
