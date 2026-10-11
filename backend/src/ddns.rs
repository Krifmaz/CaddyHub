//! Dynamic DNS status: what the public address is and whether the configured
//! names point at it. The updating itself is done by Caddy's dynamic_dns
//! app (caddy-dynamicdns); this is the panel's view of the result.

use serde::Serialize;
use std::net::IpAddr;
use std::time::Duration;

use crate::model::DdnsSettings;

#[derive(Debug, Clone, Default, Serialize)]
pub struct RecordStatus {
    pub name: String,
    pub addresses: Vec<String>,
    /// None when the public address is unknown
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up_to_date: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DdnsStatus {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_ipv4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_ipv6: Option<String>,
    /// where the public address came from
    pub source: String,
    pub records: Vec<RecordStatus>,
    pub checked_at: chrono::DateTime<chrono::Utc>,
}

/// Every FQDN the settings keep updated.
pub fn names(d: &DdnsSettings) -> Vec<String> {
    let mut out = Vec::new();
    for z in &d.domains {
        let zone = z.zone.trim().trim_end_matches('.').to_ascii_lowercase();
        if zone.is_empty() {
            continue;
        }
        let mut names: Vec<&str> = z
            .names
            .iter()
            .map(|n| n.trim())
            .filter(|n| !n.is_empty())
            .collect();
        if names.is_empty() {
            names.push("@");
        }
        for n in names {
            let fqdn = if n == "@" {
                zone.clone()
            } else {
                format!("{}.{zone}", n.trim_end_matches('.'))
            };
            if !out.contains(&fqdn) {
                out.push(fqdn);
            }
        }
    }
    out
}

async fn fetch_ip(client: &reqwest::Client, url: &str) -> Option<IpAddr> {
    let r = client.get(url).send().await.ok()?.error_for_status().ok()?;
    let t = r.text().await.ok()?;
    t.trim().parse().ok()
}

/// Looks up the public address and resolves every configured name.
pub async fn status(d: &DdnsSettings) -> DdnsStatus {
    let client = crate::httpc::builder()
        .timeout(Duration::from_secs(6))
        .build()
        .expect("http client");
    let mut st = DdnsStatus {
        enabled: d.enabled,
        checked_at: chrono::Utc::now(),
        ..Default::default()
    };
    // Prefer the user's own simple_http source so both sides agree.
    let custom = d
        .ip_sources
        .iter()
        .find(|s| s.kind == "simple_http" && !s.value.trim().is_empty())
        .map(|s| s.value.trim().to_string());
    let static_ip = d
        .ip_sources
        .iter()
        .find(|s| s.kind == "static" && !s.value.trim().is_empty())
        .map(|s| s.value.trim().to_string());
    if let Some(ip) = static_ip {
        for a in ip
            .split([' ', ','])
            .filter_map(|a| a.parse::<IpAddr>().ok())
        {
            match a {
                IpAddr::V4(_) if st.public_ipv4.is_none() => st.public_ipv4 = Some(a.to_string()),
                IpAddr::V6(_) if st.public_ipv6.is_none() => st.public_ipv6 = Some(a.to_string()),
                _ => {}
            }
        }
        st.source = "static".into();
    } else {
        let (v4_url, v6_url, src) = match &custom {
            Some(u) => (u.clone(), String::new(), u.clone()),
            None => (
                "https://ipv4.icanhazip.com".to_string(),
                "https://ipv6.icanhazip.com".to_string(),
                "icanhazip.com".to_string(),
            ),
        };
        st.source = src;
        if let Some(a) = fetch_ip(&client, &v4_url).await {
            match a {
                IpAddr::V4(_) => st.public_ipv4 = Some(a.to_string()),
                IpAddr::V6(_) => st.public_ipv6 = Some(a.to_string()),
            }
        }
        if d.ipv6 && !v6_url.is_empty() && st.public_ipv6.is_none() {
            if let Some(a) = fetch_ip(&client, &v6_url).await {
                st.public_ipv6 = Some(a.to_string());
            }
        }
    }
    for name in names(d) {
        let addrs: Vec<String> = match tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::lookup_host(format!("{name}:0")),
        )
        .await
        {
            Ok(Ok(it)) => {
                let mut v: Vec<String> = it.map(|sa| sa.ip().to_string()).collect();
                v.sort();
                v.dedup();
                v
            }
            _ => Vec::new(),
        };
        let want: Vec<&String> = [&st.public_ipv4, &st.public_ipv6]
            .into_iter()
            .flatten()
            .collect();
        let up_to_date = if want.is_empty() {
            None
        } else {
            Some(want.iter().any(|w| addrs.contains(w)))
        };
        st.records.push(RecordStatus {
            name,
            addresses: addrs,
            up_to_date,
        });
    }
    st
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DdnsDomain;

    #[test]
    fn fqdns() {
        let d = DdnsSettings {
            domains: vec![
                DdnsDomain {
                    zone: "Example.com.".into(),
                    names: vec!["@".into(), "www".into(), "".into()],
                },
                DdnsDomain {
                    zone: "example.net".into(),
                    names: vec![],
                },
            ],
            ..Default::default()
        };
        assert_eq!(
            names(&d),
            vec!["example.com", "www.example.com", "example.net"]
        );
    }
}
