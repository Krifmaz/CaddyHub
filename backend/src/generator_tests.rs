use super::*;
use crate::registry::{DNS_PROVIDERS, FEATURES, parse_version};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Pretends every module the panel can use is installed.
fn full_caps() -> Capabilities {
    let mut c = Capabilities {
        detected: true,
        version: parse_version("v2.11.7"),
        version_s: "v2.11.7".into(),
        ..Default::default()
    };
    for f in FEATURES {
        for m in f.modules {
            c.modules.insert(m.to_string());
        }
    }
    for p in DNS_PROVIDERS {
        c.modules.insert(p.module());
    }
    c
}

fn base_env() -> Env {
    Env {
        admin_listen: "caddy-admin:2019".into(),
        admin_origins: vec!["caddy-admin:2019".into()],
        log_dir: "/var/log/caddy".into(),
        panel_upstream: "panel:8080".into(),
        trusted_proxy_ranges: BTreeMap::from([
            (
                "cloudflare".to_string(),
                vec!["173.245.48.0/20".to_string(), "2400:cb00::/32".to_string()],
            ),
            ("fastly".to_string(), vec!["23.235.32.0/20".to_string()]),
        ]),
        ..Default::default()
    }
}

fn base_settings() -> Settings {
    Settings {
        acme_email: "admin@example.com".into(),
        ..Default::default()
    }
}

fn proxy(ups: &[&str]) -> Option<ProxyConfig> {
    Some(ProxyConfig {
        upstreams: ups.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    })
}

fn site(id: i64, name: &str, hosts: &[&str], kind: &str, config: SiteConfig) -> Site {
    Site {
        id,
        name: name.into(),
        hosts: hosts.iter().map(|s| s.to_string()).collect(),
        kind: kind.into(),
        enabled: true,
        config,
        ..Default::default()
    }
}

fn m(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

pub(crate) struct Case {
    pub name: &'static str,
    pub input: Input,
    /// modules the case needs beyond the stock binary (for real validation)
    pub needs: Vec<&'static str>,
    /// adapt only (e.g. custom cert files that don't exist)
    pub skip_validate: bool,
}

fn case(name: &'static str, input: Input) -> Case {
    Case {
        name,
        input,
        needs: Vec::new(),
        skip_validate: false,
    }
}

pub(crate) fn cases() -> Vec<Case> {
    let cf_id = 1i64;
    let pb_id = 2i64;
    let creds: BTreeMap<i64, CredRef> = BTreeMap::from([
        (
            cf_id,
            CredRef {
                provider: "cloudflare".into(),
                fields: m(&[("api_token", "{file./run/caddyhub/secrets/dns-1-api_token}")]),
            },
        ),
        (
            pb_id,
            CredRef {
                provider: "porkbun".into(),
                fields: m(&[
                    ("api_key", "{env.PORKBUN_API_KEY}"),
                    (
                        "api_secret_key",
                        "{file./run/caddyhub/secrets/dns-2-api_secret_key}",
                    ),
                ]),
            },
        ),
    ]);
    let input = |sites: Vec<Site>| Input {
        settings: base_settings(),
        caps: full_caps(),
        env: base_env(),
        sites,
        ..Default::default()
    };

    vec![
        case(
            "basic_proxy",
            input(vec![
                site(
                    1,
                    "App",
                    &["app.example.com"],
                    KIND_PROXY,
                    SiteConfig {
                        proxy: proxy(&["app:8080"]),
                        ..Default::default()
                    },
                ),
                Site {
                    enabled: false,
                    ..site(
                        2,
                        "Disabled",
                        &["off.example.com"],
                        KIND_PROXY,
                        SiteConfig {
                            proxy: proxy(&["off:80"]),
                            ..Default::default()
                        },
                    )
                },
            ]),
        ),
        case(
            "full_proxy",
            input(vec![site(
                7,
                "Proxmox",
                &["pve.example.com"],
                KIND_PROXY,
                SiteConfig {
                    proxy: Some(ProxyConfig {
                        upstreams: vec![
                            "https://10.0.0.10:8006".into(),
                            "https://10.0.0.11:8006".into(),
                        ],
                        lb_policy: "least_conn".into(),
                        lb_retries: 2,
                        lb_try_duration: "5s".into(),
                        health_uri: "/".into(),
                        health_interval: "30s".into(),
                        health_timeout: "5s".into(),
                        health_status: "2xx".into(),
                        fail_duration: "30s".into(),
                        max_fails: 3,
                        unhealthy_status: "5xx".into(),
                        tls_skip_verify: true,
                        dial_timeout: "5s".into(),
                        response_header_timeout: "30s".into(),
                        flush_interval: "-1".into(),
                        header_up: m(&[("X-Real-IP", "{client_ip}")]),
                        ..Default::default()
                    }),
                    routes: vec![
                        Route {
                            path: "/grpc/*".into(),
                            strip_prefix: true,
                            kind: KIND_PROXY.into(),
                            proxy: Some(ProxyConfig {
                                upstreams: vec!["grpc:50051".into()],
                                h2c: true,
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                        Route {
                            path: "/old/*".into(),
                            kind: KIND_REDIRECT.into(),
                            redirect: Some(RedirectConfig {
                                to: "https://new.example.com".into(),
                                code: 301,
                                keep_path: true,
                            }),
                            ..Default::default()
                        },
                    ],
                    compression: vec!["zstd".into(), "gzip".into()],
                    headers_set: m(&[
                        (
                            "Strict-Transport-Security",
                            "max-age=31536000; includeSubDomains",
                        ),
                        ("X-Frame-Options", "SAMEORIGIN"),
                    ]),
                    headers_remove: vec!["Server".into(), "X-Powered-By".into()],
                    max_body_size: "100MB".into(),
                    access: AccessConfig {
                        basic_auth: vec![BasicAuthUser {
                            username: "admin".into(),
                            hash: "$2a$14$Zkx19XLiW6VYouLHR5NmfOFU0z2GTNmpkT/5qqR7hx4IjWJPDhjvG"
                                .into(),
                        }],
                        allow_cidrs: vec!["192.168.0.0/16".into(), "10.0.0.0/8".into()],
                        deny_cidrs: vec!["192.168.66.0/24".into()],
                        forward_auth: Some(ForwardAuth {
                            preset: "authelia".into(),
                            upstream: "authelia:9091".into(),
                            uri: "/api/authz/forward-auth".into(),
                            copy_headers: vec![
                                "Remote-User".into(),
                                "Remote-Groups".into(),
                                "Remote-Email".into(),
                                "Remote-Name".into(),
                            ],
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )]),
        ),
        case(
            "kinds",
            input(vec![
                Site {
                    position: 2,
                    ..site(
                        1,
                        "Docs",
                        &["docs.example.com"],
                        KIND_STATIC,
                        SiteConfig {
                            r#static: Some(StaticConfig {
                                root: "/srv/docs".into(),
                                spa: true,
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    )
                },
                Site {
                    position: 1,
                    ..site(
                        2,
                        "Files",
                        &["files.example.com"],
                        KIND_STATIC,
                        SiteConfig {
                            r#static: Some(StaticConfig {
                                root: "/srv/files".into(),
                                browse: true,
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    )
                },
                Site {
                    position: 3,
                    ..site(
                        3,
                        "Old",
                        &["old.example.com"],
                        KIND_REDIRECT,
                        SiteConfig {
                            redirect: Some(RedirectConfig {
                                to: "https://new.example.com".into(),
                                code: 308,
                                keep_path: true,
                            }),
                            ..Default::default()
                        },
                    )
                },
                Site {
                    position: 4,
                    ..site(
                        4,
                        "Status",
                        &["status.example.com"],
                        KIND_RESPOND,
                        SiteConfig {
                            respond: Some(RespondConfig {
                                body: r#"{"ok":true}"#.into(),
                                status: 200,
                                content_type: "application/json".into(),
                            }),
                            ..Default::default()
                        },
                    )
                },
                Site {
                    position: 5,
                    ..site(
                        5,
                        "Maint",
                        &["maint.example.com"],
                        KIND_PROXY,
                        SiteConfig {
                            maintenance: true,
                            proxy: proxy(&["app:80"]),
                            ..Default::default()
                        },
                    )
                },
            ]),
        ),
        Case {
            needs: vec!["dns.providers.cloudflare", "dns.providers.porkbun"],
            ..case("dns_multi_domain", {
                let mut s = base_settings();
                s.acme_ca = "letsencrypt_staging".into();
                s.propagation_timeout = "5m".into();
                Input {
                    settings: s,
                    caps: full_caps(),
                    env: base_env(),
                    credentials: creds.clone(),
                    domains: vec![
                        Domain {
                            id: 1,
                            name: "example.com".into(),
                            challenge: CHALLENGE_DNS.into(),
                            credential_id: Some(cf_id),
                            wildcard: true,
                            ..Default::default()
                        },
                        Domain {
                            id: 2,
                            name: "example.net".into(),
                            challenge: CHALLENGE_DNS.into(),
                            credential_id: Some(pb_id),
                            resolvers: vec!["1.1.1.1".into()],
                            ..Default::default()
                        },
                        Domain {
                            id: 3,
                            name: "example.org".into(),
                            challenge: CHALLENGE_HTTP.into(),
                            ..Default::default()
                        },
                    ],
                    sites: vec![
                        site(
                            1,
                            "Vault",
                            &["vault.example.com"],
                            KIND_PROXY,
                            SiteConfig {
                                proxy: Some(ProxyConfig {
                                    upstreams: vec!["vaultwarden:80".into()],
                                    websocket: true,
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                        ),
                        site(
                            2,
                            "Jelly",
                            &["media.example.com"],
                            KIND_PROXY,
                            SiteConfig {
                                proxy: proxy(&["jellyfin:8096"]),
                                access_log: Some(false),
                                ..Default::default()
                            },
                        ),
                        site(
                            3,
                            "Deep",
                            &["a.b.example.com"],
                            KIND_PROXY,
                            SiteConfig {
                                proxy: proxy(&["deep:80"]),
                                ..Default::default()
                            },
                        ),
                        site(
                            4,
                            "Net",
                            &["www.example.net"],
                            KIND_PROXY,
                            SiteConfig {
                                proxy: proxy(&["net:80"]),
                                ..Default::default()
                            },
                        ),
                        site(
                            5,
                            "Org",
                            &["example.org"],
                            KIND_PROXY,
                            SiteConfig {
                                proxy: proxy(&["org:80"]),
                                ..Default::default()
                            },
                        ),
                    ],
                    ..Default::default()
                }
            })
        },
        Case {
            skip_validate: true, // custom cert files don't exist in the test env
            ..case(
                "tls_modes",
                input(vec![
                    site(
                        1,
                        "Internal",
                        &["nas.home.arpa"],
                        KIND_PROXY,
                        SiteConfig {
                            tls: TlsConfig {
                                mode: TLS_INTERNAL.into(),
                                ..Default::default()
                            },
                            proxy: proxy(&["nas:5000"]),
                            ..Default::default()
                        },
                    ),
                    site(
                        2,
                        "Custom",
                        &["secure.example.com"],
                        KIND_PROXY,
                        SiteConfig {
                            tls: TlsConfig {
                                mode: TLS_CUSTOM.into(),
                                cert_file: "/certs/secure.crt".into(),
                                key_file: "/certs/secure.key".into(),
                            },
                            proxy: Some(ProxyConfig {
                                upstreams: vec!["secure:443".into()],
                                tls_skip_verify: true,
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    ),
                    site(
                        3,
                        "Plain",
                        &["plain.example.com"],
                        KIND_PROXY,
                        SiteConfig {
                            tls: TlsConfig {
                                mode: TLS_OFF.into(),
                                ..Default::default()
                            },
                            proxy: proxy(&["plain:80"]),
                            ..Default::default()
                        },
                    ),
                    site(
                        4,
                        "NoRedirect",
                        &["both.example.com"],
                        KIND_PROXY,
                        SiteConfig {
                            http_redirect: Some(false),
                            proxy: proxy(&["both:80"]),
                            ..Default::default()
                        },
                    ),
                    site(
                        5,
                        "ToWWW",
                        &["example.com"],
                        KIND_PROXY,
                        SiteConfig {
                            www_redirect: "to_www".into(),
                            proxy: proxy(&["web:80"]),
                            ..Default::default()
                        },
                    ),
                    site(
                        6,
                        "ToApex",
                        &["example.net", "www.example.org"],
                        KIND_PROXY,
                        SiteConfig {
                            www_redirect: "to_apex".into(),
                            proxy: proxy(&["web2:80"]),
                            ..Default::default()
                        },
                    ),
                ]),
            )
        },
        case("snippets_raw", {
            let mut s = base_settings();
            s.raw_global = "servers {\n\tprotocols h1 h2\n}".into();
            Input {
                settings: s,
                caps: full_caps(),
                env: base_env(),
                snippets: vec![
                    Snippet { id: 1, name: "security_headers".into(), description: "Common security headers".into(), body: "header {\n\tX-Content-Type-Options nosniff\n\tReferrer-Policy strict-origin-when-cross-origin\n}".into() },
                    Snippet { id: 2, name: "lan_only".into(), body: "@external not remote_ip private_ranges\nrespond @external 403".into(), ..Default::default() },
                ],
                raw_blocks: vec![
                    RawBlock { id: 1, name: "imported legacy".into(), enabled: true, position: 1, body: "legacy.example.com:8443 {\n\trespond \"legacy\"\n}".into(), ..Default::default() },
                    RawBlock { id: 2, name: "disabled".into(), enabled: false, position: 2, body: "nope.example.com {\n\trespond nope\n}".into(), ..Default::default() },
                ],
                sites: vec![site(
                    1,
                    "App",
                    &["app.example.com"],
                    KIND_PROXY,
                    SiteConfig {
                        snippets: vec!["security_headers".into(), "lan_only".into()],
                        proxy: proxy(&["app:80"]),
                        raw: "handle_errors {\n\trespond \"{err.status_code} {err.status_text}\"\n}".into(),
                        ..Default::default()
                    },
                )],
                ..Default::default()
            }
        }),
        Case {
            needs: vec![
                "http.handlers.rate_limit",
                "crowdsec",
                "http.handlers.crowdsec",
            ],
            ..case("security_plugins", {
                let mut s = base_settings();
                s.trusted_proxies = TrustedProxies {
                    enabled: true,
                    presets: vec!["cloudflare".into(), "private".into()],
                    custom: vec!["203.0.113.0/24".into()],
                    client_ip_headers: vec!["CF-Connecting-IP".into(), "X-Forwarded-For".into()],
                    strict: true,
                };
                s.crowdsec = CrowdSecSettings {
                    enabled: true,
                    api_url: "http://crowdsec:8080".into(),
                    ticker_interval: "15s".into(),
                    ..Default::default()
                };
                let mut e = base_env();
                e.crowdsec_key_ref = "{file./run/caddyhub/secrets/crowdsec-api_key}".into();
                Input {
                    settings: s,
                    caps: full_caps(),
                    env: e,
                    sites: vec![site(
                        1,
                        "API",
                        &["api.example.com"],
                        KIND_PROXY,
                        SiteConfig {
                            proxy: proxy(&["api:3000"]),
                            access: AccessConfig {
                                crowdsec: true,
                                rate_limit: Some(RateLimit {
                                    events: 100,
                                    window: "1m".into(),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                            ..Default::default()
                        },
                    )],
                    ..Default::default()
                }
            })
        },
        case("missing_plugins_skipped", {
            let mut caps = full_caps();
            caps.modules.remove("http.handlers.rate_limit");
            caps.modules.remove("dns.providers.cloudflare");
            Input {
                settings: base_settings(),
                caps,
                env: base_env(),
                credentials: creds.clone(),
                domains: vec![Domain {
                    id: 1,
                    name: "example.com".into(),
                    challenge: CHALLENGE_DNS.into(),
                    credential_id: Some(cf_id),
                    wildcard: true,
                    ..Default::default()
                }],
                sites: vec![site(
                    1,
                    "API",
                    &["api.example.com"],
                    KIND_PROXY,
                    SiteConfig {
                        proxy: proxy(&["api:3000"]),
                        access: AccessConfig {
                            rate_limit: Some(RateLimit {
                                events: 10,
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                )],
                ..Default::default()
            }
        }),
        case("panel_domain_internal_ca", {
            let mut s = base_settings();
            s.acme_ca = "caddy_internal".into();
            s.panel_domain = "panel.home.arpa".into();
            s.metrics = false;
            Input {
                settings: s,
                caps: full_caps(),
                env: base_env(),
                ..Default::default()
            }
        }),
        Case {
            needs: vec!["dynamic_dns", "dns.providers.cloudflare"],
            ..case("dynamic_dns", {
                let mut s = base_settings();
                s.ddns = DdnsSettings {
                    enabled: true,
                    credential_id: Some(cf_id),
                    domains: vec![
                        DdnsDomain {
                            zone: "example.net".into(),
                            names: vec!["home".into()],
                        },
                        DdnsDomain {
                            zone: "example.com".into(),
                            names: vec!["@".into(), "www".into()],
                        },
                    ],
                    ip_sources: vec![
                        DdnsIpSource {
                            kind: "upnp".into(),
                            value: String::new(),
                        },
                        DdnsIpSource {
                            kind: "simple_http".into(),
                            value: "https://icanhazip.com".into(),
                        },
                    ],
                    check_interval: "5m".into(),
                    ipv4: true,
                    ipv6: false,
                    ttl: "1h".into(),
                    dynamic_domains: false,
                    update_only: true,
                };
                Input {
                    settings: s,
                    caps: full_caps(),
                    env: base_env(),
                    credentials: creds.clone(),
                    sites: vec![site(
                        1,
                        "Home",
                        &["home.example.net"],
                        KIND_PROXY,
                        SiteConfig {
                            proxy: proxy(&["home:80"]),
                            ..Default::default()
                        },
                    )],
                    ..Default::default()
                }
            })
        },
        Case {
            needs: vec!["http.handlers.forward_proxy"],
            ..case(
                "forward_proxy",
                input(vec![site(
                    1,
                    "Proxy",
                    &["proxy.example.com"],
                    KIND_FORWARD_PROXY,
                    SiteConfig {
                        forward_proxy: Some(ForwardProxyConfig {
                            basic_auth: vec![ForwardProxyUser {
                                username: "alice".into(),
                                password: "s3cret pass".into(),
                            }],
                            hide_ip: true,
                            hide_via: true,
                            probe_resistance: "secret.localhost".into(),
                            dial_timeout: "30s".into(),
                            ports: vec![80, 443],
                            acl: vec![
                                "deny 10.0.0.0/8".into(),
                                "allow all".into(),
                                "garbage".into(),
                            ],
                            ..Default::default()
                        }),
                        access: AccessConfig {
                            allow_cidrs: vec!["192.168.0.0/16".into()],
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                )]),
            )
        },
    ]
}

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/generator")
        .join(format!("{name}.golden"))
}

fn line_diff(a: &str, b: &str) -> String {
    let al: Vec<&str> = a.split('\n').collect();
    let bl: Vec<&str> = b.split('\n').collect();
    let mut sb = String::new();
    for i in 0..al.len().max(bl.len()) {
        let x = al.get(i).copied().unwrap_or("");
        let y = bl.get(i).copied().unwrap_or("");
        if x != y {
            sb.push_str(&format!("-{x}\n+{y}\n"));
        }
    }
    sb
}

#[test]
fn golden() {
    let update = std::env::var("UPDATE_GOLDEN").is_ok();
    let mut failures = Vec::new();
    for tc in cases() {
        let out = generate(&tc.input);
        let mut got = out.caddyfile.clone();
        if !out.warnings.is_empty() {
            got.push_str(&format!(
                "\n# --- warnings ---\n# {}\n",
                out.warnings.join("\n# ")
            ));
        }
        let path = golden_path(tc.name);
        if update {
            std::fs::write(&path, &got).unwrap();
        }
        let Ok(want) = std::fs::read_to_string(&path) else {
            failures.push(format!(
                "{}: missing golden file {} (run with UPDATE_GOLDEN=1)",
                tc.name,
                path.display()
            ));
            continue;
        };
        if want.replace("\r\n", "\n") != got {
            failures.push(format!(
                "{}: output differs from {} (run with UPDATE_GOLDEN=1 to accept):\n{}",
                tc.name,
                path.display(),
                line_diff(&want, &got)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn deterministic() {
    for tc in cases() {
        let a = generate(&tc.input).caddyfile;
        for _ in 0..5 {
            assert_eq!(
                a,
                generate(&tc.input).caddyfile,
                "{}: non-deterministic output",
                tc.name
            );
        }
    }
}

/// Adapts and validates every golden case with a real Caddy binary. Set
/// CADDY_BIN to enable (CI runs it against several versions).
#[tokio::test]
async fn real_caddy() {
    let Ok(bin) = std::env::var("CADDY_BIN") else {
        eprintln!("CADDY_BIN not set; skipping");
        return;
    };
    let r = crate::caddy::Runner::new(bin);
    let caps = r.capabilities().await.expect("detect capabilities");
    eprintln!("caddy {}, {} modules", caps.version_s, caps.modules.len());
    for tc in cases() {
        if let Some(m) = tc.needs.iter().find(|m| !caps.modules.contains(**m)) {
            eprintln!("{}: binary lacks module {m}; skipped", tc.name);
            continue;
        }
        let mut input = tc.input.clone();
        let out = generate(&input);
        if let Err(e) = r.adapt(&out.caddyfile).await {
            panic!("{}: adapt failed: {e}\n{}", tc.name, out.caddyfile);
        }
        if tc.skip_validate {
            continue;
        }
        // validate a copy with logs redirected to a temp dir, exactly as the
        // apply pipeline does
        let logs = tempfile::tempdir().unwrap();
        input.env.log_dir = crate::secrets::to_slash(logs.path());
        input.env.validation_mode = true;
        let text = generate(&input).caddyfile;
        // materialize realistic dummy secrets where the config expects them
        let sec = tempfile::tempdir().unwrap();
        let secdir = crate::secrets::to_slash(sec.path());
        let text = text.replace("/run/caddyhub/secrets", &secdir);
        for (name, v) in [
            ("dns-1-api_token", "a1B2c3D4e5".repeat(4)),
            ("dns-2-api_secret_key", format!("sk1_{}", "f".repeat(60))),
            ("crowdsec-api_key", "dummy-bouncer-key".to_string()),
        ] {
            std::fs::write(sec.path().join(name), v).unwrap();
        }
        let mut vr = r.clone();
        vr.extra_env = vec![(
            "PORKBUN_API_KEY".to_string(),
            format!("pk1_{}", "e".repeat(60)),
        )];
        if let Err(e) = vr.validate(&text).await {
            panic!("{}: validate failed: {e}\n{text}", tc.name);
        }
    }
}
