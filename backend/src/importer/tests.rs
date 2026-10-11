use super::*;
use crate::generator;
use crate::model::*;
use crate::registry::Capabilities;
use std::collections::HashMap;

const SAMPLE: &str = r#"# My old hand-written Caddyfile
{
	email ops@example.com
	acme_ca https://acme-staging-v02.api.letsencrypt.org/directory
	admin localhost:2019
	servers {
		protocols h1 h2
	}
}

(secure) {
	header {
		X-Frame-Options DENY
		-Server
	}
}

vault.example.com {
	import secure
	encode zstd gzip
	reverse_proxy vaultwarden:80 {
		header_up X-Real-IP {remote_host}
	}
	log {
		output file /var/log/vault.log
	}
}

pve.example.com {
	reverse_proxy https://10.0.0.5:8006 {
		transport http {
			tls_insecure_skip_verify
		}
	}
	tls {
		dns cloudflare {env.CF_API_TOKEN}
		resolvers 1.1.1.1
	}
}

http://plain.example.com {
	respond "plain text" 200
}

docs.example.com, www.docs.example.com {
	root * /srv/docs
	try_files {path} /index.html
	file_server
	basic_auth {
		alice $2a$14$Zkx19XLiW6VYouLHR5NmfOFU0z2GTNmpkT/5qqR7hx4IjWJPDhjvG
	}
}

app.example.com {
	handle_path /api/* {
		reverse_proxy api:3000
	}
	@websockets {
		header Connection *Upgrade*
	}
	reverse_proxy @websockets ws:8080
	reverse_proxy frontend:80
	header Cache-Control "no-store"
}

:8443 {
	respond "odd port"
}

&(shared) {
	respond "named route"
}

old.example.com {
	redir https://new.example.com{uri} permanent
}
"#;

fn by_host(res: &ImportResult) -> HashMap<String, Site> {
    let mut m = HashMap::new();
    for s in &res.sites {
        for h in &s.hosts {
            m.insert(h.clone(), s.clone());
        }
    }
    m
}

#[test]
fn import_sample() {
    let res = import(SAMPLE).unwrap();
    assert_eq!(res.email, "ops@example.com");
    assert_eq!(res.acme_ca, "letsencrypt_staging");
    assert!(
        res.raw_global.contains("protocols h1 h2") && !res.raw_global.contains("admin"),
        "{:?}",
        res.raw_global
    );
    assert_eq!(res.snippets.len(), 1);
    assert_eq!(res.snippets[0].name, "secure");
    assert!(res.snippets[0].body.contains("X-Frame-Options DENY"));
    let sites = by_host(&res);
    let v = &sites["vault.example.com"];
    let vp = v.config.proxy.as_ref().unwrap();
    assert_eq!(v.kind, KIND_PROXY);
    assert_eq!(vp.upstreams[0], "vaultwarden:80");
    assert_eq!(v.config.raw, "");
    assert_eq!(v.config.snippets.len(), 1);
    assert_eq!(v.config.compression.len(), 2);
    assert_eq!(vp.header_up["X-Real-IP"], "{remote_host}");
    let p = &sites["pve.example.com"];
    assert!(
        p.config.proxy.as_ref().unwrap().tls_skip_verify && p.config.raw.is_empty(),
        "{:?}",
        p.config
    );
    assert_eq!(res.credentials.len(), 1);
    assert_eq!(res.credentials[0].provider, "cloudflare");
    assert_eq!(res.credentials[0].fields["api_token"], "env:CF_API_TOKEN");
    assert_eq!(res.domains.len(), 1);
    assert_eq!(res.domains[0].name, "example.com");
    assert_eq!(res.domains[0].challenge, CHALLENGE_DNS);
    let s = &sites["plain.example.com"];
    assert_eq!(s.config.tls.mode, TLS_OFF);
    assert_eq!(s.kind, KIND_RESPOND);
    assert_eq!(s.config.respond.as_ref().unwrap().body, "plain text");
    let d = &sites["docs.example.com"];
    let ds = d.config.r#static.as_ref().unwrap();
    assert_eq!(d.kind, KIND_STATIC);
    assert!(
        ds.spa
            && ds.root == "/srv/docs"
            && d.config.access.basic_auth.len() == 1
            && d.hosts.len() == 2
    );
    let a = &sites["app.example.com"];
    assert_eq!(a.kind, KIND_PROXY);
    assert_eq!(a.config.routes.len(), 1);
    assert!(a.config.routes[0].strip_prefix);
    assert!(
        a.config.raw.contains("@websockets")
            && a.config.raw.contains("reverse_proxy @websockets ws:8080"),
        "{}",
        a.config.raw
    );
    assert_eq!(a.config.headers_set["Cache-Control"], "no-store");
    let o = &sites["old.example.com"];
    let or = o.config.redirect.as_ref().unwrap();
    assert!(o.kind == KIND_REDIRECT && or.code == 301 && or.keep_path);
    assert_eq!(
        res.raw_blocks.len(),
        2,
        "expected :8443 and &(shared) as raw blocks: {:?}",
        res.raw_blocks
    );
    for rb in &res.raw_blocks {
        assert!(
            SAMPLE.contains(&rb.body),
            "raw block not verbatim: {:?}",
            rb.body
        );
    }
}

#[test]
fn import_braceless() {
    let res = import("example.com\n\nreverse_proxy app:80\n").unwrap();
    assert_eq!(res.sites.len(), 1);
    assert_eq!(
        res.sites[0].config.proxy.as_ref().unwrap().upstreams[0],
        "app:80"
    );
}

#[test]
fn import_heredoc_and_comments() {
    let src = "a.example.com {\n\trespond <<HTML\n\t\t<h1>Hi # not a comment</h1>\n\t\tHTML 200\n\t# real comment\n}\n";
    let res = import(src).unwrap();
    assert_eq!(res.sites.len(), 1);
    assert_eq!(res.sites[0].kind, KIND_RESPOND);
    assert!(
        res.sites[0]
            .config
            .respond
            .as_ref()
            .unwrap()
            .body
            .contains("# not a comment")
    );
}

fn testdata(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/testdata/importer/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

/// testdata/importer/caddy_config.json is `caddy adapt` output of
/// caddy_config.Caddyfile.
#[test]
fn import_json_config() {
    let res = import_json(&testdata("caddy_config.json")).unwrap();
    let h = by_host(&res);
    let jf = &h["jellyfin.example.com"];
    let jp = jf.config.proxy.as_ref().unwrap();
    assert_eq!(jf.kind, KIND_PROXY);
    assert_eq!(jp.upstreams[0], "jellyfin:8096");
    assert_eq!(jp.lb_policy, "round_robin");
    assert_eq!(jp.health_uri, "/health");
    assert_eq!(jf.config.headers_set["X-Frame-Options"], "DENY");
    assert_eq!(jf.config.compression.len(), 2);
    let v = &h["pw.example.com"];
    let vp = v.config.proxy.as_ref().unwrap();
    assert_eq!(v.kind, KIND_PROXY);
    assert_eq!(vp.upstreams[0], "https://10.0.0.5:8443");
    assert!(vp.tls_skip_verify);
    assert_eq!(v.config.max_body_size, "10MB");
    assert_eq!(v.config.access.basic_auth.len(), 1);
    assert_eq!(v.config.routes.len(), 1);
    assert_eq!(v.config.routes[0].path, "/api/*");
    assert!(v.config.routes[0].strip_prefix);
    let d = &h["docs.example.com"];
    let ds = d.config.r#static.as_ref().unwrap();
    assert!(
        d.kind == KIND_STATIC && ds.root == "/srv/docs" && ds.browse && ds.spa,
        "{ds:?}"
    );
    let o = &h["old.example.com"];
    let or = o.config.redirect.as_ref().unwrap();
    assert!(
        o.kind == KIND_REDIRECT
            && or.to == "https://new.example.com"
            && or.code == 301
            && or.keep_path
    );
    let s = &h["status.example.com"];
    assert!(s.kind == KIND_RESPOND && s.config.respond.as_ref().unwrap().body == "OK");
    assert_eq!(
        h["a.lan.example.com"].kind, KIND_PROXY,
        "wildcard sub-site not split out"
    );
    assert!(
        !h.contains_key("weird.example.com"),
        "php site should not be imported as structured"
    );

    // Nothing is lost: unmappable routes are kept (disabled) with their JSON.
    assert_eq!(res.raw_blocks.len(), 2, "{:?}", res.report);
    for rb in &res.raw_blocks {
        assert!(!rb.enabled && rb.body.contains("\"handler\""), "{rb:?}");
    }

    // DNS: env reference kept as a reference, literal secret flagged.
    let env_ref = res
        .credentials
        .iter()
        .any(|c| c.fields.get("api_token").map(|s| s.as_str()) == Some("env:CF_API_TOKEN"));
    let literal = res
        .credentials
        .iter()
        .any(|c| c.fields.get("api_token").map(|s| s.as_str()) == Some("literal-secret-token"));
    assert!(
        env_ref && literal && res.warnings.len() == 1,
        "{:?} {:?}",
        res.credentials,
        res.warnings
    );
    let doms: HashMap<&str, &DomainSuggestion> =
        res.domains.iter().map(|d| (d.name.as_str(), d)).collect();
    assert!(doms["lan.example.com"].wildcard);
    assert_eq!(doms["example.com"].challenge, CHALLENGE_DNS);
    assert_eq!(res.email, "me@example.com");
}

#[test]
fn import_json_rejects_garbage() {
    assert!(import_json(b"not json").is_err());
    let res = import_json(br#"{"admin":{"listen":"localhost:2019"}}"#).unwrap();
    assert!(res.sites.is_empty());
}

/// import -> generate -> caddy adapt must succeed. Needs CADDY_BIN.
#[tokio::test]
async fn import_round_trip() {
    let Ok(bin) = std::env::var("CADDY_BIN") else {
        return;
    };
    let src = SAMPLE.replacen(
        "\ttls {\n\t\tdns cloudflare {env.CF_API_TOKEN}\n\t\tresolvers 1.1.1.1\n\t}\n",
        "",
        1,
    );
    let mut res = import(&src).unwrap();
    let s = Settings {
        acme_email: res.email.clone(),
        acme_ca: res.acme_ca.clone(),
        raw_global: res.raw_global.clone(),
        ..Default::default()
    };
    for (i, st) in res.sites.iter_mut().enumerate() {
        st.id = (i + 1) as i64;
    }
    for (i, rb) in res.raw_blocks.iter_mut().enumerate() {
        rb.id = (i + 1) as i64;
    }
    let out = generator::generate(&generator::Input {
        settings: s,
        sites: res.sites.clone(),
        snippets: res.snippets.clone(),
        raw_blocks: res.raw_blocks.clone(),
        caps: Capabilities::default(),
        env: generator::Env {
            admin_listen: "localhost:2019".into(),
            log_dir: "/var/log/caddy".into(),
            ..Default::default()
        },
        ..Default::default()
    });
    if let Err(e) = crate::caddy::Runner::new(bin).adapt(&out.caddyfile).await {
        panic!("round-trip adapt failed: {e}\n{}", out.caddyfile);
    }
}

/// Imports a Caddyfile both ways, regenerates it from the model and checks
/// every host behaves the same. Needs CADDY_BIN.
#[tokio::test]
async fn round_trip_both_importers() {
    let Ok(bin) = std::env::var("CADDY_BIN") else {
        return;
    };
    let r = crate::caddy::Runner::new(bin);
    let caps = r.capabilities().await.unwrap();
    let src = r#"{
	email me@example.com
}
app.example.com {
	encode zstd gzip
	reverse_proxy app:8080 {
		lb_policy least_conn
	}
}
files.example.com {
	root * /srv/files
	file_server browse
}
api.example.com {
	handle_path /v1/* {
		reverse_proxy v1:9000
	}
	reverse_proxy https://10.0.0.5:8443 {
		transport http {
			tls_insecure_skip_verify
		}
	}
}
go.example.com {
	redir https://example.org{uri} permanent
}
ok.example.com {
	respond "fine" 200
}
"#;
    let adapted = r.adapt(src).await.unwrap();
    let orig = import_json(&serde_json::to_vec(&adapted.json).unwrap()).unwrap();
    assert_eq!(orig.sites.len(), 5, "{:?}", orig.report);
    // The Caddyfile importer must agree with the JSON importer.
    let cf = import(src).unwrap();
    let d = compare_fingerprints(&fingerprint(&orig), &fingerprint(&cf));
    assert!(
        d.is_empty(),
        "Caddyfile vs JSON import differ:\n{}",
        d.join("\n")
    );

    let regen = generator::generate(&preview_input(
        &orig,
        Settings::default(),
        generator::Env {
            admin_listen: "localhost:2019".into(),
            ..Default::default()
        },
        caps,
    ));
    let again = r
        .adapt(&regen.caddyfile)
        .await
        .unwrap_or_else(|e| panic!("regenerated config invalid: {e}\n{}", regen.caddyfile));
    let back = import_json(&serde_json::to_vec(&again.json).unwrap()).unwrap();
    let d = compare_fingerprints(&fingerprint(&orig), &fingerprint(&back));
    assert!(
        d.is_empty(),
        "round trip differs:\n{}\n\ngenerated:\n{}",
        d.join("\n"),
        regen.caddyfile
    );
}
