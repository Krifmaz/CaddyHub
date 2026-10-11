use super::*;
use crate::caddy::{ApiError, CaddyError};
use crate::secrets::SecretBox;
use std::sync::Mutex;

// ---------------------------------------------------------------- fakes

#[derive(Default)]
struct FakeValidator {
    adapt_err: Option<String>,
    validate_err: Option<CaddyError>,
    validated: Mutex<Vec<String>>,
}

impl Validator for FakeValidator {
    fn adapt<'a>(&'a self, _s: &'a str) -> BoxFut<'a, Result<AdaptResult>> {
        Box::pin(async move {
            match &self.adapt_err {
                Some(e) => Err(anyhow!("{e}")),
                None => Ok(AdaptResult {
                    json: serde_json::json!({}),
                    warnings: Vec::new(),
                }),
            }
        })
    }
    fn validate<'a>(&'a self, s: &'a str) -> BoxFut<'a, Result<()>> {
        Box::pin(async move {
            self.validated.lock().unwrap().push(s.to_string());
            match &self.validate_err {
                Some(e) => Err(CaddyError {
                    stage: e.stage.clone(),
                    messages: e.messages.clone(),
                    cause: e.cause.clone(),
                }
                .into()),
                None => Ok(()),
            }
        })
    }
}

#[derive(Default)]
struct FakeAdmin {
    loads: Mutex<Vec<String>>,
    load_err: Option<ApiError>,
    json_loads: Mutex<Vec<String>>,
}

impl AdminApi for FakeAdmin {
    fn load_caddyfile<'a>(&'a self, s: &'a str, _force: bool) -> BoxFut<'a, Result<()>> {
        Box::pin(async move {
            self.loads.lock().unwrap().push(s.to_string());
            match &self.load_err {
                Some(e) => Err(ApiError {
                    status: e.status,
                    body: e.body.clone(),
                }
                .into()),
                None => Ok(()),
            }
        })
    }
    fn load_json<'a>(&'a self, b: &'a [u8]) -> BoxFut<'a, Result<()>> {
        Box::pin(async move {
            self.json_loads
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(b).to_string());
            Ok(())
        })
    }
    fn config<'a>(&'a self) -> BoxFut<'a, Result<Vec<u8>>> {
        Box::pin(async { Ok(br#"{"apps":{"marker":"previous"}}"#.to_vec()) })
    }
    fn ping<'a>(&'a self) -> BoxFut<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

struct FakeHealth {
    err: Mutex<Option<String>>,
}

impl HealthChecker for FakeHealth {
    fn check<'a>(&'a self, _expect: bool) -> BoxFut<'a, Result<()>> {
        Box::pin(async move {
            match self.err.lock().unwrap().clone() {
                Some(e) => Err(anyhow!("{e}")),
                None => Ok(()),
            }
        })
    }
}

fn new_store() -> Arc<Store> {
    Arc::new(Store::open_memory(Arc::new(SecretBox::new(b"test-key").unwrap())).unwrap())
}

struct Harness {
    dir: tempfile::TempDir,
    store: Arc<Store>,
    admin: Arc<FakeAdmin>,
    health: Arc<FakeHealth>,
    validator: Arc<FakeValidator>,
    p: Pipeline,
}

fn harness(validator: FakeValidator, admin: FakeAdmin) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let store = new_store();
    let admin = Arc::new(admin);
    let health = Arc::new(FakeHealth {
        err: Mutex::new(None),
    });
    let validator = Arc::new(validator);
    let p = Pipeline::new(PipelineParts {
        store: store.clone(),
        validator: validator.clone(),
        admin: admin.clone(),
        health: health.clone(),
        secrets: Some(Arc::new(Materializer::new(dir.path().join("secrets")))),
        env: Env {
            admin_listen: "localhost:2019".into(),
            log_dir: "/var/log/caddy".into(),
            ..Default::default()
        },
        persist_path: dir.path().join("config").join("Caddyfile"),
        caps: Arc::new(RwLock::new(Capabilities::default())),
        notify: None,
    });
    Harness {
        dir,
        store,
        admin,
        health,
        validator,
        p,
    }
}

fn add_site(s: &Store, host: &str, upstream: &str) -> Site {
    s.create_site(Site {
        name: host.into(),
        hosts: vec![host.into()],
        kind: KIND_PROXY.into(),
        enabled: true,
        config: SiteConfig {
            proxy: Some(ProxyConfig {
                upstreams: vec![upstream.into()],
                ..Default::default()
            }),
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap()
}

// ---------------------------------------------------------------- unit tests

#[tokio::test]
async fn apply_success_persists() {
    let h = harness(FakeValidator::default(), FakeAdmin::default());
    add_site(&h.store, "app.example.com", "app:80");
    let res =
        h.p.apply(Options {
            user: "tester".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(res.status, "applied", "{}", res.message);
    let b = std::fs::read_to_string(&h.p.persist_path).unwrap();
    assert!(b.contains("reverse_proxy app:80"));
    let lg = h.store.last_good().unwrap();
    assert_eq!(lg.id, res.version_id);
    assert_eq!(lg.user, "tester");
    // validation used the redirected-log copy, not the real paths
    let validated = h.validator.validated.lock().unwrap();
    assert!(
        !validated[0].contains("/var/log/caddy"),
        "validation copy must not reference the real log dir"
    );
}

#[tokio::test]
async fn invalid_config_blocked() {
    let v = FakeValidator {
        validate_err: Some(CaddyError {
            stage: "validate".into(),
            messages: vec![Message {
                level: "error".into(),
                text: "bad module".into(),
            }],
            cause: "exit 1".into(),
        }),
        ..Default::default()
    };
    let h = harness(v, FakeAdmin::default());
    add_site(&h.store, "app.example.com", "app:80");
    let res =
        h.p.apply(Options {
            user: "u".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(res.status, "invalid");
    assert!(res.message.contains("bad module"), "{}", res.message);
    assert!(
        h.admin.loads.lock().unwrap().is_empty(),
        "invalid config must never reach /load"
    );
    assert!(
        !h.p.persist_path.exists(),
        "invalid config must not be persisted"
    );
}

#[tokio::test]
async fn load_rejected_not_persisted() {
    let a = FakeAdmin {
        load_err: Some(ApiError {
            status: 400,
            body: r#"{"error":"listen tcp :443: bind: address already in use"}"#.into(),
        }),
        ..Default::default()
    };
    let h = harness(FakeValidator::default(), a);
    add_site(&h.store, "app.example.com", "app:80");
    let res =
        h.p.apply(Options {
            user: "u".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(res.status, "failed");
    assert!(
        res.message.contains("address already in use"),
        "{}",
        res.message
    );
    assert!(!h.p.persist_path.exists());
}

#[tokio::test]
async fn health_failure_rolls_back() {
    let h = harness(FakeValidator::default(), FakeAdmin::default());
    add_site(&h.store, "app.example.com", "app:80");
    let res =
        h.p.apply(Options {
            user: "u".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(res.status, "applied");
    let good = std::fs::read_to_string(&h.p.persist_path).unwrap();

    add_site(&h.store, "new.example.com", "new:80");
    *h.health.err.lock().unwrap() = Some("listener caddy:443 not accepting connections".into());
    let res =
        h.p.apply(Options {
            user: "u".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(res.status, "rolled_back");
    assert!(res.rolled_back);
    let jl = h.admin.json_loads.lock().unwrap();
    assert_eq!(jl.len(), 1);
    assert!(
        jl[0].contains(r#""marker":"previous""#),
        "exact previous JSON should be restored"
    );
    assert_eq!(
        std::fs::read_to_string(&h.p.persist_path).unwrap(),
        good,
        "persisted config must remain the last good one"
    );
    let vs = h.store.versions(10).unwrap();
    assert_eq!(vs[0].status, "rolled_back");
    assert!(!vs[0].good);
}

#[tokio::test]
async fn dry_run_does_not_apply() {
    let h = harness(FakeValidator::default(), FakeAdmin::default());
    add_site(&h.store, "app.example.com", "app:80");
    let res =
        h.p.apply(Options {
            dry_run: true,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(res.status, "dry_run");
    assert!(h.admin.loads.lock().unwrap().is_empty());
    assert!(res.plan.changed && res.plan.added > 0);
    assert!(
        h.store.versions(10).unwrap().is_empty(),
        "dry run must not create versions"
    );
}

#[tokio::test]
async fn rollback_to_version() {
    let h = harness(FakeValidator::default(), FakeAdmin::default());
    let mut site = add_site(&h.store, "app.example.com", "v1:80");
    let r1 =
        h.p.apply(Options {
            user: "u".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    site.config.proxy.as_mut().unwrap().upstreams = vec!["v2:80".into()];
    h.store.update_site(&site).unwrap();
    h.p.apply(Options {
        user: "u".into(),
        ..Default::default()
    })
    .await
    .unwrap();
    let res =
        h.p.apply_snapshot(
            r1.version_id,
            Options {
                user: "u".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(res.status, "applied", "{}", res.message);
    assert!(
        std::fs::read_to_string(&h.p.persist_path)
            .unwrap()
            .contains("v1:80")
    );
}

/// Swaps a domain from Cloudflare to Porkbun and checks the regenerated
/// config, the secret files, and that the plan shows the change.
#[tokio::test]
async fn provider_switch() {
    let h = harness(FakeValidator::default(), FakeAdmin::default());
    let s = &h.store;
    let cf = s
        .save_credential(DnsCredential {
            name: "cf".into(),
            provider: "cloudflare".into(),
            fields: BTreeMap::from([(
                "api_token".to_string(),
                "cf-secret-token-value-1234567890abcdef".to_string(),
            )]),
            ..Default::default()
        })
        .unwrap();
    let pb = s
        .save_credential(DnsCredential {
            name: "pb".into(),
            provider: "porkbun".into(),
            fields: BTreeMap::from([
                ("api_key".to_string(), "env:PORKBUN_KEY".to_string()),
                ("api_secret_key".to_string(), "pb-secret".to_string()),
            ]),
            ..Default::default()
        })
        .unwrap();
    let mut d = s
        .save_domain(Domain {
            name: "example.com".into(),
            challenge: CHALLENGE_DNS.into(),
            credential_id: Some(cf.id),
            ..Default::default()
        })
        .unwrap();
    add_site(s, "app.example.com", "app:80");
    let res =
        h.p.apply(Options {
            user: "u".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(res.status, "applied", "{}", res.message);
    let cf_file = h
        .dir
        .path()
        .join("secrets")
        .join(format!("dns-{}-api_token", cf.id));
    assert_eq!(
        std::fs::read_to_string(&cf_file).unwrap(),
        "cf-secret-token-value-1234567890abcdef"
    );
    let persisted = std::fs::read_to_string(&h.p.persist_path).unwrap();
    assert!(
        !persisted.contains("cf-secret-token"),
        "secret leaked into the Caddyfile"
    );

    d.credential_id = Some(pb.id);
    s.save_domain(d).unwrap();
    let plan = h.p.plan().await.unwrap();
    let has_line = |prefix: char, text: &str| {
        plan.diff
            .lines()
            .any(|l| l.starts_with(prefix) && l[1..].trim() == text)
    };
    assert!(
        has_line('+', "dns porkbun {") && has_line('-', "dns cloudflare {"),
        "plan diff should show provider swap:\n{}",
        plan.diff
    );
    assert!(plan.caddyfile.contains("api_key {env.PORKBUN_KEY}"));
    assert!(!plan.caddyfile.contains("pb-secret"));
    // cloudflare credential still exists, so its file is kept; delete it and
    // make sure the file is pruned on the next build
    s.delete_credential(cf.id).unwrap();
    h.p.plan().await.unwrap();
    assert!(
        !cf_file.exists(),
        "secret file for deleted credential should be pruned"
    );
    let res =
        h.p.apply(Options {
            user: "u".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(res.status, "applied", "{}", res.message);
}

#[test]
fn validation_copy_rewrites() {
    let text = "{\n\tadmin x\n\tlog {\n\t\toutput file /var/log/caddy/caddy.log\n\t}\n}\na.example.com {\n\tlog {\n\t\toutput file /var/log/caddy/access-site-1.log\n\t}\n}\n";
    let out = validation_copy(text, "/var/log/caddy", "/tmp/x");
    assert!(!out.contains("caddy.log"), "{out}");
    assert!(out.contains("/tmp/x/access-site-1.log"), "{out}");
    assert!(has_site_blocks(text));
    assert!(!has_site_blocks("{\n\tadmin off\n}\n"));
}

// ---------------------------------------------------------------- real Caddy

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Runs apply + health-failure rollback against a real Caddy process. Set
/// CADDY_BIN to enable.
#[tokio::test]
async fn real_caddy_pipeline() {
    let Ok(bin) = std::env::var("CADDY_BIN") else {
        eprintln!("CADDY_BIN not set; skipping");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let (admin_port, http_port) = (free_port(), free_port());
    let admin_addr = format!("127.0.0.1:{admin_port}");
    let boot = dir.path().join("Caddyfile");
    std::fs::write(&boot, format!("{{\n\tadmin {admin_addr}\n}}\n")).unwrap();

    let mut child = tokio::process::Command::new(&bin)
        .args([
            "run",
            "--config",
            &secrets::to_slash(&boot),
            "--adapter",
            "caddyfile",
        ])
        .env("XDG_DATA_HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .env("HOME", dir.path())
        .env("APPDATA", dir.path())
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    let admin = Arc::new(Admin::new(&admin_addr));
    admin.wait_ready(Duration::from_secs(20)).await.unwrap();

    let store = new_store();
    store.update_settings(|st| st.metrics = false).unwrap();
    store
        .create_site(Site {
            name: "hello".into(),
            hosts: vec![format!("localhost:{http_port}")],
            kind: KIND_RESPOND.into(),
            enabled: true,
            config: SiteConfig {
                tls: TlsConfig {
                    mode: TLS_OFF.into(),
                    ..Default::default()
                },
                respond: Some(RespondConfig {
                    body: "hello v1".into(),
                    status: 200,
                    ..Default::default()
                }),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();

    let runner = Arc::new(Runner::new(&bin));
    let caps = runner.capabilities().await.unwrap();
    let health: Arc<dyn HealthChecker> = Arc::new(DefaultHealth {
        admin: admin.clone(),
        probe_addrs: vec![format!("127.0.0.1:{http_port}")],
        settle: Duration::from_millis(500),
    });
    let mk = |health: Arc<dyn HealthChecker>| {
        Pipeline::new(PipelineParts {
            store: store.clone(),
            validator: runner.clone(),
            admin: admin.clone(),
            health,
            secrets: Some(Arc::new(Materializer::new(dir.path().join("secrets")))),
            env: Env {
                admin_listen: admin_addr.clone(),
                log_dir: secrets::to_slash(&dir.path().join("logs")),
                ..Default::default()
            },
            persist_path: boot.clone(),
            caps: Arc::new(RwLock::new(caps.clone())),
            notify: None,
        })
    };

    let client = crate::httpc::client();
    let get = || async {
        let r = client
            .get(format!("http://127.0.0.1:{http_port}/"))
            .header("Host", format!("localhost:{http_port}"))
            .send()
            .await;
        match r {
            Ok(r) => r.text().await.unwrap_or_default(),
            Err(e) => format!("ERR {e}"),
        }
    };

    let p = mk(health.clone());
    let res = p
        .apply(Options {
            user: "it".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(res.status, "applied", "{}", res.message);
    assert_eq!(get().await, "hello v1");

    // change the site, but force the health check to fail -> rollback
    let mut sites = store.sites().unwrap();
    sites[0].config.respond.as_mut().unwrap().body = "hello v2".into();
    store.update_site(&sites[0]).unwrap();
    struct FailingAfterLoad(Arc<dyn HealthChecker>);
    impl HealthChecker for FailingAfterLoad {
        fn check<'a>(&'a self, expect: bool) -> BoxFut<'a, Result<()>> {
            Box::pin(async move {
                self.0.check(expect).await?;
                Err(anyhow!("simulated health check failure"))
            })
        }
    }
    let p2 = mk(Arc::new(FailingAfterLoad(health.clone())));
    let res = p2
        .apply(Options {
            user: "it".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(res.status, "rolled_back", "{}", res.message);
    assert_eq!(
        get().await,
        "hello v1",
        "after rollback Caddy should serve v1 again"
    );

    // invalid raw snippet is caught by validation and never loaded
    sites[0].config.raw = "this_is_not_a_directive foo".into();
    store.update_site(&sites[0]).unwrap();
    let res = p
        .apply(Options {
            user: "it".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(res.status, "invalid");
    assert_eq!(res.plan.stage, "adapt");
    assert_eq!(get().await, "hello v1");

    // fix and apply v2 for real
    sites[0].config.raw = String::new();
    store.update_site(&sites[0]).unwrap();
    let res = p
        .apply(Options {
            user: "it".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(res.status, "applied", "{}", res.message);
    assert_eq!(get().await, "hello v2");
    assert!(
        std::fs::read_to_string(&boot).unwrap().contains("hello v2"),
        "v2 not persisted for restarts"
    );

    let _ = child.kill().await;
}
