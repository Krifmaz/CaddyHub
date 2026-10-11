use super::*;
use crate::apply::{DefaultHealth, Pipeline, PipelineParts};
use crate::secrets::{Materializer, SecretBox};
use serde_json::{Value, json};

struct TestServer {
    base: String,
    _dir: tempfile::TempDir,
}

async fn start() -> TestServer {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        Store::open_memory(Arc::new(
            SecretBox::new(b"test-key-material-test-key-material").unwrap(),
        ))
        .unwrap(),
    );
    let runner = Arc::new(Runner::new(""));
    let admin = Arc::new(Admin::new("127.0.0.1:1"));
    let caps = Arc::new(RwLock::new(Capabilities::default()));
    let pipeline = Arc::new(Pipeline::new(PipelineParts {
        store: store.clone(),
        validator: runner.clone(),
        admin: admin.clone(),
        health: Arc::new(DefaultHealth {
            admin: admin.clone(),
            probe_addrs: vec![],
            settle: Duration::ZERO,
        }),
        secrets: Some(Arc::new(Materializer::new(dir.path().join("secrets")))),
        env: Default::default(),
        persist_path: dir.path().join("Caddyfile"),
        caps: caps.clone(),
        notify: None,
    }));
    let plugins = Arc::new(plugins::Manager::new(
        store.clone(),
        admin.clone(),
        caps.clone(),
        pipeline.clone(),
        dir.path().join("caddy"),
        String::new(),
        String::new(),
    ));
    let st = AppState::new(AppParts {
        store: store.clone(),
        pipeline,
        runner,
        admin,
        notifier: Arc::new(Notifier::new(store.clone())),
        caps,
        plugins,
        version: "test".into(),
        setup_token: String::new(),
        trust_xff: false,
        secure_cookie: false,
        dev_no_auth: false,
        imports: ImportPaths::default(),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = router(st);
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    TestServer { base, _dir: dir }
}

struct TestClient {
    base: String,
    http: reqwest::Client,
    csrf: String,
}

impl TestClient {
    fn new(base: &str) -> TestClient {
        TestClient {
            base: base.to_string(),
            http: crate::httpc::builder().cookie_store(true).build().unwrap(),
            csrf: String::new(),
        }
    }

    async fn call(&mut self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let mut req = self
            .http
            .request(method.parse().unwrap(), format!("{}{path}", self.base))
            .header("content-type", "application/json");
        if !self.csrf.is_empty() {
            req = req.header("x-csrf-token", &self.csrf);
        }
        if let Some(b) = body {
            req = req.body(b.to_string());
        }
        let resp = req.send().await.unwrap();
        let code = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        let v: Value = serde_json::from_str(&text).unwrap_or(json!({"_raw": text}));
        if let Some(tok) = v.get("csrf").and_then(|t| t.as_str()) {
            if !tok.is_empty() {
                self.csrf = tok.to_string();
            }
        }
        (code, v)
    }
}

#[tokio::test]
async fn setup_login_and_csrf() {
    let ts = start().await;
    let mut c = TestClient::new(&ts.base);
    let (code, me) = c.call("GET", "/api/me", None).await;
    assert_eq!(code, 200);
    assert_eq!(me["needs_setup"], true);
    assert_eq!(c.call("GET", "/api/sites", None).await.0, 401);
    let (code, _) = c
        .call(
            "POST",
            "/api/setup",
            Some(json!({"username": "admin", "password": "short"})),
        )
        .await;
    assert_eq!(code, 400, "weak password accepted");
    let (code, out) = c
        .call(
            "POST",
            "/api/setup",
            Some(json!({"username": "admin", "password": "long enough password"})),
        )
        .await;
    assert_eq!(code, 200, "{out}");
    // Setup only works once.
    let mut other = TestClient::new(&ts.base);
    assert_eq!(
        other
            .call(
                "POST",
                "/api/setup",
                Some(json!({"username": "evil", "password": "long enough password"}))
            )
            .await
            .0,
        409
    );

    // Writes need the CSRF token.
    let tok = c.csrf.clone();
    c.csrf = String::new();
    assert_eq!(c.call("POST", "/api/sites", Some(json!({}))).await.0, 403);
    c.csrf = tok;

    let site = json!({"name": "app", "hosts": ["App.Example.com", "app.example.com"], "kind": "proxy", "enabled": true,
        "config": {"proxy": {"upstreams": ["localhost:8080", " "]}}});
    let (code, out) = c.call("POST", "/api/sites", Some(site.clone())).await;
    assert_eq!(code, 201, "{out}");
    assert_eq!(
        out["hosts"],
        json!(["app.example.com"]),
        "hosts not normalized"
    );
    // Same hostname on another enabled site is rejected.
    assert_eq!(c.call("POST", "/api/sites", Some(site)).await.0, 409);
    // Invalid input gets a helpful 400.
    let bad = json!({"hosts": ["app.example.com:8080"], "kind": "proxy", "config": {"proxy": {"upstreams": ["x:1"]}}});
    let (code, out) = c.call("POST", "/api/sites", Some(bad)).await;
    assert_eq!(code, 400);
    assert!(out["error"].as_str().unwrap().contains("port"), "{out}");

    // Login with wrong then right password.
    let mut l = TestClient::new(&ts.base);
    assert_eq!(
        l.call(
            "POST",
            "/api/login",
            Some(json!({"username": "admin", "password": "nope nope nope"}))
        )
        .await
        .0,
        401
    );
    let (code, out) = l
        .call(
            "POST",
            "/api/login",
            Some(json!({"username": "admin", "password": "long enough password"})),
        )
        .await;
    assert_eq!(code, 200, "{out}");
    assert!(out["csrf"].as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(l.call("POST", "/api/logout", None).await.0, 200);
    assert_eq!(l.call("GET", "/api/sites", None).await.0, 401);
}

#[tokio::test]
async fn roles_and_secret_masking() {
    let ts = start().await;
    let mut admin = TestClient::new(&ts.base);
    admin
        .call(
            "POST",
            "/api/setup",
            Some(json!({"username": "admin", "password": "long enough password"})),
        )
        .await;
    let (code, out) = admin
        .call(
            "POST",
            "/api/users",
            Some(json!({"username": "viewer", "password": "viewer password 1", "role": "viewer"})),
        )
        .await;
    assert_eq!(code, 200, "{out}");
    let mut v = TestClient::new(&ts.base);
    v.call(
        "POST",
        "/api/login",
        Some(json!({"username": "viewer", "password": "viewer password 1"})),
    )
    .await;
    assert_eq!(v.call("GET", "/api/sites", None).await.0, 200);
    assert_eq!(v.call("POST", "/api/sites", Some(json!({}))).await.0, 403);
    assert_eq!(v.call("GET", "/api/users", None).await.0, 403);

    // DNS credential secrets are stored but never returned.
    let (code, out) = admin
        .call(
            "POST",
            "/api/dns-credentials",
            Some(json!({"provider": "cloudflare", "fields": {"api_token": "super-secret-token"}})),
        )
        .await;
    assert_eq!(code, 200, "{out}");
    let (_, list) = admin.call("GET", "/api/dns-credentials", None).await;
    assert!(
        !list.to_string().contains("super-secret-token"),
        "secret leaked: {list}"
    );
    // Updating with an empty secret keeps the stored value.
    let id = out["id"].as_i64().unwrap();
    let (code, out) = admin
        .call(
            "PUT",
            &format!("/api/dns-credentials/{id}"),
            Some(json!({"provider": "cloudflare", "name": "cf", "fields": {"api_token": ""}})),
        )
        .await;
    assert_eq!(code, 200, "{out}");
    assert_eq!(out["set"]["api_token"], true);

    // The last admin can't be demoted.
    assert_eq!(
        admin
            .call(
                "PUT",
                "/api/users/1",
                Some(json!({"username": "admin", "role": "viewer"}))
            )
            .await
            .0,
        409
    );

    // API keys work without CSRF and respect roles.
    let (code, out) = admin
        .call(
            "POST",
            "/api/api-keys",
            Some(json!({"name": "ci", "role": "viewer"})),
        )
        .await;
    assert_eq!(code, 201, "{out}");
    let tok = out["token"].as_str().unwrap().to_string();
    let plain = crate::httpc::client();
    let r = plain
        .get(format!("{}/api/sites", ts.base))
        .bearer_auth(&tok)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let r = plain
        .post(format!("{}/api/sites", ts.base))
        .bearer_auth(&tok)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 403);

    // Settings round-trip keeps defaults and validates DDNS input.
    let (code, s) = admin.call("GET", "/api/settings", None).await;
    assert_eq!(code, 200);
    assert_eq!(s["ddns"]["check_interval"], "5m");
    let mut body = s.clone();
    body["ddns"]["enabled"] = json!(true);
    body["ddns"]["credential_id"] = json!(id);
    body["ddns"]["domains"] = json!([{"zone": "Example.com.", "names": ["@", " www "]}]);
    let (code, out) = admin.call("PUT", "/api/settings", Some(body)).await;
    assert_eq!(code, 200, "{out}");
    assert_eq!(out["ddns"]["domains"][0]["zone"], "example.com");
    assert_eq!(out["ddns"]["domains"][0]["names"], json!(["@", "www"]));
    assert_eq!(out["acme_eab_mac_set"], false);
    // The credential is now in use by DDNS.
    assert_eq!(
        admin
            .call("DELETE", &format!("/api/dns-credentials/{id}"), None)
            .await
            .0,
        409
    );
}

#[tokio::test]
async fn reach_explains_failures() {
    let ts = start().await;
    let mut c = TestClient::new(&ts.base);
    c.call(
        "POST",
        "/api/setup",
        Some(json!({"username": "admin", "password": "long enough password"})),
    )
    .await;
    // A listener that is up, a closed port, and a name that doesn't resolve.
    let up = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_addr = up.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            let _ = up.accept().await;
        }
    });
    for (i, u) in [
        up_addr.as_str(),
        "127.0.0.1:1",
        "no-such-container.invalid:8096",
    ]
    .iter()
    .enumerate()
    {
        let site = json!({"name": i.to_string(), "hosts": [format!("s{i}.example.com")], "kind": "proxy", "enabled": true, "config": {"proxy": {"upstreams": [u]}}});
        let (code, out) = c.call("POST", "/api/sites", Some(site)).await;
        assert_eq!(code, 201, "{out}");
    }
    let (code, res) = c.call("GET", "/api/upstreams/reach", None).await;
    assert_eq!(code, 200, "{res}");
    let got: std::collections::HashMap<String, netscan::ReachResult> = res
        .as_array()
        .unwrap()
        .iter()
        .map(|r| serde_json::from_value::<netscan::ReachResult>(r.clone()).unwrap())
        .map(|r| (r.upstream.clone(), r))
        .collect();
    assert!(got[&up_addr].ok, "live upstream: {:?}", got[&up_addr]);
    let r = &got["127.0.0.1:1"];
    assert!(
        !r.ok && r.error.contains("nothing is listening"),
        "closed port: {r:?}"
    );
    let r = &got["no-such-container.invalid:8096"];
    assert!(
        !r.ok && r.error.contains("not found"),
        "unknown name: {r:?}"
    );
}

#[tokio::test]
async fn forward_proxy_site_validation() {
    let ts = start().await;
    let mut c = TestClient::new(&ts.base);
    c.call(
        "POST",
        "/api/setup",
        Some(json!({"username": "admin", "password": "long enough password"})),
    )
    .await;
    let bad = json!({"hosts": ["proxy.example.com"], "kind": "forward_proxy", "enabled": true,
        "config": {"forward_proxy": {"basic_auth": [{"username": "u", "password": ""}]}}});
    let (code, out) = c.call("POST", "/api/sites", Some(bad)).await;
    assert_eq!(code, 400, "{out}");
    let good = json!({"hosts": ["proxy.example.com"], "kind": "forward_proxy", "enabled": true,
        "config": {"forward_proxy": {"basic_auth": [{"username": "u", "password": "p"}], "acl": ["deny 10.0.0.0/8", "allow all"], "ports": [443, 0]}}});
    let (code, out) = c.call("POST", "/api/sites", Some(good)).await;
    assert_eq!(code, 201, "{out}");
    assert_eq!(out["config"]["forward_proxy"]["ports"], json!([443]));
    let (_, preview) = c.call("GET", "/api/config/preview", None).await;
    assert!(
        preview["caddyfile"]
            .as_str()
            .unwrap()
            .contains("forward_proxy {"),
        "{preview}"
    );
}
