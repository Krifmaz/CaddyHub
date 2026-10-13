use anyhow::{Result, anyhow};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::registry::{Capabilities, parse_version};
use crate::secrets::to_slash;

/// Executes a Caddy binary.
#[derive(Debug, Clone)]
pub struct Runner {
    /// path to the caddy binary
    pub bin: PathBuf,
    /// per command
    pub timeout: Duration,
    /// Appended to the command environment (e.g. env refs that the
    /// generated config uses via {env.*}).
    pub extra_env: Vec<(String, String)>,
}

/// One structured log line from the CLI.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Message {
    pub level: String,
    pub text: String,
}

/// A CLI failure with readable messages.
#[derive(Debug, thiserror::Error)]
pub struct CaddyError {
    pub stage: String,
    pub messages: Vec<Message>,
    pub cause: String,
}

impl std::fmt::Display for CaddyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parts: Vec<&str> = self
            .messages
            .iter()
            .filter(|m| m.level == "error" || m.level == "fatal" || m.level.is_empty())
            .map(|m| m.text.as_str())
            .collect();
        if parts.is_empty() {
            write!(f, "{}: {}", self.stage, self.cause)
        } else {
            write!(f, "{}: {}", self.stage, parts.join("; "))
        }
    }
}

/// The output of `caddy adapt`.
#[derive(Debug, Clone, Serialize)]
pub struct AdaptResult {
    pub json: serde_json::Value,
    pub warnings: Vec<String>,
}

/// Turns any error into the list of messages shown in the UI.
pub fn err_messages(err: &anyhow::Error) -> Vec<Message> {
    if let Some(ce) = err.downcast_ref::<CaddyError>() {
        if !ce.messages.is_empty() {
            return ce.messages.clone();
        }
    }
    vec![Message {
        level: "error".into(),
        text: err.to_string(),
    }]
}

impl Runner {
    /// A runner with defaults.
    pub fn new(bin: impl Into<PathBuf>) -> Runner {
        Runner {
            bin: bin.into(),
            timeout: Duration::from_secs(60),
            extra_env: Vec::new(),
        }
    }

    /// Reports whether the binary exists.
    pub fn available(&self) -> bool {
        !self.bin.as_os_str().is_empty() && self.bin.is_file()
    }

    async fn run(&self, dir: &Path, args: &[&str]) -> Result<(Vec<u8>, Vec<u8>)> {
        if !self.available() {
            return Err(anyhow!("caddy binary not found at {:?}", self.bin));
        }
        let mut cmd = tokio::process::Command::new(&self.bin);
        cmd.args(args).current_dir(dir);
        // Isolate storage so validation never touches real certificates.
        cmd.env("XDG_DATA_HOME", dir.join("data"));
        cmd.env("XDG_CONFIG_HOME", dir.join("config"));
        cmd.env("HOME", dir);
        cmd.env("APPDATA", dir.join("appdata"));
        for (k, v) in &self.extra_env {
            cmd.env(k, v);
        }
        cmd.stdin(std::process::Stdio::null());
        cmd.kill_on_drop(true);
        let out = tokio::time::timeout(self.timeout, cmd.output())
            .await
            .map_err(|_| anyhow!("caddy {} timed out", args.first().unwrap_or(&"")))??;
        if !out.status.success() {
            return Err(RunFailure {
                stdout: out.stdout,
                stderr: out.stderr,
                status: out.status.code().unwrap_or(-1),
            }
            .into());
        }
        Ok((out.stdout, out.stderr))
    }

    /// Converts a Caddyfile to JSON using the binary.
    pub async fn adapt(&self, caddyfile: &str) -> Result<AdaptResult> {
        let tmp = tempfile::Builder::new().prefix("caddymium-").tempdir()?;
        let path = tmp.path().join("Caddyfile");
        std::fs::write(&path, caddyfile)?;
        let ps = to_slash(&path);
        match self
            .run(
                tmp.path(),
                &["adapt", "--config", &ps, "--adapter", "caddyfile"],
            )
            .await
        {
            Ok((out, err_out)) => {
                let msgs = parse_log_messages(&err_out, &ps);
                let json: serde_json::Value =
                    serde_json::from_slice(&out).unwrap_or(serde_json::Value::Null);
                let warnings = msgs
                    .into_iter()
                    .filter(|m| m.level == "warn")
                    .map(|m| m.text)
                    .collect();
                Ok(AdaptResult { json, warnings })
            }
            Err(e) => Err(stage_error("adapt", e, &ps)),
        }
    }

    /// Runs `caddy validate` (adapt + provision, without starting).
    pub async fn validate(&self, caddyfile: &str) -> Result<()> {
        let tmp = tempfile::Builder::new().prefix("caddymium-").tempdir()?;
        let path = tmp.path().join("Caddyfile");
        std::fs::write(&path, caddyfile)?;
        let ps = to_slash(&path);
        match self
            .run(
                tmp.path(),
                &["validate", "--config", &ps, "--adapter", "caddyfile"],
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(stage_error("validate", e, &ps)),
        }
    }

    /// `caddy version` output.
    pub async fn version(&self) -> Result<String> {
        let (out, _) = self
            .run(&std::env::temp_dir(), &["version"])
            .await
            .map_err(|e| stage_error("version", e, ""))?;
        Ok(String::from_utf8_lossy(&out).trim().to_string())
    }

    /// `caddy build-info` output.
    pub async fn build_info(&self) -> Result<String> {
        let (out, _) = self
            .run(&std::env::temp_dir(), &["build-info"])
            .await
            .map_err(|e| stage_error("build-info", e, ""))?;
        Ok(String::from_utf8_lossy(&out).to_string())
    }

    /// The GOARCH the binary was built for (amd64, arm64, ...), if known.
    pub async fn arch(&self) -> Option<String> {
        let info = self.build_info().await.ok()?;
        info.lines().find_map(|l| {
            let l = l.trim();
            l.strip_prefix("build")
                .map(|r| r.trim())
                .and_then(|r| r.strip_prefix("GOARCH="))
                .map(|a| a.trim().to_string())
        })
    }

    /// Detects version and modules.
    pub async fn capabilities(&self) -> Result<Capabilities> {
        let mut caps = Capabilities::default();
        let v = self.version().await?;
        caps.version_s = v.split_whitespace().next().unwrap_or("").to_string();
        caps.version = parse_version(&v);
        let out = match self
            .run(
                &std::env::temp_dir(),
                &["list-modules", "--packages", "--versions"],
            )
            .await
        {
            Ok((out, _)) => out,
            // older/newer CLIs may not support the flags; fall back to plain
            Err(_) => {
                self.run(&std::env::temp_dir(), &["list-modules"])
                    .await
                    .map_err(|e| stage_error("list-modules", e, ""))?
                    .0
            }
        };
        parse_modules(&String::from_utf8_lossy(&out), &mut caps);
        caps.detected = true;
        Ok(caps)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("exit status {status}")]
struct RunFailure {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    status: i32,
}

fn stage_error(stage: &str, e: anyhow::Error, tmp_path: &str) -> anyhow::Error {
    match e.downcast::<RunFailure>() {
        Ok(rf) => {
            let mut messages = parse_log_messages(&rf.stderr, tmp_path);
            if messages.is_empty() && !rf.stdout.is_empty() {
                messages = parse_log_messages(&rf.stdout, tmp_path);
            }
            CaddyError {
                stage: stage.into(),
                messages,
                cause: rf.to_string(),
            }
            .into()
        }
        Err(e) => CaddyError {
            stage: stage.into(),
            messages: Vec::new(),
            cause: e.to_string(),
        }
        .into(),
    }
}

/// Parses list-modules output. Lines look like:
///
///   http.handlers.reverse_proxy v2.11.7 github.com/caddyserver/caddy/v2/...
///   dns.providers.cloudflare v0.2.1 github.com/caddy-dns/cloudflare
///
/// Section headers ("Standard modules: 120") and blank lines are ignored.
pub fn parse_modules(out: &str, caps: &mut Capabilities) {
    for line in out.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.is_empty() || f[0].ends_with(':') || line.contains(" modules:") {
            continue;
        }
        let id = f[0];
        if !looks_like_module_id(id) {
            continue;
        }
        caps.modules.insert(id.to_string());
        if f.len() >= 3 {
            caps.packages
                .insert(id.to_string(), format!("{}@{}", f[2], f[1]));
        } else if f.len() == 2 {
            caps.packages.insert(id.to_string(), f[1].to_string());
        }
    }
}

fn looks_like_module_id(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|r| {
            r.is_ascii_lowercase() || r.is_ascii_digit() || r == '.' || r == '_' || r == '-'
        })
}

/// Turns Caddy's JSON log lines (or plain text) into messages, replacing the
/// temp file path with "Caddyfile" for readability.
pub fn parse_log_messages(b: &[u8], tmp_path: &str) -> Vec<Message> {
    let mut out = Vec::new();
    for line in String::from_utf8_lossy(b).lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(m) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(line) {
            let lvl = m
                .get("level")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let mut msg = m
                .get("msg")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if let Some(e) = m.get("error").and_then(|v| v.as_str()) {
                if !e.is_empty() {
                    msg = format!("{msg}: {e}");
                }
            }
            if lvl == "info" || lvl == "debug" {
                continue;
            }
            if lvl == "warn"
                && m.get("adapter")
                    .and_then(|v| v.as_str())
                    .is_some_and(|a| !a.is_empty())
            {
                if let Some(f) = m.get("file").and_then(|v| v.as_str()) {
                    let base = f.rsplit(['/', '\\']).next().unwrap_or(f);
                    let ln = m.get("line").map(|v| v.to_string()).unwrap_or_default();
                    msg = format!("{msg} ({base}:{ln})");
                }
            }
            out.push(Message {
                level: lvl,
                text: clean_path(&msg, tmp_path),
            });
            continue;
        }
        out.push(Message {
            level: "error".into(),
            text: clean_path(line, tmp_path),
        });
    }
    out
}

fn clean_path(s: &str, p: &str) -> String {
    if p.is_empty() {
        return s.to_string();
    }
    s.replace(p, "Caddyfile")
        .replace(&p.replace('/', "\\"), "Caddyfile")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_modules_and_logs() {
        let mut caps = Capabilities::default();
        parse_modules(
            "Standard modules: 2\nadmin.api.load v2.11.7 github.com/caddyserver/caddy/v2\n\ndns.providers.cloudflare v0.2.4 github.com/caddy-dns/cloudflare\n  Non-standard modules: 1\n",
            &mut caps,
        );
        assert!(caps.modules.contains("dns.providers.cloudflare"));
        assert_eq!(
            caps.packages["dns.providers.cloudflare"],
            "github.com/caddy-dns/cloudflare@v0.2.4"
        );
        assert_eq!(
            caps.plugin_packages()
                .get("github.com/caddy-dns/cloudflare")
                .unwrap(),
            "v0.2.4"
        );
        let msgs = parse_log_messages(
            br#"{"level":"info","msg":"x"}
{"level":"error","msg":"adapt: /tmp/x/Caddyfile:3: unrecognized directive","error":"boom"}
plain line"#,
            "/tmp/x/Caddyfile",
        );
        assert_eq!(msgs.len(), 2);
        assert_eq!(
            msgs[0].text,
            "adapt: Caddyfile:3: unrecognized directive: boom"
        );
        assert_eq!(msgs[1].level, "error");
    }
}
