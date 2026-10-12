//! Encryption at rest and the materialization of secrets into files that
//! Caddy reads through {file.*} placeholders, so that secrets never appear in
//! the Caddyfile, the database (unencrypted), logs or backups.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result, anyhow};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Fills `buf` with cryptographically secure random bytes.
pub fn random_bytes(buf: &mut [u8]) {
    getrandom::fill(buf).expect("OS random source unavailable");
}

/// Encrypts and decrypts with AES-256-GCM.
pub struct SecretBox {
    cipher: Aes256Gcm,
    #[allow(dead_code)]
    key: [u8; 32],
}

impl SecretBox {
    /// Derives a 32-byte key from the given material (raw 32 bytes, base64
    /// of 32 bytes, or any passphrase which is hashed with SHA-256).
    pub fn new(material: &[u8]) -> Result<SecretBox> {
        let m = String::from_utf8_lossy(material).trim().to_string();
        if m.is_empty() {
            return Err(anyhow!("empty secret key"));
        }
        let mut key = [0u8; 32];
        match base64::engine::general_purpose::STANDARD.decode(&m) {
            Ok(b) if b.len() == 32 => key.copy_from_slice(&b),
            _ => key.copy_from_slice(&Sha256::digest(m.as_bytes())),
        }
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow!("{e}"))?;
        Ok(SecretBox { cipher, key })
    }

    /// Encrypts plaintext. Output: nonce || ciphertext.
    pub fn seal(&self, plain: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 12];
        random_bytes(&mut nonce);
        let ct = self
            .cipher
            .encrypt(&Nonce::try_from(&nonce[..]).expect("nonce"), plain)
            .map_err(|e| anyhow!("encrypt: {e}"))?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypts data produced by `seal`.
    pub fn open(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 12 {
            return Err(anyhow!("ciphertext too short"));
        }
        self.cipher
            .decrypt(&Nonce::try_from(&data[..12]).expect("nonce"), &data[12..])
            .map_err(|_| anyhow!("message authentication failed"))
    }

    #[allow(dead_code)]
    /// The raw key encoded as base64 (for encrypted backups).
    pub fn key_material(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.key)
    }
}

/// Resolves the master key: env var, then *_FILE (Docker secret), then a
/// generated key file in data_dir. Returns the key and where it came from.
pub fn load_key(env_val: &str, env_file: &str, data_dir: &Path) -> Result<(Vec<u8>, &'static str)> {
    if !env_val.is_empty() {
        return Ok((env_val.as_bytes().to_vec(), "env"));
    }
    if !env_file.is_empty() {
        let b = std::fs::read(env_file).context("read secret key file")?;
        return Ok((b, "file"));
    }
    let p = data_dir.join("secret.key");
    if let Ok(b) = std::fs::read(&p) {
        return Ok((b, "generated"));
    }
    let mut raw = [0u8; 32];
    random_bytes(&mut raw);
    let enc = format!(
        "{}\n",
        base64::engine::general_purpose::STANDARD.encode(raw)
    );
    write_private(&p, enc.as_bytes()).context("write generated secret key")?;
    Ok((enc.into_bytes(), "generated"))
}

/// Writes a file readable only by the owner (where the OS supports it).
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data)
    }
    #[cfg(not(unix))]
    std::fs::write(path, data)
}

#[allow(dead_code)]
/// Reports whether a stored value is a reference rather than a secret.
pub fn is_ref(v: &str) -> bool {
    v.starts_with("env:") || v.starts_with("file:")
}

/// Converts "env:NAME" / "file:/path" to a Caddy placeholder.
pub fn ref_placeholder(v: &str) -> Option<String> {
    if let Some(name) = v.strip_prefix("env:") {
        if !valid_env_name(name) {
            return None;
        }
        return Some(format!("{{env.{name}}}"));
    }
    if let Some(p) = v.strip_prefix("file:") {
        if p.is_empty() || p.contains(['{', '}', ' ', '\t', '\n']) {
            return None;
        }
        return Some(format!("{{file.{p}}}"));
    }
    None
}

fn valid_env_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .enumerate()
            .all(|(i, r)| r == '_' || r.is_ascii_alphabetic() || (i > 0 && r.is_ascii_digit()))
}

/// Writes secret files into a directory shared with Caddy (mounted at the
/// same path in both containers).
pub struct Materializer {
    pub dir: PathBuf,
    lock: Mutex<()>,
}

impl Materializer {
    pub fn new(dir: PathBuf) -> Materializer {
        Materializer {
            dir,
            lock: Mutex::new(()),
        }
    }

    /// Writes value to `<dir>/<name>` and returns the {file.*} placeholder.
    /// Names are sanitized; files are 0600 and the directory 0700.
    pub fn file_ref(&self, name: &str, value: &str) -> Result<String> {
        let _g = self.lock.lock().unwrap();
        let name = sanitize(name);
        create_private_dir(&self.dir)?;
        let p = self.dir.join(&name);
        let cur = std::fs::read(&p).ok();
        if cur.as_deref() != Some(value.as_bytes()) {
            let tmp = self.dir.join(format!("{name}.tmp"));
            write_private(&tmp, value.as_bytes())?;
            std::fs::rename(&tmp, &p)?;
        }
        Ok(format!("{{file.{}}}", to_slash(&p)))
    }

    /// Deletes files in dir not in keep (by sanitized name).
    pub fn prune(&self, keep: &[String]) -> Result<()> {
        let _g = self.lock.lock().unwrap();
        let keep: std::collections::HashSet<String> = keep.iter().map(|n| sanitize(n)).collect();
        let ents = match std::fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        for e in ents.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if e.file_type().map(|t| !t.is_dir()).unwrap_or(false) && !keep.contains(&name) {
                let _ = std::fs::remove_file(e.path());
            }
        }
        Ok(())
    }
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// Renders a path with forward slashes (what Caddy expects on every OS).
pub fn to_slash(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

fn sanitize(s: &str) -> String {
    let b: String = s
        .chars()
        .map(|r| {
            if r.is_ascii_alphanumeric() || r == '-' || r == '_' || r == '.' {
                r
            } else {
                '_'
            }
        })
        .collect();
    let out = b.trim_start_matches('.').to_string();
    if out.is_empty() { "_".to_string() } else { out }
}

#[allow(dead_code)]
/// Replaces any of the given secret values in s with "***".
pub fn redact(s: &str, values: &[&str]) -> String {
    let mut vs: Vec<&str> = values.to_vec();
    vs.sort_by_key(|v| std::cmp::Reverse(v.len()));
    let mut s = s.to_string();
    for v in vs {
        if v.len() >= 4 {
            s = s.replace(v, "***");
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let b = SecretBox::new(b"test-key").unwrap();
        let ct = b.seal(b"hello").unwrap();
        assert_eq!(b.open(&ct).unwrap(), b"hello");
        assert!(b.open(&ct[..5]).is_err());
        let other = SecretBox::new(b"other").unwrap();
        assert!(other.open(&ct).is_err());
    }

    #[test]
    fn refs() {
        assert_eq!(ref_placeholder("env:CF_TOKEN").unwrap(), "{env.CF_TOKEN}");
        assert_eq!(
            ref_placeholder("file:/run/secrets/x").unwrap(),
            "{file./run/secrets/x}"
        );
        assert!(ref_placeholder("env:1bad").is_none());
        assert!(ref_placeholder("plain").is_none());
    }

    #[test]
    fn redact_values() {
        assert_eq!(
            redact("token abcdef and ab", &["abcdef", "ab"]),
            "token *** and ab"
        );
    }
}
