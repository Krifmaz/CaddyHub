//! Password hashing (argon2id), TOTP (RFC 6238), random tokens and role
//! checks.

use anyhow::{Result, anyhow};
use argon2::password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use data_encoding::{BASE32_NOPAD, HEXLOWER};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;
use subtle::ConstantTimeEq;

use crate::secrets::random_bytes;

// Roles, in increasing privilege.
pub const ROLE_VIEWER: &str = "viewer";
pub const ROLE_EDITOR: &str = "editor";
pub const ROLE_ADMIN: &str = "admin";

fn role_rank(r: &str) -> u8 {
    match r {
        ROLE_VIEWER => 1,
        ROLE_EDITOR => 2,
        ROLE_ADMIN => 3,
        _ => 0,
    }
}

/// Reports whether r is a known role.
pub fn valid_role(r: &str) -> bool {
    role_rank(r) > 0
}

/// Reports whether role has at least the privileges of need.
pub fn allows(role: &str, need: &str) -> bool {
    role_rank(role) >= role_rank(need) && role_rank(role) > 0
}

// argon2id parameters (OWASP recommended minimums, tuned for small hosts).
const ARGON_TIME: u32 = 3;
const ARGON_MEMORY: u32 = 64 * 1024;
const ARGON_THREADS: u32 = 2;
const ARGON_KEY_LEN: usize = 32;

fn argon() -> Argon2<'static> {
    let params = Params::new(ARGON_MEMORY, ARGON_TIME, ARGON_THREADS, Some(ARGON_KEY_LEN))
        .expect("argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Returns a PHC-formatted argon2id hash.
pub fn hash_password(pw: &str) -> Result<String> {
    let mut salt = [0u8; 16];
    random_bytes(&mut salt);
    let h = argon()
        .hash_password_with_salt(pw.as_bytes(), &salt)
        .map_err(|e| anyhow!("{e}"))?;
    Ok(h.to_string())
}

/// Checks pw against a PHC argon2id hash in constant time.
pub fn verify_password(hash: &str, pw: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    if parsed.algorithm.as_str() != "argon2id" {
        return false;
    }
    Argon2::default()
        .verify_password(pw.as_bytes(), &parsed)
        .is_ok()
}

static DUMMY_HASH: LazyLock<String> =
    LazyLock::new(|| hash_password("caddyhub-timing-equalizer").unwrap());

/// Burns the same time as a real verification (for unknown users).
pub fn verify_dummy(pw: &str) {
    let _ = verify_password(&DUMMY_HASH, pw);
}

/// Returns an error if pw is too weak.
pub fn password_policy(pw: &str) -> Result<(), String> {
    if pw.len() < 10 {
        return Err("password must be at least 10 characters".into());
    }
    if pw.len() > 1024 {
        return Err("password too long".into());
    }
    Ok(())
}

/// Hashes a password for Caddy's basic_auth (which uses bcrypt).
pub fn bcrypt_hash(pw: &str) -> Result<String> {
    Ok(bcrypt::hash(pw, 14)?)
}

/// Returns n random bytes, URL-safe base64 encoded (no padding).
pub fn random_token(n: usize) -> String {
    let mut b = vec![0u8; n];
    random_bytes(&mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// The SHA-256 hex digest used to store tokens.
pub fn token_hash(tok: &str) -> String {
    HEXLOWER.encode(&Sha256::digest(tok.as_bytes()))
}

// ---------------------------------------------------------------- TOTP

/// A random base32 secret (160 bits).
pub fn new_totp_secret() -> String {
    let mut b = [0u8; 20];
    random_bytes(&mut b);
    BASE32_NOPAD.encode(&b)
}

/// An otpauth:// URI for authenticator apps.
pub fn totp_uri(issuer: &str, account: &str, secret: &str) -> String {
    let label = url::form_urlencoded::byte_serialize(format!("{issuer}:{account}").as_bytes())
        .collect::<String>()
        .replace('+', "%20");
    let mut q = url::form_urlencoded::Serializer::new(String::new());
    q.append_pair("algorithm", "SHA1");
    q.append_pair("digits", "6");
    q.append_pair("issuer", issuer);
    q.append_pair("period", "30");
    q.append_pair("secret", secret);
    format!("otpauth://totp/{label}?{}", q.finish())
}

fn totp_at(secret: &str, counter: u64) -> Result<String> {
    let norm = secret.trim_end_matches('=').to_ascii_uppercase();
    let key = BASE32_NOPAD
        .decode(norm.as_bytes())
        .map_err(|e| anyhow!("bad TOTP secret: {e}"))?;
    let mut mac = <Hmac<Sha1>>::new_from_slice(&key).map_err(|e| anyhow!("{e}"))?;
    mac.update(&counter.to_be_bytes());
    let sum = mac.finalize().into_bytes();
    let off = (sum[sum.len() - 1] & 0x0f) as usize;
    let code = (u32::from_be_bytes([sum[off], sum[off + 1], sum[off + 2], sum[off + 3]])
        & 0x7fff_ffff)
        % 1_000_000;
    Ok(format!("{code:06}"))
}

/// The code for unix time t (for tests).
#[allow(dead_code)]
pub fn totp_code(secret: &str, t: i64) -> String {
    totp_at(secret, (t / 30) as u64).unwrap_or_default()
}

/// Checks a code allowing ±1 step of clock drift. Returns the matched
/// counter so callers can reject replays.
pub fn verify_totp(secret: &str, code: &str, t: i64) -> Option<u64> {
    let code = code.trim().replace(' ', "");
    if code.len() != 6 {
        return None;
    }
    let now = t / 30;
    for d in [0i64, -1, 1] {
        let c = (now + d) as u64;
        let want = totp_at(secret, c).ok()?;
        if want.as_bytes().ct_eq(code.as_bytes()).into() {
            return Some(c);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash() {
        let h = hash_password("correct horse battery staple").unwrap();
        assert!(h.starts_with("$argon2id$v=19$"), "{h}");
        assert!(verify_password(&h, "correct horse battery staple"));
        assert!(!verify_password(&h, "wrong"));
        let h2 = hash_password("correct horse battery staple").unwrap();
        assert_ne!(h, h2, "salt not random");
    }

    #[test]
    fn totp_rfc6238() {
        // RFC 6238 test vector (SHA1): secret "12345678901234567890", T=59 -> 94287082 -> last 6: 287082
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert_eq!(totp_code(secret, 59), "287082");
        assert_eq!(totp_code(secret, 1111111109), "081804");
        let now = 1111111109;
        assert!(
            verify_totp(secret, "081804", now + 25).is_some(),
            "drift +1 step should be accepted"
        );
        assert!(
            verify_totp(secret, "081804", now + 300).is_none(),
            "old code should be rejected"
        );
    }

    #[test]
    fn roles() {
        assert!(allows(ROLE_ADMIN, ROLE_EDITOR));
        assert!(!allows(ROLE_VIEWER, ROLE_EDITOR));
        assert!(!allows("bogus", ROLE_VIEWER));
    }

    #[test]
    fn uri() {
        let u = totp_uri("CaddyHub", "alice", "ABC");
        assert!(u.starts_with("otpauth://totp/CaddyHub%3Aalice?"));
        assert!(u.contains("secret=ABC"));
    }
}
