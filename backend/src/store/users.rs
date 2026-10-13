use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::{OptionalExtension, Row, params};
use serde::Serialize;

use super::{NotFound, Store, col_ts, col_ts_opt, ts};

/// A panel account.
#[derive(Debug, Clone, Default, Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    #[serde(skip)]
    pub password_hash: String,
    pub role: String,
    /// decrypted
    #[serde(skip)]
    pub totp_secret: String,
    pub totp_enabled: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub oidc_subject: String,
    pub disabled: bool,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_login: Option<DateTime<Utc>>,
}

const USER_COLS: &str = "id, username, password_hash, role, totp_secret, totp_enabled, COALESCE(oidc_subject, ''), disabled, created_at, last_login";

impl Store {
    fn scan_user(&self, row: &Row) -> rusqlite::Result<User> {
        let totp: Option<Vec<u8>> = row.get(4)?;
        let te: i64 = row.get(5)?;
        let dis: i64 = row.get(7)?;
        let totp_secret = match totp {
            Some(b) if !b.is_empty() => self
                .secret_box()
                .open(&b)
                .ok()
                .and_then(|p| String::from_utf8(p).ok())
                .unwrap_or_default(),
            _ => String::new(),
        };
        Ok(User {
            id: row.get(0)?,
            username: row.get(1)?,
            password_hash: row.get(2)?,
            role: row.get(3)?,
            totp_secret,
            totp_enabled: te == 1,
            oidc_subject: row.get(6)?,
            disabled: dis == 1,
            created_at: col_ts(row, 8)?,
            last_login: col_ts_opt(row, 9)?,
        })
    }

    /// The number of users.
    pub fn user_count(&self) -> i64 {
        self.conn()
            .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
            .unwrap_or(0)
    }

    /// Lists users.
    pub fn users(&self) -> Result<Vec<User>> {
        let conn = self.conn();
        let mut st = conn.prepare(&format!("SELECT {USER_COLS} FROM users ORDER BY username"))?;
        let rows = st.query_map([], |r| self.scan_user(r))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    fn user_where(&self, cond: &str, arg: &dyn rusqlite::ToSql) -> Result<User> {
        self.conn()
            .query_row(
                &format!("SELECT {USER_COLS} FROM users WHERE {cond}"),
                [arg],
                |r| self.scan_user(r),
            )
            .optional()?
            .ok_or_else(|| NotFound.into())
    }

    /// A user by ID.
    pub fn user_by_id(&self, id: i64) -> Result<User> {
        self.user_where("id = ?", &id)
    }

    /// A user by username (case-insensitive).
    pub fn user_by_name(&self, name: &str) -> Result<User> {
        self.user_where("username = ?", &name.trim())
    }

    #[allow(dead_code)]
    /// A user by OIDC subject.
    pub fn user_by_oidc(&self, sub: &str) -> Result<User> {
        self.user_where("oidc_subject = ?", &sub)
    }

    /// Inserts or updates a user (TOTP secret is encrypted).
    pub fn save_user(&self, mut u: User) -> Result<User> {
        let totp: Option<Vec<u8>> = if u.totp_secret.is_empty() {
            None
        } else {
            Some(self.secret_box().seal(u.totp_secret.as_bytes())?)
        };
        let oidc: Option<String> = if u.oidc_subject.is_empty() {
            None
        } else {
            Some(u.oidc_subject.clone())
        };
        let username = u.username.trim().to_string();
        let conn = self.conn();
        if u.id == 0 {
            conn.execute(
                "INSERT INTO users(username, password_hash, role, totp_secret, totp_enabled, oidc_subject, disabled) VALUES(?,?,?,?,?,?,?)",
                params![username, u.password_hash, u.role, totp, u.totp_enabled as i64, oidc, u.disabled as i64],
            )?;
            u.id = conn.last_insert_rowid();
            u.created_at = Utc::now();
            return Ok(u);
        }
        conn.execute(
            "UPDATE users SET username=?, password_hash=?, role=?, totp_secret=?, totp_enabled=?, oidc_subject=?, disabled=? WHERE id=?",
            params![username, u.password_hash, u.role, totp, u.totp_enabled as i64, oidc, u.disabled as i64, u.id],
        )?;
        Ok(u)
    }

    /// Removes a user.
    pub fn delete_user(&self, id: i64) -> Result<()> {
        self.conn()
            .execute("DELETE FROM users WHERE id = ?", params![id])?;
        Ok(())
    }

    /// Counts enabled admins.
    pub fn admin_count(&self) -> i64 {
        self.conn()
            .query_row(
                "SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0)
    }

    /// Sets last_login.
    pub fn touch_login(&self, id: i64) {
        let _ = self.conn().execute(
            "UPDATE users SET last_login = ? WHERE id = ?",
            params![ts(&Utc::now()), id],
        );
    }

    // ---------------------------------------------------------------- sessions

    /// Stores a session.
    pub fn create_session(&self, se: &Session) -> Result<()> {
        self.conn().execute(
            "INSERT INTO sessions(id, user_id, csrf, created_at, expires_at, last_seen, ip, user_agent, pending_2fa) VALUES(?,?,?,?,?,?,?,?,?)",
            params![se.id, se.user_id, se.csrf, ts(&se.created_at), ts(&se.expires_at), ts(&se.last_seen), se.ip, se.user_agent, se.pending_2fa as i64],
        )?;
        Ok(())
    }

    /// A session by ID hash.
    pub fn get_session(&self, id: &str) -> Result<Session> {
        self.conn()
            .query_row(
                "SELECT id, user_id, csrf, created_at, expires_at, last_seen, COALESCE(ip,''), COALESCE(user_agent,''), pending_2fa FROM sessions WHERE id = ?",
                params![id],
                |r| {
                    let p: i64 = r.get(8)?;
                    Ok(Session {
                        id: r.get(0)?,
                        user_id: r.get(1)?,
                        csrf: r.get(2)?,
                        created_at: col_ts(r, 3)?,
                        expires_at: col_ts(r, 4)?,
                        last_seen: col_ts(r, 5)?,
                        ip: r.get(6)?,
                        user_agent: r.get(7)?,
                        pending_2fa: p == 1,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| NotFound.into())
    }

    /// Updates last_seen.
    pub fn touch_session(&self, id: &str, t: DateTime<Utc>) {
        let _ = self.conn().execute(
            "UPDATE sessions SET last_seen = ? WHERE id = ?",
            params![ts(&t), id],
        );
    }

    /// Clears the pending flag.
    pub fn complete_session_2fa(&self, id: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE sessions SET pending_2fa = 0 WHERE id = ?",
            params![id],
        )?;
        Ok(())
    }

    /// Removes a session.
    pub fn delete_session(&self, id: &str) {
        let _ = self
            .conn()
            .execute("DELETE FROM sessions WHERE id = ?", params![id]);
    }

    /// Removes all sessions of a user (e.g. password change), including the
    /// user's sign-ins to protected sites.
    pub fn delete_user_sessions(&self, uid: i64, except: &str) {
        let conn = self.conn();
        let _ = conn.execute(
            "DELETE FROM sessions WHERE user_id = ? AND id != ?",
            params![uid, except],
        );
        let _ = conn.execute("DELETE FROM sso_sessions WHERE user_id = ?", params![uid]);
    }

    /// Deletes expired sessions.
    pub fn prune_sessions(&self) {
        let now = ts(&Utc::now());
        let conn = self.conn();
        let _ = conn.execute("DELETE FROM sessions WHERE expires_at < ?", params![now]);
        let _ = conn.execute(
            "DELETE FROM sso_sessions WHERE expires_at < ?",
            params![now],
        );
    }

    // ---------------------------------------------------------------- site sign-ins

    /// Stores a sign-in to protected sites.
    pub fn create_sso_session(&self, se: &SsoSession) -> Result<()> {
        self.conn().execute(
            "INSERT INTO sso_sessions(id, user_id, created_at, expires_at, last_seen, ip, user_agent, mfa) VALUES(?,?,?,?,?,?,?,?)",
            params![se.id, se.user_id, ts(&se.created_at), ts(&se.expires_at), ts(&se.last_seen), se.ip, se.user_agent, se.mfa as i64],
        )?;
        Ok(())
    }

    /// A sign-in by ID hash.
    pub fn get_sso_session(&self, id: &str) -> Result<SsoSession> {
        self.conn()
            .query_row(
                "SELECT id, user_id, created_at, expires_at, last_seen, ip, user_agent, mfa FROM sso_sessions WHERE id = ?",
                params![id],
                |r| {
                    let mfa: i64 = r.get(7)?;
                    Ok(SsoSession {
                        id: r.get(0)?,
                        user_id: r.get(1)?,
                        created_at: col_ts(r, 2)?,
                        expires_at: col_ts(r, 3)?,
                        last_seen: col_ts(r, 4)?,
                        ip: r.get(5)?,
                        user_agent: r.get(6)?,
                        mfa: mfa == 1,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| NotFound.into())
    }

    /// Updates last_seen of a sign-in.
    pub fn touch_sso_session(&self, id: &str, t: DateTime<Utc>) {
        let _ = self.conn().execute(
            "UPDATE sso_sessions SET last_seen = ? WHERE id = ?",
            params![ts(&t), id],
        );
    }

    /// Ends one sign-in.
    pub fn delete_sso_session(&self, id: &str) {
        let _ = self
            .conn()
            .execute("DELETE FROM sso_sessions WHERE id = ?", params![id]);
    }

    /// Ends every sign-in (all users). Returns how many there were.
    pub fn delete_all_sso_sessions(&self) -> usize {
        self.conn()
            .execute("DELETE FROM sso_sessions", [])
            .unwrap_or(0)
    }

    /// Active sign-ins (newest first) with their usernames.
    pub fn sso_sessions(&self) -> Result<Vec<(SsoSession, String)>> {
        let conn = self.conn();
        let mut st = conn.prepare(
            "SELECT s.id, s.user_id, s.created_at, s.expires_at, s.last_seen, s.ip, s.user_agent, s.mfa, u.username \
             FROM sso_sessions s JOIN users u ON u.id = s.user_id WHERE s.expires_at >= ? ORDER BY s.last_seen DESC LIMIT 200",
        )?;
        let rows = st.query_map(params![ts(&Utc::now())], |r| {
            let mfa: i64 = r.get(7)?;
            Ok((
                SsoSession {
                    id: r.get(0)?,
                    user_id: r.get(1)?,
                    created_at: col_ts(r, 2)?,
                    expires_at: col_ts(r, 3)?,
                    last_seen: col_ts(r, 4)?,
                    ip: r.get(5)?,
                    user_agent: r.get(6)?,
                    mfa: mfa == 1,
                },
                r.get::<_, String>(8)?,
            ))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    // ---------------------------------------------------------------- API keys

    /// Stores a key.
    pub fn create_api_key(&self, mut k: ApiKey) -> Result<ApiKey> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO api_keys(name, prefix, hash, role, user_id, expires_at) VALUES(?,?,?,?,?,?)",
            params![k.name, k.prefix, k.hash, k.role, k.user_id, k.expires_at.map(|t| ts(&t))],
        )?;
        k.id = conn.last_insert_rowid();
        k.created_at = Utc::now();
        Ok(k)
    }

    fn scan_key(row: &Row) -> rusqlite::Result<ApiKey> {
        let uid: Option<i64> = row.get(5)?;
        Ok(ApiKey {
            id: row.get(0)?,
            name: row.get(1)?,
            prefix: row.get(2)?,
            hash: row.get(3)?,
            role: row.get(4)?,
            user_id: uid.unwrap_or(0),
            created_at: col_ts(row, 6)?,
            last_used: col_ts_opt(row, 7)?,
            expires_at: col_ts_opt(row, 8)?,
        })
    }

    /// Lists keys.
    pub fn api_keys(&self) -> Result<Vec<ApiKey>> {
        let conn = self.conn();
        let mut st = conn.prepare("SELECT id, name, prefix, hash, role, user_id, created_at, last_used, expires_at FROM api_keys ORDER BY id")?;
        let rows = st.query_map([], Self::scan_key)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Finds a key by token hash.
    pub fn api_key_by_hash(&self, h: &str) -> Result<ApiKey> {
        self.conn()
            .query_row(
                "SELECT id, name, prefix, hash, role, user_id, created_at, last_used, expires_at FROM api_keys WHERE hash = ?",
                params![h],
                Self::scan_key,
            )
            .optional()?
            .ok_or_else(|| NotFound.into())
    }

    /// Updates last_used.
    pub fn touch_api_key(&self, id: i64) {
        let _ = self.conn().execute(
            "UPDATE api_keys SET last_used = ? WHERE id = ?",
            params![ts(&Utc::now()), id],
        );
    }

    /// Removes a key.
    pub fn delete_api_key(&self, id: i64) -> Result<()> {
        self.conn()
            .execute("DELETE FROM api_keys WHERE id = ?", params![id])?;
        Ok(())
    }
}

/// A login session. ID is the SHA-256 of the cookie token.
#[derive(Debug, Clone, Default)]
pub struct Session {
    pub id: String,
    pub user_id: i64,
    pub csrf: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub ip: String,
    pub user_agent: String,
    pub pending_2fa: bool,
}

/// A sign-in to sites behind the login wall. ID is the SHA-256 of the
/// cookie token.
#[derive(Debug, Clone, Default)]
pub struct SsoSession {
    pub id: String,
    pub user_id: i64,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub ip: String,
    pub user_agent: String,
    /// Signed in with a two-factor code.
    pub mfa: bool,
}

/// A scripted-access key. Only its hash is stored.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ApiKey {
    pub id: i64,
    pub name: String,
    pub prefix: String,
    #[serde(skip)]
    pub hash: String,
    pub role: String,
    pub user_id: i64,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::super::test_store;
    use super::*;

    #[test]
    fn users_sessions_keys() {
        let s = test_store();
        let u = s
            .save_user(User {
                username: " Admin ".into(),
                password_hash: "h".into(),
                role: "admin".into(),
                totp_secret: "SECRET".into(),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(s.user_count(), 1);
        let got = s.user_by_name("admin").unwrap();
        assert_eq!(got.username, "Admin");
        assert_eq!(got.totp_secret, "SECRET");
        assert_eq!(s.admin_count(), 1);
        let se = Session {
            id: "sid".into(),
            user_id: u.id,
            csrf: "c".into(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            last_seen: Utc::now(),
            ..Default::default()
        };
        s.create_session(&se).unwrap();
        assert_eq!(s.get_session("sid").unwrap().user_id, u.id);
        s.prune_sessions();
        assert!(s.get_session("sid").is_ok());
        s.delete_user_sessions(u.id, "");
        assert!(s.get_session("sid").is_err());
        let k = s
            .create_api_key(ApiKey {
                name: "k".into(),
                prefix: "chk_".into(),
                hash: "hash".into(),
                role: "viewer".into(),
                user_id: u.id,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(s.api_key_by_hash("hash").unwrap().id, k.id);
        assert_eq!(s.api_keys().unwrap().len(), 1);
    }
}
