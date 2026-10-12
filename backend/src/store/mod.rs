//! The SQLite-backed source of truth for CaddyHub.

mod migrations;
mod misc;
mod users;

pub use misc::Channel;
#[allow(unused_imports)]
pub use misc::{Build, Discovered, Template};
pub use users::{ApiKey, Session, User};

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, NaiveDateTime, Utc};
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::model::*;
use crate::secrets::SecretBox;

/// Returned when a row doesn't exist.
#[derive(Debug, thiserror::Error)]
#[error("not found")]
pub struct NotFound;

/// Reports whether an error is a missing row.
pub fn is_not_found(err: &anyhow::Error) -> bool {
    err.downcast_ref::<NotFound>().is_some()
}

/// Wraps the database. One connection, serialized: SQLite has one writer
/// anyway, and this keeps things simple and safe.
pub struct Store {
    conn: Mutex<Connection>,
    secret_box: Arc<SecretBox>,
    /// serializes settings read-modify-write
    settings_lock: Mutex<()>,
}

/// Audit log row.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub ts: DateTime<Utc>,
    pub user: String,
    pub action: String,
    pub target: String,
    pub details: String,
    pub ip: String,
}

// ---------------------------------------------------------------- time helpers

/// Formats a timestamp the way the database stores it (sortable text).
pub fn ts(t: &DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M:%S%.f+00:00").to_string()
}

/// Parses the timestamp formats found in the database: the panel's own
/// format, SQLite's CURRENT_TIMESTAMP, and RFC 3339.
pub fn parse_ts(s: &str) -> DateTime<Utc> {
    let s = s.trim();
    if let Ok(t) = DateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f%:z") {
        return t.with_timezone(&Utc);
    }
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        return t.with_timezone(&Utc);
    }
    if let Ok(t) = DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f%:z") {
        return t.with_timezone(&Utc);
    }
    if let Ok(t) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f") {
        return t.and_utc();
    }
    if let Ok(t) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return t.and_utc();
    }
    DateTime::<Utc>::default()
}

fn col_ts(row: &Row, idx: usize) -> rusqlite::Result<DateTime<Utc>> {
    let s: String = row.get(idx)?;
    Ok(parse_ts(&s))
}

fn col_ts_opt(row: &Row, idx: usize) -> rusqlite::Result<Option<DateTime<Utc>>> {
    let s: Option<String> = row.get(idx)?;
    Ok(s.map(|s| parse_ts(&s)))
}

fn json_str<T: Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "null".into())
}

fn from_json<T: DeserializeOwned + Default>(s: &str) -> T {
    serde_json::from_str(s).unwrap_or_default()
}

/// Deep-merges `over` into `base` (objects recursively; everything else
/// replaced), the way Go's json.Unmarshal fills a pre-populated struct.
pub fn deep_merge(base: &mut serde_json::Value, over: serde_json::Value) {
    match (base, over) {
        (serde_json::Value::Object(b), serde_json::Value::Object(o)) => {
            for (k, v) in o {
                match b.get_mut(&k) {
                    Some(bv) if bv.is_object() && v.is_object() => deep_merge(bv, v),
                    _ => {
                        b.insert(k, v);
                    }
                }
            }
        }
        (b, o) => *b = o,
    }
}

impl Store {
    /// Opens (and migrates) the database at path.
    pub fn open(path: &Path, secret_box: Arc<SecretBox>) -> Result<Store> {
        let conn = Connection::open(path).with_context(|| format!("open {}", path.display()))?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", 1)?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        let s = Store {
            conn: Mutex::new(conn),
            secret_box,
            settings_lock: Mutex::new(()),
        };
        s.migrate()?;
        Ok(s)
    }

    #[allow(dead_code)]
    /// Opens an in-memory database (tests).
    pub fn open_memory(secret_box: Arc<SecretBox>) -> Result<Store> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", 1)?;
        let s = Store {
            conn: Mutex::new(conn),
            secret_box,
            settings_lock: Mutex::new(()),
        };
        s.migrate()?;
        Ok(s)
    }

    pub(crate) fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The encryption box.
    pub fn secret_box(&self) -> &SecretBox {
        &self.secret_box
    }

    /// The current migration version.
    pub fn schema_version(&self) -> i64 {
        self.conn()
            .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
            .unwrap_or(0)
    }

    #[allow(dead_code)]
    /// The number of known migrations.
    pub fn latest_schema_version() -> i64 {
        migrations::MIGRATIONS.len() as i64
    }

    fn migrate(&self) -> Result<()> {
        let mut conn = self.conn();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
            [],
        )?;
        let v: Option<i64> = conn
            .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
            .optional()?;
        let v = match v {
            Some(v) => v,
            None => {
                conn.execute("INSERT INTO schema_version(version) VALUES (0)", [])?;
                0
            }
        };
        let n = migrations::MIGRATIONS.len() as i64;
        if v > n {
            return Err(anyhow!(
                "database schema v{v} is newer than this panel (v{n}); upgrade the panel"
            ));
        }
        for (i, m) in migrations::MIGRATIONS.iter().enumerate().skip(v as usize) {
            let tx = conn.transaction()?;
            tx.execute_batch(m)
                .with_context(|| format!("migration {}", i + 1))?;
            tx.execute(
                "UPDATE schema_version SET version = ?",
                params![(i + 1) as i64],
            )?;
            tx.commit()?;
        }
        Ok(())
    }

    // ---------------------------------------------------------------- settings / kv

    /// Reads a raw settings key.
    pub fn kv_get(&self, key: &str) -> Option<String> {
        self.conn()
            .query_row(
                "SELECT value FROM settings WHERE key = ?",
                params![key],
                |r| r.get(0),
            )
            .ok()
    }

    /// Writes a raw settings key.
    pub fn kv_set(&self, key: &str, value: &str) -> Result<()> {
        self.conn().execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Decodes a JSON settings key.
    pub fn kv_get_json<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        let raw = self.kv_get(key)?;
        serde_json::from_str(&raw).ok()
    }

    /// Stores v as JSON.
    pub fn kv_set_json<T: Serialize>(&self, key: &str, v: &T) -> Result<()> {
        self.kv_set(key, &json_str(v))
    }

    /// Global settings merged over defaults (so new fields get defaults
    /// after an upgrade).
    pub fn settings(&self) -> Settings {
        let mut base = serde_json::to_value(Settings::default()).unwrap_or_default();
        if let Some(stored) = self.kv_get_json::<serde_json::Value>("global") {
            deep_merge(&mut base, stored);
        }
        serde_json::from_value(base).unwrap_or_default()
    }

    /// Persists global settings.
    pub fn save_settings(&self, st: &Settings) -> Result<()> {
        self.kv_set_json("global", st)
    }

    /// Applies f atomically.
    pub fn update_settings(&self, f: impl FnOnce(&mut Settings)) -> Result<Settings> {
        let _g = self.settings_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut st = self.settings();
        f(&mut st);
        self.save_settings(&st)?;
        Ok(st)
    }

    // ---------------------------------------------------------------- named secrets

    /// Stores an encrypted named secret (empty value deletes it).
    pub fn set_secret(&self, name: &str, value: &str) -> Result<()> {
        if value.is_empty() {
            self.conn()
                .execute("DELETE FROM secrets WHERE name = ?", params![name])?;
            return Ok(());
        }
        let enc = self.secret_box.seal(value.as_bytes())?;
        self.conn().execute(
            "INSERT INTO secrets(name, value) VALUES(?, ?) ON CONFLICT(name) DO UPDATE SET value = excluded.value",
            params![name, enc],
        )?;
        Ok(())
    }

    /// A decrypted named secret.
    pub fn secret(&self, name: &str) -> Option<String> {
        let enc: Vec<u8> = self
            .conn()
            .query_row(
                "SELECT value FROM secrets WHERE name = ?",
                params![name],
                |r| r.get(0),
            )
            .ok()?;
        let b = self.secret_box.open(&enc).ok()?;
        String::from_utf8(b).ok()
    }

    #[allow(dead_code)]
    /// Stored secret names.
    pub fn secret_names(&self) -> Vec<String> {
        let conn = self.conn();
        let mut st = match conn.prepare("SELECT name FROM secrets ORDER BY name") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        st.query_map([], |r| r.get(0))
            .map(|it| it.flatten().collect())
            .unwrap_or_default()
    }

    // ---------------------------------------------------------------- sites

    fn scan_site(row: &Row) -> rusqlite::Result<Site> {
        let hosts: String = row.get(2)?;
        let tags: String = row.get(6)?;
        let cfg: String = row.get(7)?;
        let en: i64 = row.get(4)?;
        Ok(Site {
            id: row.get(0)?,
            name: row.get(1)?,
            hosts: from_json(&hosts),
            kind: row.get(3)?,
            enabled: en == 1,
            position: row.get(5)?,
            tags: from_json(&tags),
            config: from_json(&cfg),
            created_at: col_ts(row, 8)?,
            updated_at: col_ts(row, 9)?,
        })
    }

    const SITE_COLS: &'static str =
        "id, name, hosts, kind, enabled, position, tags, config, created_at, updated_at";

    /// All sites ordered by position.
    pub fn sites(&self) -> Result<Vec<Site>> {
        let conn = self.conn();
        let mut st = conn.prepare(&format!(
            "SELECT {} FROM sites ORDER BY position, id",
            Self::SITE_COLS
        ))?;
        let rows = st.query_map([], Self::scan_site)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// One site.
    pub fn site(&self, id: i64) -> Result<Site> {
        self.conn()
            .query_row(
                &format!("SELECT {} FROM sites WHERE id = ?", Self::SITE_COLS),
                params![id],
                Self::scan_site,
            )
            .optional()?
            .ok_or_else(|| NotFound.into())
    }

    /// Inserts a site and returns it with its ID. New sites go last.
    pub fn create_site(&self, mut st: Site) -> Result<Site> {
        let now = Utc::now();
        let conn = self.conn();
        if st.position == 0 {
            st.position = conn
                .query_row(
                    "SELECT COALESCE(MAX(position), 0) + 1 FROM sites",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(1);
        }
        conn.execute(
            "INSERT INTO sites(name, hosts, kind, enabled, position, tags, config, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
            params![st.name, json_str(&st.hosts), st.kind, st.enabled as i64, st.position, json_str(&st.tags), json_str(&st.config), ts(&now), ts(&now)],
        )?;
        st.id = conn.last_insert_rowid();
        st.created_at = now;
        st.updated_at = now;
        Ok(st)
    }

    /// Replaces a site.
    pub fn update_site(&self, st: &Site) -> Result<()> {
        let n = self.conn().execute(
            "UPDATE sites SET name=?, hosts=?, kind=?, enabled=?, position=?, tags=?, config=?, updated_at=? WHERE id=?",
            params![st.name, json_str(&st.hosts), st.kind, st.enabled as i64, st.position, json_str(&st.tags), json_str(&st.config), ts(&Utc::now()), st.id],
        )?;
        if n == 0 {
            return Err(NotFound.into());
        }
        Ok(())
    }

    /// Removes a site.
    pub fn delete_site(&self, id: i64) -> Result<()> {
        let n = self
            .conn()
            .execute("DELETE FROM sites WHERE id = ?", params![id])?;
        if n == 0 {
            return Err(NotFound.into());
        }
        Ok(())
    }

    /// Sets positions according to the given ID order.
    pub fn reorder_sites(&self, ids: &[i64]) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        for (i, id) in ids.iter().enumerate() {
            tx.execute(
                "UPDATE sites SET position = ? WHERE id = ?",
                params![(i + 1) as i64, id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Bulk enables/disables.
    pub fn set_sites_enabled(&self, ids: &[i64], enabled: bool) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let now = ts(&Utc::now());
        for id in ids {
            tx.execute(
                "UPDATE sites SET enabled = ?, updated_at = ? WHERE id = ?",
                params![enabled as i64, now, id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    // ---------------------------------------------------------------- domains

    fn scan_domain(row: &Row) -> rusqlite::Result<Domain> {
        #[derive(Default, serde::Deserialize)]
        #[serde(default)]
        struct Extra {
            propagation_delay: String,
            propagation_timeout: String,
            resolvers: Vec<String>,
        }
        let cfg: String = row.get(5)?;
        let ex: Extra = from_json(&cfg);
        let wc: i64 = row.get(4)?;
        Ok(Domain {
            id: row.get(0)?,
            name: row.get(1)?,
            challenge: row.get(2)?,
            credential_id: row.get(3)?,
            wildcard: wc == 1,
            propagation_delay: ex.propagation_delay,
            propagation_timeout: ex.propagation_timeout,
            resolvers: ex.resolvers,
            created_at: col_ts(row, 6)?,
        })
    }

    const DOMAIN_COLS: &'static str =
        "id, name, challenge, credential_id, wildcard, config, created_at";

    /// All domains.
    pub fn domains(&self) -> Result<Vec<Domain>> {
        let conn = self.conn();
        let mut st = conn.prepare(&format!(
            "SELECT {} FROM domains ORDER BY name",
            Self::DOMAIN_COLS
        ))?;
        let rows = st.query_map([], Self::scan_domain)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    #[allow(dead_code)]
    /// One domain.
    pub fn domain(&self, id: i64) -> Result<Domain> {
        self.conn()
            .query_row(
                &format!("SELECT {} FROM domains WHERE id = ?", Self::DOMAIN_COLS),
                params![id],
                Self::scan_domain,
            )
            .optional()?
            .ok_or_else(|| NotFound.into())
    }

    /// Inserts or updates a domain.
    pub fn save_domain(&self, mut d: Domain) -> Result<Domain> {
        d.name = d.name.trim().to_ascii_lowercase();
        let ex = serde_json::json!({
            "propagation_delay": d.propagation_delay,
            "propagation_timeout": d.propagation_timeout,
            "resolvers": d.resolvers,
        });
        let ex = json_str(&ex);
        let conn = self.conn();
        if d.id == 0 {
            conn.execute(
                "INSERT INTO domains(name, challenge, credential_id, wildcard, config) VALUES(?,?,?,?,?)",
                params![d.name, d.challenge, d.credential_id, d.wildcard as i64, ex],
            )?;
            d.id = conn.last_insert_rowid();
            d.created_at = Utc::now();
            return Ok(d);
        }
        let n = conn.execute(
            "UPDATE domains SET name=?, challenge=?, credential_id=?, wildcard=?, config=? WHERE id=?",
            params![d.name, d.challenge, d.credential_id, d.wildcard as i64, ex, d.id],
        )?;
        if n == 0 {
            return Err(NotFound.into());
        }
        Ok(d)
    }

    /// Removes a domain.
    pub fn delete_domain(&self, id: i64) -> Result<()> {
        self.conn()
            .execute("DELETE FROM domains WHERE id = ?", params![id])?;
        Ok(())
    }

    // ---------------------------------------------------------------- DNS credentials

    fn scan_cred(&self, row: &Row) -> rusqlite::Result<DnsCredential> {
        let enc: Vec<u8> = row.get(3)?;
        let id: i64 = row.get(0)?;
        let plain = self.secret_box.open(&enc).map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(
                format!("decrypt credential {id} (wrong CADDYHUB_SECRET_KEY?): {e}").into(),
            )
        })?;
        let fields: BTreeMap<String, String> = serde_json::from_slice(&plain).unwrap_or_default();
        Ok(DnsCredential {
            id,
            name: row.get(1)?,
            provider: row.get(2)?,
            fields,
            created_at: col_ts(row, 4)?,
        })
    }

    /// Credentials with decrypted fields.
    pub fn credentials(&self) -> Result<Vec<DnsCredential>> {
        let conn = self.conn();
        let mut st = conn.prepare(
            "SELECT id, name, provider, fields, created_at FROM dns_credentials ORDER BY name",
        )?;
        let rows = st.query_map([], |r| self.scan_cred(r))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// One credential.
    pub fn credential(&self, id: i64) -> Result<DnsCredential> {
        self.conn()
            .query_row(
                "SELECT id, name, provider, fields, created_at FROM dns_credentials WHERE id = ?",
                params![id],
                |r| self.scan_cred(r),
            )
            .optional()?
            .ok_or_else(|| NotFound.into())
    }

    /// Inserts or updates a credential, encrypting fields.
    pub fn save_credential(&self, mut c: DnsCredential) -> Result<DnsCredential> {
        let enc = self.secret_box.seal(json_str(&c.fields).as_bytes())?;
        let conn = self.conn();
        if c.id == 0 {
            conn.execute(
                "INSERT INTO dns_credentials(name, provider, fields) VALUES(?,?,?)",
                params![c.name, c.provider, enc],
            )?;
            c.id = conn.last_insert_rowid();
            c.created_at = Utc::now();
            return Ok(c);
        }
        let n = conn.execute(
            "UPDATE dns_credentials SET name=?, provider=?, fields=? WHERE id=?",
            params![c.name, c.provider, enc, c.id],
        )?;
        if n == 0 {
            return Err(NotFound.into());
        }
        Ok(c)
    }

    /// Removes a credential (domains using it are unset).
    pub fn delete_credential(&self, id: i64) -> Result<()> {
        self.conn()
            .execute("DELETE FROM dns_credentials WHERE id = ?", params![id])?;
        Ok(())
    }

    // ---------------------------------------------------------------- snippets

    /// All snippets.
    pub fn snippets(&self) -> Result<Vec<Snippet>> {
        let conn = self.conn();
        let mut st =
            conn.prepare("SELECT id, name, description, body FROM snippets ORDER BY name")?;
        let rows = st.query_map([], |r| {
            Ok(Snippet {
                id: r.get(0)?,
                name: r.get(1)?,
                description: r.get(2)?,
                body: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Inserts or updates.
    pub fn save_snippet(&self, mut sn: Snippet) -> Result<Snippet> {
        let conn = self.conn();
        if sn.id == 0 {
            conn.execute(
                "INSERT INTO snippets(name, description, body) VALUES(?,?,?)",
                params![sn.name, sn.description, sn.body],
            )?;
            sn.id = conn.last_insert_rowid();
            return Ok(sn);
        }
        let n = conn.execute(
            "UPDATE snippets SET name=?, description=?, body=? WHERE id=?",
            params![sn.name, sn.description, sn.body, sn.id],
        )?;
        if n == 0 {
            return Err(NotFound.into());
        }
        Ok(sn)
    }

    /// Removes a snippet.
    pub fn delete_snippet(&self, id: i64) -> Result<()> {
        self.conn()
            .execute("DELETE FROM snippets WHERE id = ?", params![id])?;
        Ok(())
    }

    // ---------------------------------------------------------------- raw blocks

    /// All raw blocks.
    pub fn raw_blocks(&self) -> Result<Vec<RawBlock>> {
        let conn = self.conn();
        let mut st = conn.prepare("SELECT id, name, body, enabled, position, source FROM raw_blocks ORDER BY position, id")?;
        let rows = st.query_map([], |r| {
            let en: i64 = r.get(3)?;
            Ok(RawBlock {
                id: r.get(0)?,
                name: r.get(1)?,
                body: r.get(2)?,
                enabled: en == 1,
                position: r.get(4)?,
                source: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Inserts or updates.
    pub fn save_raw_block(&self, mut b: RawBlock) -> Result<RawBlock> {
        if b.source.is_empty() {
            b.source = "user".into();
        }
        let conn = self.conn();
        if b.id == 0 {
            conn.execute(
                "INSERT INTO raw_blocks(name, body, enabled, position, source) VALUES(?,?,?,?,?)",
                params![b.name, b.body, b.enabled as i64, b.position, b.source],
            )?;
            b.id = conn.last_insert_rowid();
            return Ok(b);
        }
        let n = conn.execute(
            "UPDATE raw_blocks SET name=?, body=?, enabled=?, position=?, source=? WHERE id=?",
            params![b.name, b.body, b.enabled as i64, b.position, b.source, b.id],
        )?;
        if n == 0 {
            return Err(NotFound.into());
        }
        Ok(b)
    }

    /// Removes a raw block.
    pub fn delete_raw_block(&self, id: i64) -> Result<()> {
        self.conn()
            .execute("DELETE FROM raw_blocks WHERE id = ?", params![id])?;
        Ok(())
    }

    // ---------------------------------------------------------------- versions

    /// Records a config snapshot.
    pub fn add_version(&self, mut v: ConfigVersion) -> Result<ConfigVersion> {
        if v.created_at == DateTime::<Utc>::default() {
            v.created_at = Utc::now();
        }
        let conn = self.conn();
        conn.execute(
            "INSERT INTO config_versions(created_at, user, caddyfile, status, message, good, caddy_version, model) VALUES(?,?,?,?,?,?,?,?)",
            params![ts(&v.created_at), v.user, v.caddyfile, v.status, v.message, v.good as i64, v.caddy_version, v.model],
        )?;
        v.id = conn.last_insert_rowid();
        Ok(v)
    }

    #[allow(dead_code)]
    /// Updates status/message/good.
    pub fn update_version_status(
        &self,
        id: i64,
        status: &str,
        msg: &str,
        good: bool,
    ) -> Result<()> {
        self.conn().execute(
            "UPDATE config_versions SET status=?, message=?, good=? WHERE id=?",
            params![status, msg, good as i64, id],
        )?;
        Ok(())
    }

    fn scan_version(row: &Row, with_body: bool) -> rusqlite::Result<ConfigVersion> {
        let mut i = 0;
        let mut next = || {
            let c = i;
            i += 1;
            c
        };
        let id = row.get(next())?;
        let created_at = col_ts(row, next())?;
        let user = row.get(next())?;
        let caddyfile = if with_body {
            row.get(next())?
        } else {
            String::new()
        };
        let status = row.get(next())?;
        let message = row.get(next())?;
        let good: i64 = row.get(next())?;
        let caddy_version = row.get(next())?;
        let model = if with_body {
            row.get(next())?
        } else {
            String::new()
        };
        let snapshot: i64 = row.get(next())?;
        Ok(ConfigVersion {
            id,
            created_at,
            user,
            caddyfile,
            status,
            message,
            good: good == 1,
            caddy_version,
            model,
            snapshot: snapshot == 1,
        })
    }

    /// Versions (newest first) without bodies.
    pub fn versions(&self, limit: i64) -> Result<Vec<ConfigVersion>> {
        let limit = if limit <= 0 { 100 } else { limit };
        let conn = self.conn();
        let mut st = conn.prepare("SELECT id, created_at, user, status, message, good, caddy_version, (model <> '') FROM config_versions ORDER BY id DESC LIMIT ?")?;
        let rows = st.query_map(params![limit], |r| Self::scan_version(r, false))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// A version with its Caddyfile.
    pub fn version(&self, id: i64) -> Result<ConfigVersion> {
        self.conn()
            .query_row(
                "SELECT id, created_at, user, caddyfile, status, message, good, caddy_version, model, (model <> '') FROM config_versions WHERE id = ?",
                params![id],
                |r| Self::scan_version(r, true),
            )
            .optional()?
            .ok_or_else(|| NotFound.into())
    }

    /// The most recent successfully applied version.
    pub fn last_good(&self) -> Result<ConfigVersion> {
        let id: Option<i64> = self
            .conn()
            .query_row(
                "SELECT id FROM config_versions WHERE good = 1 ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        match id {
            Some(id) => self.version(id),
            None => Err(NotFound.into()),
        }
    }

    /// The most recent version of any status.
    pub fn last_version(&self) -> Result<ConfigVersion> {
        let id: Option<i64> = self
            .conn()
            .query_row(
                "SELECT id FROM config_versions ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        match id {
            Some(id) => self.version(id),
            None => Err(NotFound.into()),
        }
    }

    /// Keeps the newest n versions (the latest good one is always kept).
    pub fn prune_versions(&self, keep: i64) -> Result<()> {
        if keep <= 0 {
            return Ok(());
        }
        self.conn().execute(
            "DELETE FROM config_versions WHERE id NOT IN (SELECT id FROM config_versions ORDER BY id DESC LIMIT ?) \
             AND id != COALESCE((SELECT id FROM config_versions WHERE good = 1 ORDER BY id DESC LIMIT 1), -1)",
            params![keep],
        )?;
        Ok(())
    }

    // ---------------------------------------------------------------- audit

    /// Records an action. Details must never contain secrets.
    pub fn audit(&self, user: &str, action: &str, target: &str, details: &str, ip: &str) {
        let _ = self.conn().execute(
            "INSERT INTO audit_log(ts, user, action, target, details, ip) VALUES(?,?,?,?,?,?)",
            params![ts(&Utc::now()), user, action, target, details, ip],
        );
    }

    /// Entries newest first, optionally filtered.
    pub fn audit_log(&self, q: &str, limit: i64, offset: i64) -> Result<Vec<AuditEntry>> {
        let limit = if limit <= 0 || limit > 1000 {
            200
        } else {
            limit
        };
        let conn = self.conn();
        let mut query =
            String::from("SELECT id, ts, user, action, target, details, ip FROM audit_log");
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if !q.is_empty() {
            query
                .push_str(" WHERE user LIKE ? OR action LIKE ? OR target LIKE ? OR details LIKE ?");
            let like = format!("%{q}%");
            for _ in 0..4 {
                args.push(Box::new(like.clone()));
            }
        }
        query.push_str(" ORDER BY id DESC LIMIT ? OFFSET ?");
        args.push(Box::new(limit));
        args.push(Box::new(offset));
        let mut st = conn.prepare(&query)?;
        let rows = st.query_map(
            rusqlite::params_from_iter(args.iter().map(|a| a.as_ref())),
            |r| {
                Ok(AuditEntry {
                    id: r.get(0)?,
                    ts: col_ts(r, 1)?,
                    user: r.get(2)?,
                    action: r.get(3)?,
                    target: r.get(4)?,
                    details: r.get(5)?,
                    ip: r.get(6)?,
                })
            },
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    // ---------------------------------------------------------------- alert dedupe

    #[allow(dead_code)]
    /// Reports whether key was NOT sent within window, marking it if so.
    pub fn alert_once(&self, key: &str, window: chrono::Duration) -> bool {
        let conn = self.conn();
        let sent: Option<String> = conn
            .query_row(
                "SELECT sent_at FROM alert_state WHERE key = ?",
                params![key],
                |r| r.get(0),
            )
            .ok();
        if let Some(s) = sent {
            if Utc::now() - parse_ts(&s) < window {
                return false;
            }
        }
        let _ = conn.execute(
            "INSERT INTO alert_state(key, sent_at) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET sent_at = excluded.sent_at",
            params![key, ts(&Utc::now())],
        );
        true
    }

    #[allow(dead_code)]
    /// Removes an alert key (e.g. when an upstream recovers).
    pub fn clear_alert(&self, key: &str) {
        let _ = self
            .conn()
            .execute("DELETE FROM alert_state WHERE key = ?", params![key]);
    }
}

#[cfg(test)]
pub(crate) fn test_store() -> Store {
    Store::open_memory(Arc::new(SecretBox::new(b"test-key").unwrap())).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps() {
        for s in [
            "2026-10-08 22:31:12.729+00:00",
            "2026-10-08 22:31:12",
            "2026-10-08T22:31:12.729Z",
            "2026-10-08 22:31:12+00:00",
        ] {
            let t = parse_ts(s);
            assert_eq!(
                t.format("%Y-%m-%d %H:%M:%S").to_string(),
                "2026-10-08 22:31:12",
                "{s}"
            );
        }
        let now = Utc::now();
        assert_eq!(parse_ts(&ts(&now)), now);
    }

    #[test]
    fn settings_merge_over_defaults() {
        let s = test_store();
        s.kv_set(
            "global",
            r#"{"acme_email":"a@b.c","oidc":{"enabled":true}}"#,
        )
        .unwrap();
        let st = s.settings();
        assert_eq!(st.acme_email, "a@b.c");
        assert!(st.oidc.enabled);
        assert_eq!(st.oidc.default_role, "viewer", "nested defaults kept");
        assert_eq!(st.log_roll_keep, 5);
        let st = s.update_settings(|x| x.metrics = false).unwrap();
        assert!(!st.metrics && st.acme_email == "a@b.c");
    }

    #[test]
    fn sites_and_versions() {
        let s = test_store();
        let site = s
            .create_site(Site {
                name: "a".into(),
                hosts: vec!["a.example.com".into()],
                kind: KIND_PROXY.into(),
                enabled: true,
                config: SiteConfig {
                    proxy: Some(ProxyConfig {
                        upstreams: vec!["a:80".into()],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ..Default::default()
            })
            .unwrap();
        assert_eq!(site.position, 1);
        let got = s.site(site.id).unwrap();
        assert_eq!(got.config.proxy.unwrap().upstreams, vec!["a:80"]);
        assert!(is_not_found(&s.site(99).unwrap_err()));
        let v = s
            .add_version(ConfigVersion {
                user: "u".into(),
                caddyfile: "x".into(),
                status: "applied".into(),
                good: true,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(s.last_good().unwrap().id, v.id);
        assert_eq!(s.versions(10).unwrap()[0].caddyfile, "");
        s.audit("u", "test", "", "", "127.0.0.1");
        assert_eq!(s.audit_log("tes", 10, 0).unwrap().len(), 1);
        assert!(s.alert_once("k", chrono::Duration::hours(1)));
        assert!(!s.alert_once("k", chrono::Duration::hours(1)));
    }

    #[test]
    fn credentials_encrypted() {
        let s = test_store();
        let c = s
            .save_credential(DnsCredential {
                name: "cf".into(),
                provider: "cloudflare".into(),
                fields: BTreeMap::from([("api_token".to_string(), "secret-value".to_string())]),
                ..Default::default()
            })
            .unwrap();
        let raw: Vec<u8> = s
            .conn()
            .query_row(
                "SELECT fields FROM dns_credentials WHERE id = ?",
                params![c.id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("secret-value"));
        assert_eq!(
            s.credential(c.id).unwrap().fields["api_token"],
            "secret-value"
        );
    }
}
