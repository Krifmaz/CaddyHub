//! Snapshots of the editable configuration (sites, domains, DNS accounts,
//! snippets, raw blocks, templates, notification channels, named secrets
//! and the global settings) and backup archives built from them.
//!
//! A snapshot is a generic, id-preserving dump of those tables: rows are
//! copied as they are stored, so encrypted values stay encrypted and nothing
//! has to be re-encoded through the model types. Two things use it:
//!
//! - every successful apply records a snapshot with the version, so
//!   "Discard changes" can put the configuration back to what is running and
//!   restoring a version from History brings the sites back with it;
//! - the backup archive the admin can download is a snapshot sealed with the
//!   panel's secret key, so secrets never leave the panel readable and a
//!   restore needs the same key (as the README has always said).
//!
//! Users, API keys, sessions, the version history and the audit log are not
//! part of a snapshot.

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use chrono::{DateTime, Utc};
use rusqlite::types::{Value as SqlValue, ValueRef};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

use crate::store::Store;

pub const FORMAT: &str = "caddyhub-backup";
pub const ARCHIVE_VERSION: i64 = 1;

/// Tables in dependency order: parents before children, so a restore can
/// insert in this order and delete in the reverse one.
pub const TABLES: &[&str] = &[
    "secrets",
    "dns_credentials",
    "domains",
    "sites",
    "snippets",
    "raw_blocks",
    "templates",
    "notification_channels",
];

/// Key in the settings table that holds the global settings.
const SETTINGS_KEY: &str = "global";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Table {
    pub columns: Vec<String>,
    /// Cells are JSON null / number / string; BLOBs are {"$b64": "..."}.
    pub rows: Vec<Vec<Value>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Snapshot {
    /// Database schema version the rows were read with.
    pub schema: i64,
    /// The global settings as stored (JSON text), empty when unset.
    pub settings: String,
    pub tables: BTreeMap<String, Table>,
}

/// What a restore changed.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Summary {
    /// rows restored per table
    pub tables: BTreeMap<String, usize>,
    pub settings: bool,
}

/// The downloadable archive: metadata in the clear, the snapshot sealed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Envelope {
    pub format: String,
    pub version: i64,
    pub created_at: Option<DateTime<Utc>>,
    pub panel_version: String,
    pub caddy_version: String,
    pub schema: i64,
    /// Counts, so the file says what it holds without the key.
    pub contents: BTreeMap<String, usize>,
    /// base64 of the sealed JSON snapshot (nonce || ciphertext).
    pub data: String,
}

fn cell(v: ValueRef<'_>) -> Value {
    match v {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(i) => json!(i),
        ValueRef::Real(f) => json!(f),
        ValueRef::Text(t) => Value::String(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => json!({"$b64": base64::engine::general_purpose::STANDARD.encode(b)}),
    }
}

fn uncell(v: &Value) -> Result<SqlValue> {
    Ok(match v {
        Value::Null => SqlValue::Null,
        Value::Bool(b) => SqlValue::Integer(*b as i64),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                SqlValue::Integer(i)
            } else {
                SqlValue::Real(n.as_f64().unwrap_or(0.0))
            }
        }
        Value::String(s) => SqlValue::Text(s.clone()),
        Value::Object(o) => match o.get("$b64").and_then(|b| b.as_str()) {
            Some(b) => SqlValue::Blob(
                base64::engine::general_purpose::STANDARD
                    .decode(b)
                    .context("blob cell is not base64")?,
            ),
            None => return Err(anyhow!("unsupported cell {v}")),
        },
        Value::Array(_) => return Err(anyhow!("unsupported cell {v}")),
    })
}

fn valid_ident(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Reads the configuration tables and the global settings.
pub fn snapshot(store: &Store) -> Result<Snapshot> {
    let conn = store.conn();
    let mut tables = BTreeMap::new();
    for t in TABLES {
        let mut st = conn.prepare(&format!("SELECT * FROM {t} ORDER BY rowid"))?;
        let columns: Vec<String> = st.column_names().iter().map(|c| c.to_string()).collect();
        let n = columns.len();
        let rows = st
            .query_map([], |r| {
                let mut row = Vec::with_capacity(n);
                for i in 0..n {
                    row.push(cell(r.get_ref(i)?));
                }
                Ok(row)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        tables.insert(t.to_string(), Table { columns, rows });
    }
    let settings: String = conn
        .query_row(
            "SELECT value FROM settings WHERE key = ?",
            [SETTINGS_KEY],
            |r| r.get(0),
        )
        .unwrap_or_default();
    let schema: i64 = conn
        .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
        .unwrap_or(0);
    Ok(Snapshot {
        schema,
        settings,
        tables,
    })
}

/// The snapshot as JSON text; empty when it cannot be taken (logged).
pub fn snapshot_json(store: &Store) -> String {
    match snapshot(store).and_then(|s| Ok(serde_json::to_string(&s)?)) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(err = %e, "could not snapshot the configuration");
            String::new()
        }
    }
}

/// Replaces the configuration tables and the global settings with the
/// snapshot, keeping row ids, in one transaction.
pub fn restore(store: &Store, snap: &Snapshot) -> Result<Summary> {
    let mut conn = store.conn();
    let schema: i64 = conn
        .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
        .unwrap_or(0);
    if snap.schema > schema {
        return Err(anyhow!(
            "the snapshot was made by a newer panel (schema v{}, this one has v{schema}); upgrade first",
            snap.schema
        ));
    }
    let tx = conn.transaction()?;
    tx.execute_batch("PRAGMA defer_foreign_keys = ON")?;
    let mut summary = Summary::default();
    for t in TABLES.iter().rev() {
        if snap.tables.contains_key(*t) {
            tx.execute(&format!("DELETE FROM {t}"), [])?;
        }
    }
    for t in TABLES {
        let Some(table) = snap.tables.get(*t) else {
            continue;
        };
        // Only columns this schema knows; newer columns keep their defaults.
        let known: Vec<String> = {
            let mut st = tx.prepare(&format!("PRAGMA table_info({t})"))?;
            st.query_map([], |r| r.get::<_, String>(1))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let cols: Vec<(usize, &String)> = table
            .columns
            .iter()
            .enumerate()
            .filter(|(_, c)| valid_ident(c) && known.contains(c))
            .collect();
        if cols.is_empty() {
            continue;
        }
        let names: Vec<&str> = cols.iter().map(|(_, c)| c.as_str()).collect();
        let marks = vec!["?"; cols.len()].join(",");
        let sql = format!("INSERT INTO {t}({}) VALUES({marks})", names.join(","));
        let mut st = tx.prepare(&sql)?;
        let mut n = 0;
        for row in &table.rows {
            let mut vals = Vec::with_capacity(cols.len());
            for (i, _) in &cols {
                vals.push(uncell(row.get(*i).unwrap_or(&Value::Null))?);
            }
            st.execute(rusqlite::params_from_iter(vals.iter()))
                .with_context(|| format!("restore {t}"))?;
            n += 1;
        }
        summary.tables.insert(t.to_string(), n);
    }
    if snap.settings.is_empty() {
        // Nothing was ever saved when the snapshot was taken: back to defaults.
        tx.execute("DELETE FROM settings WHERE key = ?", [SETTINGS_KEY])?;
    } else {
        tx.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [SETTINGS_KEY, snap.settings.as_str()],
        )?;
    }
    summary.settings = true;
    tx.commit()?;
    Ok(summary)
}

/// Restores from the JSON text `snapshot_json` produced.
pub fn restore_json(store: &Store, json: &str) -> Result<Summary> {
    let snap: Snapshot = serde_json::from_str(json).context("decode snapshot")?;
    restore(store, &snap)
}

/// Builds the downloadable archive: the snapshot sealed with the secret key.
pub fn seal(store: &Store, panel_version: &str, caddy_version: &str) -> Result<Envelope> {
    let snap = snapshot(store)?;
    let plain = serde_json::to_vec(&snap)?;
    let sealed = store.secret_box().seal(&plain)?;
    let contents = snap
        .tables
        .iter()
        .map(|(k, t)| (k.clone(), t.rows.len()))
        .collect();
    Ok(Envelope {
        format: FORMAT.into(),
        version: ARCHIVE_VERSION,
        created_at: Some(Utc::now()),
        panel_version: panel_version.into(),
        caddy_version: caddy_version.into(),
        schema: snap.schema,
        contents,
        data: base64::engine::general_purpose::STANDARD.encode(sealed),
    })
}

/// Decrypts and decodes an archive.
pub fn open(store: &Store, env: &Envelope) -> Result<Snapshot> {
    if env.format != FORMAT {
        return Err(anyhow!("this is not a CaddyHub backup file"));
    }
    if env.version > ARCHIVE_VERSION {
        return Err(anyhow!(
            "backup format v{} is newer than this panel understands (v{ARCHIVE_VERSION})",
            env.version
        ));
    }
    let sealed = base64::engine::general_purpose::STANDARD
        .decode(env.data.trim())
        .context("the backup data is not valid base64")?;
    let plain = store.secret_box().open(&sealed).map_err(|_| {
        anyhow!("cannot decrypt this backup: it was made with a different CADDYHUB_SECRET_KEY")
    })?;
    let snap: Snapshot = serde_json::from_slice(&plain).context("decode backup")?;
    Ok(snap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DnsCredential, Domain, Site, Snippet};
    use crate::secrets::SecretBox;
    use std::sync::Arc;

    fn store(key: &[u8]) -> Store {
        Store::open_memory(Arc::new(SecretBox::new(key).unwrap())).unwrap()
    }

    fn fill(s: &Store) -> (i64, i64) {
        let c = s
            .save_credential(DnsCredential {
                name: "cf".into(),
                provider: "cloudflare".into(),
                fields: BTreeMap::from([("api_token".to_string(), "tok-123".to_string())]),
                ..Default::default()
            })
            .unwrap();
        let d = s
            .save_domain(Domain {
                name: "example.com".into(),
                challenge: "dns".into(),
                credential_id: Some(c.id),
                ..Default::default()
            })
            .unwrap();
        s.create_site(Site {
            name: "app".into(),
            hosts: vec!["app.example.com".into()],
            kind: "reverse_proxy".into(),
            enabled: true,
            ..Default::default()
        })
        .unwrap();
        s.save_snippet(Snippet {
            name: "common".into(),
            body: "encode gzip".into(),
            ..Default::default()
        })
        .unwrap();
        s.set_secret("acme_eab_mac", "mac-secret").unwrap();
        s.update_settings(|st| st.acme_email = "me@example.com".into())
            .unwrap();
        (c.id, d.id)
    }

    #[test]
    fn snapshot_restore_round_trip_keeps_ids_and_secrets() {
        let s = store(b"k1");
        let (cid, did) = fill(&s);
        let snap = snapshot(&s).unwrap();
        assert_eq!(snap.tables["sites"].rows.len(), 1);
        assert_eq!(snap.tables["dns_credentials"].rows.len(), 1);
        assert!(snap.settings.contains("me@example.com"));

        // Change everything, then restore.
        s.delete_domain(did).unwrap();
        s.delete_credential(cid).unwrap();
        for site in s.sites().unwrap() {
            s.delete_site(site.id).unwrap();
        }
        s.create_site(Site {
            name: "other".into(),
            hosts: vec!["x.example.com".into()],
            kind: "static".into(),
            ..Default::default()
        })
        .unwrap();
        s.set_secret("acme_eab_mac", "").unwrap();
        s.update_settings(|st| st.acme_email = "someone@else".into())
            .unwrap();

        let sum = restore(&s, &snap).unwrap();
        assert_eq!(sum.tables["sites"], 1);
        assert!(sum.settings);
        let sites = s.sites().unwrap();
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].name, "app");
        let d = s.domain(did).unwrap();
        assert_eq!(d.credential_id, Some(cid), "foreign key kept by id");
        let c = s.credential(cid).unwrap();
        assert_eq!(c.fields["api_token"], "tok-123", "encrypted blob restored");
        assert_eq!(s.secret("acme_eab_mac").as_deref(), Some("mac-secret"));
        assert_eq!(s.settings().acme_email, "me@example.com");
        assert_eq!(s.snippets().unwrap()[0].name, "common");
    }

    #[test]
    fn archive_needs_the_same_key() {
        let s = store(b"k1");
        fill(&s);
        let env = seal(&s, "test", "v2.0.0").unwrap();
        assert_eq!(env.format, FORMAT);
        assert_eq!(env.contents["sites"], 1);
        assert!(!env.data.is_empty());
        let text = serde_json::to_string(&env).unwrap();
        assert!(!text.contains("tok-123"), "secrets never in the clear");

        let other = store(b"k2");
        let err = open(&other, &env).unwrap_err().to_string();
        assert!(err.contains("different CADDYHUB_SECRET_KEY"), "{err}");

        let fresh = store(b"k1");
        let snap = open(&fresh, &env).unwrap();
        restore(&fresh, &snap).unwrap();
        assert_eq!(fresh.sites().unwrap()[0].name, "app");
        assert_eq!(
            fresh.credentials().unwrap()[0].fields["api_token"],
            "tok-123"
        );

        let bad = Envelope {
            format: "something".into(),
            ..Default::default()
        };
        assert!(open(&fresh, &bad).is_err());
    }
}
