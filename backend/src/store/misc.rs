#![allow(dead_code)] // templates, discovery and builds back roadmap features

use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

use super::{NotFound, Store, col_ts, from_json, json_str};

/// A user-saved site template (the data is a Site JSON).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Template {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub data: serde_json::Value,
}

/// A container suggested by Docker label discovery.
#[derive(Debug, Clone, Serialize)]
pub struct Discovered {
    pub id: i64,
    pub container_id: String,
    pub name: String,
    /// suggestion (site draft + labels)
    pub data: serde_json::Value,
    /// pending, approved, dismissed, gone
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A notification destination. Config is encrypted (URLs often embed
/// tokens).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Channel {
    pub id: i64,
    pub name: String,
    pub r#type: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub config: BTreeMap<String, String>,
    pub events: Vec<String>,
    pub enabled: bool,
}

/// A custom Caddy build recorded by the plugin manager.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Build {
    pub id: i64,
    pub tag: String,
    pub version: String,
    pub plugins: Vec<String>,
    /// building, built, failed, active, retired
    pub status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub log: String,
    pub created_at: DateTime<Utc>,
    pub active: bool,
}

impl Store {
    // ---------------------------------------------------------------- templates

    /// Lists user templates.
    pub fn templates(&self) -> Result<Vec<Template>> {
        let conn = self.conn();
        let mut st =
            conn.prepare("SELECT id, name, description, data FROM templates ORDER BY name")?;
        let rows = st.query_map([], |r| {
            let d: String = r.get(3)?;
            Ok(Template {
                id: r.get(0)?,
                name: r.get(1)?,
                description: r.get(2)?,
                data: from_json(&d),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Inserts or replaces a template by name.
    pub fn save_template(&self, mut t: Template) -> Result<Template> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO templates(name, description, data) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET description=excluded.description, data=excluded.data",
            params![t.name, t.description, json_str(&t.data)],
        )?;
        t.id = conn.last_insert_rowid();
        Ok(t)
    }

    /// Removes a template.
    pub fn delete_template(&self, id: i64) -> Result<()> {
        self.conn()
            .execute("DELETE FROM templates WHERE id = ?", params![id])?;
        Ok(())
    }

    // ---------------------------------------------------------------- discovery

    /// Inserts a new suggestion or refreshes an existing one (status is
    /// preserved so dismissed items stay dismissed).
    pub fn upsert_discovered(
        &self,
        container_id: &str,
        name: &str,
        data: &serde_json::Value,
    ) -> Result<()> {
        self.conn().execute(
            "INSERT INTO discovered(container_id, name, data, status) VALUES(?,?,?, 'pending') \
             ON CONFLICT(container_id) DO UPDATE SET name=excluded.name, data=excluded.data, updated_at=CURRENT_TIMESTAMP, \
             status = CASE WHEN discovered.status = 'gone' THEN 'pending' ELSE discovered.status END",
            params![container_id, name, json_str(data)],
        )?;
        Ok(())
    }

    /// Lists suggestions.
    pub fn discovered_list(&self) -> Result<Vec<Discovered>> {
        let conn = self.conn();
        let mut st = conn.prepare("SELECT id, container_id, name, data, status, created_at, updated_at FROM discovered ORDER BY status, name")?;
        let rows = st.query_map([], |r| {
            let d: String = r.get(3)?;
            Ok(Discovered {
                id: r.get(0)?,
                container_id: r.get(1)?,
                name: r.get(2)?,
                data: from_json(&d),
                status: r.get(4)?,
                created_at: col_ts(r, 5)?,
                updated_at: col_ts(r, 6)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// One suggestion.
    pub fn discovered_by_id(&self, id: i64) -> Result<Discovered> {
        self.discovered_list()?
            .into_iter()
            .find(|d| d.id == id)
            .ok_or_else(|| NotFound.into())
    }

    /// Updates status.
    pub fn set_discovered_status(&self, id: i64, status: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE discovered SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            params![status, id],
        )?;
        Ok(())
    }

    /// Marks pending suggestions whose containers vanished.
    pub fn mark_discovered_gone(&self, alive: &HashSet<String>) {
        if let Ok(list) = self.discovered_list() {
            for d in list {
                if !alive.contains(&d.container_id) && d.status == "pending" {
                    let _ = self.set_discovered_status(d.id, "gone");
                }
            }
        }
    }

    // ---------------------------------------------------------------- notifications

    /// Lists channels (decrypted).
    pub fn channels(&self) -> Result<Vec<Channel>> {
        let conn = self.conn();
        let mut st = conn.prepare("SELECT id, name, type, config, events, enabled FROM notification_channels ORDER BY name")?;
        let rows = st.query_map([], |r| {
            let enc: Vec<u8> = r.get(3)?;
            let ev: String = r.get(4)?;
            let en: i64 = r.get(5)?;
            let config = self
                .secret_box()
                .open(&enc)
                .ok()
                .map(|b| serde_json::from_slice(&b).unwrap_or_default())
                .unwrap_or_default();
            Ok(Channel {
                id: r.get(0)?,
                name: r.get(1)?,
                r#type: r.get(2)?,
                config,
                events: from_json(&ev),
                enabled: en == 1,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Inserts or updates.
    pub fn save_channel(&self, mut c: Channel) -> Result<Channel> {
        let enc = self.secret_box().seal(json_str(&c.config).as_bytes())?;
        let conn = self.conn();
        if c.id == 0 {
            conn.execute(
                "INSERT INTO notification_channels(name, type, config, events, enabled) VALUES(?,?,?,?,?)",
                params![c.name, c.r#type, enc, json_str(&c.events), c.enabled as i64],
            )?;
            c.id = conn.last_insert_rowid();
            return Ok(c);
        }
        conn.execute(
            "UPDATE notification_channels SET name=?, type=?, config=?, events=?, enabled=? WHERE id=?",
            params![c.name, c.r#type, enc, json_str(&c.events), c.enabled as i64, c.id],
        )?;
        Ok(c)
    }

    /// Removes a channel.
    pub fn delete_channel(&self, id: i64) -> Result<()> {
        self.conn().execute(
            "DELETE FROM notification_channels WHERE id = ?",
            params![id],
        )?;
        Ok(())
    }

    // ---------------------------------------------------------------- caddy builds

    /// Inserts or updates.
    pub fn save_build(&self, mut b: Build) -> Result<Build> {
        let conn = self.conn();
        if b.id == 0 {
            conn.execute(
                "INSERT INTO caddy_builds(tag, version, plugins, status, log, active) VALUES(?,?,?,?,?,?)",
                params![b.tag, b.version, json_str(&b.plugins), b.status, b.log, b.active as i64],
            )?;
            b.id = conn.last_insert_rowid();
            b.created_at = Utc::now();
            return Ok(b);
        }
        conn.execute(
            "UPDATE caddy_builds SET tag=?, version=?, plugins=?, status=?, log=?, active=? WHERE id=?",
            params![b.tag, b.version, json_str(&b.plugins), b.status, b.log, b.active as i64, b.id],
        )?;
        Ok(b)
    }

    /// Lists builds newest first.
    pub fn builds(&self) -> Result<Vec<Build>> {
        let conn = self.conn();
        let mut st = conn.prepare("SELECT id, tag, version, plugins, status, log, created_at, active FROM caddy_builds ORDER BY id DESC")?;
        let rows = st.query_map([], |r| {
            let pl: String = r.get(3)?;
            let a: i64 = r.get(7)?;
            Ok(Build {
                id: r.get(0)?,
                tag: r.get(1)?,
                version: r.get(2)?,
                plugins: from_json(&pl),
                status: r.get(4)?,
                log: r.get(5)?,
                created_at: col_ts(r, 6)?,
                active: a == 1,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// A build by ID.
    pub fn build_by_id(&self, id: i64) -> Result<Build> {
        self.builds()?
            .into_iter()
            .find(|b| b.id == id)
            .ok_or_else(|| NotFound.into())
    }

    /// Marks one build active.
    pub fn set_active_build(&self, id: i64) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute("UPDATE caddy_builds SET active = 0", [])?;
        tx.execute(
            "UPDATE caddy_builds SET active = 1, status = 'active' WHERE id = ?",
            params![id],
        )?;
        tx.execute(
            "UPDATE caddy_builds SET status = 'built' WHERE id != ? AND status = 'active'",
            params![id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The most recent build, if any.
    pub fn latest_build(&self) -> Option<Build> {
        self.conn()
            .query_row(
                "SELECT id FROM caddy_builds ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .ok()
            .flatten()
            .and_then(|id| self.build_by_id(id).ok())
    }
}
