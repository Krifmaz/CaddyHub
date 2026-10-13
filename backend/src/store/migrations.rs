/// Migrations are applied in order; each runs in a transaction and bumps
/// schema_version. Never edit a released migration: append a new one.
pub static MIGRATIONS: &[&str] = &[
    // 1: initial schema
    r#"
CREATE TABLE settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE secrets (
	name  TEXT PRIMARY KEY,
	value BLOB NOT NULL
);
CREATE TABLE users (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
	password_hash TEXT NOT NULL DEFAULT '',
	role          TEXT NOT NULL DEFAULT 'viewer',
	totp_secret   BLOB,
	totp_enabled  INTEGER NOT NULL DEFAULT 0,
	oidc_subject  TEXT,
	disabled      INTEGER NOT NULL DEFAULT 0,
	created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_login    TIMESTAMP
);
CREATE UNIQUE INDEX users_oidc ON users(oidc_subject) WHERE oidc_subject IS NOT NULL;
CREATE TABLE sessions (
	id         TEXT PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	csrf       TEXT NOT NULL,
	created_at TIMESTAMP NOT NULL,
	expires_at TIMESTAMP NOT NULL,
	last_seen  TIMESTAMP NOT NULL,
	ip         TEXT,
	user_agent TEXT,
	pending_2fa INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE api_keys (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL,
	prefix     TEXT NOT NULL,
	hash       TEXT NOT NULL UNIQUE,
	role       TEXT NOT NULL,
	user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_used  TIMESTAMP,
	expires_at TIMESTAMP
);
CREATE TABLE dns_credentials (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL,
	provider   TEXT NOT NULL,
	fields     BLOB NOT NULL,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE domains (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	name          TEXT NOT NULL UNIQUE COLLATE NOCASE,
	challenge     TEXT NOT NULL,
	credential_id INTEGER REFERENCES dns_credentials(id) ON DELETE SET NULL,
	wildcard      INTEGER NOT NULL DEFAULT 0,
	config        TEXT NOT NULL DEFAULT '{}',
	created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE sites (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL,
	hosts      TEXT NOT NULL,
	kind       TEXT NOT NULL,
	enabled    INTEGER NOT NULL DEFAULT 1,
	position   INTEGER NOT NULL DEFAULT 0,
	tags       TEXT NOT NULL DEFAULT '[]',
	config     TEXT NOT NULL DEFAULT '{}',
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE snippets (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	name        TEXT NOT NULL UNIQUE,
	description TEXT NOT NULL DEFAULT '',
	body        TEXT NOT NULL
);
CREATE TABLE raw_blocks (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	name     TEXT NOT NULL,
	body     TEXT NOT NULL,
	enabled  INTEGER NOT NULL DEFAULT 1,
	position INTEGER NOT NULL DEFAULT 0,
	source   TEXT NOT NULL DEFAULT 'user'
);
CREATE TABLE config_versions (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	created_at    TIMESTAMP NOT NULL,
	user          TEXT NOT NULL,
	caddyfile     TEXT NOT NULL,
	status        TEXT NOT NULL,
	message       TEXT NOT NULL DEFAULT '',
	good          INTEGER NOT NULL DEFAULT 0,
	caddy_version TEXT NOT NULL DEFAULT ''
);
CREATE INDEX config_versions_good ON config_versions(good, id);
CREATE TABLE audit_log (
	id      INTEGER PRIMARY KEY AUTOINCREMENT,
	ts      TIMESTAMP NOT NULL,
	user    TEXT NOT NULL,
	action  TEXT NOT NULL,
	target  TEXT NOT NULL DEFAULT '',
	details TEXT NOT NULL DEFAULT '',
	ip      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_log_ts ON audit_log(ts);
CREATE TABLE templates (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	name        TEXT NOT NULL UNIQUE,
	description TEXT NOT NULL DEFAULT '',
	data        TEXT NOT NULL
);
CREATE TABLE discovered (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	container_id TEXT NOT NULL UNIQUE,
	name         TEXT NOT NULL,
	data         TEXT NOT NULL,
	status       TEXT NOT NULL DEFAULT 'pending',
	created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE notification_channels (
	id      INTEGER PRIMARY KEY AUTOINCREMENT,
	name    TEXT NOT NULL,
	type    TEXT NOT NULL,
	config  BLOB NOT NULL,
	events  TEXT NOT NULL DEFAULT '[]',
	enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE alert_state (
	key     TEXT PRIMARY KEY,
	sent_at TIMESTAMP NOT NULL
);
CREATE TABLE caddy_builds (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	tag        TEXT NOT NULL UNIQUE,
	version    TEXT NOT NULL,
	plugins    TEXT NOT NULL DEFAULT '[]',
	status     TEXT NOT NULL,
	log        TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	active     INTEGER NOT NULL DEFAULT 0
);
"#,
    // 2: snapshot of the editable configuration recorded with each applied
    // version (see backup.rs), so Discard changes and History restores can
    // put the sites and settings back.
    r#"
ALTER TABLE config_versions ADD COLUMN model TEXT NOT NULL DEFAULT '';
"#,
    // 3: sign-in sessions for sites behind the login wall (server/sso.rs);
    // separate from panel sessions so one can never be used as the other.
    r#"
CREATE TABLE sso_sessions (
	id         TEXT PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	created_at TIMESTAMP NOT NULL,
	expires_at TIMESTAMP NOT NULL,
	last_seen  TIMESTAMP NOT NULL,
	ip         TEXT NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL DEFAULT '',
	mfa        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX sso_sessions_user ON sso_sessions(user_id);
"#,
];
