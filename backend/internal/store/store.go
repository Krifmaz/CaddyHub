// Package store is the SQLite-backed source of truth for CaddyHub.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Krifmaz/CaddyHub/internal/model"
	"github.com/Krifmaz/CaddyHub/internal/secrets"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a row doesn't exist.
var ErrNotFound = errors.New("not found")

// Store wraps the database.
type Store struct {
	DB  *sql.DB
	box *secrets.Box
	mu  sync.Mutex // serializes settings read-modify-write
}

// Open opens (and migrates) the database at path.
func Open(path string, box *secrets.Box) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: one writer; keeps things simple and safe
	s := &Store{DB: db, box: box}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the DB.
func (s *Store) Close() error { return s.DB.Close() }

// Box returns the encryption box.
func (s *Store) Box() *secrets.Box { return s.box }

// SchemaVersion returns the current migration version.
func (s *Store) SchemaVersion() int {
	var v int
	s.DB.QueryRow(`SELECT version FROM schema_version`).Scan(&v)
	return v
}

// LatestSchemaVersion is the number of known migrations.
func LatestSchemaVersion() int { return len(migrations) }

func (s *Store) migrate() error {
	if _, err := s.DB.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return err
	}
	var v int
	err := s.DB.QueryRow(`SELECT version FROM schema_version`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := s.DB.Exec(`INSERT INTO schema_version(version) VALUES (0)`); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if v > len(migrations) {
		return fmt.Errorf("database schema v%d is newer than this panel (v%d); upgrade the panel", v, len(migrations))
	}
	for i := v; i < len(migrations); i++ {
		tx, err := s.DB.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(`UPDATE schema_version SET version = ?`, i+1); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func jsonStr(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---------------------------------------------------------------- settings / kv

// KVGet reads a raw settings key.
func (s *Store) KVGet(key string) (string, bool) {
	var v string
	if err := s.DB.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v); err != nil {
		return "", false
	}
	return v, true
}

// KVSet writes a raw settings key.
func (s *Store) KVSet(key, value string) error {
	_, err := s.DB.Exec(`INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// KVGetJSON decodes a JSON settings key into v.
func (s *Store) KVGetJSON(key string, v any) bool {
	raw, ok := s.KVGet(key)
	if !ok {
		return false
	}
	return json.Unmarshal([]byte(raw), v) == nil
}

// KVSetJSON stores v as JSON.
func (s *Store) KVSetJSON(key string, v any) error { return s.KVSet(key, jsonStr(v)) }

// Settings returns global settings merged over defaults (so new fields get
// defaults after an upgrade).
func (s *Store) Settings() model.Settings {
	st := model.DefaultSettings()
	s.KVGetJSON("global", &st)
	return st
}

// SaveSettings persists global settings.
func (s *Store) SaveSettings(st model.Settings) error { return s.KVSetJSON("global", st) }

// UpdateSettings applies fn atomically.
func (s *Store) UpdateSettings(fn func(*model.Settings)) (model.Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.Settings()
	fn(&st)
	return st, s.SaveSettings(st)
}

// ---------------------------------------------------------------- named secrets

// SetSecret stores an encrypted named secret.
func (s *Store) SetSecret(name, value string) error {
	if value == "" {
		_, err := s.DB.Exec(`DELETE FROM secrets WHERE name = ?`, name)
		return err
	}
	enc, err := s.box.Seal([]byte(value))
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(`INSERT INTO secrets(name, value) VALUES(?, ?) ON CONFLICT(name) DO UPDATE SET value = excluded.value`, name, enc)
	return err
}

// Secret returns a decrypted named secret.
func (s *Store) Secret(name string) (string, bool) {
	var enc []byte
	if err := s.DB.QueryRow(`SELECT value FROM secrets WHERE name = ?`, name).Scan(&enc); err != nil {
		return "", false
	}
	b, err := s.box.Open(enc)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// SecretNames lists stored secret names.
func (s *Store) SecretNames() []string {
	rows, err := s.DB.Query(`SELECT name FROM secrets ORDER BY name`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		rows.Scan(&n)
		out = append(out, n)
	}
	return out
}

// ---------------------------------------------------------------- sites

const siteCols = `id, name, hosts, kind, enabled, position, tags, config, created_at, updated_at`

func scanSite(sc interface{ Scan(...any) error }) (model.Site, error) {
	var st model.Site
	var hosts, tags, cfg string
	var en int
	if err := sc.Scan(&st.ID, &st.Name, &hosts, &st.Kind, &en, &st.Position, &tags, &cfg, &st.CreatedAt, &st.UpdatedAt); err != nil {
		return st, err
	}
	st.Enabled = en == 1
	json.Unmarshal([]byte(hosts), &st.Hosts)
	json.Unmarshal([]byte(tags), &st.Tags)
	json.Unmarshal([]byte(cfg), &st.Config)
	if st.Tags == nil {
		st.Tags = []string{}
	}
	return st, nil
}

// Sites returns all sites ordered by position.
func (s *Store) Sites() ([]model.Site, error) {
	rows, err := s.DB.Query(`SELECT ` + siteCols + ` FROM sites ORDER BY position, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Site{}
	for rows.Next() {
		st, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// Site returns one site.
func (s *Store) Site(id int64) (model.Site, error) {
	st, err := scanSite(s.DB.QueryRow(`SELECT `+siteCols+` FROM sites WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return st, ErrNotFound
	}
	return st, err
}

// CreateSite inserts a site and returns it with its ID. New sites go last.
func (s *Store) CreateSite(st model.Site) (model.Site, error) {
	now := time.Now().UTC()
	if st.Tags == nil {
		st.Tags = []string{}
	}
	if st.Position == 0 {
		s.DB.QueryRow(`SELECT COALESCE(MAX(position), 0) + 1 FROM sites`).Scan(&st.Position)
	}
	res, err := s.DB.Exec(`INSERT INTO sites(name, hosts, kind, enabled, position, tags, config, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		st.Name, jsonStr(st.Hosts), st.Kind, boolInt(st.Enabled), st.Position, jsonStr(st.Tags), jsonStr(st.Config), now, now)
	if err != nil {
		return st, err
	}
	st.ID, _ = res.LastInsertId()
	st.CreatedAt, st.UpdatedAt = now, now
	return st, nil
}

// UpdateSite replaces a site.
func (s *Store) UpdateSite(st model.Site) error {
	if st.Tags == nil {
		st.Tags = []string{}
	}
	res, err := s.DB.Exec(`UPDATE sites SET name=?, hosts=?, kind=?, enabled=?, position=?, tags=?, config=?, updated_at=? WHERE id=?`,
		st.Name, jsonStr(st.Hosts), st.Kind, boolInt(st.Enabled), st.Position, jsonStr(st.Tags), jsonStr(st.Config), time.Now().UTC(), st.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteSite removes a site.
func (s *Store) DeleteSite(id int64) error {
	res, err := s.DB.Exec(`DELETE FROM sites WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ReorderSites sets positions according to the given ID order.
func (s *Store) ReorderSites(ids []int64) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	for i, id := range ids {
		if _, err := tx.Exec(`UPDATE sites SET position = ? WHERE id = ?`, i+1, id); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// SetSitesEnabled bulk enables/disables.
func (s *Store) SetSitesEnabled(ids []int64, enabled bool) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := tx.Exec(`UPDATE sites SET enabled = ?, updated_at = ? WHERE id = ?`, boolInt(enabled), time.Now().UTC(), id); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// ---------------------------------------------------------------- domains

type domainExtra struct {
	PropagationDelay   string   `json:"propagation_delay,omitempty"`
	PropagationTimeout string   `json:"propagation_timeout,omitempty"`
	Resolvers          []string `json:"resolvers,omitempty"`
}

// Domains returns all domains.
func (s *Store) Domains() ([]model.Domain, error) {
	rows, err := s.DB.Query(`SELECT id, name, challenge, credential_id, wildcard, config, created_at FROM domains ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Domain{}
	for rows.Next() {
		d, err := scanDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func scanDomain(sc interface{ Scan(...any) error }) (model.Domain, error) {
	var d model.Domain
	var cred sql.NullInt64
	var wc int
	var cfg string
	if err := sc.Scan(&d.ID, &d.Name, &d.Challenge, &cred, &wc, &cfg, &d.CreatedAt); err != nil {
		return d, err
	}
	if cred.Valid {
		v := cred.Int64
		d.CredentialID = &v
	}
	d.Wildcard = wc == 1
	var ex domainExtra
	json.Unmarshal([]byte(cfg), &ex)
	d.PropagationDelay, d.PropagationTimeout, d.Resolvers = ex.PropagationDelay, ex.PropagationTimeout, ex.Resolvers
	return d, nil
}

// Domain returns one domain.
func (s *Store) Domain(id int64) (model.Domain, error) {
	d, err := scanDomain(s.DB.QueryRow(`SELECT id, name, challenge, credential_id, wildcard, config, created_at FROM domains WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	return d, err
}

// SaveDomain inserts or updates a domain.
func (s *Store) SaveDomain(d model.Domain) (model.Domain, error) {
	d.Name = strings.ToLower(strings.TrimSpace(d.Name))
	ex := jsonStr(domainExtra{d.PropagationDelay, d.PropagationTimeout, d.Resolvers})
	var cred any
	if d.CredentialID != nil {
		cred = *d.CredentialID
	}
	if d.ID == 0 {
		res, err := s.DB.Exec(`INSERT INTO domains(name, challenge, credential_id, wildcard, config) VALUES(?,?,?,?,?)`, d.Name, d.Challenge, cred, boolInt(d.Wildcard), ex)
		if err != nil {
			return d, err
		}
		d.ID, _ = res.LastInsertId()
		d.CreatedAt = time.Now().UTC()
		return d, nil
	}
	res, err := s.DB.Exec(`UPDATE domains SET name=?, challenge=?, credential_id=?, wildcard=?, config=? WHERE id=?`, d.Name, d.Challenge, cred, boolInt(d.Wildcard), ex, d.ID)
	if err != nil {
		return d, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return d, ErrNotFound
	}
	return d, nil
}

// DeleteDomain removes a domain.
func (s *Store) DeleteDomain(id int64) error {
	_, err := s.DB.Exec(`DELETE FROM domains WHERE id = ?`, id)
	return err
}

// ---------------------------------------------------------------- DNS credentials

// Credentials returns credentials with decrypted fields.
func (s *Store) Credentials() ([]model.DNSCredential, error) {
	rows, err := s.DB.Query(`SELECT id, name, provider, fields, created_at FROM dns_credentials ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.DNSCredential{}
	for rows.Next() {
		c, err := s.scanCred(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) scanCred(sc interface{ Scan(...any) error }) (model.DNSCredential, error) {
	var c model.DNSCredential
	var enc []byte
	if err := sc.Scan(&c.ID, &c.Name, &c.Provider, &enc, &c.CreatedAt); err != nil {
		return c, err
	}
	plain, err := s.box.Open(enc)
	if err != nil {
		return c, fmt.Errorf("decrypt credential %d (wrong CADDYHUB_SECRET_KEY?): %w", c.ID, err)
	}
	json.Unmarshal(plain, &c.Fields)
	if c.Fields == nil {
		c.Fields = map[string]string{}
	}
	return c, nil
}

// Credential returns one credential.
func (s *Store) Credential(id int64) (model.DNSCredential, error) {
	c, err := s.scanCred(s.DB.QueryRow(`SELECT id, name, provider, fields, created_at FROM dns_credentials WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	return c, err
}

// SaveCredential inserts or updates a credential, encrypting fields.
func (s *Store) SaveCredential(c model.DNSCredential) (model.DNSCredential, error) {
	b, _ := json.Marshal(c.Fields)
	enc, err := s.box.Seal(b)
	if err != nil {
		return c, err
	}
	if c.ID == 0 {
		res, err := s.DB.Exec(`INSERT INTO dns_credentials(name, provider, fields) VALUES(?,?,?)`, c.Name, c.Provider, enc)
		if err != nil {
			return c, err
		}
		c.ID, _ = res.LastInsertId()
		c.CreatedAt = time.Now().UTC()
		return c, nil
	}
	res, err := s.DB.Exec(`UPDATE dns_credentials SET name=?, provider=?, fields=? WHERE id=?`, c.Name, c.Provider, enc, c.ID)
	if err != nil {
		return c, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return c, ErrNotFound
	}
	return c, nil
}

// DeleteCredential removes a credential (domains using it are unset).
func (s *Store) DeleteCredential(id int64) error {
	_, err := s.DB.Exec(`DELETE FROM dns_credentials WHERE id = ?`, id)
	return err
}

// ---------------------------------------------------------------- snippets

// Snippets returns all snippets.
func (s *Store) Snippets() ([]model.Snippet, error) {
	rows, err := s.DB.Query(`SELECT id, name, description, body FROM snippets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Snippet{}
	for rows.Next() {
		var sn model.Snippet
		if err := rows.Scan(&sn.ID, &sn.Name, &sn.Description, &sn.Body); err != nil {
			return nil, err
		}
		out = append(out, sn)
	}
	return out, rows.Err()
}

// SaveSnippet inserts or updates.
func (s *Store) SaveSnippet(sn model.Snippet) (model.Snippet, error) {
	if sn.ID == 0 {
		res, err := s.DB.Exec(`INSERT INTO snippets(name, description, body) VALUES(?,?,?)`, sn.Name, sn.Description, sn.Body)
		if err != nil {
			return sn, err
		}
		sn.ID, _ = res.LastInsertId()
		return sn, nil
	}
	res, err := s.DB.Exec(`UPDATE snippets SET name=?, description=?, body=? WHERE id=?`, sn.Name, sn.Description, sn.Body, sn.ID)
	if err != nil {
		return sn, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sn, ErrNotFound
	}
	return sn, nil
}

// DeleteSnippet removes a snippet.
func (s *Store) DeleteSnippet(id int64) error {
	_, err := s.DB.Exec(`DELETE FROM snippets WHERE id = ?`, id)
	return err
}

// ---------------------------------------------------------------- raw blocks

// RawBlocks returns all raw blocks.
func (s *Store) RawBlocks() ([]model.RawBlock, error) {
	rows, err := s.DB.Query(`SELECT id, name, body, enabled, position, source FROM raw_blocks ORDER BY position, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.RawBlock{}
	for rows.Next() {
		var b model.RawBlock
		var en int
		if err := rows.Scan(&b.ID, &b.Name, &b.Body, &en, &b.Position, &b.Source); err != nil {
			return nil, err
		}
		b.Enabled = en == 1
		out = append(out, b)
	}
	return out, rows.Err()
}

// SaveRawBlock inserts or updates.
func (s *Store) SaveRawBlock(b model.RawBlock) (model.RawBlock, error) {
	if b.Source == "" {
		b.Source = "user"
	}
	if b.ID == 0 {
		res, err := s.DB.Exec(`INSERT INTO raw_blocks(name, body, enabled, position, source) VALUES(?,?,?,?,?)`, b.Name, b.Body, boolInt(b.Enabled), b.Position, b.Source)
		if err != nil {
			return b, err
		}
		b.ID, _ = res.LastInsertId()
		return b, nil
	}
	res, err := s.DB.Exec(`UPDATE raw_blocks SET name=?, body=?, enabled=?, position=?, source=? WHERE id=?`, b.Name, b.Body, boolInt(b.Enabled), b.Position, b.Source, b.ID)
	if err != nil {
		return b, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return b, ErrNotFound
	}
	return b, nil
}

// DeleteRawBlock removes a raw block.
func (s *Store) DeleteRawBlock(id int64) error {
	_, err := s.DB.Exec(`DELETE FROM raw_blocks WHERE id = ?`, id)
	return err
}

// ---------------------------------------------------------------- versions

// AddVersion records a config snapshot.
func (s *Store) AddVersion(v model.ConfigVersion) (model.ConfigVersion, error) {
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now().UTC()
	}
	res, err := s.DB.Exec(`INSERT INTO config_versions(created_at, user, caddyfile, status, message, good, caddy_version) VALUES(?,?,?,?,?,?,?)`,
		v.CreatedAt, v.User, v.Caddyfile, v.Status, v.Message, boolInt(v.Good), v.CaddyVersion)
	if err != nil {
		return v, err
	}
	v.ID, _ = res.LastInsertId()
	return v, nil
}

// UpdateVersionStatus updates status/message/good.
func (s *Store) UpdateVersionStatus(id int64, status, msg string, good bool) error {
	_, err := s.DB.Exec(`UPDATE config_versions SET status=?, message=?, good=? WHERE id=?`, status, msg, boolInt(good), id)
	return err
}

// Versions lists versions (newest first) without bodies.
func (s *Store) Versions(limit int) ([]model.ConfigVersion, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.DB.Query(`SELECT id, created_at, user, status, message, good, caddy_version FROM config_versions ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ConfigVersion{}
	for rows.Next() {
		var v model.ConfigVersion
		var g int
		if err := rows.Scan(&v.ID, &v.CreatedAt, &v.User, &v.Status, &v.Message, &g, &v.CaddyVersion); err != nil {
			return nil, err
		}
		v.Good = g == 1
		out = append(out, v)
	}
	return out, rows.Err()
}

// Version returns a version with its Caddyfile.
func (s *Store) Version(id int64) (model.ConfigVersion, error) {
	var v model.ConfigVersion
	var g int
	err := s.DB.QueryRow(`SELECT id, created_at, user, caddyfile, status, message, good, caddy_version FROM config_versions WHERE id = ?`, id).
		Scan(&v.ID, &v.CreatedAt, &v.User, &v.Caddyfile, &v.Status, &v.Message, &g, &v.CaddyVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	v.Good = g == 1
	return v, err
}

// LastGood returns the most recent successfully applied version.
func (s *Store) LastGood() (model.ConfigVersion, error) {
	var id int64
	err := s.DB.QueryRow(`SELECT id FROM config_versions WHERE good = 1 ORDER BY id DESC LIMIT 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ConfigVersion{}, ErrNotFound
	}
	if err != nil {
		return model.ConfigVersion{}, err
	}
	return s.Version(id)
}

// LastVersion returns the most recent version of any status.
func (s *Store) LastVersion() (model.ConfigVersion, error) {
	var id int64
	err := s.DB.QueryRow(`SELECT id FROM config_versions ORDER BY id DESC LIMIT 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ConfigVersion{}, ErrNotFound
	}
	if err != nil {
		return model.ConfigVersion{}, err
	}
	return s.Version(id)
}

// PruneVersions keeps the newest n versions (good versions are never all
// removed: the latest good one is always kept).
func (s *Store) PruneVersions(keep int) error {
	if keep <= 0 {
		return nil
	}
	_, err := s.DB.Exec(`DELETE FROM config_versions WHERE id NOT IN (SELECT id FROM config_versions ORDER BY id DESC LIMIT ?)
		AND id != COALESCE((SELECT id FROM config_versions WHERE good = 1 ORDER BY id DESC LIMIT 1), -1)`, keep)
	return err
}

// ---------------------------------------------------------------- audit

// AuditEntry is a row in the audit log.
type AuditEntry struct {
	ID      int64     `json:"id"`
	TS      time.Time `json:"ts"`
	User    string    `json:"user"`
	Action  string    `json:"action"`
	Target  string    `json:"target"`
	Details string    `json:"details"`
	IP      string    `json:"ip"`
}

// Audit records an action. Details must never contain secrets.
func (s *Store) Audit(user, action, target, details, ip string) {
	s.DB.Exec(`INSERT INTO audit_log(ts, user, action, target, details, ip) VALUES(?,?,?,?,?,?)`, time.Now().UTC(), user, action, target, details, ip)
}

// AuditLog returns entries newest first, optionally filtered.
func (s *Store) AuditLog(ctx context.Context, q string, limit, offset int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	query := `SELECT id, ts, user, action, target, details, ip FROM audit_log`
	var args []any
	if q != "" {
		query += ` WHERE user LIKE ? OR action LIKE ? OR target LIKE ? OR details LIKE ?`
		like := "%" + q + "%"
		args = append(args, like, like, like, like)
	}
	query += ` ORDER BY id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.User, &e.Action, &e.Target, &e.Details, &e.IP); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- alert dedupe

// AlertSent reports whether key was sent within window, and marks it if not.
func (s *Store) AlertOnce(key string, window time.Duration) bool {
	var t time.Time
	err := s.DB.QueryRow(`SELECT sent_at FROM alert_state WHERE key = ?`, key).Scan(&t)
	if err == nil && time.Since(t) < window {
		return false
	}
	s.DB.Exec(`INSERT INTO alert_state(key, sent_at) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET sent_at = excluded.sent_at`, key, time.Now().UTC())
	return true
}

// ClearAlert removes an alert key (e.g. when an upstream recovers).
func (s *Store) ClearAlert(key string) { s.DB.Exec(`DELETE FROM alert_state WHERE key = ?`, key) }
