package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// ---------------------------------------------------------------- templates

// Template is a user-saved site template (the data is a model.Site JSON).
type Template struct {
	ID          int64           `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Data        json.RawMessage `json:"data"`
}

// Templates lists user templates.
func (s *Store) Templates() ([]Template, error) {
	rows, err := s.DB.Query(`SELECT id, name, description, data FROM templates ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Template{}
	for rows.Next() {
		var t Template
		var d string
		if err := rows.Scan(&t.ID, &t.Name, &t.Description, &d); err != nil {
			return nil, err
		}
		t.Data = json.RawMessage(d)
		out = append(out, t)
	}
	return out, rows.Err()
}

// SaveTemplate inserts or replaces a template by name.
func (s *Store) SaveTemplate(t Template) (Template, error) {
	res, err := s.DB.Exec(`INSERT INTO templates(name, description, data) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET description=excluded.description, data=excluded.data`, t.Name, t.Description, string(t.Data))
	if err != nil {
		return t, err
	}
	t.ID, _ = res.LastInsertId()
	return t, nil
}

// DeleteTemplate removes a template.
func (s *Store) DeleteTemplate(id int64) error {
	_, err := s.DB.Exec(`DELETE FROM templates WHERE id = ?`, id)
	return err
}

// ---------------------------------------------------------------- discovery

// Discovered is a container suggested by Docker label discovery.
type Discovered struct {
	ID          int64           `json:"id"`
	ContainerID string          `json:"container_id"`
	Name        string          `json:"name"`
	Data        json.RawMessage `json:"data"`   // suggestion (site draft + labels)
	Status      string          `json:"status"` // pending, approved, dismissed, gone
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// UpsertDiscovered inserts a new suggestion or refreshes an existing one
// (status is preserved so dismissed items stay dismissed).
func (s *Store) UpsertDiscovered(d Discovered) error {
	_, err := s.DB.Exec(`INSERT INTO discovered(container_id, name, data, status) VALUES(?,?,?, 'pending')
		ON CONFLICT(container_id) DO UPDATE SET name=excluded.name, data=excluded.data, updated_at=CURRENT_TIMESTAMP,
		status = CASE WHEN discovered.status = 'gone' THEN 'pending' ELSE discovered.status END`, d.ContainerID, d.Name, string(d.Data))
	return err
}

// DiscoveredList lists suggestions.
func (s *Store) DiscoveredList() ([]Discovered, error) {
	rows, err := s.DB.Query(`SELECT id, container_id, name, data, status, created_at, updated_at FROM discovered ORDER BY status, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Discovered{}
	for rows.Next() {
		var d Discovered
		var data string
		if err := rows.Scan(&d.ID, &d.ContainerID, &d.Name, &data, &d.Status, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, err
		}
		d.Data = json.RawMessage(data)
		out = append(out, d)
	}
	return out, rows.Err()
}

// DiscoveredByID returns one suggestion.
func (s *Store) DiscoveredByID(id int64) (Discovered, error) {
	var d Discovered
	var data string
	err := s.DB.QueryRow(`SELECT id, container_id, name, data, status, created_at, updated_at FROM discovered WHERE id = ?`, id).
		Scan(&d.ID, &d.ContainerID, &d.Name, &data, &d.Status, &d.CreatedAt, &d.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	d.Data = json.RawMessage(data)
	return d, err
}

// SetDiscoveredStatus updates status.
func (s *Store) SetDiscoveredStatus(id int64, status string) error {
	_, err := s.DB.Exec(`UPDATE discovered SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, status, id)
	return err
}

// MarkDiscoveredGone marks pending suggestions whose containers vanished.
func (s *Store) MarkDiscoveredGone(alive map[string]bool) {
	list, _ := s.DiscoveredList()
	for _, d := range list {
		if !alive[d.ContainerID] && d.Status == "pending" {
			s.SetDiscoveredStatus(d.ID, "gone")
		}
	}
}

// ---------------------------------------------------------------- notifications

// Channel is a notification destination. Config is encrypted (URLs often
// embed tokens).
type Channel struct {
	ID      int64             `json:"id"`
	Name    string            `json:"name"`
	Type    string            `json:"type"`
	Config  map[string]string `json:"config,omitempty"`
	Events  []string          `json:"events"`
	Enabled bool              `json:"enabled"`
}

// Channels lists channels (decrypted).
func (s *Store) Channels() ([]Channel, error) {
	rows, err := s.DB.Query(`SELECT id, name, type, config, events, enabled FROM notification_channels ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Channel{}
	for rows.Next() {
		var c Channel
		var enc []byte
		var ev string
		var en int
		if err := rows.Scan(&c.ID, &c.Name, &c.Type, &enc, &ev, &en); err != nil {
			return nil, err
		}
		if b, err := s.box.Open(enc); err == nil {
			json.Unmarshal(b, &c.Config)
		}
		json.Unmarshal([]byte(ev), &c.Events)
		c.Enabled = en == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

// SaveChannel inserts or updates.
func (s *Store) SaveChannel(c Channel) (Channel, error) {
	b, _ := json.Marshal(c.Config)
	enc, err := s.box.Seal(b)
	if err != nil {
		return c, err
	}
	if c.Events == nil {
		c.Events = []string{}
	}
	if c.ID == 0 {
		res, err := s.DB.Exec(`INSERT INTO notification_channels(name, type, config, events, enabled) VALUES(?,?,?,?,?)`, c.Name, c.Type, enc, jsonStr(c.Events), boolInt(c.Enabled))
		if err != nil {
			return c, err
		}
		c.ID, _ = res.LastInsertId()
		return c, nil
	}
	_, err = s.DB.Exec(`UPDATE notification_channels SET name=?, type=?, config=?, events=?, enabled=? WHERE id=?`, c.Name, c.Type, enc, jsonStr(c.Events), boolInt(c.Enabled), c.ID)
	return c, err
}

// DeleteChannel removes a channel.
func (s *Store) DeleteChannel(id int64) error {
	_, err := s.DB.Exec(`DELETE FROM notification_channels WHERE id = ?`, id)
	return err
}

// ---------------------------------------------------------------- caddy builds

// Build is a custom Caddy image built by the plugin manager.
type Build struct {
	ID        int64     `json:"id"`
	Tag       string    `json:"tag"`
	Version   string    `json:"version"`
	Plugins   []string  `json:"plugins"`
	Status    string    `json:"status"` // building, built, failed, active, retired
	Log       string    `json:"log,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	Active    bool      `json:"active"`
}

// SaveBuild inserts or updates.
func (s *Store) SaveBuild(b Build) (Build, error) {
	if b.ID == 0 {
		res, err := s.DB.Exec(`INSERT INTO caddy_builds(tag, version, plugins, status, log, active) VALUES(?,?,?,?,?,?)`, b.Tag, b.Version, jsonStr(b.Plugins), b.Status, b.Log, boolInt(b.Active))
		if err != nil {
			return b, err
		}
		b.ID, _ = res.LastInsertId()
		b.CreatedAt = time.Now().UTC()
		return b, nil
	}
	_, err := s.DB.Exec(`UPDATE caddy_builds SET tag=?, version=?, plugins=?, status=?, log=?, active=? WHERE id=?`, b.Tag, b.Version, jsonStr(b.Plugins), b.Status, b.Log, boolInt(b.Active), b.ID)
	return b, err
}

// Builds lists builds newest first.
func (s *Store) Builds() ([]Build, error) {
	rows, err := s.DB.Query(`SELECT id, tag, version, plugins, status, log, created_at, active FROM caddy_builds ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Build{}
	for rows.Next() {
		var b Build
		var pl string
		var a int
		if err := rows.Scan(&b.ID, &b.Tag, &b.Version, &pl, &b.Status, &b.Log, &b.CreatedAt, &a); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(pl), &b.Plugins)
		b.Active = a == 1
		out = append(out, b)
	}
	return out, rows.Err()
}

// BuildByID returns a build.
func (s *Store) BuildByID(id int64) (Build, error) {
	list, err := s.Builds()
	if err != nil {
		return Build{}, err
	}
	for _, b := range list {
		if b.ID == id {
			return b, nil
		}
	}
	return Build{}, ErrNotFound
}

// SetActiveBuild marks one build active.
func (s *Store) SetActiveBuild(id int64) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	tx.Exec(`UPDATE caddy_builds SET active = 0`)
	tx.Exec(`UPDATE caddy_builds SET active = 1, status = 'active' WHERE id = ?`, id)
	tx.Exec(`UPDATE caddy_builds SET status = 'built' WHERE id != ? AND status = 'active'`, id)
	return tx.Commit()
}
