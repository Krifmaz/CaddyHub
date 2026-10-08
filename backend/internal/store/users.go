package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// User is a panel account.
type User struct {
	ID           int64      `json:"id"`
	Username     string     `json:"username"`
	PasswordHash string     `json:"-"`
	Role         string     `json:"role"`
	TOTPSecret   string     `json:"-"` // decrypted
	TOTPEnabled  bool       `json:"totp_enabled"`
	OIDCSubject  string     `json:"oidc_subject,omitempty"`
	Disabled     bool       `json:"disabled"`
	CreatedAt    time.Time  `json:"created_at"`
	LastLogin    *time.Time `json:"last_login,omitempty"`
}

const userCols = `id, username, password_hash, role, totp_secret, totp_enabled, COALESCE(oidc_subject, ''), disabled, created_at, last_login`

func (s *Store) scanUser(sc interface{ Scan(...any) error }) (User, error) {
	var u User
	var totp []byte
	var te, dis int
	var ll sql.NullTime
	if err := sc.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &totp, &te, &u.OIDCSubject, &dis, &u.CreatedAt, &ll); err != nil {
		return u, err
	}
	u.TOTPEnabled, u.Disabled = te == 1, dis == 1
	if ll.Valid {
		t := ll.Time
		u.LastLogin = &t
	}
	if len(totp) > 0 {
		if b, err := s.box.Open(totp); err == nil {
			u.TOTPSecret = string(b)
		}
	}
	return u, nil
}

// UserCount returns the number of users.
func (s *Store) UserCount() int {
	var n int
	s.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n
}

// Users lists users.
func (s *Store) Users() ([]User, error) {
	rows, err := s.DB.Query(`SELECT ` + userCols + ` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := s.scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UserByID returns a user.
func (s *Store) UserByID(id int64) (User, error) {
	u, err := s.scanUser(s.DB.QueryRow(`SELECT `+userCols+` FROM users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

// UserByName returns a user by username (case-insensitive).
func (s *Store) UserByName(name string) (User, error) {
	u, err := s.scanUser(s.DB.QueryRow(`SELECT `+userCols+` FROM users WHERE username = ?`, strings.TrimSpace(name)))
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

// UserByOIDC returns a user by OIDC subject.
func (s *Store) UserByOIDC(sub string) (User, error) {
	u, err := s.scanUser(s.DB.QueryRow(`SELECT `+userCols+` FROM users WHERE oidc_subject = ?`, sub))
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

// SaveUser inserts or updates a user (TOTP secret is encrypted).
func (s *Store) SaveUser(u User) (User, error) {
	var totp []byte
	if u.TOTPSecret != "" {
		enc, err := s.box.Seal([]byte(u.TOTPSecret))
		if err != nil {
			return u, err
		}
		totp = enc
	}
	var oidc any
	if u.OIDCSubject != "" {
		oidc = u.OIDCSubject
	}
	if u.ID == 0 {
		res, err := s.DB.Exec(`INSERT INTO users(username, password_hash, role, totp_secret, totp_enabled, oidc_subject, disabled) VALUES(?,?,?,?,?,?,?)`,
			strings.TrimSpace(u.Username), u.PasswordHash, u.Role, totp, boolInt(u.TOTPEnabled), oidc, boolInt(u.Disabled))
		if err != nil {
			return u, err
		}
		u.ID, _ = res.LastInsertId()
		u.CreatedAt = time.Now().UTC()
		return u, nil
	}
	_, err := s.DB.Exec(`UPDATE users SET username=?, password_hash=?, role=?, totp_secret=?, totp_enabled=?, oidc_subject=?, disabled=? WHERE id=?`,
		strings.TrimSpace(u.Username), u.PasswordHash, u.Role, totp, boolInt(u.TOTPEnabled), oidc, boolInt(u.Disabled), u.ID)
	return u, err
}

// DeleteUser removes a user.
func (s *Store) DeleteUser(id int64) error {
	_, err := s.DB.Exec(`DELETE FROM users WHERE id = ?`, id)
	return err
}

// AdminCount counts enabled admins.
func (s *Store) AdminCount() int {
	var n int
	s.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0`).Scan(&n)
	return n
}

// TouchLogin sets last_login.
func (s *Store) TouchLogin(id int64) {
	s.DB.Exec(`UPDATE users SET last_login = ? WHERE id = ?`, time.Now().UTC(), id)
}

// ---------------------------------------------------------------- sessions

// Session is a login session. ID is the SHA-256 of the cookie token.
type Session struct {
	ID         string
	UserID     int64
	CSRF       string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeen   time.Time
	IP         string
	UserAgent  string
	Pending2FA bool
}

// CreateSession stores a session.
func (s *Store) CreateSession(se Session) error {
	_, err := s.DB.Exec(`INSERT INTO sessions(id, user_id, csrf, created_at, expires_at, last_seen, ip, user_agent, pending_2fa) VALUES(?,?,?,?,?,?,?,?,?)`,
		se.ID, se.UserID, se.CSRF, se.CreatedAt, se.ExpiresAt, se.LastSeen, se.IP, se.UserAgent, boolInt(se.Pending2FA))
	return err
}

// GetSession returns a session by ID hash.
func (s *Store) GetSession(id string) (Session, error) {
	var se Session
	var p int
	err := s.DB.QueryRow(`SELECT id, user_id, csrf, created_at, expires_at, last_seen, COALESCE(ip,''), COALESCE(user_agent,''), pending_2fa FROM sessions WHERE id = ?`, id).
		Scan(&se.ID, &se.UserID, &se.CSRF, &se.CreatedAt, &se.ExpiresAt, &se.LastSeen, &se.IP, &se.UserAgent, &p)
	if errors.Is(err, sql.ErrNoRows) {
		return se, ErrNotFound
	}
	se.Pending2FA = p == 1
	return se, err
}

// TouchSession updates last_seen.
func (s *Store) TouchSession(id string, t time.Time) {
	s.DB.Exec(`UPDATE sessions SET last_seen = ? WHERE id = ?`, t, id)
}

// CompleteSession2FA clears the pending flag.
func (s *Store) CompleteSession2FA(id string) error {
	_, err := s.DB.Exec(`UPDATE sessions SET pending_2fa = 0 WHERE id = ?`, id)
	return err
}

// DeleteSession removes a session.
func (s *Store) DeleteSession(id string) { s.DB.Exec(`DELETE FROM sessions WHERE id = ?`, id) }

// DeleteUserSessions removes all sessions of a user (e.g. password change).
func (s *Store) DeleteUserSessions(uid int64, except string) {
	s.DB.Exec(`DELETE FROM sessions WHERE user_id = ? AND id != ?`, uid, except)
}

// PruneSessions deletes expired sessions.
func (s *Store) PruneSessions() {
	s.DB.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now().UTC())
}

// ---------------------------------------------------------------- API keys

// APIKey is a scripted-access key. Only its hash is stored.
type APIKey struct {
	ID        int64      `json:"id"`
	Name      string     `json:"name"`
	Prefix    string     `json:"prefix"`
	Hash      string     `json:"-"`
	Role      string     `json:"role"`
	UserID    int64      `json:"user_id"`
	CreatedAt time.Time  `json:"created_at"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// CreateAPIKey stores a key.
func (s *Store) CreateAPIKey(k APIKey) (APIKey, error) {
	res, err := s.DB.Exec(`INSERT INTO api_keys(name, prefix, hash, role, user_id, expires_at) VALUES(?,?,?,?,?,?)`, k.Name, k.Prefix, k.Hash, k.Role, k.UserID, k.ExpiresAt)
	if err != nil {
		return k, err
	}
	k.ID, _ = res.LastInsertId()
	k.CreatedAt = time.Now().UTC()
	return k, nil
}

func scanKey(sc interface{ Scan(...any) error }) (APIKey, error) {
	var k APIKey
	var lu, ex sql.NullTime
	var uid sql.NullInt64
	err := sc.Scan(&k.ID, &k.Name, &k.Prefix, &k.Hash, &k.Role, &uid, &k.CreatedAt, &lu, &ex)
	if lu.Valid {
		t := lu.Time
		k.LastUsed = &t
	}
	if ex.Valid {
		t := ex.Time
		k.ExpiresAt = &t
	}
	k.UserID = uid.Int64
	return k, err
}

// APIKeys lists keys.
func (s *Store) APIKeys() ([]APIKey, error) {
	rows, err := s.DB.Query(`SELECT id, name, prefix, hash, role, user_id, created_at, last_used, expires_at FROM api_keys ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIKey{}
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// APIKeyByHash finds a key by token hash.
func (s *Store) APIKeyByHash(h string) (APIKey, error) {
	k, err := scanKey(s.DB.QueryRow(`SELECT id, name, prefix, hash, role, user_id, created_at, last_used, expires_at FROM api_keys WHERE hash = ?`, h))
	if errors.Is(err, sql.ErrNoRows) {
		return k, ErrNotFound
	}
	return k, err
}

// TouchAPIKey updates last_used.
func (s *Store) TouchAPIKey(id int64) {
	s.DB.Exec(`UPDATE api_keys SET last_used = ? WHERE id = ?`, time.Now().UTC(), id)
}

// DeleteAPIKey removes a key.
func (s *Store) DeleteAPIKey(id int64) error {
	_, err := s.DB.Exec(`DELETE FROM api_keys WHERE id = ?`, id)
	return err
}
