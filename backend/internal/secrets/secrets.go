// Package secrets handles encryption at rest and the materialization of
// secrets into files that Caddy reads through {file.*} placeholders, so that
// secrets never appear in the Caddyfile, the database (unencrypted), logs or
// backups.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Box encrypts and decrypts with AES-256-GCM.
type Box struct {
	aead cipher.AEAD
	key  []byte
}

// NewBox derives a 32-byte key from the given material (raw 32 bytes,
// base64 of 32 bytes, or any passphrase which is hashed with SHA-256).
func NewBox(material []byte) (*Box, error) {
	m := strings.TrimSpace(string(material))
	if m == "" {
		return nil, errors.New("empty secret key")
	}
	var key []byte
	if b, err := base64.StdEncoding.DecodeString(m); err == nil && len(b) == 32 {
		key = b
	} else {
		h := sha256.Sum256([]byte(m))
		key = h[:]
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead, key: key}, nil
}

// Seal encrypts plaintext. Output: nonce || ciphertext.
func (b *Box) Seal(plain []byte) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return b.aead.Seal(nonce, nonce, plain, nil), nil
}

// Open decrypts data produced by Seal.
func (b *Box) Open(data []byte) ([]byte, error) {
	ns := b.aead.NonceSize()
	if len(data) < ns {
		return nil, errors.New("ciphertext too short")
	}
	return b.aead.Open(nil, data[:ns], data[ns:], nil)
}

// KeyMaterial returns the raw key encoded as base64 (for encrypted backups).
func (b *Box) KeyMaterial() string { return base64.StdEncoding.EncodeToString(b.key) }

// LoadKey resolves the master key: env var, then *_FILE (Docker secret),
// then a generated key file in dataDir. Returns the key and where it came from.
func LoadKey(envVal, envFile, dataDir string) ([]byte, string, error) {
	if envVal != "" {
		return []byte(envVal), "env", nil
	}
	if envFile != "" {
		b, err := os.ReadFile(envFile)
		if err != nil {
			return nil, "", fmt.Errorf("read secret key file: %w", err)
		}
		return b, "file", nil
	}
	p := filepath.Join(dataDir, "secret.key")
	if b, err := os.ReadFile(p); err == nil {
		return b, "generated", nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", err
	}
	enc := []byte(base64.StdEncoding.EncodeToString(raw) + "\n")
	if err := os.WriteFile(p, enc, 0o600); err != nil {
		return nil, "", fmt.Errorf("write generated secret key: %w", err)
	}
	return enc, "generated", nil
}

// IsRef reports whether a stored value is a reference rather than a secret.
func IsRef(v string) bool {
	return strings.HasPrefix(v, "env:") || strings.HasPrefix(v, "file:")
}

// RefPlaceholder converts "env:NAME" / "file:/path" to a Caddy placeholder.
func RefPlaceholder(v string) (string, bool) {
	switch {
	case strings.HasPrefix(v, "env:"):
		name := strings.TrimPrefix(v, "env:")
		if !validEnvName(name) {
			return "", false
		}
		return "{env." + name + "}", true
	case strings.HasPrefix(v, "file:"):
		p := strings.TrimPrefix(v, "file:")
		if p == "" || strings.ContainsAny(p, "{} \t\n") {
			return "", false
		}
		return "{file." + p + "}", true
	}
	return "", false
}

func validEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// Materializer writes secret files into a directory shared with Caddy
// (mounted at the same path in both containers).
type Materializer struct {
	Dir string
	mu  sync.Mutex
}

// FileRef writes value to <Dir>/<name> and returns the {file.*} placeholder.
// Names are sanitized; files are 0600 and the directory 0700.
func (m *Materializer) FileRef(name, value string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	name = sanitize(name)
	if err := os.MkdirAll(m.Dir, 0o700); err != nil {
		return "", err
	}
	p := filepath.Join(m.Dir, name)
	cur, err := os.ReadFile(p)
	if err != nil || string(cur) != value {
		tmp := p + ".tmp"
		if err := os.WriteFile(tmp, []byte(value), 0o600); err != nil {
			return "", err
		}
		if err := os.Rename(tmp, p); err != nil {
			return "", err
		}
	}
	return "{file." + filepath.ToSlash(p) + "}", nil
}

// Prune deletes files in Dir not in keep (by sanitized name).
func (m *Materializer) Prune(keep []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := map[string]bool{}
	for _, n := range keep {
		k[sanitize(n)] = true
	}
	ents, err := os.ReadDir(m.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range ents {
		if !e.IsDir() && !k[e.Name()] {
			os.Remove(filepath.Join(m.Dir, e.Name()))
		}
	}
	return nil
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := strings.TrimLeft(b.String(), ".")
	if out == "" {
		out = "_"
	}
	return out
}

// Redact replaces any of the given secret values in s with "***".
func Redact(s string, values ...string) string {
	vs := append([]string(nil), values...)
	sort.Slice(vs, func(i, j int) bool { return len(vs[i]) > len(vs[j]) })
	for _, v := range vs {
		if len(v) >= 4 {
			s = strings.ReplaceAll(s, v, "***")
		}
	}
	return s
}
