// Package server is CaddyHub's HTTP layer: a JSON REST API under /api and
// the embedded web UI on every other path.
//
// Authentication uses an opaque session cookie (only its SHA-256 is stored)
// plus a per-session CSRF token that the UI sends in X-CSRF-Token on every
// state-changing request. API keys (Authorization: Bearer) skip CSRF.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Krifmaz/CaddyHub/internal/apply"
	"github.com/Krifmaz/CaddyHub/internal/auth"
	"github.com/Krifmaz/CaddyHub/internal/caddy"
	"github.com/Krifmaz/CaddyHub/internal/notify"
	"github.com/Krifmaz/CaddyHub/internal/registry"
	"github.com/Krifmaz/CaddyHub/internal/store"
)

const (
	cookieName      = "caddyhub_session"
	sessionAbsolute = 7 * 24 * time.Hour
	maxBody         = 4 << 20
)

// Options configure the server.
type Options struct {
	Store     *store.Store
	Pipeline  *apply.Pipeline
	Runner    *caddy.Runner
	Admin     *caddy.Admin
	Notifier  *notify.Notifier
	Caps      func() registry.Capabilities
	Log       *slog.Logger
	UI        fs.FS // built web UI (may be empty)
	Version   string
	SetupTok  string // optional token required by first-run setup
	TrustXFF  bool   // trust X-Forwarded-For (panel behind Caddy)
	SecureCk  bool   // set Secure on cookies
	DevNoAuth bool
	Imports   ImportPaths // existing configs offered for import
}

// Server handles HTTP.
type Server struct {
	Options
	mux     *http.ServeMux
	limiter *limiter
}

// New builds the server and its routes.
func New(o Options) *Server {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	s := &Server{Options: o, mux: http.NewServeMux(), limiter: newLimiter(10, 15*time.Minute)}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "same-origin")
	s.mux.ServeHTTP(w, r)
}

// ---------------------------------------------------------------- identity

// principal is the authenticated caller.
type principal struct {
	User    store.User
	Session *store.Session // nil for API keys
	ViaKey  bool
	Role    string
}

type ctxKey struct{}

func who(r *http.Request) *principal {
	p, _ := r.Context().Value(ctxKey{}).(*principal)
	return p
}

func (s *Server) username(r *http.Request) string {
	if p := who(r); p != nil {
		return p.User.Username
	}
	return ""
}

// authenticate resolves the caller from a cookie or API key.
func (s *Server) authenticate(r *http.Request) (*principal, error) {
	if s.DevNoAuth {
		return &principal{User: store.User{ID: 0, Username: "dev", Role: auth.RoleAdmin}, Role: auth.RoleAdmin}, nil
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		k, err := s.Store.APIKeyByHash(auth.TokenHash(strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))))
		if err != nil {
			return nil, errors.New("invalid API key")
		}
		if k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt) {
			return nil, errors.New("API key expired")
		}
		u, err := s.Store.UserByID(k.UserID)
		if err != nil || u.Disabled {
			return nil, errors.New("API key owner disabled")
		}
		s.Store.TouchAPIKey(k.ID)
		role := k.Role
		if !auth.Allows(u.Role, role) { // a key never exceeds its owner
			role = u.Role
		}
		return &principal{User: u, ViaKey: true, Role: role}, nil
	}
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return nil, errors.New("not logged in")
	}
	se, err := s.Store.GetSession(auth.TokenHash(c.Value))
	if err != nil {
		return nil, errors.New("session expired")
	}
	now := time.Now().UTC()
	idle := time.Duration(s.Store.Settings().SessionTimeoutMinutes) * time.Minute
	if now.After(se.ExpiresAt) || (idle > 0 && now.Sub(se.LastSeen) > idle) {
		s.Store.DeleteSession(se.ID)
		return nil, errors.New("session expired")
	}
	u, err := s.Store.UserByID(se.UserID)
	if err != nil || u.Disabled {
		return nil, errors.New("account disabled")
	}
	if now.Sub(se.LastSeen) > 30*time.Second {
		s.Store.TouchSession(se.ID, now)
	}
	return &principal{User: u, Session: &se, Role: u.Role}, nil
}

// guard wraps a handler with authentication, a role check and CSRF.
func (s *Server) guard(role string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := s.authenticate(r)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		if p.Session != nil && p.Session.Pending2FA {
			writeErr(w, http.StatusUnauthorized, "two-factor code required")
			return
		}
		if !auth.Allows(p.Role, role) {
			writeErr(w, http.StatusForbidden, "your role ("+p.Role+") can't do this")
			return
		}
		if p.Session != nil && !safeMethod(r.Method) && r.Header.Get("X-CSRF-Token") != p.Session.CSRF {
			writeErr(w, http.StatusForbidden, "missing or invalid CSRF token; reload the page")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
	}
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

func (s *Server) clientIP(r *http.Request) string {
	if s.TrustXFF {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) audit(r *http.Request, action, target, details string) {
	s.Store.Audit(s.username(r), action, target, details, s.clientIP(r))
}

// ---------------------------------------------------------------- json

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// storeErr maps store errors to HTTP responses.
func storeErr(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if strings.Contains(err.Error(), "UNIQUE constraint") {
		writeErr(w, http.StatusConflict, "an entry with that name already exists")
		return
	}
	writeErr(w, http.StatusInternalServerError, err.Error())
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return 0, false
	}
	return id, true
}

// ---------------------------------------------------------------- rate limit

// limiter counts failed attempts per key in a sliding window.
type limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string][]time.Time
}

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{max: max, window: window, hits: map[string][]time.Time{}}
}

func (l *limiter) prune(key string, now time.Time) []time.Time {
	h := l.hits[key]
	i := 0
	for i < len(h) && now.Sub(h[i]) > l.window {
		i++
	}
	h = h[i:]
	if len(h) == 0 {
		delete(l.hits, key)
	} else {
		l.hits[key] = h
	}
	return h
}

func (l *limiter) blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.prune(key, time.Now())) >= l.max
}

func (l *limiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.hits[key] = append(l.prune(key, now), now)
}

func (l *limiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.hits, key)
}

// ---------------------------------------------------------------- static UI

// spa serves the built UI, falling back to index.html for client routes.
func (s *Server) spa() http.Handler {
	if s.UI == nil {
		return http.HandlerFunc(noUI)
	}
	if _, err := fs.Stat(s.UI, "index.html"); err != nil {
		return http.HandlerFunc(noUI)
	}
	files := http.FileServerFS(s.UI)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p != "" {
			if st, err := fs.Stat(s.UI, p); err == nil && !st.IsDir() {
				if strings.HasPrefix(p, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				files.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFileFS(w, r, s.UI, "index.html")
	})
}

func noUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, "CaddyHub API is running, but the web UI was not built into this binary.\nBuild it with: cd frontend && npm ci && npm run build\n")
}
