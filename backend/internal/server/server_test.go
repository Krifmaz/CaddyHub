package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Krifmaz/CaddyHub/internal/apply"
	"github.com/Krifmaz/CaddyHub/internal/secrets"
	"github.com/Krifmaz/CaddyHub/internal/store"
)

type client struct {
	t    *testing.T
	base string
	http *http.Client
	csrf string
}

func newTestServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	box, err := secrets.NewBox([]byte("test-key-material-test-key-material"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := New(Options{Store: st, Pipeline: &apply.Pipeline{Store: st}, Version: "test"})
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return ts, st
}

func newClient(t *testing.T, base string) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, base: base, http: &http.Client{Jar: jar}}
}

func (c *client) do(method, path string, body any) (int, map[string]any) {
	c.t.Helper()
	var r *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	} else {
		r = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, c.base+path, r)
	req.Header.Set("Content-Type", "application/json")
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	var raw json.RawMessage
	json.NewDecoder(resp.Body).Decode(&raw)
	json.Unmarshal(raw, &out)
	if out == nil {
		out = map[string]any{"_raw": string(raw)}
	}
	if tok, ok := out["csrf"].(string); ok && tok != "" {
		c.csrf = tok
	}
	return resp.StatusCode, out
}

func TestSetupLoginAndCSRF(t *testing.T) {
	ts, _ := newTestServer(t)
	c := newClient(t, ts.URL)

	if code, me := c.do("GET", "/api/me", nil); code != 200 || me["needs_setup"] != true {
		t.Fatalf("me before setup: %d %v", code, me)
	}
	if code, _ := c.do("GET", "/api/sites", nil); code != 401 {
		t.Fatalf("unauthenticated list: %d", code)
	}
	if code, out := c.do("POST", "/api/setup", map[string]string{"username": "admin", "password": "short"}); code != 400 {
		t.Fatalf("weak password accepted: %d %v", code, out)
	}
	if code, out := c.do("POST", "/api/setup", map[string]string{"username": "admin", "password": "long enough password"}); code != 200 {
		t.Fatalf("setup: %d %v", code, out)
	}
	// Setup only works once.
	other := newClient(t, ts.URL)
	if code, _ := other.do("POST", "/api/setup", map[string]string{"username": "evil", "password": "long enough password"}); code != 409 {
		t.Fatalf("second setup: %d", code)
	}

	// Writes need the CSRF token.
	tok := c.csrf
	c.csrf = ""
	if code, _ := c.do("POST", "/api/sites", map[string]any{}); code != 403 {
		t.Fatalf("missing CSRF: %d", code)
	}
	c.csrf = tok

	site := map[string]any{"name": "app", "hosts": []string{"App.Example.com", "app.example.com"}, "kind": "proxy", "enabled": true,
		"config": map[string]any{"proxy": map[string]any{"upstreams": []string{"localhost:8080", " "}}}}
	code, out := c.do("POST", "/api/sites", site)
	if code != 201 {
		t.Fatalf("create site: %d %v", code, out)
	}
	if hosts := out["hosts"].([]any); len(hosts) != 1 || hosts[0] != "app.example.com" {
		t.Fatalf("hosts not normalized: %v", hosts)
	}
	// Same hostname on another enabled site is rejected.
	if code, _ := c.do("POST", "/api/sites", site); code != 409 {
		t.Fatalf("duplicate host: %d", code)
	}
	// Invalid input gets a helpful 400.
	bad := map[string]any{"hosts": []string{"app.example.com:8080"}, "kind": "proxy", "config": map[string]any{"proxy": map[string]any{"upstreams": []string{"x:1"}}}}
	if code, out := c.do("POST", "/api/sites", bad); code != 400 || !strings.Contains(out["error"].(string), "port") {
		t.Fatalf("host with port: %d %v", code, out)
	}

	// Login with wrong then right password.
	l := newClient(t, ts.URL)
	if code, _ := l.do("POST", "/api/login", map[string]string{"username": "admin", "password": "nope nope nope"}); code != 401 {
		t.Fatalf("bad login: %d", code)
	}
	if code, out := l.do("POST", "/api/login", map[string]string{"username": "admin", "password": "long enough password"}); code != 200 || out["csrf"] == "" {
		t.Fatalf("login: %d %v", code, out)
	}
	if code, _ := l.do("POST", "/api/logout", nil); code != 200 {
		t.Fatal("logout failed")
	}
	if code, _ := l.do("GET", "/api/sites", nil); code != 401 {
		t.Fatalf("after logout: %d", code)
	}
}

func TestRolesAndSecretMasking(t *testing.T) {
	ts, _ := newTestServer(t)
	admin := newClient(t, ts.URL)
	admin.do("POST", "/api/setup", map[string]string{"username": "admin", "password": "long enough password"})
	if code, out := admin.do("POST", "/api/users", map[string]string{"username": "viewer", "password": "viewer password 1", "role": "viewer"}); code != 200 {
		t.Fatalf("create viewer: %d %v", code, out)
	}
	v := newClient(t, ts.URL)
	v.do("POST", "/api/login", map[string]string{"username": "viewer", "password": "viewer password 1"})
	if code, _ := v.do("GET", "/api/sites", nil); code != 200 {
		t.Fatalf("viewer read: %d", code)
	}
	if code, _ := v.do("POST", "/api/sites", map[string]any{}); code != 403 {
		t.Fatalf("viewer write: %d", code)
	}
	if code, _ := v.do("GET", "/api/users", nil); code != 403 {
		t.Fatalf("viewer admin page: %d", code)
	}

	// DNS credential secrets are stored but never returned.
	code, out := admin.do("POST", "/api/dns-credentials", map[string]any{"provider": "cloudflare", "fields": map[string]string{"api_token": "super-secret-token"}})
	if code != 200 {
		t.Fatalf("save credential: %d %v", code, out)
	}
	resp, _ := admin.http.Get(ts.URL + "/api/dns-credentials")
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	resp.Body.Close()
	if strings.Contains(buf.String(), "super-secret-token") {
		t.Fatalf("secret leaked: %s", buf.String())
	}
	// Updating with an empty secret keeps the stored value.
	id := int(out["id"].(float64))
	if code, out := admin.do("PUT", "/api/dns-credentials/"+itoa(id), map[string]any{"provider": "cloudflare", "name": "cf", "fields": map[string]string{"api_token": ""}}); code != 200 || out["set"].(map[string]any)["api_token"] != true {
		t.Fatalf("update keeps secret: %d %v", code, out)
	}

	// The last admin can't be demoted.
	if code, _ := admin.do("PUT", "/api/users/1", map[string]any{"username": "admin", "role": "viewer"}); code != 409 {
		t.Fatalf("demote last admin: %d", code)
	}
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }
