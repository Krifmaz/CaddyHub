package caddy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Admin is a client for Caddy's admin API. Address may be "host:port",
// "http://host:port" or "unix//path/to/socket".
type Admin struct {
	base   string
	host   string // Host header (must match admin origins)
	client *http.Client
}

// NewAdmin creates an admin client.
func NewAdmin(address string) *Admin {
	a := &Admin{}
	tr := &http.Transport{MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second}
	switch {
	case strings.HasPrefix(address, "unix/"):
		sock := strings.TrimPrefix(address, "unix/")
		if i := strings.IndexByte(sock, '|'); i >= 0 { // strip file mode suffix
			sock = sock[:i]
		}
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}
		a.base = "http://localhost"
		a.host = "localhost"
	default:
		addr := strings.TrimPrefix(strings.TrimPrefix(address, "http://"), "https://")
		a.base = "http://" + addr
		a.host = addr
	}
	a.client = &http.Client{Transport: tr, Timeout: 30 * time.Second}
	return a
}

// APIError is a non-2xx admin response.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	msg := strings.TrimSpace(e.Body)
	var j struct {
		Error string `json:"error"`
	}
	if json.Unmarshal([]byte(msg), &j) == nil && j.Error != "" {
		msg = j.Error
	}
	return fmt.Sprintf("admin API %d: %s", e.Status, msg)
}

func (a *Admin) do(ctx context.Context, method, path, ctype string, body []byte, hdr map[string]string) ([]byte, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, r)
	if err != nil {
		return nil, err
	}
	req.Host = a.host
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode/100 != 2 {
		return b, &APIError{Status: resp.StatusCode, Body: string(b)}
	}
	return b, nil
}

// Ping checks that the admin API answers.
func (a *Admin) Ping(ctx context.Context) error {
	_, err := a.do(ctx, http.MethodGet, "/config/", "", nil, nil)
	return err
}

// LoadCaddyfile loads a Caddyfile via POST /load. Caddy adapts it with the
// running binary and atomically rolls back on failure. must-revalidate
// forces a reload even if the config is unchanged (used to re-trigger
// certificate management).
func (a *Admin) LoadCaddyfile(ctx context.Context, caddyfile string, force bool) error {
	h := map[string]string{}
	if force {
		h["Cache-Control"] = "must-revalidate"
	}
	_, err := a.do(ctx, http.MethodPost, "/load", "text/caddyfile", []byte(caddyfile), h)
	return err
}

// LoadJSON loads a JSON config (used to restore an exact previous state).
func (a *Admin) LoadJSON(ctx context.Context, cfg []byte) error {
	_, err := a.do(ctx, http.MethodPost, "/load", "application/json", cfg, map[string]string{"Cache-Control": "must-revalidate"})
	return err
}

// Config returns the running JSON config (GET /config/).
func (a *Admin) Config(ctx context.Context) (json.RawMessage, error) {
	b, err := a.do(ctx, http.MethodGet, "/config/", "", nil, nil)
	return json.RawMessage(b), err
}

// Upstream is an entry of /reverse_proxy/upstreams.
type Upstream struct {
	Address     string `json:"address"`
	NumRequests int    `json:"num_requests"`
	Fails       int    `json:"fails"`
}

// Upstreams returns reverse proxy upstream status.
func (a *Admin) Upstreams(ctx context.Context) ([]Upstream, error) {
	b, err := a.do(ctx, http.MethodGet, "/reverse_proxy/upstreams", "", nil, nil)
	if err != nil {
		return nil, err
	}
	var out []Upstream
	return out, json.Unmarshal(b, &out)
}

// Metrics returns the Prometheus exposition text from the admin endpoint.
func (a *Admin) Metrics(ctx context.Context) (string, error) {
	b, err := a.do(ctx, http.MethodGet, "/metrics", "", nil, nil)
	return string(b), err
}

// Stop asks Caddy to exit (the container restart policy brings it back).
func (a *Admin) Stop(ctx context.Context) error {
	_, err := a.do(ctx, http.MethodPost, "/stop", "", nil, nil)
	return err
}

// WaitReady polls until the admin API responds or the timeout elapses.
func (a *Admin) WaitReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		c, cancel := context.WithTimeout(ctx, 3*time.Second)
		last = a.Ping(c)
		cancel()
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("caddy admin API not ready after %s: %w", timeout, last)
}
