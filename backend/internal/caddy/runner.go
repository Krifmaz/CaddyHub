// Package caddy talks to Caddy through its stable interfaces only: the CLI
// (adapt, validate, version, list-modules) and the admin API (/load, /config,
// /reverse_proxy/upstreams, /metrics, /stop).
package caddy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Krifmaz/CaddyHub/internal/registry"
)

// Runner executes a Caddy binary.
type Runner struct {
	Bin     string        // path to the caddy binary
	Timeout time.Duration // per command
	// ExtraEnv is appended to the command environment (e.g. env refs that
	// the generated config uses via {env.*}).
	ExtraEnv []string
}

// NewRunner returns a runner with defaults.
func NewRunner(bin string) *Runner {
	return &Runner{Bin: bin, Timeout: 60 * time.Second}
}

// Available reports whether the binary exists.
func (r *Runner) Available() bool {
	if r == nil || r.Bin == "" {
		return false
	}
	st, err := os.Stat(r.Bin)
	return err == nil && !st.IsDir()
}

func (r *Runner) run(ctx context.Context, dir string, args ...string) (stdout, stderr []byte, err error) {
	if !r.Available() {
		return nil, nil, fmt.Errorf("caddy binary not found at %q", r.Bin)
	}
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.Bin, args...)
	cmd.Dir = dir
	// Isolate storage so validation never touches real certificates.
	env := append(os.Environ(),
		"XDG_DATA_HOME="+filepath.Join(dir, "data"),
		"XDG_CONFIG_HOME="+filepath.Join(dir, "config"),
		"HOME="+dir,
		"APPDATA="+filepath.Join(dir, "appdata"),
	)
	cmd.Env = append(env, r.ExtraEnv...)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err = cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("caddy %s timed out", args[0])
	}
	return o.Bytes(), e.Bytes(), err
}

func tempConfig(caddyfile string) (dir, path string, err error) {
	dir, err = os.MkdirTemp("", "caddyhub-*")
	if err != nil {
		return "", "", err
	}
	path = filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(path, []byte(caddyfile), 0o600); err != nil {
		os.RemoveAll(dir)
		return "", "", err
	}
	return dir, path, nil
}

// AdaptResult is the output of `caddy adapt`.
type AdaptResult struct {
	JSON     json.RawMessage `json:"json"`
	Warnings []string        `json:"warnings"`
}

// Adapt converts a Caddyfile to JSON using the binary.
func (r *Runner) Adapt(ctx context.Context, caddyfile string) (*AdaptResult, error) {
	dir, path, err := tempConfig(caddyfile)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	out, errOut, err := r.run(ctx, dir, "adapt", "--config", path, "--adapter", "caddyfile")
	msgs := parseLogMessages(errOut, path)
	if err != nil {
		return nil, &Error{Stage: "adapt", Messages: msgs, Err: err}
	}
	res := &AdaptResult{JSON: bytes.TrimSpace(out)}
	for _, m := range msgs {
		if m.Level == "warn" {
			res.Warnings = append(res.Warnings, m.Text)
		}
	}
	return res, nil
}

// Validate runs `caddy validate` (adapt + provision, without starting).
func (r *Runner) Validate(ctx context.Context, caddyfile string) error {
	dir, path, err := tempConfig(caddyfile)
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	_, errOut, err := r.run(ctx, dir, "validate", "--config", path, "--adapter", "caddyfile")
	if err != nil {
		return &Error{Stage: "validate", Messages: parseLogMessages(errOut, path), Err: err}
	}
	return nil
}

// Version returns `caddy version` output.
func (r *Runner) Version(ctx context.Context) (string, error) {
	out, _, err := r.run(ctx, os.TempDir(), "version")
	return strings.TrimSpace(string(out)), err
}

// Capabilities detects version and modules.
func (r *Runner) Capabilities(ctx context.Context) (registry.Capabilities, error) {
	caps := registry.Capabilities{Modules: map[string]bool{}, Packages: map[string]string{}}
	v, err := r.Version(ctx)
	if err != nil {
		return caps, err
	}
	caps.VersionS = strings.Fields(v + " ")[0]
	caps.Version = registry.ParseVersion(v)
	out, _, err := r.run(ctx, os.TempDir(), "list-modules", "--packages", "--versions")
	if err != nil {
		// older/newer CLIs may not support the flags; fall back to plain
		out, _, err = r.run(ctx, os.TempDir(), "list-modules")
		if err != nil {
			return caps, err
		}
	}
	parseModules(string(out), &caps)
	caps.Detected = true
	return caps, nil
}

// parseModules parses list-modules output. Lines look like:
//
//	http.handlers.reverse_proxy v2.11.7 github.com/caddyserver/caddy/v2/...
//	dns.providers.cloudflare v0.2.1 github.com/caddy-dns/cloudflare
//
// Section headers ("Standard modules: 120") and blank lines are ignored.
func parseModules(out string, caps *registry.Capabilities) {
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 || strings.HasSuffix(f[0], ":") || strings.Contains(sc.Text(), " modules:") {
			continue
		}
		id := f[0]
		if !looksLikeModuleID(id) {
			continue
		}
		caps.Modules[id] = true
		if len(f) >= 3 {
			caps.Packages[id] = f[2] + "@" + f[1]
		} else if len(f) == 2 {
			caps.Packages[id] = f[1]
		}
	}
}

func looksLikeModuleID(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// Message is one structured log line from the CLI.
type Message struct {
	Level string `json:"level"`
	Text  string `json:"text"`
}

// Error is a CLI failure with readable messages.
type Error struct {
	Stage    string
	Messages []Message
	Err      error
}

func (e *Error) Error() string {
	var parts []string
	for _, m := range e.Messages {
		if m.Level == "error" || m.Level == "fatal" || m.Level == "" {
			parts = append(parts, m.Text)
		}
	}
	if len(parts) == 0 {
		return e.Stage + ": " + e.Err.Error()
	}
	return e.Stage + ": " + strings.Join(parts, "; ")
}

func (e *Error) Unwrap() error { return e.Err }

// Details returns all messages (for UI display).
func (e *Error) Details() []Message { return e.Messages }

// AsError extracts a *Error.
func AsError(err error) (*Error, bool) {
	var ce *Error
	ok := errors.As(err, &ce)
	return ce, ok
}

// parseLogMessages turns Caddy's JSON log lines (or plain text) into
// messages, replacing the temp file path with "Caddyfile" for readability.
func parseLogMessages(b []byte, tmpPath string) []Message {
	var out []Message
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil {
			lvl, _ := m["level"].(string)
			msg, _ := m["msg"].(string)
			if e, ok := m["error"].(string); ok && e != "" {
				msg += ": " + e
			}
			if lvl == "info" || lvl == "debug" {
				continue
			}
			if a, ok := m["adapter"].(string); ok && a != "" && lvl == "warn" {
				if f, ok := m["file"].(string); ok {
					msg += fmt.Sprintf(" (%s:%v)", filepath.Base(f), m["line"])
				}
			}
			out = append(out, Message{Level: lvl, Text: cleanPath(msg, tmpPath)})
			continue
		}
		out = append(out, Message{Level: "error", Text: cleanPath(line, tmpPath)})
	}
	return out
}

func cleanPath(s, p string) string {
	if p == "" {
		return s
	}
	s = strings.ReplaceAll(s, p, "Caddyfile")
	return strings.ReplaceAll(s, filepath.ToSlash(p), "Caddyfile")
}
