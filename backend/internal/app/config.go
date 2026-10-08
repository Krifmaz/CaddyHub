// Package app wires the panel together: configuration, services and
// background jobs.
package app

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config comes entirely from environment variables (and *_FILE Docker
// secrets). Defaults match the shipped docker-compose.yml; nothing is
// specific to any one deployment.
type Config struct {
	Listen        string
	DataDir       string
	SecretKey     string
	SecretKeyFile string

	CaddyBin       string   // binary used for adapt/validate (shared from the caddy container)
	CaddyAdmin     string   // address the panel uses to reach the admin API
	AdminListen    string   // address Caddy's admin endpoint binds to (written into the config)
	AdminOrigins   []string // allowed admin origins
	CaddyfilePath  string   // persisted Caddyfile Caddy starts from
	SecretsDir     string   // shared secrets directory (same path in both containers)
	LogDir         string   // Caddy log directory (same path in both containers)
	CaddyDataDir   string   // Caddy's data dir mounted into the panel (certificates)
	ProbeAddrs     []string // Caddy listeners to probe after apply
	PanelUpstream  string   // how Caddy reaches the panel (when proxying the panel)
	CaddyHost      string   // host Caddy is reachable at for "test route" (e.g. caddy)

	BaseURL            string // public URL of the panel (OIDC redirects, cookies)
	TrustProxyHeaders  bool   // trust X-Forwarded-For from Caddy for client IPs
	SetupToken         string // optional fixed setup token
	InitialAdminUser   string
	InitialAdminPass   string

	DockerHost        string // read-only socket proxy for discovery
	DockerManagerHost string // socket proxy allowing builds/containers (opt-in)
	CaddyImage        string // image repository for builds, e.g. caddyhub-caddy
	CaddyContainer    string // name/label of the caddy container
	BuilderImage      string // xcaddy builder image template

	BackupPassphrase string
	GitHubToken      string // optional, raises GitHub API rate limits for update checks

	DevNoAuth bool // never set in production; for local UI development only
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

// envSecret reads KEY, or the file named by KEY_FILE (Docker secrets).
func envSecret(key string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	if f := os.Getenv(key + "_FILE"); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

func envList(key, def string) []string {
	var out []string
	for _, p := range strings.Split(env(key, def), ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// LoadConfig reads configuration from the environment.
func LoadConfig() Config {
	c := Config{
		Listen:        env("CADDYHUB_LISTEN", ":8080"),
		DataDir:       env("CADDYHUB_DATA_DIR", "/data"),
		SecretKey:     os.Getenv("CADDYHUB_SECRET_KEY"),
		SecretKeyFile: os.Getenv("CADDYHUB_SECRET_KEY_FILE"),

		CaddyBin:      env("CADDYHUB_CADDY_BIN", "/caddy-bin/caddy"),
		CaddyAdmin:    env("CADDYHUB_CADDY_ADMIN", "caddy-admin:2019"),
		CaddyfilePath: env("CADDYHUB_CADDYFILE", "/etc/caddyhub/Caddyfile"),
		SecretsDir:    env("CADDYHUB_SECRETS_DIR", "/run/caddyhub/secrets"),
		LogDir:        env("CADDYHUB_LOG_DIR", "/var/log/caddy"),
		CaddyDataDir:  env("CADDYHUB_CADDY_DATA", "/caddy-data"),
		ProbeAddrs:    envList("CADDYHUB_PROBE", "caddy:80"),
		PanelUpstream: env("CADDYHUB_PANEL_UPSTREAM", "panel:8080"),
		CaddyHost:     env("CADDYHUB_CADDY_HOST", "caddy"),

		BaseURL:           strings.TrimRight(os.Getenv("CADDYHUB_BASE_URL"), "/"),
		TrustProxyHeaders: envBool("CADDYHUB_TRUST_PROXY_HEADERS", false),
		SetupToken:        envSecret("CADDYHUB_SETUP_TOKEN"),
		InitialAdminUser:  os.Getenv("CADDYHUB_INITIAL_ADMIN_USER"),
		InitialAdminPass:  envSecret("CADDYHUB_INITIAL_ADMIN_PASSWORD"),

		DockerHost:        os.Getenv("CADDYHUB_DOCKER_HOST"),
		DockerManagerHost: os.Getenv("CADDYHUB_DOCKER_MANAGER_HOST"),
		CaddyImage:        env("CADDYHUB_CADDY_IMAGE", "caddyhub-caddy"),
		CaddyContainer:    env("CADDYHUB_CADDY_CONTAINER", "caddyhub-caddy"),
		BuilderImage:      env("CADDYHUB_BUILDER_IMAGE", "caddy:builder"),

		BackupPassphrase: envSecret("CADDYHUB_BACKUP_PASSPHRASE"),
		GitHubToken:      envSecret("CADDYHUB_GITHUB_TOKEN"),
		DevNoAuth:        envBool("CADDYHUB_DEV_NO_AUTH", false),
	}
	c.AdminListen = env("CADDYHUB_ADMIN_LISTEN", c.CaddyAdmin)
	c.AdminOrigins = envList("CADDYHUB_ADMIN_ORIGINS", c.CaddyAdmin)
	if strings.HasPrefix(c.AdminListen, "unix/") {
		c.AdminOrigins = nil
	}
	return c
}

// Path returns a path inside the data directory.
func (c Config) Path(parts ...string) string {
	return filepath.Join(append([]string{c.DataDir}, parts...)...)
}

// SessionTTL bounds.
const (
	sessionAbsolute = 7 * 24 * time.Hour
)
