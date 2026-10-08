// Package model defines the structured configuration that CaddyHub owns.
// The SQLite store persists these types and the generator turns them into a
// Caddyfile. Nothing here is specific to any particular deployment.
package model

import "time"

// Site kinds.
const (
	KindProxy    = "proxy"
	KindStatic   = "static"
	KindRedirect = "redirect"
	KindRespond  = "respond"
	// KindNone has no structured handler: everything is in the raw snippet
	// (used for imported sites the importer could only partially map).
	KindNone = "none"
)

// TLS modes.
const (
	TLSAuto     = "auto"     // ACME, using the domain's challenge settings
	TLSInternal = "internal" // Caddy's internal CA
	TLSCustom   = "custom"   // user-supplied cert/key files
	TLSOff      = "off"      // plain HTTP only
)

// ACME challenge types per domain.
const (
	ChallengeHTTP    = "http-01"
	ChallengeTLSALPN = "tls-alpn-01"
	ChallengeDNS     = "dns-01"
)

// Site is one entry in the GUI: a set of hostnames with a handler.
type Site struct {
	ID        int64      `json:"id"`
	Name      string     `json:"name"`
	Hosts     []string   `json:"hosts"`
	Kind      string     `json:"kind"`
	Enabled   bool       `json:"enabled"`
	Position  int        `json:"position"`
	Tags      []string   `json:"tags"`
	Config    SiteConfig `json:"config"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// SiteConfig holds every per-site option. It is stored as JSON so new
// options can be added without schema changes; zero values mean "default".
type SiteConfig struct {
	// Handler config
	Proxy    *ProxyConfig    `json:"proxy,omitempty"`
	Static   *StaticConfig   `json:"static,omitempty"`
	Redirect *RedirectConfig `json:"redirect,omitempty"`
	Respond  *RespondConfig  `json:"respond,omitempty"`

	// Extra path-based routes evaluated (in order) before the main handler.
	Routes []Route `json:"routes,omitempty"`

	TLS          TLSConfig `json:"tls"`
	HTTPRedirect *bool     `json:"http_redirect,omitempty"` // nil = true (Caddy default)
	WWWRedirect  string    `json:"www_redirect,omitempty"`  // "", "to_www", "to_apex"
	Compression  []string  `json:"compression,omitempty"`   // e.g. ["zstd","gzip"]

	HeadersSet    map[string]string `json:"headers_set,omitempty"`
	HeadersRemove []string          `json:"headers_remove,omitempty"`

	MaxBodySize string `json:"max_body_size,omitempty"` // e.g. "10MB"

	Snippets []string `json:"snippets,omitempty"` // names of reusable snippets to import

	Access          AccessConfig `json:"access"`
	Maintenance     bool         `json:"maintenance,omitempty"`
	MaintenanceBody string       `json:"maintenance_body,omitempty"`

	AccessLog *bool `json:"access_log,omitempty"` // nil = true

	// Raw Caddyfile appended inside the site block (escape hatch).
	Raw string `json:"raw,omitempty"`
}

// Route is a path-matched handler inside a site.
type Route struct {
	Path        string          `json:"path"` // e.g. /api/*
	StripPrefix bool            `json:"strip_prefix,omitempty"`
	Kind        string          `json:"kind"`
	Proxy       *ProxyConfig    `json:"proxy,omitempty"`
	Static      *StaticConfig   `json:"static,omitempty"`
	Redirect    *RedirectConfig `json:"redirect,omitempty"`
	Respond     *RespondConfig  `json:"respond,omitempty"`
}

type ProxyConfig struct {
	Upstreams []string `json:"upstreams"` // host:port or scheme://host:port

	LBPolicy      string `json:"lb_policy,omitempty"` // random, round_robin, least_conn, ip_hash, first, ...
	LBRetries     int    `json:"lb_retries,omitempty"`
	LBTryDuration string `json:"lb_try_duration,omitempty"`

	// Active health checks
	HealthURI      string `json:"health_uri,omitempty"`
	HealthInterval string `json:"health_interval,omitempty"`
	HealthTimeout  string `json:"health_timeout,omitempty"`
	HealthStatus   string `json:"health_status,omitempty"`

	// Passive health checks
	FailDuration    string `json:"fail_duration,omitempty"`
	MaxFails        int    `json:"max_fails,omitempty"`
	UnhealthyStatus string `json:"unhealthy_status,omitempty"`

	TLSSkipVerify bool   `json:"tls_skip_verify,omitempty"`
	TLSServerName string `json:"tls_server_name,omitempty"`
	H2C           bool   `json:"h2c,omitempty"`   // gRPC over cleartext / h2c upstreams
	HTTP2         bool   `json:"http2,omitempty"` // force HTTP/2 to TLS upstreams (gRPC)

	DialTimeout           string `json:"dial_timeout,omitempty"`
	ResponseHeaderTimeout string `json:"response_header_timeout,omitempty"`
	ReadTimeout           string `json:"read_timeout,omitempty"`
	WriteTimeout          string `json:"write_timeout,omitempty"`

	FlushInterval  string            `json:"flush_interval,omitempty"`   // "-1" for streaming
	PassHostHeader *bool             `json:"pass_host_header,omitempty"` // nil = true (Caddy default)
	HeaderUp       map[string]string `json:"header_up,omitempty"`
	HeaderDown     map[string]string `json:"header_down,omitempty"`
	// Websockets are proxied transparently by Caddy; the flag only adds
	// streaming-friendly settings and documents intent.
	Websocket bool `json:"websocket,omitempty"`
}

type StaticConfig struct {
	Root   string `json:"root"`
	Browse bool   `json:"browse,omitempty"`
	SPA    bool   `json:"spa,omitempty"` // try_files {path} /index.html
}

type RedirectConfig struct {
	To       string `json:"to"`
	Code     int    `json:"code,omitempty"` // default 302
	KeepPath bool   `json:"keep_path,omitempty"`
}

type RespondConfig struct {
	Body        string `json:"body,omitempty"`
	Status      int    `json:"status,omitempty"`
	ContentType string `json:"content_type,omitempty"`
}

type TLSConfig struct {
	Mode     string `json:"mode,omitempty"` // auto (default), internal, custom, off
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
}

type AccessConfig struct {
	BasicAuth   []BasicAuthUser `json:"basic_auth,omitempty"`
	AllowCIDRs  []string        `json:"allow_cidrs,omitempty"`
	DenyCIDRs   []string        `json:"deny_cidrs,omitempty"`
	ForwardAuth *ForwardAuth    `json:"forward_auth,omitempty"`
	RateLimit   *RateLimit      `json:"rate_limit,omitempty"`
	CrowdSec    bool            `json:"crowdsec,omitempty"`
}

type BasicAuthUser struct {
	Username string `json:"username"`
	// Hash is a bcrypt hash (what Caddy's basic_auth expects). Plaintext is
	// never stored; the API hashes on write.
	Hash string `json:"hash"`
}

type ForwardAuth struct {
	Preset      string   `json:"preset,omitempty"` // authelia, authentik, custom
	Upstream    string   `json:"upstream"`
	URI         string   `json:"uri"`
	CopyHeaders []string `json:"copy_headers,omitempty"`
}

type RateLimit struct {
	Events int    `json:"events"`
	Window string `json:"window"`
	Key    string `json:"key,omitempty"` // default {remote_host}
}

// Domain is a base domain (zone) the user manages certificates for.
type Domain struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"` // e.g. example.com
	Challenge    string `json:"challenge"`
	CredentialID *int64 `json:"credential_id,omitempty"` // DNS credential for dns-01
	Wildcard     bool   `json:"wildcard"`                // issue *.name (dns-01 only), off by default
	// Optional overrides; empty means use global settings.
	PropagationDelay   string    `json:"propagation_delay,omitempty"`
	PropagationTimeout string    `json:"propagation_timeout,omitempty"`
	Resolvers          []string  `json:"resolvers,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
}

// DNSCredential is a provider account. Field values are encrypted at rest;
// a value may also be a reference: "env:NAME" or "file:/path".
type DNSCredential struct {
	ID        int64             `json:"id"`
	Name      string            `json:"name"`
	Provider  string            `json:"provider"`
	Fields    map[string]string `json:"-"` // decrypted, never serialized
	CreatedAt time.Time         `json:"created_at"`
}

// Snippet is a reusable Caddyfile fragment, imported by sites.
type Snippet struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Body        string `json:"body"`
}

// RawBlock is top-level Caddyfile text kept verbatim (e.g. unparsed import).
type RawBlock struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Body     string `json:"body"`
	Enabled  bool   `json:"enabled"`
	Position int    `json:"position"`
	Source   string `json:"source"` // "import" or "user"
}

// Settings are global options. Stored as a single JSON document.
type Settings struct {
	SetupComplete bool   `json:"setup_complete"`
	ACMEEmail     string `json:"acme_email"`
	ACMECA        string `json:"acme_ca"`          // preset id or URL
	ACMECAURL     string `json:"acme_ca_url"`      // custom directory URL
	ACMECARoot    string `json:"acme_ca_root"`     // path to PEM for custom/internal CA
	ACMEEABKeyID  string `json:"acme_eab_key_id"`  // for ZeroSSL / custom CAs
	ACMEEABMacRef string `json:"acme_eab_mac_ref"` // secret ref (encrypted in secrets table)

	Resolvers          []string `json:"resolvers"`       // DNS propagation check resolvers
	ResolverPreset     string   `json:"resolver_preset"` // quad9, cloudflare, google, custom, system
	PropagationDelay   string   `json:"propagation_delay"`
	PropagationTimeout string   `json:"propagation_timeout"`

	TrustedProxies TrustedProxies `json:"trusted_proxies"`

	Metrics          bool   `json:"metrics"`
	DefaultAccessLog bool   `json:"default_access_log"`
	LogRollSize      string `json:"log_roll_size"`
	LogRollKeep      int    `json:"log_roll_keep"`

	CrowdSec CrowdSecSettings `json:"crowdsec"`

	CertAlertDays []int `json:"cert_alert_days"`

	PanelDomain string `json:"panel_domain"` // optional: serve the panel itself through Caddy

	DryRun bool `json:"dry_run"` // global "always dry-run" safety toggle

	Backup                BackupSettings `json:"backup"`
	OIDC                  OIDCSettings   `json:"oidc"`
	SessionTimeoutMinutes int            `json:"session_timeout_minutes"`

	UpdateCheck bool `json:"update_check"`
	Discovery   bool `json:"discovery"`

	// RawGlobal is verbatim text placed inside the global options block
	// (e.g. options the importer could not map). Validated before apply.
	RawGlobal string `json:"raw_global"`
}

type TrustedProxies struct {
	Enabled         bool     `json:"enabled"`
	Presets         []string `json:"presets"` // cloudflare, fastly, private
	Custom          []string `json:"custom"`
	Strict          bool     `json:"strict"`
	ClientIPHeaders []string `json:"client_ip_headers"`
}

type CrowdSecSettings struct {
	Enabled        bool   `json:"enabled"`
	APIURL         string `json:"api_url"`
	APIKeyRef      string `json:"api_key_ref"` // "env:NAME", "file:/path" or "secret:<name>"
	TickerInterval string `json:"ticker_interval"`
}

type BackupSettings struct {
	Enabled   bool   `json:"enabled"`
	Schedule  string `json:"schedule"` // "daily" | "weekly" | duration like "12h"
	Retention int    `json:"retention"`
}

type OIDCSettings struct {
	Enabled         bool     `json:"enabled"`
	Preset          string   `json:"preset"`
	Issuer          string   `json:"issuer"`
	ClientID        string   `json:"client_id"`
	ClientSecretRef string   `json:"client_secret_ref"`
	RedirectURL     string   `json:"redirect_url"`
	Scopes          []string `json:"scopes"`
	GroupsClaim     string   `json:"groups_claim"`
	AdminGroups     []string `json:"admin_groups"`
	EditorGroups    []string `json:"editor_groups"`
	AutoCreate      bool     `json:"auto_create"`
	DefaultRole     string   `json:"default_role"`
	ButtonLabel     string   `json:"button_label"`
}

// DefaultSettings returns safe defaults for a fresh install.
func DefaultSettings() Settings {
	return Settings{
		ACMECA:                "letsencrypt",
		ResolverPreset:        "quad9",
		Resolvers:             []string{"9.9.9.9", "149.112.112.112"},
		PropagationTimeout:    "",
		TrustedProxies:        TrustedProxies{Enabled: false},
		Metrics:               true,
		DefaultAccessLog:      true,
		LogRollSize:           "10MiB",
		LogRollKeep:           5,
		CertAlertDays:         []int{14, 7},
		Backup:                BackupSettings{Enabled: true, Schedule: "daily", Retention: 7},
		SessionTimeoutMinutes: 60,
		UpdateCheck:           true,
		CrowdSec:              CrowdSecSettings{APIURL: "http://crowdsec:8080", TickerInterval: "15s"},
		OIDC:                  OIDCSettings{Scopes: []string{"openid", "profile", "email", "groups"}, GroupsClaim: "groups", DefaultRole: "viewer"},
	}
}

// ConfigVersion is a snapshot of a generated Caddyfile and its apply result.
type ConfigVersion struct {
	ID           int64     `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	User         string    `json:"user"`
	Caddyfile    string    `json:"caddyfile,omitempty"`
	Status       string    `json:"status"` // applied, failed, rolled_back, dry_run, validated
	Message      string    `json:"message"`
	Good         bool      `json:"good"`
	CaddyVersion string    `json:"caddy_version"`
}
