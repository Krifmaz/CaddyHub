package generator

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Krifmaz/CaddyHub/internal/caddy"
	"github.com/Krifmaz/CaddyHub/internal/model"
	"github.com/Krifmaz/CaddyHub/internal/registry"
)

var update = flag.Bool("update", false, "rewrite golden files")

func ptr[T any](v T) *T { return &v }

// fullCaps pretends every module the panel can use is installed.
func fullCaps() registry.Capabilities {
	c := registry.Capabilities{Detected: true, Version: registry.ParseVersion("v2.11.7"), VersionS: "v2.11.7", Modules: map[string]bool{}}
	for _, f := range registry.Features {
		for _, m := range f.Modules {
			c.Modules[m] = true
		}
	}
	for _, p := range registry.DNSProviders {
		c.Modules[p.Module()] = true
	}
	return c
}

func baseEnv() Env {
	return Env{
		AdminListen:   "caddy-admin:2019",
		AdminOrigins:  []string{"caddy-admin:2019"},
		LogDir:        "/var/log/caddy",
		PanelUpstream: "panel:8080",
		TrustedProxyRanges: map[string][]string{
			"cloudflare": {"173.245.48.0/20", "2400:cb00::/32"},
			"fastly":     {"23.235.32.0/20"},
		},
	}
}

func baseSettings() model.Settings {
	s := model.DefaultSettings()
	s.ACMEEmail = "admin@example.com"
	return s
}

type tcase struct {
	name string
	in   Input
	// modules the case needs beyond the stock binary (for real validation)
	needs []string
	// skipValidate: adapt only (e.g. custom cert files that don't exist)
	skipValidate bool
}

func cases() []tcase {
	cfID := int64(1)
	pbID := int64(2)
	creds := map[int64]CredRef{
		cfID: {Provider: "cloudflare", Fields: map[string]string{"api_token": "{file./run/caddyhub/secrets/dns-1-api_token}"}},
		pbID: {Provider: "porkbun", Fields: map[string]string{
			"api_key":        "{env.PORKBUN_API_KEY}",
			"api_secret_key": "{file./run/caddyhub/secrets/dns-2-api_secret_key}",
		}},
	}
	return []tcase{
		{
			name: "basic_proxy",
			in: Input{Settings: baseSettings(), Caps: fullCaps(), Env: baseEnv(), Sites: []model.Site{
				{ID: 1, Name: "App", Hosts: []string{"app.example.com"}, Kind: model.KindProxy, Enabled: true,
					Config: model.SiteConfig{Proxy: &model.ProxyConfig{Upstreams: []string{"app:8080"}}}},
				{ID: 2, Name: "Disabled", Hosts: []string{"off.example.com"}, Kind: model.KindProxy, Enabled: false,
					Config: model.SiteConfig{Proxy: &model.ProxyConfig{Upstreams: []string{"off:80"}}}},
			}},
		},
		{
			name: "full_proxy",
			in: Input{Settings: baseSettings(), Caps: fullCaps(), Env: baseEnv(), Sites: []model.Site{
				{ID: 7, Name: "Proxmox", Hosts: []string{"pve.example.com"}, Kind: model.KindProxy, Enabled: true,
					Config: model.SiteConfig{
						Proxy: &model.ProxyConfig{
							Upstreams: []string{"https://10.0.0.10:8006", "https://10.0.0.11:8006"},
							LBPolicy:  "least_conn", LBRetries: 2, LBTryDuration: "5s",
							HealthURI: "/", HealthInterval: "30s", HealthTimeout: "5s", HealthStatus: "2xx",
							FailDuration: "30s", MaxFails: 3, UnhealthyStatus: "5xx",
							TLSSkipVerify: true, DialTimeout: "5s", ResponseHeaderTimeout: "30s",
							FlushInterval: "-1", HeaderUp: map[string]string{"X-Real-IP": "{client_ip}"},
						},
						Routes: []model.Route{
							{Path: "/grpc/*", StripPrefix: true, Kind: model.KindProxy, Proxy: &model.ProxyConfig{Upstreams: []string{"grpc:50051"}, H2C: true}},
							{Path: "/old/*", Kind: model.KindRedirect, Redirect: &model.RedirectConfig{To: "https://new.example.com", Code: 301, KeepPath: true}},
						},
						Compression:   []string{"zstd", "gzip"},
						HeadersSet:    map[string]string{"Strict-Transport-Security": "max-age=31536000; includeSubDomains", "X-Frame-Options": "SAMEORIGIN"},
						HeadersRemove: []string{"Server", "X-Powered-By"},
						MaxBodySize:   "100MB",
						Access: model.AccessConfig{
							BasicAuth:   []model.BasicAuthUser{{Username: "admin", Hash: "$2a$14$Zkx19XLiW6VYouLHR5NmfOFU0z2GTNmpkT/5qqR7hx4IjWJPDhjvG"}},
							AllowCIDRs:  []string{"192.168.0.0/16", "10.0.0.0/8"},
							DenyCIDRs:   []string{"192.168.66.0/24"},
							ForwardAuth: &model.ForwardAuth{Preset: "authelia", Upstream: "authelia:9091", URI: "/api/authz/forward-auth", CopyHeaders: []string{"Remote-User", "Remote-Groups", "Remote-Email", "Remote-Name"}},
						},
					}},
			}},
		},
		{
			name: "kinds",
			in: Input{Settings: baseSettings(), Caps: fullCaps(), Env: baseEnv(), Sites: []model.Site{
				{ID: 1, Name: "Docs", Hosts: []string{"docs.example.com"}, Kind: model.KindStatic, Enabled: true, Position: 2,
					Config: model.SiteConfig{Static: &model.StaticConfig{Root: "/srv/docs", SPA: true}}},
				{ID: 2, Name: "Files", Hosts: []string{"files.example.com"}, Kind: model.KindStatic, Enabled: true, Position: 1,
					Config: model.SiteConfig{Static: &model.StaticConfig{Root: "/srv/files", Browse: true}}},
				{ID: 3, Name: "Old", Hosts: []string{"old.example.com"}, Kind: model.KindRedirect, Enabled: true, Position: 3,
					Config: model.SiteConfig{Redirect: &model.RedirectConfig{To: "https://new.example.com", Code: 308, KeepPath: true}}},
				{ID: 4, Name: "Status", Hosts: []string{"status.example.com"}, Kind: model.KindRespond, Enabled: true, Position: 4,
					Config: model.SiteConfig{Respond: &model.RespondConfig{Body: `{"ok":true}`, Status: 200, ContentType: "application/json"}}},
				{ID: 5, Name: "Maint", Hosts: []string{"maint.example.com"}, Kind: model.KindProxy, Enabled: true, Position: 5,
					Config: model.SiteConfig{Maintenance: true, Proxy: &model.ProxyConfig{Upstreams: []string{"app:80"}}}},
			}},
		},
		{
			name:  "dns_multi_domain",
			needs: []string{"dns.providers.cloudflare", "dns.providers.porkbun"},
			in: func() Input {
				s := baseSettings()
				s.ACMECA = "letsencrypt_staging"
				s.PropagationTimeout = "5m"
				return Input{Settings: s, Caps: fullCaps(), Env: baseEnv(), Credentials: creds,
					Domains: []model.Domain{
						{ID: 1, Name: "example.com", Challenge: model.ChallengeDNS, CredentialID: &cfID, Wildcard: true},
						{ID: 2, Name: "example.net", Challenge: model.ChallengeDNS, CredentialID: &pbID, Resolvers: []string{"1.1.1.1"}},
						{ID: 3, Name: "example.org", Challenge: model.ChallengeHTTP},
					},
					Sites: []model.Site{
						{ID: 1, Name: "Vault", Hosts: []string{"vault.example.com"}, Kind: model.KindProxy, Enabled: true,
							Config: model.SiteConfig{Proxy: &model.ProxyConfig{Upstreams: []string{"vaultwarden:80"}, Websocket: true}}},
						{ID: 2, Name: "Jelly", Hosts: []string{"media.example.com"}, Kind: model.KindProxy, Enabled: true,
							Config: model.SiteConfig{Proxy: &model.ProxyConfig{Upstreams: []string{"jellyfin:8096"}}, AccessLog: ptr(false)}},
						{ID: 3, Name: "Deep", Hosts: []string{"a.b.example.com"}, Kind: model.KindProxy, Enabled: true,
							Config: model.SiteConfig{Proxy: &model.ProxyConfig{Upstreams: []string{"deep:80"}}}},
						{ID: 4, Name: "Net", Hosts: []string{"www.example.net"}, Kind: model.KindProxy, Enabled: true,
							Config: model.SiteConfig{Proxy: &model.ProxyConfig{Upstreams: []string{"net:80"}}}},
						{ID: 5, Name: "Org", Hosts: []string{"example.org"}, Kind: model.KindProxy, Enabled: true,
							Config: model.SiteConfig{Proxy: &model.ProxyConfig{Upstreams: []string{"org:80"}}}},
					}}
			}(),
		},
		{
			name:         "tls_modes",
			skipValidate: true, // custom cert files don't exist in the test env
			in: Input{Settings: baseSettings(), Caps: fullCaps(), Env: baseEnv(), Sites: []model.Site{
				{ID: 1, Name: "Internal", Hosts: []string{"nas.home.arpa"}, Kind: model.KindProxy, Enabled: true,
					Config: model.SiteConfig{TLS: model.TLSConfig{Mode: model.TLSInternal}, Proxy: &model.ProxyConfig{Upstreams: []string{"nas:5000"}}}},
				{ID: 2, Name: "Custom", Hosts: []string{"secure.example.com"}, Kind: model.KindProxy, Enabled: true,
					Config: model.SiteConfig{TLS: model.TLSConfig{Mode: model.TLSCustom, CertFile: "/certs/secure.crt", KeyFile: "/certs/secure.key"}, Proxy: &model.ProxyConfig{Upstreams: []string{"secure:443"}, TLSSkipVerify: true}}},
				{ID: 3, Name: "Plain", Hosts: []string{"plain.example.com"}, Kind: model.KindProxy, Enabled: true,
					Config: model.SiteConfig{TLS: model.TLSConfig{Mode: model.TLSOff}, Proxy: &model.ProxyConfig{Upstreams: []string{"plain:80"}}}},
				{ID: 4, Name: "NoRedirect", Hosts: []string{"both.example.com"}, Kind: model.KindProxy, Enabled: true,
					Config: model.SiteConfig{HTTPRedirect: ptr(false), Proxy: &model.ProxyConfig{Upstreams: []string{"both:80"}}}},
				{ID: 5, Name: "ToWWW", Hosts: []string{"example.com"}, Kind: model.KindProxy, Enabled: true,
					Config: model.SiteConfig{WWWRedirect: "to_www", Proxy: &model.ProxyConfig{Upstreams: []string{"web:80"}}}},
				{ID: 6, Name: "ToApex", Hosts: []string{"example.net", "www.example.org"}, Kind: model.KindProxy, Enabled: true,
					Config: model.SiteConfig{WWWRedirect: "to_apex", Proxy: &model.ProxyConfig{Upstreams: []string{"web2:80"}}}},
			}},
		},
		{
			name: "snippets_raw",
			in: func() Input {
				s := baseSettings()
				s.RawGlobal = "servers {\n\tprotocols h1 h2\n}"
				return Input{Settings: s, Caps: fullCaps(), Env: baseEnv(),
					Snippets: []model.Snippet{
						{ID: 1, Name: "security_headers", Description: "Common security headers", Body: "header {\n\tX-Content-Type-Options nosniff\n\tReferrer-Policy strict-origin-when-cross-origin\n}"},
						{ID: 2, Name: "lan_only", Body: "@external not remote_ip private_ranges\nrespond @external 403"},
					},
					RawBlocks: []model.RawBlock{
						{ID: 1, Name: "imported legacy", Enabled: true, Position: 1, Body: "legacy.example.com:8443 {\n\trespond \"legacy\"\n}"},
						{ID: 2, Name: "disabled", Enabled: false, Position: 2, Body: "nope.example.com {\n\trespond nope\n}"},
					},
					Sites: []model.Site{
						{ID: 1, Name: "App", Hosts: []string{"app.example.com"}, Kind: model.KindProxy, Enabled: true,
							Config: model.SiteConfig{Snippets: []string{"security_headers", "lan_only"}, Proxy: &model.ProxyConfig{Upstreams: []string{"app:80"}},
								Raw: "handle_errors {\n\trespond \"{err.status_code} {err.status_text}\"\n}"}},
					}}
			}(),
		},
		{
			name:  "security_plugins",
			needs: []string{"http.handlers.rate_limit", "crowdsec", "http.handlers.crowdsec"},
			in: func() Input {
				s := baseSettings()
				s.TrustedProxies = model.TrustedProxies{Enabled: true, Presets: []string{"cloudflare", "private"}, Custom: []string{"203.0.113.0/24"}, ClientIPHeaders: []string{"CF-Connecting-IP", "X-Forwarded-For"}, Strict: true}
				s.CrowdSec = model.CrowdSecSettings{Enabled: true, APIURL: "http://crowdsec:8080", TickerInterval: "15s"}
				e := baseEnv()
				e.CrowdSecKeyRef = "{file./run/caddyhub/secrets/crowdsec-api_key}"
				return Input{Settings: s, Caps: fullCaps(), Env: e, Sites: []model.Site{
					{ID: 1, Name: "API", Hosts: []string{"api.example.com"}, Kind: model.KindProxy, Enabled: true,
						Config: model.SiteConfig{Proxy: &model.ProxyConfig{Upstreams: []string{"api:3000"}},
							Access: model.AccessConfig{CrowdSec: true, RateLimit: &model.RateLimit{Events: 100, Window: "1m"}}}},
				}}
			}(),
		},
		{
			name: "missing_plugins_skipped",
			in: func() Input {
				caps := fullCaps()
				delete(caps.Modules, "http.handlers.rate_limit")
				delete(caps.Modules, "dns.providers.cloudflare")
				s := baseSettings()
				return Input{Settings: s, Caps: caps, Env: baseEnv(), Credentials: creds,
					Domains: []model.Domain{{ID: 1, Name: "example.com", Challenge: model.ChallengeDNS, CredentialID: &cfID, Wildcard: true}},
					Sites: []model.Site{
						{ID: 1, Name: "API", Hosts: []string{"api.example.com"}, Kind: model.KindProxy, Enabled: true,
							Config: model.SiteConfig{Proxy: &model.ProxyConfig{Upstreams: []string{"api:3000"}},
								Access: model.AccessConfig{RateLimit: &model.RateLimit{Events: 10}}}},
					}}
			}(),
		},
		{
			name: "panel_domain_internal_ca",
			in: func() Input {
				s := baseSettings()
				s.ACMECA = "caddy_internal"
				s.PanelDomain = "panel.home.arpa"
				s.Metrics = false
				return Input{Settings: s, Caps: fullCaps(), Env: baseEnv()}
			}(),
		},
	}
}

func TestGolden(t *testing.T) {
	for _, tc := range cases() {
		t.Run(tc.name, func(t *testing.T) {
			out := Generate(tc.in)
			got := out.Caddyfile
			if len(out.Warnings) > 0 {
				got += "\n# --- warnings ---\n# " + strings.Join(out.Warnings, "\n# ") + "\n"
			}
			path := filepath.Join("testdata", tc.name+".golden")
			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("missing golden file (run with -update): %v", err)
			}
			if string(want) != got {
				t.Errorf("output differs from %s (run go test -update to accept):\n%s", path, lineDiff(string(want), got))
			}
		})
	}
}

func TestDeterministic(t *testing.T) {
	for _, tc := range cases() {
		a := Generate(tc.in).Caddyfile
		for i := 0; i < 5; i++ {
			if b := Generate(tc.in).Caddyfile; a != b {
				t.Fatalf("%s: non-deterministic output", tc.name)
			}
		}
	}
}

var (
	capsOnce sync.Once
	binCaps  registry.Capabilities
	binErr   error
)

// TestRealCaddy adapts and validates every golden case with a real Caddy
// binary. Set CADDY_BIN to enable (CI runs it against several versions).
func TestRealCaddy(t *testing.T) {
	bin := os.Getenv("CADDY_BIN")
	if bin == "" {
		t.Skip("CADDY_BIN not set")
	}
	r := caddy.NewRunner(bin)
	capsOnce.Do(func() { binCaps, binErr = r.Capabilities(context.Background()) })
	if binErr != nil {
		t.Fatalf("detect capabilities: %v", binErr)
	}
	t.Logf("caddy %s, %d modules", binCaps.VersionS, len(binCaps.Modules))
	for _, tc := range cases() {
		t.Run(tc.name, func(t *testing.T) {
			for _, m := range tc.needs {
				if !binCaps.Modules[m] {
					t.Skipf("binary lacks module %s", m)
				}
			}
			in := tc.in
			out := Generate(in)
			if _, err := r.Adapt(context.Background(), out.Caddyfile); err != nil {
				t.Fatalf("adapt failed: %v\n%s", err, out.Caddyfile)
			}
			if tc.skipValidate {
				return
			}
			// validate a copy with logs redirected to a temp dir, exactly as
			// the apply pipeline does
			in.Env.LogDir = filepath.ToSlash(t.TempDir())
			in.Env.ValidationMode = true
			text := Generate(in).Caddyfile
			// materialize realistic dummy secrets where the config expects them
			sec := filepath.ToSlash(t.TempDir())
			text = strings.ReplaceAll(text, "/run/caddyhub/secrets", sec)
			for name, v := range map[string]string{
				"dns-1-api_token":      strings.Repeat("a1B2c3D4e5", 4),
				"dns-2-api_secret_key": "sk1_" + strings.Repeat("f", 60),
				"crowdsec-api_key":     "dummy-bouncer-key",
			} {
				os.WriteFile(filepath.Join(sec, name), []byte(v), 0o600)
			}
			vr := *r
			vr.ExtraEnv = []string{"PORKBUN_API_KEY=pk1_" + strings.Repeat("e", 60)}
			if err := vr.Validate(context.Background(), text); err != nil {
				t.Fatalf("validate failed: %v\n%s", err, text)
			}
		})
	}
}

// lineDiff is a tiny diff for test output.
func lineDiff(a, b string) string {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	var sb strings.Builder
	n := len(al)
	if len(bl) > n {
		n = len(bl)
	}
	for i := 0; i < n; i++ {
		var x, y string
		if i < len(al) {
			x = al[i]
		}
		if i < len(bl) {
			y = bl[i]
		}
		if x != y {
			sb.WriteString("-" + x + "\n+" + y + "\n")
		}
	}
	return sb.String()
}
