package importer

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/Krifmaz/CaddyHub/internal/caddy"
	"github.com/Krifmaz/CaddyHub/internal/generator"
	"github.com/Krifmaz/CaddyHub/internal/model"
	"github.com/Krifmaz/CaddyHub/internal/registry"
)

const sample = `# My old hand-written Caddyfile
{
	email ops@example.com
	acme_ca https://acme-staging-v02.api.letsencrypt.org/directory
	admin localhost:2019
	servers {
		protocols h1 h2
	}
}

(secure) {
	header {
		X-Frame-Options DENY
		-Server
	}
}

vault.example.com {
	import secure
	encode zstd gzip
	reverse_proxy vaultwarden:80 {
		header_up X-Real-IP {remote_host}
	}
	log {
		output file /var/log/vault.log
	}
}

pve.example.com {
	reverse_proxy https://10.0.0.5:8006 {
		transport http {
			tls_insecure_skip_verify
		}
	}
	tls {
		dns cloudflare {env.CF_API_TOKEN}
		resolvers 1.1.1.1
	}
}

http://plain.example.com {
	respond "plain text" 200
}

docs.example.com, www.docs.example.com {
	root * /srv/docs
	try_files {path} /index.html
	file_server
	basic_auth {
		alice $2a$14$Zkx19XLiW6VYouLHR5NmfOFU0z2GTNmpkT/5qqR7hx4IjWJPDhjvG
	}
}

app.example.com {
	handle_path /api/* {
		reverse_proxy api:3000
	}
	@websockets {
		header Connection *Upgrade*
	}
	reverse_proxy @websockets ws:8080
	reverse_proxy frontend:80
	header Cache-Control "no-store"
}

:8443 {
	respond "odd port"
}

&(shared) {
	respond "named route"
}

old.example.com {
	redir https://new.example.com{uri} permanent
}
`

func TestImportSample(t *testing.T) {
	res, err := Import(sample)
	if err != nil {
		t.Fatal(err)
	}
	if res.Email != "ops@example.com" || res.ACMECA != "letsencrypt_staging" {
		t.Errorf("globals not mapped: email=%q ca=%q", res.Email, res.ACMECA)
	}
	if !strings.Contains(res.RawGlobal, "protocols h1 h2") || strings.Contains(res.RawGlobal, "admin") {
		t.Errorf("raw global wrong: %q", res.RawGlobal)
	}
	if len(res.Snippets) != 1 || res.Snippets[0].Name != "secure" || !strings.Contains(res.Snippets[0].Body, "X-Frame-Options DENY") {
		t.Errorf("snippet not imported: %+v", res.Snippets)
	}
	sites := map[string]model.Site{}
	for _, s := range res.Sites {
		sites[s.Hosts[0]] = s
	}
	v := sites["vault.example.com"]
	if v.Kind != model.KindProxy || v.Config.Proxy.Upstreams[0] != "vaultwarden:80" || v.Config.Raw != "" ||
		len(v.Config.Snippets) != 1 || len(v.Config.Compression) != 2 || v.Config.Proxy.HeaderUp["X-Real-IP"] != "{remote_host}" {
		t.Errorf("vault mapped wrong: %+v", v)
	}
	p := sites["pve.example.com"]
	if !p.Config.Proxy.TLSSkipVerify || p.Config.Raw != "" {
		t.Errorf("pve mapped wrong: %+v", p.Config)
	}
	if len(res.Credentials) != 1 || res.Credentials[0].Provider != "cloudflare" || res.Credentials[0].Fields["api_token"] != "env:CF_API_TOKEN" {
		t.Errorf("credential not imported as env ref: %+v", res.Credentials)
	}
	if len(res.Domains) != 1 || res.Domains[0].Name != "example.com" || res.Domains[0].Challenge != model.ChallengeDNS {
		t.Errorf("domain suggestion wrong: %+v", res.Domains)
	}
	if s := sites["plain.example.com"]; s.Config.TLS.Mode != model.TLSOff || s.Kind != model.KindRespond || s.Config.Respond.Body != "plain text" {
		t.Errorf("plain mapped wrong: %+v", s)
	}
	d := sites["docs.example.com"]
	if d.Kind != model.KindStatic || !d.Config.Static.SPA || d.Config.Static.Root != "/srv/docs" || len(d.Config.Access.BasicAuth) != 1 || len(d.Hosts) != 2 {
		t.Errorf("docs mapped wrong: %+v", d)
	}
	a := sites["app.example.com"]
	if a.Kind != model.KindProxy || len(a.Config.Routes) != 1 || !a.Config.Routes[0].StripPrefix ||
		!strings.Contains(a.Config.Raw, "@websockets") || !strings.Contains(a.Config.Raw, "reverse_proxy @websockets ws:8080") ||
		a.Config.HeadersSet["Cache-Control"] != "no-store" {
		t.Errorf("app mapped wrong: %+v raw=%q", a.Config, a.Config.Raw)
	}
	if o := sites["old.example.com"]; o.Kind != model.KindRedirect || o.Config.Redirect.Code != 301 || !o.Config.Redirect.KeepPath {
		t.Errorf("redirect mapped wrong: %+v", o.Config.Redirect)
	}
	if len(res.RawBlocks) != 2 {
		t.Fatalf("expected :8443 and &(shared) as raw blocks, got %+v", res.RawBlocks)
	}
	for _, rb := range res.RawBlocks {
		if !strings.Contains(sample, rb.Body) {
			t.Errorf("raw block not verbatim: %q", rb.Body)
		}
	}
}

// TestImportRoundTrip: import -> generate -> caddy adapt must succeed.
func TestImportRoundTrip(t *testing.T) {
	bin := os.Getenv("CADDY_BIN")
	if bin == "" {
		t.Skip("CADDY_BIN not set")
	}
	src := strings.Replace(sample, "\ttls {\n\t\tdns cloudflare {env.CF_API_TOKEN}\n\t\tresolvers 1.1.1.1\n\t}\n", "", 1)
	res, err := Import(src)
	if err != nil {
		t.Fatal(err)
	}
	s := model.DefaultSettings()
	s.ACMEEmail, s.ACMECA, s.RawGlobal = res.Email, res.ACMECA, res.RawGlobal
	for i := range res.Sites {
		res.Sites[i].ID = int64(i + 1)
	}
	for i := range res.RawBlocks {
		res.RawBlocks[i].ID = int64(i + 1)
	}
	out := generator.Generate(generator.Input{
		Settings: s, Sites: res.Sites, Snippets: res.Snippets, RawBlocks: res.RawBlocks,
		Caps: registry.Capabilities{}, Env: generator.Env{AdminListen: "localhost:2019", LogDir: "/var/log/caddy"},
	})
	if _, err := caddy.NewRunner(bin).Adapt(context.Background(), out.Caddyfile); err != nil {
		t.Fatalf("round-trip adapt failed: %v\n%s", err, out.Caddyfile)
	}
}

func TestImportBraceless(t *testing.T) {
	res, err := Import("example.com\n\nreverse_proxy app:80\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sites) != 1 || res.Sites[0].Config.Proxy == nil || res.Sites[0].Config.Proxy.Upstreams[0] != "app:80" {
		t.Fatalf("braceless site not imported: %+v", res)
	}
}

func TestImportHeredocAndComments(t *testing.T) {
	src := "a.example.com {\n\trespond <<HTML\n\t\t<h1>Hi # not a comment</h1>\n\t\tHTML 200\n\t# real comment\n}\n"
	res, err := Import(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sites) != 1 || res.Sites[0].Kind != model.KindRespond || !strings.Contains(res.Sites[0].Config.Respond.Body, "# not a comment") {
		t.Fatalf("heredoc not handled: %+v", res.Sites)
	}
}
