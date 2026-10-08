package importer

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/Krifmaz/CaddyHub/internal/caddy"
	"github.com/Krifmaz/CaddyHub/internal/generator"
	"github.com/Krifmaz/CaddyHub/internal/model"
)

// testdata/caddy_config.json is `caddy adapt` output of caddy_config.Caddyfile.
func TestImportJSON(t *testing.T) {
	b, err := os.ReadFile("testdata/caddy_config.json")
	if err != nil {
		t.Fatal(err)
	}
	res, err := ImportJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	byHost := map[string]model.Site{}
	for _, s := range res.Sites {
		for _, h := range s.Hosts {
			byHost[h] = s
		}
	}

	jf := byHost["jellyfin.example.com"]
	if jf.Kind != model.KindProxy || jf.Config.Proxy.Upstreams[0] != "jellyfin:8096" || jf.Config.Proxy.LBPolicy != "round_robin" ||
		jf.Config.Proxy.HealthURI != "/health" || jf.Config.HeadersSet["X-Frame-Options"] != "DENY" || len(jf.Config.Compression) != 2 {
		t.Errorf("jellyfin: %+v", jf.Config)
	}
	v := byHost["pw.example.com"]
	if v.Kind != model.KindProxy || v.Config.Proxy.Upstreams[0] != "https://10.0.0.5:8443" || !v.Config.Proxy.TLSSkipVerify ||
		v.Config.MaxBodySize != "10MB" || len(v.Config.Access.BasicAuth) != 1 || len(v.Config.Routes) != 1 ||
		v.Config.Routes[0].Path != "/api/*" || !v.Config.Routes[0].StripPrefix {
		t.Errorf("vault: %+v", v.Config)
	}
	if d := byHost["docs.example.com"]; d.Kind != model.KindStatic || d.Config.Static.Root != "/srv/docs" || !d.Config.Static.Browse || !d.Config.Static.SPA {
		t.Errorf("docs: %+v", d.Config.Static)
	}
	if o := byHost["old.example.com"]; o.Kind != model.KindRedirect || o.Config.Redirect.To != "https://new.example.com" || o.Config.Redirect.Code != 301 || !o.Config.Redirect.KeepPath {
		t.Errorf("redirect: %+v", o.Config.Redirect)
	}
	if s := byHost["status.example.com"]; s.Kind != model.KindRespond || s.Config.Respond.Body != "OK" {
		t.Errorf("respond: %+v", s.Config.Respond)
	}
	if a := byHost["a.lan.example.com"]; a.Kind != model.KindProxy {
		t.Errorf("wildcard sub-site not split out: %+v", res.Sites)
	}
	if _, ok := byHost["weird.example.com"]; ok {
		t.Error("php site should not be imported as structured")
	}

	// Nothing is lost: unmappable routes are kept (disabled) with their JSON.
	if len(res.RawBlocks) != 2 {
		t.Fatalf("raw blocks: %d", len(res.RawBlocks))
	}
	for _, rb := range res.RawBlocks {
		if rb.Enabled || !strings.Contains(rb.Body, "\"handler\"") {
			t.Errorf("raw block should be disabled and hold JSON: %+v", rb)
		}
	}

	// DNS: env reference kept as a reference, literal secret flagged.
	var envRef, literal bool
	for _, c := range res.Credentials {
		switch c.Fields["api_token"] {
		case "env:CF_API_TOKEN":
			envRef = true
		case "literal-secret-token":
			literal = true
		}
	}
	if !envRef || !literal || len(res.Warnings) != 1 {
		t.Errorf("credentials %+v warnings %v", res.Credentials, res.Warnings)
	}
	doms := map[string]DomainSuggestion{}
	for _, d := range res.Domains {
		doms[d.Name] = d
	}
	if !doms["lan.example.com"].Wildcard || doms["example.com"].Challenge != model.ChallengeDNS {
		t.Errorf("domains: %+v", res.Domains)
	}
	if res.Email != "me@example.com" {
		t.Errorf("email %q", res.Email)
	}
}

func TestImportJSONRejectsGarbage(t *testing.T) {
	if _, err := ImportJSON([]byte("not json")); err == nil {
		t.Fatal("expected error")
	}
	res, err := ImportJSON([]byte(`{"admin":{"listen":"localhost:2019"}}`))
	if err != nil || len(res.Sites) != 0 {
		t.Fatalf("empty config: %v %+v", err, res)
	}
}

// TestRoundTrip imports a Caddyfile both ways, regenerates it from the
// model and checks every host behaves the same. Needs CADDY_BIN.
func TestRoundTrip(t *testing.T) {
	bin := os.Getenv("CADDY_BIN")
	if bin == "" {
		t.Skip("CADDY_BIN not set")
	}
	r := caddy.NewRunner(bin)
	ctx := context.Background()
	caps, err := r.Capabilities(ctx)
	if err != nil {
		t.Fatal(err)
	}
	src := `{
	email me@example.com
}
app.example.com {
	encode zstd gzip
	reverse_proxy app:8080 {
		lb_policy least_conn
	}
}
files.example.com {
	root * /srv/files
	file_server browse
}
api.example.com {
	handle_path /v1/* {
		reverse_proxy v1:9000
	}
	reverse_proxy https://10.0.0.5:8443 {
		transport http {
			tls_insecure_skip_verify
		}
	}
}
go.example.com {
	redir https://example.org{uri} permanent
}
ok.example.com {
	respond "fine" 200
}
`
	adapted, err := r.Adapt(ctx, src)
	if err != nil {
		t.Fatal(err)
	}
	orig, err := ImportJSON(adapted.JSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(orig.Sites) != 5 {
		t.Fatalf("imported %d sites: %+v", len(orig.Sites), orig.Report)
	}
	// The Caddyfile importer must agree with the JSON importer.
	cfImp, err := Import(src)
	if err != nil {
		t.Fatal(err)
	}
	if d := CompareFingerprints(Fingerprint(orig), Fingerprint(cfImp)); len(d) > 0 {
		t.Errorf("Caddyfile vs JSON import differ:\n%s", strings.Join(d, "\n"))
	}

	gen := generator.Generate(PreviewInput(orig, model.DefaultSettings(), generator.Env{AdminListen: "localhost:2019"}, caps))
	again, err := r.Adapt(ctx, gen.Caddyfile)
	if err != nil {
		t.Fatalf("regenerated config invalid: %v\n%s", err, gen.Caddyfile)
	}
	back, err := ImportJSON(again.JSON)
	if err != nil {
		t.Fatal(err)
	}
	if d := CompareFingerprints(Fingerprint(orig), Fingerprint(back)); len(d) > 0 {
		t.Errorf("round trip differs:\n%s\n\ngenerated:\n%s", strings.Join(d, "\n"), gen.Caddyfile)
	}
}
