package apply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Krifmaz/CaddyHub/internal/caddy"
	"github.com/Krifmaz/CaddyHub/internal/generator"
	"github.com/Krifmaz/CaddyHub/internal/model"
	"github.com/Krifmaz/CaddyHub/internal/registry"
	"github.com/Krifmaz/CaddyHub/internal/secrets"
	"github.com/Krifmaz/CaddyHub/internal/store"
)

// ---------------------------------------------------------------- fakes

type fakeValidator struct {
	adaptErr, validateErr error
	validated             []string
}

func (f *fakeValidator) Adapt(_ context.Context, s string) (*caddy.AdaptResult, error) {
	if f.adaptErr != nil {
		return nil, f.adaptErr
	}
	return &caddy.AdaptResult{JSON: json.RawMessage(`{}`)}, nil
}
func (f *fakeValidator) Validate(_ context.Context, s string) error {
	f.validated = append(f.validated, s)
	return f.validateErr
}

type fakeAdmin struct {
	running  string // "caddyfile:<text>" or "json:<json>"
	loads    []string
	loadErr  error
	jsonLoad []string
}

func (f *fakeAdmin) LoadCaddyfile(_ context.Context, s string, _ bool) error {
	f.loads = append(f.loads, s)
	if f.loadErr != nil {
		return f.loadErr
	}
	f.running = "caddyfile:" + s
	return nil
}
func (f *fakeAdmin) LoadJSON(_ context.Context, b []byte) error {
	f.jsonLoad = append(f.jsonLoad, string(b))
	f.running = "json:" + string(b)
	return nil
}
func (f *fakeAdmin) Config(context.Context) (json.RawMessage, error) {
	return json.RawMessage(`{"apps":{"marker":"previous"}}`), nil
}
func (f *fakeAdmin) Ping(context.Context) error { return nil }

type fakeHealth struct{ err error }

func (f *fakeHealth) Check(context.Context, bool) error { return f.err }

func newStore(t *testing.T) *store.Store {
	t.Helper()
	box, _ := secrets.NewBox([]byte("test-key"))
	s, err := store.Open(filepath.Join(t.TempDir(), "panel.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func newPipeline(t *testing.T, s *store.Store, v Validator, a AdminAPI, h HealthChecker) *Pipeline {
	dir := t.TempDir()
	return &Pipeline{
		Store: s, Validator: v, Admin: a, Health: h,
		Secrets:     &secrets.Materializer{Dir: filepath.Join(dir, "secrets")},
		Env:         generator.Env{AdminListen: "localhost:2019", LogDir: "/var/log/caddy"},
		PersistPath: filepath.Join(dir, "config", "Caddyfile"),
		Caps:        func() registry.Capabilities { return registry.Capabilities{} },
	}
}

func addSite(t *testing.T, s *store.Store, host, upstream string) model.Site {
	st, err := s.CreateSite(model.Site{Name: host, Hosts: []string{host}, Kind: model.KindProxy, Enabled: true,
		Config: model.SiteConfig{Proxy: &model.ProxyConfig{Upstreams: []string{upstream}}}})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// ---------------------------------------------------------------- unit tests

func TestApplySuccessPersists(t *testing.T) {
	s := newStore(t)
	addSite(t, s, "app.example.com", "app:80")
	adm := &fakeAdmin{}
	p := newPipeline(t, s, &fakeValidator{}, adm, &fakeHealth{})
	res, err := p.Apply(context.Background(), Options{User: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "applied" {
		t.Fatalf("status = %s (%s)", res.Status, res.Message)
	}
	b, err := os.ReadFile(p.PersistPath)
	if err != nil || !strings.Contains(string(b), "reverse_proxy app:80") {
		t.Fatalf("persisted Caddyfile missing or wrong: %v\n%s", err, b)
	}
	lg, err := s.LastGood()
	if err != nil || lg.ID != res.VersionID || lg.User != "tester" {
		t.Fatalf("last good not recorded: %+v %v", lg, err)
	}
	// validation used the redirected-log copy, not the real paths
	fv := p.Validator.(*fakeValidator)
	if strings.Contains(fv.validated[0], "/var/log/caddy") {
		t.Fatal("validation copy must not reference the real log dir")
	}
}

func TestInvalidConfigBlocked(t *testing.T) {
	s := newStore(t)
	addSite(t, s, "app.example.com", "app:80")
	adm := &fakeAdmin{}
	v := &fakeValidator{validateErr: &caddy.Error{Stage: "validate", Messages: []caddy.Message{{Level: "error", Text: "bad module"}}, Err: errors.New("exit 1")}}
	p := newPipeline(t, s, v, adm, &fakeHealth{})
	res, err := p.Apply(context.Background(), Options{User: "u"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "invalid" || !strings.Contains(res.Message, "bad module") {
		t.Fatalf("unexpected result: %+v", res)
	}
	if len(adm.loads) != 0 {
		t.Fatal("invalid config must never reach /load")
	}
	if _, err := os.Stat(p.PersistPath); !os.IsNotExist(err) {
		t.Fatal("invalid config must not be persisted")
	}
}

func TestLoadRejectedNotPersisted(t *testing.T) {
	s := newStore(t)
	addSite(t, s, "app.example.com", "app:80")
	adm := &fakeAdmin{loadErr: &caddy.APIError{Status: 400, Body: `{"error":"listen tcp :443: bind: address already in use"}`}}
	p := newPipeline(t, s, &fakeValidator{}, adm, &fakeHealth{})
	res, _ := p.Apply(context.Background(), Options{User: "u"})
	if res.Status != "failed" || !strings.Contains(res.Message, "address already in use") {
		t.Fatalf("unexpected: %+v", res)
	}
	if _, err := os.Stat(p.PersistPath); !os.IsNotExist(err) {
		t.Fatal("rejected config must not be persisted")
	}
}

func TestHealthFailureRollsBack(t *testing.T) {
	s := newStore(t)
	addSite(t, s, "app.example.com", "app:80")
	adm := &fakeAdmin{}
	h := &fakeHealth{}
	p := newPipeline(t, s, &fakeValidator{}, adm, h)
	// first a good apply
	if res, _ := p.Apply(context.Background(), Options{User: "u"}); res.Status != "applied" {
		t.Fatalf("first apply: %+v", res)
	}
	good, _ := os.ReadFile(p.PersistPath)

	// now change something and make the health check fail
	addSite(t, s, "new.example.com", "new:80")
	h.err = errors.New("listener caddy:443 not accepting connections")
	res, _ := p.Apply(context.Background(), Options{User: "u"})
	if res.Status != "rolled_back" || !res.RolledBack {
		t.Fatalf("expected rollback, got %+v", res)
	}
	if len(adm.jsonLoad) != 1 || !strings.Contains(adm.jsonLoad[0], `"marker":"previous"`) {
		t.Fatalf("expected exact previous JSON to be restored, got %v", adm.jsonLoad)
	}
	after, _ := os.ReadFile(p.PersistPath)
	if string(after) != string(good) {
		t.Fatal("persisted config must remain the last good one after rollback")
	}
	vs, _ := s.Versions(10)
	if vs[0].Status != "rolled_back" || vs[0].Good {
		t.Fatalf("version history should record the rollback: %+v", vs[0])
	}
}

func TestDryRunDoesNotApply(t *testing.T) {
	s := newStore(t)
	addSite(t, s, "app.example.com", "app:80")
	adm := &fakeAdmin{}
	p := newPipeline(t, s, &fakeValidator{}, adm, &fakeHealth{})
	res, _ := p.Apply(context.Background(), Options{DryRun: true})
	if res.Status != "dry_run" || len(adm.loads) != 0 || !res.Plan.Changed || res.Plan.Added == 0 {
		t.Fatalf("unexpected dry run result: %+v loads=%d", res, len(adm.loads))
	}
	if vs, _ := s.Versions(10); len(vs) != 0 {
		t.Fatal("dry run must not create versions")
	}
}

func TestRollbackToVersion(t *testing.T) {
	s := newStore(t)
	site := addSite(t, s, "app.example.com", "v1:80")
	adm := &fakeAdmin{}
	p := newPipeline(t, s, &fakeValidator{}, adm, &fakeHealth{})
	r1, _ := p.Apply(context.Background(), Options{User: "u"})
	site.Config.Proxy.Upstreams = []string{"v2:80"}
	s.UpdateSite(site)
	p.Apply(context.Background(), Options{User: "u"})
	res, err := p.ApplySnapshot(context.Background(), r1.VersionID, Options{User: "u"})
	if err != nil || res.Status != "applied" {
		t.Fatalf("rollback: %+v %v", res, err)
	}
	b, _ := os.ReadFile(p.PersistPath)
	if !strings.Contains(string(b), "v1:80") {
		t.Fatal("rollback should persist the old version")
	}
}

// TestProviderSwitch swaps a domain from Cloudflare to Porkbun and checks the
// regenerated config, the secret files, and that the plan shows the change.
func TestProviderSwitch(t *testing.T) {
	s := newStore(t)
	cf, _ := s.SaveCredential(model.DNSCredential{Name: "cf", Provider: "cloudflare", Fields: map[string]string{"api_token": "cf-secret-token-value-1234567890abcdef"}})
	pb, _ := s.SaveCredential(model.DNSCredential{Name: "pb", Provider: "porkbun", Fields: map[string]string{"api_key": "env:PORKBUN_KEY", "api_secret_key": "pb-secret"}})
	d, _ := s.SaveDomain(model.Domain{Name: "example.com", Challenge: model.ChallengeDNS, CredentialID: &cf.ID})
	addSite(t, s, "app.example.com", "app:80")
	adm := &fakeAdmin{}
	p := newPipeline(t, s, &fakeValidator{}, adm, &fakeHealth{})
	if res, _ := p.Apply(context.Background(), Options{User: "u"}); res.Status != "applied" {
		t.Fatalf("apply: %+v", res)
	}
	cfFile := filepath.Join(p.Secrets.Dir, fmt.Sprintf("dns-%d-api_token", cf.ID))
	if b, err := os.ReadFile(cfFile); err != nil || string(b) != "cf-secret-token-value-1234567890abcdef" {
		t.Fatalf("cloudflare secret not materialized: %v", err)
	}
	persisted, _ := os.ReadFile(p.PersistPath)
	if strings.Contains(string(persisted), "cf-secret-token") {
		t.Fatal("secret leaked into the Caddyfile")
	}

	// switch provider
	d.CredentialID = &pb.ID
	s.SaveDomain(d)
	plan, err := p.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	hasLine := func(prefix, text string) bool {
		for _, l := range strings.Split(plan.Diff, "\n") {
			if strings.HasPrefix(l, prefix) && strings.TrimSpace(l[1:]) == text {
				return true
			}
		}
		return false
	}
	if !hasLine("+", "dns porkbun {") || !hasLine("-", "dns cloudflare {") {
		t.Fatalf("plan diff should show provider swap:\n%s", plan.Diff)
	}
	if !strings.Contains(plan.Caddyfile, "api_key {env.PORKBUN_KEY}") {
		t.Fatal("env reference should become an {env.*} placeholder")
	}
	if strings.Contains(plan.Caddyfile, "pb-secret") {
		t.Fatal("secret leaked into the Caddyfile")
	}
	if _, err := os.Stat(cfFile); !os.IsNotExist(err) {
		// cloudflare credential still exists, so its file is kept; delete it
		// and make sure the file is pruned on the next build
		s.DeleteCredential(cf.ID)
		p.Plan(context.Background())
		if _, err := os.Stat(cfFile); !os.IsNotExist(err) {
			t.Fatal("secret file for deleted credential should be pruned")
		}
	}
	res, _ := p.Apply(context.Background(), Options{User: "u"})
	if res.Status != "applied" {
		t.Fatalf("apply after switch: %+v", res)
	}
}

// ---------------------------------------------------------------- real Caddy

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// TestRealCaddyPipeline runs apply + health-failure rollback against a real
// Caddy process. Set CADDY_BIN to enable.
func TestRealCaddyPipeline(t *testing.T) {
	bin := os.Getenv("CADDY_BIN")
	if bin == "" {
		t.Skip("CADDY_BIN not set")
	}
	dir := t.TempDir()
	adminPort, httpPort := freePort(t), freePort(t)
	adminAddr := fmt.Sprintf("127.0.0.1:%d", adminPort)
	boot := filepath.Join(dir, "Caddyfile")
	os.WriteFile(boot, []byte(fmt.Sprintf("{\n\tadmin %s\n}\n", adminAddr)), 0o644)

	cmd := exec.Command(bin, "run", "--config", boot, "--adapter", "caddyfile")
	cmd.Env = append(os.Environ(), "XDG_DATA_HOME="+dir, "XDG_CONFIG_HOME="+dir, "HOME="+dir, "APPDATA="+dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })

	admin := caddy.NewAdmin(adminAddr)
	if err := admin.WaitReady(context.Background(), 20*time.Second); err != nil {
		t.Fatal(err)
	}

	s := newStore(t)
	s.UpdateSettings(func(st *model.Settings) { st.Metrics = false })
	s.CreateSite(model.Site{Name: "hello", Hosts: []string{fmt.Sprintf("localhost:%d", httpPort)}, Kind: model.KindRespond, Enabled: true,
		Config: model.SiteConfig{TLS: model.TLSConfig{Mode: model.TLSOff}, Respond: &model.RespondConfig{Body: "hello v1", Status: 200}}})

	runner := caddy.NewRunner(bin)
	caps, _ := runner.Capabilities(context.Background())
	health := &DefaultHealth{Admin: admin, ProbeAddrs: []string{fmt.Sprintf("127.0.0.1:%d", httpPort)}}
	p := &Pipeline{
		Store: s, Validator: runner, Admin: admin, Health: health,
		Secrets:     &secrets.Materializer{Dir: filepath.Join(dir, "secrets")},
		Env:         generator.Env{AdminListen: adminAddr, LogDir: filepath.ToSlash(filepath.Join(dir, "logs"))},
		PersistPath: boot,
		Caps:        func() registry.Capabilities { return caps },
	}

	get := func() string {
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", httpPort), nil)
		req.Host = fmt.Sprintf("localhost:%d", httpPort)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "ERR " + err.Error()
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}

	res, err := p.Apply(context.Background(), Options{User: "it"})
	if err != nil || res.Status != "applied" {
		t.Fatalf("apply v1: %+v %v", res, err)
	}
	if got := get(); got != "hello v1" {
		t.Fatalf("v1 not served: %q", got)
	}

	// change the site, but force the health check to fail -> rollback
	sites, _ := s.Sites()
	sites[0].Config.Respond.Body = "hello v2"
	s.UpdateSite(sites[0])
	p.Health = &failingAfterLoad{inner: health}
	res, _ = p.Apply(context.Background(), Options{User: "it"})
	if res.Status != "rolled_back" {
		t.Fatalf("expected rollback: %+v", res)
	}
	if got := get(); got != "hello v1" {
		t.Fatalf("after rollback Caddy should serve v1 again, got %q", got)
	}

	// invalid raw snippet is caught by validation and never loaded
	sites[0].Config.Raw = "this_is_not_a_directive foo"
	s.UpdateSite(sites[0])
	p.Health = health
	res, _ = p.Apply(context.Background(), Options{User: "it"})
	if res.Status != "invalid" || res.Plan.Stage != "adapt" {
		t.Fatalf("expected adapt failure: %+v", res)
	}
	if got := get(); got != "hello v1" {
		t.Fatalf("invalid config must not change the running site, got %q", got)
	}

	// fix and apply v2 for real
	sites[0].Config.Raw = ""
	s.UpdateSite(sites[0])
	res, _ = p.Apply(context.Background(), Options{User: "it"})
	if res.Status != "applied" || get() != "hello v2" {
		t.Fatalf("v2 apply failed: %+v body=%q", res, get())
	}
	persisted, _ := os.ReadFile(boot)
	if !strings.Contains(string(persisted), "hello v2") {
		t.Fatal("v2 not persisted for restarts")
	}
}

// failingAfterLoad verifies the new config really loaded, then reports failure.
type failingAfterLoad struct{ inner HealthChecker }

func (f *failingAfterLoad) Check(ctx context.Context, expect bool) error {
	if err := f.inner.Check(ctx, expect); err != nil {
		return err
	}
	return errors.New("simulated health check failure")
}
