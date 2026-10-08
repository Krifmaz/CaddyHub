// Package apply implements the config pipeline:
//
//	generate -> caddy adapt -> caddy validate -> diff -> POST /load
//	         -> health check -> persist snapshot (or roll back)
//
// The structured model in the store is the source of truth. The applied
// Caddyfile is persisted to a file Caddy starts from, so restarts keep the
// same config, and every attempt is recorded in the version history.
package apply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Krifmaz/CaddyHub/internal/caddy"
	cf "github.com/Krifmaz/CaddyHub/internal/caddyfile"
	"github.com/Krifmaz/CaddyHub/internal/diff"
	"github.com/Krifmaz/CaddyHub/internal/generator"
	"github.com/Krifmaz/CaddyHub/internal/model"
	"github.com/Krifmaz/CaddyHub/internal/registry"
	"github.com/Krifmaz/CaddyHub/internal/secrets"
	"github.com/Krifmaz/CaddyHub/internal/store"
)

// Validator is the subset of caddy.Runner used here (fakeable in tests).
type Validator interface {
	Adapt(ctx context.Context, caddyfile string) (*caddy.AdaptResult, error)
	Validate(ctx context.Context, caddyfile string) error
}

// AdminAPI is the subset of caddy.Admin used here.
type AdminAPI interface {
	LoadCaddyfile(ctx context.Context, caddyfile string, force bool) error
	Config(ctx context.Context) (json.RawMessage, error)
	Ping(ctx context.Context) error
}

// HealthChecker verifies Caddy after a load.
type HealthChecker interface {
	Check(ctx context.Context, expectHTTP bool) error
}

// Pipeline wires everything together.
type Pipeline struct {
	Store       *store.Store
	Validator   Validator
	Admin       AdminAPI
	Health      HealthChecker
	Secrets     *secrets.Materializer
	Env         generator.Env
	PersistPath string // Caddyfile that Caddy starts from (shared volume)
	Caps        func() registry.Capabilities
	// Notify is called on failures (event, message).
	Notify func(event, msg string)
	// AdminAvailable lets callers know if Caddy is reachable.
	mu sync.Mutex
}

// Plan is the result of generate+adapt+validate+diff.
type Plan struct {
	Caddyfile     string          `json:"caddyfile"`
	Previous      string          `json:"previous"`
	PreviousID    int64           `json:"previous_id"`
	Diff          string          `json:"diff"`
	Added         int             `json:"added"`
	Removed       int             `json:"removed"`
	Changed       bool            `json:"changed"`
	Warnings      []string        `json:"warnings"`
	AdaptWarnings []string        `json:"adapt_warnings"`
	Valid         bool            `json:"valid"`
	Stage         string          `json:"stage,omitempty"` // where it failed
	Errors        []caddy.Message `json:"errors,omitempty"`
}

// Result of an apply.
type Result struct {
	Plan       *Plan  `json:"plan"`
	Status     string `json:"status"` // dry_run, applied, invalid, failed, rolled_back
	Message    string `json:"message"`
	VersionID  int64  `json:"version_id,omitempty"`
	RolledBack bool   `json:"rolled_back"`
}

// Options control an apply.
type Options struct {
	DryRun  bool
	User    string
	Message string
}

// BuildInput loads the model and resolves secrets into placeholders.
func (p *Pipeline) BuildInput() (generator.Input, error) {
	var in generator.Input
	var err error
	in.Settings = p.Store.Settings()
	if in.Sites, err = p.Store.Sites(); err != nil {
		return in, err
	}
	if in.Domains, err = p.Store.Domains(); err != nil {
		return in, err
	}
	if in.Snippets, err = p.Store.Snippets(); err != nil {
		return in, err
	}
	if in.RawBlocks, err = p.Store.RawBlocks(); err != nil {
		return in, err
	}
	if p.Caps != nil {
		in.Caps = p.Caps()
	}
	in.Env = p.Env
	if in.Env.TrustedProxyRanges == nil {
		in.Env.TrustedProxyRanges = map[string][]string{}
	}
	cached := map[string][]string{}
	if p.Store.KVGetJSON("trusted_proxy_ranges", &cached) {
		for k, v := range cached {
			in.Env.TrustedProxyRanges[k] = v
		}
	}

	creds, err := p.Store.Credentials()
	if err != nil {
		return in, err
	}
	in.Credentials = map[int64]generator.CredRef{}
	var keep []string
	for _, c := range creds {
		prov, ok := registry.DNSProviderByID(c.Provider)
		if !ok {
			continue
		}
		ref := generator.CredRef{Provider: c.Provider, Fields: map[string]string{}}
		for _, f := range prov.Fields {
			v := c.Fields[f.Key]
			if v == "" {
				continue
			}
			if ph, ok := secrets.RefPlaceholder(v); ok {
				ref.Fields[f.Key] = ph
				continue
			}
			if f.Secret {
				name := fmt.Sprintf("dns-%d-%s", c.ID, f.Key)
				ph, err := p.materialize(name, v)
				if err != nil {
					return in, err
				}
				keep = append(keep, name)
				ref.Fields[f.Key] = ph
				continue
			}
			ref.Fields[f.Key] = v
		}
		in.Credentials[c.ID] = ref
	}

	// named secrets used by global options
	if v, ok := p.Store.Secret("acme_eab_mac"); ok && in.Settings.ACMEEABKeyID != "" {
		ph, err := p.materialize("acme-eab-mac", v)
		if err != nil {
			return in, err
		}
		keep = append(keep, "acme-eab-mac")
		in.Env.EABMacRef = ph
	}
	if in.Settings.CrowdSec.Enabled {
		ref := in.Settings.CrowdSec.APIKeyRef
		if ph, ok := secrets.RefPlaceholder(ref); ok {
			in.Env.CrowdSecKeyRef = ph
		} else if v, ok := p.Store.Secret("crowdsec_api_key"); ok {
			ph, err := p.materialize("crowdsec-api_key", v)
			if err != nil {
				return in, err
			}
			keep = append(keep, "crowdsec-api_key")
			in.Env.CrowdSecKeyRef = ph
		}
	}
	if p.Secrets != nil {
		p.Secrets.Prune(keep)
	}
	return in, nil
}

func (p *Pipeline) materialize(name, value string) (string, error) {
	if p.Secrets == nil {
		return "", errors.New("secrets directory not configured")
	}
	return p.Secrets.FileRef(name, value)
}

// Generate renders the current model.
func (p *Pipeline) Generate() (generator.Output, generator.Input, error) {
	in, err := p.BuildInput()
	if err != nil {
		return generator.Output{}, in, err
	}
	return generator.Generate(in), in, nil
}

// Plan generates and validates without applying.
func (p *Pipeline) Plan(ctx context.Context) (*Plan, error) {
	out, in, err := p.Generate()
	if err != nil {
		return nil, err
	}
	return p.planText(ctx, out.Caddyfile, out.Warnings, &in)
}

// planText validates a given Caddyfile. When in is non-nil a validation copy
// is generated with logs redirected to a temp dir; otherwise (rollback to an
// old snapshot) the text is validated with log paths rewritten.
func (p *Pipeline) planText(ctx context.Context, text string, warnings []string, in *generator.Input) (*Plan, error) {
	plan := &Plan{Caddyfile: text, Warnings: warnings}
	if prev, err := p.Store.LastGood(); err == nil {
		plan.Previous, plan.PreviousID = prev.Caddyfile, prev.ID
	}
	plan.Diff = diff.Unified(plan.Previous, text, "applied", "pending", 3)
	plan.Added, plan.Removed = diff.Stats(diff.Lines(plan.Previous, text))
	plan.Changed = plan.Diff != ""

	ar, err := p.Validator.Adapt(ctx, text)
	if err != nil {
		plan.Stage = "adapt"
		plan.Errors = errMessages(err)
		return plan, nil
	}
	plan.AdaptWarnings = ar.Warnings

	tmpLogs, err := os.MkdirTemp("", "caddyhub-validate-logs-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpLogs)
	var vtext string
	if in != nil {
		vin := *in
		vin.Env.LogDir = filepath.ToSlash(tmpLogs)
		vin.Env.ValidationMode = true
		vtext = generator.Generate(vin).Caddyfile
	} else {
		vtext = validationCopy(text, p.Env.LogDir, filepath.ToSlash(tmpLogs))
	}
	if err := p.Validator.Validate(ctx, vtext); err != nil {
		plan.Stage = "validate"
		plan.Errors = errMessages(err)
		return plan, nil
	}
	plan.Valid = true
	return plan, nil
}

// validationCopy rewrites log paths of an arbitrary snapshot and drops the
// default global log block so that validation errors reach stderr.
func validationCopy(text, logDir, tmp string) string {
	if blocks, err := cf.Parse(text); err == nil && len(blocks) > 0 && blocks[0].IsGlobal() {
		src := strings.ReplaceAll(text, "\r\n", "\n")
		g := blocks[0]
		for i := len(g.Body) - 1; i >= 0; i-- {
			d := g.Body[i]
			if d.Name() == "log" && len(d.Args) == 1 {
				src = src[:d.Start] + src[d.End:]
			}
		}
		text = src
	}
	if logDir != "" {
		text = strings.ReplaceAll(text, logDir+"/", tmp+"/")
	}
	return text
}

// hasSiteBlocks reports whether a Caddyfile defines any site.
func hasSiteBlocks(text string) bool {
	blocks, err := cf.Parse(text)
	if err != nil {
		return true
	}
	for _, b := range blocks {
		if !b.IsGlobal() && !b.IsSnippet() && !b.IsNamedRoute() {
			return true
		}
	}
	return false
}

func errMessages(err error) []caddy.Message {
	if ce, ok := caddy.AsError(err); ok && len(ce.Messages) > 0 {
		return ce.Messages
	}
	return []caddy.Message{{Level: "error", Text: err.Error()}}
}

// Apply runs the full pipeline for the current model.
func (p *Pipeline) Apply(ctx context.Context, opt Options) (*Result, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out, in, err := p.Generate()
	if err != nil {
		return nil, err
	}
	plan, err := p.planText(ctx, out.Caddyfile, out.Warnings, &in)
	if err != nil {
		return nil, err
	}
	expectHTTP := hasEnabledSites(in.Sites) || in.Settings.PanelDomain != ""
	return p.applyPlan(ctx, plan, opt, expectHTTP)
}

// ApplySnapshot re-applies an older version (rollback to version N).
func (p *Pipeline) ApplySnapshot(ctx context.Context, versionID int64, opt Options) (*Result, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, err := p.Store.Version(versionID)
	if err != nil {
		return nil, err
	}
	// Snapshots may reference secret files: make sure they exist.
	if _, err := p.BuildInput(); err != nil {
		return nil, err
	}
	plan, err := p.planText(ctx, v.Caddyfile, nil, nil)
	if err != nil {
		return nil, err
	}
	if opt.Message == "" {
		opt.Message = fmt.Sprintf("rollback to version %d", versionID)
	}
	return p.applyPlan(ctx, plan, opt, hasSiteBlocks(v.Caddyfile))
}

func hasEnabledSites(sites []model.Site) bool {
	for _, s := range sites {
		if s.Enabled {
			return true
		}
	}
	return false
}

func (p *Pipeline) applyPlan(ctx context.Context, plan *Plan, opt Options, expectHTTP bool) (*Result, error) {
	res := &Result{Plan: plan}
	version := ""
	if p.Caps != nil {
		version = p.Caps().VersionS
	}
	record := func(status, msg string, good bool) {
		v, err := p.Store.AddVersion(model.ConfigVersion{User: opt.User, Caddyfile: plan.Caddyfile, Status: status, Message: msg, Good: good, CaddyVersion: version})
		if err == nil {
			res.VersionID = v.ID
		}
		p.Store.PruneVersions(200)
	}

	if !plan.Valid {
		res.Status = "invalid"
		res.Message = fmt.Sprintf("%s failed: %s", plan.Stage, joinMessages(plan.Errors))
		if !opt.DryRun {
			record("invalid", res.Message, false)
			p.notify("apply_failed", "Config rejected before apply: "+res.Message)
		}
		return res, nil
	}
	if opt.DryRun {
		res.Status = "dry_run"
		res.Message = "validated; not applied (dry run)"
		return res, nil
	}

	// Snapshot what's running now so a failed health check can restore the
	// exact previous state, even if it was never applied by the panel.
	prevJSON, prevErr := p.Admin.Config(ctx)

	loadCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	err := p.Admin.LoadCaddyfile(loadCtx, plan.Caddyfile, true)
	cancel()
	if err != nil {
		// Caddy rolls back atomically on a failed /load: nothing changed.
		res.Status = "failed"
		res.Message = "load rejected by Caddy: " + err.Error()
		record("failed", res.Message, false)
		p.notify("apply_failed", res.Message)
		return res, nil
	}

	hctx, hcancel := context.WithTimeout(ctx, 45*time.Second)
	herr := p.Health.Check(hctx, expectHTTP)
	hcancel()
	if herr != nil {
		res.RolledBack = true
		rbErr := p.rollback(ctx, prevJSON, prevErr)
		res.Status = "rolled_back"
		res.Message = "health check failed after apply: " + herr.Error()
		if rbErr != nil {
			res.Message += "; ROLLBACK FAILED: " + rbErr.Error()
		} else {
			res.Message += "; previous config restored"
		}
		record("rolled_back", res.Message, false)
		p.notify("apply_failed", res.Message)
		return res, nil
	}

	if err := p.persist(plan.Caddyfile); err != nil {
		// Running config is fine but not persisted: surface loudly.
		res.Status = "applied"
		res.Message = "applied, but persisting the Caddyfile failed: " + err.Error()
		record("applied", res.Message, true)
		p.notify("apply_failed", res.Message)
		return res, nil
	}
	res.Status = "applied"
	res.Message = firstNonEmpty(opt.Message, "applied successfully")
	record("applied", res.Message, true)
	return res, nil
}

func (p *Pipeline) rollback(ctx context.Context, prevJSON json.RawMessage, prevErr error) error {
	rctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	// Prefer the exact running config captured before the load.
	if prevErr == nil && len(prevJSON) > 0 && string(prevJSON) != "null" {
		if l, ok := p.Admin.(interface {
			LoadJSON(context.Context, []byte) error
		}); ok {
			if err := l.LoadJSON(rctx, prevJSON); err == nil {
				return nil
			}
		}
	}
	// Fall back to the last good snapshot.
	if lg, err := p.Store.LastGood(); err == nil {
		return p.Admin.LoadCaddyfile(rctx, lg.Caddyfile, true)
	}
	// Last resort: the persisted file Caddy started from.
	if b, err := os.ReadFile(p.PersistPath); err == nil {
		return p.Admin.LoadCaddyfile(rctx, string(b), true)
	}
	return errors.New("no previous configuration available")
}

// persist writes the applied Caddyfile atomically.
func (p *Pipeline) persist(text string) error {
	if p.PersistPath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p.PersistPath), 0o755); err != nil {
		return err
	}
	tmp := p.PersistPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p.PersistPath)
}

func (p *Pipeline) notify(event, msg string) {
	if p.Notify != nil {
		p.Notify(event, msg)
	}
}

func joinMessages(ms []caddy.Message) string {
	var parts []string
	for _, m := range ms {
		if m.Level != "warn" {
			parts = append(parts, m.Text)
		}
	}
	if len(parts) == 0 {
		for _, m := range ms {
			parts = append(parts, m.Text)
		}
	}
	return strings.Join(parts, "; ")
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}

// ---------------------------------------------------------------- health

// DefaultHealth checks the admin API and that Caddy's HTTP listeners accept
// connections. Upstream availability is deliberately not part of it: an
// upstream being down is not a reason to roll back Caddy's config.
type DefaultHealth struct {
	Admin interface {
		Ping(ctx context.Context) error
		Config(ctx context.Context) (json.RawMessage, error)
	}
	// ProbeAddrs are host:port listeners to TCP-dial (e.g. caddy:80, caddy:443).
	ProbeAddrs []string
	Settle     time.Duration
}

// Check implements HealthChecker.
func (h *DefaultHealth) Check(ctx context.Context, expectHTTP bool) error {
	if h.Settle > 0 {
		select {
		case <-time.After(h.Settle):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	var last error
	for attempt := 0; attempt < 10; attempt++ {
		last = h.once(ctx, expectHTTP)
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%v (%w)", last, ctx.Err())
		case <-time.After(time.Second):
		}
	}
	return last
}

func (h *DefaultHealth) once(ctx context.Context, expectHTTP bool) error {
	if err := h.Admin.Ping(ctx); err != nil {
		return fmt.Errorf("admin API unreachable: %w", err)
	}
	cfg, err := h.Admin.Config(ctx)
	if err != nil {
		return fmt.Errorf("cannot read running config: %w", err)
	}
	if expectHTTP {
		var c struct {
			Apps struct {
				HTTP *struct {
					Servers map[string]json.RawMessage `json:"servers"`
				} `json:"http"`
			} `json:"apps"`
		}
		if err := json.Unmarshal(cfg, &c); err != nil {
			return fmt.Errorf("running config unreadable: %w", err)
		}
		if c.Apps.HTTP == nil || len(c.Apps.HTTP.Servers) == 0 {
			return errors.New("running config has no HTTP servers")
		}
		for _, a := range h.ProbeAddrs {
			d := net.Dialer{Timeout: 3 * time.Second}
			conn, err := d.DialContext(ctx, "tcp", a)
			if err != nil {
				return fmt.Errorf("listener %s not accepting connections: %w", a, err)
			}
			conn.Close()
		}
	}
	return nil
}
