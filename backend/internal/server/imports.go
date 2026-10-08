package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Krifmaz/CaddyHub/internal/generator"
	"github.com/Krifmaz/CaddyHub/internal/importer"
	"github.com/Krifmaz/CaddyHub/internal/model"
	"github.com/Krifmaz/CaddyHub/internal/registry"
)

// ImportPaths are files the panel can import from without pasting.
type ImportPaths struct {
	AutosaveBackup string // autosave.json saved before CaddyHub first started Caddy
	Autosave       string // Caddy's live autosave.json
	Caddyfile      string // an old Caddyfile mounted into the panel
}

// importSource is one place an existing config was found.
type importSource struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	Detail      string   `json:"detail"`
	Sites       int      `json:"sites"`
	Credentials int      `json:"credentials"`
	Kept        int      `json:"kept"`
	Hosts       []string `json:"hosts"`
}

// loadSource reads one import source. ok is false when it doesn't exist.
func (s *Server) loadSource(ctx context.Context, id string) (res *importer.Result, label string, ok bool, err error) {
	readJSONFile := func(path string) (*importer.Result, bool, error) {
		if path == "" {
			return nil, false, nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, false, nil
		}
		r, err := importer.ImportJSON(b)
		return r, true, err
	}
	switch id {
	case "admin":
		// The running config only counts until CaddyHub has applied its own.
		if s.Admin == nil {
			return nil, "", false, nil
		}
		if _, err := s.Store.LastGood(); err == nil {
			return nil, "", false, nil
		}
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		raw, err := s.Admin.Config(cctx)
		if err != nil || len(raw) == 0 || string(raw) == "null" {
			return nil, "", false, nil
		}
		r, err := importer.ImportJSON(raw)
		return r, "the running Caddy", true, err
	case "autosave-backup":
		r, ok, err := readJSONFile(s.Imports.AutosaveBackup)
		return r, "Caddy's saved config from before CaddyHub", ok, err
	case "autosave":
		r, ok, err := readJSONFile(s.Imports.Autosave)
		return r, "Caddy's autosave.json", ok, err
	case "caddyfile":
		if s.Imports.Caddyfile == "" {
			return nil, "", false, nil
		}
		b, err := os.ReadFile(s.Imports.Caddyfile)
		if err != nil {
			return nil, "", false, nil
		}
		r, err := importer.Import(string(b))
		return r, "the mounted Caddyfile (" + s.Imports.Caddyfile + ")", true, err
	}
	return nil, "", false, errors.New("unknown import source")
}

var sourceOrder = []string{"admin", "autosave-backup", "autosave", "caddyfile"}

// importSources lists existing configs worth importing, best first.
func (s *Server) importSources(w http.ResponseWriter, r *http.Request) {
	out := []importSource{}
	seen := map[string]bool{}
	for _, id := range sourceOrder {
		res, label, ok, err := s.loadSource(r.Context(), id)
		if !ok || err != nil || len(res.Sites)+len(res.RawBlocks) == 0 {
			continue
		}
		// Skip a source identical to one already listed (e.g. live config = autosave).
		fp, _ := json.Marshal(importer.Fingerprint(res))
		if seen[string(fp)] {
			continue
		}
		seen[string(fp)] = true
		src := importSource{ID: id, Label: label, Sites: len(res.Sites), Credentials: len(res.Credentials), Kept: len(res.RawBlocks)}
		for _, st := range res.Sites {
			src.Hosts = append(src.Hosts, st.Hosts...)
		}
		parts := []string{fmt.Sprintf("%d site(s)", src.Sites)}
		if src.Credentials > 0 {
			parts = append(parts, fmt.Sprintf("%d DNS provider account(s)", src.Credentials))
		}
		if src.Kept > 0 {
			parts = append(parts, fmt.Sprintf("%d block(s) kept for manual review", src.Kept))
		}
		src.Detail = strings.Join(parts, ", ")
		out = append(out, src)
	}
	writeJSON(w, http.StatusOK, out)
}

type importRequest struct {
	Source    string `json:"source"`
	Caddyfile string `json:"caddyfile"`
	Replace   bool   `json:"replace"`
	Settings  bool   `json:"settings"`
}

func (s *Server) loadImport(w http.ResponseWriter, r *http.Request) (*importer.Result, importRequest, bool) {
	var req importRequest
	if !readJSON(w, r, &req) {
		return nil, req, false
	}
	var res *importer.Result
	var err error
	switch {
	case req.Source != "":
		var ok bool
		res, _, ok, err = s.loadSource(r.Context(), req.Source)
		if err == nil && !ok {
			err = errors.New("that config is no longer available")
		}
	case strings.TrimSpace(req.Caddyfile) != "":
		text := strings.TrimSpace(req.Caddyfile)
		if strings.HasPrefix(text, "{") && json.Valid([]byte(text)) {
			res, err = importer.ImportJSON([]byte(text)) // pasted JSON config
		} else {
			res, err = importer.Import(req.Caddyfile)
		}
	default:
		err = errors.New("paste a Caddyfile or pick a detected config")
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return nil, req, false
	}
	return res, req, true
}

// verifyResult is the round-trip check: regenerate the imported model,
// adapt it with Caddy and compare what every host does.
type verifyResult struct {
	Checked     bool     `json:"checked"`
	Sites       int      `json:"sites"`
	Differences []string `json:"differences"`
	Error       string   `json:"error,omitempty"`
}

func (s *Server) verifyImport(ctx context.Context, res *importer.Result) verifyResult {
	v := verifyResult{Sites: len(res.Sites), Differences: []string{}}
	if s.Runner == nil || !s.Runner.Available() {
		v.Error = "Caddy binary not available, so the regenerated config couldn't be checked"
		return v
	}
	env := generator.Env{}
	if s.Pipeline != nil {
		env = s.Pipeline.Env
	}
	env.LogDir = "" // logs don't affect behavior and need real paths
	gen := generator.Generate(importer.PreviewInput(res, s.Store.Settings(), env, s.caps()))
	adapted, err := s.Runner.Adapt(ctx, gen.Caddyfile)
	if err != nil {
		v.Error = "the regenerated config didn't pass Caddy's check: " + err.Error()
		return v
	}
	back, err := importer.ImportJSON(adapted.JSON)
	if err != nil {
		v.Error = err.Error()
		return v
	}
	v.Checked = true
	v.Differences = importer.CompareFingerprints(importer.Fingerprint(res), importer.Fingerprint(back))
	if v.Differences == nil {
		v.Differences = []string{}
	}
	return v
}

func (s *Server) importPreview(w http.ResponseWriter, r *http.Request) {
	res, _, ok := s.loadImport(w, r)
	if !ok {
		return
	}
	v := s.verifyImport(r.Context(), res)
	for i := range res.Credentials { // never echo secrets back
		for k, val := range res.Credentials[i].Fields {
			if val != "" && !strings.HasPrefix(val, "env:") && !strings.HasPrefix(val, "file:") {
				res.Credentials[i].Fields[k] = masked
			}
		}
	}
	writeJSON(w, http.StatusOK, struct {
		*importer.Result
		Verify verifyResult `json:"verify"`
	}{res, v})
}

// importCommit stores an import. Nothing is applied: the user reviews the
// result and applies through the normal pipeline. With replace, existing
// sites, snippets and raw blocks are removed first.
func (s *Server) importCommit(w http.ResponseWriter, r *http.Request) {
	res, req, ok := s.loadImport(w, r)
	if !ok {
		return
	}
	if req.Replace {
		old, _ := s.Store.Sites()
		for _, st := range old {
			s.Store.DeleteSite(st.ID)
		}
		sn, _ := s.Store.Snippets()
		for _, x := range sn {
			s.Store.DeleteSnippet(x.ID)
		}
		rb, _ := s.Store.RawBlocks()
		for _, x := range rb {
			s.Store.DeleteRawBlock(x.ID)
		}
	}
	existingHosts := map[string]bool{}
	if cur, err := s.Store.Sites(); err == nil {
		for _, st := range cur {
			for _, h := range st.Hosts {
				existingHosts[h] = true
			}
		}
	}
	var skipped []string
	nSites := 0
	for _, st := range res.Sites {
		dup := false
		for _, h := range st.Hosts {
			if existingHosts[h] {
				dup = true
			}
		}
		if dup {
			skipped = append(skipped, strings.Join(st.Hosts, ", "))
			continue
		}
		st.ID, st.Position = 0, 0
		if _, err := s.Store.CreateSite(st); err != nil {
			storeErr(w, err)
			return
		}
		nSites++
	}
	existingSn := map[string]bool{}
	if sn, err := s.Store.Snippets(); err == nil {
		for _, x := range sn {
			existingSn[x.Name] = true
		}
	}
	for _, sn := range res.Snippets {
		if existingSn[sn.Name] {
			skipped = append(skipped, "snippet "+sn.Name)
			continue
		}
		sn.ID = 0
		s.Store.SaveSnippet(sn)
	}
	for _, b := range res.RawBlocks {
		b.ID = 0
		s.Store.SaveRawBlock(b)
	}

	// DNS credentials (encrypted at rest by the store) and domains.
	credIDs := map[string]int64{}
	for _, c := range res.Credentials {
		name := c.Provider + " (imported)"
		if prov, ok := registry.DNSProviderByID(c.Provider); ok {
			name = prov.Name + " (imported)"
		}
		saved, err := s.Store.SaveCredential(model.DNSCredential{Name: name, Provider: c.Provider, Fields: c.Fields})
		if err == nil {
			credIDs[c.Key] = saved.ID
		}
	}
	existingDom := map[string]bool{}
	if ds, err := s.Store.Domains(); err == nil {
		for _, d := range ds {
			existingDom[d.Name] = true
		}
	}
	for _, d := range res.Domains {
		if existingDom[d.Name] {
			continue
		}
		dom := model.Domain{Name: d.Name, Challenge: d.Challenge, Wildcard: d.Wildcard}
		if id, ok := credIDs[d.CredentialKey]; ok {
			dom.CredentialID = &id
		} else if dom.Challenge == model.ChallengeDNS {
			dom.Challenge, dom.Wildcard = model.ChallengeHTTP, false
		}
		s.Store.SaveDomain(dom)
	}
	if req.Settings {
		s.Store.UpdateSettings(func(st *model.Settings) {
			if res.Email != "" {
				st.ACMEEmail = res.Email
			}
			if res.ACMECA != "" {
				st.ACMECA, st.ACMECAURL = res.ACMECA, res.ACMECAURL
			}
			if res.RawGlobal != "" {
				st.RawGlobal = res.RawGlobal
			}
		})
	}
	from := "pasted config"
	if req.Source != "" {
		from = req.Source
	}
	s.audit(r, "config.import", fmt.Sprintf("%d sites", nSites), "from "+from)
	writeJSON(w, http.StatusOK, map[string]any{"sites": nSites, "snippets": len(res.Snippets), "raw_blocks": len(res.RawBlocks),
		"credentials": len(res.Credentials), "skipped": skipped, "report": res.Report, "warnings": res.Warnings})
}
