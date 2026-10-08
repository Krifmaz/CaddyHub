package server

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Krifmaz/CaddyHub/internal/apply"
	"github.com/Krifmaz/CaddyHub/internal/auth"
	"github.com/Krifmaz/CaddyHub/internal/diff"
	"github.com/Krifmaz/CaddyHub/internal/generator"
	"github.com/Krifmaz/CaddyHub/internal/importer"
	"github.com/Krifmaz/CaddyHub/internal/model"
	"github.com/Krifmaz/CaddyHub/internal/notify"
	"github.com/Krifmaz/CaddyHub/internal/registry"
	"github.com/Krifmaz/CaddyHub/internal/store"
)

func (s *Server) routes() {
	m := s.mux
	V, E, A := auth.RoleViewer, auth.RoleEditor, auth.RoleAdmin

	m.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	m.HandleFunc("GET /api/me", s.handleMe)
	m.HandleFunc("POST /api/setup", s.handleSetup)
	m.HandleFunc("POST /api/login", s.handleLogin)
	m.HandleFunc("POST /api/login/totp", s.handleLoginTOTP)
	m.HandleFunc("POST /api/logout", s.handleLogout)
	m.HandleFunc("POST /api/me/password", s.guard(V, s.handleChangePassword))
	m.HandleFunc("POST /api/me/totp/begin", s.guard(V, s.handleTOTPBegin))
	m.HandleFunc("POST /api/me/totp/enable", s.guard(V, s.handleTOTPEnable))
	m.HandleFunc("POST /api/me/totp/disable", s.guard(V, s.handleTOTPDisable))

	m.HandleFunc("GET /api/meta", s.guard(V, s.handleMeta))
	m.HandleFunc("GET /api/status", s.guard(V, s.handleStatus))
	m.HandleFunc("GET /api/upstreams", s.guard(V, s.handleUpstreams))

	m.HandleFunc("GET /api/sites", s.guard(V, s.listSites))
	m.HandleFunc("POST /api/sites", s.guard(E, s.createSite))
	m.HandleFunc("POST /api/sites/bulk", s.guard(E, s.bulkSites))
	m.HandleFunc("GET /api/sites/{id}", s.guard(V, s.getSite))
	m.HandleFunc("PUT /api/sites/{id}", s.guard(E, s.updateSite))
	m.HandleFunc("DELETE /api/sites/{id}", s.guard(E, s.deleteSite))
	m.HandleFunc("POST /api/sites/{id}/clone", s.guard(E, s.cloneSite))

	m.HandleFunc("GET /api/domains", s.guard(V, s.listDomains))
	m.HandleFunc("POST /api/domains", s.guard(A, s.saveDomain))
	m.HandleFunc("PUT /api/domains/{id}", s.guard(A, s.saveDomain))
	m.HandleFunc("DELETE /api/domains/{id}", s.guard(A, s.deleteDomain))

	m.HandleFunc("GET /api/dns-credentials", s.guard(A, s.listCredentials))
	m.HandleFunc("POST /api/dns-credentials", s.guard(A, s.saveCredential))
	m.HandleFunc("PUT /api/dns-credentials/{id}", s.guard(A, s.saveCredential))
	m.HandleFunc("DELETE /api/dns-credentials/{id}", s.guard(A, s.deleteCredential))

	m.HandleFunc("GET /api/snippets", s.guard(V, s.listSnippets))
	m.HandleFunc("POST /api/snippets", s.guard(E, s.saveSnippet))
	m.HandleFunc("PUT /api/snippets/{id}", s.guard(E, s.saveSnippet))
	m.HandleFunc("DELETE /api/snippets/{id}", s.guard(E, s.deleteSnippet))

	m.HandleFunc("GET /api/raw-blocks", s.guard(V, s.listRawBlocks))
	m.HandleFunc("POST /api/raw-blocks", s.guard(A, s.saveRawBlock))
	m.HandleFunc("PUT /api/raw-blocks/{id}", s.guard(A, s.saveRawBlock))
	m.HandleFunc("DELETE /api/raw-blocks/{id}", s.guard(A, s.deleteRawBlock))

	m.HandleFunc("GET /api/settings", s.guard(V, s.getSettings))
	m.HandleFunc("PUT /api/settings", s.guard(A, s.putSettings))

	m.HandleFunc("GET /api/config/preview", s.guard(V, s.handlePreview))
	m.HandleFunc("POST /api/config/plan", s.guard(V, s.handlePlan))
	m.HandleFunc("POST /api/config/apply", s.guard(E, s.handleApply))
	m.HandleFunc("GET /api/config/export", s.guard(V, s.handleExport))
	m.HandleFunc("POST /api/config/validate", s.guard(E, s.handleValidateText))
	m.HandleFunc("GET /api/versions", s.guard(V, s.listVersions))
	m.HandleFunc("GET /api/versions/diff", s.guard(V, s.diffVersions))
	m.HandleFunc("GET /api/versions/{id}", s.guard(V, s.getVersion))
	m.HandleFunc("POST /api/versions/{id}/rollback", s.guard(E, s.rollbackVersion))

	m.HandleFunc("POST /api/import/preview", s.guard(A, s.importPreview))
	m.HandleFunc("POST /api/import/commit", s.guard(A, s.importCommit))

	m.HandleFunc("GET /api/users", s.guard(A, s.listUsers))
	m.HandleFunc("POST /api/users", s.guard(A, s.saveUser))
	m.HandleFunc("PUT /api/users/{id}", s.guard(A, s.saveUser))
	m.HandleFunc("DELETE /api/users/{id}", s.guard(A, s.deleteUser))
	m.HandleFunc("GET /api/api-keys", s.guard(A, s.listKeys))
	m.HandleFunc("POST /api/api-keys", s.guard(A, s.createKey))
	m.HandleFunc("DELETE /api/api-keys/{id}", s.guard(A, s.deleteKey))

	m.HandleFunc("GET /api/notifications", s.guard(A, s.listChannels))
	m.HandleFunc("POST /api/notifications", s.guard(A, s.saveChannel))
	m.HandleFunc("PUT /api/notifications/{id}", s.guard(A, s.saveChannel))
	m.HandleFunc("DELETE /api/notifications/{id}", s.guard(A, s.deleteChannel))
	m.HandleFunc("POST /api/notifications/test", s.guard(A, s.testChannel))

	m.HandleFunc("GET /api/audit", s.guard(A, s.listAudit))

	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { writeErr(w, http.StatusNotFound, "no such API endpoint") })
	m.Handle("/", s.spa())
}

// ---------------------------------------------------------------- meta & status

func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	caps := s.caps()
	type provider struct {
		registry.DNSProvider
		Available bool `json:"available"`
	}
	var provs []provider
	for _, p := range registry.DNSProviders {
		provs = append(provs, provider{p, caps.HasModule(p.Module())})
	}
	cas := make([]string, 0, len(generator.CAPresets))
	for k := range generator.CAPresets {
		cas = append(cas, k)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"dns_providers":       provs,
		"features":            caps.AllFeatureStatus(),
		"ca_presets":          cas,
		"resolver_presets":    generator.ResolverPresets,
		"notification_types":  notify.Types,
		"notification_events": notify.AllEvents,
	})
}

func (s *Server) caps() registry.Capabilities {
	if s.Caps == nil {
		return registry.Capabilities{}
	}
	return s.Caps()
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	caps := s.caps()
	res := map[string]any{
		"panel_version":  s.Version,
		"caddy_version":  caps.VersionS,
		"caddy_detected": caps.Detected,
		"caddy_binary":   s.Runner != nil && s.Runner.Available(),
		"schema":         s.Store.SchemaVersion(),
	}
	if s.Admin != nil {
		err := s.Admin.Ping(ctx)
		res["caddy_reachable"] = err == nil
		if err != nil {
			res["caddy_error"] = err.Error()
		}
	}
	if v, err := s.Store.LastVersion(); err == nil {
		v.Caddyfile = ""
		res["last_apply"] = v
	}
	// Pending = the model differs from what was last applied successfully.
	if out, _, err := s.Pipeline.Generate(); err == nil {
		lg, lerr := s.Store.LastGood()
		res["pending_changes"] = lerr != nil || lg.Caddyfile != out.Caddyfile
	}
	sites, _ := s.Store.Sites()
	en := 0
	for _, st := range sites {
		if st.Enabled {
			en++
		}
	}
	res["sites_total"], res["sites_enabled"] = len(sites), en
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleUpstreams(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	ups, err := s.Admin.Upstreams(ctx)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "can't reach Caddy: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ups)
}

// ---------------------------------------------------------------- config

func (s *Server) handlePreview(w http.ResponseWriter, r *http.Request) {
	out, _, err := s.Pipeline.Generate()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request) {
	plan, err := s.Pipeline.Plan(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DryRun  bool   `json:"dry_run"`
		Message string `json:"message"`
	}
	if r.ContentLength > 0 && !readJSON(w, r, &req) {
		return
	}
	dry := req.DryRun || s.Store.Settings().DryRun
	res, err := s.Pipeline.Apply(r.Context(), apply.Options{DryRun: dry, User: s.username(r), Message: req.Message})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !dry {
		s.audit(r, "config.apply", res.Status, res.Message)
	}
	writeJSON(w, http.StatusOK, res)
}

// handleValidateText checks an arbitrary snippet of Caddyfile text (raw site
// snippets, raw blocks) by wrapping it the way it will be used.
func (s *Server) handleValidateText(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text    string `json:"text"`
		Context string `json:"context"` // "site" (inside a site block) or "top"
	}
	if !readJSON(w, r, &req) {
		return
	}
	if s.Runner == nil || !s.Runner.Available() {
		writeErr(w, http.StatusServiceUnavailable, "caddy binary not available for validation")
		return
	}
	text := req.Text
	if req.Context == "site" {
		text = "{\n\tadmin off\n}\n\nhttp://validate.invalid {\n" + req.Text + "\n}\n"
	} else {
		text = "{\n\tadmin off\n}\n\n" + req.Text + "\n"
	}
	_, err := s.Runner.Adapt(r.Context(), text)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true})
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	text := ""
	if r.URL.Query().Get("source") == "applied" {
		v, err := s.Store.LastGood()
		if err != nil {
			writeErr(w, http.StatusNotFound, "nothing has been applied yet")
			return
		}
		text = v.Caddyfile
	} else {
		out, _, err := s.Pipeline.Generate()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		text = out.Caddyfile
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="Caddyfile"`)
	w.Write([]byte(text))
}

func (s *Server) listVersions(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	vs, err := s.Store.Versions(limit)
	if err != nil {
		storeErr(w, err)
		return
	}
	for i := range vs {
		vs[i].Caddyfile = ""
	}
	writeJSON(w, http.StatusOK, vs)
}

func (s *Server) getVersion(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	v, err := s.Store.Version(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// diffVersions compares two versions; b=0 (or missing) means the pending config.
func (s *Server) diffVersions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	a, _ := strconv.ParseInt(q.Get("a"), 10, 64)
	b, _ := strconv.ParseInt(q.Get("b"), 10, 64)
	text := func(id int64) (string, string, error) {
		if id == 0 {
			out, _, err := s.Pipeline.Generate()
			return out.Caddyfile, "pending", err
		}
		v, err := s.Store.Version(id)
		return v.Caddyfile, fmt.Sprintf("version %d", id), err
	}
	ta, na, err := text(a)
	if err != nil {
		storeErr(w, err)
		return
	}
	tb, nb, err := text(b)
	if err != nil {
		storeErr(w, err)
		return
	}
	ins, del := diff.Stats(diff.Lines(ta, tb))
	writeJSON(w, http.StatusOK, map[string]any{"diff": diff.Unified(ta, tb, na, nb, 3), "added": ins, "removed": del})
}

func (s *Server) rollbackVersion(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	res, err := s.Pipeline.ApplySnapshot(r.Context(), id, apply.Options{User: s.username(r)})
	if err != nil {
		storeErr(w, err)
		return
	}
	s.audit(r, "config.rollback", fmt.Sprint(id), res.Status+": "+res.Message)
	writeJSON(w, http.StatusOK, res)
}

// ---------------------------------------------------------------- import

func (s *Server) importPreview(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Caddyfile string `json:"caddyfile"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	res, err := importer.Import(req.Caddyfile)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	for i := range res.Credentials { // never echo secrets back
		for k, v := range res.Credentials[i].Fields {
			if v != "" && !strings.HasPrefix(v, "env:") && !strings.HasPrefix(v, "file:") {
				res.Credentials[i].Fields[k] = "••••••"
			}
		}
	}
	writeJSON(w, http.StatusOK, res)
}

// importCommit stores an imported Caddyfile. With replace, existing sites,
// snippets and raw blocks are removed first (domains/credentials are kept).
func (s *Server) importCommit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Caddyfile string `json:"caddyfile"`
		Replace   bool   `json:"replace"`
		Settings  bool   `json:"settings"` // also take email/CA/global options
	}
	if !readJSON(w, r, &req) {
		return
	}
	res, err := importer.Import(req.Caddyfile)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
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

	// DNS credentials and domains found in tls/acme_dns directives.
	credIDs := map[string]int64{}
	for _, c := range res.Credentials {
		prov, ok := registry.DNSProviderByID(c.Provider)
		name := c.Provider + " (imported)"
		if ok {
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
		dom := model.Domain{Name: d.Name, Challenge: d.Challenge}
		if id, ok := credIDs[d.CredentialKey]; ok {
			dom.CredentialID = &id
		} else if dom.Challenge == model.ChallengeDNS {
			dom.Challenge = model.ChallengeHTTP
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
	s.audit(r, "config.import", fmt.Sprintf("%d sites", nSites), "")
	writeJSON(w, http.StatusOK, map[string]any{"sites": nSites, "snippets": len(res.Snippets), "raw_blocks": len(res.RawBlocks), "skipped": skipped, "report": res.Report})
}

// ---------------------------------------------------------------- users & keys

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	us, err := s.Store.Users()
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, us)
}

func (s *Server) saveUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
		Disabled bool   `json:"disabled"`
		Reset2FA bool   `json:"reset_2fa"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !auth.ValidRole(req.Role) {
		writeErr(w, http.StatusBadRequest, "role must be admin, editor or viewer")
		return
	}
	var u store.User
	if r.PathValue("id") != "" {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		cur, err := s.Store.UserByID(id)
		if err != nil {
			storeErr(w, err)
			return
		}
		u = cur
		demote := u.Role == auth.RoleAdmin && (req.Role != auth.RoleAdmin || req.Disabled)
		if demote && !u.Disabled && s.Store.AdminCount() <= 1 {
			writeErr(w, http.StatusConflict, "you can't remove the last admin")
			return
		}
	} else if req.Password == "" {
		writeErr(w, http.StatusBadRequest, "set a password for the new user")
		return
	}
	u.Username = strings.TrimSpace(req.Username)
	if u.Username == "" {
		writeErr(w, http.StatusBadRequest, "username is required")
		return
	}
	u.Role, u.Disabled = req.Role, req.Disabled
	if req.Reset2FA {
		u.TOTPEnabled, u.TOTPSecret = false, ""
	}
	if req.Password != "" {
		if err := auth.PasswordPolicy(req.Password); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		h, err := auth.HashPassword(req.Password)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		u.PasswordHash = h
	}
	u, err := s.Store.SaveUser(u)
	if err != nil {
		storeErr(w, err)
		return
	}
	if u.Disabled || req.Password != "" {
		s.Store.DeleteUserSessions(u.ID, "")
	}
	s.audit(r, "user.save", u.Username, u.Role)
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	u, err := s.Store.UserByID(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	if id == who(r).User.ID {
		writeErr(w, http.StatusConflict, "you can't delete yourself")
		return
	}
	if u.Role == auth.RoleAdmin && !u.Disabled && s.Store.AdminCount() <= 1 {
		writeErr(w, http.StatusConflict, "you can't delete the last admin")
		return
	}
	s.Store.DeleteUserSessions(id, "")
	if err := s.Store.DeleteUser(id); err != nil {
		storeErr(w, err)
		return
	}
	s.audit(r, "user.delete", u.Username, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request) {
	ks, err := s.Store.APIKeys()
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ks)
}

func (s *Server) createKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Role     string `json:"role"`
		ValidDay int    `json:"valid_days"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !auth.ValidRole(req.Role) {
		writeErr(w, http.StatusBadRequest, "role must be admin, editor or viewer")
		return
	}
	tok := "chk_" + auth.RandomToken(32)
	k := store.APIKey{Name: strings.TrimSpace(req.Name), Prefix: tok[:12], Hash: auth.TokenHash(tok), Role: req.Role, UserID: who(r).User.ID}
	if req.ValidDay > 0 {
		t := time.Now().UTC().Add(time.Duration(req.ValidDay) * 24 * time.Hour)
		k.ExpiresAt = &t
	}
	k, err := s.Store.CreateAPIKey(k)
	if err != nil {
		storeErr(w, err)
		return
	}
	s.audit(r, "api_key.create", k.Name, k.Role)
	writeJSON(w, http.StatusCreated, map[string]any{"key": k, "token": tok})
}

func (s *Server) deleteKey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.Store.DeleteAPIKey(id); err != nil {
		storeErr(w, err)
		return
	}
	s.audit(r, "api_key.delete", fmt.Sprint(id), "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------- notifications

const masked = "••••••"

func maskChannel(c store.Channel) store.Channel {
	cfg := map[string]string{}
	for k, v := range c.Config {
		if notify.SecretFields[k] && v != "" {
			v = masked
		}
		cfg[k] = v
	}
	c.Config = cfg
	return c
}

func (s *Server) listChannels(w http.ResponseWriter, r *http.Request) {
	cs, err := s.Store.Channels()
	if err != nil {
		storeErr(w, err)
		return
	}
	for i := range cs {
		cs[i] = maskChannel(cs[i])
	}
	writeJSON(w, http.StatusOK, cs)
}

// channelFromRequest merges masked secret fields with stored values.
func (s *Server) channelFromRequest(w http.ResponseWriter, r *http.Request) (store.Channel, bool) {
	var c store.Channel
	if !readJSON(w, r, &c) {
		return c, false
	}
	if _, ok := notify.Types[c.Type]; !ok {
		writeErr(w, http.StatusBadRequest, "unknown notification type")
		return c, false
	}
	if r.PathValue("id") != "" {
		id, ok := pathID(w, r)
		if !ok {
			return c, false
		}
		c.ID = id
	}
	if c.ID != 0 {
		cs, _ := s.Store.Channels()
		for _, old := range cs {
			if old.ID == c.ID {
				for k, v := range c.Config {
					if v == masked {
						c.Config[k] = old.Config[k]
					}
				}
			}
		}
	}
	return c, true
}

func (s *Server) saveChannel(w http.ResponseWriter, r *http.Request) {
	c, ok := s.channelFromRequest(w, r)
	if !ok {
		return
	}
	c, err := s.Store.SaveChannel(c)
	if err != nil {
		storeErr(w, err)
		return
	}
	s.audit(r, "notification.save", c.Name, c.Type)
	writeJSON(w, http.StatusOK, maskChannel(c))
}

func (s *Server) deleteChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.Store.DeleteChannel(id); err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) testChannel(w http.ResponseWriter, r *http.Request) {
	c, ok := s.channelFromRequest(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := s.Notifier.Test(ctx, c); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	es, err := s.Store.AuditLog(r.Context(), q.Get("q"), limit, offset)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, es)
}
