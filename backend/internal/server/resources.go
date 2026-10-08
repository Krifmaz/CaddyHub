package server

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/Krifmaz/CaddyHub/internal/auth"
	"github.com/Krifmaz/CaddyHub/internal/generator"
	"github.com/Krifmaz/CaddyHub/internal/importer"
	"github.com/Krifmaz/CaddyHub/internal/model"
	"github.com/Krifmaz/CaddyHub/internal/registry"
)

// ---------------------------------------------------------------- sites

var validKinds = map[string]bool{model.KindProxy: true, model.KindStatic: true, model.KindRedirect: true, model.KindRespond: true, model.KindNone: true}

// normalizeSite validates a site and hashes any plaintext basic-auth
// passwords (the UI sends new passwords in the hash field).
func normalizeSite(st *model.Site) error {
	st.Name = strings.TrimSpace(st.Name)
	var hosts []string
	seen := map[string]bool{}
	for _, h := range st.Hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || seen[h] {
			continue
		}
		h = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(h, "https://"), "http://"), "/")
		if !importer.ValidHost(strings.TrimPrefix(h, "*.")) {
			if strings.Contains(h, ":") {
				return fmt.Errorf("%q: enter just the hostname, without a port", h)
			}
			return fmt.Errorf("%q is not a valid hostname", h)
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	if len(hosts) == 0 {
		return fmt.Errorf("add at least one hostname")
	}
	st.Hosts = hosts
	if st.Name == "" {
		st.Name = hosts[0]
	}
	if !validKinds[st.Kind] {
		return fmt.Errorf("unknown site type %q", st.Kind)
	}
	c := &st.Config
	switch st.Kind {
	case model.KindProxy:
		if c.Proxy == nil || len(nonEmpty(c.Proxy.Upstreams)) == 0 {
			return fmt.Errorf("a reverse proxy needs at least one upstream (e.g. localhost:8080)")
		}
		c.Proxy.Upstreams = nonEmpty(c.Proxy.Upstreams)
	case model.KindStatic:
		if c.Static == nil || strings.TrimSpace(c.Static.Root) == "" {
			return fmt.Errorf("a file server needs a root folder")
		}
	case model.KindRedirect:
		if c.Redirect == nil || strings.TrimSpace(c.Redirect.To) == "" {
			return fmt.Errorf("a redirect needs a target URL")
		}
	case model.KindRespond:
		if c.Respond == nil {
			c.Respond = &model.RespondConfig{}
		}
	}
	for i := range c.Routes {
		rt := &c.Routes[i]
		rt.Path = strings.TrimSpace(rt.Path)
		if rt.Path == "" || !strings.HasPrefix(rt.Path, "/") {
			return fmt.Errorf("route %d: path must start with / (e.g. /api/*)", i+1)
		}
		if rt.Kind == model.KindProxy && (rt.Proxy == nil || len(nonEmpty(rt.Proxy.Upstreams)) == 0) {
			return fmt.Errorf("route %s: needs an upstream", rt.Path)
		}
		if rt.Proxy != nil {
			rt.Proxy.Upstreams = nonEmpty(rt.Proxy.Upstreams)
		}
	}
	for i := range c.Access.BasicAuth {
		u := &c.Access.BasicAuth[i]
		u.Username = strings.TrimSpace(u.Username)
		if u.Username == "" {
			return fmt.Errorf("basic auth: username is required")
		}
		if !strings.HasPrefix(u.Hash, "$2") {
			if u.Hash == "" {
				return fmt.Errorf("basic auth: set a password for %s", u.Username)
			}
			h, err := auth.BcryptHash(u.Hash)
			if err != nil {
				return err
			}
			u.Hash = h
		}
	}
	if st.Tags == nil {
		st.Tags = []string{}
	}
	return nil
}

func nonEmpty(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (s *Server) listSites(w http.ResponseWriter, r *http.Request) {
	sites, err := s.Store.Sites()
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sites)
}

func (s *Server) getSite(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	st, err := s.Store.Site(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) createSite(w http.ResponseWriter, r *http.Request) {
	var st model.Site
	if !readJSON(w, r, &st) {
		return
	}
	st.ID = 0
	if err := normalizeSite(&st); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.hostConflict(st); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	st, err := s.Store.CreateSite(st)
	if err != nil {
		storeErr(w, err)
		return
	}
	s.audit(r, "site.create", st.Name, strings.Join(st.Hosts, ", "))
	writeJSON(w, http.StatusCreated, st)
}

func (s *Server) updateSite(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	cur, err := s.Store.Site(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	var st model.Site
	if !readJSON(w, r, &st) {
		return
	}
	st.ID, st.CreatedAt = id, cur.CreatedAt
	if st.Position == 0 {
		st.Position = cur.Position
	}
	if err := normalizeSite(&st); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.hostConflict(st); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if err := s.Store.UpdateSite(st); err != nil {
		storeErr(w, err)
		return
	}
	s.audit(r, "site.update", st.Name, "")
	st, _ = s.Store.Site(id)
	writeJSON(w, http.StatusOK, st)
}

// hostConflict rejects a hostname that another enabled site already serves:
// Caddy refuses duplicate site addresses.
func (s *Server) hostConflict(st model.Site) error {
	if !st.Enabled {
		return nil
	}
	all, err := s.Store.Sites()
	if err != nil {
		return nil
	}
	mine := map[string]bool{}
	for _, h := range st.Hosts {
		mine[h] = true
	}
	for _, o := range all {
		if o.ID == st.ID || !o.Enabled {
			continue
		}
		for _, h := range o.Hosts {
			if mine[h] {
				return fmt.Errorf("%s is already used by site %q", h, o.Name)
			}
		}
	}
	return nil
}

func (s *Server) deleteSite(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	st, err := s.Store.Site(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	if err := s.Store.DeleteSite(id); err != nil {
		storeErr(w, err)
		return
	}
	s.audit(r, "site.delete", st.Name, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// cloneSite copies a site, disabled, so it doesn't clash with the original.
func (s *Server) cloneSite(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	st, err := s.Store.Site(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	st.ID, st.Position, st.Enabled = 0, 0, false
	st.Name += " (copy)"
	st, err = s.Store.CreateSite(st)
	if err != nil {
		storeErr(w, err)
		return
	}
	s.audit(r, "site.clone", st.Name, "")
	writeJSON(w, http.StatusCreated, st)
}

func (s *Server) bulkSites(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs    []int64 `json:"ids"`
		Action string  `json:"action"` // enable, disable, delete, reorder
	}
	if !readJSON(w, r, &req) {
		return
	}
	var err error
	switch req.Action {
	case "enable", "disable":
		if req.Action == "enable" {
			for _, id := range req.IDs {
				st, e := s.Store.Site(id)
				if e != nil {
					continue
				}
				st.Enabled = true
				if e := s.hostConflict(st); e != nil {
					writeErr(w, http.StatusConflict, e.Error())
					return
				}
			}
		}
		err = s.Store.SetSitesEnabled(req.IDs, req.Action == "enable")
	case "delete":
		for _, id := range req.IDs {
			if e := s.Store.DeleteSite(id); e != nil && err == nil {
				err = e
			}
		}
	case "reorder":
		err = s.Store.ReorderSites(req.IDs)
	default:
		writeErr(w, http.StatusBadRequest, "unknown action")
		return
	}
	if err != nil {
		storeErr(w, err)
		return
	}
	s.audit(r, "site."+req.Action, fmt.Sprintf("%d sites", len(req.IDs)), "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------- domains

func (s *Server) listDomains(w http.ResponseWriter, r *http.Request) {
	ds, err := s.Store.Domains()
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ds)
}

func (s *Server) saveDomain(w http.ResponseWriter, r *http.Request) {
	var d model.Domain
	if !readJSON(w, r, &d) {
		return
	}
	d.ID = 0
	if r.PathValue("id") != "" {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		d.ID = id
	}
	d.Name = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(d.Name, "*.")))
	if d.Name == "" || !importer.ValidHost(d.Name) {
		writeErr(w, http.StatusBadRequest, "enter a domain like example.com")
		return
	}
	switch d.Challenge {
	case "":
		d.Challenge = model.ChallengeHTTP
	case model.ChallengeHTTP, model.ChallengeTLSALPN:
	case model.ChallengeDNS:
		if d.CredentialID == nil {
			writeErr(w, http.StatusBadRequest, "DNS-01 needs a DNS provider account")
			return
		}
		if _, err := s.Store.Credential(*d.CredentialID); err != nil {
			writeErr(w, http.StatusBadRequest, "that DNS provider account doesn't exist")
			return
		}
	default:
		writeErr(w, http.StatusBadRequest, "unknown challenge type")
		return
	}
	if d.Challenge != model.ChallengeDNS {
		d.CredentialID, d.Wildcard = nil, false
	}
	d, err := s.Store.SaveDomain(d)
	if err != nil {
		storeErr(w, err)
		return
	}
	s.audit(r, "domain.save", d.Name, d.Challenge)
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) deleteDomain(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.Store.DeleteDomain(id); err != nil {
		storeErr(w, err)
		return
	}
	s.audit(r, "domain.delete", fmt.Sprint(id), "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------- DNS credentials

// credView is a credential as the UI sees it: secret values are never
// returned, only whether they are set (or the env:/file: reference).
type credView struct {
	ID       int64             `json:"id"`
	Name     string            `json:"name"`
	Provider string            `json:"provider"`
	Fields   map[string]string `json:"fields"`
	Set      map[string]bool   `json:"set"`
}

func viewCred(c model.DNSCredential) credView {
	v := credView{ID: c.ID, Name: c.Name, Provider: c.Provider, Fields: map[string]string{}, Set: map[string]bool{}}
	prov, _ := registry.DNSProviderByID(c.Provider)
	secret := map[string]bool{}
	for _, f := range prov.Fields {
		secret[f.Key] = f.Secret
	}
	for k, val := range c.Fields {
		v.Set[k] = val != ""
		if !secret[k] || strings.HasPrefix(val, "env:") || strings.HasPrefix(val, "file:") {
			v.Fields[k] = val
		}
	}
	return v
}

func (s *Server) listCredentials(w http.ResponseWriter, r *http.Request) {
	cs, err := s.Store.Credentials()
	if err != nil {
		storeErr(w, err)
		return
	}
	out := make([]credView, 0, len(cs))
	for _, c := range cs {
		out = append(out, viewCred(c))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) saveCredential(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string            `json:"name"`
		Provider string            `json:"provider"`
		Fields   map[string]string `json:"fields"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	prov, ok := registry.DNSProviderByID(req.Provider)
	if !ok {
		writeErr(w, http.StatusBadRequest, "unknown DNS provider")
		return
	}
	c := model.DNSCredential{Name: strings.TrimSpace(req.Name), Provider: req.Provider, Fields: map[string]string{}}
	if r.PathValue("id") != "" {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		cur, err := s.Store.Credential(id)
		if err != nil {
			storeErr(w, err)
			return
		}
		c.ID = id
		if cur.Provider == req.Provider {
			c.Fields = cur.Fields // blank secret inputs keep the stored value
		}
	}
	if c.Name == "" {
		c.Name = prov.Name
	}
	for _, f := range prov.Fields {
		v, sent := req.Fields[f.Key]
		v = strings.TrimSpace(v)
		if !sent || (v == "" && f.Secret) {
			continue
		}
		if v == "" {
			delete(c.Fields, f.Key)
			continue
		}
		c.Fields[f.Key] = v
	}
	for _, f := range prov.Fields {
		if f.Required && c.Fields[f.Key] == "" {
			writeErr(w, http.StatusBadRequest, f.Label+" is required")
			return
		}
	}
	c, err := s.Store.SaveCredential(c)
	if err != nil {
		storeErr(w, err)
		return
	}
	s.audit(r, "dns_credential.save", c.Name, c.Provider)
	writeJSON(w, http.StatusOK, viewCred(c))
}

func (s *Server) deleteCredential(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	ds, _ := s.Store.Domains()
	for _, d := range ds {
		if d.CredentialID != nil && *d.CredentialID == id {
			writeErr(w, http.StatusConflict, "domain "+d.Name+" still uses this account; change it first")
			return
		}
	}
	if err := s.Store.DeleteCredential(id); err != nil {
		storeErr(w, err)
		return
	}
	s.audit(r, "dns_credential.delete", fmt.Sprint(id), "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------- snippets & raw blocks

func (s *Server) listSnippets(w http.ResponseWriter, r *http.Request) {
	sn, err := s.Store.Snippets()
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sn)
}

func (s *Server) saveSnippet(w http.ResponseWriter, r *http.Request) {
	var sn model.Snippet
	if !readJSON(w, r, &sn) {
		return
	}
	sn.ID = 0
	if r.PathValue("id") != "" {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		sn.ID = id
	}
	sn.Name = strings.TrimSpace(sn.Name)
	if sn.Name == "" || strings.ContainsAny(sn.Name, " \t(){}") {
		writeErr(w, http.StatusBadRequest, "snippet name is required and can't contain spaces or brackets")
		return
	}
	sn, err := s.Store.SaveSnippet(sn)
	if err != nil {
		storeErr(w, err)
		return
	}
	s.audit(r, "snippet.save", sn.Name, "")
	writeJSON(w, http.StatusOK, sn)
}

func (s *Server) deleteSnippet(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.Store.DeleteSnippet(id); err != nil {
		storeErr(w, err)
		return
	}
	s.audit(r, "snippet.delete", fmt.Sprint(id), "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) listRawBlocks(w http.ResponseWriter, r *http.Request) {
	bs, err := s.Store.RawBlocks()
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, bs)
}

func (s *Server) saveRawBlock(w http.ResponseWriter, r *http.Request) {
	var b model.RawBlock
	if !readJSON(w, r, &b) {
		return
	}
	b.ID = 0
	if r.PathValue("id") != "" {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		b.ID = id
	}
	if strings.TrimSpace(b.Body) == "" {
		writeErr(w, http.StatusBadRequest, "block is empty")
		return
	}
	if b.Source == "" {
		b.Source = "user"
	}
	b, err := s.Store.SaveRawBlock(b)
	if err != nil {
		storeErr(w, err)
		return
	}
	s.audit(r, "raw_block.save", b.Name, "")
	writeJSON(w, http.StatusOK, b)
}

func (s *Server) deleteRawBlock(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.Store.DeleteRawBlock(id); err != nil {
		storeErr(w, err)
		return
	}
	s.audit(r, "raw_block.delete", fmt.Sprint(id), "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------- settings

type settingsView struct {
	model.Settings
	EABMacSet      bool `json:"acme_eab_mac_set"`
	CrowdSecKeySet bool `json:"crowdsec_api_key_set"`
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	_, eab := s.Store.Secret("acme_eab_mac")
	_, cs := s.Store.Secret("crowdsec_api_key")
	writeJSON(w, http.StatusOK, settingsView{Settings: s.Store.Settings(), EABMacSet: eab, CrowdSecKeySet: cs})
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		model.Settings
		EABMac      *string `json:"acme_eab_mac"`
		CrowdSecKey *string `json:"crowdsec_api_key"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	st := req.Settings
	if st.ACMECA != "" && st.ACMECA != "custom" {
		if _, ok := generator.CAPresets[st.ACMECA]; !ok {
			writeErr(w, http.StatusBadRequest, "unknown certificate authority")
			return
		}
	}
	if st.ResolverPreset != "" && st.ResolverPreset != "custom" {
		p, ok := generator.ResolverPresets[st.ResolverPreset]
		if !ok {
			writeErr(w, http.StatusBadRequest, "unknown resolver preset")
			return
		}
		st.Resolvers = p
	}
	if st.SessionTimeoutMinutes <= 0 {
		st.SessionTimeoutMinutes = 60
	}
	sort.Ints(st.CertAlertDays)
	if _, err := s.Store.UpdateSettings(func(cur *model.Settings) {
		setup := cur.SetupComplete
		*cur = st
		cur.SetupComplete = setup || st.SetupComplete
	}); err != nil {
		storeErr(w, err)
		return
	}
	if req.EABMac != nil {
		s.Store.SetSecret("acme_eab_mac", *req.EABMac)
	}
	if req.CrowdSecKey != nil {
		s.Store.SetSecret("crowdsec_api_key", *req.CrowdSecKey)
	}
	s.audit(r, "settings.update", "", "")
	s.getSettings(w, r)
}
