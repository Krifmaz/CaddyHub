package importer

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Krifmaz/CaddyHub/internal/model"
	"github.com/Krifmaz/CaddyHub/internal/registry"
)

// ImportJSON converts a Caddy JSON config (the admin API's /config/, an
// autosave.json, or `caddy adapt` output) into the model. Routes it can't
// express are reported and preserved as disabled raw blocks holding the
// original JSON as comments, so nothing silently disappears.
func ImportJSON(data []byte) (*Result, error) {
	var cfg jConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("not a Caddy JSON config: %w", err)
	}
	im := &jsonImporter{importer: importer{res: &Result{}, creds: map[string]bool{}}, hostCreds: map[string]string{}, internalTLS: map[string]bool{}}
	im.tlsPolicies(cfg.Apps.TLS)

	names := make([]string, 0, len(cfg.Apps.HTTP.Servers))
	for n := range cfg.Apps.HTTP.Servers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		srv := cfg.Apps.HTTP.Servers[n]
		for _, r := range srv.Routes {
			im.topRoute(srv, r)
		}
	}
	im.finishDomains()
	if cfg.Storage != nil {
		im.report("storage", "skipped", "custom certificate storage is not managed by CaddyHub; Caddy's data volume is used")
	}
	return im.res, nil
}

// ---------------------------------------------------------------- JSON shapes

type jConfig struct {
	Storage json.RawMessage `json:"storage"`
	Apps    struct {
		HTTP struct {
			Servers map[string]jServer `json:"servers"`
		} `json:"http"`
		TLS *jTLS `json:"tls"`
	} `json:"apps"`
}

type jServer struct {
	Listen         []string `json:"listen"`
	Routes         []jRoute `json:"routes"`
	AutomaticHTTPS *struct {
		Disable bool `json:"disable"`
	} `json:"automatic_https"`
}

// plainHTTP reports whether a server only serves HTTP: it doesn't listen on
// the HTTPS port and has no TLS of its own (e.g. http:// sites, auto_https off).
func (s jServer) plainHTTP() bool {
	for _, l := range s.Listen {
		if strings.HasSuffix(l, ":443") {
			return false
		}
	}
	return len(s.Listen) > 0
}

type jRoute struct {
	Group    string                       `json:"group,omitempty"`
	Match    []map[string]json.RawMessage `json:"match,omitempty"`
	Handle   []map[string]any             `json:"handle,omitempty"`
	Terminal bool                         `json:"terminal,omitempty"`
}

type jTLS struct {
	Automation *struct {
		Policies []struct {
			Subjects []string         `json:"subjects"`
			Issuers  []map[string]any `json:"issuers"`
		} `json:"policies"`
	} `json:"automation"`
}

type jsonImporter struct {
	importer
	pos         int
	global      *Credential       // DNS provider from a policy without subjects
	hostCreds   map[string]string // subject -> credential key
	wildcards   map[string]string // base domain -> credential key
	internalTLS map[string]bool   // subjects using Caddy's internal issuer
}

// ---------------------------------------------------------------- TLS

func (im *jsonImporter) tlsPolicies(t *jTLS) {
	if t == nil || t.Automation == nil {
		return
	}
	for _, p := range t.Automation.Policies {
		var cred *Credential
		internal := false
		for _, is := range p.Issuers {
			switch str(is["module"]) {
			case "internal":
				internal = true
			case "acme", "zerossl", "":
				if e := str(is["email"]); e != "" && im.res.Email == "" {
					im.res.Email = e
				}
				if ca := str(is["ca"]); ca != "" && im.res.ACMECA == "" && ca != "https://acme.zerossl.com/v2/DV90" {
					im.setCA(ca)
				}
				if ch, ok := is["challenges"].(map[string]any); ok {
					if dns, ok := ch["dns"].(map[string]any); ok {
						if prov, ok := dns["provider"].(map[string]any); ok && cred == nil {
							cred = im.jsonCred(prov)
						}
					}
				}
			}
		}
		if len(p.Subjects) == 0 {
			if cred != nil && im.global == nil {
				im.global = cred
			}
			continue
		}
		for _, s := range p.Subjects {
			s = strings.ToLower(s)
			if internal {
				im.internalTLS[s] = true
			}
			if cred != nil {
				im.hostCreds[s] = cred.Key
			}
		}
	}
}

// jsonCred turns {"name": "cloudflare", "api_token": "..."} into a credential.
// Literal secrets are kept (they'll be encrypted at rest) but flagged.
func (im *jsonImporter) jsonCred(p map[string]any) *Credential {
	name := str(p["name"])
	prov, ok := registry.DNSProviderByID(name)
	if !ok {
		im.report("tls dns "+name, "skipped", "DNS provider "+name+" is not known to CaddyHub; add it under Domains & DNS")
		return nil
	}
	c := Credential{Provider: prov.ID, Fields: map[string]string{}}
	secret := map[string]bool{}
	for _, f := range prov.Fields {
		secret[f.Key] = f.Secret
	}
	for k, v := range p {
		if k == "name" {
			continue
		}
		sv := str(v)
		if sv == "" {
			continue
		}
		ref := refValue(sv)
		c.Fields[k] = ref
		if secret[k] && ref == sv {
			im.res.Warnings = appendUnique(im.res.Warnings, fmt.Sprintf("Your %s %s was written in plain text in the Caddy config. CaddyHub stores it encrypted and only passes it to Caddy as a {file.*} placeholder.", prov.Name, k))
		}
	}
	for _, ex := range im.res.Credentials {
		if ex.Provider == c.Provider && mapsEqual(ex.Fields, c.Fields) {
			return &ex
		}
	}
	c.Key = prov.ID + ":" + strconv.Itoa(len(im.res.Credentials))
	im.res.Credentials = append(im.res.Credentials, c)
	return &im.res.Credentials[len(im.res.Credentials)-1]
}

// finishDomains turns DNS policies into domain entries for imported sites.
func (im *jsonImporter) finishDomains() {
	seen := map[string]bool{}
	add := func(name, key string, wildcard bool) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		im.res.Domains = append(im.res.Domains, DomainSuggestion{Name: name, Challenge: model.ChallengeDNS, CredentialKey: key, Wildcard: wildcard})
	}
	for base, key := range im.wildcards {
		add(base, key, true)
	}
	for subj, key := range im.hostCreds {
		if strings.HasPrefix(subj, "*.") {
			add(strings.TrimPrefix(subj, "*."), key, true)
		} else {
			add(BaseDomain(subj), key, false)
		}
	}
	if im.global != nil {
		for _, s := range im.res.Sites {
			for _, h := range s.Hosts {
				add(BaseDomain(h), im.global.Key, false)
			}
		}
	}
	sort.Slice(im.res.Domains, func(i, j int) bool { return im.res.Domains[i].Name < im.res.Domains[j].Name })
}

// ---------------------------------------------------------------- routes

func (im *jsonImporter) topRoute(srv jServer, r jRoute) {
	hosts, other := splitMatch(r.Match)
	label := strings.Join(hosts, ", ")
	if label == "" {
		label = "listener " + strings.Join(srv.Listen, ", ")
	}
	if len(hosts) == 0 {
		im.manual(label, r, "routes without a hostname (port-only addresses like :8081) aren't supported as sites")
		return
	}
	if other {
		im.manual(label, r, "top-level matchers other than host aren't supported")
		return
	}

	// A wildcard site whose subroutes each match a host: one site per host,
	// served by a wildcard certificate.
	if len(hosts) == 1 && strings.HasPrefix(hosts[0], "*.") {
		if split, ok := hostSplit(r.Handle); ok {
			base := strings.TrimPrefix(hosts[0], "*.")
			key := im.hostCreds[hosts[0]]
			if key == "" && im.global != nil {
				key = im.global.Key
			}
			if key != "" {
				if im.wildcards == nil {
					im.wildcards = map[string]string{}
				}
				im.wildcards[base] = key
			}
			for _, sr := range split {
				sh, _ := splitMatch(sr.Match)
				im.site(sh, sr.Handle, sr, false)
			}
			return
		}
	}
	im.site(hosts, r.Handle, r, srv.plainHTTP())
}

// hostSplit reports whether a handler list is a subroute of host-matched routes.
func hostSplit(handle []map[string]any) ([]jRoute, bool) {
	if len(handle) != 1 || str(handle[0]["handler"]) != "subroute" {
		return nil, false
	}
	routes := subRoutes(handle[0])
	var out []jRoute
	for _, r := range routes {
		hs, other := splitMatch(r.Match)
		if len(hs) == 0 || other {
			// tolerate a trailing catch-all such as `handle { abort }`
			if len(r.Match) == 0 && onlyAbort(r.Handle) {
				continue
			}
			return nil, false
		}
		out = append(out, r)
	}
	return out, len(out) > 0
}

func onlyAbort(h []map[string]any) bool {
	for _, x := range flattenHandlers(h) {
		if str(x["handler"]) != "static_response" || x["abort"] != true {
			return false
		}
	}
	return true
}

// site interprets one site's handler chain.
func (im *jsonImporter) site(hosts []string, handle []map[string]any, orig jRoute, plain bool) {
	label := strings.Join(hosts, ", ")
	st := model.Site{Name: hosts[0], Hosts: hosts, Enabled: true, Tags: []string{}, Config: model.SiteConfig{TLS: model.TLSConfig{Mode: model.TLSAuto}}}
	for _, h := range hosts {
		if im.internalTLS[h] {
			st.Config.TLS.Mode = model.TLSInternal
		}
	}
	if plain {
		st.Config.TLS.Mode = model.TLSOff
	}
	c := &st.Config
	var dropped []string
	var root string
	spa := false

	steps := flattenSteps(handle)
	for _, s := range steps {
		if len(s.match) > 0 {
			path, ok := pathOnly(s.match)
			if spaRewrite(s) {
				spa = true
				continue
			}
			if !ok {
				dropped = append(dropped, describe(s))
				continue
			}
			rt, ok := pathRoute(path, s.handlers)
			if !ok {
				dropped = append(dropped, "route "+path)
				continue
			}
			c.Routes = append(c.Routes, rt)
			continue
		}
		for _, h := range s.handlers {
			switch str(h["handler"]) {
			case "headers":
				if !responseHeaders(h, c) {
					dropped = append(dropped, "headers (request)")
				}
			case "encode":
				c.Compression = encodings(h)
			case "request_body":
				if n, ok := num(h["max_size"]); ok {
					c.MaxBodySize = byteSize(int64(n))
				}
			case "authentication":
				if !basicAuth(h, c) {
					dropped = append(dropped, "authentication")
				}
			case "vars":
				if r := str(h["root"]); r != "" {
					root = r
				}
			case "file_server":
				st.Kind = model.KindStatic
				_, browse := h["browse"]
				c.Static = &model.StaticConfig{Root: root, Browse: browse}
			case "reverse_proxy":
				p, ok := proxyConfig(h)
				if !ok {
					dropped = append(dropped, "reverse_proxy (non-HTTP transport)")
					continue
				}
				st.Kind, c.Proxy = model.KindProxy, p
			case "static_response":
				if red, ok := redirect(h); ok {
					st.Kind, c.Redirect = model.KindRedirect, red
				} else {
					st.Kind, c.Respond = model.KindRespond, respond(h)
				}
			default:
				dropped = append(dropped, str(h["handler"]))
			}
		}
	}
	if c.Static != nil {
		if c.Static.Root == "" {
			c.Static.Root = root
		}
		c.Static.SPA = spa
	}
	if st.Kind == "" {
		im.manual(label, orig, "no handler CaddyHub understands ("+strings.Join(uniq(dropped), ", ")+")")
		return
	}
	im.res.Sites = append(im.res.Sites, st)
	if len(dropped) > 0 {
		im.keepJSON(label+" (unmapped parts)", orig)
		im.report(label, "partial", "imported as "+st.Kind+"; not mapped: "+strings.Join(uniq(dropped), ", ")+". The original JSON is kept as a disabled raw block.")
		return
	}
	im.report(label, "structured", st.Kind+" site")
}

// manual keeps a route that can't be modeled, as commented JSON.
func (im *jsonImporter) manual(label string, r jRoute, why string) {
	im.keepJSON(label, r)
	im.report(label, "raw", why+"; kept as a disabled raw block with the original JSON for reference")
}

func (im *jsonImporter) keepJSON(label string, r jRoute) {
	b, _ := json.MarshalIndent(r, "", "  ")
	var sb strings.Builder
	sb.WriteString("# Imported from Caddy JSON; CaddyHub could not map this automatically.\n")
	sb.WriteString("# Rewrite it as Caddyfile directives (or add it to a site's custom box), then enable this block.\n")
	for _, l := range strings.Split(string(b), "\n") {
		sb.WriteString("# " + l + "\n")
	}
	im.pos++
	im.res.RawBlocks = append(im.res.RawBlocks, model.RawBlock{Name: label, Body: sb.String(), Enabled: false, Position: im.pos, Source: "import"})
}

// ---------------------------------------------------------------- handler flattening

type step struct {
	match    []map[string]json.RawMessage
	handlers []map[string]any
}

func subRoutes(h map[string]any) []jRoute {
	b, _ := json.Marshal(h["routes"])
	var rs []jRoute
	json.Unmarshal(b, &rs)
	return rs
}

// flattenSteps unwraps unmatched subroutes into a linear list of steps; a
// matched subroute becomes one step whose handlers are its flattened content.
func flattenSteps(handle []map[string]any) []step {
	var out []step
	var cur []map[string]any
	flush := func() {
		if len(cur) > 0 {
			out = append(out, step{handlers: cur})
			cur = nil
		}
	}
	for _, h := range handle {
		if str(h["handler"]) != "subroute" {
			cur = append(cur, h)
			continue
		}
		flush()
		for _, r := range subRoutes(h) {
			if len(r.Match) == 0 {
				out = append(out, flattenSteps(r.Handle)...)
				continue
			}
			out = append(out, step{match: r.Match, handlers: flattenHandlers(r.Handle)})
		}
	}
	flush()
	return out
}

// flattenHandlers lists all handlers inside nested unmatched subroutes.
func flattenHandlers(handle []map[string]any) []map[string]any {
	var out []map[string]any
	for _, h := range handle {
		if str(h["handler"]) == "subroute" {
			for _, r := range subRoutes(h) {
				if len(r.Match) == 0 {
					out = append(out, flattenHandlers(r.Handle)...)
				} else {
					out = append(out, map[string]any{"handler": "matched_subroute"})
				}
			}
			continue
		}
		out = append(out, h)
	}
	return out
}

func splitMatch(ms []map[string]json.RawMessage) (hosts []string, other bool) {
	for _, m := range ms {
		for k, v := range m {
			if k != "host" {
				other = true
				continue
			}
			var hs []string
			json.Unmarshal(v, &hs)
			for _, h := range hs {
				hosts = appendUnique(hosts, strings.ToLower(h))
			}
		}
	}
	return
}

func pathOnly(ms []map[string]json.RawMessage) (string, bool) {
	if len(ms) != 1 || len(ms[0]) != 1 {
		return "", false
	}
	raw, ok := ms[0]["path"]
	if !ok {
		return "", false
	}
	var ps []string
	if json.Unmarshal(raw, &ps) != nil || len(ps) != 1 {
		return "", false
	}
	return ps[0], true
}

// spaRewrite detects `try_files {path} /index.html`.
func spaRewrite(s step) bool {
	if len(s.handlers) != 1 || str(s.handlers[0]["handler"]) != "rewrite" || len(s.match) != 1 {
		return false
	}
	raw, ok := s.match[0]["file"]
	if !ok {
		return false
	}
	var f struct {
		TryFiles []string `json:"try_files"`
	}
	json.Unmarshal(raw, &f)
	return len(f.TryFiles) == 2 && f.TryFiles[0] == "{http.request.uri.path}" && f.TryFiles[1] == "/index.html"
}

func describe(s step) string {
	var keys []string
	for _, m := range s.match {
		for k := range m {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return "route matching " + strings.Join(keys, "+")
}

func pathRoute(path string, hs []map[string]any) (model.Route, bool) {
	rt := model.Route{Path: path}
	for _, h := range hs {
		switch str(h["handler"]) {
		case "rewrite":
			if p := str(h["strip_path_prefix"]); p != "" && strings.HasPrefix(path, p) {
				rt.StripPrefix = true
				continue
			}
			return rt, false
		case "reverse_proxy":
			p, ok := proxyConfig(h)
			if !ok {
				return rt, false
			}
			rt.Kind, rt.Proxy = model.KindProxy, p
		case "file_server":
			rt.Kind, rt.Static = model.KindStatic, &model.StaticConfig{Root: str(h["root"])}
		case "static_response":
			if red, ok := redirect(h); ok {
				rt.Kind, rt.Redirect = model.KindRedirect, red
			} else {
				rt.Kind, rt.Respond = model.KindRespond, respond(h)
			}
		default:
			return rt, false
		}
	}
	return rt, rt.Kind != ""
}

// ---------------------------------------------------------------- handlers

func proxyConfig(h map[string]any) (*model.ProxyConfig, bool) {
	p := &model.ProxyConfig{}
	tr, _ := h["transport"].(map[string]any)
	scheme := ""
	if tr != nil {
		if proto := str(tr["protocol"]); proto != "" && proto != "http" {
			return nil, false
		}
		if tls, ok := tr["tls"].(map[string]any); ok {
			scheme = "https://"
			p.TLSSkipVerify = tls["insecure_skip_verify"] == true
			p.TLSServerName = str(tls["server_name"])
		}
		if vs, ok := tr["versions"].([]any); ok {
			for _, v := range vs {
				if str(v) == "h2c" {
					p.H2C = true
				}
			}
		}
		p.DialTimeout = dur(tr["dial_timeout"])
		p.ResponseHeaderTimeout = dur(tr["response_header_timeout"])
		p.ReadTimeout = dur(tr["read_timeout"])
		p.WriteTimeout = dur(tr["write_timeout"])
	}
	ups, _ := h["upstreams"].([]any)
	for _, u := range ups {
		if um, ok := u.(map[string]any); ok {
			if d := str(um["dial"]); d != "" {
				p.Upstreams = append(p.Upstreams, scheme+d)
			}
		}
	}
	if len(p.Upstreams) == 0 {
		return nil, false
	}
	if lb, ok := h["load_balancing"].(map[string]any); ok {
		if sp, ok := lb["selection_policy"].(map[string]any); ok {
			p.LBPolicy = str(sp["policy"])
		}
		if n, ok := num(lb["retries"]); ok {
			p.LBRetries = int(n)
		}
		p.LBTryDuration = dur(lb["try_duration"])
	}
	if hc, ok := h["health_checks"].(map[string]any); ok {
		if a, ok := hc["active"].(map[string]any); ok {
			p.HealthURI = str(a["uri"])
			if p.HealthURI == "" {
				p.HealthURI = str(a["path"])
			}
			p.HealthInterval = dur(a["interval"])
			p.HealthTimeout = dur(a["timeout"])
			if n, ok := num(a["expect_status"]); ok {
				p.HealthStatus = strconv.Itoa(int(n))
			}
		}
		if ps, ok := hc["passive"].(map[string]any); ok {
			p.FailDuration = dur(ps["fail_duration"])
			if n, ok := num(ps["max_fails"]); ok {
				p.MaxFails = int(n)
			}
		}
	}
	if fi, ok := h["flush_interval"]; ok {
		if n, ok := num(fi); ok && n < 0 {
			p.FlushInterval = "-1"
		} else {
			p.FlushInterval = dur(fi)
		}
	}
	if hd, ok := h["headers"].(map[string]any); ok {
		p.HeaderUp = headerSet(hd["request"])
		p.HeaderDown = headerSet(hd["response"])
	}
	return p, true
}

func headerSet(v any) map[string]string {
	m, _ := v.(map[string]any)
	set, _ := m["set"].(map[string]any)
	if len(set) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, vals := range set {
		if vs, ok := vals.([]any); ok && len(vs) > 0 {
			out[k] = str(vs[0])
		}
	}
	return out
}

func responseHeaders(h map[string]any, c *model.SiteConfig) bool {
	if _, ok := h["request"]; ok {
		return false
	}
	resp, _ := h["response"].(map[string]any)
	if resp == nil {
		return false
	}
	if set := headerSet(resp); set != nil {
		if c.HeadersSet == nil {
			c.HeadersSet = map[string]string{}
		}
		for k, v := range set {
			c.HeadersSet[k] = v
		}
	}
	if del, ok := resp["delete"].([]any); ok {
		for _, d := range del {
			c.HeadersRemove = appendUnique(c.HeadersRemove, str(d))
		}
	}
	return true
}

func encodings(h map[string]any) []string {
	var out []string
	if pref, ok := h["prefer"].([]any); ok {
		for _, p := range pref {
			out = append(out, str(p))
		}
		return out
	}
	enc, _ := h["encodings"].(map[string]any)
	for _, k := range []string{"zstd", "gzip"} {
		if _, ok := enc[k]; ok {
			out = append(out, k)
		}
	}
	return out
}

func basicAuth(h map[string]any, c *model.SiteConfig) bool {
	provs, _ := h["providers"].(map[string]any)
	hb, _ := provs["http_basic"].(map[string]any)
	accts, _ := hb["accounts"].([]any)
	if len(accts) == 0 {
		return false
	}
	for _, a := range accts {
		am, _ := a.(map[string]any)
		c.Access.BasicAuth = append(c.Access.BasicAuth, model.BasicAuthUser{Username: str(am["username"]), Hash: str(am["password"])})
	}
	return true
}

func redirect(h map[string]any) (*model.RedirectConfig, bool) {
	code, _ := num(h["status_code"])
	if code < 300 || code > 399 {
		if s, err := strconv.Atoi(str(h["status_code"])); err == nil {
			code = float64(s)
		}
	}
	hdr, _ := h["headers"].(map[string]any)
	loc, _ := hdr["Location"].([]any)
	if code < 300 || code > 399 || len(loc) != 1 {
		return nil, false
	}
	to := str(loc[0])
	keep := false
	for _, suf := range []string{"{http.request.uri}", "{uri}"} {
		if strings.HasSuffix(to, suf) {
			to, keep = strings.TrimSuffix(to, suf), true
		}
	}
	return &model.RedirectConfig{To: to, Code: int(code), KeepPath: keep}, true
}

func respond(h map[string]any) *model.RespondConfig {
	r := &model.RespondConfig{Body: str(h["body"]), Status: 200}
	if n, ok := num(h["status_code"]); ok {
		r.Status = int(n)
	} else if s, err := strconv.Atoi(str(h["status_code"])); err == nil {
		r.Status = s
	}
	if hdr, ok := h["headers"].(map[string]any); ok {
		if ct, ok := hdr["Content-Type"].([]any); ok && len(ct) > 0 {
			r.ContentType = str(ct[0])
		}
	}
	return r
}

// ---------------------------------------------------------------- value helpers

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	}
	return ""
}

func num(v any) (float64, bool) {
	f, ok := v.(float64)
	return f, ok
}

// dur renders a Caddy duration (string, or integer nanoseconds).
func dur(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		if x <= 0 {
			return ""
		}
		return time.Duration(int64(x)).String()
	}
	return ""
}

func byteSize(n int64) string {
	switch {
	case n > 0 && n%1_000_000_000 == 0:
		return strconv.FormatInt(n/1_000_000_000, 10) + "GB"
	case n > 0 && n%1_000_000 == 0:
		return strconv.FormatInt(n/1_000_000, 10) + "MB"
	case n > 0 && n%1000 == 0:
		return strconv.FormatInt(n/1000, 10) + "KB"
	}
	return strconv.FormatInt(n, 10)
}

func uniq(in []string) []string {
	var out []string
	for _, s := range in {
		out = appendUnique(out, s)
	}
	return out
}

// ---------------------------------------------------------------- round trip

// Fingerprint summarizes what each host does, for comparing an imported
// config with what CaddyHub regenerates from it.
func Fingerprint(res *Result) map[string]string {
	out := map[string]string{}
	for _, s := range res.Sites {
		c := s.Config
		var parts []string
		switch s.Kind {
		case model.KindProxy:
			ups := append([]string(nil), c.Proxy.Upstreams...)
			sort.Strings(ups)
			parts = append(parts, "proxy "+strings.Join(ups, ","))
		case model.KindStatic:
			parts = append(parts, fmt.Sprintf("files %s browse=%v spa=%v", c.Static.Root, c.Static.Browse, c.Static.SPA))
		case model.KindRedirect:
			parts = append(parts, fmt.Sprintf("redirect %s %d keep=%v", c.Redirect.To, c.Redirect.Code, c.Redirect.KeepPath))
		case model.KindRespond:
			parts = append(parts, fmt.Sprintf("respond %d %q", c.Respond.Status, c.Respond.Body))
		}
		for _, r := range c.Routes {
			t := r.Kind
			if r.Proxy != nil {
				t += " " + strings.Join(r.Proxy.Upstreams, ",")
			}
			parts = append(parts, fmt.Sprintf("route %s strip=%v %s", r.Path, r.StripPrefix, t))
		}
		var users []string
		for _, u := range c.Access.BasicAuth {
			users = append(users, u.Username)
		}
		if len(users) > 0 {
			sort.Strings(users)
			parts = append(parts, "auth "+strings.Join(users, ","))
		}
		mode := c.TLS.Mode
		if mode == "" {
			mode = model.TLSAuto
		}
		parts = append(parts, "tls "+mode)
		fp := strings.Join(parts, "; ")
		for _, h := range s.Hosts {
			out[h] = fp
		}
	}
	return out
}

// CompareFingerprints lists hosts whose behavior differs between a and b.
func CompareFingerprints(a, b map[string]string) []string {
	var diffs []string
	for h, fa := range a {
		fb, ok := b[h]
		switch {
		case !ok:
			diffs = append(diffs, h+": missing after regeneration")
		case fa != fb:
			diffs = append(diffs, fmt.Sprintf("%s: was %q, regenerated as %q", h, fa, fb))
		}
	}
	for h := range b {
		if _, ok := a[h]; !ok {
			diffs = append(diffs, h+": appears only after regeneration")
		}
	}
	sort.Strings(diffs)
	return diffs
}
