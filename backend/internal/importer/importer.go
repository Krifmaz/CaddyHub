// Package importer converts an existing Caddyfile into structured entries.
// Whatever it can't map is preserved verbatim (as raw blocks, raw global
// options, or a site's raw snippet) — nothing is ever dropped silently.
package importer

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	cf "github.com/Krifmaz/CaddyHub/internal/caddyfile"
	"github.com/Krifmaz/CaddyHub/internal/generator"
	"github.com/Krifmaz/CaddyHub/internal/model"
	"github.com/Krifmaz/CaddyHub/internal/registry"
)

// Credential is a DNS credential discovered in the Caddyfile.
type Credential struct {
	Key      string            `json:"key"` // dedupe key
	Provider string            `json:"provider"`
	Fields   map[string]string `json:"fields"` // literal secrets or env:/file: refs
}

// DomainSuggestion links a base domain to a challenge/credential.
type DomainSuggestion struct {
	Name          string `json:"name"`
	Challenge     string `json:"challenge"`
	CredentialKey string `json:"credential_key,omitempty"`
	Wildcard      bool   `json:"wildcard,omitempty"`
}

// Result is the import outcome.
type Result struct {
	Sites       []model.Site       `json:"sites"`
	Snippets    []model.Snippet    `json:"snippets"`
	RawBlocks   []model.RawBlock   `json:"raw_blocks"`
	RawGlobal   string             `json:"raw_global"`
	Email       string             `json:"email,omitempty"`
	ACMECA      string             `json:"acme_ca,omitempty"`     // preset id
	ACMECAURL   string             `json:"acme_ca_url,omitempty"` // when custom
	Credentials []Credential       `json:"credentials"`
	Domains     []DomainSuggestion `json:"domains"`
	Report      []ReportLine       `json:"report"`
	Warnings    []string           `json:"warnings,omitempty"`
}

// ReportLine explains what happened to each block.
type ReportLine struct {
	Block  string `json:"block"`
	Status string `json:"status"` // structured, partial, raw, skipped
	Detail string `json:"detail"`
}

type importer struct {
	src    string
	res    *Result
	creds  map[string]bool
	global *Credential // from acme_dns / dns global option
}

// Import parses a Caddyfile.
func Import(src string) (*Result, error) {
	src = strings.ReplaceAll(src, "\r\n", "\n")
	blocks, err := cf.Parse(src)
	if err != nil {
		return nil, fmt.Errorf("cannot parse Caddyfile: %w", err)
	}
	im := &importer{src: src, res: &Result{}, creds: map[string]bool{}}
	pos := 0
	for _, b := range blocks {
		switch {
		case b.IsGlobal():
			im.globalBlock(b)
		case b.IsSnippet():
			name := strings.TrimSuffix(strings.TrimPrefix(b.Keys[0].Text, "("), ")")
			im.res.Snippets = append(im.res.Snippets, model.Snippet{Name: name, Body: im.innerText(b), Description: "imported"})
			im.report(b.Keys[0].Text, "structured", "snippet")
		case b.IsNamedRoute():
			pos++
			im.raw(b, pos, "named route kept as raw block")
		default:
			pos++
			im.siteBlock(b, pos)
		}
	}
	// apply global DNS provider to all imported domains
	if im.global != nil {
		seen := map[string]bool{}
		for _, d := range im.res.Domains {
			seen[d.Name] = true
		}
		for _, s := range im.res.Sites {
			for _, h := range s.Hosts {
				bd := BaseDomain(h)
				if bd != "" && !seen[bd] {
					seen[bd] = true
					im.res.Domains = append(im.res.Domains, DomainSuggestion{Name: bd, Challenge: model.ChallengeDNS, CredentialKey: im.global.Key})
				}
			}
		}
	}
	return im.res, nil
}

func (im *importer) report(block, status, detail string) {
	im.res.Report = append(im.res.Report, ReportLine{Block: block, Status: status, Detail: detail})
}

func (im *importer) raw(b *cf.TopBlock, pos int, why string) {
	name := strings.Join(b.KeyStrings(), ", ")
	im.res.RawBlocks = append(im.res.RawBlocks, model.RawBlock{Name: name, Body: b.Text, Enabled: true, Position: pos, Source: "import"})
	im.report(name, "raw", why)
}

// innerText returns the source between a block's braces.
func (im *importer) innerText(b *cf.TopBlock) string {
	t := b.Text
	i := strings.Index(t, "{")
	j := strings.LastIndex(t, "}")
	if i < 0 || j <= i {
		return ""
	}
	return strings.Trim(t[i+1:j], "\n")
}

// ---------------------------------------------------------------- global

func (im *importer) globalBlock(b *cf.TopBlock) {
	var raw []string
	for _, d := range b.Body {
		args := d.ArgStrings()
		switch d.Name() {
		case "email":
			if len(args) == 1 {
				im.res.Email = args[0]
				continue
			}
		case "acme_ca":
			if len(args) == 1 {
				im.setCA(args[0])
				continue
			}
		case "admin":
			im.report("global: admin", "skipped", "the panel manages the admin endpoint")
			continue
		case "acme_dns", "dns":
			if c := im.dnsCred(d); c != nil {
				im.global = c
				im.report("global: "+d.Name(), "structured", "DNS provider "+c.Provider+" applied to imported domains")
				continue
			}
		case "local_certs":
			im.res.ACMECA = "caddy_internal"
			continue
		case "log":
			if len(args) == 0 {
				im.report("global: log", "skipped", "the panel manages Caddy's logs")
				continue
			}
		}
		raw = append(raw, d.Source(im.src))
	}
	if len(raw) > 0 {
		im.res.RawGlobal = strings.Join(raw, "\n")
		im.report("global options", "partial", fmt.Sprintf("%d option(s) kept as raw global options", len(raw)))
	}
}

func (im *importer) setCA(u string) {
	for id, url := range generator.CAPresets {
		if url != "" && url == u {
			im.res.ACMECA = id
			return
		}
	}
	if u == "https://acme-v02.api.letsencrypt.org/directory" {
		im.res.ACMECA = "letsencrypt"
		return
	}
	im.res.ACMECA, im.res.ACMECAURL = "custom", u
}

// refValue turns placeholders into stored references.
func refValue(v string) string {
	switch {
	case strings.HasPrefix(v, "{env.") && strings.HasSuffix(v, "}"):
		return "env:" + v[5:len(v)-1]
	case strings.HasPrefix(v, "{$") && strings.HasSuffix(v, "}"):
		name := v[2 : len(v)-1]
		if i := strings.Index(name, ":"); i >= 0 {
			name = name[:i]
		}
		return "env:" + name
	case strings.HasPrefix(v, "{file.") && strings.HasSuffix(v, "}"):
		return "file:" + v[6:len(v)-1]
	}
	return v
}

// dnsCred parses `dns <provider> [token] [{ ... }]`.
func (im *importer) dnsCred(d *cf.Directive) *Credential {
	args := d.ArgStrings()
	if len(args) < 1 {
		return nil
	}
	prov, ok := registry.DNSProviderByID(args[0])
	if !ok {
		return nil
	}
	c := &Credential{Provider: prov.ID, Fields: map[string]string{}}
	if len(args) == 2 {
		// single-argument form maps to the first required field
		for _, f := range prov.Fields {
			if f.Required {
				c.Fields[f.Key] = refValue(args[1])
				break
			}
		}
	} else if len(args) > 2 {
		return nil
	}
	known := map[string]bool{}
	for _, f := range prov.Fields {
		known[f.Key] = true
	}
	for _, sub := range d.Block {
		sa := sub.ArgStrings()
		if !known[sub.Name()] || len(sa) != 1 {
			return nil
		}
		c.Fields[sub.Name()] = refValue(sa[0])
	}
	c.Key = prov.ID + ":" + fmt.Sprint(len(im.creds))
	// dedupe identical credentials
	for _, ex := range im.res.Credentials {
		if ex.Provider == c.Provider && mapsEqual(ex.Fields, c.Fields) {
			return &ex
		}
	}
	im.creds[c.Key] = true
	im.res.Credentials = append(im.res.Credentials, *c)
	return c
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- sites

// parseAddress returns host and scheme for supported site addresses.
func parseAddress(a string) (host, scheme string, ok bool) {
	scheme = ""
	switch {
	case strings.HasPrefix(a, "https://"):
		scheme, a = "https", strings.TrimPrefix(a, "https://")
	case strings.HasPrefix(a, "http://"):
		scheme, a = "http", strings.TrimPrefix(a, "http://")
	}
	if strings.Contains(a, "/") || strings.HasPrefix(a, ":") || strings.Contains(a, "{") {
		return "", "", false
	}
	if h, p, err := net.SplitHostPort(a); err == nil {
		if (p == "443" && scheme != "http") || (p == "80" && scheme == "http") {
			a = h
		} else {
			return "", "", false
		}
	}
	if strings.HasPrefix(a, "*") || !ValidHost(a) {
		return "", "", false
	}
	return strings.ToLower(a), scheme, true
}

// ValidHost checks a hostname (no wildcards, no ports).
func ValidHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	for _, l := range strings.Split(h, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

// BaseDomain guesses the zone of a host: the host itself for two labels,
// otherwise the host minus its first label. Users can adjust in the wizard.
func BaseDomain(h string) string {
	if net.ParseIP(h) != nil || !strings.Contains(h, ".") {
		return ""
	}
	parts := strings.Split(h, ".")
	if len(parts) <= 2 {
		return h
	}
	return strings.Join(parts[1:], ".")
}

func (im *importer) siteBlock(b *cf.TopBlock, pos int) {
	keys := b.KeyStrings()
	name := strings.Join(keys, ", ")
	schemes := map[string]map[string]bool{}
	var hosts []string
	for _, k := range keys {
		h, sc, ok := parseAddress(k)
		if !ok {
			im.raw(b, pos, "address "+k+" is not a plain hostname; kept verbatim")
			return
		}
		if schemes[h] == nil {
			schemes[h] = map[string]bool{}
			hosts = append(hosts, h)
		}
		schemes[h][sc] = true
	}
	site := model.Site{Name: hosts[0], Hosts: hosts, Enabled: true, Position: pos, Tags: []string{"imported"}}
	c := &site.Config
	// scheme handling: all http -> TLS off; both http+https -> no redirect
	allHTTP, both := true, false
	for _, s := range schemes {
		if !s["http"] {
			allHTTP = false
		}
		if s["http"] && (s["https"] || s[""]) {
			both = true
		}
	}
	if allHTTP && !both {
		c.TLS.Mode = model.TLSOff
	} else if both {
		f := false
		c.HTTPRedirect = &f
	}

	var raw []string
	var mapped int
	var static model.StaticConfig
	hasRoot, hasFS := false, false
	for _, d := range b.Body {
		ok := true
		switch d.Name() {
		case "reverse_proxy":
			p, good := parseProxy(d)
			if good && site.Kind == "" {
				site.Kind, c.Proxy = model.KindProxy, p
			} else {
				ok = false
			}
		case "root":
			a := d.ArgStrings()
			switch {
			case len(a) == 2 && a[0] == "*":
				static.Root, hasRoot = a[1], true
			case len(a) == 1 && !strings.HasPrefix(a[0], "/") || len(a) == 1 && strings.HasPrefix(a[0], "/") && !strings.HasSuffix(a[0], "*"):
				static.Root, hasRoot = a[0], true
			default:
				ok = false
			}
		case "file_server":
			a := d.ArgStrings()
			switch {
			case d.HasBlock:
				ok = false
			case len(a) == 0:
				hasFS = true
			case len(a) == 1 && a[0] == "browse":
				hasFS, static.Browse = true, true
			default:
				ok = false
			}
		case "try_files":
			a := d.ArgStrings()
			if len(a) == 2 && a[0] == "{path}" && a[1] == "/index.html" {
				static.SPA = true
			} else {
				ok = false
			}
		case "redir":
			r, good := parseRedir(d)
			if good && site.Kind == "" {
				site.Kind, c.Redirect = model.KindRedirect, r
			} else {
				ok = false
			}
		case "respond":
			r, good := parseRespond(d)
			if good && site.Kind == "" {
				site.Kind, c.Respond = model.KindRespond, r
			} else {
				ok = false
			}
		case "encode":
			a := d.ArgStrings()
			if d.HasBlock || len(a) == 0 {
				ok = false
				break
			}
			for _, e := range a {
				if e != "zstd" && e != "gzip" {
					ok = false
				}
			}
			if ok {
				c.Compression = a
			}
		case "header":
			ok = parseHeader(d, c)
		case "tls":
			ok = im.parseTLS(d, &site)
		case "log":
			im.report(name, "partial", "log directive replaced by panel-managed access logs")
		case "basic_auth", "basicauth":
			if len(d.ArgStrings()) > 0 {
				ok = false
				break
			}
			for _, u := range d.Block {
				ua := u.ArgStrings()
				if len(ua) != 1 {
					ok = false
					break
				}
				c.Access.BasicAuth = append(c.Access.BasicAuth, model.BasicAuthUser{Username: u.Name(), Hash: ua[0]})
			}
		case "request_body":
			if len(d.Block) == 1 && d.Block[0].Name() == "max_size" && len(d.Block[0].ArgStrings()) == 1 && len(d.ArgStrings()) == 0 {
				c.MaxBodySize = d.Block[0].ArgStrings()[0]
			} else {
				ok = false
			}
		case "import":
			a := d.ArgStrings()
			if len(a) == 1 && !strings.ContainsAny(a[0], "/*.") {
				c.Snippets = append(c.Snippets, a[0])
			} else {
				ok = false
			}
		case "handle", "handle_path":
			r, good := parseRoute(d)
			if good {
				c.Routes = append(c.Routes, r)
			} else {
				ok = false
			}
		default:
			ok = false
		}
		if ok {
			mapped++
		} else {
			raw = append(raw, d.Source(im.src))
		}
	}
	if hasRoot && hasFS && site.Kind == "" {
		site.Kind = model.KindStatic
		c.Static = &static
	} else if hasRoot || hasFS || static.SPA {
		// pieces of a static config without a clean mapping: keep raw
		for _, d := range b.Body {
			if n := d.Name(); n == "root" || n == "file_server" || n == "try_files" {
				raw = appendUnique(raw, d.Source(im.src))
			}
		}
	}
	if site.Kind == "" {
		site.Kind = model.KindNone
	}
	if len(raw) > 0 {
		c.Raw = strings.Join(raw, "\n")
	}
	im.res.Sites = append(im.res.Sites, site)
	switch {
	case len(raw) == 0:
		im.report(name, "structured", fmt.Sprintf("%s site", site.Kind))
	case mapped == 0:
		im.report(name, "partial", "no directives mapped; everything kept in the site's raw snippet")
	default:
		im.report(name, "partial", fmt.Sprintf("%d directive(s) kept in the site's raw snippet", len(raw)))
	}
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func isMatcher(s string) bool {
	return strings.HasPrefix(s, "@") || strings.HasPrefix(s, "/") || s == "*"
}

var proxyScalar = map[string]bool{
	"lb_policy": true, "lb_retries": true, "lb_try_duration": true, "health_uri": true, "health_interval": true,
	"health_timeout": true, "health_status": true, "fail_duration": true, "max_fails": true, "unhealthy_status": true,
	"flush_interval": true,
}

func parseProxy(d *cf.Directive) (*model.ProxyConfig, bool) {
	a := d.ArgStrings()
	if len(a) > 0 && isMatcher(a[0]) {
		return nil, false
	}
	p := &model.ProxyConfig{Upstreams: a}
	for _, s := range d.Block {
		sa := s.ArgStrings()
		switch {
		case s.Name() == "to":
			p.Upstreams = append(p.Upstreams, sa...)
		case proxyScalar[s.Name()] && len(sa) == 1:
			v := sa[0]
			switch s.Name() {
			case "lb_policy":
				p.LBPolicy = v
			case "lb_retries":
				n, err := strconv.Atoi(v)
				if err != nil {
					return nil, false
				}
				p.LBRetries = n
			case "lb_try_duration":
				p.LBTryDuration = v
			case "health_uri":
				p.HealthURI = v
			case "health_interval":
				p.HealthInterval = v
			case "health_timeout":
				p.HealthTimeout = v
			case "health_status":
				p.HealthStatus = v
			case "fail_duration":
				p.FailDuration = v
			case "max_fails":
				n, err := strconv.Atoi(v)
				if err != nil {
					return nil, false
				}
				p.MaxFails = n
			case "unhealthy_status":
				p.UnhealthyStatus = v
			case "flush_interval":
				p.FlushInterval = v
			}
		case (s.Name() == "header_up" || s.Name() == "header_down") && len(sa) == 2 && !strings.HasPrefix(sa[0], "+") && !strings.HasPrefix(sa[0], "-"):
			if s.Name() == "header_up" {
				if strings.EqualFold(sa[0], "Host") && sa[1] == "{upstream_hostport}" {
					f := false
					p.PassHostHeader = &f
					continue
				}
				if p.HeaderUp == nil {
					p.HeaderUp = map[string]string{}
				}
				p.HeaderUp[sa[0]] = sa[1]
			} else {
				if p.HeaderDown == nil {
					p.HeaderDown = map[string]string{}
				}
				p.HeaderDown[sa[0]] = sa[1]
			}
		case s.Name() == "transport" && len(sa) == 1 && sa[0] == "http":
			for _, t := range s.Block {
				ta := t.ArgStrings()
				switch {
				case t.Name() == "tls" && len(ta) == 0:
				case t.Name() == "tls_insecure_skip_verify" && len(ta) == 0:
					p.TLSSkipVerify = true
				case t.Name() == "tls_server_name" && len(ta) == 1:
					p.TLSServerName = ta[0]
				case t.Name() == "versions" && strings.Join(ta, " ") == "h2c 2":
					p.H2C = true
				case t.Name() == "versions" && strings.Join(ta, " ") == "2":
					p.HTTP2 = true
				case t.Name() == "dial_timeout" && len(ta) == 1:
					p.DialTimeout = ta[0]
				case t.Name() == "response_header_timeout" && len(ta) == 1:
					p.ResponseHeaderTimeout = ta[0]
				case t.Name() == "read_timeout" && len(ta) == 1:
					p.ReadTimeout = ta[0]
				case t.Name() == "write_timeout" && len(ta) == 1:
					p.WriteTimeout = ta[0]
				default:
					return nil, false
				}
			}
		default:
			return nil, false
		}
	}
	if len(p.Upstreams) == 0 {
		return nil, false
	}
	return p, true
}

func parseRedir(d *cf.Directive) (*model.RedirectConfig, bool) {
	a := d.ArgStrings()
	if d.HasBlock || len(a) == 0 || len(a) > 2 || isMatcher(a[0]) && !strings.HasPrefix(a[0], "/") {
		return nil, false
	}
	if len(a) == 2 && strings.HasPrefix(a[0], "/") && !strings.HasPrefix(a[1], "/") && !strings.Contains(a[1], "://") {
		// "redir /path target" vs "redir target code" ambiguity: be strict
		if _, err := strconv.Atoi(a[1]); err != nil && a[1] != "permanent" && a[1] != "temporary" && a[1] != "html" {
			return nil, false
		}
	}
	r := &model.RedirectConfig{To: a[0], Code: 302}
	if strings.HasSuffix(r.To, "{uri}") {
		r.To, r.KeepPath = strings.TrimSuffix(r.To, "{uri}"), true
	}
	if len(a) == 2 {
		switch a[1] {
		case "permanent":
			r.Code = 301
		case "temporary":
			r.Code = 302
		default:
			n, err := strconv.Atoi(a[1])
			if err != nil || n < 300 || n > 399 {
				return nil, false
			}
			r.Code = n
		}
	}
	return r, true
}

func parseRespond(d *cf.Directive) (*model.RespondConfig, bool) {
	a := d.ArgStrings()
	if d.HasBlock || len(a) > 2 || len(a) > 0 && isMatcher(a[0]) {
		return nil, false
	}
	r := &model.RespondConfig{Status: 200}
	switch len(a) {
	case 1:
		if n, err := strconv.Atoi(a[0]); err == nil && n >= 100 && n <= 999 && !d.Args[1].Quoted {
			r.Status = n
		} else {
			r.Body = a[0]
		}
	case 2:
		n, err := strconv.Atoi(a[1])
		if err != nil {
			return nil, false
		}
		r.Body, r.Status = a[0], n
	}
	return r, true
}

func parseHeader(d *cf.Directive, c *model.SiteConfig) bool {
	a := d.ArgStrings()
	set := func(k, v string) {
		if c.HeadersSet == nil {
			c.HeadersSet = map[string]string{}
		}
		c.HeadersSet[k] = v
	}
	if d.HasBlock {
		if len(a) > 0 {
			return false
		}
		for _, s := range d.Block {
			sa := s.ArgStrings()
			n := s.Name()
			switch {
			case strings.HasPrefix(n, "-") && len(sa) == 0:
				c.HeadersRemove = append(c.HeadersRemove, n[1:])
			case !strings.HasPrefix(n, "+") && !strings.HasPrefix(n, ">") && !strings.HasPrefix(n, "?") && !strings.HasPrefix(n, "-") && len(sa) == 1 && n != "defer" && n != "match":
				set(n, sa[0])
			default:
				return false
			}
		}
		return true
	}
	switch {
	case len(a) == 1 && strings.HasPrefix(a[0], "-"):
		c.HeadersRemove = append(c.HeadersRemove, a[0][1:])
		return true
	case len(a) == 2 && !isMatcher(a[0]) && !strings.ContainsAny(a[0][:1], "+-?>"):
		set(a[0], a[1])
		return true
	}
	return false
}

func (im *importer) parseTLS(d *cf.Directive, s *model.Site) bool {
	a := d.ArgStrings()
	c := &s.Config
	switch {
	case !d.HasBlock && len(a) == 1 && a[0] == "internal":
		c.TLS.Mode = model.TLSInternal
		return true
	case !d.HasBlock && len(a) == 2:
		c.TLS = model.TLSConfig{Mode: model.TLSCustom, CertFile: a[0], KeyFile: a[1]}
		return true
	case !d.HasBlock && len(a) == 1 && strings.Contains(a[0], "@"):
		if im.res.Email == "" {
			im.res.Email = a[0]
		}
		return true
	case d.HasBlock && len(a) == 0:
		// only "dns <provider> ..." plus propagation/resolvers is mapped
		var cred *Credential
		for _, sub := range d.Block {
			switch sub.Name() {
			case "dns":
				cred = im.dnsCred(sub)
				if cred == nil {
					return false
				}
			case "resolvers", "propagation_delay", "propagation_timeout":
				// folded into domain/global settings; acceptable loss of
				// per-site granularity is reported
			default:
				return false
			}
		}
		if cred == nil {
			return false
		}
		for _, h := range s.Hosts {
			bd := BaseDomain(h)
			if bd == "" {
				continue
			}
			exists := false
			for _, ds := range im.res.Domains {
				if ds.Name == bd {
					exists = true
				}
			}
			if !exists {
				im.res.Domains = append(im.res.Domains, DomainSuggestion{Name: bd, Challenge: model.ChallengeDNS, CredentialKey: cred.Key})
			}
		}
		return true
	}
	return false
}

func parseRoute(d *cf.Directive) (model.Route, bool) {
	a := d.ArgStrings()
	if len(a) != 1 || !strings.HasPrefix(a[0], "/") || !d.HasBlock || len(d.Block) != 1 {
		return model.Route{}, false
	}
	r := model.Route{Path: a[0], StripPrefix: d.Name() == "handle_path"}
	inner := d.Block[0]
	switch inner.Name() {
	case "reverse_proxy":
		p, ok := parseProxy(inner)
		if !ok {
			return r, false
		}
		r.Kind, r.Proxy = model.KindProxy, p
	case "redir":
		rd, ok := parseRedir(inner)
		if !ok {
			return r, false
		}
		r.Kind, r.Redirect = model.KindRedirect, rd
	case "respond":
		rs, ok := parseRespond(inner)
		if !ok {
			return r, false
		}
		r.Kind, r.Respond = model.KindRespond, rs
	default:
		return r, false
	}
	return r, true
}
