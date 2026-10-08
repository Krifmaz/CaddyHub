// Package registry maps GUI features and DNS providers to the Caddy
// modules/versions they need. Adding a new directive or provider means
// adding an entry here (and a generator hook), not touching the core.
package registry

import "sort"

// Capabilities describes the running Caddy binary.
type Capabilities struct {
	Version  Version         `json:"-"`
	VersionS string          `json:"version"`
	Modules  map[string]bool `json:"-"`
	// Packages maps module ID -> "package@version" when known.
	Packages map[string]string `json:"packages,omitempty"`
	Detected bool              `json:"detected"`
}

// HasModule reports whether a module is compiled in. If capabilities were
// never detected (Caddy unreachable), everything is assumed present so the
// generator doesn't silently drop config; validation will catch errors.
func (c Capabilities) HasModule(id string) bool {
	if !c.Detected {
		return true
	}
	return c.Modules[id]
}

// ModuleList returns sorted module IDs.
func (c Capabilities) ModuleList() []string {
	out := make([]string, 0, len(c.Modules))
	for m := range c.Modules {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// Feature is an optional GUI capability backed by a directive/module.
type Feature struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	MinVersion  string   `json:"min_version,omitempty"`
	Modules     []string `json:"modules,omitempty"` // all required
	Plugin      string   `json:"plugin,omitempty"`  // xcaddy --with path if not standard
}

// FeatureStatus is a feature annotated with availability.
type FeatureStatus struct {
	Feature
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

// Features is the registry of optional features. Standard directives are
// listed too, with module requirements, so that a future Caddy that drops
// or renames something is detected rather than producing broken config.
var Features = []Feature{
	{ID: "reverse_proxy", Name: "Reverse proxy", Modules: []string{"http.handlers.reverse_proxy"}},
	{ID: "file_server", Name: "Static files", Modules: []string{"http.handlers.file_server"}},
	{ID: "encode_zstd", Name: "Zstandard compression", Modules: []string{"http.encoders.zstd"}},
	{ID: "encode_gzip", Name: "Gzip compression", Modules: []string{"http.encoders.gzip"}},
	{ID: "basic_auth", Name: "Basic auth", MinVersion: "v2.8.0", Modules: []string{"http.handlers.authentication"}},
	{ID: "forward_auth", Name: "Forward auth", Modules: []string{"http.handlers.reverse_proxy"}},
	{ID: "client_ip", Name: "Client IP matcher", MinVersion: "v2.7.0", Modules: []string{"http.matchers.client_ip"}},
	{ID: "metrics", Name: "Prometheus metrics", MinVersion: "v2.10.0", Modules: []string{"admin.api.metrics"}},
	{ID: "file_placeholder", Name: "{file.*} placeholder for secrets", MinVersion: "v2.8.0"},
	{ID: "rate_limit", Name: "Rate limiting", Description: "Per-site request rate limits (caddy-ratelimit)",
		Modules: []string{"http.handlers.rate_limit"}, Plugin: "github.com/mholt/caddy-ratelimit"},
	{ID: "crowdsec", Name: "CrowdSec bouncer", Description: "Block IPs using CrowdSec decisions",
		Modules: []string{"crowdsec", "http.handlers.crowdsec"}, Plugin: "github.com/hslatman/caddy-crowdsec-bouncer/http"},
	{ID: "layer4", Name: "Layer 4 (TCP/UDP) proxy", Modules: []string{"layer4"}, Plugin: "github.com/mholt/caddy-l4"},
}

// FeatureByID returns a feature by id.
func FeatureByID(id string) (Feature, bool) {
	for _, f := range Features {
		if f.ID == id {
			return f, true
		}
	}
	return Feature{}, false
}

// Check evaluates a feature against capabilities.
func (c Capabilities) Check(f Feature) FeatureStatus {
	st := FeatureStatus{Feature: f, Available: true}
	if !c.Version.AtLeast(f.MinVersion) {
		st.Available = false
		st.Reason = "requires Caddy " + f.MinVersion + " or newer"
		return st
	}
	for _, m := range f.Modules {
		if !c.HasModule(m) {
			st.Available = false
			if f.Plugin != "" {
				st.Reason = "module " + m + " not installed (plugin " + f.Plugin + ")"
			} else {
				st.Reason = "module " + m + " not available in this Caddy build"
			}
			return st
		}
	}
	return st
}

// Has is a convenience for generator checks.
func (c Capabilities) Has(featureID string) bool {
	f, ok := FeatureByID(featureID)
	if !ok {
		return false
	}
	return c.Check(f).Available
}

// AllFeatureStatus returns every feature with availability.
func (c Capabilities) AllFeatureStatus() []FeatureStatus {
	out := make([]FeatureStatus, 0, len(Features))
	for _, f := range Features {
		out = append(out, c.Check(f))
	}
	return out
}

// Plugin is an installable xcaddy module for the plugin manager.
type Plugin struct {
	Path        string `json:"path"` // go module path for xcaddy --with
	Name        string `json:"name"`
	Category    string `json:"category"` // dns, security, proxy, other
	Module      string `json:"module"`   // a module ID it registers (for detection)
	Description string `json:"description"`
}

// Plugins returns the catalog: every DNS provider plus extras.
func Plugins() []Plugin {
	out := []Plugin{
		{Path: "github.com/mholt/caddy-ratelimit", Name: "Rate limit", Category: "security", Module: "http.handlers.rate_limit", Description: "rate_limit directive"},
		{Path: "github.com/hslatman/caddy-crowdsec-bouncer/http", Name: "CrowdSec bouncer (HTTP)", Category: "security", Module: "http.handlers.crowdsec", Description: "crowdsec global app + handler"},
		{Path: "github.com/hslatman/caddy-crowdsec-bouncer/appsec", Name: "CrowdSec AppSec", Category: "security", Module: "http.handlers.appsec", Description: "CrowdSec AppSec WAF component"},
		{Path: "github.com/mholt/caddy-l4", Name: "Layer 4", Category: "proxy", Module: "layer4", Description: "TCP/UDP proxying"},
		{Path: "github.com/caddyserver/transform-encoder", Name: "Transform log encoder", Category: "other", Module: "caddy.logging.encoders.transform", Description: "Custom log formats"},
	}
	for _, p := range DNSProviders {
		out = append(out, Plugin{Path: p.Plugin, Name: p.Name + " DNS", Category: "dns", Module: "dns.providers." + p.ID, Description: "DNS-01 challenge provider"})
	}
	return out
}

// PluginByPath looks up a catalog entry.
func PluginByPath(path string) (Plugin, bool) {
	for _, p := range Plugins() {
		if p.Path == path {
			return p, true
		}
	}
	return Plugin{}, false
}
