package registry

// DNSField is one credential/option field of a DNS provider. Key is the
// exact Caddyfile subdirective name used by the caddy-dns module (verified
// against each module's UnmarshalCaddyfile).
type DNSField struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Secret   bool   `json:"secret"`
	Required bool   `json:"required"`
	Help     string `json:"help,omitempty"`
	Default  string `json:"default,omitempty"`
}

// DNSProvider describes a caddy-dns provider.
type DNSProvider struct {
	ID         string     `json:"id"` // module name: dns.providers.<ID>
	Name       string     `json:"name"`
	Plugin     string     `json:"plugin"`   // xcaddy module path
	DocsURL    string     `json:"docs_url"` // where to create a token
	Privilege  string     `json:"privilege"`
	Fields     []DNSField `json:"fields"`
	MinVersion string     `json:"min_version,omitempty"`
	LiveTest   bool       `json:"live_test"` // panel can test against the provider API
}

// Module returns the Caddy module ID.
func (p DNSProvider) Module() string { return "dns.providers." + p.ID }

const leastPriv = "Create a token restricted to DNS edit on the zone(s) you use here, nothing more."

// DNSProviders is the provider catalog. Order is display order.
var DNSProviders = []DNSProvider{
	{ID: "cloudflare", Name: "Cloudflare", Plugin: "github.com/caddy-dns/cloudflare",
		DocsURL:   "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
		Privilege: "Use an API Token (not the Global API Key) with Zone → DNS → Edit and Zone → Zone → Read, scoped to the specific zone.",
		Fields: []DNSField{
			{Key: "api_token", Label: "API token", Secret: true, Required: true},
			{Key: "zone_token", Label: "Zone token (optional)", Secret: true, Help: "Optional separate Zone:Read token if you split permissions."},
		}, LiveTest: true},
	{ID: "porkbun", Name: "Porkbun", Plugin: "github.com/caddy-dns/porkbun",
		DocsURL:   "https://porkbun.com/account/api",
		Privilege: "Enable 'API Access' only on the domains this panel manages.",
		Fields: []DNSField{
			{Key: "api_key", Label: "API key", Secret: true, Required: true},
			{Key: "api_secret_key", Label: "Secret API key", Secret: true, Required: true},
		}, LiveTest: true},
	{ID: "namecheap", Name: "Namecheap", Plugin: "github.com/caddy-dns/namecheap",
		DocsURL:   "https://www.namecheap.com/support/api/intro/",
		Privilege: "Namecheap API access is account-wide; whitelist only your server's public IP.",
		Fields: []DNSField{
			{Key: "api_key", Label: "API key", Secret: true, Required: true},
			{Key: "user", Label: "Username", Required: true},
			{Key: "client_ip", Label: "Whitelisted client IP", Help: "Public IP of this server (must be whitelisted in Namecheap)."},
			{Key: "api_endpoint", Label: "API endpoint", Help: "Leave empty for production."},
		}},
	{ID: "duckdns", Name: "DuckDNS", Plugin: "github.com/caddy-dns/duckdns",
		DocsURL:   "https://www.duckdns.org/",
		Privilege: "DuckDNS tokens are account-wide; keep it out of shared configs.",
		Fields: []DNSField{
			{Key: "api_token", Label: "Token", Secret: true, Required: true},
			{Key: "override_domain", Label: "Override domain", Help: "Only if using CNAME delegation to a duckdns.org name."},
		}},
	{ID: "route53", Name: "AWS Route 53", Plugin: "github.com/caddy-dns/route53",
		DocsURL:   "https://github.com/caddy-dns/route53#readme",
		Privilege: "Use an IAM user/role limited to route53:ChangeResourceRecordSets/ListResourceRecordSets on the hosted zone, plus route53:ListHostedZonesByName and route53:GetChange.",
		Fields: []DNSField{
			{Key: "access_key_id", Label: "Access key ID", Secret: true},
			{Key: "secret_access_key", Label: "Secret access key", Secret: true},
			{Key: "session_token", Label: "Session token", Secret: true},
			{Key: "region", Label: "Region", Default: "us-east-1"},
			{Key: "profile", Label: "AWS profile"},
			{Key: "hosted_zone_id", Label: "Hosted zone ID"},
		}},
	{ID: "digitalocean", Name: "DigitalOcean", Plugin: "github.com/caddy-dns/digitalocean",
		DocsURL:   "https://cloud.digitalocean.com/account/api/tokens",
		Privilege: "Create a custom-scoped token with only domain:read and domain:update.",
		Fields:    []DNSField{{Key: "api_token", Label: "API token", Secret: true, Required: true}}, LiveTest: true},
	{ID: "hetzner", Name: "Hetzner", Plugin: "github.com/caddy-dns/hetzner/v2",
		DocsURL:   "https://docs.hetzner.com/cloud/api/getting-started/generating-api-token/",
		Privilege: "Create a Read & Write token in a Hetzner Console project that only contains your DNS zones.",
		Fields:    []DNSField{{Key: "api_token", Label: "API token", Secret: true, Required: true}}, LiveTest: true},
	{ID: "desec", Name: "deSEC", Plugin: "github.com/caddy-dns/desec",
		DocsURL:   "https://desec.io/tokens",
		Privilege: "Create a token with a token policy limited to the domain and TXT records under _acme-challenge.",
		Fields:    []DNSField{{Key: "token", Label: "Token", Secret: true, Required: true}}, LiveTest: true},
	{ID: "gandi", Name: "Gandi", Plugin: "github.com/caddy-dns/gandi",
		DocsURL:   "https://account.gandi.net/",
		Privilege: "Create a Personal Access Token restricted to the domain with 'Manage domain technical configurations' only.",
		Fields:    []DNSField{{Key: "bearer_token", Label: "Personal access token", Secret: true, Required: true}}, LiveTest: true},
	{ID: "ovh", Name: "OVHcloud", Plugin: "github.com/caddy-dns/ovh",
		DocsURL:   "https://api.ovh.com/createToken/",
		Privilege: "Grant only GET/POST/PUT/DELETE on /domain/zone/<your-zone>/*.",
		Fields: []DNSField{
			{Key: "endpoint", Label: "Endpoint", Required: true, Default: "ovh-eu", Help: "ovh-eu, ovh-ca, ovh-us, ..."},
			{Key: "application_key", Label: "Application key", Secret: true, Required: true},
			{Key: "application_secret", Label: "Application secret", Secret: true, Required: true},
			{Key: "consumer_key", Label: "Consumer key", Secret: true, Required: true},
		}},
	{ID: "linode", Name: "Linode / Akamai", Plugin: "github.com/caddy-dns/linode",
		DocsURL:   "https://cloud.linode.com/profile/tokens",
		Privilege: "Create a personal access token with Domains: Read/Write only.",
		Fields:    []DNSField{{Key: "api_token", Label: "API token", Secret: true, Required: true}}, LiveTest: true},
	{ID: "vultr", Name: "Vultr", Plugin: "github.com/caddy-dns/vultr",
		DocsURL:   "https://my.vultr.com/settings/#settingsapi",
		Privilege: "Vultr API keys are account-wide; restrict by IP in the API settings.",
		Fields:    []DNSField{{Key: "api_token", Label: "API key", Secret: true, Required: true}}, LiveTest: true},
	{ID: "godaddy", Name: "GoDaddy", Plugin: "github.com/caddy-dns/godaddy",
		DocsURL:   "https://developer.godaddy.com/keys",
		Privilege: "Production API key; format is key:secret.",
		Fields:    []DNSField{{Key: "api_token", Label: "API token (key:secret)", Secret: true, Required: true}}, LiveTest: true},
	{ID: "azure", Name: "Azure DNS", Plugin: "github.com/caddy-dns/azure",
		DocsURL:   "https://github.com/caddy-dns/azure#readme",
		Privilege: "Assign the 'DNS Zone Contributor' role on the specific zone only.",
		Fields: []DNSField{
			{Key: "subscription_id", Label: "Subscription ID", Required: true},
			{Key: "resource_group_name", Label: "Resource group", Required: true},
			{Key: "tenant_id", Label: "Tenant ID"},
			{Key: "client_id", Label: "Client ID"},
			{Key: "client_secret", Label: "Client secret", Secret: true},
		}},
	{ID: "googleclouddns", Name: "Google Cloud DNS", Plugin: "github.com/caddy-dns/googleclouddns",
		DocsURL:   "https://github.com/caddy-dns/googleclouddns#readme",
		Privilege: "Use a service account with the 'DNS Administrator' role on the project only.",
		Fields: []DNSField{
			{Key: "gcp_project", Label: "GCP project", Required: true},
			{Key: "gcp_application_default", Label: "Service account JSON path", Help: "Path inside the caddy container, e.g. a Docker secret."},
		}},
	{ID: "netcup", Name: "netcup", Plugin: "github.com/caddy-dns/netcup",
		DocsURL:   "https://www.customercontrolpanel.de/",
		Privilege: "Create a dedicated API key/password in the CCP.",
		Fields: []DNSField{
			{Key: "customer_number", Label: "Customer number", Required: true},
			{Key: "api_key", Label: "API key", Secret: true, Required: true},
			{Key: "api_password", Label: "API password", Secret: true, Required: true},
		}},
	{ID: "ionos", Name: "IONOS", Plugin: "github.com/caddy-dns/ionos",
		DocsURL:   "https://developer.hosting.ionos.com/keys",
		Privilege: "Key format is prefix.secret.",
		Fields:    []DNSField{{Key: "api_token", Label: "API key (prefix.secret)", Secret: true, Required: true}}},
	{ID: "dnsimple", Name: "DNSimple", Plugin: "github.com/caddy-dns/dnsimple",
		DocsURL:   "https://support.dnsimple.com/articles/api-access-token/",
		Privilege: "Use an account token, not a user token.",
		Fields: []DNSField{
			{Key: "api_access_token", Label: "API access token", Secret: true, Required: true},
			{Key: "account_id", Label: "Account ID"},
		}, LiveTest: true},
	{ID: "bunny", Name: "Bunny.net", Plugin: "github.com/caddy-dns/bunny",
		DocsURL:   "https://dash.bunny.net/account/api-key",
		Privilege: "Bunny API keys are account-wide.",
		Fields:    []DNSField{{Key: "access_key", Label: "API key", Secret: true, Required: true}}, LiveTest: true},
	{ID: "namesilo", Name: "NameSilo", Plugin: "github.com/caddy-dns/namesilo",
		DocsURL:   "https://www.namesilo.com/account/api-manager",
		Privilege: "Restrict the key to this server's IP.",
		Fields:    []DNSField{{Key: "api_token", Label: "API key", Secret: true, Required: true}}, LiveTest: true},
	{ID: "infomaniak", Name: "Infomaniak", Plugin: "github.com/caddy-dns/infomaniak",
		DocsURL:   "https://manager.infomaniak.com/v3/infomaniak-api",
		Privilege: "Create a token with the 'domain:read' and 'dns:write' scopes only.",
		Fields:    []DNSField{{Key: "api_token", Label: "API token", Secret: true, Required: true}}},
	{ID: "powerdns", Name: "PowerDNS", Plugin: "github.com/caddy-dns/powerdns",
		DocsURL:   "https://doc.powerdns.com/authoritative/http-api/",
		Privilege: leastPriv,
		Fields: []DNSField{
			{Key: "server_url", Label: "Server URL", Required: true},
			{Key: "api_token", Label: "API key", Secret: true, Required: true},
			{Key: "server_id", Label: "Server ID", Default: "localhost"},
		}},
	{ID: "rfc2136", Name: "RFC 2136 (BIND, Knot, ...)", Plugin: "github.com/caddy-dns/rfc2136",
		DocsURL:   "https://github.com/caddy-dns/rfc2136#readme",
		Privilege: "Use a TSIG key only allowed to update _acme-challenge records.",
		Fields: []DNSField{
			{Key: "server", Label: "Server (host:port)", Required: true},
			{Key: "key_name", Label: "TSIG key name", Required: true},
			{Key: "key_alg", Label: "TSIG algorithm", Default: "hmac-sha256", Required: true},
			{Key: "key", Label: "TSIG secret (base64)", Secret: true, Required: true},
		}},
	{ID: "acmedns", Name: "ACME-DNS", Plugin: "github.com/caddy-dns/acmedns",
		DocsURL:   "https://github.com/joohoi/acme-dns",
		Privilege: "acme-dns accounts can only update their own TXT record.",
		Fields: []DNSField{
			{Key: "username", Label: "Username", Required: true},
			{Key: "password", Label: "Password", Secret: true, Required: true},
			{Key: "subdomain", Label: "Subdomain", Required: true},
			{Key: "server_url", Label: "Server URL", Required: true},
		}},
}

// DNSProviderByID returns a provider by id.
func DNSProviderByID(id string) (DNSProvider, bool) {
	for _, p := range DNSProviders {
		if p.ID == id {
			return p, true
		}
	}
	return DNSProvider{}, false
}
