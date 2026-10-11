use serde::Serialize;

/// One credential/option field of a DNS provider. Key is the exact
/// Caddyfile subdirective name used by the caddy-dns module (verified
/// against each module's UnmarshalCaddyfile).
#[derive(Debug, Clone, Serialize)]
pub struct DnsField {
    pub key: &'static str,
    pub label: &'static str,
    pub secret: bool,
    pub required: bool,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub help: &'static str,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub default: &'static str,
}

/// Describes a caddy-dns provider.
#[derive(Debug, Clone, Serialize)]
pub struct DnsProvider {
    /// module name: dns.providers.<id>
    pub id: &'static str,
    pub name: &'static str,
    /// package path for the download API / xcaddy
    pub plugin: &'static str,
    /// where to create a token
    pub docs_url: &'static str,
    pub privilege: &'static str,
    pub fields: &'static [DnsField],
    #[serde(skip_serializing_if = "str::is_empty")]
    pub min_version: &'static str,
    /// panel can test against the provider API
    pub live_test: bool,
}

impl DnsProvider {
    /// The Caddy module ID.
    pub fn module(&self) -> String {
        format!("dns.providers.{}", self.id)
    }
}

const fn fld(key: &'static str, label: &'static str, secret: bool, required: bool) -> DnsField {
    DnsField {
        key,
        label,
        secret,
        required,
        help: "",
        default: "",
    }
}
const fn sec(key: &'static str, label: &'static str) -> DnsField {
    fld(key, label, true, true)
}
const fn opt(key: &'static str, label: &'static str) -> DnsField {
    fld(key, label, false, false)
}

const LEAST_PRIV: &str =
    "Create a token restricted to DNS edit on the zone(s) you use here, nothing more.";

const fn prov(
    id: &'static str,
    name: &'static str,
    plugin: &'static str,
    docs_url: &'static str,
    privilege: &'static str,
    fields: &'static [DnsField],
    live_test: bool,
) -> DnsProvider {
    DnsProvider {
        id,
        name,
        plugin,
        docs_url,
        privilege,
        fields,
        min_version: "",
        live_test,
    }
}

/// The provider catalog. Order is display order.
pub static DNS_PROVIDERS: &[DnsProvider] = &[
    prov(
        "cloudflare",
        "Cloudflare",
        "github.com/caddy-dns/cloudflare",
        "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
        "Use an API Token (not the Global API Key) with Zone → DNS → Edit and Zone → Zone → Read, scoped to the specific zone.",
        &[
            sec("api_token", "API token"),
            DnsField {
                help: "Optional separate Zone:Read token if you split permissions.",
                ..fld("zone_token", "Zone token (optional)", true, false)
            },
        ],
        true,
    ),
    prov(
        "porkbun",
        "Porkbun",
        "github.com/caddy-dns/porkbun",
        "https://porkbun.com/account/api",
        "Enable 'API Access' only on the domains this panel manages.",
        &[
            sec("api_key", "API key"),
            sec("api_secret_key", "Secret API key"),
        ],
        true,
    ),
    prov(
        "namecheap",
        "Namecheap",
        "github.com/caddy-dns/namecheap",
        "https://www.namecheap.com/support/api/intro/",
        "Namecheap API access is account-wide; whitelist only your server's public IP.",
        &[
            sec("api_key", "API key"),
            fld("user", "Username", false, true),
            DnsField {
                help: "Public IP of this server (must be whitelisted in Namecheap).",
                ..opt("client_ip", "Whitelisted client IP")
            },
            DnsField {
                help: "Leave empty for production.",
                ..opt("api_endpoint", "API endpoint")
            },
        ],
        false,
    ),
    prov(
        "duckdns",
        "DuckDNS",
        "github.com/caddy-dns/duckdns",
        "https://www.duckdns.org/",
        "DuckDNS tokens are account-wide; keep it out of shared configs.",
        &[
            sec("api_token", "Token"),
            DnsField {
                help: "Only if using CNAME delegation to a duckdns.org name.",
                ..opt("override_domain", "Override domain")
            },
        ],
        false,
    ),
    prov(
        "route53",
        "AWS Route 53",
        "github.com/caddy-dns/route53",
        "https://github.com/caddy-dns/route53#readme",
        "Use an IAM user/role limited to route53:ChangeResourceRecordSets/ListResourceRecordSets on the hosted zone, plus route53:ListHostedZonesByName and route53:GetChange.",
        &[
            fld("access_key_id", "Access key ID", true, false),
            fld("secret_access_key", "Secret access key", true, false),
            fld("session_token", "Session token", true, false),
            DnsField {
                default: "us-east-1",
                ..opt("region", "Region")
            },
            opt("profile", "AWS profile"),
            opt("hosted_zone_id", "Hosted zone ID"),
        ],
        false,
    ),
    prov(
        "digitalocean",
        "DigitalOcean",
        "github.com/caddy-dns/digitalocean",
        "https://cloud.digitalocean.com/account/api/tokens",
        "Create a custom-scoped token with only domain:read and domain:update.",
        &[sec("api_token", "API token")],
        true,
    ),
    prov(
        "hetzner",
        "Hetzner",
        "github.com/caddy-dns/hetzner/v2",
        "https://docs.hetzner.com/cloud/api/getting-started/generating-api-token/",
        "Create a Read & Write token in a Hetzner Console project that only contains your DNS zones.",
        &[sec("api_token", "API token")],
        true,
    ),
    prov(
        "desec",
        "deSEC",
        "github.com/caddy-dns/desec",
        "https://desec.io/tokens",
        "Create a token with a token policy limited to the domain and TXT records under _acme-challenge.",
        &[sec("token", "Token")],
        true,
    ),
    prov(
        "gandi",
        "Gandi",
        "github.com/caddy-dns/gandi",
        "https://account.gandi.net/",
        "Create a Personal Access Token restricted to the domain with 'Manage domain technical configurations' only.",
        &[sec("bearer_token", "Personal access token")],
        true,
    ),
    prov(
        "ovh",
        "OVHcloud",
        "github.com/caddy-dns/ovh",
        "https://api.ovh.com/createToken/",
        "Grant only GET/POST/PUT/DELETE on /domain/zone/<your-zone>/*.",
        &[
            DnsField {
                default: "ovh-eu",
                help: "ovh-eu, ovh-ca, ovh-us, ...",
                ..fld("endpoint", "Endpoint", false, true)
            },
            sec("application_key", "Application key"),
            sec("application_secret", "Application secret"),
            sec("consumer_key", "Consumer key"),
        ],
        false,
    ),
    prov(
        "linode",
        "Linode / Akamai",
        "github.com/caddy-dns/linode",
        "https://cloud.linode.com/profile/tokens",
        "Create a personal access token with Domains: Read/Write only.",
        &[sec("api_token", "API token")],
        true,
    ),
    prov(
        "vultr",
        "Vultr",
        "github.com/caddy-dns/vultr",
        "https://my.vultr.com/settings/#settingsapi",
        "Vultr API keys are account-wide; restrict by IP in the API settings.",
        &[sec("api_token", "API key")],
        true,
    ),
    prov(
        "godaddy",
        "GoDaddy",
        "github.com/caddy-dns/godaddy",
        "https://developer.godaddy.com/keys",
        "Production API key; format is key:secret.",
        &[sec("api_token", "API token (key:secret)")],
        true,
    ),
    prov(
        "azure",
        "Azure DNS",
        "github.com/caddy-dns/azure",
        "https://github.com/caddy-dns/azure#readme",
        "Assign the 'DNS Zone Contributor' role on the specific zone only.",
        &[
            fld("subscription_id", "Subscription ID", false, true),
            fld("resource_group_name", "Resource group", false, true),
            opt("tenant_id", "Tenant ID"),
            opt("client_id", "Client ID"),
            fld("client_secret", "Client secret", true, false),
        ],
        false,
    ),
    prov(
        "googleclouddns",
        "Google Cloud DNS",
        "github.com/caddy-dns/googleclouddns",
        "https://github.com/caddy-dns/googleclouddns#readme",
        "Use a service account with the 'DNS Administrator' role on the project only.",
        &[
            fld("gcp_project", "GCP project", false, true),
            DnsField {
                help: "Path inside the caddy container, e.g. a Docker secret.",
                ..opt("gcp_application_default", "Service account JSON path")
            },
        ],
        false,
    ),
    prov(
        "netcup",
        "netcup",
        "github.com/caddy-dns/netcup",
        "https://www.customercontrolpanel.de/",
        "Create a dedicated API key/password in the CCP.",
        &[
            fld("customer_number", "Customer number", false, true),
            sec("api_key", "API key"),
            sec("api_password", "API password"),
        ],
        false,
    ),
    prov(
        "ionos",
        "IONOS",
        "github.com/caddy-dns/ionos",
        "https://developer.hosting.ionos.com/keys",
        "Key format is prefix.secret.",
        &[sec("api_token", "API key (prefix.secret)")],
        false,
    ),
    prov(
        "dnsimple",
        "DNSimple",
        "github.com/caddy-dns/dnsimple",
        "https://support.dnsimple.com/articles/api-access-token/",
        "Use an account token, not a user token.",
        &[
            sec("api_access_token", "API access token"),
            opt("account_id", "Account ID"),
        ],
        true,
    ),
    prov(
        "bunny",
        "Bunny.net",
        "github.com/caddy-dns/bunny",
        "https://dash.bunny.net/account/api-key",
        "Bunny API keys are account-wide.",
        &[sec("access_key", "API key")],
        true,
    ),
    prov(
        "namesilo",
        "NameSilo",
        "github.com/caddy-dns/namesilo",
        "https://www.namesilo.com/account/api-manager",
        "Restrict the key to this server's IP.",
        &[sec("api_token", "API key")],
        true,
    ),
    prov(
        "infomaniak",
        "Infomaniak",
        "github.com/caddy-dns/infomaniak",
        "https://manager.infomaniak.com/v3/infomaniak-api",
        "Create a token with the 'domain:read' and 'dns:write' scopes only.",
        &[sec("api_token", "API token")],
        false,
    ),
    prov(
        "powerdns",
        "PowerDNS",
        "github.com/caddy-dns/powerdns",
        "https://doc.powerdns.com/authoritative/http-api/",
        LEAST_PRIV,
        &[
            fld("server_url", "Server URL", false, true),
            sec("api_token", "API key"),
            DnsField {
                default: "localhost",
                ..opt("server_id", "Server ID")
            },
        ],
        false,
    ),
    prov(
        "rfc2136",
        "RFC 2136 (BIND, Knot, ...)",
        "github.com/caddy-dns/rfc2136",
        "https://github.com/caddy-dns/rfc2136#readme",
        "Use a TSIG key only allowed to update _acme-challenge records.",
        &[
            fld("server", "Server (host:port)", false, true),
            fld("key_name", "TSIG key name", false, true),
            DnsField {
                default: "hmac-sha256",
                ..fld("key_alg", "TSIG algorithm", false, true)
            },
            sec("key", "TSIG secret (base64)"),
        ],
        false,
    ),
    prov(
        "acmedns",
        "ACME-DNS",
        "github.com/caddy-dns/acmedns",
        "https://github.com/joohoi/acme-dns",
        "acme-dns accounts can only update their own TXT record.",
        &[
            fld("username", "Username", false, true),
            sec("password", "Password"),
            fld("subdomain", "Subdomain", false, true),
            fld("server_url", "Server URL", false, true),
        ],
        false,
    ),
];

/// Returns a provider by id.
pub fn dns_provider_by_id(id: &str) -> Option<&'static DnsProvider> {
    DNS_PROVIDERS.iter().find(|p| p.id == id)
}
