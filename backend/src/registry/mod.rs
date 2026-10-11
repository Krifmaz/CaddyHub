//! Maps GUI features and DNS providers to the Caddy modules/versions they
//! need. Adding a new directive or provider means adding an entry here (and
//! a generator hook), not touching the core.

pub mod dns;
pub mod features;
pub mod version;

pub use dns::{DNS_PROVIDERS, DnsField, DnsProvider, dns_provider_by_id};
#[allow(unused_imports)]
pub use features::FEATURES;
pub use features::{Capabilities, Plugin};
pub use version::parse_version;
