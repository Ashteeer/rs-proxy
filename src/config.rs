use std::{
    collections::HashSet,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use ipnet::{IpNet, Ipv6Net};
use serde::Deserialize;
use thiserror::Error;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/rs-proxy/config.toml";
const MAX_CONNECTIONS: usize = 1_000_000;
const MAX_CONCURRENT_DNS_QUERIES: usize = 100_000;
const MAX_INSPECT_BYTES: usize = 1024 * 1024;
const MAX_ADDRESSES_PER_LOOKUP: usize = 256;
const MAX_IO_TIMEOUT_MS: u64 = 60_000;
const MAX_IDLE_TIMEOUT_SECS: u64 = 86_400;
const MAX_SHUTDOWN_GRACE_SECS: u64 = 3_600;
const MAX_METRICS_INTERVAL_SECS: u64 = 86_400;
const MAX_DNS_ATTEMPTS: usize = 10;
const MAX_DNS_CACHE_ENTRIES: u64 = 1_000_000;
const MAX_DNS_ACTIVE_REQUESTS: usize = 65_536;
const MAX_NAT64_PREFIXES: usize = 64;
const IPSET_MAX_NAME_BYTES: usize = 31;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    pub dns: DnsConfig,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default)]
    pub ipset: IpSetConfig,
    pub listeners: Vec<ListenerConfig>,
}

impl Config {
    /// Read, parse, and validate a configuration file.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, TOML is malformed, an
    /// unknown field is present, or a runtime invariant is violated.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let input = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_toml(&input)
    }

    /// Parse and validate a complete TOML configuration string.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed TOML, unknown fields, or invalid values.
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input)?;
        config.validate()?;
        Ok(config)
    }

    /// Enforce invariants required by the currently implemented runtime.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] for unsupported or unsafe settings.
    #[allow(
        clippy::too_many_lines,
        reason = "validation is kept together so every cross-field invariant runs in one pass"
    )]
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.listeners.is_empty() {
            return Err(ConfigError::Invalid(
                "at least one [[listeners]] entry is required".into(),
            ));
        }
        if self.dns.servers.is_empty() {
            return Err(ConfigError::Invalid(
                "dns.servers must contain at least one explicit nameserver".into(),
            ));
        }
        if self.server.max_connections == 0 {
            return Err(ConfigError::Invalid(
                "server.max_connections must be greater than zero".into(),
            ));
        }
        if self.server.inspect_max_bytes < 512 {
            return Err(ConfigError::Invalid(
                "server.inspect_max_bytes must be at least 512".into(),
            ));
        }
        if self.server.inspect_max_bytes > MAX_INSPECT_BYTES {
            return Err(ConfigError::Invalid(format!(
                "server.inspect_max_bytes cannot exceed {MAX_INSPECT_BYTES}"
            )));
        }
        if self.server.max_connections > MAX_CONNECTIONS {
            return Err(ConfigError::Invalid(format!(
                "server.max_connections cannot exceed {MAX_CONNECTIONS}"
            )));
        }
        if self.server.inspect_timeout_ms == 0
            || self.server.connect_timeout_ms == 0
            || self.server.initial_write_timeout_ms == 0
            || self.server.idle_timeout_secs == 0
            || self.server.shutdown_grace_secs == 0
        {
            return Err(ConfigError::Invalid(
                "server timeout values must be greater than zero".into(),
            ));
        }
        if self.server.inspect_timeout_ms > MAX_IO_TIMEOUT_MS
            || self.server.connect_timeout_ms > MAX_IO_TIMEOUT_MS
            || self.server.initial_write_timeout_ms > MAX_IO_TIMEOUT_MS
        {
            return Err(ConfigError::Invalid(format!(
                "server millisecond timeouts cannot exceed {MAX_IO_TIMEOUT_MS}"
            )));
        }
        if self.server.idle_timeout_secs > MAX_IDLE_TIMEOUT_SECS {
            return Err(ConfigError::Invalid(format!(
                "server.idle_timeout_secs cannot exceed {MAX_IDLE_TIMEOUT_SECS}"
            )));
        }
        if self.server.shutdown_grace_secs > MAX_SHUTDOWN_GRACE_SECS {
            return Err(ConfigError::Invalid(format!(
                "server.shutdown_grace_secs cannot exceed {MAX_SHUTDOWN_GRACE_SECS}"
            )));
        }
        if self.server.metrics_interval_secs == 0
            || self.server.metrics_interval_secs > MAX_METRICS_INTERVAL_SECS
        {
            return Err(ConfigError::Invalid(format!(
                "server.metrics_interval_secs must be between 1 and {MAX_METRICS_INTERVAL_SECS}"
            )));
        }
        if self.dns.request_timeout_ms == 0
            || self.dns.lookup_timeout_ms == 0
            || self.dns.attempts == 0
            || self.dns.cache_size == 0
            || self.dns.max_concurrent_queries == 0
            || self.dns.max_active_requests == 0
            || self.dns.max_addresses_per_lookup == 0
        {
            return Err(ConfigError::Invalid(
                "DNS timeouts, attempts, cache, and concurrency limits must be greater than zero"
                    .into(),
            ));
        }
        if self.dns.request_timeout_ms > self.dns.lookup_timeout_ms {
            return Err(ConfigError::Invalid(
                "dns.request_timeout_ms cannot exceed dns.lookup_timeout_ms".into(),
            ));
        }
        if self.dns.request_timeout_ms > MAX_IO_TIMEOUT_MS
            || self.dns.lookup_timeout_ms > MAX_IO_TIMEOUT_MS
        {
            return Err(ConfigError::Invalid(format!(
                "DNS timeouts cannot exceed {MAX_IO_TIMEOUT_MS} milliseconds"
            )));
        }
        if self.dns.attempts > MAX_DNS_ATTEMPTS
            || self.dns.cache_size > MAX_DNS_CACHE_ENTRIES
            || self.dns.max_active_requests > MAX_DNS_ACTIVE_REQUESTS
        {
            return Err(ConfigError::Invalid(
                "DNS attempts, cache size, or active-request limit exceeds the operational maximum"
                    .into(),
            ));
        }
        if self.dns.max_concurrent_queries > MAX_CONCURRENT_DNS_QUERIES {
            return Err(ConfigError::Invalid(format!(
                "dns.max_concurrent_queries cannot exceed {MAX_CONCURRENT_DNS_QUERIES}"
            )));
        }
        if self.dns.max_addresses_per_lookup > MAX_ADDRESSES_PER_LOOKUP {
            return Err(ConfigError::Invalid(format!(
                "dns.max_addresses_per_lookup cannot exceed {MAX_ADDRESSES_PER_LOOKUP}"
            )));
        }
        if !self.routing.preserve_destination_port {
            return Err(ConfigError::Invalid(
                "routing.preserve_destination_port=false is not supported".into(),
            ));
        }
        if self.routing.nat64_prefixes.len() > MAX_NAT64_PREFIXES {
            return Err(ConfigError::Invalid(format!(
                "routing.nat64_prefixes cannot contain more than {MAX_NAT64_PREFIXES} entries"
            )));
        }
        let mut nat64_seen = HashSet::new();
        for prefix in &self.routing.nat64_prefixes {
            if !matches!(prefix.prefix_len(), 32 | 40 | 48 | 56 | 64 | 96) {
                return Err(ConfigError::Invalid(format!(
                    "NAT64 prefix {prefix} must use an RFC 6052 length: /32, /40, /48, /56, /64, or /96"
                )));
            }
            if !nat64_seen.insert(*prefix) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate NAT64 prefix: {prefix}"
                )));
            }
        }

        if self.ipset.enabled {
            validate_ipset_name("ipset.ipv4_set", &self.ipset.ipv4_set)?;
            validate_ipset_name("ipset.ipv6_set", &self.ipset.ipv6_set)?;
            if self.ipset.ipv4_set == self.ipset.ipv6_set {
                return Err(ConfigError::Invalid(
                    "ipset.ipv4_set and ipset.ipv6_set must name different sets".into(),
                ));
            }
        }

        let mut seen = HashSet::new();
        for listener in &self.listeners {
            if self.ipset.enabled
                && self.ipset.not_found != IpSetNotFound::Allow
                && listener.listen.port() == 0
            {
                return Err(ConfigError::Invalid(
                    "IPset firewall policies require explicit non-zero listener ports".into(),
                ));
            }
            if !seen.insert((listener.protocol, listener.listen)) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate listener: {:?} {}",
                    listener.protocol, listener.listen
                )));
            }
        }

        let mut dns_seen = HashSet::new();
        for server in &self.dns.servers {
            if server.port() == 0 {
                return Err(ConfigError::Invalid(format!(
                    "DNS server {server} has invalid port 0"
                )));
            }
            if server.ip().is_unspecified()
                || server.ip().is_multicast()
                || server.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
            {
                return Err(ConfigError::Invalid(format!(
                    "DNS server {server} is not a unicast endpoint"
                )));
            }
            if !dns_seen.insert(*server) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate DNS server: {server}"
                )));
            }
        }

        Ok(())
    }
}

pub(crate) fn validate_ipset_name(field: &str, name: &str) -> Result<(), ConfigError> {
    if name.is_empty() || name.len() > IPSET_MAX_NAME_BYTES {
        return Err(ConfigError::Invalid(format!(
            "{field} must contain 1..={IPSET_MAX_NAME_BYTES} ASCII bytes"
        )));
    }
    if name.starts_with('-')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
    {
        return Err(ConfigError::Invalid(format!(
            "{field} may contain only ASCII letters, digits, '_', '.', ':', and '-', and cannot start with '-'"
        )));
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub log_level: LogLevel,
    pub log_format: LogFormat,
    pub io_backend: IoBackend,
    pub max_connections: usize,
    pub inspect_max_bytes: usize,
    pub inspect_timeout_ms: u64,
    pub connect_timeout_ms: u64,
    pub initial_write_timeout_ms: u64,
    pub idle_timeout_secs: u64,
    pub shutdown_grace_secs: u64,
    pub metrics_interval_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            log_level: LogLevel::Info,
            log_format: LogFormat::Json,
            io_backend: IoBackend::Auto,
            max_connections: 4_096,
            inspect_max_bytes: 64 * 1024,
            inspect_timeout_ms: 5_000,
            connect_timeout_ms: 5_000,
            initial_write_timeout_ms: 5_000,
            idle_timeout_secs: 300,
            shutdown_grace_secs: 30,
            metrics_interval_secs: 60,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    Json,
    Compact,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum IoBackend {
    Auto,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    pub servers: Vec<SocketAddr>,
    pub request_timeout_ms: u64,
    pub lookup_timeout_ms: u64,
    pub attempts: usize,
    pub cache_size: u64,
    pub max_concurrent_queries: usize,
    pub max_active_requests: usize,
    pub max_addresses_per_lookup: usize,
    pub positive_max_ttl_secs: u64,
    pub negative_max_ttl_secs: u64,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            request_timeout_ms: 1_500,
            lookup_timeout_ms: 5_000,
            attempts: 2,
            cache_size: 1_024,
            max_concurrent_queries: 256,
            max_active_requests: 32,
            max_addresses_per_lookup: 16,
            positive_max_ttl_secs: 300,
            negative_max_ttl_secs: 30,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RoutingConfig {
    pub unknown_destination: UnknownDestination,
    pub preserve_destination_port: bool,
    pub allow_upstream_cidrs: Vec<IpNet>,
    /// Network-specific RFC 6052 prefixes used by the deployment's NAT64.
    /// The well-known and RFC 8215 local-use prefixes are always recognized.
    pub nat64_prefixes: Vec<Ipv6Net>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            unknown_destination: UnknownDestination::SilentDrop,
            preserve_destination_port: true,
            allow_upstream_cidrs: Vec::new(),
            nat64_prefixes: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UnknownDestination {
    SilentDrop,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IpSetConfig {
    pub enabled: bool,
    pub ipv4_set: String,
    pub ipv6_set: String,
    pub not_found: IpSetNotFound,
}

impl Default for IpSetConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ipv4_set: "rs_proxy_clients_v4".into(),
            ipv6_set: "rs_proxy_clients_v6".into(),
            not_found: IpSetNotFound::Silent,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum IpSetNotFound {
    Allow,
    FirstResponse,
    Reject,
    Silent,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    pub protocol: ListenerProtocol,
    pub listen: SocketAddr,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ListenerProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read configuration {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid TOML configuration: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        [dns]
        servers = ["1.1.1.1:53"]

        [[listeners]]
        protocol = "tcp"
        listen = "127.0.0.1:443"
    "#;

    #[test]
    fn minimal_config_uses_safe_defaults() {
        let config = Config::from_toml(MINIMAL).expect("valid config");
        assert_eq!(config.server.inspect_max_bytes, 64 * 1024);
        assert_eq!(config.server.metrics_interval_secs, 60);
        assert!(config.routing.allow_upstream_cidrs.is_empty());
        assert!(!config.ipset.enabled);
        assert_eq!(config.ipset.not_found, IpSetNotFound::Silent);
        assert_eq!(config.dns.servers[0], "1.1.1.1:53".parse().unwrap());
    }

    #[test]
    fn metrics_interval_is_positive_and_bounded() {
        for value in [0, MAX_METRICS_INTERVAL_SECS + 1] {
            let input = MINIMAL.replace(
                "[dns]",
                &format!("[server]\nmetrics_interval_secs = {value}\n\n[dns]"),
            );
            let error = Config::from_toml(&input).expect_err("invalid interval must fail");
            assert!(error.to_string().contains("metrics_interval_secs"));
        }

        let input = MINIMAL.replace(
            "[dns]",
            &format!("[server]\nmetrics_interval_secs = {MAX_METRICS_INTERVAL_SECS}\n\n[dns]"),
        );
        Config::from_toml(&input).expect("maximum interval is valid");
    }

    #[test]
    fn enabled_ipset_requires_safe_distinct_set_names() {
        let valid = MINIMAL.replace(
            "[[listeners]]",
            "[ipset]\nenabled = true\nipv4_set = \"clients-v4\"\nipv6_set = \"clients-v6\"\nnot_found = \"allow\"\n\n[[listeners]]",
        );
        Config::from_toml(&valid).expect("safe IPset names are valid");

        for (ipv4, ipv6) in [
            ("", "v6"),
            ("-option", "v6"),
            ("bad name", "v6"),
            ("same", "same"),
            ("abcdefghijklmnopqrstuvwxyz123456", "v6"),
        ] {
            let input = MINIMAL.replace(
                "[[listeners]]",
                &format!(
                    "[ipset]\nenabled = true\nipv4_set = \"{ipv4}\"\nipv6_set = \"{ipv6}\"\n\n[[listeners]]"
                ),
            );
            assert!(
                Config::from_toml(&input).is_err(),
                "names {ipv4:?}/{ipv6:?} must fail"
            );
        }
    }

    #[test]
    fn strict_ipset_firewall_rejects_ephemeral_listener_ports_but_allow_does_not() {
        let strict = MINIMAL
            .replace("listen = \"127.0.0.1:443\"", "listen = \"127.0.0.1:0\"")
            .replace(
                "[[listeners]]",
                "[ipset]\nenabled = true\nnot_found = \"reject\"\n\n[[listeners]]",
            );
        let error = Config::from_toml(&strict).expect_err("strict rule cannot target port zero");
        assert!(
            error
                .to_string()
                .contains("explicit non-zero listener ports")
        );

        let allow = strict.replace("not_found = \"reject\"", "not_found = \"allow\"");
        Config::from_toml(&allow).expect("userspace allow needs no firewall port match");
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let input = MINIMAL.replace(
            "servers = [\"1.1.1.1:53\"]",
            "servers = [\"1.1.1.1:53\"]\npoisoned_fallback = true",
        );
        let error = Config::from_toml(&input).expect_err("unknown field must fail");
        assert!(error.to_string().contains("poisoned_fallback"));
    }

    #[test]
    fn udp_and_tcp_may_share_an_address_but_exact_duplicates_are_rejected() {
        let udp = MINIMAL.replace("protocol = \"tcp\"", "protocol = \"udp\"");
        Config::from_toml(&udp).expect("UDP listener is supported");

        let mixed = MINIMAL.replace(
            "[[listeners]]\n        protocol = \"tcp\"\n        listen = \"127.0.0.1:443\"",
            "[[listeners]]\n        protocol = \"tcp\"\n        listen = \"127.0.0.1:443\"\n\n        [[listeners]]\n        protocol = \"udp\"\n        listen = \"127.0.0.1:443\"",
        );
        Config::from_toml(&mixed).expect("TCP and UDP use distinct socket namespaces");

        let duplicate = MINIMAL.replace(
            "[[listeners]]",
            "[[listeners]]\n        protocol = \"tcp\"\n        listen = \"127.0.0.1:443\"\n\n        [[listeners]]",
        );
        assert!(Config::from_toml(&duplicate).is_err());
    }

    #[test]
    fn excessive_semaphore_limits_are_rejected_without_panicking() {
        let input = MINIMAL.replace(
            "[dns]",
            "[server]\nmax_connections = 18446744073709551615\n\n[dns]",
        );
        let error = Config::from_toml(&input).expect_err("unbounded limit must fail");
        assert!(error.to_string().contains("max_connections"));
    }

    #[test]
    fn invalid_and_duplicate_dns_endpoints_are_rejected() {
        for servers in [
            "[\"0.0.0.0:53\"]",
            "[\"224.0.0.1:53\"]",
            "[\"1.1.1.1:0\"]",
            "[\"1.1.1.1:53\", \"1.1.1.1:53\"]",
        ] {
            let input = MINIMAL.replace("[\"1.1.1.1:53\"]", servers);
            assert!(
                Config::from_toml(&input).is_err(),
                "DNS endpoints {servers} must fail"
            );
        }
    }

    #[test]
    fn nat64_prefixes_require_rfc_6052_lengths_and_are_unique() {
        let valid = MINIMAL.replace(
            "[[listeners]]",
            "[routing]\nnat64_prefixes = [\"2001:db8:64::/64\"]\n\n[[listeners]]",
        );
        Config::from_toml(&valid).expect("RFC 6052 /64 prefix is valid");

        for prefixes in [
            "[\"2001:db8::/65\"]",
            "[\"2001:db8:64::/64\", \"2001:db8:64::/64\"]",
        ] {
            let input = MINIMAL.replace(
                "[[listeners]]",
                &format!("[routing]\nnat64_prefixes = {prefixes}\n\n[[listeners]]"),
            );
            assert!(Config::from_toml(&input).is_err());
        }
    }
}
