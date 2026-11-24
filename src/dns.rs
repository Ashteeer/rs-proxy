use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};

use hickory_resolver::{
    TokioResolver,
    config::{LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts},
    net::runtime::TokioRuntimeProvider,
};
use thiserror::Error;
use tokio::{sync::Semaphore, time::timeout};

use crate::{
    config::DnsConfig,
    policy::{AddressPolicy, PolicyRefreshError},
};

#[derive(Clone)]
pub struct IndependentResolver {
    inner: TokioResolver,
    query_slots: Arc<Semaphore>,
    lookup_timeout: Duration,
    runtime_guard: Option<RuntimeDnsGuard>,
}

#[derive(Clone)]
struct RuntimeDnsGuard {
    policy: Arc<AddressPolicy>,
    servers: Arc<[SocketAddr]>,
}

impl IndependentResolver {
    /// Build a resolver that uses only the explicitly configured nameservers.
    ///
    /// # Errors
    ///
    /// Returns an error if Hickory cannot construct its resolver pool.
    pub fn new(config: &DnsConfig, policy: &AddressPolicy) -> Result<Self, DnsError> {
        Self::build(config, policy, None)
    }

    /// Build a resolver that refreshes local interfaces and rejects DNS loops
    /// immediately before each lookup.
    ///
    /// # Errors
    ///
    /// Returns an error if Hickory cannot construct its resolver pool.
    pub fn new_with_runtime_guard(
        config: &DnsConfig,
        policy: &Arc<AddressPolicy>,
    ) -> Result<Self, DnsError> {
        let guard = RuntimeDnsGuard {
            policy: Arc::clone(policy),
            servers: Arc::from(config.servers.clone()),
        };
        Self::build(config, policy, Some(guard))
    }

    fn build(
        config: &DnsConfig,
        policy: &AddressPolicy,
        runtime_guard: Option<RuntimeDnsGuard>,
    ) -> Result<Self, DnsError> {
        let name_servers = config
            .servers
            .iter()
            .map(|server| nameserver_config(*server))
            .collect();
        let resolver_config = ResolverConfig::from_name_servers(name_servers);

        let mut options = ResolverOpts::default();
        options.timeout = Duration::from_millis(config.request_timeout_ms);
        options.attempts = config.attempts;
        options.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        options.cache_size = config.cache_size;
        options.use_hosts_file = ResolveHosts::Never;
        options.positive_max_ttl = Some(Duration::from_secs(config.positive_max_ttl_secs));
        options.negative_max_ttl = Some(Duration::from_secs(config.negative_max_ttl_secs));
        options.num_concurrent_reqs = config.servers.len().min(2);
        options.max_active_requests = config.max_active_requests;
        options.try_tcp_on_error = true;
        options.allow_answers = policy.resolver_allowed_networks();
        options.deny_answers = policy.resolver_denied_networks();

        let inner =
            TokioResolver::builder_with_config(resolver_config, TokioRuntimeProvider::default())
                .with_options(options)
                .build()?;

        Ok(Self {
            inner,
            query_slots: Arc::new(Semaphore::new(config.max_concurrent_queries)),
            lookup_timeout: Duration::from_millis(config.lookup_timeout_ms),
            runtime_guard,
        })
    }

    /// Resolve a DNS hostname and freeze the allowed address snapshot for one route.
    ///
    /// # Errors
    ///
    /// Returns an error on timeout, resolver failure, or an empty answer.
    /// Address policy is rechecked immediately before the connector runs.
    pub async fn resolve(&self, hostname: &str, port: u16) -> Result<Vec<SocketAddr>, DnsError> {
        let _permit = timeout(self.lookup_timeout, self.query_slots.acquire())
            .await
            .map_err(|_| DnsError::ConcurrencyTimeout)?
            .map_err(|_| DnsError::ShuttingDown)?;
        self.check_runtime_dns_endpoints().await?;

        let fqdn = format!("{}.", hostname.trim_end_matches('.'));
        let lookup = timeout(self.lookup_timeout, self.inner.lookup_ip(fqdn))
            .await
            .map_err(|_| DnsError::LookupTimeout)??;

        let mut seen = HashSet::new();
        let mut addresses = Vec::new();
        for ip in lookup.iter() {
            if !seen.insert(ip) {
                continue;
            }
            addresses.push(SocketAddr::new(ip, port));
        }

        if addresses.is_empty() {
            return Err(DnsError::NoAddresses);
        }
        Ok(addresses)
    }

    async fn check_runtime_dns_endpoints(&self) -> Result<(), DnsError> {
        let Some(guard) = &self.runtime_guard else {
            return Ok(());
        };
        guard
            .policy
            .refresh_local_addresses(self.lookup_timeout)
            .await?;
        if let Some(server) = guard
            .servers
            .iter()
            .copied()
            .find(|server| guard.policy.dns_endpoint_conflicts(*server))
        {
            return Err(DnsError::ServerLoop(server));
        }
        Ok(())
    }
}

fn nameserver_config(server: SocketAddr) -> NameServerConfig {
    let mut config = NameServerConfig::udp_and_tcp(server.ip());
    for connection in &mut config.connections {
        connection.port = server.port();
    }
    config
}

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("DNS resolver operation failed: {0}")]
    Network(#[from] hickory_resolver::net::NetError),
    #[error("DNS lookup timed out")]
    LookupTimeout,
    #[error("DNS query concurrency limit stayed full until timeout")]
    ConcurrencyTimeout,
    #[error("DNS resolver is shutting down")]
    ShuttingDown,
    #[error("DNS lookup returned no IP addresses")]
    NoAddresses,
    #[error("DNS endpoint policy refresh failed: {0}")]
    PolicyRefresh(#[from] PolicyRefreshError),
    #[error("DNS server {0} became a proxy-listener loop")]
    ServerLoop(SocketAddr),
}
