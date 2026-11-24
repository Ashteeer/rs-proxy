use std::{
    collections::HashSet,
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, RwLock},
    time::Duration,
};

use ipnet::{IpNet, Ipv6Net};
use thiserror::Error;
use tokio::{
    sync::Semaphore,
    time::{Instant, timeout},
};

const DEFAULT_DENIED_CIDRS: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/128",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
    "2001:db8::/32",
    "fec0::/10",
];

const DEFAULT_NAT64_PREFIXES: &[&str] = &["64:ff9b::/96", "64:ff9b:1::/48"];

type LocalAddressProvider = dyn Fn() -> Result<HashSet<IpAddr>, io::Error> + Send + Sync + 'static;

#[derive(Clone)]
struct LocalAddressSource(Arc<LocalAddressProvider>);

impl LocalAddressSource {
    fn system() -> Self {
        Self(Arc::new(enumerate_local_ips))
    }

    fn enumerate(&self) -> Result<HashSet<IpAddr>, io::Error> {
        (self.0)()
    }
}

impl fmt::Debug for LocalAddressSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalAddressSource(..)")
    }
}

#[derive(Debug)]
pub struct AddressPolicy {
    allowed: Vec<IpNet>,
    denied: Vec<IpNet>,
    local_ips: RwLock<HashSet<IpAddr>>,
    listener_addrs: Vec<SocketAddr>,
    nat64_prefixes: Vec<Ipv6Net>,
    local_address_source: LocalAddressSource,
    refresh_slot: Arc<Semaphore>,
}

impl AddressPolicy {
    /// Create a policy using the host's current interface addresses.
    ///
    /// # Errors
    ///
    /// Returns an error if interfaces cannot be enumerated or an internal
    /// reserved-network constant cannot be parsed.
    pub fn discover(
        listener_addrs: Vec<SocketAddr>,
        allowed: Vec<IpNet>,
    ) -> Result<Self, PolicyBuildError> {
        Self::discover_with_nat64(listener_addrs, allowed, Vec::new())
    }

    /// Create a policy with the deployment's network-specific NAT64 prefixes.
    ///
    /// # Errors
    ///
    /// Returns an error if interfaces cannot be enumerated or an internal
    /// reserved-network/NAT64 constant cannot be parsed.
    pub fn discover_with_nat64(
        listener_addrs: Vec<SocketAddr>,
        allowed: Vec<IpNet>,
        nat64_prefixes: Vec<Ipv6Net>,
    ) -> Result<Self, PolicyBuildError> {
        let local_ips = enumerate_local_ips()?;
        Self::from_parts_with_nat64(listener_addrs, allowed, local_ips, nat64_prefixes)
    }

    /// Create a policy from an explicit local-address snapshot.
    ///
    /// This constructor supports deterministic tests and callers that already
    /// performed interface discovery.
    ///
    /// # Errors
    ///
    /// Returns an error if an internal reserved-network constant is invalid.
    pub fn from_parts(
        listener_addrs: Vec<SocketAddr>,
        allowed: Vec<IpNet>,
        local_ips: HashSet<IpAddr>,
    ) -> Result<Self, PolicyBuildError> {
        Self::from_parts_with_nat64(listener_addrs, allowed, local_ips, Vec::new())
    }

    /// Deterministic constructor with explicit local addresses and NAT64 prefixes.
    ///
    /// # Errors
    ///
    /// Returns an error if an internal reserved-network/NAT64 constant is invalid.
    pub fn from_parts_with_nat64(
        listener_addrs: Vec<SocketAddr>,
        allowed: Vec<IpNet>,
        local_ips: HashSet<IpAddr>,
        configured_nat64_prefixes: Vec<Ipv6Net>,
    ) -> Result<Self, PolicyBuildError> {
        Self::from_parts_with_source(
            listener_addrs,
            allowed,
            local_ips,
            configured_nat64_prefixes,
            LocalAddressSource::system(),
        )
    }

    fn from_parts_with_source(
        listener_addrs: Vec<SocketAddr>,
        allowed: Vec<IpNet>,
        local_ips: HashSet<IpAddr>,
        configured_nat64_prefixes: Vec<Ipv6Net>,
        local_address_source: LocalAddressSource,
    ) -> Result<Self, PolicyBuildError> {
        let denied = DEFAULT_DENIED_CIDRS
            .iter()
            .map(|cidr| cidr.parse::<IpNet>())
            .collect::<Result<Vec<_>, _>>()?;
        let mut nat64_prefixes = DEFAULT_NAT64_PREFIXES
            .iter()
            .map(|prefix| prefix.parse::<Ipv6Net>())
            .collect::<Result<Vec<_>, _>>()?;
        for prefix in configured_nat64_prefixes {
            if !nat64_prefixes.contains(&prefix) {
                nat64_prefixes.push(prefix);
            }
        }
        // Prefer the most specific match when operators configure overlapping
        // network-specific prefixes.
        nat64_prefixes.sort_by_key(|prefix| std::cmp::Reverse(prefix.prefix_len()));
        let local_ips = local_ips
            .into_iter()
            .map(|ip| normalize_ip(ip, &nat64_prefixes))
            .collect();
        Ok(Self {
            allowed,
            denied,
            local_ips: RwLock::new(local_ips),
            listener_addrs,
            nat64_prefixes,
            local_address_source,
            refresh_slot: Arc::new(Semaphore::new(1)),
        })
    }

    /// Refresh the local-interface snapshot through the shared blocking-work gate.
    ///
    /// Only one interface enumeration can be running or queued per policy. The
    /// gate permit moves into the blocking closure, so a caller timing out does
    /// not release capacity until that closure really exits.
    ///
    /// # Errors
    ///
    /// Returns an error on deadline expiry, task failure, or interface
    /// enumeration failure.
    pub async fn refresh_local_addresses(
        self: &Arc<Self>,
        deadline: Duration,
    ) -> Result<(), PolicyRefreshError> {
        let started = Instant::now();
        let permit = timeout(deadline, Arc::clone(&self.refresh_slot).acquire_owned())
            .await
            .map_err(|_| PolicyRefreshError::Timeout)?
            .map_err(|_| PolicyRefreshError::Closed)?;
        let remaining = deadline.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(PolicyRefreshError::Timeout);
        }

        let policy = Arc::clone(self);
        let refresh = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            policy.refresh_local_addresses_now()
        });
        timeout(remaining, refresh)
            .await
            .map_err(|_| PolicyRefreshError::Timeout)???;
        Ok(())
    }

    fn refresh_local_addresses_now(&self) -> Result<(), PolicyBuildError> {
        let refreshed = self
            .local_address_source
            .enumerate()?
            .into_iter()
            .map(|ip| normalize_ip(ip, &self.nat64_prefixes))
            .collect();
        let mut local_ips = self
            .local_ips
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *local_ips = refreshed;
        Ok(())
    }

    /// Check one resolved address immediately before an upstream connection.
    ///
    /// # Errors
    ///
    /// Returns [`AddressDenied`] for proxy loops, local interfaces, and
    /// non-public ranges that do not have an explicit allow-list exception.
    pub fn check(&self, ip: IpAddr, port: u16) -> Result<(), AddressDenied> {
        let original_ip = normalize_ipv4_mapped(ip);
        let ip = normalize_ip(original_ip, &self.nat64_prefixes);
        let local_ips = self
            .local_ips
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.is_listener_target(ip, port, &local_ips) {
            return Err(AddressDenied::ProxyLoop(ip, port));
        }
        if self
            .allowed
            .iter()
            .any(|network| network.contains(&original_ip) || network.contains(&ip))
        {
            return Ok(());
        }
        if local_ips.contains(&ip) {
            return Err(AddressDenied::LocalInterface(ip));
        }
        if self.denied.iter().any(|network| network.contains(&ip)) {
            return Err(AddressDenied::Reserved(ip));
        }
        Ok(())
    }

    #[must_use]
    pub fn resolver_denied_networks(&self) -> Vec<IpNet> {
        self.denied.clone()
    }

    #[must_use]
    pub fn resolver_allowed_networks(&self) -> Vec<IpNet> {
        self.allowed.clone()
    }

    /// Return whether a trusted DNS endpoint can loop into a proxy listener.
    ///
    /// Wildcard listeners conflict when the endpoint currently belongs to a
    /// local interface and uses the same port.
    #[must_use]
    pub fn dns_endpoint_conflicts(&self, endpoint: SocketAddr) -> bool {
        let endpoint_ip = normalize_ip(endpoint.ip(), &self.nat64_prefixes);
        let local_ips = self
            .local_ips
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.is_listener_target(endpoint_ip, endpoint.port(), &local_ips)
    }

    fn is_listener_target(&self, ip: IpAddr, port: u16, local_ips: &HashSet<IpAddr>) -> bool {
        self.listener_addrs.iter().any(|listener| {
            if listener.port() != port {
                return false;
            }
            let listener_ip = normalize_ip(listener.ip(), &self.nat64_prefixes);
            listener_ip == ip || (listener_ip.is_unspecified() && local_ips.contains(&ip))
        })
    }
}

fn normalize_ipv4_mapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => {
            if let Some(ipv4) = ip.to_ipv4_mapped() {
                return IpAddr::V4(ipv4);
            }
            IpAddr::V6(ip)
        }
        IpAddr::V4(_) => ip,
    }
}

fn normalize_ip(ip: IpAddr, nat64_prefixes: &[Ipv6Net]) -> IpAddr {
    let ip = normalize_ipv4_mapped(ip);
    let IpAddr::V6(ipv6) = ip else {
        return ip;
    };
    nat64_prefixes
        .iter()
        .find_map(|prefix| decode_nat64(ipv6, *prefix))
        .map_or(IpAddr::V6(ipv6), IpAddr::V4)
}

fn decode_nat64(address: Ipv6Addr, prefix: Ipv6Net) -> Option<Ipv4Addr> {
    if !prefix.contains(&address) {
        return None;
    }

    let octets = address.octets();
    let prefix_len = usize::from(prefix.prefix_len());
    let mut ipv4 = [0_u8; 4];
    if prefix_len == 96 {
        ipv4.copy_from_slice(&octets[12..16]);
    } else {
        let before_reserved_octet = (64 - prefix_len) / 8;
        let prefix_bytes = prefix_len / 8;
        ipv4[..before_reserved_octet]
            .copy_from_slice(&octets[prefix_bytes..prefix_bytes + before_reserved_octet]);
        let remaining = 4 - before_reserved_octet;
        ipv4[before_reserved_octet..].copy_from_slice(&octets[9..9 + remaining]);
    }
    Some(Ipv4Addr::from(ipv4))
}

fn enumerate_local_ips() -> Result<HashSet<IpAddr>, std::io::Error> {
    Ok(if_addrs::get_if_addrs()?
        .into_iter()
        .map(|interface| normalize_ipv4_mapped(interface.ip()))
        .collect())
}

#[derive(Debug, Error)]
pub enum PolicyBuildError {
    #[error("failed to enumerate local network interfaces: {0}")]
    Interfaces(#[from] std::io::Error),
    #[error("internal invalid denied CIDR: {0}")]
    InvalidCidr(#[from] ipnet::AddrParseError),
}

#[derive(Debug, Error)]
pub enum PolicyRefreshError {
    #[error("local-address refresh exceeded its deadline")]
    Timeout,
    #[error("local-address refresh boundary is closed")]
    Closed,
    #[error("local-address refresh task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
    #[error("local-address refresh failed: {0}")]
    Build(#[from] PolicyBuildError),
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AddressDenied {
    #[error("address {0} is on a local interface")]
    LocalInterface(IpAddr),
    #[error("address {0} is non-public or reserved")]
    Reserved(IpAddr),
    #[error("address {0}:{1} would connect back to this proxy")]
    ProxyLoop(IpAddr, u16),
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::{
            Arc, Condvar, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use tokio::{sync::Notify, task::JoinSet, time::timeout};

    use super::*;

    fn policy(allowed: &[&str]) -> AddressPolicy {
        AddressPolicy::from_parts(
            vec![SocketAddr::from((Ipv4Addr::UNSPECIFIED, 443))],
            allowed.iter().map(|cidr| cidr.parse().unwrap()).collect(),
            HashSet::from([
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            ]),
        )
        .unwrap()
    }

    #[test]
    fn blocks_special_and_local_addresses_by_default() {
        let policy = policy(&[]);
        assert!(policy.check("10.0.0.1".parse().unwrap(), 443).is_err());
        assert!(policy.check("192.0.2.10".parse().unwrap(), 8443).is_err());
        assert!(policy.check("1.1.1.1".parse().unwrap(), 443).is_ok());
    }

    #[test]
    fn explicit_allow_does_not_override_proxy_loop_guard() {
        let policy = policy(&["127.0.0.0/8"]);
        assert!(policy.check("127.0.0.2".parse().unwrap(), 8443).is_ok());
        assert_eq!(
            policy.check("127.0.0.1".parse().unwrap(), 443),
            Err(AddressDenied::ProxyLoop("127.0.0.1".parse().unwrap(), 443))
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_cannot_bypass_policy() {
        let policy = policy(&[]);
        assert!(
            policy
                .check("::ffff:127.0.0.1".parse().unwrap(), 443)
                .is_err()
        );
    }

    #[test]
    fn well_known_nat64_cannot_bypass_ipv4_policy() {
        let policy = policy(&[]);
        assert!(
            policy
                .check("64:ff9b::7f00:1".parse().unwrap(), 443)
                .is_err()
        );
        assert!(
            policy
                .check("64:ff9b::a9fe:a9fe".parse().unwrap(), 443)
                .is_err()
        );
    }

    #[test]
    fn every_rfc_6052_prefix_length_decodes_before_policy_check() {
        for prefix in [
            "2001:4860::/32",
            "2001:4860:1200::/40",
            "2001:4860:1234::/48",
            "2001:4860:1234:5600::/56",
            "2001:4860:1234:5678::/64",
            "2001:4860:1234:5678:90ab:cdef::/96",
        ] {
            let prefix: Ipv6Net = prefix.parse().unwrap();
            let policy = AddressPolicy::from_parts_with_nat64(
                vec![SocketAddr::from((Ipv4Addr::UNSPECIFIED, 443))],
                Vec::new(),
                HashSet::new(),
                vec![prefix],
            )
            .unwrap();
            let metadata = synthesize_nat64(prefix, Ipv4Addr::new(169, 254, 169, 254));
            assert!(
                policy.check(IpAddr::V6(metadata), 443).is_err(),
                "prefix {prefix} must not hide a blocked IPv4 address"
            );
            let public = synthesize_nat64(prefix, Ipv4Addr::new(1, 1, 1, 1));
            assert!(
                policy.check(IpAddr::V6(public), 443).is_ok(),
                "prefix {prefix} must preserve a public IPv4 destination"
            );
        }
    }

    #[test]
    fn rfc_8215_local_use_nat64_cannot_bypass_ipv4_policy() {
        let policy = policy(&[]);
        let prefix: Ipv6Net = "64:ff9b:1::/48".parse().unwrap();
        let address = synthesize_nat64(prefix, Ipv4Addr::LOCALHOST);
        assert!(policy.check(IpAddr::V6(address), 8443).is_err());
    }

    #[test]
    fn ipv4_allow_rule_applies_to_configured_nat64_destination() {
        let prefix: Ipv6Net = "2001:4860:1234:5678::/64".parse().unwrap();
        let policy = AddressPolicy::from_parts_with_nat64(
            vec![SocketAddr::from((Ipv4Addr::UNSPECIFIED, 443))],
            vec!["10.0.0.0/8".parse().unwrap()],
            HashSet::new(),
            vec![prefix],
        )
        .unwrap();
        let address = synthesize_nat64(prefix, Ipv4Addr::new(10, 20, 30, 40));
        assert!(policy.check(IpAddr::V6(address), 8443).is_ok());
    }

    #[test]
    fn refreshed_interface_is_protected_by_wildcard_listener() {
        let policy = policy(&["198.51.100.0/24"]);
        {
            let mut local_ips = policy.local_ips.write().unwrap();
            local_ips.insert("198.51.100.20".parse().unwrap());
        }
        assert!(matches!(
            policy.check("198.51.100.20".parse().unwrap(), 443),
            Err(AddressDenied::ProxyLoop(_, 443))
        ));
    }

    #[test]
    fn wildcard_listener_only_conflicts_with_local_dns_endpoint() {
        let policy = policy(&[]);
        assert!(policy.dns_endpoint_conflicts("127.0.0.1:443".parse().unwrap()));
        assert!(!policy.dns_endpoint_conflicts("1.1.1.1:443".parse().unwrap()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stalled_refresh_holds_the_gate_after_caller_timeout_and_recovers() {
        struct ProviderState {
            starts: AtomicUsize,
            started: Notify,
            released: Mutex<bool>,
            release_signal: Condvar,
        }

        struct ReleaseOnDrop(Arc<ProviderState>);

        impl Drop for ReleaseOnDrop {
            fn drop(&mut self) {
                *self
                    .0
                    .released
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
                self.0.release_signal.notify_all();
            }
        }

        let state = Arc::new(ProviderState {
            starts: AtomicUsize::new(0),
            started: Notify::new(),
            released: Mutex::new(false),
            release_signal: Condvar::new(),
        });
        let _release_on_drop = ReleaseOnDrop(Arc::clone(&state));
        let provider_state = Arc::clone(&state);
        let source = LocalAddressSource(Arc::new(move || {
            let invocation = provider_state.starts.fetch_add(1, Ordering::SeqCst);
            if invocation == 0 {
                provider_state.started.notify_one();
                let released = provider_state
                    .released
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                drop(
                    provider_state
                        .release_signal
                        .wait_while(released, |released| !*released)
                        .unwrap_or_else(std::sync::PoisonError::into_inner),
                );
            }
            Ok(HashSet::from(["8.8.4.4".parse().unwrap()]))
        }));
        let policy = Arc::new(
            AddressPolicy::from_parts_with_source(
                Vec::new(),
                Vec::new(),
                HashSet::new(),
                Vec::new(),
                source,
            )
            .unwrap(),
        );

        let first_started = state.started.notified();
        let first_policy = Arc::clone(&policy);
        let first = tokio::spawn(async move {
            first_policy
                .refresh_local_addresses(Duration::from_millis(100))
                .await
        });
        timeout(Duration::from_secs(1), first_started)
            .await
            .expect("first blocking refresh must start");
        assert!(matches!(
            first.await.expect("refresh caller must not panic"),
            Err(PolicyRefreshError::Timeout)
        ));

        let mut waiters = JoinSet::new();
        for _ in 0..8 {
            let waiter_policy = Arc::clone(&policy);
            waiters.spawn(async move {
                waiter_policy
                    .refresh_local_addresses(Duration::from_millis(20))
                    .await
            });
        }
        while let Some(result) = waiters.join_next().await {
            assert!(matches!(
                result.expect("refresh waiter must not panic"),
                Err(PolicyRefreshError::Timeout)
            ));
        }
        assert_eq!(state.starts.load(Ordering::SeqCst), 1);

        *state
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        state.release_signal.notify_all();
        policy
            .refresh_local_addresses(Duration::from_secs(1))
            .await
            .expect("refresh must recover after the stalled provider exits");

        assert_eq!(state.starts.load(Ordering::SeqCst), 2);
        assert_eq!(
            policy.check("8.8.4.4".parse().unwrap(), 443),
            Err(AddressDenied::LocalInterface("8.8.4.4".parse().unwrap()))
        );
    }

    fn synthesize_nat64(prefix: Ipv6Net, ipv4: Ipv4Addr) -> Ipv6Addr {
        let mut output = prefix.network().octets();
        let ipv4 = ipv4.octets();
        let prefix_len = usize::from(prefix.prefix_len());
        if prefix_len == 96 {
            output[12..16].copy_from_slice(&ipv4);
        } else {
            let before_reserved_octet = (64 - prefix_len) / 8;
            let prefix_bytes = prefix_len / 8;
            output[prefix_bytes..prefix_bytes + before_reserved_octet]
                .copy_from_slice(&ipv4[..before_reserved_octet]);
            output[8] = 0;
            output[9..9 + (4 - before_reserved_octet)]
                .copy_from_slice(&ipv4[before_reserved_octet..]);
        }
        Ipv6Addr::from(output)
    }
}
