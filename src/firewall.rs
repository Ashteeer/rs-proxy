//! Lifecycle-owned Netfilter rules for strict `IPset` source policies.
//!
//! Operator `hash:ip` sets remain read-only. RS-Proxy owns only chains with an
//! explicit marker and, for `first_response`, short-lived `hash:ip,port` sets.
//! Every command uses a trusted absolute path, bounded output, and a deadline.

use std::{
    cmp::Ordering as CmpOrdering,
    collections::{BinaryHeap, HashMap, HashSet},
    fs::{File, OpenOptions},
    io,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use fs2::FileExt;
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc},
    task::JoinHandle,
    time::{Instant as TokioInstant, sleep_until, timeout},
};

use crate::config::{IpSetConfig, IpSetNotFound, ListenerConfig, ListenerProtocol};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_STDOUT_BYTES: usize = 1024 * 1024;
const MAX_STDERR_BYTES: usize = 8 * 1024;
const OWNER_MARK: &str = "rs-proxy-owned-v1";
const CHAIN_PREFIX: &str = "RSPX_";
const FLOW_INPUT_PREFIX_V4: &str = "RSPX_FI4_";
const FLOW_INPUT_PREFIX_V6: &str = "RSPX_FI6_";
const FLOW_OUTPUT_PREFIX_V4: &str = "RSPX_FO4_";
const FLOW_OUTPUT_PREFIX_V6: &str = "RSPX_FO6_";
const FLOW_SET_PREFIX_V4: &str = "rspx_f4_";
const FLOW_SET_PREFIX_V6: &str = "rspx_f6_";
const FLOW_OWNER_SENTINEL_V4: &str = "255.255.255.255,tcp:1";
const FLOW_OWNER_SENTINEL_V6: &str = "ff02::1,tcp:1";
const MAX_FLOW_CAPACITY: usize = 1_000_000;
const IPTABLES_CANDIDATES: [&str; 2] = ["/usr/sbin/iptables", "/sbin/iptables"];
const IP6TABLES_CANDIDATES: [&str; 2] = ["/usr/sbin/ip6tables", "/sbin/ip6tables"];
const IPSET_CANDIDATES: [&str; 2] = ["/usr/sbin/ipset", "/sbin/ipset"];
const FIREWALL_RUNTIME_DIR: &str = "/run/rs-proxy";
const FIREWALL_LOCK_PATH: &str = "/run/rs-proxy/firewall.lock";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FirewallProtocol {
    Tcp,
    Udp,
}

impl FirewallProtocol {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl From<ListenerProtocol> for FirewallProtocol {
    fn from(value: ListenerProtocol) -> Self {
        match value {
            ListenerProtocol::Tcp => Self::Tcp,
            ListenerProtocol::Udp => Self::Udp,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Family {
    V4,
    V6,
}

impl Family {
    const fn base_input_chain(self) -> &'static str {
        match self {
            Self::V4 => "RSPX_BI4",
            Self::V6 => "RSPX_BI6",
        }
    }

    const fn base_output_chain(self) -> &'static str {
        match self {
            Self::V4 => "RSPX_BO4",
            Self::V6 => "RSPX_BO6",
        }
    }

    const fn saved_name(self) -> &'static str {
        match self {
            Self::V4 => "inet",
            Self::V6 => "inet6",
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FlowTargetKey {
    protocol: FirewallProtocol,
    listener: SocketAddr,
    client_family: Family,
}

#[derive(Debug)]
struct FlowSet {
    name: String,
}

#[derive(Debug)]
struct FlowCapacity {
    slots: Arc<Semaphore>,
    retention_tx: mpsc::Sender<RetainedPermit>,
}

impl FlowCapacity {
    fn new(capacity: usize) -> (Self, JoinHandle<()>) {
        let slots = Arc::new(Semaphore::new(capacity));
        let (retention_tx, retention_rx) = mpsc::channel(capacity);
        let reaper = tokio::spawn(reap_capacity_permits(retention_rx));
        (
            Self {
                slots,
                retention_tx,
            },
            reaper,
        )
    }

    fn reserve(
        &self,
        key: FlowTargetKey,
        set_name: String,
    ) -> Result<FirstResponseReservation, FirewallError> {
        let protocol = key.protocol;
        let listener = key.listener;
        let permit = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| FirewallError::FlowSetSaturated { protocol, listener })?;
        Ok(FirstResponseReservation {
            key,
            set_name,
            permit: Some(permit),
        })
    }

    async fn reserve_wait(
        &self,
        key: FlowTargetKey,
        set_name: String,
    ) -> Result<FirstResponseReservation, FirewallError> {
        let permit = Arc::clone(&self.slots)
            .acquire_owned()
            .await
            .map_err(|_| FirewallError::FlowCapacityUnavailable)?;
        Ok(FirstResponseReservation {
            key,
            set_name,
            permit: Some(permit),
        })
    }

    fn retain(
        &self,
        permit: OwnedSemaphorePermit,
        retention: Duration,
    ) -> Result<(), FirewallError> {
        self.retention_tx
            .try_send(RetainedPermit {
                release_at: TokioInstant::now() + retention,
                permit,
            })
            .map_err(|_| FirewallError::PermitReaperUnavailable)
    }
}

struct RetainedPermit {
    release_at: TokioInstant,
    permit: OwnedSemaphorePermit,
}

struct ScheduledPermit {
    release_at: TokioInstant,
    sequence: u64,
    _permit: OwnedSemaphorePermit,
}

impl PartialEq for ScheduledPermit {
    fn eq(&self, other: &Self) -> bool {
        self.release_at == other.release_at && self.sequence == other.sequence
    }
}

impl Eq for ScheduledPermit {}

impl PartialOrd for ScheduledPermit {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScheduledPermit {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        other
            .release_at
            .cmp(&self.release_at)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

#[derive(Debug)]
pub struct FirstResponseReservation {
    key: FlowTargetKey,
    set_name: String,
    permit: Option<OwnedSemaphorePermit>,
}

#[derive(Clone, Debug)]
struct EffectiveListener {
    origin: SocketAddr,
    address: SocketAddr,
    protocol: FirewallProtocol,
    family: Family,
}

#[derive(Debug)]
struct CommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Debug)]
pub struct KernelFirewall {
    ipset_command: PathBuf,
    iptables_v4: Option<PathBuf>,
    iptables_v6: Option<PathBuf>,
    flow_sets: HashMap<FlowTargetKey, FlowSet>,
    flow_capacity: FlowCapacity,
    flow_capacity_limit: usize,
    flow_timeout_secs: u64,
    command_lock: Mutex<()>,
    active: AtomicBool,
    capacity_reaper: JoinHandle<()>,
    _instance_lock: File,
}

impl Drop for KernelFirewall {
    fn drop(&mut self) {
        self.capacity_reaper.abort();
    }
}

impl KernelFirewall {
    /// Recover stale owned artifacts and install strict rules before listeners bind.
    ///
    /// Enabled `allow` installs no new rule but audits and removes stale owned
    /// artifacts in both available families. Other enabled modes fail startup
    /// closed if a required executable or rule operation is unavailable.
    ///
    /// # Errors
    ///
    /// Returns an error when strict policy cannot be represented safely, the
    /// lifecycle lock or trusted tools are unavailable, recovery finds foreign
    /// reserved artifacts, or a bounded kernel command fails.
    ///
    /// # Panics
    ///
    /// Panics if the setup-only firewall owner unexpectedly escapes before the
    /// initialized value is returned.
    pub async fn initialize(
        config: &IpSetConfig,
        listeners: &[ListenerConfig],
        idle_timeout: Duration,
        max_connections: usize,
    ) -> Result<Option<Arc<Self>>, FirewallError> {
        if !config.has_active_sets() {
            return Ok(None);
        }
        if !cfg!(target_os = "linux") {
            return Err(FirewallError::UnsupportedPlatform);
        }
        if max_connections == 0 {
            return Err(FirewallError::FlowCapacityZero);
        }
        if max_connections > MAX_FLOW_CAPACITY {
            return Err(FirewallError::FlowCapacityTooLarge(max_connections));
        }

        // `allow` installs no rules but still takes ownership of recovery when
        // filtering is enabled. Disabled startup intentionally remains free of
        // CAP_NET_ADMIN requirements and needs explicit operator cleanup.
        let effective = if config.not_found == IpSetNotFound::Allow {
            Vec::new()
        } else {
            // A wildcard IPv6 socket can be either IPv6-only or dual-stack. The
            // Tokio bind path does not expose that effective setting before the
            // firewall must be installed, so guessing here could either leave
            // IPv4 traffic unfiltered or filter an unrelated IPv4 listener.
            effective_listeners(listeners, config)?
        };
        let instance_lock = acquire_instance_lock()?;
        let needs_v4 = effective
            .iter()
            .any(|listener| listener.family == Family::V4);
        let needs_v6 = effective
            .iter()
            .any(|listener| listener.family == Family::V6);
        let ipset_command = locate_trusted(&IPSET_CANDIDATES, "ipset")?;
        // Recovery is deliberately broader than the current listener set: a
        // strict-to-allow or dual-to-single transition must not strand owned
        // artifacts in an otherwise available family.
        let iptables_v4 = locate_optional_trusted(&IPTABLES_CANDIDATES);
        let iptables_v6 = locate_optional_trusted(&IP6TABLES_CANDIDATES);
        if needs_v4 && iptables_v4.is_none() {
            return Err(FirewallError::TrustedExecutableNotFound { name: "iptables" });
        }
        if needs_v6 && iptables_v6.is_none() {
            return Err(FirewallError::TrustedExecutableNotFound { name: "ip6tables" });
        }
        let (flow_capacity, capacity_reaper) = FlowCapacity::new(max_connections);
        let firewall = Arc::new(Self {
            ipset_command,
            iptables_v4,
            iptables_v6,
            flow_sets: HashMap::new(),
            flow_capacity,
            flow_capacity_limit: max_connections,
            flow_timeout_secs: idle_timeout.as_secs().max(1),
            command_lock: Mutex::new(()),
            active: AtomicBool::new(false),
            capacity_reaper,
            _instance_lock: instance_lock,
        });

        let mut flow_sets = HashMap::new();
        let setup = async {
            for family in [Family::V4, Family::V6] {
                if firewall.command_for(family).is_some() {
                    firewall.recover_family(family).await?;
                }
            }
            for family in [Family::V4, Family::V6] {
                if effective.iter().any(|listener| listener.family == family) {
                    firewall
                        .create_base_chains(family, config.not_found)
                        .await?;
                }
            }
            for (index, listener) in effective.iter().enumerate() {
                let flow_set = firewall.install_listener(listener, index, config).await?;
                if let Some(flow_set) = flow_set {
                    flow_sets.insert(
                        FlowTargetKey {
                            protocol: listener.protocol,
                            listener: listener.origin,
                            client_family: listener.family,
                        },
                        FlowSet { name: flow_set },
                    );
                }
            }
            Ok::<(), FirewallError>(())
        }
        .await;

        if let Err(error) = setup {
            if let Err(cleanup) = firewall.cleanup_after_setup_failure().await {
                return Err(FirewallError::SetupCleanup {
                    setup: Box::new(error),
                    cleanup: Box::new(cleanup),
                });
            }
            return Err(error);
        }

        if effective.is_empty() {
            return Ok(None);
        }

        // No other task can observe the Arc before this point.
        let mut firewall = Arc::try_unwrap(firewall).expect("firewall setup has one owner");
        firewall.flow_sets = flow_sets;
        firewall.active.store(true, Ordering::Release);
        Ok(Some(Arc::new(firewall)))
    }

    /// Reserve capacity to activate a post-response `INPUT`/`OUTPUT` `DROP`.
    ///
    /// The listener protocol/address/port remains part of the static rule, so
    /// reusing the same client ephemeral port against another listener cannot
    /// collide. The entry expires at the configured relay idle timeout.
    ///
    /// # Errors
    ///
    /// Returns an error if the firewall is inactive, the listener/client-family
    /// flow set is absent, or its bounded reservation capacity is saturated.
    pub fn reserve_first_response(
        &self,
        protocol: FirewallProtocol,
        listener: SocketAddr,
        client: SocketAddr,
    ) -> Result<FirstResponseReservation, FirewallError> {
        let (key, set_name) = self.first_response_target(protocol, listener, client)?;
        self.flow_capacity.reserve(key, set_name)
    }

    /// Wait for global first-response capacity without writing to the accepted
    /// TCP socket. This turns churn saturation into silent backpressure until
    /// an earlier kernel tuple expires instead of closing the socket with a
    /// user-visible FIN/RST.
    ///
    /// # Errors
    ///
    /// Returns an error if the firewall is inactive, the listener/client-family
    /// flow set is absent, or the capacity semaphore unexpectedly closes.
    pub async fn reserve_first_response_wait(
        &self,
        protocol: FirewallProtocol,
        listener: SocketAddr,
        client: SocketAddr,
    ) -> Result<FirstResponseReservation, FirewallError> {
        let (key, set_name) = self.first_response_target(protocol, listener, client)?;
        let reservation = self.flow_capacity.reserve_wait(key, set_name).await?;
        if !self.active.load(Ordering::Acquire) {
            return Err(FirewallError::NotActive);
        }
        Ok(reservation)
    }

    /// Insert the reserved client tuple into its expiring kernel flow set.
    ///
    /// # Errors
    ///
    /// Returns an error if the firewall became inactive, the reservation does
    /// not match the supplied tuple, or the bounded `IPset` command fails.
    pub async fn block_flow_after_first_response(
        &self,
        protocol: FirewallProtocol,
        listener: SocketAddr,
        client: SocketAddr,
        mut reservation: FirstResponseReservation,
    ) -> Result<(), FirewallError> {
        if !self.active.load(Ordering::Acquire) {
            return Err(FirewallError::NotActive);
        }
        let client = normalize_socket(client);
        let key = FlowTargetKey {
            protocol,
            listener,
            client_family: family_of(client.ip()),
        };
        if reservation.key != key {
            return Err(FirewallError::ReservationMismatch);
        }
        let element = format!("{},{}:{}", client.ip(), protocol.as_str(), client.port());
        let args = vec![
            "-exist".to_owned(),
            "add".to_owned(),
            reservation.set_name.clone(),
            element,
            "timeout".to_owned(),
            self.flow_timeout_secs.to_string(),
        ];
        let _guard = self.command_lock.lock().await;
        if !self.active.load(Ordering::Acquire) {
            return Err(FirewallError::NotActive);
        }
        let activation = run_checked(&self.ipset_command, &args).await.map(|_| ());
        finish_first_response_activation(
            &self.flow_capacity,
            &mut reservation,
            Duration::from_secs(self.flow_timeout_secs),
            activation,
        )
    }

    /// Remove only marker-owned jumps, chains, and flow sets.
    ///
    /// # Errors
    ///
    /// Returns an error when artifact ownership cannot be authenticated or a
    /// bounded kernel cleanup command fails.
    pub async fn cleanup(&self) -> Result<(), FirewallError> {
        if !self.active.load(Ordering::Acquire) {
            return Ok(());
        }
        let _guard = self.command_lock.lock().await;
        let mut first_error = None;
        for family in [Family::V4, Family::V6] {
            if self.command_for(family).is_some()
                && let Err(error) = self.recover_family(family).await
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        self.active.store(false, Ordering::Release);
        Ok(())
    }

    fn command_for(&self, family: Family) -> Option<&Path> {
        match family {
            Family::V4 => self.iptables_v4.as_deref(),
            Family::V6 => self.iptables_v6.as_deref(),
        }
    }

    async fn cleanup_after_setup_failure(&self) -> Result<(), FirewallError> {
        let mut first_error = None;
        for family in [Family::V4, Family::V6] {
            if self.command_for(family).is_some()
                && let Err(error) = self.recover_family(family).await
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn first_response_target(
        &self,
        protocol: FirewallProtocol,
        listener: SocketAddr,
        client: SocketAddr,
    ) -> Result<(FlowTargetKey, String), FirewallError> {
        if !self.active.load(Ordering::Acquire) {
            return Err(FirewallError::NotActive);
        }
        let client = normalize_socket(client);
        let key = FlowTargetKey {
            protocol,
            listener,
            client_family: family_of(client.ip()),
        };
        let set_name = self
            .flow_sets
            .get(&key)
            .ok_or(FirewallError::MissingFlowSet {
                protocol,
                listener,
                family: key.client_family.saved_name(),
            })?
            .name
            .clone();
        Ok((key, set_name))
    }

    async fn create_base_chains(
        &self,
        family: Family,
        mode: IpSetNotFound,
    ) -> Result<(), FirewallError> {
        let command = self
            .command_for(family)
            .expect("family executable resolved");
        create_owned_chain(command, family.base_input_chain()).await?;
        add_owned_jump(command, "INPUT", family.base_input_chain()).await?;
        if mode == IpSetNotFound::FirstResponse {
            create_owned_chain(command, family.base_output_chain()).await?;
            add_owned_jump(command, "OUTPUT", family.base_output_chain()).await?;
        }
        Ok(())
    }

    async fn install_listener(
        &self,
        listener: &EffectiveListener,
        index: usize,
        config: &IpSetConfig,
    ) -> Result<Option<String>, FirewallError> {
        let command = self
            .command_for(listener.family)
            .expect("effective listener has a family executable");
        let hash = listener_hash(listener, index);
        match config.not_found {
            IpSetNotFound::Allow => Ok(None),
            IpSetNotFound::Silent | IpSetNotFound::Reject => {
                let chain = format!("RSPX_SI{}_{hash:016x}", family_digit(listener.family));
                create_owned_chain(command, &chain).await?;
                let action = terminal_action(listener.protocol, listener.family, config.not_found);
                insert_rule(command, &chain, action).await?;
                let operator_set = match listener.family {
                    Family::V4 => config.ipv4_set.as_deref(),
                    Family::V6 => config.ipv6_set.as_deref(),
                }
                .expect("effective listener has a configured source set");
                insert_rule(
                    command,
                    &chain,
                    vec![
                        "-m".into(),
                        "set".into(),
                        "--match-set".into(),
                        operator_set.into(),
                        "src".into(),
                        "-j".into(),
                        "RETURN".into(),
                    ],
                )
                .await?;
                insert_rule(
                    command,
                    listener.family.base_input_chain(),
                    listener_jump(listener, &chain, false),
                )
                .await?;
                Ok(None)
            }
            IpSetNotFound::FirstResponse => {
                let flow_set = flow_set_name(listener.family, hash);
                create_flow_set(
                    &self.ipset_command,
                    &flow_set,
                    listener.family,
                    self.flow_timeout_secs,
                    self.flow_capacity_limit,
                )
                .await?;
                let input_chain = flow_chain(listener.family, true, hash);
                let output_chain = flow_chain(listener.family, false, hash);
                create_owned_chain(command, &input_chain).await?;
                create_owned_chain(command, &output_chain).await?;
                insert_rule(
                    command,
                    &input_chain,
                    vec![
                        "-m".into(),
                        "set".into(),
                        "--match-set".into(),
                        flow_set.clone(),
                        "src,src".into(),
                        "-j".into(),
                        "DROP".into(),
                    ],
                )
                .await?;
                insert_rule(
                    command,
                    &output_chain,
                    vec![
                        "-m".into(),
                        "set".into(),
                        "--match-set".into(),
                        flow_set.clone(),
                        "dst,dst".into(),
                        "-j".into(),
                        "DROP".into(),
                    ],
                )
                .await?;
                insert_rule(
                    command,
                    listener.family.base_input_chain(),
                    listener_jump(listener, &input_chain, false),
                )
                .await?;
                insert_rule(
                    command,
                    listener.family.base_output_chain(),
                    listener_jump(listener, &output_chain, true),
                )
                .await?;
                Ok(Some(flow_set))
            }
        }
    }

    async fn recover_family(&self, family: Family) -> Result<(), FirewallError> {
        let command = self
            .command_for(family)
            .expect("family executable resolved");
        let output = run_checked(command, &["-S".into()]).await?;
        let rules = std::str::from_utf8(&output.stdout)
            .map_err(|_| FirewallError::NonUtf8Rules(command.to_path_buf()))?;
        let declared = declared_owned_namespace_chains(rules);
        let owned = marker_owned_chains(rules, &declared);
        let collisions = declared.difference(&owned).cloned().collect::<Vec<_>>();
        if !collisions.is_empty() {
            return Err(FirewallError::ForeignChainCollision(collisions));
        }

        // A crash can leave only the flow set (for example after chains were
        // removed but before `ipset destroy`). Enumerate the deterministic
        // namespace independently from iptables and require the in-set
        // ownership sentinel before mutating any matching set. Preflight every
        // collision before deleting a single rule or chain.
        let existing_sets = list_ipsets(&self.ipset_command).await?;
        let prefix = match family {
            Family::V4 => FLOW_SET_PREFIX_V4,
            Family::V6 => FLOW_SET_PREFIX_V6,
        };
        let mut flow_sets = HashSet::new();
        let mut set_collisions = Vec::new();
        for set_name in existing_sets
            .iter()
            .filter(|set_name| set_name.starts_with(prefix))
        {
            if flow_set_is_owned(&self.ipset_command, set_name, family).await? {
                flow_sets.insert(set_name.clone());
            } else {
                set_collisions.push(set_name.clone());
            }
        }
        if !set_collisions.is_empty() {
            set_collisions.sort();
            return Err(FirewallError::ForeignFlowSetCollision(set_collisions));
        }

        // A marker-owned input chain must never cause an unmarked or missing
        // set to be destroyed. Missing sets are harmless after a partial
        // cleanup; present sets were independently authenticated above.
        for referenced in owned
            .iter()
            .filter_map(|chain| flow_set_from_input_chain(chain))
        {
            if existing_sets.contains(&referenced) && !flow_sets.contains(&referenced) {
                return Err(FirewallError::ForeignFlowSetCollision(vec![referenced]));
            }
        }
        for line in rules.lines() {
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            if fields.len() >= 8
                && fields[0] == "-A"
                && matches!(fields[1], "INPUT" | "OUTPUT")
                && fields
                    .windows(2)
                    .any(|pair| pair == ["--comment", OWNER_MARK])
                && fields
                    .windows(2)
                    .any(|pair| pair[0] == "-j" && owned.contains(pair[1]))
            {
                let mut args = vec!["-D".to_owned(), fields[1].to_owned()];
                args.extend(fields[2..].iter().map(|field| (*field).to_owned()));
                run_checked(command, &args).await?;
            }
        }
        for chain in &owned {
            run_checked(command, &["-F".into(), chain.clone()]).await?;
        }
        // Listener chains first, bases last. Flushing removed all internal refs.
        let mut chains = owned.into_iter().collect::<Vec<_>>();
        chains.sort_by_key(|chain| chain.starts_with("RSPX_B"));
        for chain in chains {
            run_checked(command, &["-X".into(), chain]).await?;
        }
        for set_name in flow_sets {
            run_checked(&self.ipset_command, &["destroy".into(), set_name]).await?;
        }
        Ok(())
    }
}

async fn reap_capacity_permits(mut receiver: mpsc::Receiver<RetainedPermit>) {
    let mut scheduled = BinaryHeap::<ScheduledPermit>::new();
    let mut sequence = 0_u64;
    loop {
        let now = TokioInstant::now();
        while scheduled
            .peek()
            .is_some_and(|entry| entry.release_at <= now)
        {
            scheduled.pop();
        }

        let Some(next_release) = scheduled.peek().map(|entry| entry.release_at) else {
            let Some(retained) = receiver.recv().await else {
                break;
            };
            scheduled.push(ScheduledPermit {
                release_at: retained.release_at,
                sequence,
                _permit: retained.permit,
            });
            sequence = sequence.wrapping_add(1);
            continue;
        };

        tokio::select! {
            retained = receiver.recv() => {
                let Some(retained) = retained else {
                    break;
                };
                scheduled.push(ScheduledPermit {
                    release_at: retained.release_at,
                    sequence,
                    _permit: retained.permit,
                });
                sequence = sequence.wrapping_add(1);
            }
            () = sleep_until(next_release) => {}
        }
    }
}

fn finish_first_response_activation(
    capacity: &FlowCapacity,
    reservation: &mut FirstResponseReservation,
    retention: Duration,
    activation: Result<(), FirewallError>,
) -> Result<(), FirewallError> {
    let permit = reservation
        .permit
        .take()
        .ok_or(FirewallError::ReservationMismatch)?;
    // A delivered response consumes global churn capacity even when the later
    // kernel insertion fails. UDP has already recorded its userspace tombstone;
    // releasing this permit early would let unique tuples grow that map without
    // the configured global bound.
    capacity.retain(permit, retention)?;
    activation
}

fn effective_listeners(
    listeners: &[ListenerConfig],
    config: &IpSetConfig,
) -> Result<Vec<EffectiveListener>, FirewallError> {
    let mut effective = Vec::new();
    for listener in listeners {
        if !config.applies_to_listener(listener.listen.ip()) {
            continue;
        }
        if let IpAddr::V6(address) = listener.listen.ip()
            && address.to_ipv4_mapped().is_some()
        {
            return Err(FirewallError::AmbiguousMappedIpv6Listener(listener.listen));
        }
        if listener.listen.is_ipv6() && listener.listen.ip().is_unspecified() {
            return Err(FirewallError::AmbiguousWildcardIpv6Listener(
                listener.listen,
            ));
        }
        let protocol = listener.protocol.into();
        let family = family_of(listener.listen.ip());
        effective.push(EffectiveListener {
            origin: listener.listen,
            address: listener.listen,
            protocol,
            family,
        });
    }
    Ok(effective)
}

const fn family_of(address: IpAddr) -> Family {
    match address {
        IpAddr::V4(_) => Family::V4,
        IpAddr::V6(_) => Family::V6,
    }
}

fn normalize_socket(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(address_v6) => address_v6.ip().to_ipv4_mapped().map_or(address, |ipv4| {
            SocketAddr::new(IpAddr::V4(ipv4), address.port())
        }),
        SocketAddr::V4(_) => address,
    }
}

const fn family_digit(family: Family) -> char {
    match family {
        Family::V4 => '4',
        Family::V6 => '6',
    }
}

fn listener_hash(listener: &EffectiveListener, index: usize) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in format!(
        "{}|{}|{}|{}|{index}",
        listener.protocol.as_str(),
        listener.origin,
        listener.address,
        family_digit(listener.family)
    )
    .bytes()
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn flow_chain(family: Family, input: bool, hash: u64) -> String {
    let prefix = match (family, input) {
        (Family::V4, true) => FLOW_INPUT_PREFIX_V4,
        (Family::V6, true) => FLOW_INPUT_PREFIX_V6,
        (Family::V4, false) => FLOW_OUTPUT_PREFIX_V4,
        (Family::V6, false) => FLOW_OUTPUT_PREFIX_V6,
    };
    format!("{prefix}{hash:016x}")
}

fn flow_set_name(family: Family, hash: u64) -> String {
    let prefix = match family {
        Family::V4 => FLOW_SET_PREFIX_V4,
        Family::V6 => FLOW_SET_PREFIX_V6,
    };
    format!("{prefix}{hash:016x}")
}

fn flow_set_from_input_chain(chain: &str) -> Option<String> {
    chain
        .strip_prefix(FLOW_INPUT_PREFIX_V4)
        .map(|suffix| format!("{FLOW_SET_PREFIX_V4}{suffix}"))
        .or_else(|| {
            chain
                .strip_prefix(FLOW_INPUT_PREFIX_V6)
                .map(|suffix| format!("{FLOW_SET_PREFIX_V6}{suffix}"))
        })
}

fn listener_jump(listener: &EffectiveListener, target: &str, reverse: bool) -> Vec<String> {
    let mut rule = vec!["-p".into(), listener.protocol.as_str().into()];
    if !listener.address.ip().is_unspecified() {
        rule.push(if reverse { "-s" } else { "-d" }.into());
        rule.push(listener.address.ip().to_string());
    }
    rule.push(if reverse { "--sport" } else { "--dport" }.into());
    rule.push(listener.address.port().to_string());
    rule.extend(["-j".into(), target.into()]);
    rule
}

fn terminal_action(protocol: FirewallProtocol, family: Family, mode: IpSetNotFound) -> Vec<String> {
    match mode {
        IpSetNotFound::Silent => vec!["-j".into(), "DROP".into()],
        IpSetNotFound::Reject => match protocol {
            FirewallProtocol::Tcp => vec![
                "-p".into(),
                "tcp".into(),
                "-j".into(),
                "REJECT".into(),
                "--reject-with".into(),
                "tcp-reset".into(),
            ],
            FirewallProtocol::Udp => vec![
                "-p".into(),
                "udp".into(),
                "-j".into(),
                "REJECT".into(),
                "--reject-with".into(),
                match family {
                    Family::V4 => "icmp-port-unreachable",
                    Family::V6 => "icmp6-port-unreachable",
                }
                .into(),
            ],
        },
        IpSetNotFound::Allow | IpSetNotFound::FirstResponse => unreachable!(),
    }
}

async fn create_owned_chain(command: &Path, chain: &str) -> Result<(), FirewallError> {
    run_checked(command, &["-N".into(), chain.into()]).await?;
    let marker = run_checked(
        command,
        &[
            "-A".into(),
            chain.into(),
            "-m".into(),
            "comment".into(),
            "--comment".into(),
            OWNER_MARK.into(),
            "-j".into(),
            "RETURN".into(),
        ],
    )
    .await;
    if let Err(marker_error) = marker {
        if let Err(rollback_error) = run_checked(command, &["-X".into(), chain.into()]).await {
            return Err(FirewallError::ChainMarkerRollback {
                chain: chain.to_owned(),
                marker: Box::new(marker_error),
                rollback: Box::new(rollback_error),
            });
        }
        return Err(marker_error);
    }
    Ok(())
}

async fn add_owned_jump(command: &Path, builtin: &str, chain: &str) -> Result<(), FirewallError> {
    run_checked(
        command,
        &[
            "-I".into(),
            builtin.into(),
            "1".into(),
            "-m".into(),
            "comment".into(),
            "--comment".into(),
            OWNER_MARK.into(),
            "-j".into(),
            chain.into(),
        ],
    )
    .await?;
    Ok(())
}

async fn insert_rule(
    command: &Path,
    chain: &str,
    mut rule: Vec<String>,
) -> Result<(), FirewallError> {
    let mut args = vec!["-I".into(), chain.into(), "1".into()];
    args.append(&mut rule);
    run_checked(command, &args).await?;
    Ok(())
}

async fn create_flow_set(
    command: &Path,
    name: &str,
    family: Family,
    timeout_secs: u64,
    capacity: usize,
) -> Result<(), FirewallError> {
    run_checked(
        command,
        &[
            "create".into(),
            name.into(),
            "hash:ip,port".into(),
            "family".into(),
            family.saved_name().into(),
            "timeout".into(),
            timeout_secs.to_string(),
            "maxelem".into(),
            (capacity + 1).to_string(),
            "comment".into(),
        ],
    )
    .await?;
    let sentinel = match family {
        Family::V4 => FLOW_OWNER_SENTINEL_V4,
        Family::V6 => FLOW_OWNER_SENTINEL_V6,
    };
    let marker = run_checked(
        command,
        &[
            "add".into(),
            name.into(),
            sentinel.into(),
            "timeout".into(),
            "0".into(),
            "comment".into(),
            OWNER_MARK.into(),
        ],
    )
    .await;
    if let Err(marker_error) = marker {
        if let Err(rollback_error) = run_checked(command, &["destroy".into(), name.into()]).await {
            return Err(FirewallError::FlowSetMarkerRollback {
                set: name.to_owned(),
                marker: Box::new(marker_error),
                rollback: Box::new(rollback_error),
            });
        }
        return Err(marker_error);
    }
    Ok(())
}

async fn flow_set_is_owned(
    command: &Path,
    name: &str,
    family: Family,
) -> Result<bool, FirewallError> {
    // `save` is proportional to the number of live tuples and can exceed the
    // bounded command-output budget. Terse metadata plus one lifecycle-only
    // sentinel lookup is O(1); traffic admission never shells out per packet.
    let output = run_checked(command, &["list".into(), name.into(), "-terse".into()]).await?;
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| FirewallError::NonUtf8Rules(command.to_path_buf()))?;
    let expected_sentinel = match family {
        Family::V4 => FLOW_OWNER_SENTINEL_V4,
        Family::V6 => FLOW_OWNER_SENTINEL_V6,
    };
    let valid_type = text.lines().any(|line| line == "Type: hash:ip,port");
    let valid_header = text.lines().any(|line| {
        let Some(header) = line.strip_prefix("Header: ") else {
            return false;
        };
        let fields = header.split_ascii_whitespace().collect::<Vec<_>>();
        fields
            .windows(2)
            .any(|pair| pair == ["family", family.saved_name()])
            && fields.contains(&"comment")
            && flow_set_maxelem_is_valid(&fields)
    });
    if !valid_type || !valid_header {
        return Ok(false);
    }
    let sentinel = run_bounded(
        command,
        &["test".into(), name.into(), expected_sentinel.into()],
    )
    .await?;
    Ok(sentinel.status.success())
}

fn declared_owned_namespace_chains(rules: &str) -> HashSet<String> {
    rules
        .lines()
        .filter_map(|line| line.strip_prefix("-N "))
        .filter(|chain| chain.starts_with(CHAIN_PREFIX))
        .map(str::to_owned)
        .collect()
}

fn marker_owned_chains(rules: &str, declared: &HashSet<String>) -> HashSet<String> {
    rules
        .lines()
        .filter_map(|line| {
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            (fields.len() == 8
                && fields[0] == "-A"
                && declared.contains(fields[1])
                && fields[2..] == ["-m", "comment", "--comment", OWNER_MARK, "-j", "RETURN"])
            .then(|| fields[1].to_owned())
        })
        .collect()
}

fn flow_set_maxelem_is_valid(fields: &[&str]) -> bool {
    fields.windows(2).any(|pair| {
        pair[0] == "maxelem"
            && pair[1]
                .parse::<usize>()
                .is_ok_and(|value| (2..=MAX_FLOW_CAPACITY + 1).contains(&value))
    })
}

async fn list_ipsets(command: &Path) -> Result<HashSet<String>, FirewallError> {
    let output = run_checked(command, &["list".into(), "-name".into()]).await?;
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| FirewallError::NonUtf8Rules(command.to_path_buf()))?;
    Ok(text.lines().map(str::to_owned).collect())
}

fn locate_trusted(candidates: &[&str], name: &'static str) -> Result<PathBuf, FirewallError> {
    locate_optional_trusted(candidates).ok_or(FirewallError::TrustedExecutableNotFound { name })
}

fn locate_optional_trusted(candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .map(Path::new)
        .find(|path| is_executable_file(path))
        .map(Path::to_path_buf)
}

fn acquire_instance_lock() -> Result<File, FirewallError> {
    acquire_instance_lock_at(
        Path::new(FIREWALL_RUNTIME_DIR),
        Path::new(FIREWALL_LOCK_PATH),
    )
}

fn acquire_instance_lock_at(directory: &Path, path: &Path) -> Result<File, FirewallError> {
    std::fs::create_dir_all(directory).map_err(|source| FirewallError::InstanceLock {
        path: path.to_path_buf(),
        source,
    })?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(target_os = "linux")]
    options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    let file = options
        .open(path)
        .map_err(|source| FirewallError::InstanceLock {
            path: path.to_path_buf(),
            source,
        })?;
    FileExt::try_lock_exclusive(&file).map_err(|source| FirewallError::InstanceLock {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(file)
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

async fn run_checked(command: &Path, args: &[String]) -> Result<CommandOutput, FirewallError> {
    let mut prefixed = Vec::new();
    if command.ends_with("iptables") || command.ends_with("ip6tables") {
        prefixed.extend(["--wait".to_owned(), "2".to_owned()]);
    }
    prefixed.extend_from_slice(args);
    let output = run_bounded(command, &prefixed).await?;
    if !output.status.success() {
        return Err(FirewallError::CommandFailed {
            command: command.to_path_buf(),
            args: prefixed,
            status: output.status.code(),
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(output)
}

async fn run_bounded(command: &Path, args: &[String]) -> Result<CommandOutput, FirewallError> {
    let mut child = Command::new(command)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|source| FirewallError::CommandStart {
            command: command.to_path_buf(),
            source,
        })?;
    let stdout = child
        .stdout
        .take()
        .ok_or(FirewallError::MissingCommandPipe)?;
    let stderr = child
        .stderr
        .take()
        .ok_or(FirewallError::MissingCommandPipe)?;
    timeout(COMMAND_TIMEOUT, async {
        let stdout = read_bounded(stdout, MAX_STDOUT_BYTES);
        let stderr = read_bounded(stderr, MAX_STDERR_BYTES);
        let wait = child.wait();
        let (stdout, stderr, status) = tokio::try_join!(stdout, stderr, wait)?;
        Ok(CommandOutput {
            status,
            stdout,
            stderr,
        })
    })
    .await
    .map_err(|_| FirewallError::CommandTimeout {
        command: command.to_path_buf(),
    })?
}

async fn read_bounded<R>(reader: R, limit: usize) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let read_limit = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let mut reader = reader.take(read_limit);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).await?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "firewall command output exceeded its safety limit",
        ));
    }
    Ok(bytes)
}

#[derive(Debug, Error)]
pub enum FirewallError {
    #[error("kernel firewall integration is supported only on Linux")]
    UnsupportedPlatform,
    #[error(
        "strict IPset firewall policy cannot safely infer whether wildcard IPv6 listener {0} is IPv6-only or dual-stack; configure explicit IPv4 and IPv6 listener addresses"
    )]
    AmbiguousWildcardIpv6Listener(SocketAddr),
    #[error(
        "strict IPset firewall policy cannot safely classify IPv4-mapped IPv6 listener {0}; configure its explicit IPv4 address"
    )]
    AmbiguousMappedIpv6Listener(SocketAddr),
    #[error("cannot acquire the exclusive firewall lifecycle lock {path}: {source}")]
    InstanceLock {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("trusted {name} executable is unavailable under /usr/sbin or /sbin")]
    TrustedExecutableNotFound { name: &'static str },
    #[error("failed to start firewall command {command}: {source}")]
    CommandStart {
        command: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("firewall command did not expose stdout/stderr")]
    MissingCommandPipe,
    #[error("firewall command {command} timed out")]
    CommandTimeout { command: PathBuf },
    #[error("firewall command {command} {args:?} failed with status {status:?}: {detail}")]
    CommandFailed {
        command: PathBuf,
        args: Vec<String>,
        status: Option<i32>,
        detail: String,
    },
    #[error(
        "failed to mark new owned chain {chain} ({marker}) and failed to roll it back ({rollback})"
    )]
    ChainMarkerRollback {
        chain: String,
        marker: Box<FirewallError>,
        rollback: Box<FirewallError>,
    },
    #[error(
        "failed to mark new owned flow set {set} ({marker}) and failed to roll it back ({rollback})"
    )]
    FlowSetMarkerRollback {
        set: String,
        marker: Box<FirewallError>,
        rollback: Box<FirewallError>,
    },
    #[error("firewall setup failed ({setup}) and owned-artifact cleanup also failed ({cleanup})")]
    SetupCleanup {
        setup: Box<FirewallError>,
        cleanup: Box<FirewallError>,
    },
    #[error("firewall command I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("firewall rules from {0} were not UTF-8")]
    NonUtf8Rules(PathBuf),
    #[error("reserved firewall chain collision without an RS-Proxy ownership marker: {0:?}")]
    ForeignChainCollision(Vec<String>),
    #[error(
        "reserved first-response flow-set collision without an RS-Proxy ownership marker: {0:?}"
    )]
    ForeignFlowSetCollision(Vec<String>),
    #[error(
        "server.max_connections {0} exceeds the first-response kernel flow capacity of 1000000"
    )]
    FlowCapacityTooLarge(usize),
    #[error("server.max_connections must be greater than zero for enabled IPset filtering")]
    FlowCapacityZero,
    #[error("kernel firewall is no longer active")]
    NotActive,
    #[error(
        "first-response kernel flow capacity is saturated for {protocol:?} listener {listener}"
    )]
    FlowSetSaturated {
        protocol: FirewallProtocol,
        listener: SocketAddr,
    },
    #[error("first-response capacity reaper stopped unexpectedly")]
    PermitReaperUnavailable,
    #[error("first-response capacity semaphore closed unexpectedly")]
    FlowCapacityUnavailable,
    #[error("first-response flow reservation does not match the listener/client tuple")]
    ReservationMismatch,
    #[error(
        "missing first-response flow set for {protocol:?} listener {listener} and client family {family}"
    )]
    MissingFlowSet {
        protocol: FirewallProtocol,
        listener: SocketAddr,
        family: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_ipv6_listener_is_rejected_instead_of_guessing_its_families() {
        let listeners = [ListenerConfig {
            protocol: ListenerProtocol::Tcp,
            listen: "[::]:443".parse().unwrap(),
        }];
        let config = IpSetConfig {
            enabled: true,
            ipv4_set: Some("clients_v4".into()),
            ..IpSetConfig::default()
        };
        let error = effective_listeners(&listeners, &config).unwrap_err();
        assert!(matches!(
            error,
            FirewallError::AmbiguousWildcardIpv6Listener(address)
                if address == "[::]:443".parse().unwrap()
        ));
    }

    #[test]
    fn mapped_ipv6_listener_is_rejected_instead_of_bypassing_ipv4_netfilter() {
        let listeners = [ListenerConfig {
            protocol: ListenerProtocol::Udp,
            listen: "[::ffff:127.0.0.1]:443".parse().unwrap(),
        }];
        let config = IpSetConfig {
            enabled: true,
            ipv4_set: Some("clients_v4".into()),
            ..IpSetConfig::default()
        };
        let error = effective_listeners(&listeners, &config).unwrap_err();
        assert!(matches!(
            error,
            FirewallError::AmbiguousMappedIpv6Listener(address)
                if address == "[::ffff:127.0.0.1]:443".parse().unwrap()
        ));
    }

    #[tokio::test]
    async fn disabled_filtering_does_not_require_firewall_recovery_privileges() {
        let listeners = [ListenerConfig {
            protocol: ListenerProtocol::Tcp,
            listen: "[::]:443".parse().unwrap(),
        }];

        for config in [
            IpSetConfig {
                ipv4_set: Some("unused_v4".into()),
                ..IpSetConfig::default()
            },
            IpSetConfig {
                enabled: true,
                ..IpSetConfig::default()
            },
        ] {
            assert!(
                KernelFirewall::initialize(&config, &listeners, Duration::ZERO, 0)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn flow_set_recovery_is_derived_only_from_owned_input_chain_names() {
        assert_eq!(
            flow_set_from_input_chain("RSPX_FI4_0123456789abcdef"),
            Some("rspx_f4_0123456789abcdef".into())
        );
        assert_eq!(flow_set_from_input_chain("RSPX_BI4"), None);
        assert_eq!(flow_set_from_input_chain("FOREIGN_FI4_0123"), None);
    }

    #[tokio::test]
    async fn global_flow_capacity_uses_one_reaper_and_recovers() {
        let (capacity, reaper) = FlowCapacity::new(1);
        let first_key = FlowTargetKey {
            protocol: FirewallProtocol::Udp,
            listener: "127.0.0.1:443".parse().unwrap(),
            client_family: Family::V4,
        };
        let second_key = FlowTargetKey {
            protocol: FirewallProtocol::Tcp,
            listener: "[::1]:8443".parse().unwrap(),
            client_family: Family::V6,
        };

        let first = capacity
            .reserve(first_key.clone(), "first-set".into())
            .unwrap();
        assert!(matches!(
            capacity.reserve(second_key.clone(), "second-set".into()),
            Err(FirewallError::FlowSetSaturated { .. })
        ));
        drop(first);

        let mut retained = capacity.reserve(first_key, "first-set".into()).unwrap();
        let permit = retained.permit.take().unwrap();
        capacity.retain(permit, Duration::from_millis(20)).unwrap();
        assert!(matches!(
            capacity.reserve(second_key.clone(), "second-set".into()),
            Err(FirewallError::FlowSetSaturated { .. })
        ));
        let recovered = timeout(
            Duration::from_secs(1),
            capacity.reserve_wait(second_key, "second-set".into()),
        )
        .await
        .expect("retained capacity permit was not restored")
        .expect("capacity semaphore remains available");
        drop(recovered);
        assert!(
            !reaper.is_finished(),
            "the single shared reaper must remain available for later entries"
        );
        reaper.abort();
    }

    #[tokio::test]
    async fn activation_failure_consumes_capacity_until_reaper_recovers() {
        let (capacity, reaper) = FlowCapacity::new(1);
        let key = FlowTargetKey {
            protocol: FirewallProtocol::Udp,
            listener: "127.0.0.1:443".parse().unwrap(),
            client_family: Family::V4,
        };
        let mut failed = capacity.reserve(key.clone(), "failed-set".into()).unwrap();

        let error = finish_first_response_activation(
            &capacity,
            &mut failed,
            Duration::from_millis(20),
            Err(FirewallError::NotActive),
        )
        .expect_err("injected ipset activation must fail");
        assert!(matches!(error, FirewallError::NotActive));
        assert!(matches!(
            capacity.reserve(key.clone(), "next-set".into()),
            Err(FirewallError::FlowSetSaturated { .. })
        ));

        let recovered = timeout(
            Duration::from_secs(1),
            capacity.reserve_wait(key, "next-set".into()),
        )
        .await
        .expect("failed activation capacity was not restored")
        .expect("capacity semaphore remains available");
        drop(recovered);
        reaper.abort();
    }

    #[test]
    fn stale_owned_flow_sets_accept_every_supported_capacity() {
        assert!(flow_set_maxelem_is_valid(&["maxelem", "2"]));
        assert!(flow_set_maxelem_is_valid(&[
            "timeout", "2", "maxelem", "4097", "comment"
        ]));
        assert!(flow_set_maxelem_is_valid(&["maxelem", "1000001"]));
        assert!(!flow_set_maxelem_is_valid(&["maxelem", "1"]));
        assert!(!flow_set_maxelem_is_valid(&["maxelem", "1000002"]));
    }

    #[test]
    fn marker_is_required_before_reserved_chain_is_owned() {
        let rules = "-P INPUT ACCEPT\n-N RSPX_BI4\n-A RSPX_BI4 -m comment --comment rs-proxy-owned-v1 -j RETURN\n-N RSPX_FOREIGN\n";
        let declared = declared_owned_namespace_chains(rules);
        let owned = marker_owned_chains(rules, &declared);
        assert!(owned.contains("RSPX_BI4"));
        assert!(!owned.contains("RSPX_FOREIGN"));
    }

    #[test]
    fn listener_rule_keeps_protocol_local_address_and_port() {
        let listener = EffectiveListener {
            origin: "192.0.2.1:443".parse().unwrap(),
            address: "192.0.2.1:443".parse().unwrap(),
            protocol: FirewallProtocol::Tcp,
            family: Family::V4,
        };
        let input = listener_jump(&listener, "TARGET", false);
        assert_eq!(
            input,
            [
                "-p",
                "tcp",
                "-d",
                "192.0.2.1",
                "--dport",
                "443",
                "-j",
                "TARGET"
            ]
        );
        let output = listener_jump(&listener, "TARGET", true);
        assert_eq!(
            output,
            [
                "-p",
                "tcp",
                "-s",
                "192.0.2.1",
                "--sport",
                "443",
                "-j",
                "TARGET"
            ]
        );
    }

    #[test]
    fn exclusive_lock_prevents_a_second_lifecycle_owner() {
        let directory = std::env::temp_dir().join(format!(
            "rs-proxy-firewall-lock-test-{}",
            std::process::id()
        ));
        let path = directory.join("firewall.lock");
        let first = acquire_instance_lock_at(&directory, &path).expect("first owner lock");
        let second = acquire_instance_lock_at(&directory, &path)
            .expect_err("a live owner must exclude recovery by another process");
        assert!(matches!(second, FirewallError::InstanceLock { .. }));
        drop(first);
        let third = acquire_instance_lock_at(&directory, &path).expect("released lock recovers");
        drop(third);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir(directory);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lifecycle_lock_does_not_follow_a_symbolic_link() {
        use std::os::unix::fs::symlink;

        let directory = std::env::temp_dir().join(format!(
            "rs-proxy-firewall-symlink-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let target = directory.join("target");
        let path = directory.join("firewall.lock");
        std::fs::write(&target, b"must remain untouched").unwrap();
        symlink(&target, &path).unwrap();

        let error = acquire_instance_lock_at(&directory, &path)
            .expect_err("O_NOFOLLOW must reject a symlink lifecycle lock");
        assert!(matches!(error, FirewallError::InstanceLock { .. }));
        assert_eq!(std::fs::read(&target).unwrap(), b"must remain untouched");

        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(target).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
