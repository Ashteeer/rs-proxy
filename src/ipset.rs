//! Read-only source admission backed by existing legacy Linux `IPset` sets.
//!
//! Membership is loaded as an atomic, bounded snapshot. A single periodic
//! `ipset save` refresh replaces the snapshot, so the connection path never
//! launches `ipset test` (or any other subprocess).

use std::{
    collections::HashSet,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, RwLock},
    time::Duration,
};

use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    sync::watch,
    time::{MissedTickBehavior, interval, timeout},
};
use tracing::{debug, warn};

use crate::config::{IpSetConfig, IpSetNotFound};

const IPSET_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const IPSET_COMMAND_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
const MAX_STDERR_BYTES: usize = 4 * 1024;
const MAX_ENTRIES_PER_SET: usize = 1_000_000;
const IPSET_COMMAND_CANDIDATES: [&str; 2] = ["/usr/sbin/ipset", "/sbin/ipset"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionDecision {
    Relay,
    FirstResponse,
    CloseAccepted,
    HoldAcceptedSilent,
}

#[derive(Debug)]
pub struct IpSetAdmission {
    command: PathBuf,
    ipv4_set: Option<String>,
    ipv6_set: Option<String>,
    not_found: IpSetNotFound,
    state: RwLock<MembershipState>,
}

#[derive(Debug)]
enum MembershipState {
    Ready(Arc<Snapshot>),
    Unavailable(String),
}

#[derive(Debug)]
struct Snapshot {
    ipv4: HashSet<Ipv4Addr>,
    ipv6: HashSet<Ipv6Addr>,
}

#[derive(Clone, Copy)]
enum SetFamily {
    Inet,
    Inet6,
}

impl SetFamily {
    const fn saved_name(self) -> &'static str {
        match self {
            Self::Inet => "inet",
            Self::Inet6 => "inet6",
        }
    }
}

impl IpSetAdmission {
    /// Load and validate named `hash:ip` `IPset` sets before listeners start.
    ///
    /// # Errors
    ///
    /// Fails when `IPset` is enabled off Linux, the command/set is unavailable,
    /// a set has the wrong type/family, or its bounded snapshot cannot be read.
    pub async fn initialize(config: &IpSetConfig) -> Result<Option<Arc<Self>>, IpSetError> {
        if !config.has_active_sets() {
            return Ok(None);
        }
        if !cfg!(target_os = "linux") {
            return Err(IpSetError::UnsupportedPlatform);
        }
        config
            .validate_set_names()
            .map_err(|error| IpSetError::InvalidConfig(error.to_string()))?;

        let admission = Arc::new(Self {
            command: locate_ipset_command()?,
            ipv4_set: config.ipv4_set.clone(),
            ipv6_set: config.ipv6_set.clone(),
            not_found: config.not_found,
            state: RwLock::new(MembershipState::Unavailable(
                "initial IPset snapshot has not completed".into(),
            )),
        });
        let snapshot = admission.load_snapshot().await?;
        *admission
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            MembershipState::Ready(Arc::new(snapshot));
        Ok(Some(admission))
    }

    /// Decide admission from the latest complete snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`IpSetError::SnapshotUnavailable`] for configured families
    /// after any failed refresh. A family without a set always relays.
    pub fn decide(&self, source: IpAddr) -> Result<AdmissionDecision, IpSetError> {
        let source = normalize_source(source);
        let configured = match source {
            IpAddr::V4(_) => self.ipv4_set.is_some(),
            IpAddr::V6(_) => self.ipv6_set.is_some(),
        };
        if !configured {
            return Ok(AdmissionDecision::Relay);
        }
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let MembershipState::Ready(snapshot) = &*state else {
            let MembershipState::Unavailable(reason) = &*state else {
                unreachable!();
            };
            return Err(IpSetError::SnapshotUnavailable(reason.clone()));
        };
        let found = match source {
            IpAddr::V4(address) => snapshot.ipv4.contains(&address),
            IpAddr::V6(address) => snapshot.ipv6.contains(&address),
        };
        Ok(decision_for_membership(found, self.not_found))
    }

    /// Refresh snapshots until server shutdown. A failed refresh invalidates
    /// the old snapshot immediately; a later successful refresh recovers it.
    pub async fn refresh_until(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let mut refresh = interval(IPSET_REFRESH_INTERVAL);
        refresh.set_missed_tick_behavior(MissedTickBehavior::Skip);
        // Initialization already loaded a snapshot; avoid an immediate duplicate command.
        refresh.tick().await;
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
                _ = refresh.tick() => self.refresh_once().await,
            }
        }
    }

    /// Reload the configured sets and atomically publish them. Primarily public for
    /// privileged Linux integration tests and operational probes.
    pub async fn refresh_once(&self) {
        match self.load_snapshot().await {
            Ok(snapshot) => {
                let mut state = self
                    .state
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let recovering = matches!(*state, MembershipState::Unavailable(_));
                *state = MembershipState::Ready(Arc::new(snapshot));
                if recovering {
                    debug!("IPset snapshot recovered; new connections are admitted normally");
                }
            }
            Err(error) => {
                let reason = error.to_string();
                let mut state = self
                    .state
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let should_warn = !matches!(&*state, MembershipState::Unavailable(previous) if previous == &reason);
                *state = MembershipState::Unavailable(reason.clone());
                if should_warn {
                    warn!(%reason, "IPset refresh failed; failing admissions for configured families closed");
                }
            }
        }
    }

    async fn load_snapshot(&self) -> Result<Snapshot, IpSetError> {
        let ipv4 = load_set(&self.command, self.ipv4_set.as_deref(), SetFamily::Inet);
        let ipv6 = load_set(&self.command, self.ipv6_set.as_deref(), SetFamily::Inet6);
        let (ipv4, ipv6) = tokio::try_join!(ipv4, ipv6)?;
        Ok(Snapshot { ipv4, ipv6 })
    }
}

fn normalize_source(source: IpAddr) -> IpAddr {
    match source {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        IpAddr::V4(address) => IpAddr::V4(address),
    }
}

const fn decision_for_membership(found: bool, not_found: IpSetNotFound) -> AdmissionDecision {
    if found {
        return AdmissionDecision::Relay;
    }
    match not_found {
        IpSetNotFound::Allow => AdmissionDecision::Relay,
        IpSetNotFound::FirstResponse => AdmissionDecision::FirstResponse,
        // These are deliberately named after what userspace can actually do.
        // Neither decision claims SYN-level REJECT/DROP semantics.
        IpSetNotFound::Reject => AdmissionDecision::CloseAccepted,
        IpSetNotFound::Silent => AdmissionDecision::HoldAcceptedSilent,
    }
}

fn locate_ipset_command() -> Result<PathBuf, IpSetError> {
    select_ipset_command(is_executable_file)
}

fn select_ipset_command(mut is_usable: impl FnMut(&Path) -> bool) -> Result<PathBuf, IpSetError> {
    for candidate in IPSET_COMMAND_CANDIDATES {
        let candidate = Path::new(candidate);
        if is_usable(candidate) {
            return Ok(candidate.to_path_buf());
        }
    }
    Err(IpSetError::TrustedExecutableNotFound)
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

async fn load_set<T>(
    command: &Path,
    set_name: Option<&str>,
    family: SetFamily,
) -> Result<HashSet<T>, IpSetError>
where
    T: std::str::FromStr + Eq + std::hash::Hash + Send + 'static,
{
    let Some(set_name) = set_name else {
        return Ok(HashSet::new());
    };
    let bytes = save_set(command, set_name).await?;
    let set_name = set_name.to_owned();
    tokio::task::spawn_blocking(move || parse_saved_set(&bytes, &set_name, family))
        .await
        .map_err(|error| IpSetError::SnapshotParserTask(error.to_string()))?
}

async fn save_set(command: &Path, set_name: &str) -> Result<Vec<u8>, IpSetError> {
    let mut child = Command::new(command)
        .arg("save")
        .arg(set_name)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|source| IpSetError::CommandStart {
            command: command.to_path_buf(),
            source,
        })?;
    let stdout = child.stdout.take().ok_or(IpSetError::MissingCommandPipe)?;
    let stderr = child.stderr.take().ok_or(IpSetError::MissingCommandPipe)?;
    let operation = async {
        let stdout_read = read_bounded(stdout, MAX_SNAPSHOT_BYTES, true);
        let stderr_read = read_bounded(stderr, MAX_STDERR_BYTES, false);
        let wait = async { child.wait().await.map_err(IpSetError::Io) };
        let (stdout, stderr, status) = tokio::try_join!(stdout_read, stderr_read, wait)?;
        if !status.success() {
            let detail = String::from_utf8_lossy(&stderr).trim().to_owned();
            return Err(IpSetError::CommandFailed {
                set_name: set_name.to_owned(),
                status: status.code(),
                detail,
            });
        }
        Ok(stdout)
    };
    timeout(IPSET_COMMAND_TIMEOUT, operation)
        .await
        .map_err(|_| IpSetError::CommandTimeout {
            set_name: set_name.to_owned(),
            timeout: IPSET_COMMAND_TIMEOUT,
        })?
}

async fn read_bounded<R>(
    reader: R,
    limit: usize,
    reject_overflow: bool,
) -> Result<Vec<u8>, IpSetError>
where
    R: AsyncRead + Unpin,
{
    let read_limit = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let mut reader = reader.take(read_limit);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).await?;
    if bytes.len() > limit {
        if reject_overflow {
            return Err(IpSetError::SnapshotTooLarge(limit));
        }
        bytes.truncate(limit);
    }
    Ok(bytes)
}

fn parse_saved_set<T>(
    bytes: &[u8],
    set_name: &str,
    expected_family: SetFamily,
) -> Result<HashSet<T>, IpSetError>
where
    T: std::str::FromStr + Eq + std::hash::Hash,
{
    let text = std::str::from_utf8(bytes).map_err(|_| IpSetError::NonUtf8Snapshot {
        set_name: set_name.to_owned(),
    })?;
    let mut saw_create = false;
    let mut entries = HashSet::new();
    for (line_index, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        match fields.first().copied() {
            Some("create") => {
                if saw_create
                    || fields.get(1) != Some(&set_name)
                    || fields.get(2) != Some(&"hash:ip")
                {
                    return Err(invalid_snapshot(
                        set_name,
                        line_index,
                        "expected one matching 'create <name> hash:ip' line",
                    ));
                }
                let family = fields
                    .windows(2)
                    .find_map(|pair| (pair[0] == "family").then_some(pair[1]));
                if family != Some(expected_family.saved_name()) {
                    return Err(invalid_snapshot(
                        set_name,
                        line_index,
                        "set family does not match the configured IPv4/IPv6 role",
                    ));
                }
                if fields
                    .iter()
                    .any(|field| matches!(*field, "netmask" | "bitmask"))
                {
                    return Err(invalid_snapshot(
                        set_name,
                        line_index,
                        "netmask/bitmask sets are unsupported because membership must be exact",
                    ));
                }
                saw_create = true;
            }
            Some("add") => {
                if !saw_create || fields.get(1) != Some(&set_name) {
                    return Err(invalid_snapshot(
                        set_name,
                        line_index,
                        "element precedes or names a different set",
                    ));
                }
                let address = fields
                    .get(2)
                    .and_then(|value| value.parse::<T>().ok())
                    .ok_or_else(|| {
                        invalid_snapshot(set_name, line_index, "invalid IP address element")
                    })?;
                entries.insert(address);
                if entries.len() > MAX_ENTRIES_PER_SET {
                    return Err(IpSetError::TooManyEntries {
                        set_name: set_name.to_owned(),
                        limit: MAX_ENTRIES_PER_SET,
                    });
                }
            }
            _ => {
                return Err(invalid_snapshot(
                    set_name,
                    line_index,
                    "unsupported ipset save line",
                ));
            }
        }
    }
    if !saw_create {
        return Err(IpSetError::InvalidSnapshot {
            set_name: set_name.to_owned(),
            line: 0,
            reason: "missing create line".into(),
        });
    }
    Ok(entries)
}

fn invalid_snapshot(set_name: &str, zero_based_line: usize, reason: &str) -> IpSetError {
    IpSetError::InvalidSnapshot {
        set_name: set_name.to_owned(),
        line: zero_based_line.saturating_add(1),
        reason: reason.into(),
    }
}

#[derive(Debug, Error)]
pub enum IpSetError {
    #[error("invalid IPset configuration: {0}")]
    InvalidConfig(String),
    #[error("IPset source admission is supported only on Linux")]
    UnsupportedPlatform,
    #[error(
        "legacy ipset executable is unavailable at trusted paths /usr/sbin/ipset and /sbin/ipset; install the distribution ipset package (PATH lookup is intentionally disabled)"
    )]
    TrustedExecutableNotFound,
    #[error("failed to start legacy ipset command {command}: {source}")]
    CommandStart {
        command: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("ipset command did not expose stdout/stderr")]
    MissingCommandPipe,
    #[error("ipset save {set_name} timed out after {timeout:?}")]
    CommandTimeout { set_name: String, timeout: Duration },
    #[error("ipset save {set_name} failed with status {status:?}: {detail}")]
    CommandFailed {
        set_name: String,
        status: Option<i32>,
        detail: String,
    },
    #[error("ipset snapshot exceeded the {0}-byte safety limit")]
    SnapshotTooLarge(usize),
    #[error("ipset save {set_name} returned non-UTF-8 data")]
    NonUtf8Snapshot { set_name: String },
    #[error("ipset snapshot parser task failed: {0}")]
    SnapshotParserTask(String),
    #[error("invalid ipset snapshot for {set_name} at line {line}: {reason}")]
    InvalidSnapshot {
        set_name: String,
        line: usize,
        reason: String,
    },
    #[error("ipset {set_name} exceeded the {limit}-entry safety limit")]
    TooManyEntries { set_name: String, limit: usize },
    #[error("IPset membership snapshot is unavailable: {0}")]
    SnapshotUnavailable(String),
    #[error("IPset command I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_command_selection_prefers_usr_sbin() {
        let selected = select_ipset_command(|_| true).unwrap();
        assert_eq!(selected, Path::new("/usr/sbin/ipset"));
        assert!(selected.is_absolute());
    }

    #[test]
    fn trusted_command_selection_falls_back_only_to_sbin() {
        let mut inspected = Vec::new();
        let selected = select_ipset_command(|candidate| {
            inspected.push(candidate.to_path_buf());
            candidate == Path::new("/sbin/ipset")
        })
        .unwrap();

        assert_eq!(
            inspected,
            [
                PathBuf::from("/usr/sbin/ipset"),
                PathBuf::from("/sbin/ipset")
            ]
        );
        assert_eq!(selected, Path::new("/sbin/ipset"));
    }

    #[test]
    fn trusted_command_selection_fails_closed_without_path_lookup() {
        let error = select_ipset_command(|_| false).unwrap_err();
        assert!(matches!(error, IpSetError::TrustedExecutableNotFound));
        assert!(
            error
                .to_string()
                .contains("PATH lookup is intentionally disabled")
        );
        assert!(
            IPSET_COMMAND_CANDIDATES
                .iter()
                .all(|candidate| Path::new(candidate).is_absolute())
        );
    }

    #[test]
    fn parses_exact_hash_ip_family_and_members() {
        let ipv4 = b"create clients4 hash:ip family inet hashsize 1024 maxelem 65536\nadd clients4 192.0.2.1\nadd clients4 198.51.100.3 timeout 10\n";
        let parsed = parse_saved_set::<Ipv4Addr>(ipv4, "clients4", SetFamily::Inet).unwrap();
        assert_eq!(parsed.len(), 2);
        assert!(parsed.contains(&Ipv4Addr::new(192, 0, 2, 1)));

        let ipv6 = b"create clients6 hash:ip family inet6 hashsize 1024 maxelem 65536\nadd clients6 2001:db8::1\n";
        let parsed = parse_saved_set::<Ipv6Addr>(ipv6, "clients6", SetFamily::Inet6).unwrap();
        assert!(parsed.contains(&"2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn rejects_wrong_type_family_name_and_unknown_lines() {
        for snapshot in [
            "create clients hash:net family inet\n",
            "create clients hash:ip family inet6\n",
            "create other hash:ip family inet\n",
            "create clients hash:ip family inet\nflush clients\n",
            "add clients 192.0.2.1\n",
        ] {
            assert!(
                parse_saved_set::<Ipv4Addr>(snapshot.as_bytes(), "clients", SetFamily::Inet)
                    .is_err(),
                "snapshot must fail: {snapshot:?}"
            );
        }
    }

    #[test]
    fn rejects_ipv4_and_ipv6_masked_hash_ip_sets() {
        for (snapshot, family) in [
            (
                "create clients hash:ip family inet netmask 24\nadd clients 192.0.2.0\n",
                SetFamily::Inet,
            ),
            (
                "create clients hash:ip family inet bitmask 255.255.255.0\nadd clients 192.0.2.0\n",
                SetFamily::Inet,
            ),
        ] {
            assert!(
                parse_saved_set::<Ipv4Addr>(snapshot.as_bytes(), "clients", family).is_err(),
                "masked IPv4 snapshot must fail closed: {snapshot:?}"
            );
        }

        for snapshot in [
            "create clients hash:ip family inet6 netmask 64\nadd clients 2001:db8::\n",
            "create clients hash:ip family inet6 bitmask ffff:ffff:ffff:ffff::\nadd clients 2001:db8::\n",
        ] {
            assert!(
                parse_saved_set::<Ipv6Addr>(snapshot.as_bytes(), "clients", SetFamily::Inet6)
                    .is_err(),
                "masked IPv6 snapshot must fail closed: {snapshot:?}"
            );
        }
    }

    #[test]
    fn all_not_found_policies_are_explicit_and_members_always_relay() {
        for policy in [
            IpSetNotFound::Allow,
            IpSetNotFound::FirstResponse,
            IpSetNotFound::Reject,
            IpSetNotFound::Silent,
        ] {
            assert_eq!(
                decision_for_membership(true, policy),
                AdmissionDecision::Relay
            );
        }
        assert_eq!(
            decision_for_membership(false, IpSetNotFound::Allow),
            AdmissionDecision::Relay
        );
        assert_eq!(
            decision_for_membership(false, IpSetNotFound::FirstResponse),
            AdmissionDecision::FirstResponse
        );
        assert_eq!(
            decision_for_membership(false, IpSetNotFound::Reject),
            AdmissionDecision::CloseAccepted
        );
        assert_eq!(
            decision_for_membership(false, IpSetNotFound::Silent),
            AdmissionDecision::HoldAcceptedSilent
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_sources_use_the_ipv4_set() {
        assert_eq!(
            normalize_source("::ffff:192.0.2.9".parse().unwrap()),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))
        );
    }
}
