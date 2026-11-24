//! Bounded pre-routing and relay-accounting state for the UDP/QUIC runtime.
//!
//! This module owns no sockets and does not parse or rewrite packets. It keeps
//! exact client datagrams until a route is pinned, indexes only explicitly
//! observed connection IDs, and applies QUIC's server anti-amplification limit.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    error::Error,
    fmt,
    net::SocketAddr,
    time::{Duration, Instant},
};

const MAX_QUIC_CONNECTION_ID_LEN: usize = 20;
const ANTI_AMPLIFICATION_FACTOR: u64 = 3;

/// Stable identity of one configured UDP listener.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ListenerId(pub u64);

/// Stable identity of one live session.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionId(u64);

/// A bounded, non-empty QUIC connection ID.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ConnectionId(Vec<u8>);

impl ConnectionId {
    /// Copy a connection ID after checking the QUIC wire bound.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidConnectionIdLength`] for an empty ID or
    /// one longer than the QUIC maximum of 20 bytes.
    pub fn new(bytes: &[u8]) -> Result<Self, SessionError> {
        if bytes.is_empty() || bytes.len() > MAX_QUIC_CONNECTION_ID_LEN {
            return Err(SessionError::InvalidConnectionIdLength { len: bytes.len() });
        }
        Ok(Self(bytes.to_vec()))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Full primary key. The ODCID remains stable when the active client path changes.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SessionKey {
    pub listener_id: ListenerId,
    pub client: SocketAddr,
    pub version: u32,
    pub original_destination_connection_id: ConnectionId,
}

/// Hard memory, cardinality, and lifetime bounds for a session table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpSessionLimits {
    pub max_sessions: usize,
    pub max_known_cids_per_session: usize,
    pub max_datagram_bytes: usize,
    pub max_buffered_datagrams_per_session: usize,
    pub max_buffered_bytes_per_session: usize,
    pub max_buffered_datagrams_total: usize,
    pub max_buffered_bytes_total: usize,
    pub inspection_timeout: Duration,
    pub idle_timeout: Duration,
}

impl Default for UdpSessionLimits {
    fn default() -> Self {
        Self {
            max_sessions: 4_096,
            max_known_cids_per_session: 8,
            max_datagram_bytes: 65_535,
            max_buffered_datagrams_per_session: 64,
            max_buffered_bytes_per_session: 512 * 1024,
            max_buffered_datagrams_total: 16_384,
            max_buffered_bytes_total: 64 * 1024 * 1024,
            inspection_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(30),
        }
    }
}

/// Reason a live state was terminally closed and removed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseReason {
    InspectionTimeout,
    IdleTimeout,
    InspectionFailed,
    RelayFinished,
    Shutdown,
}

/// Explicit session lifecycle. Closed states are returned as bounded tombstones,
/// not retained in the live table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionState {
    Inspecting {
        deadline: Instant,
    },
    Routed {
        upstream: SocketAddr,
    },
    RetryInspecting {
        upstream: SocketAddr,
        deadline: Instant,
    },
    Closed {
        reason: CloseReason,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateKind {
    Inspecting,
    Routed,
    RetryInspecting,
    Closed,
}

impl SessionState {
    #[must_use]
    pub const fn kind(&self) -> StateKind {
        match self {
            Self::Inspecting { .. } => StateKind::Inspecting,
            Self::Routed { .. } => StateKind::Routed,
            Self::RetryInspecting { .. } => StateKind::RetryInspecting,
            Self::Closed { .. } => StateKind::Closed,
        }
    }
}

/// Result of registering a CID. Ambiguous CIDs remain indexed so rebinding is
/// rejected for every colliding owner rather than silently favoring one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CidRegistration {
    AlreadyKnown,
    Unique,
    Ambiguous { owners: usize },
}

/// Result of resolving a client path by an explicitly known CID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientPath {
    Existing {
        session_id: SessionId,
    },
    Rebound {
        session_id: SessionId,
        previous_client: SocketAddr,
    },
}

impl ClientPath {
    #[must_use]
    pub const fn session_id(self) -> SessionId {
        match self {
            Self::Existing { session_id } | Self::Rebound { session_id, .. } => session_id,
        }
    }
}

/// Current server-to-client allowance for the active client address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendAllowance {
    Limited(u64),
    Unlimited,
}

/// Metadata returned after a terminal transition. Buffered payload is dropped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosedSession {
    pub id: SessionId,
    pub key: SessionKey,
    pub state: SessionState,
    pub discarded_datagrams: usize,
    pub discarded_bytes: usize,
}

/// Observable table totals; payload capacity is bounded by the configured counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionTotals {
    pub live_sessions: usize,
    pub buffered_datagrams: usize,
    pub buffered_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionError {
    InvalidLimits(&'static str),
    InvalidConnectionIdLength {
        len: usize,
    },
    SessionIdExhausted,
    SessionLimit {
        limit: usize,
    },
    SessionNotFound(SessionId),
    SessionAlreadyExists(SessionId),
    InvalidTransition {
        from: StateKind,
        action: &'static str,
    },
    DatagramTooLarge {
        size: usize,
        limit: usize,
    },
    SessionDatagramLimit {
        limit: usize,
    },
    SessionByteLimit {
        limit: usize,
    },
    GlobalDatagramLimit {
        limit: usize,
    },
    GlobalByteLimit {
        limit: usize,
    },
    KnownCidLimit {
        limit: usize,
    },
    AmbiguousConnectionId {
        owners: usize,
    },
    AmbiguousClientPath {
        owners: usize,
    },
    RebindingBeforeRoute(SessionId),
    RebindingKeyCollision(SessionId),
    InspectionDeadlineElapsed(SessionId),
    DeadlineOverflow,
    CounterOverflow,
    AmplificationLimit {
        attempted: u64,
        allowance: u64,
    },
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits(reason) => {
                write!(formatter, "invalid UDP session limits: {reason}")
            }
            Self::InvalidConnectionIdLength { len } => {
                write!(
                    formatter,
                    "invalid QUIC connection ID length {len}; expected 1..=20"
                )
            }
            Self::SessionIdExhausted => formatter.write_str("UDP session ID space exhausted"),
            Self::SessionLimit { limit } => write!(formatter, "live session limit {limit} reached"),
            Self::SessionNotFound(id) => write!(formatter, "session {id:?} is not live"),
            Self::SessionAlreadyExists(id) => write!(formatter, "session {id:?} already exists"),
            Self::InvalidTransition { from, action } => {
                write!(formatter, "cannot {action} a {from:?} session")
            }
            Self::DatagramTooLarge { size, limit } => {
                write!(formatter, "datagram size {size} exceeds limit {limit}")
            }
            Self::SessionDatagramLimit { limit } => {
                write!(formatter, "per-session datagram limit {limit} reached")
            }
            Self::SessionByteLimit { limit } => {
                write!(formatter, "per-session byte limit {limit} exceeded")
            }
            Self::GlobalDatagramLimit { limit } => {
                write!(formatter, "global buffered datagram limit {limit} reached")
            }
            Self::GlobalByteLimit { limit } => {
                write!(formatter, "global buffered byte limit {limit} exceeded")
            }
            Self::KnownCidLimit { limit } => {
                write!(formatter, "per-session known CID limit {limit} reached")
            }
            Self::AmbiguousConnectionId { owners } => {
                write!(formatter, "connection ID has {owners} live owners")
            }
            Self::AmbiguousClientPath { owners } => {
                write!(formatter, "client path has {owners} live sessions")
            }
            Self::RebindingBeforeRoute(id) => {
                write!(formatter, "session {id:?} cannot rebind during inspection")
            }
            Self::RebindingKeyCollision(id) => {
                write!(formatter, "rebinding would collide with session {id:?}")
            }
            Self::InspectionDeadlineElapsed(id) => {
                write!(formatter, "inspection deadline elapsed for session {id:?}")
            }
            Self::DeadlineOverflow => formatter.write_str("session deadline overflow"),
            Self::CounterOverflow => formatter.write_str("session byte counter overflow"),
            Self::AmplificationLimit {
                attempted,
                allowance,
            } => write!(
                formatter,
                "send of {attempted} bytes exceeds anti-amplification allowance {allowance}"
            ),
        }
    }
}

impl Error for SessionError {}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct CidIndexKey {
    listener_id: ListenerId,
    version: u32,
    cid: ConnectionId,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ClientIndexKey {
    listener_id: ListenerId,
    client: SocketAddr,
}

#[derive(Debug)]
struct Session {
    key: SessionKey,
    state: SessionState,
    known_cids: HashSet<ConnectionId>,
    buffered: VecDeque<Vec<u8>>,
    buffered_bytes: usize,
    idle_deadline: Instant,
    address_validated: bool,
    bytes_received_on_path: u64,
    bytes_sent_on_path: u64,
}

/// Bounded owner of pre-routing datagrams and QUIC session metadata.
pub struct UdpSessionTable {
    limits: UdpSessionLimits,
    next_session_id: u64,
    sessions: HashMap<SessionId, Session>,
    sessions_by_key: HashMap<SessionKey, SessionId>,
    sessions_by_cid: HashMap<CidIndexKey, HashSet<SessionId>>,
    sessions_by_client: HashMap<ClientIndexKey, HashSet<SessionId>>,
    buffered_datagrams: usize,
    buffered_bytes: usize,
}

impl UdpSessionTable {
    /// Construct a table after validating every configured bound.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidLimits`] if a bound is zero or a
    /// per-session bound exceeds its corresponding global bound.
    pub fn new(limits: UdpSessionLimits) -> Result<Self, SessionError> {
        validate_limits(limits)?;
        Ok(Self {
            limits,
            next_session_id: 0,
            sessions: HashMap::new(),
            sessions_by_key: HashMap::new(),
            sessions_by_cid: HashMap::new(),
            sessions_by_client: HashMap::new(),
            buffered_datagrams: 0,
            buffered_bytes: 0,
        })
    }

    /// Create a new inspection state. Its ODCID is the first known CID.
    ///
    /// # Errors
    ///
    /// Returns an error for a duplicate key, an exhausted session bound or ID
    /// space, or an `Instant` that cannot represent a configured deadline.
    pub fn create_inspecting(
        &mut self,
        key: SessionKey,
        now: Instant,
    ) -> Result<SessionId, SessionError> {
        if let Some(id) = self.sessions_by_key.get(&key) {
            return Err(SessionError::SessionAlreadyExists(*id));
        }
        if self.sessions.len() >= self.limits.max_sessions {
            return Err(SessionError::SessionLimit {
                limit: self.limits.max_sessions,
            });
        }

        let inspection_deadline = deadline(now, self.limits.inspection_timeout)?;
        let idle_deadline = deadline(now, self.limits.idle_timeout)?;
        let id = SessionId(self.next_session_id);
        self.next_session_id = self
            .next_session_id
            .checked_add(1)
            .ok_or(SessionError::SessionIdExhausted)?;

        let odcid = key.original_destination_connection_id.clone();
        let cid_key = CidIndexKey {
            listener_id: key.listener_id,
            version: key.version,
            cid: odcid.clone(),
        };
        let client_key = ClientIndexKey {
            listener_id: key.listener_id,
            client: key.client,
        };
        let mut known_cids = HashSet::new();
        known_cids.insert(odcid);
        self.sessions.insert(
            id,
            Session {
                key: key.clone(),
                state: SessionState::Inspecting {
                    deadline: inspection_deadline,
                },
                known_cids,
                buffered: VecDeque::new(),
                buffered_bytes: 0,
                idle_deadline,
                address_validated: false,
                bytes_received_on_path: 0,
                bytes_sent_on_path: 0,
            },
        );
        self.sessions_by_key.insert(key, id);
        self.sessions_by_cid.entry(cid_key).or_default().insert(id);
        self.sessions_by_client
            .entry(client_key)
            .or_default()
            .insert(id);
        Ok(id)
    }

    #[must_use]
    pub fn totals(&self) -> SessionTotals {
        SessionTotals {
            live_sessions: self.sessions.len(),
            buffered_datagrams: self.buffered_datagrams,
            buffered_bytes: self.buffered_bytes,
        }
    }

    #[must_use]
    pub fn state(&self, id: SessionId) -> Option<&SessionState> {
        self.sessions.get(&id).map(|session| &session.state)
    }

    #[must_use]
    pub fn key(&self, id: SessionId) -> Option<&SessionKey> {
        self.sessions.get(&id).map(|session| &session.key)
    }

    #[must_use]
    pub fn find_exact(&self, key: &SessionKey) -> Option<SessionId> {
        self.sessions_by_key.get(key).copied()
    }

    /// Find the only live session on one listener/client tuple.
    ///
    /// A runtime that cannot safely decode a short-header destination CID can
    /// use this conservative lookup after enforcing at most one connection per
    /// tuple. Existing ambiguous state always fails closed.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::AmbiguousClientPath`] when more than one live
    /// session owns the tuple.
    pub fn find_unique_client_path(
        &self,
        listener_id: ListenerId,
        client: SocketAddr,
    ) -> Result<Option<SessionId>, SessionError> {
        let index_key = ClientIndexKey {
            listener_id,
            client,
        };
        let Some(indexed) = self.sessions_by_client.get(&index_key) else {
            return Ok(None);
        };
        let owners = indexed.len();
        if owners > 1 {
            return Err(SessionError::AmbiguousClientPath { owners });
        }
        let Some(id) = indexed.iter().next().copied() else {
            return Ok(None);
        };
        if !self.sessions.contains_key(&id) {
            return Err(SessionError::SessionNotFound(id));
        }
        Ok(Some(id))
    }

    /// Retain one exact client datagram for later FIFO forwarding.
    ///
    /// Successful buffering also accounts these bytes as received for QUIC's
    /// anti-amplification rule. Every limit is checked before table mutation.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is absent or no longer inspecting, a
    /// buffer bound would be exceeded, a counter overflows, or the refreshed
    /// idle deadline is not representable.
    pub fn buffer_client_datagram(
        &mut self,
        id: SessionId,
        datagram: &[u8],
        now: Instant,
    ) -> Result<(), SessionError> {
        self.buffer_datagram_in_state(
            id,
            datagram,
            now,
            StateKind::Inspecting,
            "buffer pre-routing datagram for",
        )
    }

    /// Retain one exact client datagram while a routed connection validates a
    /// post-Retry Initial flight.
    ///
    /// This uses the same per-session/global count and byte bounds as initial
    /// inspection and accounts the bytes for anti-amplification. Callers must
    /// drain or close the session after post-Retry validation completes.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is absent or not in post-Retry
    /// inspection, a buffer bound would be exceeded, a counter overflows, or a
    /// deadline cannot be represented.
    pub fn buffer_retry_client_datagram(
        &mut self,
        id: SessionId,
        datagram: &[u8],
        now: Instant,
    ) -> Result<(), SessionError> {
        self.buffer_datagram_in_state(
            id,
            datagram,
            now,
            StateKind::RetryInspecting,
            "buffer post-Retry datagram for",
        )
    }

    /// Queue one exact client datagram for the per-session upstream writer.
    ///
    /// The session must be routed. Payload remains under the same global and
    /// per-session byte/count bounds until the writer pops it.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is absent or not routed, a buffer bound
    /// would be exceeded, a counter overflows, or the idle deadline cannot be
    /// represented.
    pub fn queue_routed_client_datagram(
        &mut self,
        id: SessionId,
        datagram: &[u8],
        now: Instant,
    ) -> Result<(), SessionError> {
        self.buffer_datagram_in_state(
            id,
            datagram,
            now,
            StateKind::Routed,
            "queue routed datagram for",
        )
    }

    fn buffer_datagram_in_state(
        &mut self,
        id: SessionId,
        datagram: &[u8],
        now: Instant,
        required_state: StateKind,
        action: &'static str,
    ) -> Result<(), SessionError> {
        let session = self
            .sessions
            .get(&id)
            .ok_or(SessionError::SessionNotFound(id))?;
        if session.state.kind() != required_state {
            return Err(SessionError::InvalidTransition {
                from: session.state.kind(),
                action,
            });
        }
        if state_inspection_deadline(&session.state).is_some_and(|deadline| now >= deadline) {
            return Err(SessionError::InspectionDeadlineElapsed(id));
        }
        self.check_buffer_limits(session, datagram.len())?;
        let received = checked_add_usize(session.bytes_received_on_path, datagram.len())?;
        let idle_deadline = deadline(now, self.limits.idle_timeout)?;

        let Some(session) = self.sessions.get_mut(&id) else {
            return Err(SessionError::SessionNotFound(id));
        };
        session.buffered.push_back(datagram.to_vec());
        session.buffered_bytes += datagram.len();
        session.bytes_received_on_path = received;
        session.idle_deadline = idle_deadline;
        self.buffered_datagrams += 1;
        self.buffered_bytes += datagram.len();
        Ok(())
    }

    /// Pin exactly one upstream and leave inspection permanently.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is absent, has already left inspection,
    /// or the refreshed idle deadline is not representable.
    pub fn route(
        &mut self,
        id: SessionId,
        upstream: SocketAddr,
        now: Instant,
    ) -> Result<(), SessionError> {
        let idle_deadline = deadline(now, self.limits.idle_timeout)?;
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(SessionError::SessionNotFound(id))?;
        if session.state.kind() != StateKind::Inspecting {
            return Err(SessionError::InvalidTransition {
                from: session.state.kind(),
                action: "route",
            });
        }
        if state_inspection_deadline(&session.state).is_some_and(|deadline| now >= deadline) {
            return Err(SessionError::InspectionDeadlineElapsed(id));
        }
        session.state = SessionState::Routed { upstream };
        session.idle_deadline = idle_deadline;
        Ok(())
    }

    /// Enter a bounded post-Retry inspection window without changing upstream.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is absent or not routed, or if either
    /// refreshed deadline cannot be represented.
    pub fn begin_retry_inspection(
        &mut self,
        id: SessionId,
        now: Instant,
    ) -> Result<(), SessionError> {
        let inspection_deadline = deadline(now, self.limits.inspection_timeout)?;
        let idle_deadline = deadline(now, self.limits.idle_timeout)?;
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(SessionError::SessionNotFound(id))?;
        let upstream = match &session.state {
            SessionState::Routed { upstream } => *upstream,
            state => {
                return Err(SessionError::InvalidTransition {
                    from: state.kind(),
                    action: "begin post-Retry inspection for",
                });
            }
        };
        session.state = SessionState::RetryInspecting {
            upstream,
            deadline: inspection_deadline,
        };
        session.idle_deadline = idle_deadline;
        Ok(())
    }

    /// Finish post-Retry inspection and resume the pinned routed state.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is absent or not validating Retry, or
    /// if the refreshed idle deadline cannot be represented.
    pub fn complete_retry_inspection(
        &mut self,
        id: SessionId,
        now: Instant,
    ) -> Result<(), SessionError> {
        let idle_deadline = deadline(now, self.limits.idle_timeout)?;
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(SessionError::SessionNotFound(id))?;
        let upstream = match &session.state {
            SessionState::RetryInspecting { upstream, deadline } => {
                if now >= *deadline {
                    return Err(SessionError::InspectionDeadlineElapsed(id));
                }
                *upstream
            }
            state => {
                return Err(SessionError::InvalidTransition {
                    from: state.kind(),
                    action: "complete post-Retry inspection for",
                });
            }
        };
        session.state = SessionState::Routed { upstream };
        session.idle_deadline = idle_deadline;
        Ok(())
    }

    /// Remove the oldest retained datagram after a route has been pinned.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is absent or is not routed.
    pub fn pop_buffered_datagram(
        &mut self,
        id: SessionId,
    ) -> Result<Option<Vec<u8>>, SessionError> {
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(SessionError::SessionNotFound(id))?;
        if session.state.kind() != StateKind::Routed {
            return Err(SessionError::InvalidTransition {
                from: session.state.kind(),
                action: "drain buffered datagram from",
            });
        }
        let datagram = session.buffered.pop_front();
        if let Some(bytes) = &datagram {
            session.buffered_bytes -= bytes.len();
            self.buffered_datagrams -= 1;
            self.buffered_bytes -= bytes.len();
        }
        Ok(datagram)
    }

    /// Add a CID learned from authenticated or otherwise trusted protocol state.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is absent or its known-CID bound has
    /// already been reached.
    pub fn register_connection_id(
        &mut self,
        id: SessionId,
        cid: ConnectionId,
    ) -> Result<CidRegistration, SessionError> {
        let session = self
            .sessions
            .get(&id)
            .ok_or(SessionError::SessionNotFound(id))?;
        if session.known_cids.contains(&cid) {
            return Ok(CidRegistration::AlreadyKnown);
        }
        if session.known_cids.len() >= self.limits.max_known_cids_per_session {
            return Err(SessionError::KnownCidLimit {
                limit: self.limits.max_known_cids_per_session,
            });
        }
        let index_key = CidIndexKey {
            listener_id: session.key.listener_id,
            version: session.key.version,
            cid: cid.clone(),
        };

        let Some(session) = self.sessions.get_mut(&id) else {
            return Err(SessionError::SessionNotFound(id));
        };
        session.known_cids.insert(cid);
        let owners = self.sessions_by_cid.entry(index_key).or_default();
        owners.insert(id);
        if owners.len() == 1 {
            Ok(CidRegistration::Unique)
        } else {
            Ok(CidRegistration::Ambiguous {
                owners: owners.len(),
            })
        }
    }

    /// Locate a session by a known CID and optionally move a routed session to a
    /// new client address. Inspection states never rebind. CID collisions always
    /// fail closed. Rebinding resets address validation and amplification counts.
    /// A same-address lookup does not refresh the idle timer or account bytes;
    /// the caller must record the accepted datagram separately.
    ///
    /// # Errors
    ///
    /// Returns an error for an ambiguous CID, a rebinding attempt during
    /// inspection, a primary-key collision, an inconsistent live index, or an
    /// unrepresentable refreshed idle deadline.
    pub fn locate_client_path(
        &mut self,
        listener_id: ListenerId,
        client: SocketAddr,
        version: u32,
        cid: &ConnectionId,
        now: Instant,
    ) -> Result<Option<ClientPath>, SessionError> {
        let index_key = CidIndexKey {
            listener_id,
            version,
            cid: cid.clone(),
        };
        let Some(owners) = self.sessions_by_cid.get(&index_key) else {
            return Ok(None);
        };
        if owners.len() != 1 {
            return Err(SessionError::AmbiguousConnectionId {
                owners: owners.len(),
            });
        }
        let Some(&id) = owners.iter().next() else {
            return Ok(None);
        };
        let session = self
            .sessions
            .get(&id)
            .ok_or(SessionError::SessionNotFound(id))?;
        if session.key.client == client {
            return Ok(Some(ClientPath::Existing { session_id: id }));
        }
        if session.state.kind() != StateKind::Routed {
            return Err(SessionError::RebindingBeforeRoute(id));
        }

        let old_key = session.key.clone();
        let mut new_key = old_key.clone();
        new_key.client = client;
        if let Some(other) = self.sessions_by_key.get(&new_key)
            && *other != id
        {
            return Err(SessionError::RebindingKeyCollision(*other));
        }
        let idle_deadline = deadline(now, self.limits.idle_timeout)?;

        self.sessions_by_key.remove(&old_key);
        self.sessions_by_key.insert(new_key.clone(), id);
        let old_client_key = ClientIndexKey {
            listener_id: old_key.listener_id,
            client: old_key.client,
        };
        let remove_old_client =
            if let Some(owners) = self.sessions_by_client.get_mut(&old_client_key) {
                owners.remove(&id);
                owners.is_empty()
            } else {
                false
            };
        if remove_old_client {
            self.sessions_by_client.remove(&old_client_key);
        }
        self.sessions_by_client
            .entry(ClientIndexKey {
                listener_id: new_key.listener_id,
                client: new_key.client,
            })
            .or_default()
            .insert(id);
        let Some(session) = self.sessions.get_mut(&id) else {
            return Err(SessionError::SessionNotFound(id));
        };
        session.key = new_key;
        session.idle_deadline = idle_deadline;
        session.address_validated = false;
        session.bytes_received_on_path = 0;
        session.bytes_sent_on_path = 0;
        Ok(Some(ClientPath::Rebound {
            session_id: id,
            previous_client: old_key.client,
        }))
    }

    /// Account client bytes on the active path and refresh the idle deadline.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is absent, the byte counter overflows, or
    /// the refreshed idle deadline is not representable.
    pub fn record_client_bytes_received(
        &mut self,
        id: SessionId,
        bytes: usize,
        now: Instant,
    ) -> Result<(), SessionError> {
        let idle_deadline = deadline(now, self.limits.idle_timeout)?;
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(SessionError::SessionNotFound(id))?;
        session.bytes_received_on_path = checked_add_usize(session.bytes_received_on_path, bytes)?;
        session.idle_deadline = idle_deadline;
        Ok(())
    }

    /// Validate the active client address, removing the 3x send cap.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::SessionNotFound`] if the session is not live.
    pub fn validate_client_address(&mut self, id: SessionId) -> Result<(), SessionError> {
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(SessionError::SessionNotFound(id))?;
        session.address_validated = true;
        Ok(())
    }

    /// Return the remaining anti-amplification allowance for the current path.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::SessionNotFound`] if the session is not live.
    pub fn send_allowance(&self, id: SessionId) -> Result<SendAllowance, SessionError> {
        let session = self
            .sessions
            .get(&id)
            .ok_or(SessionError::SessionNotFound(id))?;
        if session.address_validated {
            return Ok(SendAllowance::Unlimited);
        }
        let permitted = session
            .bytes_received_on_path
            .saturating_mul(ANTI_AMPLIFICATION_FACTOR);
        Ok(SendAllowance::Limited(
            permitted.saturating_sub(session.bytes_sent_on_path),
        ))
    }

    /// Account server-to-client bytes only if the current path may send them.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is absent, the send exceeds the current
    /// anti-amplification allowance, a counter overflows, or the refreshed idle
    /// deadline is not representable.
    pub fn record_client_bytes_sent(
        &mut self,
        id: SessionId,
        bytes: usize,
        now: Instant,
    ) -> Result<(), SessionError> {
        let attempted = u64::try_from(bytes).map_err(|_| SessionError::CounterOverflow)?;
        if let SendAllowance::Limited(allowance) = self.send_allowance(id)?
            && attempted > allowance
        {
            return Err(SessionError::AmplificationLimit {
                attempted,
                allowance,
            });
        }
        let idle_deadline = deadline(now, self.limits.idle_timeout)?;
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(SessionError::SessionNotFound(id))?;
        session.bytes_sent_on_path = session
            .bytes_sent_on_path
            .checked_add(attempted)
            .ok_or(SessionError::CounterOverflow)?;
        session.idle_deadline = idle_deadline;
        Ok(())
    }

    /// Close and remove a live session, releasing all table-owned payload memory.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::SessionNotFound`] if the session is not live.
    pub fn close(
        &mut self,
        id: SessionId,
        reason: CloseReason,
    ) -> Result<ClosedSession, SessionError> {
        let mut session = self
            .sessions
            .remove(&id)
            .ok_or(SessionError::SessionNotFound(id))?;
        self.sessions_by_key.remove(&session.key);
        let client_key = ClientIndexKey {
            listener_id: session.key.listener_id,
            client: session.key.client,
        };
        let remove_client_entry = if let Some(owners) = self.sessions_by_client.get_mut(&client_key)
        {
            owners.remove(&id);
            owners.is_empty()
        } else {
            false
        };
        if remove_client_entry {
            self.sessions_by_client.remove(&client_key);
        }
        for cid in &session.known_cids {
            let index_key = CidIndexKey {
                listener_id: session.key.listener_id,
                version: session.key.version,
                cid: cid.clone(),
            };
            let remove_entry = if let Some(owners) = self.sessions_by_cid.get_mut(&index_key) {
                owners.remove(&id);
                owners.is_empty()
            } else {
                false
            };
            if remove_entry {
                self.sessions_by_cid.remove(&index_key);
            }
        }
        let discarded_datagrams = session.buffered.len();
        let discarded_bytes = session.buffered_bytes;
        self.buffered_datagrams -= discarded_datagrams;
        self.buffered_bytes -= discarded_bytes;
        session.state = SessionState::Closed { reason };
        Ok(ClosedSession {
            id,
            key: session.key,
            state: session.state,
            discarded_datagrams,
            discarded_bytes,
        })
    }

    /// Expire every due session. The earlier of inspection and idle deadlines
    /// determines the reason when both have elapsed.
    pub fn expire(&mut self, now: Instant) -> Vec<ClosedSession> {
        let mut due = self
            .sessions
            .iter()
            .filter_map(|(id, session)| expiration_reason(session, now).map(|reason| (*id, reason)))
            .collect::<Vec<_>>();
        due.sort_unstable_by_key(|(id, _)| *id);
        let mut closed = Vec::with_capacity(due.len());
        for (id, reason) in due {
            if let Ok(session) = self.close(id, reason) {
                closed.push(session);
            }
        }
        closed
    }

    fn check_buffer_limits(&self, session: &Session, size: usize) -> Result<(), SessionError> {
        if size > self.limits.max_datagram_bytes {
            return Err(SessionError::DatagramTooLarge {
                size,
                limit: self.limits.max_datagram_bytes,
            });
        }
        if session.buffered.len() >= self.limits.max_buffered_datagrams_per_session {
            return Err(SessionError::SessionDatagramLimit {
                limit: self.limits.max_buffered_datagrams_per_session,
            });
        }
        if session
            .buffered_bytes
            .checked_add(size)
            .is_none_or(|total| total > self.limits.max_buffered_bytes_per_session)
        {
            return Err(SessionError::SessionByteLimit {
                limit: self.limits.max_buffered_bytes_per_session,
            });
        }
        if self.buffered_datagrams >= self.limits.max_buffered_datagrams_total {
            return Err(SessionError::GlobalDatagramLimit {
                limit: self.limits.max_buffered_datagrams_total,
            });
        }
        if self
            .buffered_bytes
            .checked_add(size)
            .is_none_or(|total| total > self.limits.max_buffered_bytes_total)
        {
            return Err(SessionError::GlobalByteLimit {
                limit: self.limits.max_buffered_bytes_total,
            });
        }
        Ok(())
    }
}

fn validate_limits(limits: UdpSessionLimits) -> Result<(), SessionError> {
    if limits.max_sessions == 0 {
        return Err(SessionError::InvalidLimits("max_sessions must be positive"));
    }
    if limits.max_known_cids_per_session == 0 {
        return Err(SessionError::InvalidLimits(
            "max_known_cids_per_session must be positive",
        ));
    }
    if limits.max_datagram_bytes == 0 {
        return Err(SessionError::InvalidLimits(
            "max_datagram_bytes must be positive",
        ));
    }
    if limits.max_buffered_datagrams_per_session == 0
        || limits.max_buffered_bytes_per_session == 0
        || limits.max_buffered_datagrams_total == 0
        || limits.max_buffered_bytes_total == 0
    {
        return Err(SessionError::InvalidLimits(
            "all buffering limits must be positive",
        ));
    }
    if limits.max_buffered_datagrams_per_session > limits.max_buffered_datagrams_total {
        return Err(SessionError::InvalidLimits(
            "per-session datagram limit exceeds global limit",
        ));
    }
    if limits.max_buffered_bytes_per_session > limits.max_buffered_bytes_total {
        return Err(SessionError::InvalidLimits(
            "per-session byte limit exceeds global limit",
        ));
    }
    if limits.max_datagram_bytes > limits.max_buffered_bytes_per_session {
        return Err(SessionError::InvalidLimits(
            "max_datagram_bytes exceeds per-session byte limit",
        ));
    }
    if limits.inspection_timeout.is_zero() || limits.idle_timeout.is_zero() {
        return Err(SessionError::InvalidLimits("timeouts must be positive"));
    }
    Ok(())
}

fn deadline(now: Instant, timeout: Duration) -> Result<Instant, SessionError> {
    now.checked_add(timeout)
        .ok_or(SessionError::DeadlineOverflow)
}

fn checked_add_usize(current: u64, bytes: usize) -> Result<u64, SessionError> {
    let bytes = u64::try_from(bytes).map_err(|_| SessionError::CounterOverflow)?;
    current
        .checked_add(bytes)
        .ok_or(SessionError::CounterOverflow)
}

fn state_inspection_deadline(state: &SessionState) -> Option<Instant> {
    match state {
        SessionState::Inspecting { deadline } | SessionState::RetryInspecting { deadline, .. } => {
            Some(*deadline)
        }
        SessionState::Routed { .. } | SessionState::Closed { .. } => None,
    }
}

fn expiration_reason(session: &Session, now: Instant) -> Option<CloseReason> {
    let inspection_deadline = state_inspection_deadline(&session.state);
    match inspection_deadline {
        Some(deadline) if now >= deadline && deadline <= session.idle_deadline => {
            Some(CloseReason::InspectionTimeout)
        }
        _ if now >= session.idle_deadline => Some(CloseReason::IdleTimeout),
        Some(deadline) if now >= deadline => Some(CloseReason::InspectionTimeout),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> UdpSessionLimits {
        UdpSessionLimits {
            max_sessions: 4,
            max_known_cids_per_session: 3,
            max_datagram_bytes: 8,
            max_buffered_datagrams_per_session: 3,
            max_buffered_bytes_per_session: 12,
            max_buffered_datagrams_total: 5,
            max_buffered_bytes_total: 20,
            inspection_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(10),
        }
    }

    fn cid(value: u8) -> ConnectionId {
        ConnectionId::new(&[value; 8]).unwrap()
    }

    fn key(listener: u64, client: &str, version: u32, cid_value: u8) -> SessionKey {
        SessionKey {
            listener_id: ListenerId(listener),
            client: client.parse().unwrap(),
            version,
            original_destination_connection_id: cid(cid_value),
        }
    }

    fn upstream() -> SocketAddr {
        "203.0.113.9:443".parse().unwrap()
    }

    #[test]
    fn validates_limits_and_connection_id_bounds() {
        let mut invalid = limits();
        invalid.max_sessions = 0;
        assert_eq!(
            UdpSessionTable::new(invalid).err(),
            Some(SessionError::InvalidLimits("max_sessions must be positive"))
        );
        assert_eq!(
            ConnectionId::new(&[]),
            Err(SessionError::InvalidConnectionIdLength { len: 0 })
        );
        assert_eq!(
            ConnectionId::new(&[0; 21]),
            Err(SessionError::InvalidConnectionIdLength { len: 21 })
        );
        assert_eq!(ConnectionId::new(&[0; 20]).unwrap().as_bytes(), &[0; 20]);
    }

    #[test]
    fn full_key_isolation_and_session_limit_are_enforced() {
        let now = Instant::now();
        let mut table = UdpSessionTable::new(limits()).unwrap();
        let keys = [
            key(1, "192.0.2.1:5000", 1, 1),
            key(2, "192.0.2.1:5000", 1, 1),
            key(1, "192.0.2.2:5000", 1, 1),
            key(1, "192.0.2.1:5000", 2, 1),
        ];
        let ids = keys
            .iter()
            .cloned()
            .map(|key| table.create_inspecting(key, now).unwrap())
            .collect::<Vec<_>>();
        for (key, id) in keys.iter().zip(ids) {
            assert_eq!(table.find_exact(key), Some(id));
        }
        assert!(matches!(
            table.create_inspecting(key(1, "192.0.2.1:5000", 1, 2), now),
            Err(SessionError::SessionLimit { limit: 4 })
        ));
        assert_eq!(table.totals().live_sessions, 4);
    }

    #[test]
    fn duplicate_full_key_is_rejected() {
        let now = Instant::now();
        let mut table = UdpSessionTable::new(limits()).unwrap();
        let key = key(1, "192.0.2.1:5000", 1, 1);
        let id = table.create_inspecting(key.clone(), now).unwrap();
        assert_eq!(
            table.create_inspecting(key, now),
            Err(SessionError::SessionAlreadyExists(id))
        );
    }

    #[test]
    fn unique_client_path_lookup_fails_closed_on_multiple_connections() {
        let now = Instant::now();
        let mut table = UdpSessionTable::new(limits()).unwrap();
        let client = "192.0.2.1:5000".parse().unwrap();
        assert_eq!(
            table.find_unique_client_path(ListenerId(1), client),
            Ok(None)
        );
        let first = table
            .create_inspecting(key(1, "192.0.2.1:5000", 1, 1), now)
            .unwrap();
        assert_eq!(
            table.find_unique_client_path(ListenerId(1), client),
            Ok(Some(first))
        );
        let second = table
            .create_inspecting(key(1, "192.0.2.1:5000", 1, 2), now)
            .unwrap();
        assert_eq!(
            table.find_unique_client_path(ListenerId(1), client),
            Err(SessionError::AmbiguousClientPath { owners: 2 })
        );
        table.close(second, CloseReason::InspectionFailed).unwrap();
        assert_eq!(
            table.find_unique_client_path(ListenerId(1), client),
            Ok(Some(first))
        );
        table.close(first, CloseReason::InspectionFailed).unwrap();
        assert_eq!(
            table.find_unique_client_path(ListenerId(1), client),
            Ok(None)
        );
    }

    #[test]
    fn datagrams_are_exact_fifo_and_route_is_pinned() {
        let now = Instant::now();
        let mut table = UdpSessionTable::new(limits()).unwrap();
        let id = table
            .create_inspecting(key(1, "192.0.2.1:5000", 1, 1), now)
            .unwrap();
        table
            .buffer_client_datagram(id, &[0, 1, 0, 2], now)
            .unwrap();
        table.buffer_client_datagram(id, &[], now).unwrap();
        table.buffer_client_datagram(id, &[9, 8], now).unwrap();
        assert_eq!(
            table.pop_buffered_datagram(id),
            Err(SessionError::InvalidTransition {
                from: StateKind::Inspecting,
                action: "drain buffered datagram from"
            })
        );

        table.route(id, upstream(), now).unwrap();
        assert_eq!(
            table.state(id),
            Some(&SessionState::Routed {
                upstream: upstream()
            })
        );
        assert!(matches!(
            table.route(id, "203.0.113.10:443".parse().unwrap(), now),
            Err(SessionError::InvalidTransition {
                from: StateKind::Routed,
                ..
            })
        ));
        assert_eq!(
            table.pop_buffered_datagram(id).unwrap(),
            Some(vec![0, 1, 0, 2])
        );
        assert_eq!(table.pop_buffered_datagram(id).unwrap(), Some(vec![]));
        assert_eq!(table.pop_buffered_datagram(id).unwrap(), Some(vec![9, 8]));
        assert_eq!(table.pop_buffered_datagram(id).unwrap(), None);
        table.begin_retry_inspection(id, now).unwrap();
        assert_eq!(
            table.state(id),
            Some(&SessionState::RetryInspecting {
                upstream: upstream(),
                deadline: now + Duration::from_secs(5),
            })
        );
        table
            .buffer_retry_client_datagram(id, &[7, 0, 7], now)
            .unwrap();
        assert!(matches!(
            table.pop_buffered_datagram(id),
            Err(SessionError::InvalidTransition {
                from: StateKind::RetryInspecting,
                ..
            })
        ));
        table.complete_retry_inspection(id, now).unwrap();
        assert_eq!(
            table.pop_buffered_datagram(id).unwrap(),
            Some(vec![7, 0, 7])
        );
        assert_eq!(table.pop_buffered_datagram(id).unwrap(), None);
        assert_eq!(table.totals().buffered_bytes, 0);
        assert_eq!(table.totals().buffered_datagrams, 0);
    }

    #[test]
    fn route_transitions_reject_elapsed_inspection_deadlines_without_tick() {
        let start = Instant::now();
        let deadline = start + Duration::from_secs(5);
        let mut table = UdpSessionTable::new(limits()).unwrap();
        let initial = table
            .create_inspecting(key(1, "192.0.2.1:5000", 1, 1), start)
            .unwrap();
        assert_eq!(
            table.route(initial, upstream(), deadline),
            Err(SessionError::InspectionDeadlineElapsed(initial))
        );
        assert!(matches!(
            table.state(initial),
            Some(SessionState::Inspecting { deadline: current }) if *current == deadline
        ));

        let retry = table
            .create_inspecting(key(1, "192.0.2.2:5000", 1, 2), start)
            .unwrap();
        table.route(retry, upstream(), start).unwrap();
        table.begin_retry_inspection(retry, start).unwrap();
        assert_eq!(
            table.complete_retry_inspection(retry, deadline),
            Err(SessionError::InspectionDeadlineElapsed(retry))
        );
        assert!(matches!(
            table.state(retry),
            Some(SessionState::RetryInspecting { deadline: current, .. }) if *current == deadline
        ));
    }

    #[test]
    fn per_session_and_global_buffer_limits_fail_without_mutation() {
        let now = Instant::now();
        let mut table = UdpSessionTable::new(limits()).unwrap();
        let first = table
            .create_inspecting(key(1, "192.0.2.1:5000", 1, 1), now)
            .unwrap();
        let second = table
            .create_inspecting(key(1, "192.0.2.2:5000", 1, 2), now)
            .unwrap();
        assert!(matches!(
            table.buffer_client_datagram(first, &[0; 9], now),
            Err(SessionError::DatagramTooLarge { .. })
        ));
        table.buffer_client_datagram(first, &[1; 8], now).unwrap();
        table.buffer_client_datagram(first, &[2; 4], now).unwrap();
        assert!(matches!(
            table.buffer_client_datagram(first, &[3], now),
            Err(SessionError::SessionByteLimit { .. })
        ));
        table.buffer_client_datagram(second, &[4; 8], now).unwrap();
        assert!(matches!(
            table.buffer_client_datagram(second, &[5], now),
            Err(SessionError::GlobalByteLimit { limit: 20 })
        ));
        assert_eq!(
            table.totals(),
            SessionTotals {
                live_sessions: 2,
                buffered_datagrams: 3,
                buffered_bytes: 20
            }
        );
    }

    #[test]
    fn datagram_count_limits_are_independent_of_byte_limits() {
        let now = Instant::now();
        let mut count_limits = limits();
        count_limits.max_buffered_datagrams_per_session = 2;
        count_limits.max_buffered_datagrams_total = 3;
        let mut table = UdpSessionTable::new(count_limits).unwrap();
        let first = table
            .create_inspecting(key(1, "192.0.2.1:5000", 1, 1), now)
            .unwrap();
        let second = table
            .create_inspecting(key(1, "192.0.2.2:5000", 1, 2), now)
            .unwrap();
        table.buffer_client_datagram(first, &[], now).unwrap();
        table.buffer_client_datagram(first, &[], now).unwrap();
        assert_eq!(
            table.buffer_client_datagram(first, &[], now),
            Err(SessionError::SessionDatagramLimit { limit: 2 })
        );
        table.buffer_client_datagram(second, &[], now).unwrap();
        assert_eq!(
            table.buffer_client_datagram(second, &[], now),
            Err(SessionError::GlobalDatagramLimit { limit: 3 })
        );
        assert_eq!(table.totals().buffered_datagrams, 3);
        assert_eq!(table.totals().buffered_bytes, 0);
    }

    #[test]
    fn cid_scope_collision_and_registration_bound_are_explicit() {
        let now = Instant::now();
        let mut table = UdpSessionTable::new(limits()).unwrap();
        let first = table
            .create_inspecting(key(1, "192.0.2.1:5000", 1, 1), now)
            .unwrap();
        let second = table
            .create_inspecting(key(1, "192.0.2.2:5000", 1, 1), now)
            .unwrap();
        assert_eq!(
            table.locate_client_path(
                ListenerId(1),
                "192.0.2.3:5000".parse().unwrap(),
                1,
                &cid(1),
                now
            ),
            Err(SessionError::AmbiguousConnectionId { owners: 2 })
        );
        assert_eq!(
            table.register_connection_id(first, cid(2)).unwrap(),
            CidRegistration::Unique
        );
        assert_eq!(
            table.register_connection_id(second, cid(2)).unwrap(),
            CidRegistration::Ambiguous { owners: 2 }
        );
        assert_eq!(
            table.register_connection_id(first, cid(2)).unwrap(),
            CidRegistration::AlreadyKnown
        );
        assert_eq!(
            table.register_connection_id(first, cid(3)).unwrap(),
            CidRegistration::Unique
        );
        assert!(matches!(
            table.register_connection_id(first, cid(4)),
            Err(SessionError::KnownCidLimit { limit: 3 })
        ));

        let other_listener = table
            .create_inspecting(key(2, "192.0.2.1:5000", 1, 1), now)
            .unwrap();
        assert_eq!(
            table.locate_client_path(
                ListenerId(2),
                "192.0.2.1:5000".parse().unwrap(),
                1,
                &cid(1),
                now
            ),
            Ok(Some(ClientPath::Existing {
                session_id: other_listener
            }))
        );

        table.close(second, CloseReason::InspectionFailed).unwrap();
        assert_eq!(
            table.locate_client_path(
                ListenerId(1),
                "192.0.2.1:5000".parse().unwrap(),
                1,
                &cid(2),
                now
            ),
            Ok(Some(ClientPath::Existing { session_id: first }))
        );
    }

    #[test]
    fn rebinding_requires_unique_known_cid_and_routed_state() {
        let now = Instant::now();
        let mut table = UdpSessionTable::new(limits()).unwrap();
        let original = key(1, "192.0.2.1:5000", 1, 1);
        let id = table.create_inspecting(original.clone(), now).unwrap();
        assert_eq!(
            table.locate_client_path(
                ListenerId(1),
                "192.0.2.9:6000".parse().unwrap(),
                1,
                &cid(1),
                now
            ),
            Err(SessionError::RebindingBeforeRoute(id))
        );
        assert_eq!(
            table.locate_client_path(
                ListenerId(1),
                "192.0.2.9:6000".parse().unwrap(),
                1,
                &cid(9),
                now
            ),
            Ok(None)
        );

        table.route(id, upstream(), now).unwrap();
        table.validate_client_address(id).unwrap();
        let new_client = "192.0.2.9:6000".parse().unwrap();
        assert_eq!(
            table
                .locate_client_path(ListenerId(1), new_client, 1, &cid(1), now)
                .unwrap(),
            Some(ClientPath::Rebound {
                session_id: id,
                previous_client: original.client
            })
        );
        assert_eq!(table.find_exact(&original), None);
        let mut rebound_key = original;
        rebound_key.client = new_client;
        assert_eq!(table.find_exact(&rebound_key), Some(id));
        assert_eq!(
            table.find_unique_client_path(ListenerId(1), "192.0.2.1:5000".parse().unwrap()),
            Ok(None)
        );
        assert_eq!(
            table.find_unique_client_path(ListenerId(1), new_client),
            Ok(Some(id))
        );
        assert_eq!(table.send_allowance(id).unwrap(), SendAllowance::Limited(0));
    }

    #[test]
    fn anti_amplification_is_exactly_three_x_until_validation() {
        let now = Instant::now();
        let mut table = UdpSessionTable::new(limits()).unwrap();
        let id = table
            .create_inspecting(key(1, "192.0.2.1:5000", 1, 1), now)
            .unwrap();
        table.record_client_bytes_received(id, 100, now).unwrap();
        assert_eq!(
            table.send_allowance(id).unwrap(),
            SendAllowance::Limited(300)
        );
        table.record_client_bytes_sent(id, 299, now).unwrap();
        assert_eq!(table.send_allowance(id).unwrap(), SendAllowance::Limited(1));
        assert_eq!(
            table.record_client_bytes_sent(id, 2, now),
            Err(SessionError::AmplificationLimit {
                attempted: 2,
                allowance: 1
            })
        );
        assert_eq!(table.send_allowance(id).unwrap(), SendAllowance::Limited(1));
        table.record_client_bytes_sent(id, 1, now).unwrap();
        assert_eq!(table.send_allowance(id).unwrap(), SendAllowance::Limited(0));
        table.validate_client_address(id).unwrap();
        assert_eq!(table.send_allowance(id).unwrap(), SendAllowance::Unlimited);
        table.record_client_bytes_sent(id, 10_000, now).unwrap();
    }

    #[test]
    fn expiration_uses_earliest_deadline_and_releases_indexes_and_bytes() {
        let start = Instant::now();
        let mut table = UdpSessionTable::new(limits()).unwrap();
        let inspection = table
            .create_inspecting(key(1, "192.0.2.1:5000", 1, 1), start)
            .unwrap();
        table
            .buffer_client_datagram(inspection, &[1, 2, 3], start + Duration::from_secs(4))
            .unwrap();
        let routed = table
            .create_inspecting(key(1, "192.0.2.2:5000", 1, 2), start)
            .unwrap();
        table.route(routed, upstream(), start).unwrap();
        let retry = table
            .create_inspecting(key(1, "192.0.2.3:5000", 1, 3), start)
            .unwrap();
        table.route(retry, upstream(), start).unwrap();
        table
            .begin_retry_inspection(retry, start + Duration::from_secs(1))
            .unwrap();
        table
            .buffer_retry_client_datagram(retry, &[4, 5], start + Duration::from_secs(2))
            .unwrap();

        let closed = table.expire(start + Duration::from_secs(5));
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].id, inspection);
        assert_eq!(
            closed[0].state,
            SessionState::Closed {
                reason: CloseReason::InspectionTimeout
            }
        );
        assert_eq!(closed[0].discarded_datagrams, 1);
        assert_eq!(closed[0].discarded_bytes, 3);
        assert_eq!(table.totals().buffered_bytes, 2);
        assert_eq!(
            table.locate_client_path(
                ListenerId(1),
                "192.0.2.1:5000".parse().unwrap(),
                1,
                &cid(1),
                start
            ),
            Ok(None)
        );

        let closed = table.expire(start + Duration::from_secs(6));
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].id, retry);
        assert_eq!(
            closed[0].state,
            SessionState::Closed {
                reason: CloseReason::InspectionTimeout
            }
        );
        assert_eq!(closed[0].discarded_datagrams, 1);
        assert_eq!(closed[0].discarded_bytes, 2);
        assert_eq!(table.totals().buffered_bytes, 0);

        let closed = table.expire(start + Duration::from_secs(10));
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].id, routed);
        assert_eq!(
            closed[0].state,
            SessionState::Closed {
                reason: CloseReason::IdleTimeout
            }
        );
        assert_eq!(table.totals().live_sessions, 0);
    }

    #[test]
    fn routed_traffic_refreshes_idle_deadline() {
        let start = Instant::now();
        let mut table = UdpSessionTable::new(limits()).unwrap();
        let id = table
            .create_inspecting(key(1, "192.0.2.1:5000", 1, 1), start)
            .unwrap();
        table.route(id, upstream(), start).unwrap();
        table
            .record_client_bytes_received(id, 1, start + Duration::from_secs(9))
            .unwrap();
        assert!(table.expire(start + Duration::from_secs(10)).is_empty());
        let closed = table.expire(start + Duration::from_secs(19));
        assert_eq!(closed.len(), 1);
        assert_eq!(
            closed[0].state,
            SessionState::Closed {
                reason: CloseReason::IdleTimeout
            }
        );
    }

    #[test]
    fn explicit_close_is_terminal_and_frees_capacity() {
        let now = Instant::now();
        let mut one = limits();
        one.max_sessions = 1;
        let mut table = UdpSessionTable::new(one).unwrap();
        let id = table
            .create_inspecting(key(1, "192.0.2.1:5000", 1, 1), now)
            .unwrap();
        table.buffer_client_datagram(id, &[1, 2], now).unwrap();
        let closed = table.close(id, CloseReason::InspectionFailed).unwrap();
        assert_eq!(
            closed.state,
            SessionState::Closed {
                reason: CloseReason::InspectionFailed
            }
        );
        assert_eq!(closed.discarded_bytes, 2);
        assert_eq!(table.totals().live_sessions, 0);
        assert_eq!(table.state(id), None);
        table
            .create_inspecting(key(1, "192.0.2.2:5000", 1, 2), now)
            .unwrap();
    }
}
