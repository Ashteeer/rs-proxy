//! Bounded UDP/QUIC listener and relay runtime.
//!
//! The runtime accepts only authenticated QUIC v1/v2 Initial destinations,
//! retains original client datagrams in `udp_session`, resolves through the
//! independent resolver, and pins one connected upstream UDP socket. It
//! intentionally supports only one active connection per listener/client tuple;
//! path migration and short-header CID demultiplexing remain unsupported.

use std::{
    collections::HashMap,
    future::Future,
    io, mem,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use thiserror::Error;
use tokio::{
    net::UdpSocket,
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::JoinHandle,
    time::{MissedTickBehavior, interval, sleep, timeout},
};
use tracing::{debug, info, warn};

use crate::{
    connector::{ConnectError, connect_udp},
    dns::{DnsError, IndependentResolver},
    firewall::{FirewallError, FirewallProtocol, FirstResponseReservation, KernelFirewall},
    inspect::quic::{
        QuicInitialInspector, QuicInspectConfig, QuicInspectError, QuicInspection,
        QuicLongHeaderKind, QuicRetryAcceptance, parse_client_initial_header,
        parse_client_long_header, parse_server_initial_source_connection_id,
        validate_client_long_header_datagram_identity,
    },
    ipset::{AdmissionDecision, IpSetAdmission},
    metrics::{ActiveFlowGuard, RuntimeMetrics},
    policy::{AddressPolicy, PolicyRefreshError},
    udp_session::{
        CloseReason, ConnectionId, ListenerId, SessionError, SessionId, SessionKey, SessionState,
        StateKind, UdpSessionLimits, UdpSessionTable,
    },
};

const UDP_DATAGRAM_BYTES: usize = 65_535;
const EXPIRY_INTERVAL: Duration = Duration::from_millis(50);
const MAX_QUEUED_RUNTIME_EVENTS: usize = 256;

pub(crate) struct BoundUdpListener {
    pub(crate) socket: UdpSocket,
    pub(crate) address: SocketAddr,
    pub(crate) id: ListenerId,
}

#[derive(Clone)]
pub(crate) struct UdpRuntimeConfig {
    pub(crate) policy: Arc<AddressPolicy>,
    pub(crate) resolver: IndependentResolver,
    pub(crate) session_slots: Arc<Semaphore>,
    pub(crate) inspect_timeout: Duration,
    pub(crate) connect_timeout: Duration,
    pub(crate) send_timeout: Duration,
    pub(crate) idle_timeout: Duration,
    pub(crate) inspect_max_bytes: usize,
    pub(crate) max_addresses_per_lookup: usize,
    pub(crate) max_sessions: usize,
    pub(crate) ipset: Option<Arc<IpSetAdmission>>,
    pub(crate) firewall: Option<Arc<KernelFirewall>>,
    pub(crate) metrics: Arc<RuntimeMetrics>,
}

enum RuntimePhase {
    Inspecting(Box<QuicInitialInspector>),
    Resolving,
    Routed(mpsc::Sender<()>),
}

struct RuntimeSession {
    phase: RuntimePhase,
    task: Option<JoinHandle<()>>,
    writer_task: Option<JoinHandle<()>>,
    retry: Option<Arc<Mutex<RuntimeRetry>>>,
    _permit: OwnedSemaphorePermit,
    client: SocketAddr,
    version: u32,
    active_initial_dcid: Vec<u8>,
    client_initial_scid: Vec<u8>,
    first_response_only: bool,
    first_response_reservation: Option<FirstResponseReservation>,
    _active_metrics: ActiveFlowGuard,
}

impl RuntimeSession {
    async fn stop_tasks(&mut self) {
        abort_and_join(&mut self.task).await;
        abort_and_join(&mut self.writer_task).await;
    }
}

impl Drop for RuntimeSession {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
        if let Some(task) = &self.writer_task {
            task.abort();
        }
    }
}

enum RuntimeEvent {
    RouteReady {
        id: SessionId,
        result: Result<ConnectedUpstream, UdpRouteError>,
    },
    RelayEnded {
        id: SessionId,
        error: Option<String>,
    },
    ClientDatagram {
        id: SessionId,
        client: SocketAddr,
        datagram: Vec<u8>,
        close_after_send: bool,
    },
}

struct ConnectedUpstream {
    socket: UdpSocket,
    address: SocketAddr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetryPhase {
    AwaitingServer,
    AwaitingPostRetry,
    Complete,
}

struct RuntimeRetry {
    inspector: Box<QuicInitialInspector>,
    expected_server_name: String,
    version: u32,
    client_initial_scid: Vec<u8>,
    active_initial_dcid: Vec<u8>,
    server_initial_scid: Option<Vec<u8>>,
    phase: RetryPhase,
}

enum RetryClientProgress {
    Pending,
    Complete { active_initial_dcid: Vec<u8> },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetryUpstreamDisposition {
    Passthrough,
    Accepted,
    Duplicate,
}

impl RuntimeRetry {
    fn new(
        inspector: Box<QuicInitialInspector>,
        inspection: &QuicInspection,
        client_initial_scid: Vec<u8>,
    ) -> Self {
        Self {
            inspector,
            expected_server_name: inspection.server_name.clone(),
            version: inspection.version.wire(),
            client_initial_scid,
            active_initial_dcid: inspection.destination_connection_id.clone(),
            server_initial_scid: None,
            phase: RetryPhase::AwaitingServer,
        }
    }

    const fn is_awaiting_post_retry(&self) -> bool {
        matches!(self.phase, RetryPhase::AwaitingPostRetry)
    }

    fn observe_upstream(
        &mut self,
        datagram: &[u8],
    ) -> Result<RetryUpstreamDisposition, RetryRuntimeError> {
        let accepted = self.inspector.accept_retry_if_present(datagram)?;
        match (self.phase, accepted) {
            (RetryPhase::AwaitingServer, Some(QuicRetryAcceptance::New(retry))) => {
                self.active_initial_dcid = retry.retry_source_connection_id;
                self.server_initial_scid = None;
                self.phase = RetryPhase::AwaitingPostRetry;
                Ok(RetryUpstreamDisposition::Accepted)
            }
            (RetryPhase::AwaitingServer | RetryPhase::Complete, None) => {
                self.observe_server_initial(datagram)?;
                self.phase = RetryPhase::Complete;
                Ok(RetryUpstreamDisposition::Passthrough)
            }
            (RetryPhase::AwaitingPostRetry, None) => {
                Err(RetryRuntimeError::UpstreamBeforePostRetry)
            }
            (
                RetryPhase::AwaitingPostRetry | RetryPhase::Complete,
                Some(QuicRetryAcceptance::Duplicate(_)),
            ) => Ok(RetryUpstreamDisposition::Duplicate),
            (_, Some(QuicRetryAcceptance::New(_)))
            | (RetryPhase::AwaitingServer, Some(QuicRetryAcceptance::Duplicate(_))) => {
                Err(RetryRuntimeError::RetryAfterWindowClosed)
            }
        }
    }

    fn observe_server_initial(&mut self, datagram: &[u8]) -> Result<(), RetryRuntimeError> {
        let Some(scid) = parse_server_initial_source_connection_id(
            datagram,
            self.version,
            &self.client_initial_scid,
        )?
        else {
            return Ok(());
        };
        if let Some(previous) = &self.server_initial_scid
            && previous != &scid
        {
            return Err(RetryRuntimeError::ServerInitialConnectionIdChanged);
        }
        self.active_initial_dcid.clone_from(&scid);
        self.server_initial_scid = Some(scid);
        Ok(())
    }

    fn active_initial_dcid(&self) -> &[u8] {
        &self.active_initial_dcid
    }

    fn inspect_post_retry(
        &mut self,
        datagram: &[u8],
    ) -> Result<RetryClientProgress, RetryRuntimeError> {
        if self.phase != RetryPhase::AwaitingPostRetry {
            return Err(RetryRuntimeError::PostRetryWithoutTransition);
        }
        let Some(inspection) = self.inspector.inspect_datagram(datagram)? else {
            return Ok(RetryClientProgress::Pending);
        };
        if inspection.server_name != self.expected_server_name {
            return Err(RetryRuntimeError::DestinationChanged {
                expected: self.expected_server_name.clone(),
                actual: inspection.server_name,
            });
        }
        self.phase = RetryPhase::Complete;
        self.active_initial_dcid
            .clone_from(&inspection.destination_connection_id);
        self.server_initial_scid = None;
        Ok(RetryClientProgress::Complete {
            active_initial_dcid: inspection.destination_connection_id,
        })
    }
}

#[derive(Debug, Error)]
enum RetryRuntimeError {
    #[error("QUIC Retry inspection failed: {0}")]
    Inspect(#[from] QuicInspectError),
    #[error("upstream sent data before the post-Retry Initial authenticated")]
    UpstreamBeforePostRetry,
    #[error("post-Retry client data arrived without an authenticated Retry transition")]
    PostRetryWithoutTransition,
    #[error("upstream supplied Retry after the one-packet Retry window closed")]
    RetryAfterWindowClosed,
    #[error("pinned upstream changed its server Initial source connection ID")]
    ServerInitialConnectionIdChanged,
    #[error("post-Retry SNI changed from {expected} to {actual}")]
    DestinationChanged { expected: String, actual: String },
}

#[derive(Debug, Error)]
enum UdpRouteError {
    #[error("DNS resolution failed: {0}")]
    Dns(#[from] DnsError),
    #[error("upstream UDP connection failed: {0}")]
    Connect(#[from] ConnectError),
}

/// Serve one bound UDP listener until shutdown, expiring every session and
/// aborting all per-session work before returning.
pub(crate) async fn run_udp_listener(
    listener: BoundUdpListener,
    config: UdpRuntimeConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), UdpRuntimeError> {
    let BoundUdpListener {
        socket,
        address,
        id: listener_id,
    } = listener;
    let socket = Arc::new(socket);
    let limits = session_limits(&config);
    let table = Arc::new(Mutex::new(UdpSessionTable::new(limits)?));
    let mut sessions = HashMap::<SessionId, RuntimeSession>::new();
    let event_capacity = config.max_sessions.clamp(1, MAX_QUEUED_RUNTIME_EVENTS);
    let (event_tx, mut event_rx) = mpsc::channel(event_capacity);
    let mut expiry = interval(EXPIRY_INTERVAL);
    expiry.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut receive_buffer = vec![0_u8; UDP_DATAGRAM_BYTES];
    // A datagram may already be queued in the listener socket while the
    // first-response flow tuple is added to Netfilter. Keep the same bounded
    // userspace tombstone so that pre-rule queued packets cannot start a new
    // session after the terminal response.
    let mut first_response_blocks = HashMap::<SocketAddr, Instant>::new();

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            received = socket.recv_from(&mut receive_buffer) => {
                match received {
                    Ok((length, client)) => {
                        if first_response_blocks
                            .get(&client)
                            .is_some_and(|deadline| *deadline > Instant::now())
                        {
                            config.metrics.udp_datagram_dropped();
                            continue;
                        }
                        first_response_blocks.remove(&client);
                        let datagram = &receive_buffer[..length];
                        let mut drop_accounted_by_close = false;
                        if let Err(error) = handle_client_datagram(
                            listener_id,
                            address,
                            client,
                            datagram,
                            &config,
                            &table,
                            &mut sessions,
                            &event_tx,
                            &mut drop_accounted_by_close,
                        ).await {
                            if !drop_accounted_by_close {
                                config.metrics.udp_datagram_dropped();
                            }
                            error.record_metrics(&config.metrics);
                        }
                    }
                    Err(error) => {
                        warn!(%error, listen = %address, "UDP receive failed; retrying");
                        sleep(Duration::from_millis(100)).await;
                    }
                }
            }
            event = event_rx.recv() => {
                if let Some(event) = event {
                    handle_runtime_event(
                        event,
                        &socket,
                        &table,
                        &mut sessions,
                        &event_tx,
                        &config.metrics,
                        config.firewall.as_deref(),
                        address,
                        &mut first_response_blocks,
                        config.idle_timeout,
                        config.send_timeout,
                    ).await;
                }
            }
            _ = expiry.tick() => {
                expire_sessions(&table, &mut sessions, &config.metrics).await;
                let now = Instant::now();
                first_response_blocks.retain(|_, deadline| *deadline > now);
            }
        }
    }

    close_all_sessions(
        &table,
        &mut sessions,
        CloseReason::Shutdown,
        &config.metrics,
    )
    .await;
    info!(listen = %address, protocol = "udp", "listener stopped");
    Ok(())
}

fn session_limits(config: &UdpRuntimeConfig) -> UdpSessionLimits {
    UdpSessionLimits {
        max_sessions: config.max_sessions,
        inspection_timeout: config.inspect_timeout,
        idle_timeout: config.idle_timeout,
        ..UdpSessionLimits::default()
    }
}

fn first_response_only(
    config: &UdpRuntimeConfig,
    client: SocketAddr,
) -> Result<bool, UdpDatagramError> {
    match &config.ipset {
        Some(ipset) => match ipset.decide(client.ip())? {
            AdmissionDecision::Relay => Ok(false),
            AdmissionDecision::FirstResponse => Ok(true),
            AdmissionDecision::CloseAccepted | AdmissionDecision::HoldAcceptedSilent => {
                Err(UdpDatagramError::SourceRejected)
            }
        },
        None => Ok(false),
    }
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "one admission-and-creation transaction keeps UDP session state rollback atomic"
)]
async fn handle_client_datagram(
    listener_id: ListenerId,
    listener_address: SocketAddr,
    client: SocketAddr,
    datagram: &[u8],
    config: &UdpRuntimeConfig,
    table: &Arc<Mutex<UdpSessionTable>>,
    sessions: &mut HashMap<SessionId, RuntimeSession>,
    event_tx: &mpsc::Sender<RuntimeEvent>,
    drop_accounted_by_close: &mut bool,
) -> Result<(), UdpDatagramError> {
    let upstream_port = listener_address.port();
    if datagram.is_empty() {
        return Err(UdpDatagramError::NotQuicInitial);
    }

    let existing = table
        .lock()
        .await
        .find_unique_client_path(listener_id, client)?;
    if let Some(id) = existing {
        return handle_existing_datagram_and_close(
            id,
            upstream_port,
            datagram,
            config,
            table,
            sessions,
            event_tx,
            drop_accounted_by_close,
        )
        .await;
    }

    let first_response_only = first_response_only(config, client)?;
    let first_response_reservation = if first_response_only {
        Some(
            config
                .firewall
                .as_ref()
                .ok_or(FirewallError::NotActive)?
                .reserve_first_response(FirewallProtocol::Udp, listener_address, client)?,
        )
    } else {
        None
    };
    let header = parse_client_initial_header(datagram)?;
    let original_dcid = ConnectionId::new(&header.destination_connection_id)?;
    let permit = Arc::clone(&config.session_slots)
        .try_acquire_owned()
        .map_err(|_| UdpDatagramError::SessionLimit)?;
    let key = SessionKey {
        listener_id,
        client,
        version: header.version.wire(),
        original_destination_connection_id: original_dcid,
    };
    let now = Instant::now();
    let id = {
        let mut table = table.lock().await;
        let id = table.create_inspecting(key, now)?;
        if let Err(error) = table.buffer_client_datagram(id, datagram, now) {
            let _ = table.close(id, CloseReason::InspectionFailed);
            return Err(error.into());
        }
        id
    };

    let inspect_config = QuicInspectConfig {
        max_crypto_bytes: config.inspect_max_bytes,
        max_total_datagram_bytes: UdpSessionLimits::default().max_buffered_bytes_per_session,
        max_datagrams: UdpSessionLimits::default().max_buffered_datagrams_per_session,
        ..QuicInspectConfig::default()
    };
    let mut inspector = QuicInitialInspector::new(inspect_config)?;
    let inspected = match inspector.inspect_datagram(datagram) {
        Ok(inspected) => inspected,
        Err(error) => {
            let _ = table.lock().await.close(id, CloseReason::InspectionFailed);
            return Err(error.into());
        }
    };
    config.metrics.udp_session_started();
    let active_metrics = config.metrics.track_udp_session();
    sessions.insert(
        id,
        RuntimeSession {
            phase: RuntimePhase::Inspecting(Box::new(inspector)),
            task: None,
            writer_task: None,
            retry: None,
            _permit: permit,
            client,
            version: header.version.wire(),
            active_initial_dcid: header.destination_connection_id,
            client_initial_scid: header.source_connection_id,
            first_response_only,
            first_response_reservation,
            _active_metrics: active_metrics,
        },
    );
    if let Some(inspection) = inspected
        && let Err(error) =
            begin_resolution(id, inspection, upstream_port, config, sessions, event_tx)
    {
        let discarded = close_runtime_session(
            id,
            CloseReason::InspectionFailed,
            table,
            sessions,
            &config.metrics,
        )
        .await;
        *drop_accounted_by_close = discarded > 0;
        return Err(error);
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the wrapper preserves exact drop accounting across the session close"
)]
async fn handle_existing_datagram_and_close(
    id: SessionId,
    upstream_port: u16,
    datagram: &[u8],
    config: &UdpRuntimeConfig,
    table: &Arc<Mutex<UdpSessionTable>>,
    sessions: &mut HashMap<SessionId, RuntimeSession>,
    event_tx: &mpsc::Sender<RuntimeEvent>,
    drop_accounted_by_close: &mut bool,
) -> Result<(), UdpDatagramError> {
    let (result, current_datagram_buffered) = handle_existing_datagram(
        id,
        upstream_port,
        datagram,
        config,
        table,
        sessions,
        event_tx,
    )
    .await;
    if let Err(error) = &result
        && error.terminates_session()
    {
        let discarded = close_runtime_session(
            id,
            CloseReason::InspectionFailed,
            table,
            sessions,
            &config.metrics,
        )
        .await;
        *drop_accounted_by_close =
            current_drop_accounted_by_close(current_datagram_buffered, discarded);
    }
    result
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the transition is explicit about listener-owned state and route dependencies"
)]
async fn handle_existing_datagram(
    id: SessionId,
    upstream_port: u16,
    datagram: &[u8],
    config: &UdpRuntimeConfig,
    table: &Arc<Mutex<UdpSessionTable>>,
    sessions: &mut HashMap<SessionId, RuntimeSession>,
    event_tx: &mpsc::Sender<RuntimeEvent>,
) -> (Result<(), UdpDatagramError>, bool) {
    let mut current_datagram_buffered = false;
    let result = async {
        let routed = sessions.get(&id).and_then(|session| match &session.phase {
            RuntimePhase::Routed(writer) => session.retry.as_ref().map(|retry| {
                (
                    writer.clone(),
                    Arc::clone(retry),
                    session.version,
                    session.client_initial_scid.clone(),
                )
            }),
            RuntimePhase::Inspecting(_) | RuntimePhase::Resolving => None,
        });
        if let Some((writer, retry, version, client_scid)) = routed {
            let (awaiting_post_retry, active_initial_dcid) = {
                let retry = retry.lock().await;
                (
                    retry.is_awaiting_post_retry(),
                    retry.active_initial_dcid().to_vec(),
                )
            };
            if awaiting_post_retry {
                let kind = require_matching_initial_or_zero_rtt(
                    version,
                    &active_initial_dcid,
                    &client_scid,
                    datagram,
                )?;
                table
                    .lock()
                    .await
                    .buffer_retry_client_datagram(id, datagram, Instant::now())?;
                current_datagram_buffered = true;
                let progress = if kind == QuicLongHeaderKind::ZeroRtt {
                    RetryClientProgress::Pending
                } else {
                    retry.lock().await.inspect_post_retry(datagram)?
                };
                match progress {
                    RetryClientProgress::Pending => return Ok(()),
                    RetryClientProgress::Complete {
                        active_initial_dcid,
                    } => {
                        table
                            .lock()
                            .await
                            .complete_retry_inspection(id, Instant::now())?;
                        let session = sessions
                            .get_mut(&id)
                            .ok_or(UdpDatagramError::RuntimeStateMissing)?;
                        session.active_initial_dcid = active_initial_dcid;
                        wake_upstream_writer(&writer)?;
                        debug!(session = ?id, "authenticated post-Retry Initial flight relayed");
                        return Ok(());
                    }
                }
            }

            require_compatible_routed_datagram(
                version,
                &active_initial_dcid,
                &client_scid,
                datagram,
            )?;
            table
                .lock()
                .await
                .queue_routed_client_datagram(id, datagram, Instant::now())?;
            current_datagram_buffered = true;
            wake_upstream_writer(&writer)?;
            return Ok(());
        }

        let session = sessions
            .get_mut(&id)
            .ok_or(UdpDatagramError::RuntimeStateMissing)?;
        let mut completed = None;
        match &mut session.phase {
            RuntimePhase::Inspecting(inspector) => {
                require_matching_initial_or_zero_rtt(
                    session.version,
                    &session.active_initial_dcid,
                    &session.client_initial_scid,
                    datagram,
                )?;
                let now = Instant::now();
                table
                    .lock()
                    .await
                    .buffer_client_datagram(id, datagram, now)?;
                current_datagram_buffered = true;
                completed = inspector.inspect_datagram(datagram)?;
            }
            RuntimePhase::Resolving => {
                require_matching_initial_or_zero_rtt(
                    session.version,
                    &session.active_initial_dcid,
                    &session.client_initial_scid,
                    datagram,
                )?;
                table
                    .lock()
                    .await
                    .buffer_client_datagram(id, datagram, Instant::now())?;
                current_datagram_buffered = true;
            }
            RuntimePhase::Routed(_) => return Err(UdpDatagramError::RuntimeStateMissing),
        }

        if let Some(inspection) = completed {
            begin_resolution(id, inspection, upstream_port, config, sessions, event_tx)?;
        }
        Ok(())
    }
    .await;
    (result, current_datagram_buffered)
}

fn require_matching_initial_or_zero_rtt(
    version: u32,
    active_initial_dcid: &[u8],
    client_scid: &[u8],
    datagram: &[u8],
) -> Result<QuicLongHeaderKind, UdpDatagramError> {
    let header = parse_client_long_header(datagram)?;
    if !matches!(
        header.kind,
        QuicLongHeaderKind::Initial | QuicLongHeaderKind::ZeroRtt
    ) || header.version.wire() != version
        || header.destination_connection_id != active_initial_dcid
        || header.source_connection_id != client_scid
    {
        return Err(UdpDatagramError::SessionMismatch);
    }
    if header.kind == QuicLongHeaderKind::Initial {
        parse_client_initial_header(datagram)?;
    }
    validate_client_long_header_datagram_identity(
        datagram,
        version,
        active_initial_dcid,
        client_scid,
    )?;
    Ok(header.kind)
}

fn require_compatible_routed_datagram(
    version: u32,
    active_initial_dcid: &[u8],
    client_scid: &[u8],
    datagram: &[u8],
) -> Result<(), UdpDatagramError> {
    if datagram.first().is_some_and(|first| first & 0x80 != 0) {
        validate_client_long_header_datagram_identity(
            datagram,
            version,
            active_initial_dcid,
            client_scid,
        )?;
    }
    Ok(())
}

fn begin_resolution(
    id: SessionId,
    inspection: QuicInspection,
    upstream_port: u16,
    config: &UdpRuntimeConfig,
    sessions: &mut HashMap<SessionId, RuntimeSession>,
    event_tx: &mpsc::Sender<RuntimeEvent>,
) -> Result<(), UdpDatagramError> {
    let session = sessions
        .get_mut(&id)
        .ok_or(UdpDatagramError::RuntimeStateMissing)?;
    let previous_phase = mem::replace(&mut session.phase, RuntimePhase::Resolving);
    let RuntimePhase::Inspecting(inspector) = previous_phase else {
        session.phase = previous_phase;
        return Err(UdpDatagramError::RuntimeStateMissing);
    };
    session.retry = Some(Arc::new(Mutex::new(RuntimeRetry::new(
        inspector,
        &inspection,
        session.client_initial_scid.clone(),
    ))));
    let resolver = config.resolver.clone();
    let policy = Arc::clone(&config.policy);
    let connect_timeout = config.connect_timeout;
    let max_addresses = config.max_addresses_per_lookup;
    let event_tx = event_tx.clone();
    session.task = Some(tokio::spawn(async move {
        let result = resolve_and_connect_udp(
            resolver,
            policy,
            &inspection.server_name,
            upstream_port,
            connect_timeout,
            max_addresses,
        )
        .await;
        let _ = event_tx.send(RuntimeEvent::RouteReady { id, result }).await;
    }));
    Ok(())
}

async fn resolve_and_connect_udp(
    resolver: IndependentResolver,
    policy: Arc<AddressPolicy>,
    server_name: &str,
    upstream_port: u16,
    connect_timeout: Duration,
    max_addresses: usize,
) -> Result<ConnectedUpstream, UdpRouteError> {
    let addresses = resolver.resolve(server_name, upstream_port).await?;
    let (socket, address) = connect_udp(&addresses, connect_timeout, policy, max_addresses).await?;
    Ok(ConnectedUpstream { socket, address })
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "one listener-owned event transition keeps session state changes atomic"
)]
async fn handle_runtime_event(
    event: RuntimeEvent,
    listener: &Arc<UdpSocket>,
    table: &Arc<Mutex<UdpSessionTable>>,
    sessions: &mut HashMap<SessionId, RuntimeSession>,
    event_tx: &mpsc::Sender<RuntimeEvent>,
    metrics: &Arc<RuntimeMetrics>,
    firewall: Option<&KernelFirewall>,
    listener_address: SocketAddr,
    first_response_blocks: &mut HashMap<SocketAddr, Instant>,
    first_response_block_duration: Duration,
    send_timeout: Duration,
) {
    match event {
        RuntimeEvent::RouteReady { id, result } => {
            let Some(runtime) = sessions.get(&id) else {
                return;
            };
            if !matches!(runtime.phase, RuntimePhase::Resolving) {
                return;
            }
            let ConnectedUpstream { socket, address } = match result {
                Ok(connected) => connected,
                Err(error) => {
                    error.record_metrics(metrics);
                    warn!(session = ?id, %error, "UDP route failed");
                    close_runtime_session(
                        id,
                        CloseReason::InspectionFailed,
                        table,
                        sessions,
                        metrics,
                    )
                    .await;
                    return;
                }
            };
            let Some(retry) = sessions
                .get(&id)
                .and_then(|runtime| runtime.retry.as_ref().map(Arc::clone))
            else {
                metrics.relay_failed();
                warn!(session = ?id, "UDP Retry inspection state is missing");
                close_runtime_session(id, CloseReason::InspectionFailed, table, sessions, metrics)
                    .await;
                return;
            };
            if let Err(error) = table.lock().await.route(id, address, Instant::now()) {
                metrics.inspection_failed();
                if matches!(error, SessionError::InspectionDeadlineElapsed(_)) {
                    metrics.timeout();
                }
                warn!(session = ?id, %error, "UDP route state transition failed");
                close_runtime_session(id, CloseReason::InspectionFailed, table, sessions, metrics)
                    .await;
                return;
            }

            let upstream = Arc::new(socket);
            let (writer_tx, writer_rx) = mpsc::channel(1);
            let (client, first_response_only) = {
                let runtime = sessions
                    .get_mut(&id)
                    .expect("session existence checked before route transition");
                abort_and_join(&mut runtime.task).await;
                runtime.phase = RuntimePhase::Routed(writer_tx.clone());
                (runtime.client, runtime.first_response_only)
            };
            let writer_task = spawn_upstream_writer(
                id,
                Arc::clone(&upstream),
                writer_rx,
                Arc::clone(table),
                event_tx.clone(),
                Arc::clone(metrics),
                send_timeout,
            );
            let relay_task = spawn_upstream_reader(
                id,
                upstream,
                client,
                first_response_only,
                retry,
                Arc::clone(table),
                event_tx.clone(),
                Arc::clone(metrics),
            );
            if let Some(runtime) = sessions.get_mut(&id) {
                runtime.task = Some(relay_task);
                runtime.writer_task = Some(writer_task);
            }

            if let Err(error) = wake_upstream_writer(&writer_tx) {
                metrics.relay_failed();
                warn!(session = ?id, %error, "failed to wake UDP upstream writer");
                close_runtime_session(id, CloseReason::InspectionFailed, table, sessions, metrics)
                    .await;
            } else {
                debug!(session = ?id, %client, upstream = %address, "UDP session routed");
            }
        }
        RuntimeEvent::RelayEnded { id, error: cause } => {
            if let Some(error) = cause {
                metrics.relay_failed();
                warn!(session = ?id, %error, "UDP upstream relay ended");
            } else {
                metrics.relay_completed();
            }
            close_runtime_session(id, CloseReason::RelayFinished, table, sessions, metrics).await;
        }
        RuntimeEvent::ClientDatagram {
            id,
            client,
            datagram,
            close_after_send,
        } => {
            if !sessions.contains_key(&id) {
                return;
            }
            match listener.try_send_to(&datagram, client) {
                Ok(sent) if sent == datagram.len() => {
                    metrics.add_upstream_to_client_bytes(sent as u64);
                    metrics.add_upstream_to_client_datagrams(1);
                    if close_after_send {
                        let block_result = tombstone_before_kernel_activation(
                            first_response_blocks,
                            client,
                            first_response_block_duration,
                            async {
                                let reservation = sessions
                                    .get_mut(&id)
                                    .and_then(|runtime| runtime.first_response_reservation.take())
                                    .ok_or(FirewallError::ReservationMismatch);
                                match firewall {
                                    Some(firewall) => match reservation {
                                        Ok(reservation) => {
                                            firewall
                                                .block_flow_after_first_response(
                                                    FirewallProtocol::Udp,
                                                    listener_address,
                                                    client,
                                                    reservation,
                                                )
                                                .await
                                        }
                                        Err(error) => Err(error),
                                    },
                                    None => Err(FirewallError::NotActive),
                                }
                            },
                        )
                        .await;
                        if let Err(error) = block_result {
                            metrics.relay_failed();
                            warn!(session = ?id, %error, "failed to activate UDP first-response kernel DROP");
                            close_runtime_session(
                                id,
                                CloseReason::RelayFinished,
                                table,
                                sessions,
                                metrics,
                            )
                            .await;
                            return;
                        }
                        metrics.relay_completed();
                        close_runtime_session(
                            id,
                            CloseReason::RelayFinished,
                            table,
                            sessions,
                            metrics,
                        )
                        .await;
                    }
                }
                Ok(sent) => {
                    metrics.udp_datagram_dropped();
                    metrics.relay_failed();
                    warn!(session = ?id, expected = datagram.len(), actual = sent, "short UDP client send");
                    close_runtime_session(id, CloseReason::RelayFinished, table, sessions, metrics)
                        .await;
                }
                Err(error) => {
                    metrics.udp_datagram_dropped();
                    if client_send_error_requires_close(&error, close_after_send) {
                        metrics.relay_failed();
                        warn!(session = ?id, %error, "nonblocking UDP client send failed");
                        close_runtime_session(
                            id,
                            CloseReason::RelayFinished,
                            table,
                            sessions,
                            metrics,
                        )
                        .await;
                    } else {
                        debug!(session = ?id, "UDP client send would block; datagram dropped");
                    }
                }
            }
        }
    }
}

async fn tombstone_before_kernel_activation<F>(
    first_response_blocks: &mut HashMap<SocketAddr, Instant>,
    client: SocketAddr,
    duration: Duration,
    activation: F,
) -> Result<(), FirewallError>
where
    F: Future<Output = Result<(), FirewallError>>,
{
    first_response_blocks.insert(client, Instant::now() + duration);
    activation.await
}

fn client_send_error_requires_close(error: &io::Error, close_after_send: bool) -> bool {
    close_after_send || error.kind() != io::ErrorKind::WouldBlock
}

async fn send_runtime_event(event_tx: &mpsc::Sender<RuntimeEvent>, event: RuntimeEvent) -> bool {
    event_tx.send(event).await.is_ok()
}

fn wake_upstream_writer(writer: &mpsc::Sender<()>) -> Result<(), UdpDatagramError> {
    match writer.try_send(()) {
        Ok(()) | Err(mpsc::error::TrySendError::Full(())) => Ok(()),
        Err(mpsc::error::TrySendError::Closed(())) => Err(UdpDatagramError::WriterClosed),
    }
}

fn spawn_upstream_writer(
    id: SessionId,
    upstream: Arc<UdpSocket>,
    mut wakeups: mpsc::Receiver<()>,
    table: Arc<Mutex<UdpSessionTable>>,
    event_tx: mpsc::Sender<RuntimeEvent>,
    metrics: Arc<RuntimeMetrics>,
    send_timeout: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while wakeups.recv().await.is_some() {
            let result = drain_writer_fifo(id, &upstream, &table, &metrics, send_timeout).await;
            if let Err(error) = result {
                let _ = event_tx
                    .send(RuntimeEvent::RelayEnded {
                        id,
                        error: Some(error.to_string()),
                    })
                    .await;
                return;
            }
        }
    })
}

async fn drain_writer_fifo(
    id: SessionId,
    upstream: &UdpSocket,
    table: &Arc<Mutex<UdpSessionTable>>,
    metrics: &RuntimeMetrics,
    send_timeout: Duration,
) -> Result<(), UdpDatagramError> {
    loop {
        let popped = table.lock().await.pop_buffered_datagram(id);
        let datagram = match popped {
            Ok(Some(datagram)) => datagram,
            Ok(None)
            | Err(SessionError::InvalidTransition {
                from: StateKind::RetryInspecting,
                ..
            }) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let sent = match timeout(send_timeout, upstream.send(&datagram)).await {
            Ok(Ok(sent)) => sent,
            Ok(Err(error)) => {
                metrics.udp_datagram_dropped();
                return Err(error.into());
            }
            Err(_) => {
                metrics.timeout();
                metrics.udp_datagram_dropped();
                return Err(UdpDatagramError::SendTimeout);
            }
        };
        if sent != datagram.len() {
            metrics.udp_datagram_dropped();
            return Err(UdpDatagramError::ShortSend {
                expected: datagram.len(),
                actual: sent,
            });
        }
        metrics.add_client_to_upstream_bytes(sent as u64);
        metrics.add_client_to_upstream_datagrams(1);
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the per-session task receives explicit sockets, policy state, lifecycle channel, and deadline"
)]
fn spawn_upstream_reader(
    id: SessionId,
    upstream: Arc<UdpSocket>,
    client: SocketAddr,
    first_response_only: bool,
    retry: Arc<Mutex<RuntimeRetry>>,
    table: Arc<Mutex<UdpSessionTable>>,
    event_tx: mpsc::Sender<RuntimeEvent>,
    metrics: Arc<RuntimeMetrics>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; UDP_DATAGRAM_BYTES];
        let result = loop {
            let length = match upstream.recv(&mut buffer).await {
                Ok(length) => length,
                Err(error) => break Err(error.to_string()),
            };
            let accounting =
                table
                    .lock()
                    .await
                    .record_client_bytes_sent(id, length, Instant::now());
            match accounting {
                Ok(()) => {}
                Err(SessionError::AmplificationLimit { .. }) => {
                    metrics.udp_amplification_dropped();
                    metrics.udp_datagram_dropped();
                    if first_response_only {
                        break Ok(());
                    }
                    continue;
                }
                Err(error) => break Err(error.to_string()),
            }
            let retry_disposition = {
                let mut retry = retry.lock().await;
                retry.observe_upstream(&buffer[..length])
            };
            match retry_disposition {
                Ok(RetryUpstreamDisposition::Passthrough | RetryUpstreamDisposition::Duplicate) => {
                }
                Ok(RetryUpstreamDisposition::Accepted) => {
                    if let Err(error) = table
                        .lock()
                        .await
                        .begin_retry_inspection(id, Instant::now())
                    {
                        break Err(error.to_string());
                    }
                    metrics.quic_retry_accepted();
                }
                Err(error) => {
                    metrics.udp_datagram_dropped();
                    break Err(format!("QUIC Retry transition failed: {error}"));
                }
            }
            let response = RuntimeEvent::ClientDatagram {
                id,
                client,
                datagram: buffer[..length].to_vec(),
                close_after_send: first_response_only,
            };
            if !send_runtime_event(&event_tx, response).await {
                metrics.udp_datagram_dropped();
                break Err("UDP runtime event queue closed".to_owned());
            }
            if first_response_only {
                return;
            }
        };
        let _ = event_tx
            .send(RuntimeEvent::RelayEnded {
                id,
                error: result.err(),
            })
            .await;
    })
}

async fn expire_sessions(
    table: &Arc<Mutex<UdpSessionTable>>,
    sessions: &mut HashMap<SessionId, RuntimeSession>,
    metrics: &RuntimeMetrics,
) {
    let expired = table.lock().await.expire(Instant::now());
    for closed in expired {
        if let Some(mut runtime) = sessions.remove(&closed.id) {
            runtime.stop_tasks().await;
        }
        if closed.discarded_datagrams > 0 {
            metrics.add_udp_datagrams_dropped(
                u64::try_from(closed.discarded_datagrams).unwrap_or(u64::MAX),
            );
        }
        match closed.state {
            SessionState::Closed {
                reason: CloseReason::InspectionTimeout,
            } => {
                metrics.inspection_failed();
                metrics.timeout();
            }
            SessionState::Closed {
                reason: CloseReason::IdleTimeout,
            } => {
                metrics.relay_failed();
                metrics.timeout();
            }
            SessionState::Closed { .. }
            | SessionState::Inspecting { .. }
            | SessionState::Routed { .. }
            | SessionState::RetryInspecting { .. } => {}
        }
        debug!(session = ?closed.id, state = ?closed.state, "UDP session expired");
    }
}

async fn close_runtime_session(
    id: SessionId,
    reason: CloseReason,
    table: &Arc<Mutex<UdpSessionTable>>,
    sessions: &mut HashMap<SessionId, RuntimeSession>,
    metrics: &RuntimeMetrics,
) -> usize {
    let discarded_datagrams = if let Ok(closed) = table.lock().await.close(id, reason) {
        metrics.add_udp_datagrams_dropped(
            u64::try_from(closed.discarded_datagrams).unwrap_or(u64::MAX),
        );
        closed.discarded_datagrams
    } else {
        0
    };
    if let Some(mut runtime) = sessions.remove(&id) {
        runtime.stop_tasks().await;
    }
    discarded_datagrams
}

const fn current_drop_accounted_by_close(
    current_datagram_buffered: bool,
    discarded_datagrams: usize,
) -> bool {
    current_datagram_buffered && discarded_datagrams > 0
}

async fn abort_and_join(task: &mut Option<JoinHandle<()>>) {
    if let Some(task) = task.take() {
        task.abort();
        let _ = task.await;
    }
}

async fn close_all_sessions(
    table: &Arc<Mutex<UdpSessionTable>>,
    sessions: &mut HashMap<SessionId, RuntimeSession>,
    reason: CloseReason,
    metrics: &RuntimeMetrics,
) {
    let ids = sessions.keys().copied().collect::<Vec<_>>();
    for id in ids {
        close_runtime_session(id, reason, table, sessions, metrics).await;
    }
}

#[derive(Debug, Error)]
enum UdpDatagramError {
    #[error("datagram is not a supported QUIC client Initial")]
    NotQuicInitial,
    #[error("source admission rejected the UDP datagram")]
    SourceRejected,
    #[error("global TCP/UDP session limit reached")]
    SessionLimit,
    #[error("datagram is ambiguous or does not belong to the tuple's active QUIC session")]
    SessionMismatch,
    #[error("UDP runtime and bounded session table disagree")]
    RuntimeStateMissing,
    #[error("short UDP send: expected {expected} bytes, sent {actual}")]
    ShortSend { expected: usize, actual: usize },
    #[error("UDP send timed out")]
    SendTimeout,
    #[error("per-session UDP upstream writer stopped")]
    WriterClosed,
    #[error("QUIC inspection failed: {0}")]
    Inspect(#[from] QuicInspectError),
    #[error("QUIC Retry transition failed: {0}")]
    Retry(#[from] RetryRuntimeError),
    #[error("UDP session state failed: {0}")]
    Session(#[from] SessionError),
    #[error("IPset admission failed closed: {0}")]
    IpSet(#[from] crate::ipset::IpSetError),
    #[error("kernel first-response admission failed closed: {0}")]
    Firewall(#[from] FirewallError),
    #[error("UDP socket I/O failed: {0}")]
    Io(#[from] io::Error),
}

impl UdpDatagramError {
    fn terminates_session(&self) -> bool {
        !matches!(self, Self::SessionMismatch | Self::NotQuicInitial)
    }

    fn record_metrics(&self, metrics: &RuntimeMetrics) {
        match self {
            Self::NotQuicInitial | Self::SessionMismatch | Self::Inspect(_) | Self::Retry(_) => {
                metrics.inspection_failed();
            }
            Self::SourceRejected | Self::IpSet(_) => metrics.admission_denied(),
            Self::Firewall(FirewallError::FlowSetSaturated { .. })
            | Self::SessionLimit
            | Self::Session(SessionError::SessionLimit { .. }) => {
                metrics.capacity_rejected();
            }
            Self::SendTimeout => {
                metrics.relay_failed();
                metrics.timeout();
            }
            Self::Session(SessionError::InspectionDeadlineElapsed(_)) => {
                metrics.inspection_failed();
                metrics.timeout();
            }
            Self::RuntimeStateMissing
            | Self::ShortSend { .. }
            | Self::WriterClosed
            | Self::Firewall(_)
            | Self::Io(_) => metrics.relay_failed(),
            Self::Session(_) => {}
        }
    }
}

impl UdpRouteError {
    fn record_metrics(&self, metrics: &RuntimeMetrics) {
        match self {
            Self::Dns(error) => {
                metrics.dns_failed();
                if dns_timed_out(error) {
                    metrics.timeout();
                }
            }
            Self::Connect(error) => {
                metrics.upstream_failed();
                if error.is_timeout() {
                    metrics.timeout();
                }
            }
        }
    }
}

fn dns_timed_out(error: &DnsError) -> bool {
    matches!(
        error,
        DnsError::LookupTimeout
            | DnsError::ConcurrencyTimeout
            | DnsError::PolicyRefresh(PolicyRefreshError::Timeout)
    )
}

#[derive(Debug, Error)]
pub(crate) enum UdpRuntimeError {
    #[error("invalid UDP session limits: {0}")]
    Session(#[from] SessionError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session_id() -> SessionId {
        let mut table = UdpSessionTable::new(UdpSessionLimits::default()).expect("valid limits");
        table
            .create_inspecting(
                SessionKey {
                    listener_id: ListenerId(1),
                    client: "192.0.2.1:5000".parse().expect("test client address"),
                    version: 1,
                    original_destination_connection_id: ConnectionId::new(&[1; 8])
                        .expect("valid test CID"),
                },
                Instant::now(),
            )
            .expect("create test session")
    }

    #[tokio::test]
    async fn saturated_runtime_event_queue_backpressures_without_losing_the_response() {
        let id = test_session_id();
        let client = "192.0.2.1:5000".parse().expect("test client address");
        let event = move |octet| RuntimeEvent::ClientDatagram {
            id,
            client,
            datagram: vec![octet],
            close_after_send: false,
        };
        let (event_tx, mut event_rx) = mpsc::channel(1);
        assert!(send_runtime_event(&event_tx, event(1)).await);

        let blocked_tx = event_tx.clone();
        let blocked = tokio::spawn(async move { send_runtime_event(&blocked_tx, event(2)).await });
        tokio::task::yield_now().await;
        assert!(
            !blocked.is_finished(),
            "a full bounded queue must backpressure instead of dropping the response"
        );

        let Some(RuntimeEvent::ClientDatagram { datagram, .. }) = event_rx.recv().await else {
            panic!("first response event missing");
        };
        assert_eq!(datagram, [1]);
        assert!(
            timeout(Duration::from_millis(100), blocked)
                .await
                .expect("blocked sender should resume after queue capacity is released")
                .expect("sender task should not panic")
        );
        let Some(RuntimeEvent::ClientDatagram { datagram, .. }) = event_rx.recv().await else {
            panic!("backpressured response event missing");
        };
        assert_eq!(datagram, [2]);
    }

    #[test]
    fn transient_client_send_backpressure_does_not_require_session_close() {
        let would_block = io::Error::from(io::ErrorKind::WouldBlock);
        let hard_failure = io::Error::from(io::ErrorKind::ConnectionRefused);

        assert!(!client_send_error_requires_close(&would_block, false));
        assert!(client_send_error_requires_close(&would_block, true));
        assert!(client_send_error_requires_close(&hard_failure, false));
    }

    #[tokio::test]
    async fn first_response_tombstone_survives_kernel_activation_failure() {
        let client = "192.0.2.1:5000".parse().unwrap();
        let mut tombstones = HashMap::new();

        let error = tombstone_before_kernel_activation(
            &mut tombstones,
            client,
            Duration::from_secs(30),
            async { Err(FirewallError::NotActive) },
        )
        .await
        .expect_err("injected kernel activation must fail");

        assert!(matches!(error, FirewallError::NotActive));
        assert!(
            tombstones
                .get(&client)
                .is_some_and(|deadline| *deadline > Instant::now()),
            "a delivered first response must remain tombstoned after ipset failure"
        );
    }

    #[tokio::test]
    async fn closing_a_buffered_session_counts_each_dropped_datagram_once() {
        let now = Instant::now();
        let table = Arc::new(Mutex::new(
            UdpSessionTable::new(UdpSessionLimits::default()).expect("valid limits"),
        ));
        let id = {
            let mut table = table.lock().await;
            let id = table
                .create_inspecting(
                    SessionKey {
                        listener_id: ListenerId(1),
                        client: "192.0.2.1:5000".parse().expect("test client address"),
                        version: 1,
                        original_destination_connection_id: ConnectionId::new(&[1; 8])
                            .expect("valid test CID"),
                    },
                    now,
                )
                .expect("create session");
            table
                .buffer_client_datagram(id, b"older", now)
                .expect("buffer older datagram");
            table
                .buffer_client_datagram(id, b"current", now)
                .expect("buffer current datagram");
            id
        };
        let metrics = RuntimeMetrics::default();
        let mut sessions = HashMap::new();

        let discarded = close_runtime_session(
            id,
            CloseReason::InspectionFailed,
            &table,
            &mut sessions,
            &metrics,
        )
        .await;

        assert_eq!(discarded, 2);
        assert!(current_drop_accounted_by_close(true, discarded));
        assert_eq!(metrics.snapshot().udp_datagrams_dropped_total, 2);
        assert!(!current_drop_accounted_by_close(false, discarded));
    }

    #[tokio::test]
    async fn saturated_session_writer_does_not_block_other_wakeups_expiry_or_shutdown() {
        timeout(Duration::from_millis(100), async {
            let (stalled_tx, mut stalled_rx) = mpsc::channel(1);
            let (healthy_tx, mut healthy_rx) = mpsc::channel(1);
            wake_upstream_writer(&stalled_tx).expect("first stalled wakeup fits");
            wake_upstream_writer(&stalled_tx).expect("full wakeup is coalesced");
            wake_upstream_writer(&healthy_tx).expect("independent writer remains wakeable");
            assert_eq!(healthy_rx.recv().await, Some(()));

            let start = Instant::now();
            let limits = UdpSessionLimits {
                max_sessions: 2,
                idle_timeout: Duration::from_millis(10),
                ..UdpSessionLimits::default()
            };
            let mut table = UdpSessionTable::new(limits).expect("valid limits");
            for (octet, client) in [(1, "192.0.2.1:5000"), (2, "192.0.2.2:5000")] {
                let id = table
                    .create_inspecting(
                        SessionKey {
                            listener_id: ListenerId(1),
                            client: client.parse().expect("test client address"),
                            version: 1,
                            original_destination_connection_id: ConnectionId::new(&[octet; 8])
                                .expect("valid test CID"),
                        },
                        start,
                    )
                    .expect("create session");
                table
                    .route(id, "203.0.113.10:443".parse().unwrap(), start)
                    .expect("route session");
                table
                    .queue_routed_client_datagram(id, &[octet], start)
                    .expect("queue routed datagram");
            }
            assert_eq!(
                table.expire(start + Duration::from_millis(10)).len(),
                2,
                "expiry must run even while another writer wakeup is saturated"
            );

            drop(stalled_tx);
            assert_eq!(stalled_rx.recv().await, Some(()));
            assert_eq!(stalled_rx.recv().await, None);
            drop(healthy_tx);
            assert_eq!(healthy_rx.recv().await, None);
        })
        .await
        .expect("nonblocking writer control path must never wait on a stalled session");
    }
}
