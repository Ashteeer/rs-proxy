use std::{future::Future, io, net::SocketAddr, sync::Arc, time::Duration};

use thiserror::Error;
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Semaphore, watch},
    task::JoinSet,
    time::{sleep, timeout},
};
use tracing::{debug, error, info, warn};

use crate::{
    config::{Config, ListenerProtocol},
    connector::{ConnectError, connect_tcp},
    dns::{DnsError, IndependentResolver},
    firewall::{FirewallError, FirewallProtocol, KernelFirewall},
    inspect::{
        TcpInspectConfig, TcpInspectError, http::HttpInspectError, inspect_tcp_destination,
        tls::TlsInspectError,
    },
    ipset::{AdmissionDecision, IpSetAdmission, IpSetError},
    metrics::RuntimeMetrics,
    policy::{AddressPolicy, PolicyBuildError, PolicyRefreshError},
    relay::{RelayError, relay_tcp, relay_tcp_first_response},
    udp_runtime::{BoundUdpListener, UdpRuntimeConfig, run_udp_listener},
    udp_session::ListenerId,
};

struct BoundTcpListener {
    socket: TcpListener,
    address: SocketAddr,
}

struct Shared {
    policy: Arc<AddressPolicy>,
    resolver: IndependentResolver,
    connection_slots: Arc<Semaphore>,
    inspect: TcpInspectConfig,
    connect_timeout: Duration,
    initial_write_timeout: Duration,
    idle_timeout: Duration,
    max_addresses_per_lookup: usize,
    ipset: Option<Arc<IpSetAdmission>>,
    firewall: Option<Arc<KernelFirewall>>,
    metrics: Arc<RuntimeMetrics>,
}

pub struct ProxyServer {
    tcp_listeners: Vec<BoundTcpListener>,
    udp_listeners: Vec<BoundUdpListener>,
    shared: Arc<Shared>,
    udp_config: UdpRuntimeConfig,
    shutdown_grace: Duration,
    metrics_interval: Duration,
}

impl ProxyServer {
    /// Bind every configured TCP/UDP listener and initialize routing dependencies.
    ///
    /// # Errors
    ///
    /// Returns an error for bind failures, local-interface discovery failures,
    /// or DNS resolver initialization failures.
    pub async fn bind(config: &Config) -> Result<Self, ServerError> {
        // Validate the external admission dependency before accepting traffic.
        let ipset = IpSetAdmission::initialize(&config.ipset).await?;
        // Strict DROP/REJECT rules must exist before a listening TCP socket can
        // answer SYN. Any later startup failure explicitly removes them.
        let firewall = KernelFirewall::initialize(
            &config.ipset,
            &config.listeners,
            Duration::from_secs(config.server.idle_timeout_secs),
            config.server.max_connections,
        )
        .await?;
        match Self::bind_initialized(config, ipset, firewall.clone()).await {
            Ok(server) => Ok(server),
            Err(startup) => {
                if let Some(firewall) = &firewall
                    && let Err(cleanup) = firewall.cleanup().await
                {
                    return Err(ServerError::FirewallStartupCleanup {
                        startup: Box::new(startup),
                        cleanup,
                    });
                }
                Err(startup)
            }
        }
    }

    async fn bind_initialized(
        config: &Config,
        ipset: Option<Arc<IpSetAdmission>>,
        firewall: Option<Arc<KernelFirewall>>,
    ) -> Result<Self, ServerError> {
        let mut tcp_listeners = Vec::with_capacity(config.listeners.len());
        let mut udp_listeners = Vec::with_capacity(config.listeners.len());
        for (index, listener) in config.listeners.iter().enumerate() {
            match listener.protocol {
                ListenerProtocol::Tcp => {
                    let socket = TcpListener::bind(listener.listen).await.map_err(|source| {
                        ServerError::Bind {
                            address: listener.listen,
                            source,
                        }
                    })?;
                    let address = socket.local_addr()?;
                    tcp_listeners.push(BoundTcpListener { socket, address });
                }
                ListenerProtocol::Udp => {
                    let socket = UdpSocket::bind(listener.listen).await.map_err(|source| {
                        ServerError::BindUdp {
                            address: listener.listen,
                            source,
                        }
                    })?;
                    let address = socket.local_addr()?;
                    let id = u64::try_from(index).map_err(|_| ServerError::ListenerIdExhausted)?;
                    udp_listeners.push(BoundUdpListener {
                        socket,
                        address,
                        id: ListenerId(id),
                    });
                }
            }
        }

        let listener_addresses = tcp_listeners
            .iter()
            .map(|listener| listener.address)
            .chain(udp_listeners.iter().map(|listener| listener.address))
            .collect();
        let policy = Arc::new(AddressPolicy::discover_with_nat64(
            listener_addresses,
            config.routing.allow_upstream_cidrs.clone(),
            config.routing.nat64_prefixes.clone(),
        )?);
        for dns_server in &config.dns.servers {
            if policy.dns_endpoint_conflicts(*dns_server) {
                return Err(ServerError::DnsServerLoop(*dns_server));
            }
        }
        let resolver = IndependentResolver::new_with_runtime_guard(&config.dns, &policy)?;
        let connection_slots = Arc::new(Semaphore::new(config.server.max_connections));
        let inspect_timeout = Duration::from_millis(config.server.inspect_timeout_ms);
        let connect_timeout = Duration::from_millis(config.server.connect_timeout_ms);
        let idle_timeout = Duration::from_secs(config.server.idle_timeout_secs);
        let metrics = Arc::new(RuntimeMetrics::default());
        let shared = Arc::new(Shared {
            policy: Arc::clone(&policy),
            resolver: resolver.clone(),
            connection_slots: Arc::clone(&connection_slots),
            inspect: TcpInspectConfig {
                max_buffered_bytes: config.server.inspect_max_bytes,
                timeout: inspect_timeout,
            },
            connect_timeout,
            initial_write_timeout: Duration::from_millis(config.server.initial_write_timeout_ms),
            idle_timeout,
            max_addresses_per_lookup: config.dns.max_addresses_per_lookup,
            ipset: ipset.clone(),
            firewall: firewall.clone(),
            metrics: Arc::clone(&metrics),
        });
        let udp_config = UdpRuntimeConfig {
            policy,
            resolver,
            session_slots: connection_slots,
            inspect_timeout,
            connect_timeout,
            send_timeout: Duration::from_millis(config.server.initial_write_timeout_ms),
            idle_timeout,
            inspect_max_bytes: config.server.inspect_max_bytes,
            max_addresses_per_lookup: config.dns.max_addresses_per_lookup,
            max_sessions: config.server.max_connections,
            ipset,
            firewall,
            metrics,
        };

        Ok(Self {
            tcp_listeners,
            udp_listeners,
            shared,
            udp_config,
            shutdown_grace: Duration::from_secs(config.server.shutdown_grace_secs),
            metrics_interval: Duration::from_secs(config.server.metrics_interval_secs),
        })
    }

    #[must_use]
    pub fn local_addresses(&self) -> Vec<SocketAddr> {
        self.tcp_listeners
            .iter()
            .map(|listener| listener.address)
            .chain(self.udp_listeners.iter().map(|listener| listener.address))
            .collect()
    }

    /// Return a process-local metrics handle for embedded monitoring and tests.
    #[must_use]
    pub fn metrics(&self) -> Arc<RuntimeMetrics> {
        Arc::clone(&self.shared.metrics)
    }

    /// Serve all bound listeners until the supplied shutdown future completes.
    ///
    /// # Errors
    ///
    /// Returns an error if a listener exits unexpectedly or its task fails.
    pub async fn serve_until<F>(self, shutdown: F) -> Result<(), ServerError>
    where
        F: Future<Output = ()>,
    {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (metrics_shutdown_tx, metrics_shutdown_rx) = watch::channel(false);
        let mut listener_tasks = JoinSet::new();
        let mut reporter_tasks = JoinSet::new();
        let metrics = Arc::clone(&self.shared.metrics);
        let metrics_interval = self.metrics_interval;
        reporter_tasks.spawn(async move {
            metrics
                .report_until_shutdown(metrics_interval, metrics_shutdown_rx)
                .await;
        });
        if let Some(ipset) = &self.shared.ipset {
            let ipset = Arc::clone(ipset);
            let refresh_shutdown = shutdown_rx.clone();
            listener_tasks.spawn(async move {
                ipset.refresh_until(refresh_shutdown).await;
                Ok(())
            });
        }
        for listener in self.tcp_listeners {
            info!(listen = %listener.address, protocol = "tcp", "listener started");
            listener_tasks.spawn(run_tcp_listener(
                listener,
                Arc::clone(&self.shared),
                shutdown_rx.clone(),
            ));
        }
        for listener in self.udp_listeners {
            info!(listen = %listener.address, protocol = "udp", "listener started");
            let udp_config = self.udp_config.clone();
            let udp_shutdown = shutdown_rx.clone();
            listener_tasks.spawn(async move {
                run_udp_listener(listener, udp_config, udp_shutdown)
                    .await
                    .map_err(|error| ServerError::UdpRuntime(error.to_string()))
            });
        }

        tokio::pin!(shutdown);
        let serve_result = tokio::select! {
            () = &mut shutdown => Ok(()),
            completed = listener_tasks.join_next() => {
                match completed {
                    Some(Ok(Ok(()))) | None => Err(ServerError::ListenerExited),
                    Some(Ok(Err(error))) => Err(error),
                    Some(Err(error)) => Err(ServerError::ListenerTask(error)),
                }
            }
        };

        info!("shutdown requested; stopping listeners");
        let _ = shutdown_tx.send(true);
        drop(shutdown_tx);
        let drain = async {
            while let Some(result) = listener_tasks.join_next().await {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => error!(%error, "listener stopped with an error"),
                    Err(error) => error!(%error, "listener task failed"),
                }
            }
        };
        if timeout(self.shutdown_grace, drain).await.is_err() {
            warn!(
                grace_seconds = self.shutdown_grace.as_secs(),
                "graceful shutdown timed out; aborting active connections"
            );
            listener_tasks.abort_all();
            while listener_tasks.join_next().await.is_some() {}
        }
        let _ = metrics_shutdown_tx.send(true);
        drop(metrics_shutdown_tx);
        while let Some(result) = reporter_tasks.join_next().await {
            if let Err(error) = result {
                error!(%error, "metrics reporter task failed");
            }
        }
        let cleanup_result = match &self.shared.firewall {
            Some(firewall) => firewall.cleanup().await,
            None => Ok(()),
        };
        match (serve_result, cleanup_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(error)) => Err(ServerError::Firewall(error)),
            (Err(serve), Err(cleanup)) => Err(ServerError::FirewallShutdownCleanup {
                serve: Box::new(serve),
                cleanup,
            }),
        }
    }
}

async fn run_tcp_listener(
    listener: BoundTcpListener,
    shared: Arc<Shared>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ServerError> {
    let BoundTcpListener { socket, address } = listener;
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = socket.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        shared.metrics.tcp_connection_accepted();
                        let Ok(permit) = Arc::clone(&shared.connection_slots).try_acquire_owned() else {
                            shared.metrics.capacity_rejected();
                            warn!(%peer, "connection limit reached; closing accepted socket");
                            continue;
                        };
                        let connection_shared = Arc::clone(&shared);
                        let connection_metrics = Arc::clone(&shared.metrics);
                        connections.spawn(async move {
                            let _permit = permit;
                            let _active = connection_metrics.track_tcp_connection();
                            match handle_tcp(stream, peer, address, connection_shared).await {
                                Ok(stats) => {
                                    connection_metrics.add_client_to_upstream_bytes(stats.client_to_upstream);
                                    connection_metrics.add_upstream_to_client_bytes(stats.upstream_to_client);
                                    connection_metrics.relay_completed();
                                    debug!(
                                        %peer,
                                        client_to_upstream = stats.client_to_upstream,
                                        upstream_to_client = stats.upstream_to_client,
                                        "connection relayed"
                                    );
                                }
                                Err(error) if error.is_route_drop() => {
                                    error.record_metrics(&connection_metrics);
                                    debug!(%peer, reason = %error, "connection dropped before routing");
                                }
                                Err(error) => {
                                    error.record_metrics(&connection_metrics);
                                    warn!(%peer, %error, "connection failed");
                                }
                            }
                        });
                    }
                    Err(error) => {
                        warn!(%error, listen = %address, "accept failed; retrying");
                        sleep(Duration::from_millis(100)).await;
                    }
                }
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    error!(%error, "connection task failed");
                }
            }
        }
    }

    drop(socket);
    while let Some(result) = connections.join_next().await {
        if let Err(error) = result {
            error!(%error, "connection task failed during shutdown");
        }
    }
    info!(listen = %address, "listener stopped");
    Ok(())
}

async fn handle_tcp(
    mut client: TcpStream,
    peer: SocketAddr,
    listener: SocketAddr,
    shared: Arc<Shared>,
) -> Result<crate::relay::RelayStats, ConnectionError> {
    let first_response_only = if let Some(ipset) = &shared.ipset {
        match ipset.decide(peer.ip())? {
            AdmissionDecision::Relay => false,
            AdmissionDecision::FirstResponse => true,
            AdmissionDecision::CloseAccepted => {
                return Err(ConnectionError::SourceRejectedAfterAccept);
            }
            AdmissionDecision::HoldAcceptedSilent => {
                // TCP has already completed its handshake. Holding the accepted
                // stream emits no application response, but is not SYN-level DROP.
                sleep(shared.inspect.timeout).await;
                return Err(ConnectionError::SourceHeldAfterAccept);
            }
        }
    } else {
        false
    };
    // Reserve bounded kernel-set capacity before performing any upstream work.
    // Saturation therefore fails closed without leaking a first response that
    // cannot subsequently be silenced.
    let first_response_reservation = if first_response_only {
        Some(
            shared
                .firewall
                .as_ref()
                .ok_or(ConnectionError::MissingFirstResponseFirewall)?
                .reserve_first_response_wait(FirewallProtocol::Tcp, listener, peer)
                .await?,
        )
    } else {
        None
    };
    let upstream_port = client.local_addr()?.port();
    client.set_nodelay(true)?;

    let inspection = inspect_tcp_destination(&mut client, shared.inspect).await?;
    let addresses = shared
        .resolver
        .resolve(&inspection.server_name, upstream_port)
        .await?;
    let mut upstream = connect_tcp(
        &addresses,
        shared.connect_timeout,
        Arc::clone(&shared.policy),
        shared.max_addresses_per_lookup,
    )
    .await?;
    let stats = if first_response_only {
        let stats = relay_tcp_first_response(
            &mut client,
            &mut upstream,
            &inspection.buffered,
            shared.initial_write_timeout,
            shared.idle_timeout,
        )
        .await?;
        shared
            .firewall
            .as_ref()
            .ok_or(ConnectionError::MissingFirstResponseFirewall)?
            .block_flow_after_first_response(
                FirewallProtocol::Tcp,
                listener,
                peer,
                first_response_reservation
                    .expect("first-response admission reserves kernel-set capacity"),
            )
            .await?;
        stats
    } else {
        relay_tcp(
            &mut client,
            &mut upstream,
            &inspection.buffered,
            shared.initial_write_timeout,
            shared.idle_timeout,
        )
        .await?
    };
    Ok(stats)
}

/// Wait for Ctrl-C or, on Unix, `SIGTERM`.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    result = tokio::signal::ctrl_c() => {
                        if let Err(error) = result {
                            error!(%error, "failed to listen for Ctrl-C");
                        }
                    }
                    _ = terminate.recv() => {}
                }
            }
            Err(error) => {
                error!(%error, "failed to install SIGTERM handler");
                if let Err(error) = tokio::signal::ctrl_c().await {
                    error!(%error, "failed to listen for Ctrl-C");
                }
            }
        }
    }

    #[cfg(not(unix))]
    if let Err(error) = tokio::signal::ctrl_c().await {
        error!(%error, "failed to listen for Ctrl-C");
    }
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("failed to bind TCP listener {address}: {source}")]
    Bind {
        address: SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error("failed to bind UDP listener {address}: {source}")]
    BindUdp {
        address: SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error("listener I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("configured listener index does not fit the runtime listener ID")]
    ListenerIdExhausted,
    #[error("UDP listener runtime failed: {0}")]
    UdpRuntime(String),
    #[error("upstream policy initialization failed: {0}")]
    Policy(#[from] PolicyBuildError),
    #[error("DNS resolver initialization failed: {0}")]
    Dns(#[from] DnsError),
    #[error("IPset source-admission initialization failed: {0}")]
    IpSet(#[from] IpSetError),
    #[error("kernel firewall initialization/cleanup failed: {0}")]
    Firewall(#[from] FirewallError),
    #[error("startup failed ({startup}) and owned firewall cleanup also failed ({cleanup})")]
    FirewallStartupCleanup {
        startup: Box<ServerError>,
        cleanup: FirewallError,
    },
    #[error("listener failed ({serve}) and owned firewall cleanup also failed ({cleanup})")]
    FirewallShutdownCleanup {
        serve: Box<ServerError>,
        cleanup: FirewallError,
    },
    #[error("DNS server {0} conflicts with a proxy listener")]
    DnsServerLoop(SocketAddr),
    #[error("a listener exited unexpectedly")]
    ListenerExited,
    #[error("listener task failed: {0}")]
    ListenerTask(tokio::task::JoinError),
}

#[derive(Debug, Error)]
enum ConnectionError {
    #[error("client socket I/O failed: {0}")]
    ClientIo(#[from] io::Error),
    #[error("TLS inspection failed: {0}")]
    Inspect(#[from] TcpInspectError),
    #[error("DNS resolution failed: {0}")]
    Dns(#[from] DnsError),
    #[error("upstream connection failed: {0}")]
    Connect(#[from] ConnectError),
    #[error("relay failed: {0}")]
    Relay(#[from] RelayError),
    #[error("source is absent from IPset; closed after TCP accept (not a SYN-level REJECT)")]
    SourceRejectedAfterAccept,
    #[error("source is absent from IPset; held silent after TCP accept (not a SYN-level DROP)")]
    SourceHeldAfterAccept,
    #[error("IPset membership check failed closed: {0}")]
    IpSet(#[from] IpSetError),
    #[error("first-response admission has no initialized kernel firewall")]
    MissingFirstResponseFirewall,
    #[error("failed to activate first-response kernel DROP: {0}")]
    Firewall(#[from] FirewallError),
}

impl ConnectionError {
    fn is_route_drop(&self) -> bool {
        // Malformed or intentionally unroutable client input is expected and
        // stays at debug. DNS failures are operational faults and must remain
        // visible at the default warning level.
        matches!(
            self,
            Self::Inspect(_) | Self::SourceRejectedAfterAccept | Self::SourceHeldAfterAccept
        )
    }

    fn record_metrics(&self, metrics: &RuntimeMetrics) {
        match self {
            Self::Inspect(error) => {
                metrics.inspection_failed();
                if tcp_inspection_timed_out(error) {
                    metrics.timeout();
                }
            }
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
            Self::Relay(error) => {
                metrics.relay_failed();
                if matches!(
                    error,
                    RelayError::InitialWriteTimeout | RelayError::IdleTimeout(_)
                ) {
                    metrics.timeout();
                }
            }
            Self::SourceRejectedAfterAccept | Self::SourceHeldAfterAccept | Self::IpSet(_) => {
                metrics.admission_denied();
            }
            Self::ClientIo(_) | Self::MissingFirstResponseFirewall | Self::Firewall(_) => {
                metrics.relay_failed();
            }
        }
    }
}

fn tcp_inspection_timed_out(error: &TcpInspectError) -> bool {
    matches!(
        error,
        TcpInspectError::Timeout
            | TcpInspectError::Http(HttpInspectError::Timeout)
            | TcpInspectError::Tls(TlsInspectError::Timeout)
    )
}

fn dns_timed_out(error: &DnsError) -> bool {
    matches!(
        error,
        DnsError::LookupTimeout
            | DnsError::ConcurrencyTimeout
            | DnsError::PolicyRefresh(PolicyRefreshError::Timeout)
    )
}
