#![cfg(target_os = "linux")]

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use rs_proxy::{
    config::Config,
    metrics::{RuntimeMetrics, Snapshot},
    server::ProxyServer,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::oneshot,
    task::JoinHandle,
    time::{sleep, timeout},
};

const TEST_TIMEOUT: Duration = Duration::from_secs(4);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(1);
const UPSTREAM_V4: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const PORT_PAIR_ATTEMPTS: usize = 32;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_tcp_listeners_route_http_hosts_independently() {
    let first_host = "first.lifecycle.test";
    let second_host = "second.lifecycle.test";
    let dns = FakeDns::bind([
        (first_host, IpAddr::V4(UPSTREAM_V4)),
        (second_host, IpAddr::V4(UPSTREAM_V4)),
    ])
    .await
    .expect("bind fake DNS");
    let first_upstream = bind_v4_upstream(dns.address, &[]).await;
    let second_upstream =
        bind_v4_upstream(dns.address, &[first_upstream.local_addr().unwrap().port()]).await;
    let first_port = first_upstream.local_addr().unwrap().port();
    let second_port = second_upstream.local_addr().unwrap().port();

    let first_request = http_request(first_host, "/first");
    let second_request = http_request(second_host, "/second");
    let first_reply = b"first-listener-reply".to_vec();
    let second_reply = b"second-listener-reply".to_vec();
    let (first_upstream_task, first_upstream_ready) =
        spawn_fin_coordinated_upstream(first_upstream, first_request.clone(), first_reply.clone());
    let (second_upstream_task, second_upstream_ready) = spawn_fin_coordinated_upstream(
        second_upstream,
        second_request.clone(),
        second_reply.clone(),
    );

    let listen_addresses = [
        SocketAddr::from((Ipv4Addr::LOCALHOST, first_port)),
        SocketAddr::from((Ipv4Addr::LOCALHOST, second_port)),
    ];
    let config = test_config(dns.address, &listen_addresses, 16, 2, &["127.0.0.0/8"]);
    let proxy = RunningProxy::start(&config).await;
    assert_eq!(proxy.addresses, listen_addresses);

    let first_result = round_trip_after_upstream_ready(
        listen_addresses[0],
        &first_request,
        first_reply.len(),
        first_upstream_ready,
    )
    .await;
    let second_result = round_trip_after_upstream_ready(
        listen_addresses[1],
        &second_request,
        second_reply.len(),
        second_upstream_ready,
    )
    .await;
    assert_eq!(
        first_result.expect("first listener round trip"),
        first_reply
    );
    assert_eq!(
        second_result.expect("second listener round trip"),
        second_reply
    );

    assert_eq!(join_upstream(first_upstream_task).await, first_request);
    assert_eq!(join_upstream(second_upstream_task).await, second_request);
    assert!(
        dns.was_queried(first_host, 1),
        "first Host needs an A query"
    );
    assert!(
        dns.was_queried(second_host, 1),
        "second Host needs an A query"
    );

    let snapshot = wait_for_metrics(&proxy.metrics, |snapshot| {
        snapshot.relays_completed_total == 2
    })
    .await;
    assert_eq!(snapshot.tcp_connections_accepted_total, 2);
    assert_eq!(
        snapshot.client_to_upstream_bytes_total,
        (first_request.len() + second_request.len()) as u64
    );
    assert_eq!(
        snapshot.upstream_to_client_bytes_total,
        (first_reply.len() + second_reply.len()) as u64
    );
    assert_eq!(snapshot.relay_failures_total, 0);

    proxy.stop().await;
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn aaaa_route_reaches_ipv6_loopback_upstream() {
    let hostname = "aaaa.lifecycle.test";
    let dns = FakeDns::bind([(hostname, IpAddr::V6(Ipv6Addr::LOCALHOST))])
        .await
        .expect("bind fake DNS");

    // Bind the proxy first so its chosen port remains reserved while the
    // cross-family upstream claims the same port. Binding in the opposite
    // order races the parallel IPv4 lifecycle tests' ephemeral allocations.
    let mut selected = None;
    for _ in 0..PORT_PAIR_ATTEMPTS {
        let configured_address = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let config = test_config(dns.address, &[configured_address], 8, 2, &["::1/128"]);
        let proxy = RunningProxy::start(&config).await;
        let listener_address = proxy.addresses[0];
        match TcpListener::bind((Ipv6Addr::LOCALHOST, listener_address.port())).await {
            Ok(upstream) => {
                selected = Some((proxy, upstream, listener_address));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => proxy.stop().await,
            Err(error) => {
                proxy.stop().await;
                eprintln!(
                    "SKIP aaaa_route_reaches_ipv6_loopback_upstream: IPv6 loopback is unavailable: {error}"
                );
                dns.stop();
                return;
            }
        }
    }
    let Some((proxy, upstream, listener_address)) = selected else {
        eprintln!(
            "SKIP aaaa_route_reaches_ipv6_loopback_upstream: no shared TCP port was available after {PORT_PAIR_ATTEMPTS} attempts"
        );
        dns.stop();
        return;
    };

    let request = http_request(hostname, "/aaaa");
    let reply = b"aaaa-upstream-reply".to_vec();
    let upstream_task = spawn_one_shot_upstream(upstream, request.clone(), reply.clone());

    let received = round_trip(listener_address, &request, reply.len())
        .await
        .expect("AAAA to IPv6 upstream round trip");
    assert_eq!(received, reply);
    assert_eq!(join_upstream(upstream_task).await, request);
    assert!(
        dns.was_queried(hostname, 28),
        "hostname needs an AAAA query"
    );

    proxy.stop().await;
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ipv6_listener_accepts_and_routes_to_ipv4_upstream() {
    let hostname = "ipv6-listener.lifecycle.test";
    let dns = FakeDns::bind([(hostname, IpAddr::V4(UPSTREAM_V4))])
        .await
        .expect("bind fake DNS");
    let probe = match TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!(
                "SKIP ipv6_listener_accepts_and_routes_to_ipv4_upstream: IPv6 loopback listener is unavailable: {error}"
            );
            dns.stop();
            return;
        }
    };
    drop(probe);

    let mut selected = None;
    for _ in 0..PORT_PAIR_ATTEMPTS {
        let configured_address = SocketAddr::from((Ipv6Addr::LOCALHOST, 0));
        let config = test_config(dns.address, &[configured_address], 8, 2, &["127.0.0.0/8"]);
        let proxy = RunningProxy::start(&config).await;
        let listener_address = proxy.addresses[0];
        match TcpListener::bind((UPSTREAM_V4, listener_address.port())).await {
            Ok(upstream) => {
                selected = Some((proxy, upstream, listener_address));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => proxy.stop().await,
            Err(error) => {
                proxy.stop().await;
                panic!("bind IPv4 upstream: {error}");
            }
        }
    }
    let Some((proxy, upstream, listener_address)) = selected else {
        eprintln!(
            "SKIP ipv6_listener_accepts_and_routes_to_ipv4_upstream: no shared TCP port was available after {PORT_PAIR_ATTEMPTS} attempts"
        );
        dns.stop();
        return;
    };

    let request = http_request(hostname, "/ipv6-listener");
    let reply = b"ipv6-listener-reply".to_vec();
    let upstream_task = spawn_one_shot_upstream(upstream, request.clone(), reply.clone());

    let received = round_trip(listener_address, &request, reply.len())
        .await
        .expect("IPv6 listener round trip");
    assert_eq!(received, reply);
    assert_eq!(join_upstream(upstream_task).await, request);
    assert!(dns.was_queried(hostname, 1), "hostname needs an A query");

    proxy.stop().await;
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn established_relay_closes_both_sides_after_idle_timeout() {
    let hostname = "idle.lifecycle.test";
    let dns = FakeDns::bind([(hostname, IpAddr::V4(UPSTREAM_V4))])
        .await
        .expect("bind fake DNS");
    let upstream = bind_v4_upstream(dns.address, &[]).await;
    let port = upstream.local_addr().unwrap().port();
    let request = http_request(hostname, "/idle");
    let expected_request = request.clone();
    let (ready_tx, ready_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut received = vec![0; expected_request.len()];
        stream.read_exact(&mut received).await?;
        let _ = ready_tx.send(());

        let mut byte = [0_u8; 1];
        let close_result = stream.read(&mut byte).await;
        Ok::<_, io::Error>((received, close_result))
    });

    let listener_address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut config = test_config(dns.address, &[listener_address], 8, 2, &["127.0.0.0/8"]);
    config.server.idle_timeout_secs = 1;
    let proxy = RunningProxy::start(&config).await;
    let mut client = connect_and_write(listener_address, &request).await;
    timeout(TEST_TIMEOUT, ready_rx)
        .await
        .expect("upstream readiness timed out")
        .expect("upstream readiness sender dropped");

    expect_peer_closed_within(&mut client, TEST_TIMEOUT, "idle client").await;
    let (received, close_result) = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream did not observe idle close")
        .expect("upstream task panicked")
        .expect("upstream task failed");
    assert_eq!(received, request);
    assert_peer_close(close_result, "idle upstream");

    let snapshot = wait_for_metrics(&proxy.metrics, |snapshot| snapshot.timeouts_total >= 1).await;
    assert_eq!(snapshot.relay_failures_total, 1);

    proxy.stop().await;
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_write_half_close_keeps_client_to_upstream_direction_alive() {
    if is_wsl1() {
        eprintln!(
            "SKIP: WSL1 4.4 loses Tokio readiness after the peer's TCP write-half-close; \
             this assertion remains active on native Linux and WSL2"
        );
        return;
    }

    let hostname = "half-close.lifecycle.test";
    let dns = FakeDns::bind([(hostname, IpAddr::V4(UPSTREAM_V4))])
        .await
        .expect("bind fake DNS");
    let upstream = bind_v4_upstream(dns.address, &[]).await;
    let port = upstream.local_addr().unwrap().port();
    let request = http_request(hostname, "/half-close");
    let trailing = b"client-data-after-upstream-eof".to_vec();
    let reply = b"upstream-final-response".to_vec();
    let expected_request = request.clone();
    let expected_trailing = trailing.clone();
    let upstream_reply = reply.clone();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut received_request = vec![0; expected_request.len()];
        stream.read_exact(&mut received_request).await?;
        stream.write_all(&upstream_reply).await?;
        stream.shutdown().await?;

        let mut received_trailing = vec![0; expected_trailing.len()];
        stream.read_exact(&mut received_trailing).await?;
        let mut byte = [0_u8; 1];
        let client_eof = stream.read(&mut byte).await?;
        Ok::<_, io::Error>((received_request, received_trailing, client_eof))
    });

    let listener_address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let config = test_config(dns.address, &[listener_address], 8, 2, &["127.0.0.0/8"]);
    let proxy = RunningProxy::start(&config).await;
    let mut client = connect_and_write(listener_address, &request).await;

    let mut received_reply = vec![0; reply.len()];
    timeout(TEST_TIMEOUT, client.read_exact(&mut received_reply))
        .await
        .expect("upstream response timed out")
        .expect("read upstream response");
    assert_eq!(received_reply, reply);
    let mut byte = [0_u8; 1];
    assert_eq!(
        timeout(TEST_TIMEOUT, client.read(&mut byte))
            .await
            .expect("upstream EOF timed out")
            .expect("read upstream EOF"),
        0,
        "upstream write-half-close must be forwarded as client EOF"
    );

    client
        .write_all(&trailing)
        .await
        .expect("write client data after upstream EOF");
    client.shutdown().await.expect("half-close client writer");
    let (received_request, received_trailing, client_eof) = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream did not receive trailing client data")
        .expect("upstream task panicked")
        .expect("upstream task failed");
    assert_eq!(received_request, request);
    assert_eq!(received_trailing, trailing);
    assert_eq!(client_eof, 0, "client write-half-close must reach upstream");

    proxy.stop().await;
    dns.stop();
}

fn is_wsl1() -> bool {
    let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") else {
        return false;
    };
    let release = release.to_ascii_lowercase();
    release.contains("microsoft") && !release.contains("wsl2")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn graceful_shutdown_waits_for_active_flow_to_finish_within_grace() {
    let hostname = "graceful.lifecycle.test";
    let dns = FakeDns::bind([(hostname, IpAddr::V4(UPSTREAM_V4))])
        .await
        .expect("bind fake DNS");
    let upstream = bind_v4_upstream(dns.address, &[]).await;
    let port = upstream.local_addr().unwrap().port();
    let request = http_request(hostname, "/graceful");
    let reply = b"completed-inside-grace".to_vec();
    let expected_request = request.clone();
    let upstream_reply = reply.clone();
    let (ready_tx, ready_rx) = oneshot::channel();
    let (finish_tx, finish_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut received = vec![0; expected_request.len()];
        stream.read_exact(&mut received).await?;
        let _ = ready_tx.send(());
        let _ = finish_rx.await;
        stream.write_all(&upstream_reply).await?;
        stream.shutdown().await?;
        Ok::<_, io::Error>(received)
    });

    let listener_address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let config = test_config(dns.address, &[listener_address], 8, 2, &["127.0.0.0/8"]);
    let mut proxy = RunningProxy::start(&config).await;
    let mut client = connect_and_write(listener_address, &request).await;
    timeout(TEST_TIMEOUT, ready_rx)
        .await
        .expect("upstream readiness timed out")
        .expect("upstream readiness sender dropped");

    proxy.trigger_shutdown();
    sleep(Duration::from_millis(50)).await;
    assert!(
        !proxy.task.is_finished(),
        "serve must keep the active flow alive during its grace period"
    );
    finish_tx.send(()).expect("release upstream response");

    let mut received_reply = vec![0; reply.len()];
    timeout(TEST_TIMEOUT, client.read_exact(&mut received_reply))
        .await
        .expect("graceful response timed out")
        .expect("read graceful response");
    assert_eq!(received_reply, reply);
    drop(client);
    assert_eq!(join_upstream(upstream_task).await, request);
    proxy.wait().await;
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expired_shutdown_grace_aborts_active_flow_and_serve_returns() {
    let hostname = "abort.lifecycle.test";
    let dns = FakeDns::bind([(hostname, IpAddr::V4(UPSTREAM_V4))])
        .await
        .expect("bind fake DNS");
    let upstream = bind_v4_upstream(dns.address, &[]).await;
    let port = upstream.local_addr().unwrap().port();
    let request = http_request(hostname, "/abort");
    let expected_request = request.clone();
    let (ready_tx, ready_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut received = vec![0; expected_request.len()];
        stream.read_exact(&mut received).await?;
        let _ = ready_tx.send(());
        let mut byte = [0_u8; 1];
        let close_result = stream.read(&mut byte).await;
        Ok::<_, io::Error>((received, close_result))
    });

    let listener_address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let config = test_config(dns.address, &[listener_address], 8, 1, &["127.0.0.0/8"]);
    let mut proxy = RunningProxy::start(&config).await;
    let client = connect_and_write(listener_address, &request).await;
    timeout(TEST_TIMEOUT, ready_rx)
        .await
        .expect("upstream readiness timed out")
        .expect("upstream readiness sender dropped");

    let shutdown_started = Instant::now();
    proxy.trigger_shutdown();
    proxy.wait().await;
    assert!(
        shutdown_started.elapsed() >= Duration::from_millis(900),
        "active flow must remain alive until the one-second grace expires"
    );

    let (received, close_result) = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream did not observe proxy abort")
        .expect("upstream task panicked")
        .expect("upstream task failed");
    assert_eq!(received, request);
    match close_result {
        Ok(0) => {}
        Err(error) if is_peer_close(&error) => {}
        Ok(count) => panic!("upstream received {count} unexpected byte(s) after request"),
        Err(error) => panic!("unexpected upstream read error after abort: {error}"),
    }
    drop(client);
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn global_connection_limit_rejects_second_flow_while_first_is_active() {
    let first_host = "held.lifecycle.test";
    let second_host = "rejected.lifecycle.test";
    let dns = FakeDns::bind([
        (first_host, IpAddr::V4(UPSTREAM_V4)),
        (second_host, IpAddr::V4(UPSTREAM_V4)),
    ])
    .await
    .expect("bind fake DNS");
    let first_upstream = bind_v4_upstream(dns.address, &[]).await;
    let first_port = first_upstream.local_addr().unwrap().port();
    let second_upstream = bind_v4_upstream(dns.address, &[first_port]).await;
    let second_port = second_upstream.local_addr().unwrap().port();
    let first_request = http_request(first_host, "/held");
    let second_request = http_request(second_host, "/rejected");
    let first_reply = b"first-flow-complete".to_vec();
    let expected_first = first_request.clone();
    let upstream_reply = first_reply.clone();
    let (ready_tx, ready_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = first_upstream.accept().await?;
        let mut received = vec![0; expected_first.len()];
        stream.read_exact(&mut received).await?;
        let _ = ready_tx.send(());
        let _ = release_rx.await;
        stream.write_all(&upstream_reply).await?;
        stream.shutdown().await?;
        Ok::<_, io::Error>(received)
    });

    let listener_addresses = [
        SocketAddr::from((Ipv4Addr::LOCALHOST, first_port)),
        SocketAddr::from((Ipv4Addr::LOCALHOST, second_port)),
    ];
    let config = test_config(dns.address, &listener_addresses, 1, 2, &["127.0.0.0/8"]);
    let proxy = RunningProxy::start(&config).await;
    let mut first_client = connect_and_write(listener_addresses[0], &first_request).await;
    timeout(TEST_TIMEOUT, ready_rx)
        .await
        .expect("first flow readiness timed out")
        .expect("first flow readiness sender dropped");

    let mut second_client = timeout(TEST_TIMEOUT, TcpStream::connect(listener_addresses[1]))
        .await
        .expect("second client connect timed out")
        .expect("connect second client");
    let write_result = second_client.write_all(&second_request).await;
    if write_result.is_ok() {
        expect_peer_closed(&mut second_client).await;
    } else if let Err(error) = write_result {
        assert!(
            is_peer_close(&error),
            "unexpected second-flow write error: {error}"
        );
    }
    assert!(
        !dns.was_queried(second_host, 1) && !dns.was_queried(second_host, 28),
        "flow on the second listener must not reach DNS while the global slot is held"
    );
    let limited = proxy.metrics.snapshot();
    assert_eq!(limited.tcp_connections_accepted_total, 2);
    assert_eq!(limited.capacity_rejections_total, 1);
    assert_eq!(limited.active_tcp_connections, 1);
    drop(second_upstream);

    release_tx.send(()).expect("release first flow");
    let mut received_reply = vec![0; first_reply.len()];
    timeout(TEST_TIMEOUT, first_client.read_exact(&mut received_reply))
        .await
        .expect("first flow response timed out")
        .expect("read first flow response");
    assert_eq!(received_reply, first_reply);
    drop(first_client);
    assert_eq!(join_upstream(upstream_task).await, first_request);

    proxy.stop().await;
    dns.stop();
}

struct RunningProxy {
    addresses: Vec<SocketAddr>,
    metrics: Arc<RuntimeMetrics>,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<(), rs_proxy::server::ServerError>>,
}

impl RunningProxy {
    async fn start(config: &Config) -> Self {
        let server = ProxyServer::bind(config).await.expect("bind proxy");
        let addresses = server.local_addresses();
        let metrics = server.metrics();
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(server.serve_until(async move {
            let _ = shutdown_rx.await;
        }));
        Self {
            addresses,
            metrics,
            shutdown: Some(shutdown),
            task,
        }
    }

    fn trigger_shutdown(&mut self) {
        self.shutdown
            .take()
            .expect("shutdown is triggered once")
            .send(())
            .expect("proxy task still receives shutdown");
    }

    async fn wait(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        timeout(TEST_TIMEOUT, self.task)
            .await
            .expect("proxy shutdown timed out")
            .expect("proxy task panicked")
            .expect("proxy serve failed");
    }

    async fn stop(self) {
        self.wait().await;
    }
}

async fn wait_for_metrics(
    metrics: &RuntimeMetrics,
    condition: impl Fn(Snapshot) -> bool,
) -> Snapshot {
    let result = timeout(TEST_TIMEOUT, async {
        loop {
            let snapshot = metrics.snapshot();
            if condition(snapshot) {
                return snapshot;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    match result {
        Ok(snapshot) => snapshot,
        Err(error) => panic!(
            "runtime metrics did not reach the expected state ({error}): {:?}",
            metrics.snapshot()
        ),
    }
}

struct FakeDns {
    address: SocketAddr,
    queries: Arc<Mutex<Vec<(String, u16)>>>,
    task: JoinHandle<()>,
}

impl FakeDns {
    async fn bind<'a>(answers: impl IntoIterator<Item = (&'a str, IpAddr)>) -> io::Result<Self> {
        let answers = answers
            .into_iter()
            .map(|(hostname, address)| (hostname.to_ascii_lowercase(), address))
            .collect::<HashMap<_, _>>();
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = socket.local_addr()?;
        let queries = Arc::new(Mutex::new(Vec::new()));
        let task_queries = Arc::clone(&queries);
        let task = tokio::spawn(async move {
            let mut buffer = [0_u8; 2048];
            while let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
                let Some((response, hostname, query_type)) =
                    dns_response(&buffer[..length], &answers)
                else {
                    continue;
                };
                task_queries
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((hostname, query_type));
                let _ = socket.send_to(&response, peer).await;
            }
        });
        Ok(Self {
            address,
            queries,
            task,
        })
    }

    fn was_queried(&self, hostname: &str, query_type: u16) -> bool {
        self.queries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|query| query == &(hostname.to_ascii_lowercase(), query_type))
    }

    fn stop(self) {
        self.task.abort();
    }
}

fn test_config(
    dns_server: SocketAddr,
    listeners: &[SocketAddr],
    max_connections: usize,
    shutdown_grace_secs: u64,
    allow_upstream_cidrs: &[&str],
) -> Config {
    let listener_blocks = listeners
        .iter()
        .map(|address| format!("[[listeners]]\nprotocol = \"tcp\"\nlisten = \"{address}\"\n"))
        .collect::<Vec<_>>()
        .join("\n");
    let allowed = allow_upstream_cidrs
        .iter()
        .map(|cidr| format!("\"{cidr}\""))
        .collect::<Vec<_>>()
        .join(", ");
    Config::from_toml(&format!(
        r#"
[server]
max_connections = {max_connections}
inspect_max_bytes = 4096
inspect_timeout_ms = 500
connect_timeout_ms = 500
initial_write_timeout_ms = 500
idle_timeout_secs = 10
shutdown_grace_secs = {shutdown_grace_secs}

[dns]
servers = ["{dns_server}"]
request_timeout_ms = 250
lookup_timeout_ms = 1000
attempts = 1
cache_size = 32
max_concurrent_queries = 8
max_active_requests = 8
max_addresses_per_lookup = 8

[routing]
allow_upstream_cidrs = [{allowed}]

{listener_blocks}
"#
    ))
    .expect("valid lifecycle test config")
}

async fn bind_v4_upstream(dns_server: SocketAddr, forbidden_ports: &[u16]) -> TcpListener {
    for _ in 0..32 {
        let listener = TcpListener::bind((UPSTREAM_V4, 0))
            .await
            .expect("bind IPv4 upstream");
        let port = listener.local_addr().unwrap().port();
        if port != dns_server.port() && !forbidden_ports.contains(&port) {
            return listener;
        }
    }
    panic!("could not allocate an upstream port distinct from fake DNS");
}

fn spawn_one_shot_upstream(
    listener: TcpListener,
    expected: Vec<u8>,
    reply: Vec<u8>,
) -> JoinHandle<io::Result<Vec<u8>>> {
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut received = vec![0; expected.len()];
        stream.read_exact(&mut received).await?;
        stream.write_all(&reply).await?;
        stream.shutdown().await?;
        Ok(received)
    })
}

fn spawn_fin_coordinated_upstream(
    listener: TcpListener,
    expected: Vec<u8>,
    reply: Vec<u8>,
) -> (JoinHandle<io::Result<Vec<u8>>>, oneshot::Receiver<()>) {
    let (ready_tx, ready_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut received = vec![0; expected.len()];
        stream.read_exact(&mut received).await?;
        let _ = ready_tx.send(());
        let mut byte = [0_u8; 1];
        if stream.read(&mut byte).await? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected client data after one-shot request",
            ));
        }
        stream.write_all(&reply).await?;
        stream.shutdown().await?;
        Ok(received)
    });
    (task, ready_rx)
}

async fn join_upstream(task: JoinHandle<io::Result<Vec<u8>>>) -> Vec<u8> {
    timeout(TEST_TIMEOUT, task)
        .await
        .expect("upstream task timed out")
        .expect("upstream task panicked")
        .expect("upstream socket failed")
}

async fn connect_and_write(address: SocketAddr, bytes: &[u8]) -> TcpStream {
    let mut stream = timeout(TEST_TIMEOUT, TcpStream::connect(address))
        .await
        .expect("client connect timed out")
        .expect("connect client to proxy");
    timeout(TEST_TIMEOUT, stream.write_all(bytes))
        .await
        .expect("client write timed out")
        .expect("write client request");
    stream
}

async fn round_trip(address: SocketAddr, request: &[u8], reply_len: usize) -> io::Result<Vec<u8>> {
    timeout(TEST_TIMEOUT, async {
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(request).await?;
        let mut reply = vec![0; reply_len];
        stream.read_exact(&mut reply).await?;
        stream.shutdown().await?;
        Ok(reply)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy round trip timed out"))?
}

async fn round_trip_after_upstream_ready(
    address: SocketAddr,
    request: &[u8],
    reply_len: usize,
    upstream_ready: oneshot::Receiver<()>,
) -> io::Result<Vec<u8>> {
    timeout(TEST_TIMEOUT, async {
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(request).await?;
        upstream_ready.await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "upstream closed before receiving the request",
            )
        })?;
        sleep(Duration::from_millis(25)).await;
        stream.shutdown().await?;
        let mut reply = vec![0; reply_len];
        stream.read_exact(&mut reply).await?;
        let mut trailing = [0_u8; 1];
        if stream.read(&mut trailing).await? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected upstream data after one-shot reply",
            ));
        }
        Ok(reply)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy round trip timed out"))?
}

async fn expect_peer_closed(stream: &mut TcpStream) {
    expect_peer_closed_within(stream, CLOSE_TIMEOUT, "rejected flow").await;
}

async fn expect_peer_closed_within(stream: &mut TcpStream, deadline: Duration, context: &str) {
    let mut byte = [0_u8; 1];
    match timeout(deadline, stream.read(&mut byte)).await {
        Ok(Ok(0)) => {}
        Ok(Err(error)) if is_peer_close(&error) => {}
        Ok(Ok(count)) => panic!("{context} received {count} byte(s)"),
        Ok(Err(error)) => panic!("unexpected {context} read error: {error}"),
        Err(error) => panic!("{context} was not closed within {deadline:?}: {error}"),
    }
}

fn assert_peer_close(result: io::Result<usize>, context: &str) {
    match result {
        Ok(0) => {}
        Err(error) if is_peer_close(&error) => {}
        Ok(count) => panic!("{context} received {count} unexpected byte(s)"),
        Err(error) => panic!("unexpected {context} read error: {error}"),
    }
}

fn is_peer_close(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
    )
}

fn http_request(hostname: &str, path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: {hostname}\r\n\r\n").into_bytes()
}

fn dns_response(query: &[u8], answers: &HashMap<String, IpAddr>) -> Option<(Vec<u8>, String, u16)> {
    if query.len() < 12 || u16::from_be_bytes([query[4], query[5]]) != 1 {
        return None;
    }
    let (hostname, question_end) = parse_dns_question(query)?;
    let query_type = u16::from_be_bytes([query[question_end - 4], query[question_end - 3]]);
    let query_class = u16::from_be_bytes([query[question_end - 2], query[question_end - 1]]);
    let rdata = if query_class == 1 {
        match (query_type, answers.get(&hostname.to_ascii_lowercase())) {
            (1, Some(IpAddr::V4(address))) => Some(address.octets().to_vec()),
            (28, Some(IpAddr::V6(address))) => Some(address.octets().to_vec()),
            _ => None,
        }
    } else {
        None
    };

    let mut response =
        Vec::with_capacity(question_end + rdata.as_ref().map_or(0, |data| data.len() + 12));
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&[0x81, 0x80]);
    response.extend_from_slice(&[0, 1]);
    response.extend_from_slice(if rdata.is_some() { &[0, 1] } else { &[0, 0] });
    response.extend_from_slice(&[0, 0, 0, 0]);
    response.extend_from_slice(&query[12..question_end]);
    if let Some(rdata) = rdata {
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&query[question_end - 4..question_end]);
        response.extend_from_slice(&60_u32.to_be_bytes());
        let rdata_len = u16::try_from(rdata.len()).expect("IP RDATA length fits u16");
        response.extend_from_slice(&rdata_len.to_be_bytes());
        response.extend_from_slice(&rdata);
    }
    Some((response, hostname.to_ascii_lowercase(), query_type))
}

fn parse_dns_question(query: &[u8]) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut cursor = 12_usize;
    loop {
        let length = usize::from(*query.get(cursor)?);
        cursor += 1;
        if length == 0 {
            break;
        }
        if length > 63 {
            return None;
        }
        let end = cursor.checked_add(length)?;
        labels.push(std::str::from_utf8(query.get(cursor..end)?).ok()?);
        cursor = end;
    }
    let question_end = cursor.checked_add(4)?;
    query.get(cursor..question_end)?;
    Some((labels.join("."), question_end))
}
