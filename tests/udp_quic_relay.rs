#![cfg(target_os = "linux")]

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rs_proxy::{
    config::Config,
    inspect::quic::{QuicInitialInspector, QuicInspectConfig, QuicVersion},
    metrics::{RuntimeMetrics, Snapshot},
    server::ProxyServer,
};
use rustls::Side;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::oneshot,
    task::JoinHandle,
    time::timeout,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(4);
const SILENT_WINDOW: Duration = Duration::from_millis(400);
const HOSTNAME: &str = "upstream.test";
const UPSTREAM_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const V1_WIRE: u32 = 0x0000_0001;
const V2_WIRE: u32 = 0x6b33_43cf;
const MAX_PACKET_NUMBER: u64 = (1_u64 << 62) - 1;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ipv6_wildcard_udp_listener_binds_when_the_kernel_supports_it() {
    let loopback_probe = match UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!(
                "SKIP ipv6_wildcard_udp_listener_binds_when_the_kernel_supports_it: \
                 IPv6 loopback UDP is unavailable: {error}"
            );
            return;
        }
    };
    drop(loopback_probe);
    let config = Config::from_toml(
        r#"
[server]
shutdown_grace_secs = 1

[dns]
servers = ["127.0.0.1:9"]

[[listeners]]
protocol = "udp"
listen = "[::]:0"
"#,
    )
    .expect("IPv6 wildcard listener config");
    let server = ProxyServer::bind(&config)
        .await
        .expect("bind IPv6 wildcard UDP listener after IPv6 preflight");
    let addresses = server.local_addresses();
    assert_eq!(addresses.len(), 1, "test config has one listener");
    assert_eq!(addresses[0].ip(), IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    assert_ne!(
        addresses[0].port(),
        0,
        "kernel must assign an ephemeral port"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn aaaa_route_reaches_ipv6_udp_loopback_upstream() {
    const IPV6_HOSTNAME: &str = "ipv6-upstream.udp.test";

    let upstream = match UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!(
                "SKIP aaaa_route_reaches_ipv6_udp_loopback_upstream: \
                 IPv6 loopback UDP is unavailable: {error}"
            );
            return;
        }
    };
    let port = upstream.local_addr().expect("IPv6 upstream address").port();
    let listener_address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let listener_probe = UdpSocket::bind(listener_address)
        .await
        .expect("reserve IPv4 listener port independently of IPv6 upstream");
    drop(listener_probe);

    let dns = MappedFakeDns::bind(&[(IPV6_HOSTNAME, IpAddr::V6(Ipv6Addr::LOCALHOST))])
        .await
        .expect("bind mapped fake DNS");
    let config = Config::from_toml(&format!(
        r#"
[server]
inspect_max_bytes = 4096
inspect_timeout_ms = 500
connect_timeout_ms = 500
initial_write_timeout_ms = 500
idle_timeout_secs = 2
shutdown_grace_secs = 1

[dns]
servers = ["{}"]
request_timeout_ms = 250
lookup_timeout_ms = 1000
attempts = 1

[routing]
allow_upstream_cidrs = ["::1/128"]

[[listeners]]
protocol = "udp"
listen = "{listener_address}"
"#,
        dns.address
    ))
    .expect("IPv6 upstream UDP config");
    let proxy = RunningConfiguredProxy::start(&config)
        .await
        .expect("start IPv6 upstream UDP proxy");

    let initial = encrypted_initial(
        QuicVersion::V1,
        &[0xa6; 8],
        0,
        &crypto_frame(0, &client_hello(IPV6_HOSTNAME, &[])),
    );
    let expected = initial.clone();
    let upstream_task = tokio::spawn(async move {
        relay_one_udp_datagram(upstream, b"ipv6-upstream-reply", expected).await
    });
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind IPv4 UDP client");
    client
        .send_to(&initial, listener_address)
        .await
        .expect("send Initial for AAAA route");
    assert_eq!(
        recv_datagram_from(&client, listener_address).await,
        b"ipv6-upstream-reply"
    );
    assert_eq!(join_udp_upstream(upstream_task).await, initial);
    assert!(
        dns.was_queried(IPV6_HOSTNAME, 28),
        "IPv6 upstream hostname needs an AAAA query"
    );

    proxy.stop().await;
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ipv6_udp_loopback_listener_routes_to_ipv4_upstream() {
    let client = match UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!(
                "SKIP ipv6_udp_loopback_listener_routes_to_ipv4_upstream: \
                 IPv6 loopback UDP is unavailable: {error}"
            );
            return;
        }
    };
    let upstream = UdpSocket::bind((UPSTREAM_IP, 0))
        .await
        .expect("bind IPv4 UDP upstream");
    let port = upstream.local_addr().expect("IPv4 upstream address").port();
    let listener_address = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let listener_probe = UdpSocket::bind(listener_address)
        .await
        .expect("reserve IPv6 listener port independently of IPv4 upstream");
    drop(listener_probe);

    let dns = FakeDns::bind(UPSTREAM_IP).await.expect("bind fake DNS");
    let config = Config::from_toml(&format!(
        r#"
[server]
inspect_max_bytes = 4096
inspect_timeout_ms = 500
connect_timeout_ms = 500
initial_write_timeout_ms = 500
idle_timeout_secs = 2
shutdown_grace_secs = 1

[dns]
servers = ["{}"]
request_timeout_ms = 250
lookup_timeout_ms = 1000
attempts = 1

[routing]
allow_upstream_cidrs = ["127.0.0.0/8"]

[[listeners]]
protocol = "udp"
listen = "{listener_address}"
"#,
        dns.address
    ))
    .expect("IPv6 listener UDP config");
    let proxy = RunningConfiguredProxy::start(&config)
        .await
        .expect("start IPv6 listener UDP proxy");

    let initial = encrypted_initial(
        QuicVersion::V1,
        &[0xa4; 8],
        0,
        &crypto_frame(0, &client_hello(HOSTNAME, &[])),
    );
    let expected = initial.clone();
    let upstream_task = tokio::spawn(async move {
        relay_one_udp_datagram(upstream, b"ipv6-listener-reply", expected).await
    });
    client
        .send_to(&initial, listener_address)
        .await
        .expect("send Initial through IPv6 listener");
    assert_eq!(
        recv_datagram_from(&client, listener_address).await,
        b"ipv6-listener-reply"
    );
    assert_eq!(join_udp_upstream(upstream_task).await, initial);
    assert!(
        dns.matching_queries.load(Ordering::Relaxed) > 0,
        "IPv6 listener route needs an explicit A query"
    );

    proxy.stop().await;
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_and_udp_listeners_bind_the_same_address_and_port() {
    let dns = FakeDns::bind(UPSTREAM_IP).await.expect("bind fake DNS");
    let port = loop {
        let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("reserve mixed-listener port");
        let candidate = reservation
            .local_addr()
            .expect("reservation address")
            .port();
        drop(reservation);
        if candidate != dns.address.port() {
            break candidate;
        }
    };
    let _upstream = UdpSocket::bind((UPSTREAM_IP, port))
        .await
        .expect("reserve target port on a different loopback address");
    let config = Config::from_toml(&format!(
        r#"
[server]
shutdown_grace_secs = 1

[dns]
servers = ["{}"]

[routing]
allow_upstream_cidrs = ["127.0.0.0/8"]

[[listeners]]
protocol = "tcp"
listen = "127.0.0.1:{port}"

[[listeners]]
protocol = "udp"
listen = "127.0.0.1:{port}"
"#,
        dns.address
    ))
    .expect("mixed listener config");
    let server = ProxyServer::bind(&config)
        .await
        .expect("TCP and UDP have independent socket namespaces");
    assert_eq!(
        server.local_addresses(),
        vec![
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, port))
        ]
    );
    let (shutdown, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(server.serve_until(async move {
        let _ = shutdown_rx.await;
    }));
    let _ = shutdown.send(());
    timeout(TEST_TIMEOUT, task)
        .await
        .expect("mixed listener shutdown timed out")
        .expect("mixed listener task panicked")
        .expect("mixed listeners stopped cleanly");
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(
    clippy::too_many_lines,
    reason = "the mixed-protocol capacity scenario keeps the held flow and rejection evidence together"
)]
async fn established_tcp_flow_holds_the_shared_udp_session_slot() {
    const TCP_HOST: &str = "held.mixed.test";
    const UDP_HOST: &str = "rejected.mixed.test";

    let dns = MappedFakeDns::bind(&[
        (TCP_HOST, IpAddr::V4(UPSTREAM_IP)),
        (UDP_HOST, IpAddr::V4(UPSTREAM_IP)),
    ])
    .await
    .expect("bind mapped fake DNS");
    let (tcp_upstream, udp_upstream, port) = loop {
        let tcp = TcpListener::bind((UPSTREAM_IP, 0))
            .await
            .expect("bind candidate TCP upstream");
        let candidate = tcp.local_addr().expect("TCP upstream address").port();
        if candidate == dns.address.port() {
            continue;
        }
        let Ok(udp) = UdpSocket::bind((UPSTREAM_IP, candidate)).await else {
            continue;
        };
        let Ok(tcp_probe) = TcpListener::bind((Ipv4Addr::LOCALHOST, candidate)).await else {
            continue;
        };
        let Ok(udp_probe) = UdpSocket::bind((Ipv4Addr::LOCALHOST, candidate)).await else {
            continue;
        };
        drop(tcp_probe);
        drop(udp_probe);
        break (tcp, udp, candidate);
    };
    let listener_address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let config = Config::from_toml(&format!(
        r#"
[server]
max_connections = 1
inspect_max_bytes = 4096
inspect_timeout_ms = 500
connect_timeout_ms = 500
initial_write_timeout_ms = 500
idle_timeout_secs = 5
shutdown_grace_secs = 1

[dns]
servers = ["{}"]
request_timeout_ms = 250
lookup_timeout_ms = 1000
attempts = 1

[routing]
allow_upstream_cidrs = ["127.0.0.0/8"]

[[listeners]]
protocol = "tcp"
listen = "{listener_address}"

[[listeners]]
protocol = "udp"
listen = "{listener_address}"
"#,
        dns.address
    ))
    .expect("mixed capacity config");
    let proxy = RunningConfiguredProxy::start(&config)
        .await
        .expect("start mixed-capacity proxy");

    let request = format!("GET /held HTTP/1.1\r\nHost: {TCP_HOST}\r\n\r\n").into_bytes();
    let expected_request = request.clone();
    let (ready_tx, ready_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = tcp_upstream.accept().await?;
        let mut received = vec![0; expected_request.len()];
        stream.read_exact(&mut received).await?;
        let _ = ready_tx.send(());
        let _ = release_rx.await;
        Ok::<_, io::Error>(received)
    });
    let mut tcp_client = timeout(
        TEST_TIMEOUT,
        tokio::net::TcpStream::connect(listener_address),
    )
    .await
    .expect("TCP client connect timed out")
    .expect("connect TCP client");
    tcp_client
        .write_all(&request)
        .await
        .expect("write held TCP request");
    timeout(TEST_TIMEOUT, ready_rx)
        .await
        .expect("held TCP route timed out")
        .expect("held TCP readiness sender dropped");
    wait_for_metrics(&proxy.metrics, |snapshot| {
        snapshot.active_tcp_connections == 1
    })
    .await;

    let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind rejected UDP client");
    let initial = encrypted_initial(
        QuicVersion::V1,
        &[0xc1; 8],
        0,
        &crypto_frame(0, &client_hello(UDP_HOST, &[])),
    );
    udp_client
        .send_to(&initial, listener_address)
        .await
        .expect("send capacity-rejected Initial");
    let limited = wait_for_metrics(&proxy.metrics, |snapshot| {
        snapshot.capacity_rejections_total == 1
    })
    .await;
    assert_eq!(limited.active_tcp_connections, 1);
    assert_eq!(limited.active_udp_sessions, 0);
    assert_eq!(limited.udp_sessions_started_total, 0);
    assert!(
        !dns.was_queried(UDP_HOST, 1) && !dns.was_queried(UDP_HOST, 28),
        "capacity rejection must happen before UDP destination DNS"
    );
    assert_no_datagram(&udp_client).await;
    let mut unexpected = [0_u8; 2048];
    assert!(
        timeout(SILENT_WINDOW, udp_upstream.recv_from(&mut unexpected))
            .await
            .is_err(),
        "capacity-rejected UDP Initial must not reach an upstream"
    );

    drop(tcp_client);
    release_tx.send(()).expect("release held TCP upstream");
    let received = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("held TCP upstream timed out")
        .expect("held TCP upstream task panicked")
        .expect("held TCP upstream failed");
    assert_eq!(received, request);
    proxy.stop().await;
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(
    clippy::too_many_lines,
    reason = "the two-listener E2E keeps exact listener and upstream routing evidence together"
)]
async fn two_udp_listeners_route_hostnames_to_distinct_same_port_upstreams() {
    const FIRST_HOST: &str = "first.udp-listener.test";
    const SECOND_HOST: &str = "second.udp-listener.test";
    const SECOND_LISTENER_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);
    const SECOND_UPSTREAM_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 4);

    let dns = MappedFakeDns::bind(&[
        (FIRST_HOST, IpAddr::V4(UPSTREAM_IP)),
        (SECOND_HOST, IpAddr::V4(SECOND_UPSTREAM_IP)),
    ])
    .await
    .expect("bind mapped fake DNS");
    let (first_upstream, second_upstream, port) = loop {
        let first = UdpSocket::bind((UPSTREAM_IP, 0))
            .await
            .expect("bind candidate first UDP upstream");
        let candidate = first.local_addr().expect("first upstream address").port();
        if candidate == dns.address.port() {
            continue;
        }
        let Ok(second) = UdpSocket::bind((SECOND_UPSTREAM_IP, candidate)).await else {
            continue;
        };
        let Ok(first_probe) = UdpSocket::bind((Ipv4Addr::LOCALHOST, candidate)).await else {
            continue;
        };
        let Ok(second_probe) = UdpSocket::bind((SECOND_LISTENER_IP, candidate)).await else {
            continue;
        };
        drop(first_probe);
        drop(second_probe);
        break (first, second, candidate);
    };
    let first_listener = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let second_listener = SocketAddr::from((SECOND_LISTENER_IP, port));
    let config = Config::from_toml(&format!(
        r#"
[server]
max_connections = 4
inspect_max_bytes = 4096
inspect_timeout_ms = 500
connect_timeout_ms = 500
initial_write_timeout_ms = 500
idle_timeout_secs = 2
shutdown_grace_secs = 1

[dns]
servers = ["{}"]
request_timeout_ms = 250
lookup_timeout_ms = 1000
attempts = 1

[routing]
allow_upstream_cidrs = ["127.0.0.0/8"]

[[listeners]]
protocol = "udp"
listen = "{first_listener}"

[[listeners]]
protocol = "udp"
listen = "{second_listener}"
"#,
        dns.address
    ))
    .expect("two-listener UDP config");
    let proxy = RunningConfiguredProxy::start(&config)
        .await
        .expect("start two-listener UDP proxy");
    assert_eq!(proxy.addresses, vec![first_listener, second_listener]);

    let first_initial = encrypted_initial(
        QuicVersion::V1,
        &[0xd1; 8],
        0,
        &crypto_frame(0, &client_hello(FIRST_HOST, &[])),
    );
    let second_initial = encrypted_initial(
        QuicVersion::V1,
        &[0xd2; 8],
        0,
        &crypto_frame(0, &client_hello(SECOND_HOST, &[])),
    );
    let expected_first = first_initial.clone();
    let expected_second = second_initial.clone();
    let first_upstream_task = tokio::spawn(async move {
        relay_one_udp_datagram(first_upstream, b"first-listener-reply", expected_first).await
    });
    let second_upstream_task = tokio::spawn(async move {
        relay_one_udp_datagram(second_upstream, b"second-listener-reply", expected_second).await
    });
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind shared UDP client");

    client
        .send_to(&first_initial, first_listener)
        .await
        .expect("send first-listener Initial");
    assert_eq!(
        recv_datagram_from(&client, first_listener).await,
        b"first-listener-reply"
    );
    client
        .send_to(&second_initial, second_listener)
        .await
        .expect("send second-listener Initial");
    assert_eq!(
        recv_datagram_from(&client, second_listener).await,
        b"second-listener-reply"
    );
    assert_eq!(join_udp_upstream(first_upstream_task).await, first_initial);
    assert_eq!(
        join_udp_upstream(second_upstream_task).await,
        second_initial
    );
    assert!(dns.was_queried(FIRST_HOST, 1), "first hostname needs A DNS");
    assert!(
        dns.was_queried(SECOND_HOST, 1),
        "second hostname needs A DNS"
    );
    let snapshot = wait_for_metrics(&proxy.metrics, |snapshot| {
        snapshot.upstream_to_client_datagrams_total == 2
    })
    .await;
    assert_eq!(snapshot.udp_sessions_started_total, 2);
    assert_eq!(snapshot.client_to_upstream_datagrams_total, 2);
    assert_eq!(snapshot.upstream_to_client_datagrams_total, 2);

    proxy.stop().await;
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(
    clippy::too_many_lines,
    reason = "one end-to-end scenario keeps both isolated clients and upstream evidence together"
)]
async fn quic_v1_v2_sessions_preserve_datagrams_and_isolation() {
    let upstream = UdpSocket::bind((UPSTREAM_IP, 0))
        .await
        .expect("bind UDP upstream on 127.0.0.2");
    let upstream_address = upstream.local_addr().expect("upstream address");
    let v1 = encrypted_initial(
        QuicVersion::V1,
        &[0x11; 8],
        0,
        &crypto_frame(0, &client_hello(HOSTNAME, &[])),
    );
    let v2 = encrypted_initial(
        QuicVersion::V2,
        &[0x22; 8],
        0,
        &crypto_frame(0, &client_hello(HOSTNAME, &[])),
    );
    let expected_v1 = v1.clone();
    let expected_v2 = v2.clone();
    let upstream_task = tokio::spawn(async move {
        let mut peers = HashMap::new();
        let mut initials = Vec::new();
        let mut buffer = vec![0_u8; 65_535];
        for _ in 0..2 {
            let (length, peer) = upstream.recv_from(&mut buffer).await?;
            let datagram = buffer[..length].to_vec();
            let version = wire_version(&datagram).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing Initial version")
            })?;
            let response = match version {
                V1_WIRE => b"reply-v1".as_slice(),
                V2_WIRE => b"reply-v2".as_slice(),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected QUIC version",
                    ));
                }
            };
            peers.insert(peer, version);
            initials.push(datagram);
            upstream.send_to(response, peer).await?;
        }

        let mut followups = Vec::new();
        for _ in 0..2 {
            let (length, peer) = upstream.recv_from(&mut buffer).await?;
            let datagram = buffer[..length].to_vec();
            let version = peers.get(&peer).copied().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "unknown connected session path")
            })?;
            let response = match version {
                V1_WIRE => b"followup-v1".as_slice(),
                V2_WIRE => b"followup-v2".as_slice(),
                _ => unreachable!(),
            };
            followups.push((version, datagram));
            upstream.send_to(response, peer).await?;
        }
        Ok::<_, io::Error>((initials, followups))
    });

    let dns = FakeDns::bind(UPSTREAM_IP).await.expect("bind fake DNS");
    let proxy = RunningUdpProxy::start(upstream_address.port(), dns.address, 8, 500)
        .await
        .expect("start UDP proxy");
    let client_v1 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind v1 client");
    let client_v2 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind v2 client");
    client_v1
        .send_to(&v1, proxy.address)
        .await
        .expect("send v1 Initial");
    client_v2
        .send_to(&v2, proxy.address)
        .await
        .expect("send v2 Initial");

    assert_eq!(recv_datagram(&client_v1).await, b"reply-v1");
    assert_eq!(recv_datagram(&client_v2).await, b"reply-v2");

    let v1_followup = b"\x40v1-exact-followup";
    let v2_followup = b"\x40v2-exact-followup";
    client_v1
        .send_to(v1_followup, proxy.address)
        .await
        .expect("send v1 followup");
    client_v2
        .send_to(v2_followup, proxy.address)
        .await
        .expect("send v2 followup");
    assert_eq!(recv_datagram(&client_v1).await, b"followup-v1");
    assert_eq!(recv_datagram(&client_v2).await, b"followup-v2");

    let (initials, followups) = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream task timed out")
        .expect("upstream task panicked")
        .expect("upstream socket failed");
    assert!(initials.contains(&expected_v1));
    assert!(initials.contains(&expected_v2));
    assert!(followups.contains(&(V1_WIRE, v1_followup.to_vec())));
    assert!(followups.contains(&(V2_WIRE, v2_followup.to_vec())));
    assert!(
        dns.matching_queries.load(Ordering::Relaxed) > 0,
        "both routes must use the configured DNS endpoint"
    );
    let snapshot = proxy.metrics.snapshot();
    assert_eq!(snapshot.udp_sessions_started_total, 2);
    assert_eq!(snapshot.client_to_upstream_datagrams_total, 4);
    assert_eq!(snapshot.upstream_to_client_datagrams_total, 4);
    assert_eq!(
        snapshot.client_to_upstream_bytes_total,
        (v1.len() + v2.len() + v1_followup.len() + v2_followup.len()) as u64
    );
    assert_eq!(
        snapshot.upstream_to_client_bytes_total,
        (b"reply-v1".len() + b"reply-v2".len() + b"followup-v1".len() + b"followup-v2".len())
            as u64
    );

    proxy.stop().await;
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(
    clippy::too_many_lines,
    reason = "one Retry E2E keeps both versions and every exact wire transition together"
)]
async fn authenticated_v1_v2_retry_transitions_relay_exact_datagrams() {
    #[derive(Clone)]
    struct RetryCase {
        initial: Vec<u8>,
        retry: Vec<u8>,
        zero_rtt: Vec<u8>,
        post_retry: Vec<u8>,
        server_initial: Vec<u8>,
        followup: Vec<u8>,
        response: Vec<u8>,
    }

    let upstream = UdpSocket::bind((UPSTREAM_IP, 0))
        .await
        .expect("bind UDP Retry upstream");
    let upstream_address = upstream.local_addr().expect("upstream address");
    let original_dcid = decode_hex("8394c8f03e515708");
    let retry_scid = decode_hex("f067a5502a4262b5");
    let token = b"token";
    let mut cases = Vec::new();
    for (case_index, (version, retry_hex, response)) in [
        (
            QuicVersion::V1,
            RFC_9001_V1_RETRY,
            b"post-retry-v1".as_slice(),
        ),
        (
            QuicVersion::V2,
            RFC_9369_V2_RETRY,
            b"post-retry-v2".as_slice(),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let initial = encrypted_initial_with_fields(
            version,
            &original_dcid,
            &[],
            &[],
            0,
            &crypto_frame(0, &client_hello(HOSTNAME, &[])),
        );
        let post_retry = encrypted_initial_with_fields(
            version,
            &retry_scid,
            &[],
            token,
            1,
            &crypto_frame(0, &client_hello(HOSTNAME, &[])),
        );
        let zero_rtt =
            structural_long_packet(version, StructuralLongKind::ZeroRtt, &retry_scid, &[]);
        let server_scid = vec![0xa1 + u8::try_from(case_index).expect("case index fits"); 8];
        let mut server_initial =
            structural_long_packet(version, StructuralLongKind::Initial, &[], &server_scid);
        server_initial.extend_from_slice(&structural_long_packet(
            version,
            StructuralLongKind::Handshake,
            &[],
            &server_scid,
        ));
        let followup = encrypted_initial_with_fields(version, &server_scid, &[], token, 2, &[0x01]);
        cases.push(RetryCase {
            initial,
            retry: decode_hex(retry_hex),
            zero_rtt,
            post_retry,
            server_initial,
            followup,
            response: response.to_vec(),
        });
    }
    let upstream_cases = cases.clone();
    let upstream_task = tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65_535];
        for case in upstream_cases {
            let (initial_len, peer) = upstream.recv_from(&mut buffer).await?;
            if buffer[..initial_len] != case.initial {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proxy rewrote the pre-Retry Initial",
                ));
            }
            upstream.send_to(&case.retry, peer).await?;
            upstream.send_to(&case.retry, peer).await?;
            let (zero_rtt_len, zero_rtt_peer) = upstream.recv_from(&mut buffer).await?;
            if zero_rtt_peer != peer || buffer[..zero_rtt_len] != case.zero_rtt {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proxy rewrote or reordered separate post-Retry 0-RTT",
                ));
            }
            let (post_retry_len, post_retry_peer) = upstream.recv_from(&mut buffer).await?;
            if post_retry_peer != peer || buffer[..post_retry_len] != case.post_retry {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proxy rewrote or repathed the post-Retry Initial",
                ));
            }
            upstream.send_to(&case.server_initial, peer).await?;
            let (followup_len, followup_peer) = upstream.recv_from(&mut buffer).await?;
            if followup_peer != peer || buffer[..followup_len] != case.followup {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proxy did not learn the post-Retry server Initial SCID",
                ));
            }
            upstream.send_to(&case.response, peer).await?;
        }
        Ok::<_, io::Error>(())
    });

    let dns = FakeDns::bind(UPSTREAM_IP).await.expect("bind fake DNS");
    let proxy = RunningUdpProxy::start(upstream_address.port(), dns.address, 4, 500)
        .await
        .expect("start UDP proxy");
    for case in cases {
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind Retry client");
        client
            .send_to(&case.initial, proxy.address)
            .await
            .expect("send pre-Retry Initial");
        assert_eq!(
            recv_datagram(&client).await,
            case.retry,
            "authenticated Retry must pass through byte-exact"
        );
        assert_eq!(
            recv_datagram(&client).await,
            case.retry,
            "exact authenticated Retry retransmission must remain non-fatal"
        );
        client
            .send_to(&case.zero_rtt, proxy.address)
            .await
            .expect("send separate post-Retry 0-RTT");
        client
            .send_to(&case.post_retry, proxy.address)
            .await
            .expect("send post-Retry Initial");
        assert_eq!(recv_datagram(&client).await, case.server_initial);
        client
            .send_to(&case.followup, proxy.address)
            .await
            .expect("send Initial using learned post-Retry server SCID");
        assert_eq!(recv_datagram(&client).await, case.response);
    }
    timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("Retry upstream task timed out")
        .expect("Retry upstream task panicked")
        .expect("Retry upstream socket failed");
    assert!(
        dns.matching_queries.load(Ordering::Relaxed) > 0,
        "Retry routes must use the configured DNS endpoint"
    );
    assert_eq!(
        proxy.metrics.snapshot().quic_retries_accepted_total,
        2,
        "only each new authenticated Retry transition is counted"
    );

    proxy.stop().await;
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v1_v2_server_initial_scid_transitions_are_learned_byte_exact() {
    #[derive(Clone)]
    struct CidCase {
        initial: Vec<u8>,
        server_flight: Vec<u8>,
        followup: Vec<u8>,
        response: Vec<u8>,
    }

    let upstream = UdpSocket::bind((UPSTREAM_IP, 0))
        .await
        .expect("bind UDP CID-transition upstream");
    let upstream_address = upstream.local_addr().expect("upstream address");
    let mut cases = Vec::new();
    for (index, version) in [QuicVersion::V1, QuicVersion::V2].into_iter().enumerate() {
        let original_dcid = vec![0x51 + u8::try_from(index).expect("index fits"); 8];
        let client_scid = vec![0x61 + u8::try_from(index).expect("index fits"); 8];
        let server_scid = vec![0x71 + u8::try_from(index).expect("index fits"); 8];
        let initial = encrypted_initial_with_fields(
            version,
            &original_dcid,
            &client_scid,
            &[],
            0,
            &crypto_frame(0, &client_hello(HOSTNAME, &[])),
        );
        let mut server_flight = structural_long_packet(
            version,
            StructuralLongKind::Initial,
            &client_scid,
            &server_scid,
        );
        server_flight.extend_from_slice(&structural_long_packet(
            version,
            StructuralLongKind::Handshake,
            &client_scid,
            &server_scid,
        ));
        let followup =
            encrypted_initial_with_fields(version, &server_scid, &client_scid, &[], 1, &[0x01]);
        cases.push(CidCase {
            initial,
            server_flight,
            followup,
            response: format!("cid-transition-{index}").into_bytes(),
        });
    }
    let upstream_cases = cases.clone();
    let upstream_task = tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65_535];
        for case in upstream_cases {
            let (initial_len, peer) = upstream.recv_from(&mut buffer).await?;
            if buffer[..initial_len] != case.initial {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proxy rewrote Initial before server CID transition",
                ));
            }
            upstream.send_to(&case.server_flight, peer).await?;
            let (followup_len, followup_peer) = upstream.recv_from(&mut buffer).await?;
            if followup_peer != peer || buffer[..followup_len] != case.followup {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "client Initial using learned server SCID was not relayed exactly",
                ));
            }
            upstream.send_to(&case.response, peer).await?;
        }
        Ok::<_, io::Error>(())
    });

    let dns = FakeDns::bind(UPSTREAM_IP).await.expect("bind fake DNS");
    let proxy = RunningUdpProxy::start(upstream_address.port(), dns.address, 4, 500)
        .await
        .expect("start UDP proxy");
    for case in cases {
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind CID-transition client");
        client
            .send_to(&case.initial, proxy.address)
            .await
            .expect("send first client Initial");
        assert_eq!(recv_datagram(&client).await, case.server_flight);
        client
            .send_to(&case.followup, proxy.address)
            .await
            .expect("send client Initial with server SCID as DCID");
        assert_eq!(recv_datagram(&client).await, case.response);
    }
    timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("CID-transition upstream task timed out")
        .expect("CID-transition upstream task panicked")
        .expect("CID-transition upstream socket failed");

    proxy.stop().await;
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_server_initial_dcid_is_silent_before_and_after_retry() {
    let upstream = UdpSocket::bind((UPSTREAM_IP, 0))
        .await
        .expect("bind wrong-DCID upstream");
    let upstream_address = upstream.local_addr().expect("upstream address");
    let dns = FakeDns::bind(UPSTREAM_IP).await.expect("bind fake DNS");
    let proxy = RunningUdpProxy::start(upstream_address.port(), dns.address, 4, 500)
        .await
        .expect("start UDP proxy");
    let mut buffer = vec![0_u8; 65_535];

    let client_scid = [0x91; 8];
    let normal_initial = encrypted_initial_with_fields(
        QuicVersion::V1,
        &[0x81; 8],
        &client_scid,
        &[],
        0,
        &crypto_frame(0, &client_hello(HOSTNAME, &[])),
    );
    let normal_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind normal wrong-DCID client");
    normal_client
        .send_to(&normal_initial, proxy.address)
        .await
        .expect("send normal Initial");
    let (_, normal_peer) = timeout(TEST_TIMEOUT, upstream.recv_from(&mut buffer))
        .await
        .expect("normal Initial did not reach upstream")
        .expect("receive normal Initial");
    let wrong_normal = structural_long_packet(
        QuicVersion::V1,
        StructuralLongKind::Initial,
        &[0x92; 8],
        &[0x93; 8],
    );
    upstream
        .send_to(&wrong_normal, normal_peer)
        .await
        .expect("send wrong normal server Initial");
    assert_no_datagram(&normal_client).await;

    let retry_initial = encrypted_initial_with_fields(
        QuicVersion::V1,
        &decode_hex("8394c8f03e515708"),
        &[],
        &[],
        0,
        &crypto_frame(0, &client_hello(HOSTNAME, &[])),
    );
    let retry_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind Retry wrong-DCID client");
    retry_client
        .send_to(&retry_initial, proxy.address)
        .await
        .expect("send pre-Retry Initial");
    let (_, retry_peer) = timeout(TEST_TIMEOUT, upstream.recv_from(&mut buffer))
        .await
        .expect("pre-Retry Initial did not reach upstream")
        .expect("receive pre-Retry Initial");
    let retry = decode_hex(RFC_9001_V1_RETRY);
    upstream
        .send_to(&retry, retry_peer)
        .await
        .expect("send authenticated Retry");
    assert_eq!(recv_datagram(&retry_client).await, retry);
    let post_retry = encrypted_initial_with_fields(
        QuicVersion::V1,
        &decode_hex("f067a5502a4262b5"),
        &[],
        b"token",
        1,
        &crypto_frame(0, &client_hello(HOSTNAME, &[])),
    );
    retry_client
        .send_to(&post_retry, proxy.address)
        .await
        .expect("send post-Retry Initial");
    let (_, post_retry_peer) = timeout(TEST_TIMEOUT, upstream.recv_from(&mut buffer))
        .await
        .expect("post-Retry Initial did not reach upstream")
        .expect("receive post-Retry Initial");
    assert_eq!(post_retry_peer, retry_peer);
    let wrong_post_retry = structural_long_packet(
        QuicVersion::V1,
        StructuralLongKind::Initial,
        &[0x94; 8],
        &[0x95; 8],
    );
    upstream
        .send_to(&wrong_post_retry, retry_peer)
        .await
        .expect("send wrong post-Retry server Initial");
    assert_no_datagram(&retry_client).await;

    proxy.stop().await;
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn fragmented_initial_fifo_is_exact_and_runtime_enforces_three_x_cap() {
    let upstream = UdpSocket::bind((UPSTREAM_IP, 0))
        .await
        .expect("bind UDP upstream");
    let upstream_address = upstream.local_addr().expect("upstream address");
    let handshake = client_hello(HOSTNAME, &[]);
    let split = 40;
    let first = encrypted_initial(
        QuicVersion::V1,
        &[0x27; 8],
        0,
        &crypto_frame(split, &handshake[split..]),
    );
    let second = encrypted_initial(
        QuicVersion::V1,
        &[0x27; 8],
        1,
        &crypto_frame(0, &handshake[..split]),
    );
    let expected_first = first.clone();
    let expected_second = second.clone();
    let upstream_task = tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65_535];
        let (first_len, peer) = upstream.recv_from(&mut buffer).await?;
        let received_first = buffer[..first_len].to_vec();
        let (second_len, second_peer) = upstream.recv_from(&mut buffer).await?;
        let received_second = buffer[..second_len].to_vec();
        if peer != second_peer {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "buffered flight used multiple upstream paths",
            ));
        }
        // Two 1200-byte client datagrams permit exactly 7200 response bytes.
        upstream.send_to(&vec![0x5a; 7201], peer).await?;
        upstream.send_to(b"within-cap", peer).await?;
        Ok::<_, io::Error>((received_first, received_second))
    });

    let dns = FakeDns::bind(UPSTREAM_IP).await.expect("bind fake DNS");
    let proxy = RunningUdpProxy::start(upstream_address.port(), dns.address, 4, 500)
        .await
        .expect("start UDP proxy");
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind client");
    client
        .send_to(&first, proxy.address)
        .await
        .expect("send reordered CRYPTO suffix");
    client
        .send_to(&second, proxy.address)
        .await
        .expect("send reordered CRYPTO prefix");
    assert_eq!(
        recv_datagram(&client).await,
        b"within-cap",
        "oversized first response must be dropped as one whole datagram"
    );
    let (received_first, received_second) = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream task timed out")
        .expect("upstream task panicked")
        .expect("upstream socket failed");
    assert_eq!(received_first, expected_first);
    assert_eq!(received_second, expected_second);
    let snapshot = proxy.metrics.snapshot();
    assert_eq!(snapshot.udp_amplification_drops_total, 1);
    assert!(snapshot.udp_datagrams_dropped_total >= 1);
    assert_eq!(snapshot.upstream_to_client_datagrams_total, 1);

    proxy.stop().await;
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
#[allow(
    clippy::too_many_lines,
    reason = "the ordered flight and delayed DNS evidence belong to one E2E scenario"
)]
async fn separate_zero_rtt_is_fifo_buffered_during_inspection_and_resolution() {
    let upstream = UdpSocket::bind((UPSTREAM_IP, 0))
        .await
        .expect("bind UDP 0-RTT upstream");
    let upstream_address = upstream.local_addr().expect("upstream address");
    let dcid = [0x37; 8];
    let client_scid = [0x73; 8];
    let handshake = client_hello(HOSTNAME, &[]);
    let split = 40;
    let suffix = encrypted_initial_with_fields(
        QuicVersion::V1,
        &dcid,
        &client_scid,
        &[],
        0,
        &crypto_frame(split, &handshake[split..]),
    );
    let inspection_zero_rtt = structural_long_packet(
        QuicVersion::V1,
        StructuralLongKind::ZeroRtt,
        &dcid,
        &client_scid,
    );
    let prefix = encrypted_initial_with_fields(
        QuicVersion::V1,
        &dcid,
        &client_scid,
        &[],
        1,
        &crypto_frame(0, &handshake[..split]),
    );
    let resolving_zero_rtt = structural_long_packet(
        QuicVersion::V1,
        StructuralLongKind::ZeroRtt,
        &dcid,
        &client_scid,
    );
    let expected = [
        suffix.clone(),
        inspection_zero_rtt.clone(),
        prefix.clone(),
        resolving_zero_rtt.clone(),
    ];
    let mut probe =
        QuicInitialInspector::new(QuicInspectConfig::default()).expect("valid inspection defaults");
    assert_eq!(
        probe
            .inspect_datagram(&suffix)
            .expect("suffix authenticates"),
        None
    );
    assert_eq!(
        probe
            .inspect_datagram(&inspection_zero_rtt)
            .expect("same-flight 0-RTT is structurally accepted"),
        None
    );
    assert!(
        probe
            .inspect_datagram(&prefix)
            .expect("prefix authenticates")
            .is_some(),
        "fragmented ClientHello must complete after interleaved 0-RTT"
    );
    let upstream_task = tokio::spawn(async move {
        let mut received = Vec::new();
        let mut peer = None;
        let mut buffer = vec![0_u8; 65_535];
        for index in 0..expected.len() {
            let (length, current_peer) =
                timeout(Duration::from_secs(1), upstream.recv_from(&mut buffer))
                    .await
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("received only {index} of {} FIFO datagrams", expected.len()),
                        )
                    })??;
            if peer
                .replace(current_peer)
                .is_some_and(|old| old != current_peer)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "0-RTT FIFO changed its connected upstream path",
                ));
            }
            received.push(buffer[..length].to_vec());
        }
        if received != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "inspection/resolution FIFO did not preserve exact 0-RTT ordering",
            ));
        }
        upstream
            .send_to(b"zero-rtt-fifo", peer.expect("at least one datagram"))
            .await?;
        Ok::<_, io::Error>(())
    });

    let dns = FakeDns::bind_with_delay(UPSTREAM_IP, Duration::from_millis(100))
        .await
        .expect("bind delayed fake DNS");
    let proxy = RunningUdpProxy::start(upstream_address.port(), dns.address, 4, 500)
        .await
        .expect("start UDP proxy");
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind 0-RTT client");
    for datagram in [&suffix, &inspection_zero_rtt, &prefix, &resolving_zero_rtt] {
        client
            .send_to(datagram, proxy.address)
            .await
            .expect("send interleaved Initial/0-RTT datagram");
    }
    timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("0-RTT upstream task timed out")
        .expect("0-RTT upstream task panicked")
        .expect("0-RTT upstream socket failed");
    assert_eq!(recv_datagram(&client).await, b"zero-rtt-fifo");

    proxy.stop().await;
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn unsupported_malformed_ech_and_dns_no_route_are_silent() {
    let upstream = UdpSocket::bind((UPSTREAM_IP, 0))
        .await
        .expect("bind UDP upstream");
    let upstream_address = upstream.local_addr().expect("upstream address");
    let dns = FakeDns::bind(UPSTREAM_IP).await.expect("bind fake DNS");
    let proxy = RunningUdpProxy::start(upstream_address.port(), dns.address, 8, 500)
        .await
        .expect("start UDP proxy");

    let mut unsupported = encrypted_initial(
        QuicVersion::V1,
        &[0x33; 8],
        0,
        &crypto_frame(0, &client_hello(HOSTNAME, &[])),
    );
    unsupported[1..5].copy_from_slice(&0x709a_50c4_u32.to_be_bytes());
    let mut malformed = encrypted_initial(
        QuicVersion::V1,
        &[0x3a; 8],
        0,
        &crypto_frame(0, &client_hello(HOSTNAME, &[])),
    );
    *malformed
        .last_mut()
        .expect("encrypted Initial has an authentication tag") ^= 1;
    let ech = encrypted_initial(
        QuicVersion::V2,
        &[0x44; 8],
        0,
        &crypto_frame(0, &client_hello(HOSTNAME, &[(0xfe0d, &[0])])),
    );
    let no_route = encrypted_initial(
        QuicVersion::V1,
        &[0x4d; 8],
        0,
        &crypto_frame(0, &client_hello("missing.test", &[])),
    );
    let unsupported_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind unsupported client");
    let malformed_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind malformed client");
    let ech_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind ECH client");
    let no_route_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind no-route client");
    unsupported_client
        .send_to(&unsupported, proxy.address)
        .await
        .expect("send unsupported Initial");
    malformed_client
        .send_to(&malformed, proxy.address)
        .await
        .expect("send malformed Initial");
    ech_client
        .send_to(&ech, proxy.address)
        .await
        .expect("send ECH Initial");
    no_route_client
        .send_to(&no_route, proxy.address)
        .await
        .expect("send Initial with no DNS route");

    assert!(
        timeout(SILENT_WINDOW, upstream.recv_from(&mut [0_u8; 2048]))
            .await
            .is_err(),
        "unroutable Initials must not reach an upstream"
    );
    assert_no_datagram(&unsupported_client).await;
    assert_no_datagram(&malformed_client).await;
    assert_no_datagram(&ech_client).await;
    assert_no_datagram(&no_route_client).await;
    assert_eq!(
        dns.matching_queries.load(Ordering::Relaxed),
        0,
        "unsupported/malformed/ECH input must fail before DNS and missing.test must not match"
    );
    assert!(
        dns.total_queries.load(Ordering::Relaxed) > 0,
        "the no-route case must reach the explicitly configured DNS endpoint"
    );

    proxy.stop().await;
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn inspection_timeout_releases_the_global_session_slot() {
    let upstream = UdpSocket::bind((UPSTREAM_IP, 0))
        .await
        .expect("bind UDP upstream");
    let upstream_address = upstream.local_addr().expect("upstream address");
    let upstream_task = tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65_535];
        let (length, peer) = upstream.recv_from(&mut buffer).await?;
        upstream.send_to(b"after-timeout", peer).await?;
        Ok::<_, io::Error>(buffer[..length].to_vec())
    });
    let dns = FakeDns::bind(UPSTREAM_IP).await.expect("bind fake DNS");
    let proxy = RunningUdpProxy::start(upstream_address.port(), dns.address, 1, 100)
        .await
        .expect("start one-slot UDP proxy");

    let incomplete_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind incomplete client");
    let incomplete = encrypted_initial(QuicVersion::V1, &[0x55; 8], 0, &[0x01]);
    incomplete_client
        .send_to(&incomplete, proxy.address)
        .await
        .expect("send incomplete Initial");
    wait_for_metrics(&proxy.metrics, |snapshot| snapshot.active_udp_sessions == 1).await;

    let complete_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind complete client");
    let complete = encrypted_initial(
        QuicVersion::V1,
        &[0x66; 8],
        0,
        &crypto_frame(0, &client_hello(HOSTNAME, &[])),
    );
    complete_client
        .send_to(&complete, proxy.address)
        .await
        .expect("send complete Initial while slot is occupied");
    wait_for_metrics(&proxy.metrics, |snapshot| {
        snapshot.capacity_rejections_total == 1
    })
    .await;
    tokio::time::sleep(Duration::from_millis(250)).await;

    complete_client
        .send_to(&complete, proxy.address)
        .await
        .expect("send complete Initial after expiry");
    assert_eq!(recv_datagram(&complete_client).await, b"after-timeout");
    let forwarded = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream task timed out")
        .expect("upstream task panicked")
        .expect("upstream socket failed");
    assert_eq!(forwarded, complete);
    let snapshot = proxy.metrics.snapshot();
    assert!(snapshot.timeouts_total >= 1);
    assert_eq!(snapshot.udp_sessions_started_total, 2);
    assert_eq!(snapshot.capacity_rejections_total, 1);

    proxy.stop().await;
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn forced_listener_cancellation_aborts_children_and_releases_bind() {
    let upstream = UdpSocket::bind((UPSTREAM_IP, 0))
        .await
        .expect("bind cancellation upstream");
    let upstream_address = upstream.local_addr().expect("upstream address");
    let dns = FakeDns::bind(UPSTREAM_IP).await.expect("bind fake DNS");
    let proxy = RunningUdpProxy::start(upstream_address.port(), dns.address, 2, 500)
        .await
        .expect("start UDP proxy");
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind cancellation client");
    let initial = encrypted_initial(
        QuicVersion::V1,
        &[0xb1; 8],
        0,
        &crypto_frame(0, &client_hello(HOSTNAME, &[])),
    );
    client
        .send_to(&initial, proxy.address)
        .await
        .expect("send cancellation Initial");
    let mut buffer = vec![0_u8; 65_535];
    let (_, old_upstream_peer) = timeout(TEST_TIMEOUT, upstream.recv_from(&mut buffer))
        .await
        .expect("cancellation Initial did not reach upstream")
        .expect("receive cancellation Initial");

    let released_address = proxy.force_stop().await;
    let replacement = timeout(TEST_TIMEOUT, async {
        loop {
            match UdpSocket::bind(released_address).await {
                Ok(socket) => return socket,
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                    tokio::task::yield_now().await;
                }
                Err(error) => panic!("rebind cancelled listener address: {error}"),
            }
        }
    })
    .await
    .expect("cancelled listener address was not released within the test deadline");
    upstream
        .send_to(b"must-not-relay-after-cancel", old_upstream_peer)
        .await
        .expect("send response to cancelled connected upstream socket");
    assert_no_datagram(&client).await;
    drop(replacement);
    dns.stop();
}

async fn recv_datagram(socket: &UdpSocket) -> Vec<u8> {
    let mut response = vec![0_u8; 65_535];
    let (length, peer) = timeout(TEST_TIMEOUT, socket.recv_from(&mut response))
        .await
        .expect("client response timed out")
        .expect("receive client response");
    assert!(
        peer.ip().is_loopback(),
        "response must come from proxy listener"
    );
    response.truncate(length);
    response
}

async fn recv_datagram_from(socket: &UdpSocket, expected_peer: SocketAddr) -> Vec<u8> {
    let mut response = vec![0_u8; 65_535];
    let (length, peer) = timeout(TEST_TIMEOUT, socket.recv_from(&mut response))
        .await
        .expect("client response timed out")
        .expect("receive client response");
    assert_eq!(
        peer, expected_peer,
        "response must come from the addressed proxy listener"
    );
    response.truncate(length);
    response
}

async fn relay_one_udp_datagram(
    socket: UdpSocket,
    reply: &[u8],
    expected: Vec<u8>,
) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0_u8; 65_535];
    let (length, peer) = socket.recv_from(&mut buffer).await?;
    buffer.truncate(length);
    if buffer != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy changed or misrouted the UDP Initial",
        ));
    }
    socket.send_to(reply, peer).await?;
    Ok(buffer)
}

async fn join_udp_upstream(task: JoinHandle<io::Result<Vec<u8>>>) -> Vec<u8> {
    timeout(TEST_TIMEOUT, task)
        .await
        .expect("UDP upstream task timed out")
        .expect("UDP upstream task panicked")
        .expect("UDP upstream socket failed")
}

async fn assert_no_datagram(socket: &UdpSocket) {
    let mut response = [0_u8; 64];
    assert!(
        timeout(SILENT_WINDOW, socket.recv_from(&mut response))
            .await
            .is_err(),
        "unroutable UDP input must receive no datagram"
    );
}

struct RunningConfiguredProxy {
    addresses: Vec<SocketAddr>,
    metrics: Arc<RuntimeMetrics>,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<Result<(), rs_proxy::server::ServerError>>,
}

impl RunningConfiguredProxy {
    async fn start(config: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        let server = ProxyServer::bind(config).await?;
        let addresses = server.local_addresses();
        let metrics = server.metrics();
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(server.serve_until(async move {
            let _ = shutdown_rx.await;
        }));
        Ok(Self {
            addresses,
            metrics,
            shutdown,
            task,
        })
    }

    async fn stop(self) {
        let _ = self.shutdown.send(());
        timeout(TEST_TIMEOUT, self.task)
            .await
            .expect("configured proxy shutdown timed out")
            .expect("configured proxy task panicked")
            .expect("configured proxy serve failed");
    }
}

struct RunningUdpProxy {
    address: SocketAddr,
    metrics: Arc<RuntimeMetrics>,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<Result<(), rs_proxy::server::ServerError>>,
}

impl RunningUdpProxy {
    async fn start(
        port: u16,
        dns_server: SocketAddr,
        max_connections: usize,
        inspect_timeout_ms: u64,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let config = Config::from_toml(&format!(
            r#"
[server]
max_connections = {max_connections}
inspect_max_bytes = 4096
inspect_timeout_ms = {inspect_timeout_ms}
connect_timeout_ms = 500
initial_write_timeout_ms = 500
idle_timeout_secs = 1
shutdown_grace_secs = 1

[dns]
servers = ["{dns_server}"]
request_timeout_ms = 250
lookup_timeout_ms = 1000
attempts = 1
cache_size = 16
max_concurrent_queries = 8
max_active_requests = 8

[routing]
allow_upstream_cidrs = ["127.0.0.0/8"]

[[listeners]]
protocol = "udp"
listen = "127.0.0.1:{port}"
"#
        ))?;
        let server = ProxyServer::bind(&config).await?;
        let addresses = server.local_addresses();
        assert_eq!(addresses.len(), 1, "test config has one listener");
        let address = addresses[0];
        let metrics = server.metrics();
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(server.serve_until(async move {
            let _ = shutdown_rx.await;
        }));
        Ok(Self {
            address,
            metrics,
            shutdown,
            task,
        })
    }

    async fn stop(self) {
        let _ = self.shutdown.send(());
        timeout(TEST_TIMEOUT, self.task)
            .await
            .expect("proxy shutdown timed out")
            .expect("proxy task panicked")
            .expect("proxy serve failed");
    }

    async fn force_stop(self) -> SocketAddr {
        let Self {
            address,
            metrics: _,
            shutdown,
            task,
        } = self;
        // Keep the graceful-shutdown sender alive until the abort is observed;
        // dropping it first races a normal `serve_until` completion.
        let _shutdown_guard = shutdown;
        task.abort();
        let join_error = timeout(TEST_TIMEOUT, task)
            .await
            .expect("forced proxy cancellation timed out")
            .expect_err("aborted proxy task must not finish normally");
        assert!(join_error.is_cancelled(), "proxy task must be cancelled");
        // Dropping ProxyServer's JoinSet aborts its listener tasks. Give the
        // executor one turn to begin polling those already-cancelled futures;
        // the caller uses a bounded rebind probe while their destructors run.
        tokio::task::yield_now().await;
        address
    }
}

async fn wait_for_metrics(
    metrics: &RuntimeMetrics,
    condition: impl Fn(Snapshot) -> bool,
) -> Snapshot {
    timeout(TEST_TIMEOUT, async {
        loop {
            let snapshot = metrics.snapshot();
            if condition(snapshot) {
                return snapshot;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("runtime metrics did not reach the expected state")
}

struct MappedFakeDns {
    address: SocketAddr,
    queries: Arc<Mutex<Vec<(String, u16)>>>,
    task: JoinHandle<()>,
}

impl MappedFakeDns {
    async fn bind(records: &[(&str, IpAddr)]) -> io::Result<Self> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = socket.local_addr()?;
        let records = records
            .iter()
            .map(|(hostname, address)| (hostname.to_ascii_lowercase(), *address))
            .collect::<HashMap<_, _>>();
        let queries = Arc::new(Mutex::new(Vec::new()));
        let task_queries = Arc::clone(&queries);
        let task = tokio::spawn(async move {
            let mut buffer = [0_u8; 2048];
            while let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
                let Some((response, hostname, query_type)) =
                    mapped_dns_response(&buffer[..length], &records)
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

fn mapped_dns_response(
    query: &[u8],
    records: &HashMap<String, IpAddr>,
) -> Option<(Vec<u8>, String, u16)> {
    if query.len() < 12 || u16::from_be_bytes([query[4], query[5]]) != 1 {
        return None;
    }
    let (name, question_end) = parse_dns_question(query)?;
    let name = name.to_ascii_lowercase();
    let query_type = u16::from_be_bytes([query[question_end - 4], query[question_end - 3]]);
    let query_class = u16::from_be_bytes([query[question_end - 2], query[question_end - 1]]);
    let answer = records.get(&name).copied().filter(|address| {
        query_class == 1
            && matches!(
                (query_type, address),
                (1, IpAddr::V4(_)) | (28, IpAddr::V6(_))
            )
    });

    let mut response = Vec::with_capacity(question_end + 28);
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&[0x81, 0x80, 0, 1]);
    response.extend_from_slice(if answer.is_some() { &[0, 1] } else { &[0, 0] });
    response.extend_from_slice(&[0, 0, 0, 0]);
    response.extend_from_slice(&query[12..question_end]);
    if let Some(address) = answer {
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&query_type.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        match address {
            IpAddr::V4(address) => {
                response.extend_from_slice(&4_u16.to_be_bytes());
                response.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                response.extend_from_slice(&16_u16.to_be_bytes());
                response.extend_from_slice(&address.octets());
            }
        }
    }
    Some((response, name, query_type))
}

struct FakeDns {
    address: SocketAddr,
    matching_queries: Arc<AtomicUsize>,
    total_queries: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl FakeDns {
    async fn bind(answer: Ipv4Addr) -> io::Result<Self> {
        Self::bind_with_delay(answer, Duration::ZERO).await
    }

    async fn bind_with_delay(answer: Ipv4Addr, response_delay: Duration) -> io::Result<Self> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = socket.local_addr()?;
        let matching_queries = Arc::new(AtomicUsize::new(0));
        let task_queries = Arc::clone(&matching_queries);
        let total_queries = Arc::new(AtomicUsize::new(0));
        let task_total_queries = Arc::clone(&total_queries);
        let task = tokio::spawn(async move {
            let mut buffer = [0_u8; 2048];
            while let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
                let Some((response, matched)) = dns_response(&buffer[..length], answer) else {
                    continue;
                };
                task_total_queries.fetch_add(1, Ordering::Relaxed);
                if matched {
                    task_queries.fetch_add(1, Ordering::Relaxed);
                }
                tokio::time::sleep(response_delay).await;
                let _ = socket.send_to(&response, peer).await;
            }
        });
        Ok(Self {
            address,
            matching_queries,
            total_queries,
            task,
        })
    }

    fn stop(self) {
        self.task.abort();
    }
}

fn dns_response(query: &[u8], answer: Ipv4Addr) -> Option<(Vec<u8>, bool)> {
    if query.len() < 12 || u16::from_be_bytes([query[4], query[5]]) != 1 {
        return None;
    }
    let (name, question_end) = parse_dns_question(query)?;
    let query_type = u16::from_be_bytes([query[question_end - 4], query[question_end - 3]]);
    let query_class = u16::from_be_bytes([query[question_end - 2], query[question_end - 1]]);
    let matched = name.eq_ignore_ascii_case(HOSTNAME) && query_class == 1;
    let has_answer = matched && query_type == 1;

    let mut response = Vec::with_capacity(question_end + 16);
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&[0x81, 0x80, 0, 1]);
    response.extend_from_slice(if has_answer { &[0, 1] } else { &[0, 0] });
    response.extend_from_slice(&[0, 0, 0, 0]);
    response.extend_from_slice(&query[12..question_end]);
    if has_answer {
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(&[0, 4]);
        response.extend_from_slice(&answer.octets());
    }
    Some((response, matched))
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

fn encrypted_initial(
    version: QuicVersion,
    dcid: &[u8],
    packet_number: u64,
    frames: &[u8],
) -> Vec<u8> {
    encrypted_initial_with_fields(version, dcid, &[], &[], packet_number, frames)
}

fn encrypted_initial_with_fields(
    version: QuicVersion,
    dcid: &[u8],
    scid: &[u8],
    token: &[u8],
    packet_number: u64,
    frames: &[u8],
) -> Vec<u8> {
    const PN_LEN: usize = 2;
    const MIN_INITIAL_BYTES: usize = 1200;
    let mut plaintext = frames.to_vec();
    let (mut header, pn_offset) = loop {
        let candidate = initial_header(version, dcid, scid, token, PN_LEN, plaintext.len());
        let total = candidate.0.len() + PN_LEN + plaintext.len() + 16;
        if total == MIN_INITIAL_BYTES {
            break candidate;
        }
        if total < MIN_INITIAL_BYTES {
            plaintext.resize(plaintext.len() + MIN_INITIAL_BYTES - total, 0);
        } else {
            plaintext.truncate(plaintext.len() - (total - MIN_INITIAL_BYTES));
        }
    };
    header.extend_from_slice(
        &u16::try_from(packet_number)
            .expect("test packet number fits u16")
            .to_be_bytes(),
    );
    let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .and_then(rustls::Tls13CipherSuite::quic_suite)
        .expect("ring suite supports QUIC");
    let rustls_version = match version {
        QuicVersion::V1 => rustls::quic::Version::V1,
        QuicVersion::V2 => rustls::quic::Version::V2,
    };
    let keys = suite.keys(dcid, Side::Client, rustls_version).local;
    let mut payload = plaintext;
    let tag = keys
        .packet
        .encrypt_in_place(packet_number, &header, &mut payload)
        .expect("test Initial encryption");
    let mut protected = header;
    protected.extend_from_slice(&payload);
    protected.extend_from_slice(tag.as_ref());
    let sample_start = pn_offset + 4;
    let sample = protected[sample_start..sample_start + keys.header.sample_len()].to_vec();
    let mut first = protected[0];
    let mut protected_pn = protected[pn_offset..pn_offset + PN_LEN].to_vec();
    keys.header
        .encrypt_in_place(&sample, &mut first, &mut protected_pn)
        .expect("test header protection");
    protected[0] = first;
    protected[pn_offset..pn_offset + PN_LEN].copy_from_slice(&protected_pn);
    assert_eq!(protected.len(), MIN_INITIAL_BYTES);
    protected
}

fn initial_header(
    version: QuicVersion,
    dcid: &[u8],
    scid: &[u8],
    token: &[u8],
    packet_number_len: usize,
    plaintext_len: usize,
) -> (Vec<u8>, usize) {
    let type_bits = match version {
        QuicVersion::V1 => 0,
        QuicVersion::V2 => 1,
    };
    let mut header = vec![
        0xc0 | (type_bits << 4)
            | u8::try_from(packet_number_len - 1).expect("packet number length fits"),
    ];
    header.extend_from_slice(&version.wire().to_be_bytes());
    header.push(u8::try_from(dcid.len()).expect("DCID length fits"));
    header.extend_from_slice(dcid);
    header.push(u8::try_from(scid.len()).expect("SCID length fits"));
    header.extend_from_slice(scid);
    encode_varint(
        u64::try_from(token.len()).expect("token length fits"),
        &mut header,
    );
    header.extend_from_slice(token);
    encode_varint(
        u64::try_from(packet_number_len + plaintext_len + 16).expect("packet length fits"),
        &mut header,
    );
    let packet_number_offset = header.len();
    (header, packet_number_offset)
}

fn structural_long_packet(
    version: QuicVersion,
    kind: StructuralLongKind,
    dcid: &[u8],
    scid: &[u8],
) -> Vec<u8> {
    let type_bits = match (version, kind) {
        (QuicVersion::V1, StructuralLongKind::Initial) => 0,
        (QuicVersion::V1, StructuralLongKind::ZeroRtt)
        | (QuicVersion::V2, StructuralLongKind::Initial) => 1,
        (QuicVersion::V1, StructuralLongKind::Handshake)
        | (QuicVersion::V2, StructuralLongKind::ZeroRtt) => 2,
        (QuicVersion::V2, StructuralLongKind::Handshake) => 3,
    };
    let mut packet = vec![0xc0 | (type_bits << 4)];
    packet.extend_from_slice(&version.wire().to_be_bytes());
    packet.push(u8::try_from(dcid.len()).expect("DCID length fits"));
    packet.extend_from_slice(dcid);
    packet.push(u8::try_from(scid.len()).expect("SCID length fits"));
    packet.extend_from_slice(scid);
    if kind == StructuralLongKind::Initial {
        packet.push(0);
    }
    packet.push(1);
    packet.push(0);
    packet
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum StructuralLongKind {
    Initial,
    ZeroRtt,
    Handshake,
}

fn crypto_frame(offset: usize, data: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x06];
    encode_varint(u64::try_from(offset).expect("offset fits"), &mut frame);
    encode_varint(u64::try_from(data.len()).expect("length fits"), &mut frame);
    frame.extend_from_slice(data);
    frame
}

fn encode_varint(value: u64, target: &mut Vec<u8>) {
    match value {
        0..=63 => target.push(u8::try_from(value).expect("one-byte varint")),
        64..=16_383 => {
            let encoded = u16::try_from(value).expect("two-byte varint") | 0x4000;
            target.extend_from_slice(&encoded.to_be_bytes());
        }
        16_384..=1_073_741_823 => {
            let encoded = u32::try_from(value).expect("four-byte varint") | 0x8000_0000;
            target.extend_from_slice(&encoded.to_be_bytes());
        }
        _ if value <= MAX_PACKET_NUMBER => {
            target.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
        }
        _ => panic!("test varint exceeds 62 bits"),
    }
}

fn client_hello(hostname: &str, extra_extensions: &[(u16, &[u8])]) -> Vec<u8> {
    let mut server_name = Vec::new();
    push_u16(&mut server_name, 3 + hostname.len());
    server_name.push(0);
    push_u16(&mut server_name, hostname.len());
    server_name.extend_from_slice(hostname.as_bytes());

    let mut extensions = Vec::new();
    push_u16(&mut extensions, 0);
    push_u16(&mut extensions, server_name.len());
    extensions.extend_from_slice(&server_name);
    for (extension_type, payload) in extra_extensions {
        push_u16(&mut extensions, usize::from(*extension_type));
        push_u16(&mut extensions, payload.len());
        extensions.extend_from_slice(payload);
    }

    let mut body = Vec::new();
    body.extend_from_slice(&[3, 3]);
    body.extend_from_slice(&[7; 32]);
    body.push(0);
    body.extend_from_slice(&[0, 2, 0x13, 0x01]);
    body.extend_from_slice(&[1, 0]);
    push_u16(&mut body, extensions.len());
    body.extend_from_slice(&extensions);

    let mut handshake = vec![1];
    let encoded_len = u32::try_from(body.len())
        .expect("ClientHello length fits")
        .to_be_bytes();
    handshake.extend_from_slice(&encoded_len[1..]);
    handshake.extend_from_slice(&body);
    handshake
}

fn push_u16(target: &mut Vec<u8>, value: usize) {
    target.extend_from_slice(
        &u16::try_from(value)
            .expect("test field fits u16")
            .to_be_bytes(),
    );
}

fn wire_version(datagram: &[u8]) -> Option<u32> {
    datagram
        .get(1..5)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_be_bytes)
}

fn decode_hex(input: &str) -> Vec<u8> {
    let compact = input
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    assert_eq!(compact.len() % 2, 0, "hex input must contain whole bytes");
    let mut decoded = Vec::with_capacity(compact.len() / 2);
    for index in (0..compact.len()).step_by(2) {
        decoded.push((hex_nibble(compact[index]) << 4) | hex_nibble(compact[index + 1]));
    }
    decoded
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("not a hex digit"),
    }
}

const RFC_9001_V1_RETRY: &str =
    "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba";
const RFC_9369_V2_RETRY: &str =
    "cf6b3343cf0008f067a5502a4262b5746f6b656ec8646ce8bfe33952d955543665dcc7b6";
