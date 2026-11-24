#![cfg(target_os = "linux")]

use std::{
    collections::HashMap,
    env,
    ffi::OsString,
    fs, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[path = "support/process.rs"]
mod process_support;

use rs_proxy::{
    config::{Config, IpSetConfig, IpSetNotFound},
    ipset::{AdmissionDecision, IpSetAdmission, IpSetError},
    server::ProxyServer,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::oneshot,
    task::JoinHandle,
    time::{sleep, timeout},
};

const TEST_TIMEOUT: Duration = Duration::from_secs(6);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(1);
const REFRESH_DEADLINE: Duration = Duration::from_secs(6);
const REFRESH_PROBE_WINDOW: Duration = Duration::from_millis(150);
const SILENT_INSPECT_TIMEOUT_MS: u64 = 300;
const UPSTREAM_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const CHILD_ENV: &str = "RS_PROXY_IPSET_ADMISSION_CHILD";
const FIREWALL_RUNTIME_DIR: &str = "/run/rs-proxy";
const FIREWALL_LOCK_PATH: &str = "/run/rs-proxy/firewall.lock";

#[test]
fn legacy_hash_ip_sets_drive_proxy_policies_refresh_and_fail_closed() {
    if env::var_os(CHILD_ENV).is_some() {
        mount_private_test_filesystems();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("build isolated IPset test runtime");
        runtime.block_on(run_ipset_admission_scenarios());
        return;
    }

    if !process_support::group_kill_available() {
        skip_or_fail("fixed /bin/kill or /usr/bin/kill is unavailable");
        return;
    }

    let Some(ip) = trusted_tool("ip") else {
        skip_or_fail("trusted ip executable is unavailable");
        return;
    };
    for tool in [
        "unshare",
        "mount",
        "ipset",
        "iptables",
        "ip6tables",
        "iptables-save",
        "ip6tables-save",
    ] {
        if trusted_tool(tool).is_none() {
            skip_or_fail(&format!("trusted {tool} executable is unavailable"));
            return;
        }
    }
    let before = match HostState::capture(&ip) {
        Ok(state) => state,
        Err(reason) => {
            skip_or_fail(&format!("cannot snapshot host firewall state: {reason}"));
            return;
        }
    };
    let namespace = format!(
        "rsp-ips-{:x}-{:x}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .subsec_nanos()
    );
    assert!(
        !before.contains_namespace(&namespace),
        "generated namespace already existed before the test"
    );
    let create = run(&ip, ["netns", "add", &namespace]);
    if !create.status.success() {
        let after = HostState::capture(&ip).expect("snapshot host state after failed netns create");
        assert_eq!(before, after, "failed netns creation changed host state");
        if kernel_environment_unavailable(&create) {
            skip_or_fail(&format!(
                "network namespace/CAP_SYS_ADMIN unavailable: {}",
                String::from_utf8_lossy(&create.stderr).trim()
            ));
            return;
        }
        assert_success(&create);
    }

    let outcome = catch_unwind(AssertUnwindSafe(|| {
        run_ipset_child(&ip, &namespace);
    }));
    let cleanup = run(&ip, ["netns", "del", &namespace]);
    let after = HostState::capture(&ip).expect("snapshot host state after netns cleanup");
    assert_success(&cleanup);
    assert_eq!(
        before, after,
        "isolated IPset test changed host firewall, IPset, netns, or runtime-lock state"
    );
    if let Err(payload) = outcome {
        resume_unwind(payload);
    }
}

fn run_ipset_child(ip: &Path, namespace: &str) {
    assert_success(&run(ip, ["-n", namespace, "link", "set", "lo", "up"]));
    let unshare = trusted_tool("unshare").expect("trusted unshare");
    let executable = env::current_exe().expect("current integration-test executable");
    let output = process_support::run_with_timeout(
        Command::new(ip)
            .args(["netns", "exec", namespace])
            .arg(unshare)
            .args([
                "--mount",
                "--propagation",
                "private",
                "--fork",
                "--kill-child=KILL",
                "--",
            ])
            .arg("/usr/bin/env")
            .arg(format!("{CHILD_ENV}=1"))
            .arg(executable)
            .args([
                "--exact",
                "legacy_hash_ip_sets_drive_proxy_policies_refresh_and_fail_closed",
                "--nocapture",
                "--test-threads=1",
            ]),
        Duration::from_secs(90),
        "isolated IPset test child exceeded 90 seconds",
    )
    .unwrap_or_else(|failure| {
        panic!(
            "{}\nstdout:\n{}\nstderr:\n{}",
            failure.error,
            String::from_utf8_lossy(&failure.stdout),
            String::from_utf8_lossy(&failure.stderr)
        )
    });
    assert!(
        process_support::successful_status(output.status),
        "isolated IPset test child failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn mount_private_test_filesystems() {
    let mount = trusted_tool("mount").expect("trusted mount");
    assert_success(&run(
        &mount,
        [
            "-t",
            "tmpfs",
            "-o",
            "mode=755,nosuid,nodev",
            "rs-proxy-test-run",
            "/run",
        ],
    ));
    assert!(
        !Path::new(FIREWALL_RUNTIME_DIR).exists(),
        "private /run unexpectedly inherited the host rs-proxy runtime directory"
    );
    assert_success(&run(
        &mount,
        [
            "-t",
            "tmpfs",
            "-o",
            "mode=1777,nosuid,nodev",
            "rs-proxy-test-tmp",
            "/tmp",
        ],
    ));
}

async fn run_ipset_admission_scenarios() {
    let Some(mut fixture) = IpSetFixture::create() else {
        return;
    };
    fixture.add_v4("192.0.2.7");
    fixture.add_v6("2001:db8::7");

    let admission = IpSetAdmission::initialize(&fixture.admission_config(IpSetNotFound::Reject))
        .await
        .expect("load isolated sets")
        .expect("enabled admission");
    assert_eq!(
        admission.decide("192.0.2.7".parse().unwrap()).unwrap(),
        AdmissionDecision::Relay
    );
    assert_eq!(
        admission
            .decide("::ffff:192.0.2.7".parse().unwrap())
            .unwrap(),
        AdmissionDecision::Relay
    );
    assert_eq!(
        admission.decide("2001:db8::7".parse().unwrap()).unwrap(),
        AdmissionDecision::Relay
    );
    assert_eq!(
        admission.decide("192.0.2.8".parse().unwrap()).unwrap(),
        AdmissionDecision::CloseAccepted
    );

    let dns = FakeDns::bind(&[
        "member.ipset.test",
        "allow.ipset.test",
        "outage.ipset.test",
        "recovered.ipset.test",
        "first.ipset.test",
        "reject.ipset.test",
        "silent.ipset.test",
    ])
    .await
    .expect("bind fake DNS");

    live_operator_set_removal_rejects_active_and_new_input(&fixture, &dns).await;
    allow_fails_closed_and_recovers(&mut fixture, &dns).await;
    first_response_forwards_one_chunk(&fixture, &dns).await;
    reject_precedes_inspection_and_dns(&fixture, &dns).await;
    silent_precedes_inspection_and_dns(&fixture, &dns).await;
    dns.stop();

    fixture.del_v4("192.0.2.7");
    admission.refresh_once().await;
    assert_eq!(
        admission.decide("192.0.2.7".parse().unwrap()).unwrap(),
        AdmissionDecision::CloseAccepted,
        "new decisions must observe a refreshed set"
    );

    fixture.destroy_ipv6();
    admission.refresh_once().await;
    assert!(
        matches!(
            admission.decide("192.0.2.8".parse().unwrap()),
            Err(IpSetError::SnapshotUnavailable(_))
        ),
        "loss of either enabled set must fail every new decision closed"
    );
    fixture.recreate_ipv6();
    admission.refresh_once().await;
    assert_eq!(
        admission.decide("192.0.2.8".parse().unwrap()).unwrap(),
        AdmissionDecision::CloseAccepted,
        "a complete refresh must recover admission"
    );

    fixture.destroy_ipv6();
    fixture.destroy_ipv4();
    assert!(
        fixture.cleanup.sets.is_empty(),
        "all test sets must be removed"
    );
}

async fn live_operator_set_removal_rejects_active_and_new_input(
    fixture: &IpSetFixture,
    dns: &FakeDns,
) {
    const HOST: &str = "member.ipset.test";
    let request = http_request(HOST, "/active");
    let upstream = bind_upstream(dns.address).await;
    let port = upstream.local_addr().unwrap().port();
    let config = fixture.proxy_config(dns.address, port, IpSetNotFound::Reject, 300);

    fixture.add_v4("127.0.0.1");
    let expected = request.clone();
    let (ready_tx, ready_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut received = vec![0; expected.len()];
        stream.read_exact(&mut received).await?;
        let _ = ready_tx.send(());
        let _ = release_rx.await;
        let mut extra = [0_u8; 1];
        let active_input_reached_upstream = matches!(
            timeout(Duration::from_millis(250), stream.read(&mut extra)).await,
            Ok(Ok(count)) if count > 0
        );
        let second_accepted = matches!(
            timeout(Duration::from_millis(250), upstream.accept()).await,
            Ok(Ok(_))
        );
        Ok::<_, io::Error>((received, active_input_reached_upstream, second_accepted))
    });

    let proxy = RunningProxy::start(&config).await;
    let mut active_client = connect_and_write(proxy.address, &request).await;
    timeout(TEST_TIMEOUT, ready_rx)
        .await
        .expect("member upstream readiness timed out")
        .expect("member upstream readiness sender dropped");
    fixture.del_v4("127.0.0.1");
    wait_until_new_admissions_fail_closed(proxy.address).await;
    expect_connection_rejected(proxy.address, &request).await;

    // Strict reject rules consult the live operator set on every INPUT packet.
    // Removal does not proactively terminate an idle flow or filter OUTPUT, but
    // the next client packet is rejected before userspace or upstream sees it.
    let _ = active_client.write_all(b"x").await;
    expect_peer_closed(&mut active_client).await;
    release_tx
        .send(())
        .expect("release active-member upstream check");
    drop(active_client);

    let (received, active_input_reached_upstream, second_accepted) = join_io(upstream_task).await;
    assert_eq!(received, request);
    assert!(
        !active_input_reached_upstream,
        "live set removal must reject subsequent active-flow input before upstream"
    );
    assert!(
        !second_accepted,
        "a source removed from the live set must not reach upstream on a new flow"
    );
    proxy.stop().await;
}

async fn allow_fails_closed_and_recovers(fixture: &mut IpSetFixture, dns: &FakeDns) {
    let first_request = http_request("allow.ipset.test", "/allowed");
    let outage_request = http_request("outage.ipset.test", "/closed");
    let recovered_request = http_request("recovered.ipset.test", "/recovered");
    let reply = b"allow-policy-reply".to_vec();
    let upstream = bind_upstream(dns.address).await;
    let port = upstream.local_addr().unwrap().port();
    let config = fixture.proxy_config(dns.address, port, IpSetNotFound::Allow, 300);
    let upstream_reply = reply.clone();
    let upstream_task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = timeout(TEST_TIMEOUT, upstream.accept())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream accept"))??;
            requests.push(read_http_request(&mut stream).await?);
            stream.write_all(&upstream_reply).await?;
            stream.shutdown().await?;
        }
        Ok::<_, io::Error>(requests)
    });

    let proxy = RunningProxy::start(&config).await;
    assert_eq!(
        round_trip(proxy.address, &first_request, reply.len()).await,
        reply
    );

    fixture.destroy_ipv6();
    wait_until_new_admissions_fail_closed(proxy.address).await;
    let mut closed = connect_and_write(proxy.address, &outage_request).await;
    expect_peer_closed(&mut closed).await;
    assert_eq!(
        dns.query_count("outage.ipset.test"),
        0,
        "snapshot failure must close admission before DNS even in allow mode"
    );

    fixture.recreate_ipv6();
    assert_eq!(
        round_trip_after_recovery(proxy.address, &recovered_request, reply.len()).await,
        reply
    );
    let requests = join_io(upstream_task).await;
    assert_eq!(requests, vec![first_request, recovered_request]);
    proxy.stop().await;
}

async fn first_response_forwards_one_chunk(fixture: &IpSetFixture, dns: &FakeDns) {
    const HOST: &str = "first.ipset.test";
    let request = http_request(HOST, "/one-chunk");
    let first = b"first-chunk".to_vec();
    let trailing = b"must-not-reach-client".to_vec();
    let upstream = bind_upstream(dns.address).await;
    let port = upstream.local_addr().unwrap().port();
    let config = fixture.proxy_config(dns.address, port, IpSetNotFound::FirstResponse, 300);
    let expected = request.clone();
    let upstream_first = first.clone();
    let (release_tx, release_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut received = vec![0; expected.len()];
        stream.read_exact(&mut received).await?;
        stream.write_all(&upstream_first).await?;
        stream.flush().await?;
        let _ = release_rx.await;
        let trailing_result = stream.write_all(&trailing).await;
        Ok::<_, io::Error>((received, trailing_result))
    });

    let proxy = RunningProxy::start(&config).await;
    let mut client = connect_and_write(proxy.address, &request).await;
    let mut received_first = vec![0; first.len()];
    timeout(TEST_TIMEOUT, client.read_exact(&mut received_first))
        .await
        .expect("first response timed out")
        .expect("read first response chunk");
    assert_eq!(received_first, first);
    sleep(Duration::from_millis(50)).await;
    release_tx
        .send(())
        .expect("release trailing upstream write");
    let mut after_first = [0_u8; 1];
    assert!(
        timeout(REFRESH_PROBE_WINDOW, client.read(&mut after_first))
            .await
            .is_err(),
        "post-first-response kernel DROP exposed trailing data, FIN, or RST"
    );

    let (received, _trailing_result) = join_io(upstream_task).await;
    assert_eq!(received, request);
    proxy.stop().await;
}

async fn reject_precedes_inspection_and_dns(fixture: &IpSetFixture, dns: &FakeDns) {
    const HOST: &str = "reject.ipset.test";
    let upstream = bind_upstream(dns.address).await;
    let port = upstream.local_addr().unwrap().port();
    let config = fixture.proxy_config(dns.address, port, IpSetNotFound::Reject, 300);
    let request = http_request(HOST, "/never-inspected");

    let proxy = RunningProxy::start(&config).await;
    expect_connection_rejected(proxy.address, &request).await;
    assert_eq!(dns.query_count(HOST), 0, "reject must precede DNS");
    assert!(
        timeout(Duration::from_millis(150), upstream.accept())
            .await
            .is_err(),
        "reject must precede upstream connect"
    );
    proxy.stop().await;
}

async fn silent_precedes_inspection_and_dns(fixture: &IpSetFixture, dns: &FakeDns) {
    const HOST: &str = "silent.ipset.test";
    let upstream = bind_upstream(dns.address).await;
    let port = upstream.local_addr().unwrap().port();
    let config = fixture.proxy_config(
        dns.address,
        port,
        IpSetNotFound::Silent,
        SILENT_INSPECT_TIMEOUT_MS,
    );
    let proxy = RunningProxy::start(&config).await;
    let started = Instant::now();
    let connect = timeout(
        Duration::from_millis(SILENT_INSPECT_TIMEOUT_MS + 100),
        TcpStream::connect(proxy.address),
    )
    .await;
    assert!(connect.is_err(), "silent policy answered the TCP SYN");
    assert!(
        started.elapsed() >= Duration::from_millis(SILENT_INSPECT_TIMEOUT_MS - 30),
        "silent policy did not hold the SYN for the observation window"
    );
    assert_eq!(dns.query_count(HOST), 0, "silent must precede DNS");
    assert!(
        timeout(Duration::from_millis(150), upstream.accept())
            .await
            .is_err(),
        "silent must precede upstream connect"
    );
    proxy.stop().await;
}

struct IpSetFixture {
    command: PathBuf,
    ipv4_set: String,
    ipv6_set: String,
    cleanup: Cleanup,
}

impl IpSetFixture {
    fn create() -> Option<Self> {
        let Some(command) = find_ipset() else {
            skip_or_fail("legacy ipset executable is not installed");
            return None;
        };
        let suffix = format!("{:x}", std::process::id());
        let ipv4_set = format!("rsp_test_{suffix}_v4");
        let ipv6_set = format!("rsp_test_{suffix}_v6");

        let create_v4 = run(&command, ["create", &ipv4_set, "hash:ip", "family", "inet"]);
        if !create_v4.status.success() {
            if kernel_environment_unavailable(&create_v4) {
                skip_or_fail(&format!(
                    "cannot create an isolated IPv4 ipset (CAP_NET_ADMIN/kernel support unavailable): {}",
                    String::from_utf8_lossy(&create_v4.stderr).trim()
                ));
                return None;
            }
            assert_success(&create_v4);
        }
        let mut cleanup = Cleanup {
            command: command.clone(),
            sets: vec![ipv4_set.clone()],
        };
        let create_v6 = run(
            &command,
            ["create", &ipv6_set, "hash:ip", "family", "inet6"],
        );
        if !create_v6.status.success() {
            if kernel_environment_unavailable(&create_v6) {
                skip_or_fail(&format!(
                    "cannot create an isolated IPv6 ipset (kernel support unavailable): {}",
                    String::from_utf8_lossy(&create_v6.stderr).trim()
                ));
                return None;
            }
            assert_success(&create_v6);
        }
        cleanup.sets.push(ipv6_set.clone());
        Some(Self {
            command,
            ipv4_set,
            ipv6_set,
            cleanup,
        })
    }

    fn admission_config(&self, not_found: IpSetNotFound) -> IpSetConfig {
        IpSetConfig {
            enabled: true,
            ipv4_set: self.ipv4_set.clone(),
            ipv6_set: self.ipv6_set.clone(),
            not_found,
        }
    }

    fn proxy_config(
        &self,
        dns_server: SocketAddr,
        port: u16,
        not_found: IpSetNotFound,
        inspect_timeout_ms: u64,
    ) -> Config {
        let not_found = match not_found {
            IpSetNotFound::Allow => "allow",
            IpSetNotFound::FirstResponse => "first_response",
            IpSetNotFound::Reject => "reject",
            IpSetNotFound::Silent => "silent",
        };
        Config::from_toml(&format!(
            r#"
[server]
max_connections = 16
inspect_max_bytes = 4096
inspect_timeout_ms = {inspect_timeout_ms}
connect_timeout_ms = 500
initial_write_timeout_ms = 500
idle_timeout_secs = 10
shutdown_grace_secs = 2

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
allow_upstream_cidrs = ["127.0.0.0/8"]

[ipset]
enabled = true
ipv4_set = "{}"
ipv6_set = "{}"
not_found = "{not_found}"

[[listeners]]
protocol = "tcp"
listen = "127.0.0.1:{port}"
"#,
            self.ipv4_set, self.ipv6_set
        ))
        .expect("valid IPset proxy test config")
    }

    fn add_v4(&self, address: &str) {
        assert_success(&run(&self.command, ["add", &self.ipv4_set, address]));
    }

    fn add_v6(&self, address: &str) {
        assert_success(&run(&self.command, ["add", &self.ipv6_set, address]));
    }

    fn del_v4(&self, address: &str) {
        assert_success(&run(&self.command, ["del", &self.ipv4_set, address]));
    }

    fn destroy_ipv4(&mut self) {
        self.cleanup.destroy_checked(&self.ipv4_set);
    }

    fn destroy_ipv6(&mut self) {
        self.cleanup.destroy_checked(&self.ipv6_set);
    }

    fn recreate_ipv6(&mut self) {
        assert_success(&run(
            &self.command,
            ["create", &self.ipv6_set, "hash:ip", "family", "inet6"],
        ));
        self.cleanup.sets.push(self.ipv6_set.clone());
    }
}

struct RunningProxy {
    address: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<(), rs_proxy::server::ServerError>>,
}

impl RunningProxy {
    async fn start(config: &Config) -> Self {
        let server = ProxyServer::bind(config).await.expect("bind proxy");
        let addresses = server.local_addresses();
        assert_eq!(addresses.len(), 1, "test config has one TCP listener");
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(server.serve_until(async move {
            let _ = shutdown_rx.await;
        }));
        Self {
            address: addresses[0],
            shutdown: Some(shutdown),
            task,
        }
    }

    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        timeout(TEST_TIMEOUT, self.task)
            .await
            .expect("proxy shutdown timed out")
            .expect("proxy task panicked")
            .expect("proxy serve failed");
    }
}

struct FakeDns {
    address: SocketAddr,
    queries: Arc<Mutex<Vec<(String, u16)>>>,
    task: JoinHandle<()>,
}

impl FakeDns {
    async fn bind(hostnames: &[&str]) -> io::Result<Self> {
        let answers = hostnames
            .iter()
            .map(|hostname| (hostname.to_ascii_lowercase(), IpAddr::V4(UPSTREAM_IP)))
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

    fn query_count(&self, hostname: &str) -> usize {
        self.queries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|(name, _)| name == &hostname.to_ascii_lowercase())
            .count()
    }

    fn stop(self) {
        self.task.abort();
    }
}

async fn bind_upstream(dns_server: SocketAddr) -> TcpListener {
    for _ in 0..32 {
        let listener = TcpListener::bind((UPSTREAM_IP, 0))
            .await
            .expect("bind IPv4 upstream");
        if listener.local_addr().unwrap().port() != dns_server.port() {
            return listener;
        }
    }
    panic!("could not allocate an upstream port distinct from fake DNS");
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

async fn expect_connection_rejected(address: SocketAddr, bytes: &[u8]) {
    match timeout(TEST_TIMEOUT, TcpStream::connect(address)).await {
        Ok(Ok(mut stream)) => {
            let _ = stream.write_all(bytes).await;
            expect_peer_closed(&mut stream).await;
        }
        Ok(Err(error)) if is_peer_close(&error) => {}
        Ok(Err(error)) => panic!("unexpected rejected-connect error: {error}"),
        Err(error) => panic!("rejected connection timed out: {error}"),
    }
}

async fn round_trip(address: SocketAddr, request: &[u8], reply_len: usize) -> Vec<u8> {
    try_round_trip(address, request, reply_len, TEST_TIMEOUT)
        .await
        .expect("proxy round trip")
}

async fn round_trip_after_recovery(
    address: SocketAddr,
    request: &[u8],
    reply_len: usize,
) -> Vec<u8> {
    let deadline = Instant::now() + REFRESH_DEADLINE;
    loop {
        let error = match try_round_trip(address, request, reply_len, Duration::from_secs(2)).await
        {
            Ok(reply) => return reply,
            Err(error) => error,
        };
        assert!(
            Instant::now() < deadline,
            "IPset snapshot did not recover within {REFRESH_DEADLINE:?}: {error}"
        );
        sleep(Duration::from_millis(50)).await;
    }
}

async fn try_round_trip(
    address: SocketAddr,
    request: &[u8],
    reply_len: usize,
    deadline: Duration,
) -> io::Result<Vec<u8>> {
    timeout(deadline, async {
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(request).await?;
        let mut reply = vec![0; reply_len];
        stream.read_exact(&mut reply).await?;
        Ok(reply)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy round trip timed out"))?
}

async fn wait_until_new_admissions_fail_closed(address: SocketAddr) {
    let deadline = Instant::now() + REFRESH_DEADLINE;
    loop {
        let mut stream = match timeout(TEST_TIMEOUT, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) if is_peer_close(&error) => return,
            Ok(Err(error)) => panic!("refresh probe connect failed unexpectedly: {error}"),
            Err(error) => panic!("refresh probe connect timed out: {error}"),
        };
        let mut byte = [0_u8; 1];
        match timeout(REFRESH_PROBE_WINDOW, stream.read(&mut byte)).await {
            Ok(Ok(0)) => return,
            Ok(Err(error)) if is_peer_close(&error) => return,
            Ok(Ok(count)) => panic!("refresh probe received {count} unexpected byte(s)"),
            Ok(Err(error)) => panic!("refresh probe read failed: {error}"),
            Err(_) => {}
        }
        drop(stream);
        assert!(
            Instant::now() < deadline,
            "new admissions did not fail closed within {REFRESH_DEADLINE:?}"
        );
        sleep(Duration::from_millis(50)).await;
    }
}

async fn read_http_request(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut request = Vec::new();
    loop {
        let mut chunk = [0_u8; 512];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "request closed before header terminator",
            ));
        }
        request.extend_from_slice(&chunk[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(request);
        }
        if request.len() > 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request exceeded test bound",
            ));
        }
    }
}

async fn expect_peer_closed(stream: &mut TcpStream) {
    let mut byte = [0_u8; 1];
    match timeout(CLOSE_TIMEOUT, stream.read(&mut byte)).await {
        Ok(Ok(0)) => {}
        Ok(Err(error)) if is_peer_close(&error) => {}
        Ok(Ok(count)) => panic!("rejected flow received {count} byte(s)"),
        Ok(Err(error)) => panic!("unexpected rejected-flow read error: {error}"),
        Err(error) => panic!("flow was not closed within {CLOSE_TIMEOUT:?}: {error}"),
    }
}

async fn join_io<T>(task: JoinHandle<io::Result<T>>) -> T {
    timeout(TEST_TIMEOUT, task)
        .await
        .expect("upstream task timed out")
        .expect("upstream task panicked")
        .expect("upstream I/O failed")
}

fn is_peer_close(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
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

fn find_ipset() -> Option<PathBuf> {
    [Path::new("/usr/sbin/ipset"), Path::new("/sbin/ipset")]
        .into_iter()
        .find(|path| path.is_file())
        .map(Path::to_path_buf)
        .or_else(|| {
            std::env::var_os("PATH")
                .into_iter()
                .flat_map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
                .map(|directory| directory.join("ipset"))
                .find(|path| path.is_file())
        })
}

fn trusted_tool(name: &str) -> Option<PathBuf> {
    [
        format!("/usr/sbin/{name}"),
        format!("/usr/bin/{name}"),
        format!("/sbin/{name}"),
        format!("/bin/{name}"),
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.is_file())
}

fn run<const N: usize>(command: &Path, arguments: [&str; N]) -> Output {
    run_result(command, arguments).expect("execute test command within three-second deadline")
}

fn run_result<const N: usize>(command: &Path, arguments: [&str; N]) -> io::Result<Output> {
    process_support::run_with_timeout(
        Command::new(command).args(arguments),
        Duration::from_secs(3),
        "test command exceeded the three-second deadline",
    )
    .map_err(|failure| {
        io::Error::new(
            failure.error.kind(),
            format!(
                "{}; stdout: {}; stderr: {}",
                failure.error,
                String::from_utf8_lossy(&failure.stdout).trim(),
                String::from_utf8_lossy(&failure.stderr).trim()
            ),
        )
    })
}

fn kernel_environment_unavailable(output: &Output) -> bool {
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    [
        "cannot open session to kernel",
        "operation not permitted",
        "permission denied",
        "function not implemented",
        "protocol not supported",
        "set type is not supported in the kernel",
    ]
    .iter()
    .any(|reason| stderr.contains(reason))
}

fn skip_or_fail(reason: &str) {
    assert!(
        std::env::var_os("RS_PROXY_REQUIRE_IPSET").as_deref() != Some(std::ffi::OsStr::new("1")),
        "required privileged IPset environment is unavailable: {reason}"
    );
    eprintln!("SKIP: {reason}");
}

#[derive(Debug, Eq, PartialEq)]
struct HostState {
    iptables: Vec<u8>,
    ip6tables: Vec<u8>,
    ipsets: Vec<u8>,
    namespaces: Vec<u8>,
    runtime_directory: PathState,
    firewall_lock: PathState,
}

impl HostState {
    fn capture(ip: &Path) -> Result<Self, String> {
        let ipv4_rules_command = trusted_tool("iptables-save")
            .ok_or_else(|| "trusted iptables-save is unavailable".to_owned())?;
        let ipv6_rules_command = trusted_tool("ip6tables-save")
            .ok_or_else(|| "trusted ip6tables-save is unavailable".to_owned())?;
        let ipset =
            trusted_tool("ipset").ok_or_else(|| "trusted ipset is unavailable".to_owned())?;
        Ok(Self {
            iptables: capture_stdout(&ipv4_rules_command, &[])?,
            ip6tables: capture_stdout(&ipv6_rules_command, &[])?,
            ipsets: capture_stdout(&ipset, &["save"])?,
            namespaces: capture_stdout(ip, &["netns", "list"])?,
            runtime_directory: PathState::capture(Path::new(FIREWALL_RUNTIME_DIR))?,
            firewall_lock: PathState::capture(Path::new(FIREWALL_LOCK_PATH))?,
        })
    }

    fn contains_namespace(&self, name: &str) -> bool {
        String::from_utf8_lossy(&self.namespaces)
            .lines()
            .any(|line| line.split_ascii_whitespace().next() == Some(name))
    }
}

#[derive(Debug, Eq, PartialEq)]
enum PathState {
    Missing,
    File(Vec<u8>),
    Directory(Vec<OsString>),
    Symlink(PathBuf),
    Other,
}

impl PathState {
    fn capture(path: &Path) -> Result<Self, String> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::Missing),
            Err(error) => return Err(format!("inspect {}: {error}", path.display())),
        };
        let file_type = metadata.file_type();
        if file_type.is_file() {
            return fs::read(path)
                .map(Self::File)
                .map_err(|error| format!("read {}: {error}", path.display()));
        }
        if file_type.is_dir() {
            let mut entries = fs::read_dir(path)
                .map_err(|error| format!("list {}: {error}", path.display()))?
                .map(|entry| {
                    entry
                        .map(|entry| entry.file_name())
                        .map_err(|error| format!("list {}: {error}", path.display()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            entries.sort();
            return Ok(Self::Directory(entries));
        }
        if file_type.is_symlink() {
            return fs::read_link(path)
                .map(Self::Symlink)
                .map_err(|error| format!("read link {}: {error}", path.display()));
        }
        Ok(Self::Other)
    }
}

fn capture_stdout(command: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = process_support::run_with_timeout(
        Command::new(command).args(args),
        Duration::from_secs(3),
        "host-state command exceeded three seconds",
    )
    .map_err(|failure| {
        format!(
            "run {}: {}; stdout: {}; stderr: {}",
            command.display(),
            failure.error,
            String::from_utf8_lossy(&failure.stdout).trim(),
            String::from_utf8_lossy(&failure.stderr).trim()
        )
    })?;
    if !output.status.success() {
        return Err(format!(
            "{} {:?} failed with {:?}: {}",
            command.display(),
            args,
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output.stdout)
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "ipset command failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
}

struct Cleanup {
    command: PathBuf,
    sets: Vec<String>,
}

impl Cleanup {
    fn destroy_checked(&mut self, set: &str) {
        assert_success(&run(&self.command, ["destroy", set]));
        let index = self
            .sets
            .iter()
            .position(|candidate| candidate == set)
            .expect("destroyed set must be tracked for cleanup");
        self.sets.remove(index);
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for set in self.sets.iter().rev() {
            let _ = run_result(&self.command, ["destroy", set]);
        }
    }
}
