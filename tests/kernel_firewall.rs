#![cfg(target_os = "linux")]

use std::{
    env,
    ffi::OsString,
    fs,
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::Duration,
};

#[path = "support/process.rs"]
mod process_support;

use rs_proxy::{
    config::{IpSetConfig, IpSetNotFound, ListenerConfig, ListenerProtocol},
    firewall::{FirewallError, FirewallProtocol, KernelFirewall},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{sleep, timeout},
};

const CHILD_ENV: &str = "RS_PROXY_KERNEL_FIREWALL_CHILD";
const FIREWALL_RUNTIME_DIR: &str = "/run/rs-proxy";
const FIREWALL_LOCK_PATH: &str = "/run/rs-proxy/firewall.lock";
const TEST_TIMEOUT: Duration = Duration::from_secs(3);
const SILENT_WINDOW: Duration = Duration::from_millis(300);
const SUPERVISION_FAULT_ENV: &str = "RS_PROXY_PROCESS_SUPERVISION_FAULT";

#[test]
fn strict_kernel_policies_are_packet_verified_in_an_isolated_netns() {
    if env::var_os(CHILD_ENV).is_some() {
        mount_private_test_filesystems();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build child runtime");
        runtime.block_on(run_in_namespace());
        return;
    }

    if !process_support::group_kill_available() {
        skip_or_fail("fixed /bin/kill or /usr/bin/kill is unavailable");
        return;
    }

    let Some(ip) = trusted_tool("ip") else {
        skip_or_fail("/usr/sbin/ip is unavailable");
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
        "tcpdump",
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
        "rsp-kfw-{:x}-{:x}",
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
        if capability_unavailable(&create) {
            skip_or_fail(&format!(
                "network namespace/CAP_SYS_ADMIN unavailable: {}",
                String::from_utf8_lossy(&create.stderr).trim()
            ));
            return;
        }
        assert_success(&create);
    }
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        run_strict_child(&ip, &namespace);
    }));

    let cleanup = run(&ip, ["netns", "del", &namespace]);
    let after = HostState::capture(&ip).expect("snapshot host state after netns cleanup");
    assert_success(&cleanup);
    assert_eq!(
        before, after,
        "isolated firewall test changed host firewall, IPset, netns, or runtime-lock state"
    );
    if let Err(payload) = outcome {
        resume_unwind(payload);
    }
}

fn run_strict_child(ip: &Path, namespace: &str) {
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
                "strict_kernel_policies_are_packet_verified_in_an_isolated_netns",
                "--nocapture",
                "--test-threads=1",
            ]),
        Duration::from_secs(60),
        "kernel firewall child exceeded 60 seconds",
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
        "kernel firewall child failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "invoked as a supervised fault-injection child"]
// The descendant must outlive this group leader so the supervisor has to
// terminate it rather than relying on a direct-child wait.
#[allow(clippy::zombie_processes)]
fn process_supervision_fault_child() {
    match env::var(SUPERVISION_FAULT_ENV).as_deref() {
        Ok("pressure") => {
            let chunk = [b'x'; 8 * 1024];
            for _ in 0..1024 {
                io::stdout().write_all(&chunk).expect("write child stdout");
            }
            for _ in 0..1024 {
                io::stderr().write_all(&chunk).expect("write child stderr");
            }
        }
        Ok("pressure-timeout") => {
            let chunk = [b'x'; 8 * 1024];
            for _ in 0..1024 {
                io::stdout().write_all(&chunk).expect("write child stdout");
            }
            for _ in 0..1024 {
                io::stderr().write_all(&chunk).expect("write child stderr");
            }
            std::thread::sleep(Duration::from_secs(30));
        }
        Ok("sleeper") => std::thread::sleep(Duration::from_secs(30)),
        Ok("descendant") => {
            let executable = env::current_exe().expect("fault child executable");
            let descendant = Command::new(executable)
                .env(SUPERVISION_FAULT_ENV, "sleeper")
                .args([
                    "--ignored",
                    "--exact",
                    "process_supervision_fault_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .spawn()
                .expect("spawn fault descendant");
            println!("DESCENDANT_PID={}", descendant.id());
            io::stdout().flush().expect("flush descendant pid");
        }
        mode => panic!("unexpected supervision fault mode: {mode:?}"),
    }
}

#[test]
fn process_supervision_drains_and_bounds_output_pressure() {
    if !process_support::group_kill_available() {
        eprintln!("SKIP: fixed /bin/kill or /usr/bin/kill is unavailable");
        return;
    }
    let executable = env::current_exe().expect("fault child executable");
    let failure = process_support::run_with_timeout(
        Command::new(executable)
            .env(SUPERVISION_FAULT_ENV, "pressure")
            .args([
                "--ignored",
                "--exact",
                "process_supervision_fault_child",
                "--nocapture",
                "--test-threads=1",
            ]),
        Duration::from_secs(10),
        "output-pressure fault child exceeded ten seconds",
    )
    .expect_err("output-pressure child must report bounded capture truncation");
    assert_eq!(failure.error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(failure.stdout.len(), 4 * 1024 * 1024);
    assert_eq!(failure.stderr.len(), 4 * 1024 * 1024);
}

#[test]
fn process_supervision_timeout_kills_descendant_group() {
    if !process_support::group_kill_available() {
        eprintln!("SKIP: fixed /bin/kill or /usr/bin/kill is unavailable");
        return;
    }
    let executable = env::current_exe().expect("fault child executable");
    let failure = process_support::run_with_timeout(
        Command::new(executable)
            .env(SUPERVISION_FAULT_ENV, "descendant")
            .args([
                "--ignored",
                "--exact",
                "process_supervision_fault_child",
                "--nocapture",
                "--test-threads=1",
            ]),
        Duration::from_secs(2),
        "descendant fault child reached its deadline",
    )
    .expect_err("descendant fault child must time out");
    assert_eq!(failure.error.kind(), io::ErrorKind::TimedOut);
    let stdout = String::from_utf8_lossy(&failure.stdout);
    let pid = stdout
        .lines()
        .find_map(|line| line.split_once("DESCENDANT_PID=").map(|(_, pid)| pid))
        .unwrap_or_else(|| panic!("fault child did not report its descendant pid:\n{stdout}"));
    let descendant = Path::new("/proc").join(pid);
    let reaped_deadline = std::time::Instant::now() + Duration::from_secs(2);
    while descendant.exists() && std::time::Instant::now() < reaped_deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !descendant.exists(),
        "descendant {pid} survived process-group termination"
    );
}

#[test]
fn process_supervision_reports_truncation_on_timeout() {
    if !process_support::group_kill_available() {
        eprintln!("SKIP: fixed /bin/kill or /usr/bin/kill is unavailable");
        return;
    }
    let executable = env::current_exe().expect("fault child executable");
    let failure = process_support::run_with_timeout(
        Command::new(executable)
            .env(SUPERVISION_FAULT_ENV, "pressure-timeout")
            .args([
                "--ignored",
                "--exact",
                "process_supervision_fault_child",
                "--nocapture",
                "--test-threads=1",
            ]),
        Duration::from_millis(300),
        "output-pressure fault child reached its deadline",
    )
    .expect_err("output-pressure child must time out");
    assert_eq!(failure.error.kind(), io::ErrorKind::TimedOut);
    let message = failure.error.to_string();
    assert!(
        message.contains("stdout capture was truncated"),
        "{message}"
    );
    assert!(
        message.contains("stderr capture was truncated"),
        "{message}"
    );
    assert_eq!(failure.stdout.len(), 4 * 1024 * 1024);
    assert_eq!(failure.stderr.len(), 4 * 1024 * 1024);
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

async fn run_in_namespace() {
    let ipset = trusted_tool("ipset").expect("trusted ipset");
    let suffix = format!("{:x}", std::process::id());
    let ipv4_set = format!("rk{suffix}v4");
    let ipv6_set = format!("rk{suffix}v6");
    let sets = SetCleanup {
        command: ipset.clone(),
        names: vec![ipv4_set.clone(), ipv6_set.clone()],
    };
    assert_success(&run(
        &ipset,
        ["create", &ipv4_set, "hash:ip", "family", "inet"],
    ));
    assert_success(&run(
        &ipset,
        ["create", &ipv6_set, "hash:ip", "family", "inet6"],
    ));

    let port = reserve_port().await;
    verify_mapped_ipv6_listener_fails_closed(&ipv4_set, &ipv6_set, port).await;
    verify_silent_and_live_owner(&ipv4_set, &ipv6_set, port).await;
    verify_reject_and_live_membership(&ipset, &ipv4_set, &ipv6_set, port + 1).await;
    verify_first_response_drop_scope_and_recovery(&ipv4_set, &ipv6_set, port + 2).await;
    verify_enabled_policy_transition_recovery(&ipv4_set, &ipv6_set, port + 4).await;
    verify_orphan_flow_set_recovery_and_foreign_preservation(
        &ipset,
        &ipv4_set,
        &ipv6_set,
        port + 4,
    )
    .await;
    verify_foreign_chain_is_not_mutated(&ipv4_set, &ipv6_set, port + 6).await;
    assert_no_owned_artifacts();
    drop(sets);
}

async fn verify_mapped_ipv6_listener_fails_closed(ipv4_set: &str, ipv6_set: &str, port: u16) {
    let mapped = [listener(
        ListenerProtocol::Tcp,
        format!("[::ffff:127.0.0.1]:{port}")
            .parse()
            .expect("mapped IPv6 listener address"),
    )];
    let config = ipset_config(ipv4_set, ipv6_set, IpSetNotFound::Silent);
    let error = KernelFirewall::initialize(&config, &mapped, Duration::from_secs(2), 1)
        .await
        .expect_err("mapped IPv6 strict listener must fail closed before installing rules");
    assert!(matches!(
        error,
        FirewallError::AmbiguousMappedIpv6Listener(address)
            if address == mapped[0].listen
    ));
    assert_no_owned_artifacts();
}

async fn verify_silent_and_live_owner(ipv4_set: &str, ipv6_set: &str, port: u16) {
    let listeners = dual_family_listeners(port);
    let config = ipset_config(ipv4_set, ipv6_set, IpSetNotFound::Silent);
    let firewall = KernelFirewall::initialize(&config, &listeners, Duration::from_secs(2), 32)
        .await
        .expect("install silent rules")
        .expect("strict mode has firewall");

    let second = KernelFirewall::initialize(&config, &listeners, Duration::from_secs(2), 32)
        .await
        .expect_err("a live owner must exclude destructive recovery");
    assert!(matches!(second, FirewallError::InstanceLock { .. }));

    let capture = PacketCapture::start(port, "silent").await;
    let sockets = BoundSockets::bind(port).await;
    for address in tcp_addresses(port) {
        assert!(
            timeout(SILENT_WINDOW, TcpStream::connect(address))
                .await
                .is_err(),
            "silent TCP {address} answered instead of dropping SYN"
        );
    }
    for address in udp_addresses(port) {
        let socket = udp_client(address).await;
        socket.send(b"probe").await.expect("send silent UDP probe");
        let mut byte = [0_u8; 1];
        assert!(
            timeout(SILENT_WINDOW, socket.recv(&mut byte))
                .await
                .is_err(),
            "silent UDP {address} produced a response"
        );
    }
    sockets.assert_no_kernel_deliveries().await;
    drop(sockets);
    firewall.cleanup().await.expect("cleanup silent rules");
    let decoded = capture.stop();
    assert!(
        decoded.contains("Flags [S]"),
        "missing captured SYN:\n{decoded}"
    );
    assert!(
        !decoded.contains("Flags [S.]"),
        "silent emitted SYN-ACK:\n{decoded}"
    );
    assert!(
        !decoded.contains("Flags [R"),
        "silent emitted RST:\n{decoded}"
    );
    assert!(!decoded.contains("ICMP"), "silent emitted ICMP:\n{decoded}");
}

async fn verify_reject_and_live_membership(
    ipset: &Path,
    ipv4_set: &str,
    ipv6_set: &str,
    port: u16,
) {
    let listeners = dual_family_listeners(port);
    let config = ipset_config(ipv4_set, ipv6_set, IpSetNotFound::Reject);
    let firewall = KernelFirewall::initialize(&config, &listeners, Duration::from_secs(2), 32)
        .await
        .expect("install reject rules")
        .expect("strict mode has firewall");
    let capture = PacketCapture::start(port, "reject").await;
    let sockets = BoundSockets::bind(port).await;

    for address in tcp_addresses(port) {
        let result = timeout(TEST_TIMEOUT, TcpStream::connect(address))
            .await
            .expect("reject TCP timed out");
        assert!(result.is_err(), "reject TCP {address} connected");
    }
    for address in udp_addresses(port) {
        let socket = udp_client(address).await;
        socket
            .send(b"probe")
            .await
            .expect("send rejected UDP probe");
        let mut byte = [0_u8; 1];
        let result = timeout(TEST_TIMEOUT, socket.recv(&mut byte))
            .await
            .expect("reject UDP timed out");
        assert!(result.is_err(), "reject UDP {address} produced data");
    }

    assert_success(&run(ipset, ["add", ipv4_set, "127.0.0.1"]));
    assert_success(&run(ipset, ["add", ipv6_set, "::1"]));
    sockets.assert_member_tcp_udp_relay().await;
    assert_success(&run(ipset, ["del", ipv4_set, "127.0.0.1"]));
    assert_success(&run(ipset, ["del", ipv6_set, "::1"]));

    drop(sockets);
    firewall.cleanup().await.expect("cleanup reject rules");
    let decoded = capture.stop();
    assert!(
        decoded.contains("Flags [R.]"),
        "reject omitted TCP RST:\n{decoded}"
    );
    assert!(
        decoded.contains("ICMP"),
        "reject omitted UDP ICMP:\n{decoded}"
    );
    assert!(
        decoded.contains("ICMP6"),
        "reject omitted UDP ICMPv6:\n{decoded}"
    );
}

#[allow(
    clippy::too_many_lines,
    reason = "one packet-level lifecycle scenario keeps capture, tuple scope, and crash recovery together"
)]
async fn verify_first_response_drop_scope_and_recovery(ipv4_set: &str, ipv6_set: &str, port: u16) {
    let listeners = vec![
        listener(
            ListenerProtocol::Tcp,
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        ),
        listener(
            ListenerProtocol::Udp,
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        ),
        listener(
            ListenerProtocol::Udp,
            SocketAddr::from((Ipv4Addr::LOCALHOST, port + 1)),
        ),
    ];
    let config = ipset_config(ipv4_set, ipv6_set, IpSetNotFound::FirstResponse);
    let firewall = KernelFirewall::initialize(&config, &listeners, Duration::from_secs(2), 32)
        .await
        .expect("install first-response rules")
        .expect("first-response mode has firewall");
    let capture = PacketCapture::start(port, "first-response").await;

    let tcp_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .expect("bind first-response TCP");
    let connect = TcpStream::connect((Ipv4Addr::LOCALHOST, port));
    let (accepted, client) = tokio::join!(tcp_listener.accept(), connect);
    let (mut server_stream, _) = accepted.expect("accept first-response TCP");
    let mut client_stream = client.expect("connect first-response TCP");
    let client_address = client_stream.local_addr().expect("TCP client address");
    let tcp_reservation = firewall
        .reserve_first_response(
            FirewallProtocol::Tcp,
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            client_address,
        )
        .expect("reserve TCP flow-set capacity before response");
    client_stream
        .write_all(b"request")
        .await
        .expect("write TCP request");
    let mut request = [0_u8; 7];
    server_stream
        .read_exact(&mut request)
        .await
        .expect("read TCP request");
    server_stream
        .write_all(b"first")
        .await
        .expect("write first TCP response");
    server_stream
        .flush()
        .await
        .expect("flush first TCP response");
    let mut first = [0_u8; 5];
    client_stream
        .read_exact(&mut first)
        .await
        .expect("read first TCP response");
    firewall
        .block_flow_after_first_response(
            FirewallProtocol::Tcp,
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            client_address,
            tcp_reservation,
        )
        .await
        .expect("activate TCP post-response DROP");
    let _ = server_stream.write_all(b"second").await;
    drop(server_stream);
    let mut trailing = [0_u8; 16];
    assert!(
        timeout(SILENT_WINDOW, client_stream.read(&mut trailing))
            .await
            .is_err(),
        "TCP post-response path exposed data/FIN/RST"
    );

    let udp_listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .expect("bind first UDP listener");
    let udp_other = UdpSocket::bind((Ipv4Addr::LOCALHOST, port + 1))
        .await
        .expect("bind collision-scope UDP listener");
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind UDP client");
    client
        .connect((Ipv4Addr::LOCALHOST, port))
        .await
        .expect("connect UDP client");
    let client_address = client.local_addr().expect("UDP client address");
    let udp_reservation = firewall
        .reserve_first_response(
            FirewallProtocol::Udp,
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            client_address,
        )
        .expect("reserve UDP flow-set capacity before response");
    client.send(b"request").await.expect("send UDP request");
    let mut buffer = [0_u8; 64];
    let (_, peer) = udp_listener
        .recv_from(&mut buffer)
        .await
        .expect("receive UDP request");
    udp_listener
        .send_to(b"first", peer)
        .await
        .expect("send first UDP response");
    assert_eq!(
        client
            .recv(&mut buffer)
            .await
            .expect("receive first UDP response"),
        5
    );
    firewall
        .block_flow_after_first_response(
            FirewallProtocol::Udp,
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            client_address,
            udp_reservation,
        )
        .await
        .expect("activate UDP post-response DROP");
    assert_udp_send_or_kernel_drop(
        udp_listener.send_to(b"second", peer).await,
        6,
        "blocked UDP response",
    );
    assert_udp_send_or_kernel_drop(client.send(b"again").await, 5, "blocked UDP request");
    assert!(
        timeout(SILENT_WINDOW, client.recv(&mut buffer))
            .await
            .is_err()
    );
    assert!(
        timeout(SILENT_WINDOW, udp_listener.recv_from(&mut buffer))
            .await
            .is_err()
    );

    // The same source IP:port remains valid against another configured local port.
    client
        .connect((Ipv4Addr::LOCALHOST, port + 1))
        .await
        .expect("retarget UDP client");
    client
        .send(b"scope")
        .await
        .expect("send scoped UDP request");
    let (_, peer) = udp_other
        .recv_from(&mut buffer)
        .await
        .expect("other listener receives");
    udp_other
        .send_to(b"ok", peer)
        .await
        .expect("other listener responds");
    assert_eq!(
        client
            .recv(&mut buffer)
            .await
            .expect("receive scoped response"),
        2
    );

    drop((tcp_listener, client_stream, udp_listener, udp_other, client));
    let decoded = capture.stop();
    assert_no_proxy_fin_or_rst(&decoded, port);
    assert!(
        !decoded.contains("ICMP"),
        "post-response DROP emitted ICMP:\n{decoded}"
    );

    // Simulate a crash: dropping the manager releases only the singleton lock,
    // leaving rules. The next owner must recover them before reinstalling.
    drop(firewall);
    let recovered = KernelFirewall::initialize(&config, &listeners, Duration::from_secs(2), 32)
        .await
        .expect("recover stale owned firewall artifacts")
        .expect("recovered strict mode has firewall");
    recovered.cleanup().await.expect("cleanup recovered rules");
}

async fn verify_enabled_policy_transition_recovery(ipv4_set: &str, ipv6_set: &str, port: u16) {
    let dual_listeners = vec![
        listener(
            ListenerProtocol::Tcp,
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        ),
        listener(
            ListenerProtocol::Udp,
            SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
        ),
    ];
    let first_response = ipset_config(ipv4_set, ipv6_set, IpSetNotFound::FirstResponse);

    let stale =
        KernelFirewall::initialize(&first_response, &dual_listeners, Duration::from_secs(2), 3)
            .await
            .expect("install dual-family transition source")
            .expect("first-response transition source has firewall");
    drop(stale);

    let allow = ipset_config(ipv4_set, ipv6_set, IpSetNotFound::Allow);
    assert!(
        KernelFirewall::initialize(&allow, &dual_listeners, Duration::from_secs(2), 5)
            .await
            .expect("strict-to-allow recovers both available families")
            .is_none(),
        "allow must recover stale rules without installing a new firewall"
    );
    assert_no_owned_artifacts();

    let stale =
        KernelFirewall::initialize(&first_response, &dual_listeners, Duration::from_secs(2), 3)
            .await
            .expect("reinstall dual-family transition source")
            .expect("first-response transition source has firewall");
    drop(stale);

    let v4_listener = [listener(
        ListenerProtocol::Tcp,
        SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
    )];
    let silent = ipset_config(ipv4_set, ipv6_set, IpSetNotFound::Silent);
    let single = KernelFirewall::initialize(&silent, &v4_listener, Duration::from_secs(2), 5)
        .await
        .expect("dual-to-single recovers the unused IPv6 family")
        .expect("single-family strict policy has firewall");

    let ip6tables = trusted_tool("ip6tables").expect("trusted ip6tables");
    let rules = run(&ip6tables, ["-S"]);
    assert_success(&rules);
    assert!(
        !String::from_utf8_lossy(&rules.stdout).contains("RSPX_"),
        "dual-to-single transition stranded IPv6 rules"
    );
    let ipset = trusted_tool("ipset").expect("trusted ipset");
    assert!(
        !listed_ipsets(&ipset)
            .lines()
            .any(|name| name.starts_with("rspx_f6_")),
        "dual-to-single transition stranded an IPv6 flow set"
    );
    single
        .cleanup()
        .await
        .expect("cleanup single-family transition target");
}

async fn verify_orphan_flow_set_recovery_and_foreign_preservation(
    ipset: &Path,
    ipv4_set: &str,
    ipv6_set: &str,
    port: u16,
) {
    const OWNED_V4: &str = "rspx_f4_0123456789abcdef";
    const OWNED_V6: &str = "rspx_f6_0123456789abcdef";
    const FOREIGN_V4: &str = "rspx_f4_fedcba9876543210";
    create_owned_orphan_flow_set(ipset, OWNED_V4, "inet", "255.255.255.255,tcp:1");
    create_owned_orphan_flow_set(ipset, OWNED_V6, "inet6", "ff02::1,tcp:1");

    let listeners = vec![
        listener(
            ListenerProtocol::Tcp,
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        ),
        listener(
            ListenerProtocol::Tcp,
            SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
        ),
    ];
    let config = ipset_config(ipv4_set, ipv6_set, IpSetNotFound::Silent);
    let firewall = KernelFirewall::initialize(&config, &listeners, Duration::from_secs(2), 1)
        .await
        .expect("recover independently owned orphan flow sets")
        .expect("strict mode has firewall");
    let sets = listed_ipsets(ipset);
    assert!(
        !sets.lines().any(|name| matches!(name, OWNED_V4 | OWNED_V6)),
        "owned orphan flow set survived recovery:\n{sets}"
    );
    firewall
        .cleanup()
        .await
        .expect("cleanup orphan-recovery rules");
    drop(firewall);

    assert_success(&run(
        ipset,
        [
            "create",
            FOREIGN_V4,
            "hash:ip,port",
            "family",
            "inet",
            "timeout",
            "2",
            "maxelem",
            "1000001",
            "comment",
        ],
    ));
    let error = KernelFirewall::initialize(&config, &listeners[..1], Duration::from_secs(2), 1)
        .await
        .expect_err("unmarked reserved flow set must fail closed");
    assert!(
        matches!(&error, FirewallError::SetupCleanup { .. }),
        "a failed setup rollback must surface both errors"
    );
    assert!(matches!(
        firewall_setup_cause(&error),
        FirewallError::ForeignFlowSetCollision(names)
            if names == &[FOREIGN_V4.to_owned()]
    ));
    assert!(
        listed_ipsets(ipset).lines().any(|name| name == FOREIGN_V4),
        "foreign reserved flow set was mutated"
    );
    assert_success(&run(ipset, ["destroy", FOREIGN_V4]));
}

fn create_owned_orphan_flow_set(ipset: &Path, name: &str, family: &str, sentinel: &str) {
    assert_success(&run(
        ipset,
        [
            "create",
            name,
            "hash:ip,port",
            "family",
            family,
            "timeout",
            "2",
            "maxelem",
            "1000001",
            "comment",
        ],
    ));
    assert_success(&run(
        ipset,
        [
            "add",
            name,
            sentinel,
            "timeout",
            "0",
            "comment",
            "rs-proxy-owned-v1",
        ],
    ));
}

async fn verify_foreign_chain_is_not_mutated(ipv4_set: &str, ipv6_set: &str, port: u16) {
    let iptables = trusted_tool("iptables").expect("trusted iptables");
    assert_success(&run(&iptables, ["-N", "RSPX_FOREIGN"]));
    let listeners = vec![listener(
        ListenerProtocol::Tcp,
        SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
    )];
    let config = ipset_config(ipv4_set, ipv6_set, IpSetNotFound::Silent);
    let error = KernelFirewall::initialize(&config, &listeners, Duration::from_secs(2), 32)
        .await
        .expect_err("unmarked reserved chain must fail closed");
    assert!(
        matches!(&error, FirewallError::SetupCleanup { .. }),
        "a failed setup rollback must surface both errors"
    );
    assert!(matches!(
        firewall_setup_cause(&error),
        FirewallError::ForeignChainCollision(_)
    ));
    assert_success(&run(&iptables, ["-S", "RSPX_FOREIGN"]));
    assert_success(&run(&iptables, ["-X", "RSPX_FOREIGN"]));
}

struct BoundSockets {
    tcp_v4: TcpListener,
    tcp_v6: TcpListener,
    udp_v4: UdpSocket,
    udp_v6: UdpSocket,
    port: u16,
}

impl BoundSockets {
    async fn bind(port: u16) -> Self {
        Self {
            tcp_v4: TcpListener::bind((Ipv4Addr::LOCALHOST, port))
                .await
                .expect("bind TCP v4"),
            tcp_v6: TcpListener::bind((Ipv6Addr::LOCALHOST, port))
                .await
                .expect("bind TCP v6"),
            udp_v4: UdpSocket::bind((Ipv4Addr::LOCALHOST, port))
                .await
                .expect("bind UDP v4"),
            udp_v6: UdpSocket::bind((Ipv6Addr::LOCALHOST, port))
                .await
                .expect("bind UDP v6"),
            port,
        }
    }

    async fn assert_member_tcp_udp_relay(&self) {
        for (listener, address) in [
            (
                &self.tcp_v4,
                SocketAddr::from((Ipv4Addr::LOCALHOST, self.port)),
            ),
            (
                &self.tcp_v6,
                SocketAddr::from((Ipv6Addr::LOCALHOST, self.port)),
            ),
        ] {
            let connect = TcpStream::connect(address);
            let (accepted, client) = tokio::join!(listener.accept(), connect);
            let (mut accepted, _) = accepted.expect("accept member TCP");
            let mut client = client.expect("connect member TCP");
            accepted.write_all(b"ok").await.expect("write member TCP");
            let mut reply = [0_u8; 2];
            client
                .read_exact(&mut reply)
                .await
                .expect("read member TCP");
            assert_eq!(&reply, b"ok");
        }

        for (server, address) in [
            (
                &self.udp_v4,
                SocketAddr::from((Ipv4Addr::LOCALHOST, self.port)),
            ),
            (
                &self.udp_v6,
                SocketAddr::from((Ipv6Addr::LOCALHOST, self.port)),
            ),
        ] {
            let client = udp_client(address).await;
            client.send(b"member").await.expect("send member UDP");
            let mut buffer = [0_u8; 16];
            let (_, peer) = server
                .recv_from(&mut buffer)
                .await
                .expect("receive member UDP");
            server
                .send_to(b"ok", peer)
                .await
                .expect("respond member UDP");
            assert_eq!(client.recv(&mut buffer).await.expect("read member UDP"), 2);
        }
    }

    async fn assert_no_kernel_deliveries(&self) {
        assert!(timeout(SILENT_WINDOW, self.tcp_v4.accept()).await.is_err());
        assert!(timeout(SILENT_WINDOW, self.tcp_v6.accept()).await.is_err());
        let mut buffer = [0_u8; 16];
        assert!(
            timeout(SILENT_WINDOW, self.udp_v4.recv_from(&mut buffer))
                .await
                .is_err()
        );
        assert!(
            timeout(SILENT_WINDOW, self.udp_v6.recv_from(&mut buffer))
                .await
                .is_err()
        );
    }
}

struct PacketCapture {
    child: Child,
    path: PathBuf,
}

impl PacketCapture {
    async fn start(port: u16, label: &str) -> Self {
        let tcpdump = trusted_tool("tcpdump").expect("trusted tcpdump");
        let path = PathBuf::from(format!(
            "/tmp/rs-proxy-{label}-{}-{port}.pcap",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let child = Command::new(&tcpdump)
            .args(["-i", "lo", "-n", "-U", "-w"])
            .arg(&path)
            .arg(format!("port {port} or port {} or icmp or icmp6", port + 1))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start tcpdump");
        let mut capture = Self { child, path };
        let ready_deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if fs::metadata(&capture.path).is_ok_and(|metadata| metadata.len() >= 24) {
                break;
            }
            if let Some(status) = capture.child.try_wait().expect("poll tcpdump startup") {
                panic!("tcpdump exited before capture became ready: {status}");
            }
            assert!(
                std::time::Instant::now() < ready_deadline,
                "tcpdump did not create a ready pcap header within two seconds"
            );
            sleep(Duration::from_millis(20)).await;
        }
        // The pcap header proves the file is open; allow filter attachment and
        // interface activation to settle before emitting the first probe.
        sleep(Duration::from_millis(200)).await;
        capture
    }

    fn stop(mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let tcpdump = trusted_tool("tcpdump").expect("trusted tcpdump");
        let output = process_support::run_with_timeout(
            Command::new(tcpdump).args(["-nn", "-r"]).arg(&self.path),
            Duration::from_secs(3),
            "tcpdump capture decode exceeded three seconds",
        )
        .unwrap_or_else(|failure| {
            panic!(
                "decode packet capture: {}\nstdout:\n{}\nstderr:\n{}",
                failure.error,
                String::from_utf8_lossy(&failure.stdout),
                String::from_utf8_lossy(&failure.stderr)
            )
        });
        let _ = fs::remove_file(&self.path);
        assert_success(&output);
        String::from_utf8(output.stdout).expect("tcpdump output is UTF-8")
    }
}

impl Drop for PacketCapture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.path);
    }
}

fn assert_no_proxy_fin_or_rst(capture: &str, listener_port: u16) {
    let server_prefix = format!("127.0.0.1.{listener_port} >");
    for line in capture.lines().filter(|line| line.contains(&server_prefix)) {
        assert!(
            !line.contains("Flags [F") && !line.contains("Flags [R"),
            "proxy emitted FIN/RST after first-response block:\n{capture}"
        );
    }
}

fn assert_udp_send_or_kernel_drop(result: std::io::Result<usize>, expected: usize, label: &str) {
    match result {
        Ok(written) => assert_eq!(written, expected, "short {label}"),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
        Err(error) => panic!("unexpected {label} send error: {error}"),
    }
}

fn dual_family_listeners(port: u16) -> Vec<ListenerConfig> {
    vec![
        listener(
            ListenerProtocol::Tcp,
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        ),
        listener(
            ListenerProtocol::Udp,
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        ),
        listener(
            ListenerProtocol::Tcp,
            SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
        ),
        listener(
            ListenerProtocol::Udp,
            SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
        ),
    ]
}

fn listener(protocol: ListenerProtocol, listen: SocketAddr) -> ListenerConfig {
    ListenerConfig { protocol, listen }
}

fn tcp_addresses(port: u16) -> [SocketAddr; 2] {
    [
        SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
    ]
}

fn udp_addresses(port: u16) -> [SocketAddr; 2] {
    tcp_addresses(port)
}

async fn udp_client(address: SocketAddr) -> UdpSocket {
    let bind = match address.ip() {
        IpAddr::V4(_) => SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        IpAddr::V6(_) => SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
    };
    let socket = UdpSocket::bind(bind).await.expect("bind UDP client");
    socket.connect(address).await.expect("connect UDP client");
    socket
}

async fn reserve_port() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("reserve test port");
    let port = listener.local_addr().expect("reserved address").port();
    assert!(port <= u16::MAX - 8, "ephemeral port leaves no test range");
    drop(listener);
    port
}

fn ipset_config(ipv4_set: &str, ipv6_set: &str, not_found: IpSetNotFound) -> IpSetConfig {
    IpSetConfig {
        enabled: true,
        ipv4_set: ipv4_set.to_owned(),
        ipv6_set: ipv6_set.to_owned(),
        not_found,
    }
}

fn assert_no_owned_artifacts() {
    for tool in ["iptables", "ip6tables"] {
        let command = trusted_tool(tool).expect("trusted firewall tool");
        let output = run(&command, ["-S"]);
        assert_success(&output);
        let rules = String::from_utf8_lossy(&output.stdout);
        assert!(
            !rules.contains("RSPX_"),
            "owned chain leaked in {tool}:\n{rules}"
        );
    }
    let ipset = trusted_tool("ipset").expect("trusted ipset");
    let sets = listed_ipsets(&ipset);
    assert!(!sets.contains("rspx_f"), "owned flow set leaked:\n{sets}");
}

fn firewall_setup_cause(mut error: &FirewallError) -> &FirewallError {
    while let FirewallError::SetupCleanup { setup, .. } = error {
        error = setup;
    }
    error
}

fn listed_ipsets(ipset: &Path) -> String {
    let output = run(ipset, ["list", "-name"]);
    assert_success(&output);
    String::from_utf8(output.stdout).expect("ipset names are UTF-8")
}

fn trusted_tool(name: &str) -> Option<PathBuf> {
    [
        format!("/usr/sbin/{name}"),
        format!("/usr/bin/{name}"),
        format!("/sbin/{name}"),
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.is_file())
}

fn run<const N: usize>(command: &Path, args: [&str; N]) -> Output {
    process_support::run_with_timeout(
        Command::new(command).args(args),
        Duration::from_secs(3),
        "test command exceeded three seconds",
    )
    .unwrap_or_else(|failure| {
        panic!(
            "run {}: {}\nstdout:\n{}\nstderr:\n{}",
            command.display(),
            failure.error,
            String::from_utf8_lossy(&failure.stdout),
            String::from_utf8_lossy(&failure.stderr)
        )
    })
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed with {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
}

fn capability_unavailable(output: &Output) -> bool {
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    stderr.contains("operation not permitted")
        || stderr.contains("permission denied")
        || stderr.contains("cannot open session to kernel")
        || stderr.contains("function not implemented")
}

fn skip_or_fail(reason: &str) {
    assert!(
        env::var_os("RS_PROXY_REQUIRE_FIREWALL").is_none(),
        "required kernel firewall test cannot run: {reason}"
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
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::Missing);
            }
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

struct SetCleanup {
    command: PathBuf,
    names: Vec<String>,
}

impl Drop for SetCleanup {
    fn drop(&mut self) {
        for name in self.names.iter().rev() {
            let _ = run(&self.command, ["destroy", name]);
        }
    }
}
