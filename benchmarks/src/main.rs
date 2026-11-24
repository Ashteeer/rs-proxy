#![allow(
    clippy::too_many_lines,
    reason = "the standalone harness keeps each measured scenario inspectable in one file"
)]

use std::{
    collections::HashSet,
    fs,
    hint::black_box,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use clap::Parser;
use rs_proxy::{
    config::{Config, IpSetConfig, IpSetNotFound},
    inspect::{InspectedTcpProtocol, TcpInspectConfig, inspect_tcp_destination, quic::QuicVersion},
    ipset::{AdmissionDecision, IpSetAdmission},
    metrics::{RuntimeMetrics, Snapshot},
    server::ProxyServer,
};
use rustls::Side;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::oneshot,
    task::{JoinHandle, JoinSet},
    time::{sleep_until, timeout, timeout_at},
};

const TCP_HOSTNAME: &str = "tcp-bench.test";
const UDP_HOSTNAME: &str = "udp-bench.test";
const PROXY_IP: Ipv4Addr = Ipv4Addr::LOCALHOST;
const UPSTREAM_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_DRAIN_WINDOW: Duration = Duration::from_millis(200);
const MAX_PACKET_NUMBER: u64 = (1_u64 << 62) - 1;
const UDP_MAGIC: [u8; 4] = *b"RSPU";
const UDP_ROUTE_ACK: &[u8] = b"rs-proxy-bench-routed";

#[derive(Clone, Debug, Parser, Serialize)]
#[command(about = "Reproducible in-process RS-Proxy loopback baseline")]
struct Args {
    /// Measurement window for the TCP goodput and UDP packet-rate scenarios.
    #[arg(long, default_value_t = 5)]
    duration_secs: u64,

    /// Simultaneous long-lived TCP connections and UDP sessions.
    #[arg(long, default_value_t = 4)]
    concurrency: usize,

    /// Bytes in each verified TCP request and echo.
    #[arg(long, default_value_t = 65_536)]
    payload_bytes: usize,

    /// Bytes in each verified post-Initial UDP datagram and echo.
    #[arg(long, default_value_t = 1_200)]
    udp_payload_bytes: usize,

    /// Number of fresh TCP connections sampled after one excluded warm-up.
    #[arg(long, default_value_t = 100)]
    latency_samples: usize,

    /// In-memory complete and fragmented TLS inspector samples.
    #[arg(long, default_value_t = 10_000)]
    inspector_samples: usize,

    /// Existing legacy hash:ip IPv4 set; requires --ipset-ipv6-set too.
    #[arg(long)]
    ipset_ipv4_set: Option<String>,

    /// Existing legacy hash:ip IPv6 set; requires --ipset-ipv4-set too.
    #[arg(long)]
    ipset_ipv6_set: Option<String>,

    /// In-memory admission decisions when `IPset` names are supplied.
    #[arg(long, default_value_t = 1_000_000)]
    ipset_decision_samples: usize,
}

impl Args {
    fn validate(&self) -> Result<()> {
        ensure!(
            (1..=300).contains(&self.duration_secs),
            "--duration-secs must be in 1..=300"
        );
        ensure!(
            (1..=4_096).contains(&self.concurrency),
            "--concurrency must be in 1..=4096"
        );
        ensure!(
            (16..=1_048_576).contains(&self.payload_bytes),
            "--payload-bytes must be in 16..=1048576"
        );
        ensure!(
            (17..=60_000).contains(&self.udp_payload_bytes),
            "--udp-payload-bytes must be in 17..=60000"
        );
        ensure!(
            (1..=100_000).contains(&self.latency_samples),
            "--latency-samples must be in 1..=100000"
        );
        ensure!(
            (1..=1_000_000).contains(&self.inspector_samples),
            "--inspector-samples must be in 1..=1000000"
        );
        ensure!(
            self.ipset_ipv4_set.is_some() == self.ipset_ipv6_set.is_some(),
            "--ipset-ipv4-set and --ipset-ipv6-set must be supplied together"
        );
        ensure!(
            (1..=100_000_000).contains(&self.ipset_decision_samples),
            "--ipset-decision-samples must be in 1..=100000000"
        );
        Ok(())
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    args.validate()?;

    let fixture = Fixture::start(&args).await?;
    emit_json(&environment_record(&args, &fixture)?);

    let benchmark_result = run_benchmarks(&args, &fixture).await;
    let stop_result = fixture.stop().await;
    benchmark_result.and(stop_result)
}

async fn run_benchmarks(args: &Args, fixture: &Fixture) -> Result<()> {
    let tcp_hello = Arc::new(tcp_client_hello(TCP_HOSTNAME));
    run_tls_inspector_microbench(args, &tcp_hello).await?;
    run_ipset_decision_microbench(args).await?;
    run_tcp_warm_latency(args, fixture, Arc::clone(&tcp_hello)).await?;
    run_tcp_goodput(args, fixture, tcp_hello).await?;
    run_udp_packet_rate(args, fixture).await?;
    ensure!(
        fixture.dns_tcp_matching_queries.load(Ordering::Relaxed) > 0,
        "the explicit fake DNS server observed no matching TCP hostname query"
    );
    ensure!(
        fixture.dns_udp_matching_queries.load(Ordering::Relaxed) > 0,
        "the explicit fake DNS server observed no matching UDP hostname query"
    );
    Ok(())
}

async fn run_ipset_decision_microbench(args: &Args) -> Result<()> {
    let (Some(ipv4_set), Some(ipv6_set)) = (&args.ipset_ipv4_set, &args.ipset_ipv6_set) else {
        return Ok(());
    };
    let config = IpSetConfig {
        enabled: true,
        ipv4_set: Some(ipv4_set.clone()),
        ipv6_set: Some(ipv6_set.clone()),
        not_found: IpSetNotFound::Reject,
    };
    let admission = IpSetAdmission::initialize(&config)
        .await
        .context("initialize IPset decision benchmark")?
        .context("enabled IPset decision benchmark returned no admission state")?;
    let source = IpAddr::V4(PROXY_IP);
    ensure!(
        admission.decide(source)? == AdmissionDecision::Relay,
        "the benchmark IPv4 set must contain 127.0.0.1"
    );

    let started = Instant::now();
    for _ in 0..args.ipset_decision_samples {
        let decision = admission.decide(black_box(source))?;
        black_box(decision);
    }
    let elapsed = elapsed_ns(started.elapsed())?;
    emit_json(&json!({
        "kind": "ipset_snapshot_decision_rate",
        "schema_version": 1,
        "definition": "single-threaded exact-source membership decisions against an already loaded immutable legacy-IPset snapshot; initialization and refresh subprocess work excluded",
        "samples": args.ipset_decision_samples,
        "elapsed_ns": elapsed,
        "decisions_per_second": rate_per_second(u64::try_from(args.ipset_decision_samples)?, elapsed)?,
        "average_ns_per_decision": elapsed / u64::try_from(args.ipset_decision_samples)?,
        "source": "127.0.0.1",
        "caveat": "this does not measure Netfilter packet-rule cost, snapshot refresh, or concurrent cache effects",
    }));
    Ok(())
}

async fn run_tls_inspector_microbench(args: &Args, hello: &[u8]) -> Result<()> {
    let config = TcpInspectConfig {
        max_buffered_bytes: 64 * 1024,
        timeout: IO_TIMEOUT,
    };
    let mut complete = Vec::with_capacity(args.inspector_samples);
    let mut fragmented = Vec::with_capacity(args.inspector_samples);

    for _ in 0..args.inspector_samples {
        let (mut writer, mut reader) = tokio::io::duplex(hello.len() * 2);
        writer
            .write_all(hello)
            .await
            .context("prefill complete TLS inspector sample")?;
        let started = Instant::now();
        let inspection = inspect_tcp_destination(&mut reader, config)
            .await
            .context("inspect complete in-memory ClientHello")?;
        complete.push(elapsed_ns(started.elapsed())?);
        verify_inspection(&inspection, hello)?;
    }

    for _ in 0..args.inspector_samples {
        let (mut writer, mut reader) = tokio::io::duplex(1);
        let fragment = hello.to_vec();
        let writer_task = tokio::spawn(async move {
            for byte in fragment {
                writer.write_all(&[byte]).await?;
                tokio::task::yield_now().await;
            }
            Ok::<(), io::Error>(())
        });
        let started = Instant::now();
        let inspection = inspect_tcp_destination(&mut reader, config)
            .await
            .context("inspect byte-fragmented in-memory ClientHello")?;
        fragmented.push(elapsed_ns(started.elapsed())?);
        writer_task
            .await
            .context("fragmented TLS writer panicked")?
            .context("fragmented TLS writer failed")?;
        verify_inspection(&inspection, hello)?;
    }

    complete.sort_unstable();
    fragmented.sort_unstable();
    emit_json(&json!({
        "kind": "tls_inspector_latency",
        "schema_version": 1,
        "definition": "in-memory TCP dispatcher plus TLS ClientHello/SNI parsing; complete samples are prefilled before timing, fragmented samples deliver one byte per scheduled write",
        "samples_per_mode": args.inspector_samples,
        "client_hello_bytes": hello.len(),
        "complete": latency_summary(&complete),
        "byte_fragmented": latency_summary(&fragmented),
        "caveat": "the fragmented mode intentionally includes Tokio task scheduling; neither mode includes sockets, DNS, policy, or relay",
    }));
    Ok(())
}

fn verify_inspection(inspection: &rs_proxy::inspect::TcpInspection, hello: &[u8]) -> Result<()> {
    ensure!(
        inspection.protocol == InspectedTcpProtocol::Tls,
        "inspector microbenchmark selected a non-TLS protocol"
    );
    ensure!(
        inspection.server_name == TCP_HOSTNAME,
        "inspector microbenchmark returned the wrong SNI"
    );
    ensure!(
        inspection.buffered == hello,
        "inspector microbenchmark did not preserve exact bytes"
    );
    Ok(())
}

fn latency_summary(samples: &[u64]) -> Value {
    json!({
        "min_ns": samples[0],
        "p50_ns": percentile(samples, 50),
        "p95_ns": percentile(samples, 95),
        "p99_ns": percentile(samples, 99),
        "max_ns": samples[samples.len() - 1],
    })
}

fn emit_json(value: &Value) {
    println!(
        "{}",
        serde_json::to_string(&value).expect("benchmark result is JSON serializable")
    );
}

fn environment_record(args: &Args, fixture: &Fixture) -> Result<Value> {
    let timestamp_unix_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_millis(),
    )
    .context("timestamp does not fit u64")?;
    let proc_version = read_trimmed("/proc/version");
    let cpu_model = fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                line.strip_prefix("model name\t:")
                    .map(str::trim)
                    .map(ToOwned::to_owned)
            })
        });
    let wsl = proc_version
        .as_deref()
        .is_some_and(|version| version.to_ascii_lowercase().contains("microsoft"));

    Ok(json!({
        "kind": "environment",
        "schema_version": 1,
        "timestamp_unix_ms": timestamp_unix_ms,
        "args": args,
        "target_os": std::env::consts::OS,
        "target_arch": std::env::consts::ARCH,
        "logical_cpus_available": std::thread::available_parallelism().map_or(1, std::num::NonZero::get),
        "kernel_release": command_output("uname", &["-r"]),
        "proc_version": proc_version,
        "wsl_detected": wsl,
        "os_release": read_trimmed("/etc/os-release"),
        "cpu_model": cpu_model,
        "process_limits": read_trimmed("/proc/self/limits"),
        "build_rustc": env!("RS_PROXY_BENCH_RUSTC"),
        "source_hash_manifest": "sources.sha256 in the run output directory",
        "proxy_address": fixture.proxy_address,
        "upstream_address": fixture.upstream_address,
        "dns_address": fixture.dns_address,
        "harness": "single process: fake DNS, TCP/UDP echo upstreams, ProxyServer, and clients",
        "caveat": "loopback and in-process fixture results include client/upstream/harness scheduling and are not deployment capacity or a native-Linux claim; WSL results are WSL-only",
    }))
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|contents| contents.trim().to_owned())
}

struct Fixture {
    proxy_address: SocketAddr,
    upstream_address: SocketAddr,
    dns_address: SocketAddr,
    proxy_metrics: Arc<RuntimeMetrics>,
    dns_tcp_matching_queries: Arc<AtomicU64>,
    dns_udp_matching_queries: Arc<AtomicU64>,
    dns_total_queries: Arc<AtomicU64>,
    shutdown: oneshot::Sender<()>,
    proxy_task: JoinHandle<Result<(), rs_proxy::server::ServerError>>,
    background_tasks: Vec<JoinHandle<io::Result<()>>>,
}

impl Fixture {
    async fn start(args: &Args) -> Result<Self> {
        let dns = FakeDns::bind().await.context("bind fake DNS")?;
        let (port, tcp_upstream, udp_upstream) = reserve_fixture_port()
            .await
            .context("reserve a shared TCP/UDP fixture port")?;
        let max_connections = args
            .concurrency
            .checked_mul(4)
            .context("connection limit overflow")?
            .max(64);
        let idle_timeout_secs = args
            .duration_secs
            .checked_add(30)
            .context("idle timeout overflow")?;
        let ipset_section = match (&args.ipset_ipv4_set, &args.ipset_ipv6_set) {
            (Some(ipv4_set), Some(ipv6_set)) => format!(
                r#"
[ipset]
enabled = true
ipv4_set = {ipv4_set:?}
ipv6_set = {ipv6_set:?}
not_found = "allow"
"#
            ),
            (None, None) => String::new(),
            _ => unreachable!("argument validation requires both IPset names"),
        };
        let config = Config::from_toml(&format!(
            r#"
[server]
max_connections = {max_connections}
inspect_max_bytes = 4096
inspect_timeout_ms = 2000
connect_timeout_ms = 2000
initial_write_timeout_ms = 2000
idle_timeout_secs = {idle_timeout_secs}
shutdown_grace_secs = 3

[dns]
servers = ["{}"]
request_timeout_ms = 500
lookup_timeout_ms = 2000
attempts = 1
cache_size = 64
max_concurrent_queries = 64
max_active_requests = 64
max_addresses_per_lookup = 4
positive_max_ttl_secs = 60
negative_max_ttl_secs = 60

[routing]
allow_upstream_cidrs = ["127.0.0.2/32"]

{ipset_section}

[[listeners]]
protocol = "tcp"
listen = "127.0.0.1:{port}"

[[listeners]]
protocol = "udp"
listen = "127.0.0.1:{port}"
"#,
            dns.address,
        ))
        .context("construct benchmark proxy config")?;
        let server = ProxyServer::bind(&config)
            .await
            .context("bind benchmark ProxyServer")?;
        ensure!(
            server.local_addresses()
                == [
                    SocketAddr::from((PROXY_IP, port)),
                    SocketAddr::from((PROXY_IP, port))
                ],
            "ProxyServer did not bind the requested TCP and UDP addresses"
        );
        let proxy_metrics = server.metrics();

        let proxy_address = SocketAddr::from((PROXY_IP, port));
        let upstream_address = SocketAddr::from((UPSTREAM_IP, port));
        let (shutdown, shutdown_rx) = oneshot::channel();
        let proxy_task = tokio::spawn(server.serve_until(async move {
            let _ = shutdown_rx.await;
        }));
        let background_tasks = vec![
            dns.task,
            tokio::spawn(run_tcp_echo(tcp_upstream)),
            tokio::spawn(run_udp_echo(udp_upstream)),
        ];

        Ok(Self {
            proxy_address,
            upstream_address,
            dns_address: dns.address,
            proxy_metrics,
            dns_tcp_matching_queries: dns.tcp_matching_queries,
            dns_udp_matching_queries: dns.udp_matching_queries,
            dns_total_queries: dns.total_queries,
            shutdown,
            proxy_task,
            background_tasks,
        })
    }

    async fn stop(self) -> Result<()> {
        let _ = self.shutdown.send(());
        let proxy_result = timeout(IO_TIMEOUT, self.proxy_task)
            .await
            .context("ProxyServer shutdown timed out")?
            .context("ProxyServer task panicked")?
            .context("ProxyServer stopped with an error");
        for task in &self.background_tasks {
            task.abort();
        }
        for task in self.background_tasks {
            let _ = task.await;
        }
        proxy_result
    }
}

async fn reserve_fixture_port() -> io::Result<(u16, TcpListener, UdpSocket)> {
    for _ in 0..32 {
        let proxy_tcp = TcpListener::bind((PROXY_IP, 0)).await?;
        let port = proxy_tcp.local_addr()?.port();
        let Ok(proxy_udp) = UdpSocket::bind((PROXY_IP, port)).await else {
            continue;
        };
        let Ok(upstream_tcp) = TcpListener::bind((UPSTREAM_IP, port)).await else {
            continue;
        };
        let Ok(upstream_udp) = UdpSocket::bind((UPSTREAM_IP, port)).await else {
            continue;
        };
        drop(proxy_udp);
        drop(proxy_tcp);
        return Ok((port, upstream_tcp, upstream_udp));
    }
    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "could not reserve a shared TCP/UDP loopback port after 32 attempts",
    ))
}

async fn run_tcp_echo(listener: TcpListener) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (mut stream, _) = accepted?;
                connections.spawn(async move {
                    let mut buffer = vec![0_u8; 64 * 1024];
                    loop {
                        let length = stream.read(&mut buffer).await?;
                        if length == 0 {
                            return Ok::<(), io::Error>(());
                        }
                        stream.write_all(&buffer[..length]).await?;
                    }
                });
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                completed
                    .expect("non-empty TCP echo task set")
                    .map_err(io::Error::other)??;
            }
        }
    }
}

async fn run_udp_echo(socket: UdpSocket) -> io::Result<()> {
    let mut buffer = vec![0_u8; 65_535];
    let mut routed_peers = HashSet::new();
    loop {
        let (length, peer) = socket.recv_from(&mut buffer).await?;
        let response = if routed_peers.insert(peer) {
            UDP_ROUTE_ACK
        } else {
            &buffer[..length]
        };
        let sent = socket.send_to(response, peer).await?;
        if sent != response.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!(
                    "short UDP response: sent {sent} of {} bytes",
                    response.len()
                ),
            ));
        }
    }
}

struct FakeDns {
    address: SocketAddr,
    tcp_matching_queries: Arc<AtomicU64>,
    udp_matching_queries: Arc<AtomicU64>,
    total_queries: Arc<AtomicU64>,
    task: JoinHandle<io::Result<()>>,
}

impl FakeDns {
    async fn bind() -> io::Result<Self> {
        let socket = UdpSocket::bind((PROXY_IP, 0)).await?;
        let address = socket.local_addr()?;
        let tcp_matching_queries = Arc::new(AtomicU64::new(0));
        let udp_matching_queries = Arc::new(AtomicU64::new(0));
        let total_queries = Arc::new(AtomicU64::new(0));
        let task_tcp_matching = Arc::clone(&tcp_matching_queries);
        let task_udp_matching = Arc::clone(&udp_matching_queries);
        let task_total = Arc::clone(&total_queries);
        let task = tokio::spawn(async move {
            let mut buffer = [0_u8; 2_048];
            loop {
                let (length, peer) = socket.recv_from(&mut buffer).await?;
                let Some((response, tcp_matched, udp_matched)) = dns_response(&buffer[..length])
                else {
                    continue;
                };
                task_total.fetch_add(1, Ordering::Relaxed);
                if tcp_matched {
                    task_tcp_matching.fetch_add(1, Ordering::Relaxed);
                }
                if udp_matched {
                    task_udp_matching.fetch_add(1, Ordering::Relaxed);
                }
                socket.send_to(&response, peer).await?;
            }
        });
        Ok(Self {
            address,
            tcp_matching_queries,
            udp_matching_queries,
            total_queries,
            task,
        })
    }
}

fn dns_response(query: &[u8]) -> Option<(Vec<u8>, bool, bool)> {
    if query.len() < 12 || u16::from_be_bytes([query[4], query[5]]) != 1 {
        return None;
    }
    let (name, question_end) = parse_dns_question(query)?;
    let query_type = u16::from_be_bytes([query[question_end - 4], query[question_end - 3]]);
    let query_class = u16::from_be_bytes([query[question_end - 2], query[question_end - 1]]);
    let tcp_matched = name.eq_ignore_ascii_case(TCP_HOSTNAME) && query_class == 1;
    let udp_matched = name.eq_ignore_ascii_case(UDP_HOSTNAME) && query_class == 1;
    let matched = tcp_matched || udp_matched;
    let has_answer = matched && query_type == 1;

    let mut response = Vec::with_capacity(question_end + 16);
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&[0x81, 0x80, 0, 1]);
    response.extend_from_slice(if has_answer { &[0, 1] } else { &[0, 0] });
    let has_negative_soa = matched && !has_answer;
    response.extend_from_slice(if has_negative_soa {
        &[0, 1, 0, 0]
    } else {
        &[0, 0, 0, 0]
    });
    response.extend_from_slice(&query[12..question_end]);
    if has_answer {
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(&[0, 4]);
        response.extend_from_slice(&UPSTREAM_IP.octets());
    } else if has_negative_soa {
        response.extend_from_slice(&[0xc0, 0x0c, 0, 6, 0, 1]);
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(&22_u16.to_be_bytes());
        response.extend_from_slice(&[0, 0]);
        for field in [1_u32, 60, 60, 60, 60] {
            response.extend_from_slice(&field.to_be_bytes());
        }
    }
    Some((response, tcp_matched, udp_matched))
}

fn parse_dns_question(query: &[u8]) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut cursor = 12_usize;
    loop {
        let length = usize::from(*query.get(cursor)?);
        cursor = cursor.checked_add(1)?;
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

async fn run_tcp_warm_latency(args: &Args, fixture: &Fixture, hello: Arc<Vec<u8>>) -> Result<()> {
    tcp_route_once(fixture.proxy_address, &hello)
        .await
        .context("excluded TCP warm-up failed")?;
    let queries_before = fixture.dns_total_queries.load(Ordering::Relaxed);
    let next_sample = Arc::new(AtomicUsize::new(0));
    let mut workers = JoinSet::new();
    let worker_count = args.concurrency.min(args.latency_samples);
    for _ in 0..worker_count {
        let next_sample = Arc::clone(&next_sample);
        let hello = Arc::clone(&hello);
        let address = fixture.proxy_address;
        let total = args.latency_samples;
        workers.spawn(async move {
            let mut samples = Vec::new();
            loop {
                let index = next_sample.fetch_add(1, Ordering::Relaxed);
                if index >= total {
                    break;
                }
                samples.push(tcp_route_once(address, &hello).await?);
            }
            Ok::<_, anyhow::Error>(samples)
        });
    }
    let mut samples = Vec::with_capacity(args.latency_samples);
    while let Some(result) = workers.join_next().await {
        samples.extend(
            result
                .context("TCP latency worker panicked")?
                .context("TCP latency worker failed")?,
        );
    }
    ensure!(
        samples.len() == args.latency_samples,
        "TCP latency sample count mismatch"
    );
    samples.sort_unstable();
    let queries_after = fixture.dns_total_queries.load(Ordering::Relaxed);
    emit_json(&json!({
        "kind": "tcp_warm_route_latency",
        "schema_version": 1,
        "definition": "fresh TCP connect + TLS ClientHello write + byte-exact echoed ClientHello read; one prior route excluded; DNS resolver cache remains warm",
        "samples": samples.len(),
        "concurrency": worker_count,
        "min_ns": samples[0],
        "p50_ns": percentile(&samples, 50),
        "p95_ns": percentile(&samples, 95),
        "p99_ns": percentile(&samples, 99),
        "max_ns": samples[samples.len() - 1],
        "dns_queries_during_measurement": queries_after.saturating_sub(queries_before),
    }));
    Ok(())
}

async fn tcp_route_once(address: SocketAddr, hello: &[u8]) -> Result<u64> {
    timeout(IO_TIMEOUT, async {
        let started = Instant::now();
        let mut stream = TcpStream::connect(address)
            .await
            .context("connect TCP benchmark client")?;
        stream
            .set_nodelay(true)
            .context("set TCP_NODELAY on benchmark client")?;
        stream
            .write_all(hello)
            .await
            .context("write benchmark ClientHello")?;
        let mut echoed = vec![0_u8; hello.len()];
        stream
            .read_exact(&mut echoed)
            .await
            .context("read echoed benchmark ClientHello")?;
        ensure!(echoed == hello, "TCP ClientHello echo was not byte exact");
        elapsed_ns(started.elapsed())
    })
    .await
    .context("TCP warm route timed out")?
}

async fn run_tcp_goodput(args: &Args, fixture: &Fixture, hello: Arc<Vec<u8>>) -> Result<()> {
    let mut setup = JoinSet::new();
    for _ in 0..args.concurrency {
        let hello = Arc::clone(&hello);
        let address = fixture.proxy_address;
        setup.spawn(async move { establish_tcp_route(address, &hello).await });
    }
    let mut streams = Vec::with_capacity(args.concurrency);
    while let Some(result) = setup.join_next().await {
        streams.push(
            result
                .context("TCP setup worker panicked")?
                .context("TCP route setup failed")?,
        );
    }

    let start_at = tokio::time::Instant::now() + Duration::from_millis(50);
    let deadline = start_at + Duration::from_secs(args.duration_secs);
    let mut workers = JoinSet::new();
    for (worker_id, stream) in streams.into_iter().enumerate() {
        let payload_bytes = args.payload_bytes;
        workers.spawn(async move {
            run_tcp_goodput_worker(stream, worker_id, payload_bytes, start_at, deadline).await
        });
    }
    let mut total_iterations = 0_u64;
    let mut one_way_bytes = 0_u64;
    let mut latest_finished = start_at;
    while let Some(result) = workers.join_next().await {
        let worker = result
            .context("TCP goodput worker panicked")?
            .context("TCP goodput worker failed")?;
        total_iterations = total_iterations
            .checked_add(worker.iterations)
            .context("TCP iteration counter overflow")?;
        one_way_bytes = one_way_bytes
            .checked_add(worker.one_way_bytes)
            .context("TCP byte counter overflow")?;
        latest_finished = latest_finished.max(worker.finished_at);
    }
    let elapsed = latest_finished.saturating_duration_since(start_at);
    let relay_bytes = one_way_bytes
        .checked_mul(2)
        .context("TCP relay byte counter overflow")?;
    let elapsed_ns = elapsed_ns(elapsed)?;
    emit_json(&json!({
        "kind": "tcp_long_lived_goodput",
        "schema_version": 1,
        "definition": "route setup excluded; each application payload is verified after one upstream echo; one_way counts client-to-upstream payload and relay counts both directions",
        "concurrency": args.concurrency,
        "payload_bytes": args.payload_bytes,
        "iterations": total_iterations,
        "one_way_verified_bytes": one_way_bytes,
        "bidirectional_relay_verified_bytes": relay_bytes,
        "measurement_elapsed_ns": elapsed_ns,
        "one_way_verified_bytes_per_second": rate_per_second(one_way_bytes, elapsed_ns)?,
        "bidirectional_relay_verified_bytes_per_second": rate_per_second(relay_bytes, elapsed_ns)?,
    }));
    Ok(())
}

async fn establish_tcp_route(address: SocketAddr, hello: &[u8]) -> Result<TcpStream> {
    timeout(IO_TIMEOUT, async {
        let mut stream = TcpStream::connect(address)
            .await
            .context("connect long-lived TCP client")?;
        stream
            .set_nodelay(true)
            .context("set TCP_NODELAY on long-lived client")?;
        stream
            .write_all(hello)
            .await
            .context("write route-establishing ClientHello")?;
        let mut echoed = vec![0_u8; hello.len()];
        stream
            .read_exact(&mut echoed)
            .await
            .context("read route-establishing ClientHello echo")?;
        ensure!(
            echoed == hello,
            "long-lived TCP route setup was not byte exact"
        );
        Ok(stream)
    })
    .await
    .context("long-lived TCP route setup timed out")?
}

struct TcpWorkerResult {
    iterations: u64,
    one_way_bytes: u64,
    finished_at: tokio::time::Instant,
}

async fn run_tcp_goodput_worker(
    mut stream: TcpStream,
    worker_id: usize,
    payload_bytes: usize,
    start_at: tokio::time::Instant,
    deadline: tokio::time::Instant,
) -> Result<TcpWorkerResult> {
    let mut payload = tcp_payload(payload_bytes, worker_id, 0)?;
    let mut echoed = vec![0_u8; payload_bytes];
    let payload_bytes_u64 = u64::try_from(payload_bytes).context("payload size fits u64")?;
    let mut iterations = 0_u64;
    let mut one_way_bytes = 0_u64;
    sleep_until(start_at).await;
    while tokio::time::Instant::now() < deadline {
        payload[8..16].copy_from_slice(&iterations.to_be_bytes());
        timeout(IO_TIMEOUT, stream.write_all(&payload))
            .await
            .context("long-lived TCP write timed out")?
            .context("long-lived TCP write failed")?;
        timeout(IO_TIMEOUT, stream.read_exact(&mut echoed))
            .await
            .context("long-lived TCP read timed out")?
            .context("long-lived TCP read failed")?;
        ensure!(
            echoed == payload,
            "long-lived TCP echo was not byte exact for worker {worker_id}, iteration {iterations}"
        );
        iterations = iterations
            .checked_add(1)
            .context("TCP iteration counter overflow")?;
        one_way_bytes = one_way_bytes
            .checked_add(payload_bytes_u64)
            .context("TCP byte counter overflow")?;
    }
    Ok(TcpWorkerResult {
        iterations,
        one_way_bytes,
        finished_at: tokio::time::Instant::now(),
    })
}

fn tcp_payload(length: usize, worker_id: usize, sequence: u64) -> Result<Vec<u8>> {
    let mut payload = vec![0_u8; length];
    payload[..4].copy_from_slice(b"RSPT");
    payload[4..8].copy_from_slice(
        &u32::try_from(worker_id)
            .context("worker ID fits u32")?
            .to_be_bytes(),
    );
    payload[8..16].copy_from_slice(&sequence.to_be_bytes());
    for (index, byte) in payload[16..].iter_mut().enumerate() {
        *byte = u8::try_from((index + worker_id) % 251).expect("modulo 251 fits u8");
    }
    Ok(payload)
}

async fn run_udp_packet_rate(args: &Args, fixture: &Fixture) -> Result<()> {
    let metrics_before = fixture.proxy_metrics.snapshot();
    let queries_before = fixture.dns_udp_matching_queries.load(Ordering::Relaxed);
    let mut setup = JoinSet::new();
    for session_id in 0..args.concurrency {
        let address = fixture.proxy_address;
        setup.spawn(async move { establish_udp_route(address, session_id).await });
    }
    let mut sockets = Vec::with_capacity(args.concurrency);
    let mut setup_latencies = Vec::with_capacity(args.concurrency);
    while let Some(result) = setup.join_next().await {
        let (session_id, socket, latency) = result
            .context("UDP setup worker panicked")?
            .context("UDP route setup failed")?;
        sockets.push((session_id, socket));
        setup_latencies.push(latency);
    }
    setup_latencies.sort_unstable();

    let start_at = tokio::time::Instant::now() + Duration::from_millis(50);
    let deadline = start_at + Duration::from_secs(args.duration_secs);
    let mut workers = JoinSet::new();
    for (session_id, socket) in sockets {
        let payload_bytes = args.udp_payload_bytes;
        workers.spawn(async move {
            run_udp_worker(socket, session_id, payload_bytes, start_at, deadline).await
        });
    }
    let mut aggregate = UdpWorkerStats::default();
    while let Some(result) = workers.join_next().await {
        aggregate.merge(
            &result
                .context("UDP packet-rate worker panicked")?
                .context("UDP packet-rate worker failed")?,
        )?;
    }
    let queries_after = fixture.dns_udp_matching_queries.load(Ordering::Relaxed);
    let explicit_dns_queries = queries_after.saturating_sub(queries_before);
    ensure!(
        explicit_dns_queries > 0,
        "the cold UDP hostname route did not query the explicit fake DNS server"
    );
    let duration_ns = args
        .duration_secs
        .checked_mul(1_000_000_000)
        .context("UDP duration nanoseconds overflow")?;
    let loss = aggregate.sent.saturating_sub(aggregate.unique_received);
    let loss_ppm = ratio_parts_per_million(loss, aggregate.sent)?;
    let metrics_after = fixture.proxy_metrics.snapshot();
    emit_json(&json!({
        "kind": "udp_quic_v1_packet_rate",
        "schema_version": 1,
        "definition": "each connected client first completes a valid QUIC v1 Initial/SNI route and verifies a deterministic upstream route marker; timed traffic uses byte-verified short-header-shaped datagrams; rates normalize counts to the configured send window and receive includes the stated drain window",
        "sessions": args.concurrency,
        "payload_bytes": args.udp_payload_bytes,
        "route_setup_min_ns": setup_latencies[0],
        "route_setup_p50_ns": percentile(&setup_latencies, 50),
        "route_setup_p95_ns": percentile(&setup_latencies, 95),
        "route_setup_max_ns": setup_latencies[setup_latencies.len() - 1],
        "send_window_ns": duration_ns,
        "receive_drain_window_ns": elapsed_ns(UDP_DRAIN_WINDOW)?,
        "sent_datagrams": aggregate.sent,
        "unique_verified_datagrams": aggregate.unique_received,
        "lost_datagrams": loss,
        "loss_parts_per_million": loss_ppm,
        "duplicate_datagrams": aggregate.duplicates,
        "reordered_datagrams": aggregate.reordered,
        "invalid_datagrams": aggregate.invalid,
        "offered_datagrams_per_second": rate_per_second(aggregate.sent, duration_ns)?,
        "unique_verified_datagrams_per_second": rate_per_second(aggregate.unique_received, duration_ns)?,
        "explicit_dns_queries_during_udp_setup_and_measurement": explicit_dns_queries,
        "proxy_runtime_metrics": {
            "definition": "process-local ProxyServer snapshots bracket the complete UDP setup, timed send, and receive-drain phase; counter deltas are monotonic after-minus-before values, while active-flow gauges are reported only as point-in-time before/after values",
            "before_udp_phase": runtime_metrics_json(metrics_before),
            "after_udp_phase": runtime_metrics_json(metrics_after),
            "counter_deltas": runtime_counter_deltas_json(metrics_before, metrics_after),
        },
    }));
    ensure!(
        aggregate.invalid == 0,
        "received {} UDP datagram(s) that failed byte verification",
        aggregate.invalid
    );
    Ok(())
}

fn runtime_metrics_json(snapshot: Snapshot) -> Value {
    json!({
        "tcp_connections_accepted_total": snapshot.tcp_connections_accepted_total,
        "udp_sessions_started_total": snapshot.udp_sessions_started_total,
        "capacity_rejections_total": snapshot.capacity_rejections_total,
        "admission_denials_total": snapshot.admission_denials_total,
        "inspection_failures_total": snapshot.inspection_failures_total,
        "dns_failures_total": snapshot.dns_failures_total,
        "upstream_failures_total": snapshot.upstream_failures_total,
        "timeouts_total": snapshot.timeouts_total,
        "quic_retries_accepted_total": snapshot.quic_retries_accepted_total,
        "udp_amplification_drops_total": snapshot.udp_amplification_drops_total,
        "udp_datagrams_dropped_total": snapshot.udp_datagrams_dropped_total,
        "relays_completed_total": snapshot.relays_completed_total,
        "relay_failures_total": snapshot.relay_failures_total,
        "client_to_upstream_bytes_total": snapshot.client_to_upstream_bytes_total,
        "upstream_to_client_bytes_total": snapshot.upstream_to_client_bytes_total,
        "client_to_upstream_datagrams_total": snapshot.client_to_upstream_datagrams_total,
        "upstream_to_client_datagrams_total": snapshot.upstream_to_client_datagrams_total,
        "active_tcp_connections": snapshot.active_tcp_connections,
        "active_udp_sessions": snapshot.active_udp_sessions,
    })
}

fn runtime_counter_deltas_json(before: Snapshot, after: Snapshot) -> Value {
    json!({
        "tcp_connections_accepted_total": after.tcp_connections_accepted_total.saturating_sub(before.tcp_connections_accepted_total),
        "udp_sessions_started_total": after.udp_sessions_started_total.saturating_sub(before.udp_sessions_started_total),
        "capacity_rejections_total": after.capacity_rejections_total.saturating_sub(before.capacity_rejections_total),
        "admission_denials_total": after.admission_denials_total.saturating_sub(before.admission_denials_total),
        "inspection_failures_total": after.inspection_failures_total.saturating_sub(before.inspection_failures_total),
        "dns_failures_total": after.dns_failures_total.saturating_sub(before.dns_failures_total),
        "upstream_failures_total": after.upstream_failures_total.saturating_sub(before.upstream_failures_total),
        "timeouts_total": after.timeouts_total.saturating_sub(before.timeouts_total),
        "quic_retries_accepted_total": after.quic_retries_accepted_total.saturating_sub(before.quic_retries_accepted_total),
        "udp_amplification_drops_total": after.udp_amplification_drops_total.saturating_sub(before.udp_amplification_drops_total),
        "udp_datagrams_dropped_total": after.udp_datagrams_dropped_total.saturating_sub(before.udp_datagrams_dropped_total),
        "relays_completed_total": after.relays_completed_total.saturating_sub(before.relays_completed_total),
        "relay_failures_total": after.relay_failures_total.saturating_sub(before.relay_failures_total),
        "client_to_upstream_bytes_total": after.client_to_upstream_bytes_total.saturating_sub(before.client_to_upstream_bytes_total),
        "upstream_to_client_bytes_total": after.upstream_to_client_bytes_total.saturating_sub(before.upstream_to_client_bytes_total),
        "client_to_upstream_datagrams_total": after.client_to_upstream_datagrams_total.saturating_sub(before.client_to_upstream_datagrams_total),
        "upstream_to_client_datagrams_total": after.upstream_to_client_datagrams_total.saturating_sub(before.upstream_to_client_datagrams_total),
    })
}

async fn establish_udp_route(
    address: SocketAddr,
    session_id: usize,
) -> Result<(usize, UdpSocket, u64)> {
    let socket = UdpSocket::bind((PROXY_IP, 0))
        .await
        .context("bind UDP benchmark client")?;
    socket
        .connect(address)
        .await
        .context("connect UDP benchmark client")?;
    let dcid = u64::try_from(session_id)
        .context("session ID fits u64")?
        .wrapping_add(0x5253_5058_0000_0000)
        .to_be_bytes();
    let initial = encrypted_initial(
        QuicVersion::V1,
        &dcid,
        0,
        &crypto_frame(0, &quic_client_hello(UDP_HOSTNAME)),
    );
    let started = Instant::now();
    timeout(IO_TIMEOUT, async {
        let sent = socket
            .send(&initial)
            .await
            .context("send QUIC v1 Initial")?;
        ensure!(sent == initial.len(), "short QUIC Initial send");
        let mut response = vec![0_u8; UDP_ROUTE_ACK.len() + 1];
        let length = socket
            .recv(&mut response)
            .await
            .context("receive QUIC v1 route marker")?;
        ensure!(
            response[..length] == *UDP_ROUTE_ACK,
            "QUIC Initial route marker was not byte exact"
        );
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("QUIC v1 Initial route setup timed out")??;
    Ok((session_id, socket, elapsed_ns(started.elapsed())?))
}

#[derive(Default)]
struct UdpWorkerStats {
    sent: u64,
    unique_received: u64,
    duplicates: u64,
    reordered: u64,
    invalid: u64,
}

impl UdpWorkerStats {
    fn merge(&mut self, other: &Self) -> Result<()> {
        self.sent = checked_add(self.sent, other.sent, "UDP sent counter")?;
        self.unique_received = checked_add(
            self.unique_received,
            other.unique_received,
            "UDP receive counter",
        )?;
        self.duplicates = checked_add(self.duplicates, other.duplicates, "UDP duplicate counter")?;
        self.reordered = checked_add(self.reordered, other.reordered, "UDP reorder counter")?;
        self.invalid = checked_add(self.invalid, other.invalid, "UDP invalid counter")?;
        Ok(())
    }
}

async fn run_udp_worker(
    socket: UdpSocket,
    session_id: usize,
    payload_bytes: usize,
    start_at: tokio::time::Instant,
    deadline: tokio::time::Instant,
) -> Result<UdpWorkerStats> {
    let mut stats = UdpWorkerStats::default();
    let mut send_buffer = udp_payload(payload_bytes, session_id, 0)?;
    let mut receive_buffer = vec![0_u8; payload_bytes + 1];
    let mut received_sequences = Vec::<u64>::new();
    let mut highest_sequence = None;
    sleep_until(start_at).await;
    loop {
        tokio::select! {
            () = sleep_until(deadline) => break,
            received = socket.recv(&mut receive_buffer) => {
                let length = received.context("receive timed UDP echo")?;
                record_udp_receive(
                    &receive_buffer[..length],
                    session_id,
                    payload_bytes,
                    stats.sent,
                    &mut received_sequences,
                    &mut highest_sequence,
                    &mut stats,
                )?;
            }
            sent = socket.send(&send_buffer) => {
                let sent = sent.context("send timed UDP datagram")?;
                ensure!(sent == send_buffer.len(), "short timed UDP send");
                stats.sent = stats.sent.checked_add(1).context("UDP sent counter overflow")?;
                send_buffer[5..13].copy_from_slice(&stats.sent.to_be_bytes());
            }
        }
    }

    let drain_deadline = tokio::time::Instant::now() + UDP_DRAIN_WINDOW;
    loop {
        match timeout_at(drain_deadline, socket.recv(&mut receive_buffer)).await {
            Ok(Ok(length)) => record_udp_receive(
                &receive_buffer[..length],
                session_id,
                payload_bytes,
                stats.sent,
                &mut received_sequences,
                &mut highest_sequence,
                &mut stats,
            )?,
            Ok(Err(error)) => return Err(error).context("receive UDP datagram while draining"),
            Err(_) => break,
        }
    }
    Ok(stats)
}

fn record_udp_receive(
    datagram: &[u8],
    session_id: usize,
    expected_length: usize,
    sent: u64,
    received_sequences: &mut Vec<u64>,
    highest_sequence: &mut Option<u64>,
    stats: &mut UdpWorkerStats,
) -> Result<()> {
    let Some(sequence) = validate_udp_payload(datagram, session_id, expected_length) else {
        stats.invalid = stats
            .invalid
            .checked_add(1)
            .context("UDP invalid counter overflow")?;
        return Ok(());
    };
    if sequence >= sent {
        stats.invalid = stats
            .invalid
            .checked_add(1)
            .context("UDP invalid counter overflow")?;
        return Ok(());
    }
    if mark_sequence(received_sequences, sequence)? {
        stats.duplicates = stats
            .duplicates
            .checked_add(1)
            .context("UDP duplicate counter overflow")?;
        return Ok(());
    }
    if highest_sequence.is_some_and(|highest| sequence < highest) {
        stats.reordered = stats
            .reordered
            .checked_add(1)
            .context("UDP reorder counter overflow")?;
    }
    *highest_sequence = Some(highest_sequence.map_or(sequence, |highest| highest.max(sequence)));
    stats.unique_received = stats
        .unique_received
        .checked_add(1)
        .context("UDP receive counter overflow")?;
    Ok(())
}

fn mark_sequence(words: &mut Vec<u64>, sequence: u64) -> Result<bool> {
    let word_index = usize::try_from(sequence / 64).context("UDP sequence index fits usize")?;
    if word_index >= words.len() {
        words.resize(word_index + 1, 0);
    }
    let bit_index = u32::try_from(sequence % 64).expect("bit index fits u32");
    let mask = 1_u64 << bit_index;
    let duplicate = words[word_index] & mask != 0;
    words[word_index] |= mask;
    Ok(duplicate)
}

fn udp_payload(length: usize, session_id: usize, sequence: u64) -> Result<Vec<u8>> {
    let session_u32 = u32::try_from(session_id).context("UDP session ID fits u32")?;
    let mut payload = vec![0_u8; length];
    payload[0] = 0x40;
    payload[1..5].copy_from_slice(&session_u32.to_be_bytes());
    payload[5..13].copy_from_slice(&sequence.to_be_bytes());
    payload[13..17].copy_from_slice(&UDP_MAGIC);
    for (index, byte) in payload[17..].iter_mut().enumerate() {
        *byte = udp_pattern_byte(index, session_id);
    }
    Ok(payload)
}

fn validate_udp_payload(payload: &[u8], session_id: usize, expected_length: usize) -> Option<u64> {
    if payload.len() != expected_length || payload[0] != 0x40 || payload[13..17] != UDP_MAGIC {
        return None;
    }
    let encoded_session = u32::from_be_bytes(payload.get(1..5)?.try_into().ok()?);
    if usize::try_from(encoded_session).ok()? != session_id {
        return None;
    }
    for (index, byte) in payload[17..].iter().enumerate() {
        if *byte != udp_pattern_byte(index, session_id) {
            return None;
        }
    }
    Some(u64::from_be_bytes(payload.get(5..13)?.try_into().ok()?))
}

fn udp_pattern_byte(index: usize, session_id: usize) -> u8 {
    u8::try_from((index + session_id) % 251).expect("modulo 251 fits u8")
}

fn percentile(sorted: &[u64], percentile: usize) -> u64 {
    let rank = sorted
        .len()
        .checked_mul(percentile)
        .expect("percentile rank fits usize")
        .div_ceil(100);
    sorted[rank.saturating_sub(1)]
}

fn elapsed_ns(duration: Duration) -> Result<u64> {
    u64::try_from(duration.as_nanos()).context("duration nanoseconds fit u64")
}

fn rate_per_second(count: u64, elapsed_ns: u64) -> Result<u64> {
    ensure!(elapsed_ns > 0, "rate interval must be positive");
    let rate = u128::from(count)
        .checked_mul(1_000_000_000)
        .context("rate numerator overflow")?
        / u128::from(elapsed_ns);
    u64::try_from(rate).context("rate fits u64")
}

fn ratio_parts_per_million(numerator: u64, denominator: u64) -> Result<u64> {
    if denominator == 0 {
        return Ok(0);
    }
    let ratio = u128::from(numerator)
        .checked_mul(1_000_000)
        .context("ratio numerator overflow")?
        / u128::from(denominator);
    u64::try_from(ratio).context("ratio fits u64")
}

fn checked_add(left: u64, right: u64, label: &str) -> Result<u64> {
    left.checked_add(right)
        .with_context(|| format!("{label} overflow"))
}

fn tcp_client_hello(hostname: &str) -> Vec<u8> {
    let handshake = quic_client_hello(hostname);
    let mut record = Vec::with_capacity(5 + handshake.len());
    record.extend_from_slice(&[22, 3, 1]);
    push_u16(&mut record, handshake.len());
    record.extend_from_slice(&handshake);
    record
}

fn quic_client_hello(hostname: &str) -> Vec<u8> {
    let mut server_name = Vec::new();
    push_u16(&mut server_name, 3 + hostname.len());
    server_name.push(0);
    push_u16(&mut server_name, hostname.len());
    server_name.extend_from_slice(hostname.as_bytes());

    let mut extensions = Vec::new();
    push_u16(&mut extensions, 0);
    push_u16(&mut extensions, server_name.len());
    extensions.extend_from_slice(&server_name);

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
        .expect("ClientHello length fits u32")
        .to_be_bytes();
    handshake.extend_from_slice(&encoded_len[1..]);
    handshake.extend_from_slice(&body);
    handshake
}

fn push_u16(target: &mut Vec<u8>, value: usize) {
    target.extend_from_slice(
        &u16::try_from(value)
            .expect("benchmark vector field fits u16")
            .to_be_bytes(),
    );
}

fn encrypted_initial(
    version: QuicVersion,
    dcid: &[u8],
    packet_number: u64,
    frames: &[u8],
) -> Vec<u8> {
    const PACKET_NUMBER_LEN: usize = 2;
    const MIN_INITIAL_BYTES: usize = 1_200;
    let mut plaintext = frames.to_vec();
    let (mut header, packet_number_offset) = loop {
        let candidate = initial_header(version, dcid, PACKET_NUMBER_LEN, plaintext.len());
        let total = candidate.0.len() + PACKET_NUMBER_LEN + plaintext.len() + 16;
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
            .expect("benchmark packet number fits u16")
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
        .expect("benchmark Initial encryption");
    let mut protected = header;
    protected.extend_from_slice(&payload);
    protected.extend_from_slice(tag.as_ref());
    let sample_start = packet_number_offset + 4;
    let sample = protected[sample_start..sample_start + keys.header.sample_len()].to_vec();
    let mut first = protected[0];
    let mut protected_packet_number =
        protected[packet_number_offset..packet_number_offset + PACKET_NUMBER_LEN].to_vec();
    keys.header
        .encrypt_in_place(&sample, &mut first, &mut protected_packet_number)
        .expect("benchmark Initial header protection");
    protected[0] = first;
    protected[packet_number_offset..packet_number_offset + PACKET_NUMBER_LEN]
        .copy_from_slice(&protected_packet_number);
    assert_eq!(protected.len(), MIN_INITIAL_BYTES);
    protected
}

fn initial_header(
    version: QuicVersion,
    dcid: &[u8],
    packet_number_len: usize,
    plaintext_len: usize,
) -> (Vec<u8>, usize) {
    let type_bits = match version {
        QuicVersion::V1 => 0,
        QuicVersion::V2 => 1,
    };
    let mut header = vec![
        0xc0 | (type_bits << 4)
            | u8::try_from(packet_number_len - 1).expect("packet number length fits u8"),
    ];
    header.extend_from_slice(&version.wire().to_be_bytes());
    header.push(u8::try_from(dcid.len()).expect("DCID length fits u8"));
    header.extend_from_slice(dcid);
    header.push(0);
    header.push(0);
    encode_varint(
        u64::try_from(packet_number_len + plaintext_len + 16).expect("packet length fits u64"),
        &mut header,
    );
    let packet_number_offset = header.len();
    (header, packet_number_offset)
}

fn crypto_frame(offset: usize, data: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x06];
    encode_varint(u64::try_from(offset).expect("offset fits u64"), &mut frame);
    encode_varint(
        u64::try_from(data.len()).expect("length fits u64"),
        &mut frame,
    );
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
        _ => panic!("benchmark varint exceeds 62 bits"),
    }
}
