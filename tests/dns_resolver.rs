#![cfg(target_os = "linux")]

use std::{
    collections::HashSet,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rs_proxy::{
    config::DnsConfig,
    dns::{DnsError, IndependentResolver},
    policy::AddressPolicy,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::{JoinHandle, JoinSet},
    time::{sleep, timeout},
};

const TEST_TIMEOUT: Duration = Duration::from_secs(3);
const ALIAS: &str = "alias.test";
const TARGET: &str = "target.test";
const IPV4_ANSWER: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const IPV6_ANSWER: Ipv6Addr = Ipv6Addr::LOCALHOST;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cname_chain_returns_ipv4_and_ipv6_from_explicit_server() {
    let dns = FakeDns::bind(ResponseMode::Cname {
        alias: ALIAS,
        target: TARGET,
    })
    .await
    .expect("bind fake DNS");
    let resolver = resolver(dns.address);

    let addresses = resolve(&resolver, ALIAS, 8443)
        .await
        .expect("resolve CNAME chain");

    assert_eq!(address_set(&addresses), expected_addresses(8443));
    assert!(
        dns.total_queries() >= 2,
        "dual-stack lookup must query the explicit fake DNS server"
    );
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn positive_ttl_cache_avoids_a_second_dns_query() {
    let dns = FakeDns::bind(ResponseMode::Direct {
        name: TARGET,
        ttl: 60,
    })
    .await
    .expect("bind fake DNS");
    let resolver = resolver(dns.address);

    let first = resolve(&resolver, TARGET, 443)
        .await
        .expect("first positive lookup");
    let queries_after_first = dns.total_queries();
    assert!(queries_after_first > 0, "first lookup must reach fake DNS");

    let second = resolve(&resolver, TARGET, 443)
        .await
        .expect("cached positive lookup");

    assert_eq!(address_set(&first), expected_addresses(443));
    assert_eq!(address_set(&second), expected_addresses(443));
    assert_eq!(
        dns.total_queries(),
        queries_after_first,
        "positive answer must remain in Hickory's TTL cache"
    );
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn positive_cache_entry_expires_at_configured_ttl_cap() {
    let dns = FakeDns::bind(ResponseMode::Direct {
        name: TARGET,
        ttl: 60,
    })
    .await
    .expect("bind fake DNS");
    let resolver = resolver_with_ttl_caps(dns.address, 1, 60);

    resolve(&resolver, TARGET, 443)
        .await
        .expect("first positive lookup");
    let queries_after_first = dns.total_queries();
    sleep(Duration::from_millis(1_150)).await;
    resolve(&resolver, TARGET, 443)
        .await
        .expect("lookup after positive TTL cap");

    assert!(
        dns.total_queries() > queries_after_first,
        "expired positive answer must be queried again"
    );
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn negative_ttl_cache_avoids_a_second_nxdomain_query() {
    let dns = FakeDns::bind(ResponseMode::NxDomain)
        .await
        .expect("bind fake DNS");
    let resolver = resolver(dns.address);

    assert!(
        resolve(&resolver, "missing.test", 443).await.is_err(),
        "NXDOMAIN must not produce an address"
    );
    let queries_after_first = dns.total_queries();
    assert!(queries_after_first > 0, "first lookup must reach fake DNS");

    assert!(
        resolve(&resolver, "missing.test", 443).await.is_err(),
        "cached NXDOMAIN must remain a resolver error"
    );
    assert_eq!(
        dns.total_queries(),
        queries_after_first,
        "SOA-backed NXDOMAIN must remain in Hickory's negative cache"
    );
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn negative_cache_entry_expires_at_configured_ttl_cap() {
    let dns = FakeDns::bind(ResponseMode::NxDomain)
        .await
        .expect("bind fake DNS");
    let resolver = resolver_with_ttl_caps(dns.address, 60, 1);

    assert!(
        resolve(&resolver, "missing-expiry.test", 443)
            .await
            .is_err(),
        "first NXDOMAIN must fail"
    );
    let queries_after_first = dns.total_queries();
    sleep(Duration::from_millis(1_150)).await;
    assert!(
        resolve(&resolver, "missing-expiry.test", 443)
            .await
            .is_err(),
        "NXDOMAIN after the negative TTL cap must still fail"
    );

    assert!(
        dns.total_queries() > queries_after_first,
        "expired negative answer must be queried again"
    );
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn truncated_udp_response_falls_back_to_tcp() {
    let dns = FakeDns::bind(ResponseMode::TruncateUdp { name: TARGET })
        .await
        .expect("bind fake DNS");
    let resolver = resolver(dns.address);

    let addresses = resolve(&resolver, TARGET, 9443)
        .await
        .expect("resolve after DNS TCP fallback");

    assert_eq!(address_set(&addresses), expected_addresses(9443));
    assert!(dns.udp_queries() > 0, "lookup must start over UDP");
    assert!(
        dns.tcp_queries() > 0,
        "truncated UDP response must be retried over TCP"
    );
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_noerror_answer_is_not_accepted_as_a_route() {
    let dns = FakeDns::bind(ResponseMode::Empty)
        .await
        .expect("bind fake DNS");
    let resolver = resolver(dns.address);

    let result = resolve(&resolver, "empty.test", 443).await;

    assert!(result.is_err(), "NODATA must not produce an empty route");
    assert!(dns.total_queries() > 0, "lookup must reach fake DNS");
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unavailable_explicit_server_fails_without_an_external_fallback() {
    let dns = FakeDns::bind(ResponseMode::Drop)
        .await
        .expect("bind fake DNS");
    let resolver = resolver(dns.address);

    let error = resolve(&resolver, "unavailable.test", 443)
        .await
        .expect_err("non-responsive explicit DNS must fail");

    assert!(
        matches!(error, DnsError::Network(_) | DnsError::LookupTimeout),
        "unexpected resolver failure: {error}"
    );
    assert!(
        dns.total_queries() > 0,
        "resolver must attempt only the configured fake DNS server"
    );
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_explicit_server_answers_when_first_server_drops_queries() {
    let unavailable = FakeDns::bind(ResponseMode::Drop)
        .await
        .expect("bind unavailable fake DNS");
    let healthy = FakeDns::bind(ResponseMode::Direct {
        name: TARGET,
        ttl: 60,
    })
    .await
    .expect("bind healthy fake DNS");
    let resolver = resolver_for_servers(vec![unavailable.address, healthy.address], 60, 60);

    let addresses = resolve(&resolver, TARGET, 7443)
        .await
        .expect("resolve through the remaining explicit server");

    assert_eq!(address_set(&addresses), expected_addresses(7443));
    assert!(
        unavailable.total_queries() > 0,
        "the unavailable configured server must be exercised"
    );
    assert!(
        healthy.total_queries() > 0,
        "the healthy configured server must supply the answer"
    );
    unavailable.stop();
    healthy.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn concurrent_lookup_queue_fails_bounded_when_its_single_slot_stays_full() {
    let dns = FakeDns::bind(ResponseMode::DelayedAddresses {
        delay: Duration::from_millis(300),
    })
    .await
    .expect("bind delayed fake DNS");
    let resolver = resolver_with_limits(dns.address, 800, 800, 1);

    let first_resolver = resolver.clone();
    let first =
        tokio::spawn(async move { resolve(&first_resolver, "first-concurrency.test", 443).await });
    sleep(Duration::from_millis(20)).await;
    let second_resolver = resolver.clone();
    let second =
        tokio::spawn(
            async move { resolve(&second_resolver, "second-concurrency.test", 443).await },
        );
    sleep(Duration::from_millis(20)).await;
    let third = resolve(&resolver, "third-concurrency.test", 443).await;

    assert!(
        matches!(third, Err(DnsError::ConcurrencyTimeout)),
        "third lookup must time out in the bounded semaphore queue, got {third:?}"
    );
    assert!(
        first.await.expect("first lookup task").is_ok(),
        "first lookup must complete and release the only slot"
    );
    let _ = second.await.expect("second lookup task");
    dns.stop();
}

fn resolver(server: SocketAddr) -> IndependentResolver {
    resolver_with_ttl_caps(server, 60, 60)
}

fn resolver_with_ttl_caps(
    server: SocketAddr,
    positive_max_ttl_secs: u64,
    negative_max_ttl_secs: u64,
) -> IndependentResolver {
    resolver_for_servers(vec![server], positive_max_ttl_secs, negative_max_ttl_secs)
}

fn resolver_for_servers(
    servers: Vec<SocketAddr>,
    positive_max_ttl_secs: u64,
    negative_max_ttl_secs: u64,
) -> IndependentResolver {
    resolver_with_options(
        servers,
        100,
        600,
        8,
        positive_max_ttl_secs,
        negative_max_ttl_secs,
    )
}

fn resolver_with_limits(
    server: SocketAddr,
    request_timeout_ms: u64,
    lookup_timeout_ms: u64,
    max_concurrent_queries: usize,
) -> IndependentResolver {
    resolver_with_options(
        vec![server],
        request_timeout_ms,
        lookup_timeout_ms,
        max_concurrent_queries,
        60,
        60,
    )
}

fn resolver_with_options(
    servers: Vec<SocketAddr>,
    request_timeout_ms: u64,
    lookup_timeout_ms: u64,
    max_concurrent_queries: usize,
    positive_max_ttl_secs: u64,
    negative_max_ttl_secs: u64,
) -> IndependentResolver {
    let config = DnsConfig {
        servers,
        request_timeout_ms,
        lookup_timeout_ms,
        attempts: 1,
        cache_size: 64,
        max_concurrent_queries,
        max_active_requests: 8,
        max_addresses_per_lookup: 16,
        positive_max_ttl_secs,
        negative_max_ttl_secs,
    };
    let policy = AddressPolicy::from_parts(
        Vec::new(),
        vec![
            "127.0.0.0/8".parse().expect("valid IPv4 test CIDR"),
            "::1/128".parse().expect("valid IPv6 test CIDR"),
        ],
        HashSet::new(),
    )
    .expect("build test address policy");
    IndependentResolver::new(&config, &policy).expect("build independent resolver")
}

async fn resolve(
    resolver: &IndependentResolver,
    hostname: &str,
    port: u16,
) -> Result<Vec<SocketAddr>, DnsError> {
    timeout(TEST_TIMEOUT, resolver.resolve(hostname, port))
        .await
        .expect("resolver exceeded test timeout")
}

fn address_set(addresses: &[SocketAddr]) -> HashSet<SocketAddr> {
    addresses.iter().copied().collect()
}

fn expected_addresses(port: u16) -> HashSet<SocketAddr> {
    HashSet::from([
        SocketAddr::new(IpAddr::V4(IPV4_ANSWER), port),
        SocketAddr::new(IpAddr::V6(IPV6_ANSWER), port),
    ])
}

#[derive(Clone, Copy)]
enum ResponseMode {
    Cname {
        alias: &'static str,
        target: &'static str,
    },
    Direct {
        name: &'static str,
        ttl: u32,
    },
    NxDomain,
    TruncateUdp {
        name: &'static str,
    },
    Empty,
    Drop,
    DelayedAddresses {
        delay: Duration,
    },
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Transport {
    Udp,
    Tcp,
}

struct FakeDns {
    address: SocketAddr,
    udp_queries: Arc<AtomicUsize>,
    tcp_queries: Arc<AtomicUsize>,
    udp_task: JoinHandle<()>,
    tcp_task: JoinHandle<()>,
}

impl FakeDns {
    async fn bind(mode: ResponseMode) -> io::Result<Self> {
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = tcp.local_addr()?;
        let udp = UdpSocket::bind(address).await?;
        let udp_queries = Arc::new(AtomicUsize::new(0));
        let tcp_queries = Arc::new(AtomicUsize::new(0));

        let udp_counter = Arc::clone(&udp_queries);
        let udp_task = tokio::spawn(async move {
            let mut buffer = [0_u8; 4096];
            while let Ok((length, peer)) = udp.recv_from(&mut buffer).await {
                udp_counter.fetch_add(1, Ordering::Relaxed);
                sleep(mode.response_delay()).await;
                if let Some(response) = mode.response(&buffer[..length], Transport::Udp) {
                    let _ = udp.send_to(&response, peer).await;
                }
            }
        });

        let tcp_counter = Arc::clone(&tcp_queries);
        let tcp_task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = tcp.accept() => {
                        let Ok((stream, _peer)) = accepted else {
                            break;
                        };
                        let counter = Arc::clone(&tcp_counter);
                        connections.spawn(serve_tcp(stream, mode, counter));
                    }
                    result = connections.join_next(), if !connections.is_empty() => {
                        let _ = result;
                    }
                }
            }
        });

        Ok(Self {
            address,
            udp_queries,
            tcp_queries,
            udp_task,
            tcp_task,
        })
    }

    fn udp_queries(&self) -> usize {
        self.udp_queries.load(Ordering::Relaxed)
    }

    fn tcp_queries(&self) -> usize {
        self.tcp_queries.load(Ordering::Relaxed)
    }

    fn total_queries(&self) -> usize {
        self.udp_queries() + self.tcp_queries()
    }

    fn stop(self) {
        self.udp_task.abort();
        self.tcp_task.abort();
    }
}

async fn serve_tcp(
    mut stream: TcpStream,
    mode: ResponseMode,
    queries: Arc<AtomicUsize>,
) -> io::Result<()> {
    loop {
        let mut length = [0_u8; 2];
        match stream.read_exact(&mut length).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        }
        let mut query = vec![0_u8; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut query).await?;
        queries.fetch_add(1, Ordering::Relaxed);
        sleep(mode.response_delay()).await;
        let Some(response) = mode.response(&query, Transport::Tcp) else {
            continue;
        };
        let response_length = u16::try_from(response.len())
            .expect("test DNS response fits TCP frame")
            .to_be_bytes();
        stream.write_all(&response_length).await?;
        stream.write_all(&response).await?;
    }
}

impl ResponseMode {
    fn response(self, query: &[u8], transport: Transport) -> Option<Vec<u8>> {
        let question = parse_question(query)?;
        if question.class != 1 {
            return Some(empty_response(query, &question));
        }
        match self {
            Self::Cname { alias, target } if question.name.eq_ignore_ascii_case(alias) => {
                Some(cname_response(query, &question, target))
            }
            Self::Cname { target, .. } if question.name.eq_ignore_ascii_case(target) => {
                Some(address_response(query, &question, 60))
            }
            Self::Direct { name, ttl } if question.name.eq_ignore_ascii_case(name) => {
                Some(address_response(query, &question, ttl))
            }
            Self::TruncateUdp { .. } if transport == Transport::Udp => {
                Some(truncated_response(query, &question))
            }
            Self::TruncateUdp { name } if question.name.eq_ignore_ascii_case(name) => {
                Some(address_response(query, &question, 60))
            }
            Self::Cname { .. }
            | Self::Direct { .. }
            | Self::NxDomain
            | Self::TruncateUdp { .. } => Some(negative_response(query, &question, 3)),
            Self::Empty => Some(empty_response(query, &question)),
            Self::Drop => None,
            Self::DelayedAddresses { .. } => Some(address_response(query, &question, 60)),
        }
    }

    fn response_delay(self) -> Duration {
        match self {
            Self::DelayedAddresses { delay } => delay,
            _ => Duration::ZERO,
        }
    }
}

struct Question {
    name: String,
    record_type: u16,
    class: u16,
    end: usize,
}

fn parse_question(query: &[u8]) -> Option<Question> {
    if query.len() < 12 || u16::from_be_bytes([query[4], query[5]]) != 1 {
        return None;
    }
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
    let end = cursor.checked_add(4)?;
    let record_type = u16::from_be_bytes([*query.get(cursor)?, *query.get(cursor + 1)?]);
    let class = u16::from_be_bytes([*query.get(cursor + 2)?, *query.get(cursor + 3)?]);
    Some(Question {
        name: labels.join("."),
        record_type,
        class,
        end,
    })
}

fn address_response(query: &[u8], question: &Question, ttl: u32) -> Vec<u8> {
    let Some((record_type, rdata)) = address_rdata(question.record_type) else {
        return empty_response(query, question);
    };
    let mut response = response_prefix(query, question, 0, 1, 0);
    push_record(&mut response, &[0xc0, 0x0c], record_type, ttl, &rdata);
    response
}

fn cname_response(query: &[u8], question: &Question, target: &str) -> Vec<u8> {
    let Some((record_type, rdata)) = address_rdata(question.record_type) else {
        return empty_response(query, question);
    };
    let encoded_target = encode_name(target);
    let mut response = response_prefix(query, question, 0, 2, 0);
    push_record(&mut response, &[0xc0, 0x0c], 5, 60, &encoded_target);
    push_record(&mut response, &encoded_target, record_type, 60, &rdata);
    response
}

fn truncated_response(query: &[u8], question: &Question) -> Vec<u8> {
    response_prefix(query, question, 0x0200, 0, 0)
}

fn empty_response(query: &[u8], question: &Question) -> Vec<u8> {
    let mut response = response_prefix(query, question, 0, 0, 1);
    push_soa(&mut response);
    response
}

fn negative_response(query: &[u8], question: &Question, response_code: u16) -> Vec<u8> {
    let mut response = response_prefix(query, question, response_code, 0, 1);
    push_soa(&mut response);
    response
}

fn response_prefix(
    query: &[u8],
    question: &Question,
    extra_flags_or_response_code: u16,
    answer_count: u16,
    authority_count: u16,
) -> Vec<u8> {
    let mut response = Vec::with_capacity(256);
    response.extend_from_slice(&query[..2]);
    let recursion_desired = u16::from_be_bytes([query[2], query[3]]) & 0x0100;
    let flags = 0x8080 | recursion_desired | extra_flags_or_response_code;
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&answer_count.to_be_bytes());
    response.extend_from_slice(&authority_count.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&query[12..question.end]);
    response
}

fn address_rdata(record_type: u16) -> Option<(u16, Vec<u8>)> {
    match record_type {
        1 => Some((1, IPV4_ANSWER.octets().to_vec())),
        28 => Some((28, IPV6_ANSWER.octets().to_vec())),
        _ => None,
    }
}

fn push_soa(response: &mut Vec<u8>) {
    let mut rdata = encode_name("ns.test");
    rdata.extend_from_slice(&encode_name("hostmaster.test"));
    for value in [1_u32, 60, 60, 60, 60] {
        rdata.extend_from_slice(&value.to_be_bytes());
    }
    push_record(response, &[0xc0, 0x0c], 6, 60, &rdata);
}

fn push_record(response: &mut Vec<u8>, owner: &[u8], record_type: u16, ttl: u32, rdata: &[u8]) {
    response.extend_from_slice(owner);
    response.extend_from_slice(&record_type.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&ttl.to_be_bytes());
    let length = u16::try_from(rdata.len()).expect("test DNS RDATA fits u16");
    response.extend_from_slice(&length.to_be_bytes());
    response.extend_from_slice(rdata);
}

fn encode_name(name: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        encoded.push(u8::try_from(label.len()).expect("test DNS label fits u8"));
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0);
    encoded
}
