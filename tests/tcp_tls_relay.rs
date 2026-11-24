#![cfg(target_os = "linux")]

use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rs_proxy::{config::Config, server::ProxyServer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::oneshot,
    task::JoinHandle,
    time::timeout,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(3);
const HOSTNAME: &str = "upstream.test";
const UPSTREAM_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_host_uses_original_port_and_relays_request_byte_exact() {
    let request =
        b"GET /health HTTP/1.1\r\nhOsT: Upstream.Test:65534\r\nConnection: close\r\n\r\n".to_vec();
    let expected_len = request.len();
    let upstream = TcpListener::bind((UPSTREAM_IP, 0))
        .await
        .expect("bind upstream on 127.0.0.2");
    let upstream_address = upstream.local_addr().expect("upstream local address");
    let marker = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".to_vec();
    let upstream_marker = marker.clone();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut received = vec![0_u8; expected_len];
        stream.read_exact(&mut received).await?;
        stream.write_all(&upstream_marker).await?;
        stream.shutdown().await?;
        Ok::<_, io::Error>(received)
    });

    let dns = FakeDns::bind(UPSTREAM_IP).await.expect("bind fake DNS");
    let proxy = RunningProxy::start(upstream_address.port(), dns.address)
        .await
        .expect("start proxy");
    let mut client = timeout(TEST_TIMEOUT, TcpStream::connect(proxy.address))
        .await
        .expect("client connect timed out")
        .expect("connect client to proxy");
    write_fragmented(&mut client, &request)
        .await
        .expect("write fragmented HTTP request");

    let mut response = vec![0_u8; marker.len()];
    timeout(TEST_TIMEOUT, client.read_exact(&mut response))
        .await
        .expect("client response timed out")
        .expect("read upstream response through proxy");
    assert_eq!(response, marker, "proxy must relay the HTTP response");
    client
        .shutdown()
        .await
        .expect("close client write half after reading the exact response");

    let received = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream task timed out")
        .expect("upstream task panicked")
        .expect("upstream socket failed");
    assert_eq!(
        received, request,
        "HTTP request bytes must not be rewritten"
    );
    assert!(
        dns.matching_queries.load(Ordering::Relaxed) > 0,
        "proxy must resolve the Host hostname through configured DNS"
    );

    proxy.stop().await;
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_sni_uses_independent_dns_and_relays_bytes_bidirectionally() {
    let client_hello = client_hello(HOSTNAME, &[]);
    let expected_len = client_hello.len();
    let upstream = TcpListener::bind((UPSTREAM_IP, 0))
        .await
        .expect("bind upstream on 127.0.0.2");
    let upstream_address = upstream.local_addr().expect("upstream local address");
    let marker = b"upstream-reply".to_vec();
    let upstream_marker = marker.clone();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut received = vec![0_u8; expected_len];
        stream.read_exact(&mut received).await?;
        stream.write_all(&upstream_marker).await?;
        stream.shutdown().await?;
        Ok::<_, io::Error>(received)
    });

    let dns = FakeDns::bind(UPSTREAM_IP).await.expect("bind fake DNS");
    let proxy = RunningProxy::start(upstream_address.port(), dns.address)
        .await
        .expect("start proxy");
    assert_eq!(
        proxy.address,
        SocketAddr::from((Ipv4Addr::LOCALHOST, upstream_address.port()))
    );

    let mut client = timeout(TEST_TIMEOUT, TcpStream::connect(proxy.address))
        .await
        .expect("client connect timed out")
        .expect("connect client to proxy");
    write_fragmented(&mut client, &client_hello)
        .await
        .expect("write fragmented ClientHello");

    let mut response = Vec::new();
    timeout(TEST_TIMEOUT, client.read_to_end(&mut response))
        .await
        .expect("client response timed out")
        .expect("read upstream response through proxy");
    assert_eq!(response, marker, "proxy must relay upstream-to-client data");

    let received = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream task timed out")
        .expect("upstream task panicked")
        .expect("upstream socket failed");
    assert_eq!(
        received, client_hello,
        "upstream must receive the original ClientHello byte-for-byte before EOF"
    );
    assert!(
        dns.matching_queries.load(Ordering::Relaxed) > 0,
        "proxy must resolve upstream.test through the configured fake DNS server"
    );

    proxy.stop().await;
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn active_relay_propagates_client_half_close_before_upstream_reply() {
    let client_hello = client_hello(HOSTNAME, &[]);
    let expected_len = client_hello.len();
    let upstream = TcpListener::bind((UPSTREAM_IP, 0))
        .await
        .expect("bind upstream on 127.0.0.2");
    let upstream_address = upstream.local_addr().expect("upstream local address");
    let marker = b"reply-after-upstream-observed-eof".to_vec();
    let upstream_marker = marker.clone();
    let upstream_stage = Arc::new(AtomicUsize::new(0));
    let task_upstream_stage = Arc::clone(&upstream_stage);
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut received = vec![0_u8; expected_len];
        stream.read_exact(&mut received).await?;
        task_upstream_stage.store(1, Ordering::Release);

        let mut unexpected = [0_u8; 1];
        if stream.read(&mut unexpected).await? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "received bytes after the complete ClientHello",
            ));
        }
        task_upstream_stage.store(2, Ordering::Release);
        stream.write_all(&upstream_marker).await?;
        stream.shutdown().await?;
        Ok::<_, io::Error>(received)
    });

    let dns = FakeDns::bind(UPSTREAM_IP).await.expect("bind fake DNS");
    let proxy = RunningProxy::start(upstream_address.port(), dns.address)
        .await
        .expect("start proxy");
    let mut client = timeout(TEST_TIMEOUT, TcpStream::connect(proxy.address))
        .await
        .expect("client connect timed out")
        .expect("connect client to proxy");
    write_fragmented(&mut client, &client_hello)
        .await
        .expect("write fragmented ClientHello");

    timeout(TEST_TIMEOUT, async {
        while upstream_stage.load(Ordering::Acquire) < 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("upstream did not receive ClientHello");
    // Give the relay a scheduling turn to register read interest before FIN.
    tokio::time::sleep(Duration::from_millis(25)).await;
    client
        .shutdown()
        .await
        .expect("half-close client write side");

    let mut response = Vec::new();
    timeout(TEST_TIMEOUT, client.read_to_end(&mut response))
        .await
        .expect("client response after half-close timed out")
        .expect("read upstream response through proxy");
    assert_eq!(response, marker, "proxy must keep reverse relay open");

    let received = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream task timed out")
        .expect("upstream task panicked")
        .expect("upstream socket failed");
    assert_eq!(received, client_hello);
    assert_eq!(
        upstream_stage.load(Ordering::Acquire),
        2,
        "upstream must observe EOF before sending its marker"
    );

    proxy.stop().await;
    dns.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ech_client_hello_is_not_forwarded_or_answered_with_application_data() {
    let upstream = TcpListener::bind((UPSTREAM_IP, 0))
        .await
        .expect("bind upstream on 127.0.0.2");
    let upstream_address = upstream.local_addr().expect("upstream local address");
    let dns = FakeDns::bind(UPSTREAM_IP).await.expect("bind fake DNS");
    let proxy = RunningProxy::start(upstream_address.port(), dns.address)
        .await
        .expect("start proxy");

    let ech_client_hello = client_hello(HOSTNAME, &[(0xfe0d, &[0])]);
    let mut client = timeout(TEST_TIMEOUT, TcpStream::connect(proxy.address))
        .await
        .expect("client connect timed out")
        .expect("connect client to proxy");
    write_fragmented(&mut client, &ech_client_hello)
        .await
        .expect("write ECH ClientHello");

    let no_upstream = timeout(Duration::from_millis(500), upstream.accept());
    let no_application_data = async {
        let mut byte = [0_u8; 1];
        match timeout(Duration::from_millis(500), client.read(&mut byte)).await {
            Err(_elapsed) => {}
            Ok(Ok(0)) => {}
            Ok(Ok(count)) => {
                panic!("proxy returned {count} byte(s) of application data for an ECH ClientHello")
            }
            Ok(Err(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::BrokenPipe
                ) => {}
            Ok(Err(error)) => panic!("unexpected client read error: {error}"),
        }
    };
    let (upstream_result, ()) = tokio::join!(no_upstream, no_application_data);
    assert!(
        upstream_result.is_err(),
        "ECH ClientHello must not cause an upstream TCP connection"
    );
    assert_eq!(
        dns.matching_queries.load(Ordering::Relaxed),
        0,
        "ECH must be rejected before DNS routing"
    );

    proxy.stop().await;
    dns.stop();
}

struct RunningProxy {
    address: SocketAddr,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<Result<(), rs_proxy::server::ServerError>>,
}

impl RunningProxy {
    async fn start(port: u16, dns_server: SocketAddr) -> Result<Self, Box<dyn std::error::Error>> {
        let config = Config::from_toml(&format!(
            r#"
[server]
max_connections = 16
inspect_max_bytes = 4096
inspect_timeout_ms = 500
connect_timeout_ms = 500
initial_write_timeout_ms = 500
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
protocol = "tcp"
listen = "127.0.0.1:{port}"
"#
        ))?;
        let server = ProxyServer::bind(&config).await?;
        let addresses = server.local_addresses();
        assert_eq!(addresses.len(), 1, "test config has one listener");
        let address = addresses[0];
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(server.serve_until(async move {
            let _ = shutdown_rx.await;
        }));
        Ok(Self {
            address,
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
}

struct FakeDns {
    address: SocketAddr,
    matching_queries: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl FakeDns {
    async fn bind(answer: Ipv4Addr) -> io::Result<Self> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = socket.local_addr()?;
        let matching_queries = Arc::new(AtomicUsize::new(0));
        let task_queries = Arc::clone(&matching_queries);
        let task = tokio::spawn(async move {
            let mut buffer = [0_u8; 2048];
            while let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
                let Some((response, matched)) = dns_response(&buffer[..length], answer) else {
                    continue;
                };
                if matched {
                    task_queries.fetch_add(1, Ordering::Relaxed);
                }
                let _ = socket.send_to(&response, peer).await;
            }
        });
        Ok(Self {
            address,
            matching_queries,
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
    response.extend_from_slice(&[0x81, 0x80]);
    response.extend_from_slice(&[0, 1]);
    response.extend_from_slice(if has_answer { &[0, 1] } else { &[0, 0] });
    response.extend_from_slice(&[0, 0, 0, 0]);
    response.extend_from_slice(&query[12..question_end]);

    if has_answer {
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&[0, 1, 0, 1]);
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

async fn write_fragmented(stream: &mut TcpStream, bytes: &[u8]) -> io::Result<()> {
    let fragment_lengths = [1_usize, 2, 3, 5, 8, 13];
    let mut offset = 0_usize;
    let mut fragment = 0_usize;
    while offset < bytes.len() {
        let end = (offset + fragment_lengths[fragment % fragment_lengths.len()]).min(bytes.len());
        stream.write_all(&bytes[offset..end]).await?;
        tokio::task::yield_now().await;
        offset = end;
        fragment += 1;
    }
    Ok(())
}

fn client_hello(hostname: &str, extra_extensions: &[(u16, &[u8])]) -> Vec<u8> {
    let mut extensions = Vec::new();
    let mut server_name = Vec::new();
    push_u16(&mut server_name, 1 + 2 + hostname.len());
    server_name.push(0);
    push_u16(&mut server_name, hostname.len());
    server_name.extend_from_slice(hostname.as_bytes());
    push_u16(&mut extensions, 0);
    push_u16(&mut extensions, server_name.len());
    extensions.extend_from_slice(&server_name);
    for (extension_type, payload) in extra_extensions {
        push_u16(&mut extensions, *extension_type);
        push_u16(&mut extensions, payload.len());
        extensions.extend_from_slice(payload);
    }

    let mut body = Vec::new();
    body.extend_from_slice(&[3, 3]);
    body.extend_from_slice(&[0x42; 32]);
    body.push(0);
    body.extend_from_slice(&[0, 2, 0, 0x2f]);
    body.extend_from_slice(&[1, 0]);
    push_u16(&mut body, extensions.len());
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(1);
    push_u24(&mut handshake, body.len());
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.extend_from_slice(&[22, 3, 1]);
    push_u16(&mut record, handshake.len());
    record.extend_from_slice(&handshake);
    record
}

fn push_u16(target: &mut Vec<u8>, value: impl TryInto<u16>) {
    let value = value.try_into().ok().expect("test vector fits u16");
    target.extend_from_slice(&value.to_be_bytes());
}

fn push_u24(target: &mut Vec<u8>, value: usize) {
    assert!(value <= 0x00ff_ffff);
    let value = u32::try_from(value)
        .expect("test vector fits u32")
        .to_be_bytes();
    target.extend_from_slice(&value[1..]);
}
