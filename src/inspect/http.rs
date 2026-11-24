//! Bounded HTTP/1 request-header inspection.
//!
//! The inspector reads only through a complete header section. Every byte
//! removed from the client stream, including bytes following the header that
//! arrived in the final read, is returned unchanged for the upstream relay.

use std::{io, net::IpAddr, time::Duration};

use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    time::timeout,
};

const HEADER_TERMINATOR: &[u8; 4] = b"\r\n\r\n";
const READ_CHUNK_LEN: usize = 4096;

/// Resource bounds applied while reading an initial HTTP/1 request header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpInspectConfig {
    /// Maximum number of original TCP bytes buffered before routing.
    pub max_buffered_bytes: usize,
    /// Deadline for the complete inspection, not an idle-read timeout.
    pub timeout: Duration,
}

impl Default for HttpInspectConfig {
    fn default() -> Self {
        Self {
            max_buffered_bytes: 64 * 1024,
            timeout: Duration::from_secs(5),
        }
    }
}

/// A routable HTTP/1 request and the exact bytes already removed from TCP.
#[derive(Debug, Eq, PartialEq)]
pub struct HttpInspection {
    /// Validated, lower-case ASCII DNS hostname from the sole `Host` field.
    pub server_name: String,
    /// All bytes read from the client, including bytes following the header
    /// section that happened to arrive in the final read.
    pub buffered: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum HttpInspectError {
    #[error("HTTP/1 request inspection timed out")]
    Timeout,
    #[error("HTTP/1 request header exceeded the configured {limit}-byte buffer limit")]
    Oversized { limit: usize },
    #[error("malformed HTTP/1 request: {reason}")]
    Malformed { reason: &'static str },
    #[error("client closed before a complete HTTP/1 request header was received")]
    UnexpectedEof,
    #[error("HTTP/1 request has no Host field")]
    MissingHost,
    #[error("HTTP/1 request has multiple Host fields")]
    DuplicateHost,
    #[error("HTTP/1 Host is an IP literal, not a DNS hostname")]
    HostIsIpLiteral,
    #[error("failed to read HTTP/1 request header: {0}")]
    Io(#[from] io::Error),
}

/// Read and inspect one HTTP/1 request header section from an async stream.
///
/// The request may be fragmented across arbitrary reads. On success,
/// `HttpInspection::buffered` must be sent upstream before the normal
/// bidirectional relay starts. An optional port in `Host` is validated but is
/// not returned: routing must preserve the accepted listener's destination
/// port.
///
/// # Errors
///
/// Returns a typed error for timeout, I/O failure, EOF, resource-limit
/// exhaustion, malformed syntax, a missing or duplicate `Host`, or an IP
/// literal instead of a DNS hostname.
pub async fn inspect_request<R>(
    reader: &mut R,
    config: HttpInspectConfig,
) -> Result<HttpInspection, HttpInspectError>
where
    R: AsyncRead + Unpin,
{
    match timeout(
        config.timeout,
        inspect_with_limit(reader, config.max_buffered_bytes),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HttpInspectError::Timeout),
    }
}

async fn inspect_with_limit<R>(
    reader: &mut R,
    limit: usize,
) -> Result<HttpInspection, HttpInspectError>
where
    R: AsyncRead + Unpin,
{
    let mut buffered = Vec::with_capacity(limit.min(READ_CHUNK_LEN));
    let mut read_buffer = [0u8; READ_CHUNK_LEN];
    let mut search_from = 0usize;

    loop {
        if let Some(header_end) = find_header_end(&buffered, search_from) {
            let server_name = parse_header_block(&buffered[..header_end])?;
            return Ok(HttpInspection {
                server_name,
                buffered,
            });
        }

        let remaining = limit.saturating_sub(buffered.len());
        if remaining == 0 {
            return Err(HttpInspectError::Oversized { limit });
        }

        search_from = buffered.len().saturating_sub(HEADER_TERMINATOR.len() - 1);
        let read_len = remaining.min(read_buffer.len());
        let bytes_read = reader.read(&mut read_buffer[..read_len]).await?;
        if bytes_read == 0 {
            return Err(HttpInspectError::UnexpectedEof);
        }
        buffered.extend_from_slice(&read_buffer[..bytes_read]);
    }
}

fn find_header_end(bytes: &[u8], start: usize) -> Option<usize> {
    bytes
        .get(start..)?
        .windows(HEADER_TERMINATOR.len())
        .position(|window| window == HEADER_TERMINATOR)
        .map(|position| start + position)
}

fn parse_header_block(block: &[u8]) -> Result<String, HttpInspectError> {
    if block.is_empty() {
        return malformed("request line is empty");
    }

    let mut lines = block.split(|byte| *byte == b'\n').peekable();
    let request_line = checked_line(
        lines.next().ok_or(HttpInspectError::Malformed {
            reason: "request line is missing",
        })?,
        lines.peek().is_some(),
    )?;
    validate_request_line(request_line)?;

    let mut host = None;
    while let Some(raw_line) = lines.next() {
        let line = checked_line(raw_line, lines.peek().is_some())?;
        if line.is_empty() {
            return malformed("empty line appears inside the header section");
        }
        if matches!(line.first(), Some(b' ' | b'\t')) {
            return malformed("obsolete folded header field is not accepted");
        }

        let colon =
            line.iter()
                .position(|byte| *byte == b':')
                .ok_or(HttpInspectError::Malformed {
                    reason: "header field has no colon",
                })?;
        let name = &line[..colon];
        let value = &line[colon + 1..];
        if name.is_empty() || !name.iter().copied().all(is_tchar) {
            return malformed("header field name is not a valid token");
        }
        if !value.iter().all(|byte| is_field_value_byte(*byte)) {
            return malformed("header field value contains a forbidden control byte");
        }

        if name.eq_ignore_ascii_case(b"host") {
            if host.is_some() {
                return Err(HttpInspectError::DuplicateHost);
            }
            host = Some(parse_host(value)?);
        }
    }

    host.ok_or(HttpInspectError::MissingHost)
}

fn checked_line(line: &[u8], has_following_line: bool) -> Result<&[u8], HttpInspectError> {
    if has_following_line {
        line.strip_suffix(b"\r").ok_or(HttpInspectError::Malformed {
            reason: "request uses a bare LF line ending",
        })
    } else if line.contains(&b'\r') {
        malformed("request contains a bare CR byte")
    } else {
        Ok(line)
    }
}

fn validate_request_line(line: &[u8]) -> Result<(), HttpInspectError> {
    if line.contains(&b'\r') || line.contains(&b'\n') {
        return malformed("request line contains a bare CR or LF byte");
    }

    let mut parts = line.split(|byte| *byte == b' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if parts.next().is_some() || method.is_empty() || target.is_empty() || version.is_empty() {
        return malformed("request line must contain method, target, and version");
    }
    if !method.iter().copied().all(is_tchar) {
        return malformed("request method is not a valid token");
    }
    if !target.iter().all(|byte| (0x21..=0x7e).contains(byte)) {
        return malformed("request target contains a forbidden byte");
    }
    if method == b"CONNECT" {
        return malformed("CONNECT authority-form is not a supported routing source");
    }
    if target == b"*" {
        if method != b"OPTIONS" {
            return malformed("asterisk-form request target requires OPTIONS");
        }
    } else if !target.starts_with(b"/") {
        return malformed("only origin-form and OPTIONS asterisk-form targets are supported");
    }
    if version != b"HTTP/1.0" && version != b"HTTP/1.1" {
        return malformed("request version is not HTTP/1.0 or HTTP/1.1");
    }
    Ok(())
}

fn parse_host(raw_value: &[u8]) -> Result<String, HttpInspectError> {
    let value = trim_optional_whitespace(raw_value);
    if value.is_empty() || !value.is_ascii() {
        return malformed("Host is empty or non-ASCII");
    }

    if value[0] == b'[' {
        let close =
            value
                .iter()
                .position(|byte| *byte == b']')
                .ok_or(HttpInspectError::Malformed {
                    reason: "bracketed Host has no closing bracket",
                })?;
        let literal = &value[1..close];
        let literal_text =
            std::str::from_utf8(literal).map_err(|_| HttpInspectError::Malformed {
                reason: "bracketed Host is not ASCII",
            })?;
        if literal_text.parse::<std::net::Ipv6Addr>().is_err() {
            return malformed("bracketed Host is not a valid IPv6 literal");
        }
        validate_authority_suffix(&value[close + 1..])?;
        return Err(HttpInspectError::HostIsIpLiteral);
    }
    if value.contains(&b'[') || value.contains(&b']') {
        return malformed("Host contains a misplaced bracket");
    }

    let hostname = match value.iter().position(|byte| *byte == b':') {
        None => value,
        Some(colon) => {
            if value[colon + 1..].contains(&b':') {
                return malformed("IPv6 Host literals must use brackets");
            }
            validate_port(&value[colon + 1..])?;
            &value[..colon]
        }
    };

    validate_dns_name(hostname)
}

fn validate_authority_suffix(suffix: &[u8]) -> Result<(), HttpInspectError> {
    if suffix.is_empty() {
        return Ok(());
    }
    if suffix[0] != b':' {
        return malformed("unexpected bytes follow the bracketed Host");
    }
    validate_port(&suffix[1..])
}

fn validate_port(port: &[u8]) -> Result<(), HttpInspectError> {
    if port.is_empty() || !port.iter().all(u8::is_ascii_digit) {
        return malformed("Host port is empty or non-numeric");
    }

    let mut value = 0u32;
    for digit in port {
        value = value
            .checked_mul(10)
            .and_then(|current| current.checked_add(u32::from(*digit - b'0')))
            .ok_or(HttpInspectError::Malformed {
                reason: "Host port is outside 1..=65535",
            })?;
        if value > u32::from(u16::MAX) {
            return malformed("Host port is outside 1..=65535");
        }
    }
    if value == 0 {
        return malformed("Host port is outside 1..=65535");
    }
    Ok(())
}

fn validate_dns_name(name: &[u8]) -> Result<String, HttpInspectError> {
    if name.is_empty() || name.len() > 253 || !name.is_ascii() {
        return malformed("Host is not a valid ASCII DNS hostname");
    }

    for label in name.split(|byte| *byte == b'.') {
        if label.is_empty() || label.len() > 63 {
            return malformed("Host has an invalid DNS label length");
        }
        if !label[0].is_ascii_alphanumeric()
            || !label[label.len() - 1].is_ascii_alphanumeric()
            || !label
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            return malformed("Host contains an invalid DNS label");
        }
    }

    let name = std::str::from_utf8(name)
        .map_err(|_| HttpInspectError::Malformed {
            reason: "Host is not valid ASCII",
        })?
        .to_ascii_lowercase();
    if name.parse::<IpAddr>().is_ok() {
        return Err(HttpInspectError::HostIsIpLiteral);
    }
    Ok(name)
}

fn trim_optional_whitespace(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_field_value_byte(byte: u8) -> bool {
    byte == b'\t' || (byte >= b' ' && byte != 0x7f)
}

fn malformed<T>(reason: &'static str) -> Result<T, HttpInspectError> {
    Err(HttpInspectError::Malformed { reason })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio::io::{AsyncRead, ReadBuf};

    use super::*;

    struct FragmentedReader {
        chunks: VecDeque<Vec<u8>>,
    }

    impl FragmentedReader {
        fn new(chunks: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                chunks: chunks.into_iter().collect(),
            }
        }
    }

    impl AsyncRead for FragmentedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let Some(mut chunk) = self.chunks.pop_front() else {
                return Poll::Ready(Ok(()));
            };
            let take = chunk.len().min(buffer.remaining());
            buffer.put_slice(&chunk[..take]);
            if take < chunk.len() {
                chunk.drain(..take);
                self.chunks.push_front(chunk);
            }
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn extracts_host_and_preserves_all_read_bytes() {
        let wire =
            b"POST /submit HTTP/1.1\r\nHost: WWW.Example.COM:8443\r\nContent-Length: 4\r\n\r\nbody"
                .to_vec();
        let mut reader = FragmentedReader::new([wire.clone()]);

        let inspected = inspect_request(&mut reader, test_config(4096))
            .await
            .expect("valid HTTP/1 request");

        assert_eq!(inspected.server_name, "www.example.com");
        assert_eq!(inspected.buffered, wire);
    }

    #[tokio::test]
    async fn accepts_single_byte_fragmentation_and_case_insensitive_field_name() {
        let wire = b"GET / HTTP/1.0\r\nhOsT:\tfragmented.example \t\r\nX-Test: yes\r\n\r\n";
        let chunks = wire.iter().copied().map(|byte| vec![byte]);
        let mut reader = FragmentedReader::new(chunks);

        let inspected = inspect_request(&mut reader, test_config(4096))
            .await
            .expect("fragmented HTTP/1 request");

        assert_eq!(inspected.server_name, "fragmented.example");
        assert_eq!(inspected.buffered, wire);
    }

    #[tokio::test]
    async fn accepts_options_asterisk_form_with_host() {
        let wire = b"OPTIONS * HTTP/1.1\r\nHost: options.example\r\n\r\n";
        let mut reader = FragmentedReader::new([wire.to_vec()]);

        let inspected = inspect_request(&mut reader, test_config(4096))
            .await
            .expect("OPTIONS asterisk-form is unambiguous with Host");

        assert_eq!(inspected.server_name, "options.example");
        assert_eq!(inspected.buffered, wire);
    }

    #[tokio::test]
    async fn rejects_missing_and_duplicate_host_fields() {
        let mut missing =
            FragmentedReader::new([b"GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n".to_vec()]);
        let error = inspect_request(&mut missing, test_config(4096))
            .await
            .expect_err("missing Host must fail");
        assert!(matches!(error, HttpInspectError::MissingHost));

        for wire in [
            b"GET / HTTP/1.1\r\nHost: same.example\r\nHOST: same.example\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: one.example\r\nHost: two.example\r\n\r\n".as_slice(),
        ] {
            let mut reader = FragmentedReader::new([wire.to_vec()]);
            let error = inspect_request(&mut reader, test_config(4096))
                .await
                .expect_err("duplicate Host must fail");
            assert!(matches!(error, HttpInspectError::DuplicateHost));
        }
    }

    #[tokio::test]
    async fn rejects_ip_literals_in_both_authority_forms() {
        for authority in ["127.0.0.1:443", "[2001:db8::1]:443"] {
            let wire = format!("GET / HTTP/1.1\r\nHost: {authority}\r\n\r\n");
            let mut reader = FragmentedReader::new([wire.into_bytes()]);

            let error = inspect_request(&mut reader, test_config(4096))
                .await
                .expect_err("IP literal must not be used as a DNS destination");

            assert!(matches!(error, HttpInspectError::HostIsIpLiteral));
        }
    }

    #[tokio::test]
    async fn rejects_malformed_host_and_port_syntax() {
        for authority in [
            "bad_name.example",
            "bad..example",
            "-bad.example",
            "example.com:",
            "example.com:0",
            "example.com:65536",
            "example.com:https",
            "[example.com]:443",
            "[2001:db8::1]extra",
            "2001:db8::1",
        ] {
            let wire = format!("GET / HTTP/1.1\r\nHost: {authority}\r\n\r\n");
            let mut reader = FragmentedReader::new([wire.into_bytes()]);

            let error = inspect_request(&mut reader, test_config(4096))
                .await
                .expect_err("malformed Host must fail");

            assert!(
                matches!(error, HttpInspectError::Malformed { .. }),
                "authority {authority:?} returned {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn rejects_invalid_request_lines() {
        for request_line in [
            "GET  / HTTP/1.1",
            "GET / HTTP/2.0",
            "GET / HTTP/1.1 extra",
            "G(ET / HTTP/1.1",
            "GET /bad\tpath HTTP/1.1",
            "GET http://other.example/ HTTP/1.1",
            "CONNECT example.com:443 HTTP/1.1",
            "GET * HTTP/1.1",
        ] {
            let wire = format!("{request_line}\r\nHost: example.com\r\n\r\n");
            let mut reader = FragmentedReader::new([wire.into_bytes()]);

            let error = inspect_request(&mut reader, test_config(4096))
                .await
                .expect_err("invalid request line must fail");

            assert!(matches!(error, HttpInspectError::Malformed { .. }));
        }
    }

    #[tokio::test]
    async fn rejects_malformed_headers_and_obsolete_folding() {
        let requests = [
            b"GET / HTTP/1.1\r\nHost example.com\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nBad Name: value\r\nHost: example.com\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: example.com\r\n folded\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\nHost: example.com\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nX-Bad: a\0b\r\nHost: example.com\r\n\r\n".as_slice(),
        ];

        for wire in requests {
            let mut reader = FragmentedReader::new([wire.to_vec()]);
            let error = inspect_request(&mut reader, test_config(4096))
                .await
                .expect_err("malformed header must fail");
            assert!(matches!(error, HttpInspectError::Malformed { .. }));
        }
    }

    #[tokio::test]
    async fn enforces_buffer_limit() {
        let wire = b"GET / HTTP/1.1\r\nHost: oversized.example\r\n\r\n";
        let limit = wire.len() - 1;
        let mut reader = FragmentedReader::new(wire.iter().copied().map(|byte| vec![byte]));

        let error = inspect_request(&mut reader, test_config(limit))
            .await
            .expect_err("header over the byte limit must fail");

        assert!(matches!(error, HttpInspectError::Oversized { limit: actual } if actual == limit));
    }

    #[tokio::test]
    async fn reports_eof_before_complete_header() {
        let mut reader =
            FragmentedReader::new([b"GET / HTTP/1.1\r\nHost: example.com\r\n".to_vec()]);

        let error = inspect_request(&mut reader, test_config(4096))
            .await
            .expect_err("incomplete request must fail");

        assert!(matches!(error, HttpInspectError::UnexpectedEof));
    }

    #[tokio::test]
    async fn enforces_overall_timeout() {
        let (mut reader, _writer) = tokio::io::duplex(64);
        let config = HttpInspectConfig {
            max_buffered_bytes: 4096,
            timeout: Duration::from_millis(10),
        };

        let error = inspect_request(&mut reader, config)
            .await
            .expect_err("silent peer must time out");

        assert!(matches!(error, HttpInspectError::Timeout));
    }

    fn test_config(limit: usize) -> HttpInspectConfig {
        HttpInspectConfig {
            max_buffered_bytes: limit,
            timeout: Duration::from_secs(1),
        }
    }
}
