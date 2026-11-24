//! Bounded TLS `ClientHello` inspection.
//!
//! The inspector only consumes enough of the stream to identify a complete
//! `ClientHello`. Every byte consumed from the stream is returned to the caller
//! so it can be written to the upstream unchanged before starting the relay.

use std::{io, net::IpAddr, time::Duration};

use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    time::timeout,
};

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 22;
const CLIENT_HELLO_HANDSHAKE_TYPE: u8 = 1;
const HANDSHAKE_HEADER_LEN: usize = 4;
const MAX_TLS_PLAINTEXT_LEN: usize = 1 << 14;
const READ_CHUNK_LEN: usize = 4096;

const SERVER_NAME_EXTENSION: u16 = 0;
const HOST_NAME_TYPE: u8 = 0;

/// RFC 9849 uses 0xfe0d. The other values are exact codepoints from the
/// published ESNI predecessor and draft-ietf-tls-esni-07 through -12
/// revisions; they are not a wildcard for GREASE or unassigned extensions.
const ENCRYPTED_SERVER_NAME_DRAFT_00_TO_06: u16 = 0xffce;
const ECH_EXTENSION_DRAFT_07: u16 = 0xff02;
const ECH_EXTENSION_DRAFT_08_TO_12: std::ops::RangeInclusive<u16> = 0xfe08..=0xfe0c;
const ECH_EXTENSION_RFC_9849: u16 = 0xfe0d;

/// Resource bounds applied while reading an initial TLS `ClientHello`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsInspectConfig {
    /// Maximum number of original TCP bytes buffered before routing.
    pub max_buffered_bytes: usize,
    /// Deadline for the complete inspection, not an idle-read timeout.
    pub timeout: Duration,
}

impl Default for TlsInspectConfig {
    fn default() -> Self {
        Self {
            max_buffered_bytes: 64 * 1024,
            timeout: Duration::from_secs(5),
        }
    }
}

/// A routable TLS `ClientHello` and the exact bytes already removed from TCP.
#[derive(Debug, Eq, PartialEq)]
pub struct TlsInspection {
    /// Validated, lower-case ASCII DNS hostname from the sole SNI `host_name`.
    pub server_name: String,
    /// All bytes read from the client, including any bytes following the
    /// `ClientHello` that happened to arrive in the final read.
    pub buffered: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum TlsInspectError {
    #[error("TLS ClientHello inspection timed out")]
    Timeout,
    #[error("TLS ClientHello exceeded the configured {limit}-byte buffer limit")]
    Oversized { limit: usize },
    #[error("malformed TLS ClientHello: {reason}")]
    Malformed { reason: &'static str },
    #[error("client closed before a complete TLS ClientHello was received")]
    UnexpectedEof,
    #[error("TLS ClientHello has no unambiguous DNS SNI")]
    NoServerName,
    #[error("TLS ClientHello offers Encrypted Client Hello")]
    EncryptedClientHello,
    #[error("failed to read TLS ClientHello: {0}")]
    Io(#[from] io::Error),
}

/// Read and inspect one TLS `ClientHello` from an async byte stream.
///
/// TLS records and the handshake message may both be arbitrarily fragmented.
/// On success, `TlsInspection::buffered` must be sent upstream before the
/// normal bidirectional relay starts. ECH is rejected even when the outer
/// `ClientHello` contains a syntactically valid public SNI.
///
/// # Errors
///
/// Returns a typed error for timeout, I/O failure, EOF, resource-limit
/// exhaustion, malformed input, missing SNI, or any recognized ECH offer.
pub async fn inspect_client_hello<R>(
    reader: &mut R,
    config: TlsInspectConfig,
) -> Result<TlsInspection, TlsInspectError>
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
        Err(_) => Err(TlsInspectError::Timeout),
    }
}

async fn inspect_with_limit<R>(
    reader: &mut R,
    limit: usize,
) -> Result<TlsInspection, TlsInspectError>
where
    R: AsyncRead + Unpin,
{
    let mut buffered = Vec::with_capacity(limit.min(READ_CHUNK_LEN));
    let mut handshake = Vec::with_capacity(limit.min(READ_CHUNK_LEN));
    let mut cursor = 0usize;
    let mut record_payload_remaining = 0usize;
    let mut read_buffer = [0u8; READ_CHUNK_LEN];

    loop {
        if let Some(client_hello_len) = consume_records(
            &buffered,
            &mut cursor,
            &mut record_payload_remaining,
            &mut handshake,
            limit,
        )? {
            let server_name =
                parse_client_hello(&handshake[HANDSHAKE_HEADER_LEN..client_hello_len])?;
            return Ok(TlsInspection {
                server_name,
                buffered,
            });
        }

        let remaining = limit.saturating_sub(buffered.len());
        if remaining == 0 {
            return Err(TlsInspectError::Oversized { limit });
        }

        let read_len = remaining.min(read_buffer.len());
        let bytes_read = reader.read(&mut read_buffer[..read_len]).await?;
        if bytes_read == 0 {
            return Err(TlsInspectError::UnexpectedEof);
        }
        buffered.extend_from_slice(&read_buffer[..bytes_read]);
    }
}

fn consume_records(
    buffered: &[u8],
    cursor: &mut usize,
    record_payload_remaining: &mut usize,
    handshake: &mut Vec<u8>,
    limit: usize,
) -> Result<Option<usize>, TlsInspectError> {
    loop {
        if *record_payload_remaining == 0 {
            let available = buffered.len().saturating_sub(*cursor);
            if available < TLS_RECORD_HEADER_LEN {
                return Ok(None);
            }

            let header = &buffered[*cursor..*cursor + TLS_RECORD_HEADER_LEN];
            if header[0] != TLS_HANDSHAKE_CONTENT_TYPE {
                return malformed("record before ClientHello is not a TLS handshake record");
            }
            if header[1] != 3 || header[2] > 4 {
                return malformed("invalid TLS record legacy version");
            }

            let payload_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
            if payload_len == 0 {
                return malformed("empty TLS handshake record");
            }
            if payload_len > MAX_TLS_PLAINTEXT_LEN {
                return malformed("TLS plaintext record exceeds 2^14 bytes");
            }

            *cursor += TLS_RECORD_HEADER_LEN;
            *record_payload_remaining = payload_len;
        }

        let available = buffered.len().saturating_sub(*cursor);
        if available == 0 {
            return Ok(None);
        }

        let take = available.min(*record_payload_remaining);
        let new_handshake_len = handshake
            .len()
            .checked_add(take)
            .ok_or(TlsInspectError::Oversized { limit })?;
        if new_handshake_len > limit {
            return Err(TlsInspectError::Oversized { limit });
        }

        handshake.extend_from_slice(&buffered[*cursor..*cursor + take]);
        *cursor += take;
        *record_payload_remaining -= take;

        if handshake.len() >= HANDSHAKE_HEADER_LEN {
            if handshake[0] != CLIENT_HELLO_HANDSHAKE_TYPE {
                return malformed("first TLS handshake message is not ClientHello");
            }

            let payload_len = (usize::from(handshake[1]) << 16)
                | (usize::from(handshake[2]) << 8)
                | usize::from(handshake[3]);
            let message_len = HANDSHAKE_HEADER_LEN
                .checked_add(payload_len)
                .ok_or(TlsInspectError::Oversized { limit })?;
            if message_len > limit {
                return Err(TlsInspectError::Oversized { limit });
            }
            if handshake.len() >= message_len {
                return Ok(Some(message_len));
            }
        }
    }
}

pub(super) fn parse_client_hello(body: &[u8]) -> Result<String, TlsInspectError> {
    let mut hello = SliceCursor::new(body);

    let legacy_version = hello.u16("missing ClientHello legacy version")?;
    if legacy_version >> 8 != 3 {
        return malformed("invalid ClientHello legacy version");
    }
    hello.take(32, "truncated ClientHello random")?;

    let session_id_len = usize::from(hello.u8("missing legacy session ID length")?);
    if session_id_len > 32 {
        return malformed("legacy session ID exceeds 32 bytes");
    }
    hello.take(session_id_len, "truncated legacy session ID")?;

    let cipher_suites_len = usize::from(hello.u16("missing cipher suites length")?);
    if cipher_suites_len < 2 || cipher_suites_len % 2 != 0 {
        return malformed("cipher suites vector has an invalid length");
    }
    hello.take(cipher_suites_len, "truncated cipher suites vector")?;

    let compression_methods_len = usize::from(hello.u8("missing compression methods length")?);
    if compression_methods_len == 0 {
        return malformed("compression methods vector is empty");
    }
    hello.take(
        compression_methods_len,
        "truncated compression methods vector",
    )?;

    // The extensions vector was optional in older ClientHello formats.
    if hello.is_empty() {
        return Err(TlsInspectError::NoServerName);
    }

    let extensions_block_len = usize::from(hello.u16("truncated extensions length")?);
    if extensions_block_len != hello.remaining() {
        return malformed("extensions length does not match ClientHello length");
    }
    let mut extensions =
        SliceCursor::new(hello.take(extensions_block_len, "truncated ClientHello extensions")?);

    let mut sni_extension = None;
    let mut duplicate_sni = false;
    let mut has_ech = false;

    while !extensions.is_empty() {
        let extension_type = extensions.u16("truncated extension type")?;
        let payload_len = usize::from(extensions.u16("truncated extension length")?);
        let extension = extensions.take(payload_len, "truncated extension payload")?;

        if is_ech_extension(extension_type) {
            has_ech = true;
        }
        if extension_type == SERVER_NAME_EXTENSION && sni_extension.replace(extension).is_some() {
            duplicate_sni = true;
        }
    }

    // Outer SNI cannot identify the origin when ECH is present. Keep this
    // precedence even if the outer SNI itself is absent or ambiguous.
    if has_ech {
        return Err(TlsInspectError::EncryptedClientHello);
    }
    if duplicate_sni {
        return malformed("ClientHello contains duplicate server_name extensions");
    }

    parse_server_name(sni_extension.ok_or(TlsInspectError::NoServerName)?)
}

fn parse_server_name(extension: &[u8]) -> Result<String, TlsInspectError> {
    let mut outer = SliceCursor::new(extension);
    let list_len = usize::from(outer.u16("truncated SNI list length")?);
    if list_len == 0 || list_len != outer.remaining() {
        return malformed("SNI list length is empty or inconsistent");
    }

    let mut names = SliceCursor::new(outer.take(list_len, "truncated SNI list")?);
    let mut host_name = None;

    while !names.is_empty() {
        let name_type = names.u8("truncated SNI name type")?;
        let name_len = usize::from(names.u16("truncated SNI name length")?);
        let name = names.take(name_len, "truncated SNI name")?;

        if name_type == HOST_NAME_TYPE && host_name.replace(name).is_some() {
            return malformed("SNI list contains multiple host_name entries");
        }
    }

    validate_dns_name(host_name.ok_or(TlsInspectError::NoServerName)?)
}

fn validate_dns_name(name: &[u8]) -> Result<String, TlsInspectError> {
    if name.is_empty() || name.len() > 253 || !name.is_ascii() {
        return malformed("SNI host_name is not a valid ASCII DNS hostname");
    }

    for label in name.split(|byte| *byte == b'.') {
        if label.is_empty() || label.len() > 63 {
            return malformed("SNI host_name has an invalid DNS label length");
        }
        if !label[0].is_ascii_alphanumeric()
            || !label[label.len() - 1].is_ascii_alphanumeric()
            || !label
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            return malformed("SNI host_name contains an invalid DNS label");
        }
    }

    let name = std::str::from_utf8(name)
        .map_err(|_| TlsInspectError::Malformed {
            reason: "SNI host_name is not valid ASCII",
        })?
        .to_ascii_lowercase();
    if name.parse::<IpAddr>().is_ok() {
        return malformed("SNI host_name is an IP literal, not a DNS hostname");
    }

    Ok(name)
}

fn is_ech_extension(extension_type: u16) -> bool {
    extension_type == ENCRYPTED_SERVER_NAME_DRAFT_00_TO_06
        || extension_type == ECH_EXTENSION_DRAFT_07
        || ECH_EXTENSION_DRAFT_08_TO_12.contains(&extension_type)
        || extension_type == ECH_EXTENSION_RFC_9849
}

fn malformed<T>(reason: &'static str) -> Result<T, TlsInspectError> {
    Err(TlsInspectError::Malformed { reason })
}

struct SliceCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> SliceCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn take(&mut self, len: usize, reason: &'static str) -> Result<&'a [u8], TlsInspectError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(TlsInspectError::Malformed { reason })?;
        if end > self.bytes.len() {
            return malformed(reason);
        }
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self, reason: &'static str) -> Result<u8, TlsInspectError> {
        Ok(self.take(1, reason)?[0])
    }

    fn u16(&mut self, reason: &'static str) -> Result<u16, TlsInspectError> {
        let bytes = self.take(2, reason)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
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
    async fn extracts_sni_and_preserves_all_read_bytes() {
        let mut wire = tls_records(&client_hello(Some(b"WWW.Example.COM"), &[]), &[]);
        let trailing = [23, 3, 3, 0, 1, 42];
        wire.extend_from_slice(&trailing);
        let mut reader = FragmentedReader::new([wire.clone()]);

        let inspected = inspect_client_hello(&mut reader, test_config(4096))
            .await
            .expect("valid ClientHello");

        assert_eq!(inspected.server_name, "www.example.com");
        assert_eq!(inspected.buffered, wire);
    }

    #[tokio::test]
    async fn accepts_fragmented_reads_and_fragmented_tls_records() {
        let handshake = client_hello(Some(b"fragmented.example"), &[]);
        let wire = tls_records(&handshake, &[2, 37, 71]);
        let chunks = wire.iter().copied().map(|byte| vec![byte]);
        let mut reader = FragmentedReader::new(chunks);

        let inspected = inspect_client_hello(&mut reader, test_config(4096))
            .await
            .expect("fragmented ClientHello");

        assert_eq!(inspected.server_name, "fragmented.example");
        assert_eq!(inspected.buffered, wire);
    }

    #[tokio::test]
    async fn rejects_malformed_client_hello() {
        let malformed_handshake = [CLIENT_HELLO_HANDSHAKE_TYPE, 0, 0, 1, 3];
        let wire = tls_records(&malformed_handshake, &[]);
        let mut reader = FragmentedReader::new([wire]);

        let error = inspect_client_hello(&mut reader, test_config(4096))
            .await
            .expect_err("truncated ClientHello must fail");

        assert!(matches!(error, TlsInspectError::Malformed { .. }));
    }

    #[tokio::test]
    async fn enforces_buffer_limit_before_allocating_declared_record() {
        let wire = tls_records(&client_hello(Some(b"oversized.example"), &[]), &[]);
        let limit = wire.len() - 1;
        let mut reader = FragmentedReader::new(wire.iter().copied().map(|byte| vec![byte]));

        let error = inspect_client_hello(&mut reader, test_config(limit))
            .await
            .expect_err("ClientHello over the byte limit must fail");

        assert!(matches!(error, TlsInspectError::Oversized { limit: actual } if actual == limit));
    }

    #[tokio::test]
    async fn rejects_final_and_historical_ech_codepoints() {
        for extension_type in [0xffce, 0xff02, 0xfe08, 0xfe0a, 0xfe0c, 0xfe0d] {
            let handshake = client_hello(Some(b"public.example"), &[(extension_type, &[0])]);
            let wire = tls_records(&handshake, &[]);
            let mut reader = FragmentedReader::new([wire]);

            let error = inspect_client_hello(&mut reader, test_config(4096))
                .await
                .expect_err("ECH must make outer SNI unroutable");

            assert!(
                matches!(error, TlsInspectError::EncryptedClientHello),
                "extension {extension_type:#06x} returned {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn does_not_treat_arbitrary_grease_as_ech() {
        let handshake = client_hello(Some(b"grease.example"), &[(0xfafa, &[])]);
        let wire = tls_records(&handshake, &[]);
        let mut reader = FragmentedReader::new([wire]);

        let inspected = inspect_client_hello(&mut reader, test_config(4096))
            .await
            .expect("GREASE is not proof of ECH");

        assert_eq!(inspected.server_name, "grease.example");
    }

    #[tokio::test]
    async fn rejects_client_hello_without_sni() {
        let wire = tls_records(&client_hello(None, &[]), &[]);
        let mut reader = FragmentedReader::new([wire]);

        let error = inspect_client_hello(&mut reader, test_config(4096))
            .await
            .expect_err("missing SNI must fail");

        assert!(matches!(error, TlsInspectError::NoServerName));
    }

    #[tokio::test]
    async fn rejects_duplicate_sni_extensions() {
        let handshake = client_hello(Some(b"first.example"), &[(SERVER_NAME_EXTENSION, &[])]);
        let wire = tls_records(&handshake, &[]);
        let mut reader = FragmentedReader::new([wire]);

        let error = inspect_client_hello(&mut reader, test_config(4096))
            .await
            .expect_err("duplicate SNI extensions must be ambiguous");

        assert!(matches!(error, TlsInspectError::Malformed { .. }));
    }

    #[tokio::test]
    async fn rejects_multiple_host_names_in_one_sni_extension() {
        let mut server_names = Vec::new();
        for name in [b"first.example".as_slice(), b"second.example".as_slice()] {
            server_names.push(HOST_NAME_TYPE);
            push_u16(&mut server_names, name.len());
            server_names.extend_from_slice(name);
        }
        let mut extension = Vec::new();
        push_u16(&mut extension, server_names.len());
        extension.extend_from_slice(&server_names);

        let handshake = client_hello(None, &[(SERVER_NAME_EXTENSION, &extension)]);
        let wire = tls_records(&handshake, &[]);
        let mut reader = FragmentedReader::new([wire]);

        let error = inspect_client_hello(&mut reader, test_config(4096))
            .await
            .expect_err("multiple host_name entries must be ambiguous");

        assert!(matches!(error, TlsInspectError::Malformed { .. }));
    }

    #[tokio::test]
    async fn rejects_non_dns_sni() {
        for invalid_name in [
            &b"127.0.0.1"[..],
            &b"bad_name.example"[..],
            &b"bad..example"[..],
        ] {
            let wire = tls_records(&client_hello(Some(invalid_name), &[]), &[]);
            let mut reader = FragmentedReader::new([wire]);

            let error = inspect_client_hello(&mut reader, test_config(4096))
                .await
                .expect_err("invalid DNS SNI must fail");

            assert!(matches!(error, TlsInspectError::Malformed { .. }));
        }
    }

    #[tokio::test]
    async fn enforces_overall_timeout() {
        let (mut reader, _writer) = tokio::io::duplex(64);
        let config = TlsInspectConfig {
            max_buffered_bytes: 4096,
            timeout: Duration::from_millis(10),
        };

        let error = inspect_client_hello(&mut reader, config)
            .await
            .expect_err("silent peer must time out");

        assert!(matches!(error, TlsInspectError::Timeout));
    }

    fn test_config(limit: usize) -> TlsInspectConfig {
        TlsInspectConfig {
            max_buffered_bytes: limit,
            timeout: Duration::from_secs(1),
        }
    }

    fn client_hello(sni: Option<&[u8]>, extra_extensions: &[(u16, &[u8])]) -> Vec<u8> {
        let mut extensions = Vec::new();
        if let Some(sni) = sni {
            let mut server_name = Vec::new();
            let list_len = 1usize + 2 + sni.len();
            push_u16(&mut server_name, list_len);
            server_name.push(HOST_NAME_TYPE);
            push_u16(&mut server_name, sni.len());
            server_name.extend_from_slice(sni);

            push_u16(&mut extensions, SERVER_NAME_EXTENSION);
            push_u16(&mut extensions, server_name.len());
            extensions.extend_from_slice(&server_name);
        }
        for (extension_type, payload) in extra_extensions {
            push_u16(&mut extensions, *extension_type);
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

        let mut handshake = Vec::new();
        handshake.push(CLIENT_HELLO_HANDSHAKE_TYPE);
        push_u24(&mut handshake, body.len());
        handshake.extend_from_slice(&body);
        handshake
    }

    fn tls_records(handshake: &[u8], split_at: &[usize]) -> Vec<u8> {
        let mut wire = Vec::new();
        let mut start = 0usize;
        for end in split_at
            .iter()
            .copied()
            .chain(std::iter::once(handshake.len()))
        {
            assert!(end > start && end <= handshake.len());
            let payload = &handshake[start..end];
            wire.extend_from_slice(&[TLS_HANDSHAKE_CONTENT_TYPE, 3, 1]);
            push_u16(&mut wire, payload.len());
            wire.extend_from_slice(payload);
            start = end;
        }
        wire
    }

    fn push_u16(target: &mut Vec<u8>, value: impl TryInto<u16>) {
        let value = value.try_into().ok().expect("test vector fits u16");
        target.extend_from_slice(&value.to_be_bytes());
    }

    fn push_u24(target: &mut Vec<u8>, value: usize) {
        assert!(value <= 0x00ff_ffff);
        let encoded = u32::try_from(value)
            .expect("test vector fits u32")
            .to_be_bytes();
        target.extend_from_slice(&encoded[1..]);
    }
}
