//! Bounded destination inspection for accepted client connections.

pub mod http;
pub mod quic;
pub mod tls;

use std::{io, time::Duration};

use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    time::timeout,
};

use http::{HttpInspectConfig, HttpInspectError, inspect_request};
pub use tls::{TlsInspectConfig, TlsInspectError, TlsInspection, inspect_client_hello};

/// Shared resource bounds for automatic TCP protocol inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpInspectConfig {
    pub max_buffered_bytes: usize,
    /// Deadline for protocol selection and complete destination inspection.
    pub timeout: Duration,
}

/// Protocol that supplied the trustworthy destination hostname.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InspectedTcpProtocol {
    Http1,
    Tls,
}

/// A routable TCP stream and every byte consumed while selecting its route.
#[derive(Debug, Eq, PartialEq)]
pub struct TcpInspection {
    pub server_name: String,
    pub buffered: Vec<u8>,
    pub protocol: InspectedTcpProtocol,
}

#[derive(Debug, Error)]
pub enum TcpInspectError {
    #[error("TCP destination inspection timed out")]
    Timeout,
    #[error("client closed before protocol detection")]
    UnexpectedEof,
    #[error("failed to read protocol marker: {0}")]
    Io(#[from] io::Error),
    #[error("HTTP/1 destination inspection failed: {0}")]
    Http(#[from] HttpInspectError),
    #[error("TLS destination inspection failed: {0}")]
    Tls(#[from] TlsInspectError),
}

/// Select TLS or HTTP/1 from the first byte and extract a trustworthy hostname.
///
/// The first byte is replayed through the selected inspector, so every byte
/// consumed from the client is returned unchanged in `buffered`. Inputs that
/// are neither a TLS handshake record nor valid HTTP/1 fail closed.
///
/// # Errors
///
/// Returns a typed timeout, EOF, I/O, HTTP, or TLS inspection error.
pub async fn inspect_tcp_destination<R>(
    reader: &mut R,
    config: TcpInspectConfig,
) -> Result<TcpInspection, TcpInspectError>
where
    R: AsyncRead + Unpin,
{
    match timeout(config.timeout, inspect_tcp_inner(reader, config)).await {
        Ok(result) => result,
        Err(_) => Err(TcpInspectError::Timeout),
    }
}

async fn inspect_tcp_inner<R>(
    reader: &mut R,
    config: TcpInspectConfig,
) -> Result<TcpInspection, TcpInspectError>
where
    R: AsyncRead + Unpin,
{
    let mut first = [0_u8; 1];
    if reader.read(&mut first).await? == 0 {
        return Err(TcpInspectError::UnexpectedEof);
    }

    let prefix = std::io::Cursor::new(first);
    let mut replay = prefix.chain(reader);
    if first[0] == 22 {
        let inspected = inspect_client_hello(
            &mut replay,
            TlsInspectConfig {
                max_buffered_bytes: config.max_buffered_bytes,
                timeout: config.timeout,
            },
        )
        .await?;
        Ok(TcpInspection {
            server_name: inspected.server_name,
            buffered: inspected.buffered,
            protocol: InspectedTcpProtocol::Tls,
        })
    } else {
        let inspected = inspect_request(
            &mut replay,
            HttpInspectConfig {
                max_buffered_bytes: config.max_buffered_bytes,
                timeout: config.timeout,
            },
        )
        .await?;
        Ok(TcpInspection {
            server_name: inspected.server_name,
            buffered: inspected.buffered,
            protocol: InspectedTcpProtocol::Http1,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dispatches_http_without_losing_protocol_marker() {
        let wire = b"GET / HTTP/1.1\r\nHost: dispatch.example\r\n\r\n";
        let mut reader = std::io::Cursor::new(wire);
        let inspected = inspect_tcp_destination(
            &mut reader,
            TcpInspectConfig {
                max_buffered_bytes: 4096,
                timeout: Duration::from_secs(1),
            },
        )
        .await
        .expect("valid HTTP/1 request");

        assert_eq!(inspected.protocol, InspectedTcpProtocol::Http1);
        assert_eq!(inspected.server_name, "dispatch.example");
        assert_eq!(inspected.buffered, wire);
    }
}
