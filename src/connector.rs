use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use thiserror::Error;
use tokio::{
    net::{TcpStream, UdpSocket},
    time::{Instant, timeout},
};

use crate::policy::{AddressPolicy, PolicyRefreshError};

/// Try each resolved address until an upstream TCP connection succeeds.
///
/// # Errors
///
/// Returns an error when every address fails or when socket configuration
/// fails after a successful connection.
pub async fn connect_tcp(
    addresses: &[SocketAddr],
    connect_timeout: Duration,
    policy: Arc<AddressPolicy>,
    max_addresses: usize,
) -> Result<TcpStream, ConnectError> {
    let deadline = Instant::now() + connect_timeout;
    policy.refresh_local_addresses(connect_timeout).await?;
    let mut denied = 0_usize;
    let candidates: Vec<_> = addresses
        .iter()
        .copied()
        .filter(|address| {
            let allowed = policy.check(address.ip(), address.port()).is_ok();
            denied += usize::from(!allowed);
            allowed
        })
        .take(max_addresses)
        .collect();
    if candidates.is_empty() {
        return Err(ConnectError::AllFailed {
            summary: format!("no permitted address candidates ({denied} denied)"),
            timed_out: false,
        });
    }

    let mut failures = Vec::with_capacity(candidates.len());
    let mut timed_out = false;
    for (index, address) in candidates.iter().enumerate() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            timed_out = true;
            failures.push("overall connect deadline expired".into());
            break;
        }
        let attempts_left = u32::try_from(candidates.len() - index).unwrap_or(u32::MAX);
        let attempt_timeout = remaining / attempts_left;
        match timeout(attempt_timeout, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => {
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Ok(Err(error)) => failures.push(format!("{address}: {error}")),
            Err(_) => {
                timed_out = true;
                failures.push(format!("{address}: timed out"));
            }
        }
    }

    Err(ConnectError::AllFailed {
        summary: failures.join("; "),
        timed_out,
    })
}

/// Bind and connect one UDP socket to the first permitted resolved address.
///
/// The policy snapshot is refreshed immediately before candidate selection.
/// A connected socket pins the receive path to the selected upstream tuple;
/// it does not prove that a remote UDP service exists.
///
/// # Errors
///
/// Returns an error when policy refresh fails or every permitted candidate
/// fails local bind/connect within the shared deadline.
pub async fn connect_udp(
    addresses: &[SocketAddr],
    connect_timeout: Duration,
    policy: Arc<AddressPolicy>,
    max_addresses: usize,
) -> Result<(UdpSocket, SocketAddr), ConnectError> {
    let deadline = Instant::now() + connect_timeout;
    policy.refresh_local_addresses(connect_timeout).await?;
    let mut denied = 0_usize;
    let candidates: Vec<_> = addresses
        .iter()
        .copied()
        .filter(|address| {
            let allowed = policy.check(address.ip(), address.port()).is_ok();
            denied += usize::from(!allowed);
            allowed
        })
        .take(max_addresses)
        .collect();
    if candidates.is_empty() {
        return Err(ConnectError::AllFailed {
            summary: format!("no permitted address candidates ({denied} denied)"),
            timed_out: false,
        });
    }

    let mut failures = Vec::with_capacity(candidates.len());
    let mut timed_out = false;
    for address in candidates {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            timed_out = true;
            failures.push("overall connect deadline expired".into());
            break;
        }
        let bind_address = if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = match UdpSocket::bind(bind_address).await {
            Ok(socket) => socket,
            Err(error) => {
                failures.push(format!("{address}: local bind failed: {error}"));
                continue;
            }
        };
        match timeout(remaining, socket.connect(address)).await {
            Ok(Ok(())) => return Ok((socket, address)),
            Ok(Err(error)) => failures.push(format!("{address}: {error}")),
            Err(_) => {
                timed_out = true;
                failures.push(format!("{address}: timed out"));
            }
        }
    }

    Err(ConnectError::AllFailed {
        summary: failures.join("; "),
        timed_out,
    })
}

#[derive(Debug, Error)]
pub enum ConnectError {
    #[error("failed to configure upstream socket: {0}")]
    Configure(#[from] io::Error),
    #[error("failed to refresh local addresses before upstream connect: {0}")]
    PolicyRefresh(#[from] PolicyRefreshError),
    #[error("all upstream connection attempts failed: {summary}")]
    AllFailed { summary: String, timed_out: bool },
}

impl ConnectError {
    #[must_use]
    pub fn is_timeout(&self) -> bool {
        match self {
            Self::Configure(error) => error.kind() == io::ErrorKind::TimedOut,
            Self::PolicyRefresh(PolicyRefreshError::Timeout)
            | Self::AllFailed {
                timed_out: true, ..
            } => true,
            Self::PolicyRefresh(_) | Self::AllFailed { .. } => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_classification_is_typed_not_inferred_from_summary() {
        assert!(
            ConnectError::AllFailed {
                summary: "opaque failure".into(),
                timed_out: true,
            }
            .is_timeout()
        );
        assert!(
            !ConnectError::AllFailed {
                summary: "text says timed out but typed flag is false".into(),
                timed_out: false,
            }
            .is_timeout()
        );
        assert!(ConnectError::PolicyRefresh(PolicyRefreshError::Timeout).is_timeout());
    }
}
