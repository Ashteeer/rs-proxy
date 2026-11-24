use std::{
    io::{self, IoSlice},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, copy_bidirectional},
    net::TcpStream,
    time::{Instant, sleep_until, timeout},
};

const FIRST_RESPONSE_BUFFER_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayStats {
    pub client_to_upstream: u64,
    pub upstream_to_client: u64,
}

/// Forward the inspected prefix, then relay both directions until both EOFs.
///
/// # Errors
///
/// Returns an error when the initial bounded write or inactivity deadline is
/// exceeded, or either stream fails during the bidirectional relay.
pub async fn relay_tcp(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    buffered_client_bytes: &[u8],
    initial_write_timeout: Duration,
    idle_timeout: Duration,
) -> Result<RelayStats, RelayError> {
    timeout(
        initial_write_timeout,
        upstream.write_all(buffered_client_bytes),
    )
    .await
    .map_err(|_| RelayError::InitialWriteTimeout)??;

    let started = Instant::now();
    let last_activity_ms = Arc::new(AtomicU64::new(0));
    let mut active_client = ActivityIo::new(client, started, Arc::clone(&last_activity_ms));
    let mut active_upstream = ActivityIo::new(upstream, started, Arc::clone(&last_activity_ms));
    let transfer = copy_bidirectional(&mut active_client, &mut active_upstream);
    tokio::pin!(transfer);
    let idle_deadline = sleep_until(started + idle_timeout);
    tokio::pin!(idle_deadline);

    let (client_to_upstream, upstream_to_client) = loop {
        tokio::select! {
            result = &mut transfer => break result?,
            () = &mut idle_deadline => {
                let elapsed_ms = millis_since(started);
                let last_activity = last_activity_ms.load(Ordering::Relaxed);
                let Some(remaining) = idle_remaining(elapsed_ms, last_activity, idle_timeout) else {
                    return Err(RelayError::IdleTimeout(idle_timeout));
                };
                idle_deadline.as_mut().reset(Instant::now() + remaining);
            }
        }
    };
    Ok(RelayStats {
        client_to_upstream: client_to_upstream + buffered_client_bytes.len() as u64,
        upstream_to_client,
    })
}

/// Forward client bytes until one nonempty upstream read has been returned to
/// the client, then stop. Closing the accepted sockets after this function is
/// a userspace approximation: it does not provide packet-level silent DROP.
///
/// # Errors
///
/// Returns an error for I/O, inactivity, initial-write timeout, or an upstream
/// EOF before the first response chunk.
pub async fn relay_tcp_first_response(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    buffered_client_bytes: &[u8],
    initial_write_timeout: Duration,
    idle_timeout: Duration,
) -> Result<RelayStats, RelayError> {
    timeout(
        initial_write_timeout,
        upstream.write_all(buffered_client_bytes),
    )
    .await
    .map_err(|_| RelayError::InitialWriteTimeout)??;

    let (mut client_read, mut client_write) = client.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();
    let mut client_buffer = vec![0_u8; FIRST_RESPONSE_BUFFER_BYTES];
    let mut response_buffer = vec![0_u8; FIRST_RESPONSE_BUFFER_BYTES];
    let mut client_to_upstream = buffered_client_bytes.len() as u64;
    let mut client_open = true;

    loop {
        let event = timeout(idle_timeout, async {
            if client_open {
                tokio::select! {
                    read = client_read.read(&mut client_buffer) => FirstResponseEvent::Client(read),
                    read = upstream_read.read(&mut response_buffer) => FirstResponseEvent::Upstream(read),
                }
            } else {
                FirstResponseEvent::Upstream(upstream_read.read(&mut response_buffer).await)
            }
        })
        .await
        .map_err(|_| RelayError::IdleTimeout(idle_timeout))?;

        match event {
            FirstResponseEvent::Client(Ok(0)) => {
                client_open = false;
                timeout(idle_timeout, upstream_write.shutdown())
                    .await
                    .map_err(|_| RelayError::IdleTimeout(idle_timeout))??;
            }
            FirstResponseEvent::Client(Ok(read)) => {
                timeout(
                    idle_timeout,
                    upstream_write.write_all(&client_buffer[..read]),
                )
                .await
                .map_err(|_| RelayError::IdleTimeout(idle_timeout))??;
                client_to_upstream = client_to_upstream.saturating_add(read as u64);
            }
            FirstResponseEvent::Client(Err(error)) | FirstResponseEvent::Upstream(Err(error)) => {
                return Err(error.into());
            }
            FirstResponseEvent::Upstream(Ok(0)) => {
                return Err(RelayError::UpstreamClosedBeforeFirstResponse);
            }
            FirstResponseEvent::Upstream(Ok(read)) => {
                timeout(idle_timeout, async {
                    client_write.write_all(&response_buffer[..read]).await?;
                    client_write.flush().await
                })
                .await
                .map_err(|_| RelayError::IdleTimeout(idle_timeout))??;
                return Ok(RelayStats {
                    client_to_upstream,
                    upstream_to_client: read as u64,
                });
            }
        }
    }
}

enum FirstResponseEvent {
    Client(io::Result<usize>),
    Upstream(io::Result<usize>),
}

struct ActivityIo<'a> {
    inner: &'a mut TcpStream,
    started: Instant,
    last_activity_ms: Arc<AtomicU64>,
}

impl<'a> ActivityIo<'a> {
    fn new(inner: &'a mut TcpStream, started: Instant, last_activity_ms: Arc<AtomicU64>) -> Self {
        Self {
            inner,
            started,
            last_activity_ms,
        }
    }

    fn touch(&self) {
        self.last_activity_ms
            .store(millis_since(self.started), Ordering::Relaxed);
    }
}

impl AsyncRead for ActivityIo<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut *self.inner).poll_read(context, buffer);
        if matches!(result, Poll::Ready(Ok(()))) && buffer.filled().len() > before {
            self.touch();
        }
        result
    }
}

impl AsyncWrite for ActivityIo<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut *self.inner).poll_write(context, buffer);
        if matches!(result, Poll::Ready(Ok(written)) if written > 0) {
            self.touch();
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(context)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut *self.inner).poll_write_vectored(context, buffers);
        if matches!(result, Poll::Ready(Ok(written)) if written > 0) {
            self.touch();
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

fn millis_since(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn idle_remaining(
    elapsed_ms: u64,
    last_activity_ms: u64,
    idle_timeout: Duration,
) -> Option<Duration> {
    let idle_for = Duration::from_millis(elapsed_ms.saturating_sub(last_activity_ms));
    idle_timeout
        .checked_sub(idle_for)
        .filter(|remaining| !remaining.is_zero())
}

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("timed out while forwarding the inspected client prefix")]
    InitialWriteTimeout,
    #[error("TCP relay was inactive for {0:?}")]
    IdleTimeout(Duration),
    #[error("upstream closed before sending a first response chunk")]
    UpstreamClosedBeforeFirstResponse,
    #[error("TCP relay failed: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn activity_resets_idle_deadline_then_inactivity_expires() {
        let idle = Duration::from_millis(60);
        assert_eq!(
            idle_remaining(50, 25, idle),
            Some(Duration::from_millis(35))
        );
        assert_eq!(idle_remaining(84, 25, idle), Some(Duration::from_millis(1)));
        assert_eq!(idle_remaining(85, 25, idle), None);
        assert_eq!(idle_remaining(100, 40, idle), None);
    }

    #[tokio::test]
    async fn first_response_mode_forwards_one_nonempty_upstream_read() {
        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_address = client_listener.local_addr().unwrap();
        let client_peer = TcpStream::connect(client_address);
        let (proxy_client, client_peer) = tokio::join!(client_listener.accept(), client_peer);
        let (mut proxy_client, _) = proxy_client.unwrap();
        let mut client_peer = client_peer.unwrap();

        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream_listener.local_addr().unwrap();
        let proxy_upstream = TcpStream::connect(upstream_address);
        let (upstream_peer, proxy_upstream) =
            tokio::join!(upstream_listener.accept(), proxy_upstream);
        let (mut upstream_peer, _) = upstream_peer.unwrap();
        let mut proxy_upstream = proxy_upstream.unwrap();

        let relay = tokio::spawn(async move {
            relay_tcp_first_response(
                &mut proxy_client,
                &mut proxy_upstream,
                b"inspected-prefix",
                Duration::from_secs(1),
                Duration::from_secs(1),
            )
            .await
        });

        let mut request = [0_u8; 16];
        upstream_peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"inspected-prefix");
        upstream_peer.write_all(b"first").await.unwrap();

        let mut response = [0_u8; 5];
        client_peer.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"first");
        let stats = relay.await.unwrap().unwrap();
        assert_eq!(stats.client_to_upstream, 16);
        assert_eq!(stats.upstream_to_client, 5);

        let mut trailing = Vec::new();
        client_peer.read_to_end(&mut trailing).await.unwrap();
        assert!(trailing.is_empty());
    }
}
