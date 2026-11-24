use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::{
    sync::watch,
    time::{Instant, MissedTickBehavior, interval_at},
};

/// Process-local counters and gauges for the proxy runtime.
///
/// Every metric has a fixed name. The type intentionally has no labels so
/// callers cannot accidentally retain or publish client addresses, hostnames,
/// or payload-derived values.
#[derive(Debug, Default)]
pub struct RuntimeMetrics {
    tcp_connections_accepted_total: AtomicU64,
    udp_sessions_started_total: AtomicU64,
    capacity_rejections_total: AtomicU64,
    admission_denials_total: AtomicU64,
    inspection_failures_total: AtomicU64,
    dns_failures_total: AtomicU64,
    upstream_failures_total: AtomicU64,
    timeouts_total: AtomicU64,
    quic_retries_accepted_total: AtomicU64,
    udp_amplification_drops_total: AtomicU64,
    udp_datagrams_dropped_total: AtomicU64,
    relays_completed_total: AtomicU64,
    relay_failures_total: AtomicU64,
    client_to_upstream_bytes_total: AtomicU64,
    upstream_to_client_bytes_total: AtomicU64,
    client_to_upstream_datagrams_total: AtomicU64,
    upstream_to_client_datagrams_total: AtomicU64,
    active_tcp_connections: AtomicU64,
    active_udp_sessions: AtomicU64,
}

/// One immutable, internally consistent-enough observation of runtime metrics.
///
/// Individual fields are loaded independently. A snapshot can therefore span
/// concurrent updates, which is appropriate for operational telemetry and
/// avoids putting locks on the data path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Snapshot {
    pub tcp_connections_accepted_total: u64,
    pub udp_sessions_started_total: u64,
    pub capacity_rejections_total: u64,
    pub admission_denials_total: u64,
    pub inspection_failures_total: u64,
    pub dns_failures_total: u64,
    pub upstream_failures_total: u64,
    pub timeouts_total: u64,
    pub quic_retries_accepted_total: u64,
    pub udp_amplification_drops_total: u64,
    pub udp_datagrams_dropped_total: u64,
    pub relays_completed_total: u64,
    pub relay_failures_total: u64,
    pub client_to_upstream_bytes_total: u64,
    pub upstream_to_client_bytes_total: u64,
    pub client_to_upstream_datagrams_total: u64,
    pub upstream_to_client_datagrams_total: u64,
    pub active_tcp_connections: u64,
    pub active_udp_sessions: u64,
}

#[derive(Clone, Copy, Debug)]
enum ActiveGauge {
    Tcp,
    Udp,
}

/// Keeps an active-flow gauge raised for the guard's lifetime.
#[derive(Debug)]
#[must_use = "retain the guard for as long as the flow is active"]
pub(crate) struct ActiveFlowGuard {
    metrics: Arc<RuntimeMetrics>,
    gauge: ActiveGauge,
    counted: bool,
}

impl RuntimeMetrics {
    pub(crate) fn tcp_connection_accepted(&self) {
        saturating_add(&self.tcp_connections_accepted_total, 1);
    }

    pub(crate) fn udp_session_started(&self) {
        saturating_add(&self.udp_sessions_started_total, 1);
    }

    pub(crate) fn capacity_rejected(&self) {
        saturating_add(&self.capacity_rejections_total, 1);
    }

    pub(crate) fn admission_denied(&self) {
        saturating_add(&self.admission_denials_total, 1);
    }

    pub(crate) fn inspection_failed(&self) {
        saturating_add(&self.inspection_failures_total, 1);
    }

    pub(crate) fn dns_failed(&self) {
        saturating_add(&self.dns_failures_total, 1);
    }

    pub(crate) fn upstream_failed(&self) {
        saturating_add(&self.upstream_failures_total, 1);
    }

    pub(crate) fn timeout(&self) {
        saturating_add(&self.timeouts_total, 1);
    }

    pub(crate) fn quic_retry_accepted(&self) {
        saturating_add(&self.quic_retries_accepted_total, 1);
    }

    pub(crate) fn udp_amplification_dropped(&self) {
        saturating_add(&self.udp_amplification_drops_total, 1);
    }

    pub(crate) fn udp_datagram_dropped(&self) {
        saturating_add(&self.udp_datagrams_dropped_total, 1);
    }

    pub(crate) fn add_udp_datagrams_dropped(&self, datagrams: u64) {
        saturating_add(&self.udp_datagrams_dropped_total, datagrams);
    }

    pub(crate) fn relay_completed(&self) {
        saturating_add(&self.relays_completed_total, 1);
    }

    pub(crate) fn relay_failed(&self) {
        saturating_add(&self.relay_failures_total, 1);
    }

    pub(crate) fn add_client_to_upstream_bytes(&self, bytes: u64) {
        saturating_add(&self.client_to_upstream_bytes_total, bytes);
    }

    pub(crate) fn add_upstream_to_client_bytes(&self, bytes: u64) {
        saturating_add(&self.upstream_to_client_bytes_total, bytes);
    }

    pub(crate) fn add_client_to_upstream_datagrams(&self, datagrams: u64) {
        saturating_add(&self.client_to_upstream_datagrams_total, datagrams);
    }

    pub(crate) fn add_upstream_to_client_datagrams(&self, datagrams: u64) {
        saturating_add(&self.upstream_to_client_datagrams_total, datagrams);
    }

    pub(crate) fn track_tcp_connection(self: &Arc<Self>) -> ActiveFlowGuard {
        self.track(ActiveGauge::Tcp)
    }

    pub(crate) fn track_udp_session(self: &Arc<Self>) -> ActiveFlowGuard {
        self.track(ActiveGauge::Udp)
    }

    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            tcp_connections_accepted_total: load(&self.tcp_connections_accepted_total),
            udp_sessions_started_total: load(&self.udp_sessions_started_total),
            capacity_rejections_total: load(&self.capacity_rejections_total),
            admission_denials_total: load(&self.admission_denials_total),
            inspection_failures_total: load(&self.inspection_failures_total),
            dns_failures_total: load(&self.dns_failures_total),
            upstream_failures_total: load(&self.upstream_failures_total),
            timeouts_total: load(&self.timeouts_total),
            quic_retries_accepted_total: load(&self.quic_retries_accepted_total),
            udp_amplification_drops_total: load(&self.udp_amplification_drops_total),
            udp_datagrams_dropped_total: load(&self.udp_datagrams_dropped_total),
            relays_completed_total: load(&self.relays_completed_total),
            relay_failures_total: load(&self.relay_failures_total),
            client_to_upstream_bytes_total: load(&self.client_to_upstream_bytes_total),
            upstream_to_client_bytes_total: load(&self.upstream_to_client_bytes_total),
            client_to_upstream_datagrams_total: load(&self.client_to_upstream_datagrams_total),
            upstream_to_client_datagrams_total: load(&self.upstream_to_client_datagrams_total),
            active_tcp_connections: load(&self.active_tcp_connections),
            active_udp_sessions: load(&self.active_udp_sessions),
        }
    }

    /// Emit fixed-field snapshots until shutdown is requested.
    ///
    /// The first periodic snapshot is delayed by `period`; a final snapshot is
    /// emitted when the shutdown channel is signalled or closed. A zero period
    /// returns without logging, although validated runtime configuration never
    /// supplies one.
    pub(crate) async fn report_until_shutdown(
        &self,
        period: Duration,
        mut shutdown: watch::Receiver<bool>,
    ) {
        if period.is_zero() {
            return;
        }

        if *shutdown.borrow() {
            self.trace_snapshot(true);
            return;
        }

        let mut ticker = interval_at(Instant::now() + period, period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        self.trace_snapshot(true);
                        return;
                    }
                }
                _ = ticker.tick() => self.trace_snapshot(false),
            }
        }
    }

    fn track(self: &Arc<Self>, gauge: ActiveGauge) -> ActiveFlowGuard {
        let active_counter = match gauge {
            ActiveGauge::Tcp => &self.active_tcp_connections,
            ActiveGauge::Udp => &self.active_udp_sessions,
        };
        let gauge_incremented = try_increment(active_counter);
        ActiveFlowGuard {
            metrics: Arc::clone(self),
            gauge,
            counted: gauge_incremented,
        }
    }

    fn trace_snapshot(&self, final_snapshot: bool) {
        let snapshot = self.snapshot();
        tracing::info!(
            target: "rs_proxy::metrics",
            event = "runtime_metrics",
            final_snapshot,
            tcp_connections_accepted_total = snapshot.tcp_connections_accepted_total,
            udp_sessions_started_total = snapshot.udp_sessions_started_total,
            capacity_rejections_total = snapshot.capacity_rejections_total,
            admission_denials_total = snapshot.admission_denials_total,
            inspection_failures_total = snapshot.inspection_failures_total,
            dns_failures_total = snapshot.dns_failures_total,
            upstream_failures_total = snapshot.upstream_failures_total,
            timeouts_total = snapshot.timeouts_total,
            quic_retries_accepted_total = snapshot.quic_retries_accepted_total,
            udp_amplification_drops_total = snapshot.udp_amplification_drops_total,
            udp_datagrams_dropped_total = snapshot.udp_datagrams_dropped_total,
            relays_completed_total = snapshot.relays_completed_total,
            relay_failures_total = snapshot.relay_failures_total,
            client_to_upstream_bytes_total = snapshot.client_to_upstream_bytes_total,
            upstream_to_client_bytes_total = snapshot.upstream_to_client_bytes_total,
            client_to_upstream_datagrams_total = snapshot.client_to_upstream_datagrams_total,
            upstream_to_client_datagrams_total = snapshot.upstream_to_client_datagrams_total,
            active_tcp_connections = snapshot.active_tcp_connections,
            active_udp_sessions = snapshot.active_udp_sessions,
            "runtime metrics snapshot"
        );
    }
}

impl Drop for ActiveFlowGuard {
    fn drop(&mut self) {
        if !self.counted {
            return;
        }
        let counter = match self.gauge {
            ActiveGauge::Tcp => &self.metrics.active_tcp_connections,
            ActiveGauge::Udp => &self.metrics.active_udp_sessions,
        };
        saturating_sub(counter, 1);
    }
}

fn load(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}

fn saturating_add(counter: &AtomicU64, value: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(value))
    });
}

fn saturating_sub(counter: &AtomicU64, value: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_sub(value))
    });
}

fn try_increment(counter: &AtomicU64) -> bool {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_reports_fixed_counters_and_saturates() {
        let metrics = RuntimeMetrics::default();
        metrics.tcp_connection_accepted();
        metrics.udp_session_started();
        metrics.capacity_rejected();
        metrics.admission_denied();
        metrics.inspection_failed();
        metrics.dns_failed();
        metrics.upstream_failed();
        metrics.timeout();
        metrics.quic_retry_accepted();
        metrics.udp_amplification_dropped();
        metrics.udp_datagram_dropped();
        metrics.add_udp_datagrams_dropped(2);
        metrics.relay_completed();
        metrics.relay_failed();
        metrics.add_client_to_upstream_bytes(u64::MAX - 2);
        metrics.add_client_to_upstream_bytes(10);
        metrics.add_upstream_to_client_bytes(7);
        metrics.add_client_to_upstream_datagrams(2);
        metrics.add_upstream_to_client_datagrams(3);

        assert_eq!(
            metrics.snapshot(),
            Snapshot {
                tcp_connections_accepted_total: 1,
                udp_sessions_started_total: 1,
                capacity_rejections_total: 1,
                admission_denials_total: 1,
                inspection_failures_total: 1,
                dns_failures_total: 1,
                upstream_failures_total: 1,
                timeouts_total: 1,
                quic_retries_accepted_total: 1,
                udp_amplification_drops_total: 1,
                udp_datagrams_dropped_total: 3,
                relays_completed_total: 1,
                relay_failures_total: 1,
                client_to_upstream_bytes_total: u64::MAX,
                upstream_to_client_bytes_total: 7,
                client_to_upstream_datagrams_total: 2,
                upstream_to_client_datagrams_total: 3,
                active_tcp_connections: 0,
                active_udp_sessions: 0,
            }
        );
    }

    #[test]
    fn active_flow_guards_raise_and_release_gauges() {
        let metrics = Arc::new(RuntimeMetrics::default());
        let tcp = metrics.track_tcp_connection();
        let udp = metrics.track_udp_session();
        let udp_two = metrics.track_udp_session();
        assert_eq!(metrics.snapshot().active_tcp_connections, 1);
        assert_eq!(metrics.snapshot().active_udp_sessions, 2);

        drop(tcp);
        drop(udp);
        assert_eq!(metrics.snapshot().active_tcp_connections, 0);
        assert_eq!(metrics.snapshot().active_udp_sessions, 1);

        drop(udp_two);
        assert_eq!(metrics.snapshot().active_udp_sessions, 0);
    }

    #[test]
    fn saturated_active_gauge_is_not_decremented_by_uncounted_guard() {
        let metrics = Arc::new(RuntimeMetrics::default());
        metrics
            .active_tcp_connections
            .store(u64::MAX, Ordering::Relaxed);

        let guard = metrics.track_tcp_connection();
        assert_eq!(metrics.snapshot().active_tcp_connections, u64::MAX);
        drop(guard);
        assert_eq!(metrics.snapshot().active_tcp_connections, u64::MAX);
    }

    #[tokio::test]
    async fn reporter_stops_on_shutdown_and_zero_period() {
        let metrics = Arc::new(RuntimeMetrics::default());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let reporter_metrics = Arc::clone(&metrics);
        let reporter = tokio::spawn(async move {
            reporter_metrics
                .report_until_shutdown(Duration::from_secs(60), shutdown_rx)
                .await;
        });
        tokio::task::yield_now().await;
        shutdown_tx.send(true).expect("shutdown receiver exists");
        tokio::time::timeout(Duration::from_millis(100), reporter)
            .await
            .expect("reporter must observe shutdown immediately")
            .expect("reporter task must not panic");

        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        metrics
            .report_until_shutdown(Duration::ZERO, shutdown_rx)
            .await;
    }
}
