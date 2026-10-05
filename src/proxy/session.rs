// EvadeDPI: Modern Deep Packet Inspection Circumvention Engine
// Connection Session Tracking, Statistics, and Traffic Metrics

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

/// Global atomic statistics tracking the state and activity of EvadeDPI.
#[derive(Debug, Default)]
pub struct Stats {
    pub active_connections: AtomicUsize,
    pub total_connections: AtomicU64,
    pub bypassed_requests: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
}

#[derive(Debug, Clone, Default)]
pub struct SessionTracker {
    inner: Arc<Stats>,
}

impl SessionTracker {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Stats::default()),
        }
    }

    pub fn inc_active(&self) {
        self.inner.active_connections.fetch_add(1, Ordering::Relaxed);
        self.inner.total_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_active(&self) {
        self.inner.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_bypassed(&self) {
        self.inner.bypassed_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_bytes_sent(&self, bytes: u64) {
        self.inner.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_bytes_received(&self, bytes: u64) {
        self.inner.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn active_connections(&self) -> usize {
        self.inner.active_connections.load(Ordering::Relaxed)
    }

    pub fn total_connections(&self) -> u64 {
        self.inner.total_connections.load(Ordering::Relaxed)
    }

    pub fn bypassed_requests(&self) -> u64 {
        self.inner.bypassed_requests.load(Ordering::Relaxed)
    }

    pub fn bytes_sent(&self) -> u64 {
        self.inner.bytes_sent.load(Ordering::Relaxed)
    }

    pub fn bytes_received(&self) -> u64 {
        self.inner.bytes_received.load(Ordering::Relaxed)
    }
}
