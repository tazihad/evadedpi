// EvadeDPI: Modern Deep Packet Inspection Circumvention Engine
// Thread-Safe In-Memory DNS Cache with TTL Expiration

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::trace;

#[derive(Debug, Clone)]
struct CacheEntry {
    addrs: Vec<IpAddr>,
    expires_at: Instant,
}

/// Thread-safe in-memory DNS cache.
#[derive(Debug, Clone)]
pub struct DnsCache {
    entries: Arc<RwLock<HashMap<String, CacheEntry>>>,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Look up cached IP addresses for a domain name.
    pub async fn get(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let key = domain.to_ascii_lowercase();
        let map = self.entries.read().await;

        if let Some(entry) = map.get(&key) {
            if Instant::now() < entry.expires_at {
                trace!("DNS Cache hit for '{}': {:?}", domain, entry.addrs);
                return Some(entry.addrs.clone());
            }
        }
        None
    }

    /// Insert resolved IP addresses with a specified Time-To-Live.
    pub async fn insert(&self, domain: &str, addrs: Vec<IpAddr>, ttl_secs: u64) {
        if addrs.is_empty() {
            return;
        }

        let key = domain.to_ascii_lowercase();
        let ttl = Duration::from_secs(ttl_secs.clamp(10, 86400));
        let expires_at = Instant::now() + ttl;

        let mut map = self.entries.write().await;
        map.insert(key, CacheEntry { addrs, expires_at });
    }

    /// Clear all expired entries from cache.
    pub async fn cleanup_expired(&self) {
        let now = Instant::now();
        let mut map = self.entries.write().await;
        map.retain(|_, entry| entry.expires_at > now);
    }
}
