// -----------------------------------------------------------------------------
// File Name:      src/dns/cache.rs
// Description:    Thread-safe in-memory DNS resolution cache with TTL expiration.
// Author:         @tazihad
// Website:        https://zihad.com.bd
// License:        MIT License
// -----------------------------------------------------------------------------

// MIT License
//
// Copyright (c) 2024 @tazihad
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// -----------------------------------------------------------------------------

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
