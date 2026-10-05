// EvadeDPI: Modern Deep Packet Inspection Circumvention Engine
// Unified DNS Resolver with Cache, DoH, and System Fallback

use anyhow::Result;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use tracing::{debug, warn};

use super::cache::DnsCache;
use super::doh::{DohClient, DohProvider};

/// Unified DNS resolution engine.
#[derive(Debug, Clone)]
pub struct Resolver {
    cache: DnsCache,
    doh_client: Option<DohClient>,
    prefer_ipv4: bool,
}

impl Resolver {
    pub fn new(doh_provider: Option<DohProvider>, prefer_ipv4: bool) -> Self {
        let doh_client = doh_provider.map(DohClient::new);
        Self {
            cache: DnsCache::new(),
            doh_client,
            prefer_ipv4,
        }
    }

    /// Resolve a hostname (or IP string) with target port into a SocketAddr.
    pub async fn resolve_target(&self, host: &str, port: u16) -> Result<SocketAddr> {
        // 1. Check if host is already an IP address
        if let Ok(ip) = IpAddr::from_str(host) {
            return Ok(SocketAddr::new(ip, port));
        }

        // 2. Check DNS cache
        if let Some(cached_ips) = self.cache.get(host).await {
            if let Some(ip) = self.select_best_ip(&cached_ips) {
                return Ok(SocketAddr::new(ip, port));
            }
        }

        // 3. Try DNS-over-HTTPS (DoH) if configured
        if let Some(ref doh) = self.doh_client {
            match doh.resolve(host).await {
                Ok((ips, ttl)) => {
                    self.cache.insert(host, ips.clone(), ttl).await;
                    if let Some(ip) = self.select_best_ip(&ips) {
                        return Ok(SocketAddr::new(ip, port));
                    }
                }
                Err(err) => {
                    warn!(
                        "DoH resolution failed for '{}': {}. Falling back to system DNS.",
                        host, err
                    );
                }
            }
        }

        // 4. Fallback to system DNS resolver
        let host_port = format!("{}:{}", host, port);
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&host_port).await?.collect();
        if let Some(addr) = addrs.first() {
            debug!("Resolved '{}' via system DNS to {}", host, addr.ip());
            Ok(*addr)
        } else {
            Err(anyhow::anyhow!("Failed to resolve host: {}", host))
        }
    }

    fn select_best_ip(&self, ips: &[IpAddr]) -> Option<IpAddr> {
        if ips.is_empty() {
            return None;
        }

        if self.prefer_ipv4 {
            // Find first IPv4
            if let Some(v4) = ips.iter().find(|ip| ip.is_ipv4()) {
                return Some(*v4);
            }
        }

        // Default: return first address
        Some(ips[0])
    }
}
