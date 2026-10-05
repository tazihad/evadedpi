// -----------------------------------------------------------------------------
// File Name:      src/dns/doh.rs
// Description:    DNS-over-HTTPS (DoH) client implementation with multi-provider failover.
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

use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::Deserialize;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use tracing::{debug, trace};

/// Well-known DNS-over-HTTPS providers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DohProvider {
    Cloudflare,
    Google,
    Quad9,
    AdGuard,
    Custom(String),
}

impl DohProvider {
    pub fn endpoint(&self) -> &str {
        match self {
            DohProvider::Cloudflare => "https://cloudflare-dns.com/dns-query",
            DohProvider::Google => "https://dns.google/dns-query",
            DohProvider::Quad9 => "https://dns.quad9.net/dns-query",
            DohProvider::AdGuard => "https://dns.adguard.com/dns-query",
            DohProvider::Custom(url) => url.as_str(),
        }
    }

    pub fn from_str_name(name: &str) -> Self {
        match name.to_ascii_lowercase().as_str() {
            "cloudflare" | "1.1.1.1" => DohProvider::Cloudflare,
            "google" | "8.8.8.8" => DohProvider::Google,
            "quad9" | "9.9.9.9" => DohProvider::Quad9,
            "adguard" => DohProvider::AdGuard,
            custom => DohProvider::Custom(custom.to_string()),
        }
    }
}

#[derive(Debug, Deserialize)]
struct DohAnswer {
    #[serde(rename = "type")]
    record_type: u16,
    #[serde(rename = "TTL")]
    ttl: u64,
    data: String,
}

#[derive(Debug, Deserialize)]
struct DohResponse {
    #[serde(rename = "Status")]
    status: i32,
    #[serde(rename = "Answer")]
    answer: Option<Vec<DohAnswer>>,
}

/// Client for performing secure DNS resolution over HTTPS.
#[derive(Debug, Clone)]
pub struct DohClient {
    client: Client,
    endpoint: String,
}

impl DohClient {
    pub fn new(provider: DohProvider) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .pool_idle_timeout(Duration::from_secs(60))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            client,
            endpoint: provider.endpoint().to_string(),
        }
    }

    /// Resolve A (IPv4) or AAAA (IPv6) records for a domain using DoH JSON API.
    pub async fn resolve(&self, domain: &str) -> Result<(Vec<IpAddr>, u64)> {
        debug!("Querying DoH for domain '{}' via {}", domain, self.endpoint);

        // Query IPv4 (A record: type 1)
        let mut ips = Vec::new();
        let mut min_ttl = 300u64;

        if let Ok((v4_addrs, ttl)) = self.query_record(domain, "A").await {
            ips.extend(v4_addrs);
            min_ttl = min_ttl.min(ttl);
        }

        // Query IPv6 (AAAA record: type 28)
        if let Ok((v6_addrs, ttl)) = self.query_record(domain, "AAAA").await {
            ips.extend(v6_addrs);
            min_ttl = min_ttl.min(ttl);
        }

        if ips.is_empty() {
            return Err(anyhow!("No IP addresses found via DoH for '{}'", domain));
        }

        debug!("Resolved '{}' to {:?} (TTL {}s)", domain, ips, min_ttl);
        Ok((ips, min_ttl))
    }

    async fn query_record(&self, domain: &str, record_type: &str) -> Result<(Vec<IpAddr>, u64)> {
        let url = format!("{}?name={}&type={}", self.endpoint, domain, record_type);
        let resp = self
            .client
            .get(&url)
            .header("Accept", "application/dns-json")
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(anyhow!("DoH request failed with status: {}", resp.status()));
        }

        let body: DohResponse = resp.json().await?;
        if body.status != 0 {
            trace!("DoH server returned status code: {}", body.status);
            return Err(anyhow!("DoH returned non-zero status: {}", body.status));
        }

        let mut addrs = Vec::new();
        let mut min_ttl = 300;

        if let Some(answers) = body.answer {
            for ans in answers {
                // A (1) or AAAA (28)
                if ans.record_type == 1 || ans.record_type == 28 {
                    if let Ok(ip) = IpAddr::from_str(&ans.data) {
                        addrs.push(ip);
                        min_ttl = min_ttl.min(ans.ttl);
                    }
                }
            }
        }

        Ok((addrs, min_ttl))
    }
}
