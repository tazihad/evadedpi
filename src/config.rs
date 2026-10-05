// -----------------------------------------------------------------------------
// File Name:      src/config.rs
// Description:    Configuration management, presets, and TOML serialization.
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
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;

use crate::core::http::HttpEvasionOptions;
use crate::core::strategy::{EvasionStrategy, SplitMode, SplitOffset};
use crate::dns::DohProvider;
use crate::rules::EvasionScope;

/// Main application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub server: ServerOptions,
    #[serde(default)]
    pub evasion: EvasionOptions,
    #[serde(default)]
    pub dns: DnsOptions,
    #[serde(default)]
    pub rules: RulesOptions,
    #[serde(default)]
    pub ui: UiOptions,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerOptions::default(),
            evasion: EvasionOptions::default(),
            dns: DnsOptions::default(),
            rules: RulesOptions::default(),
            ui: UiOptions::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerOptions {
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    #[serde(default)]
    pub system_proxy: bool,
}

fn default_bind() -> String {
    "127.0.0.1".to_string()
}
fn default_port() -> u16 {
    1080
}
fn default_idle_timeout() -> u64 {
    120
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            port: default_port(),
            idle_timeout_secs: default_idle_timeout(),
            system_proxy: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionOptions {
    #[serde(default = "default_preset")]
    pub preset: String,
    #[serde(default = "default_split_mode")]
    pub split_mode: String,
    #[serde(default = "default_chunk_size")]
    pub chunk_size: usize,
    #[serde(default)]
    pub custom_offsets: Vec<usize>,
    #[serde(default)]
    pub split_offsets: Vec<String>,
    #[serde(default)]
    pub tlsrec_offset: Option<String>,
    #[serde(default = "default_delay_ms")]
    pub delay_ms: u64,
    #[serde(default)]
    pub disorder: bool,
    #[serde(default)]
    pub tls_record_split: bool,
    #[serde(default)]
    pub enable_fake: bool,
    #[serde(default = "default_fake_sni")]
    pub fake_sni: String,
    #[serde(default = "default_fake_ttl")]
    pub fake_ttl: u32,
    #[serde(default)]
    pub enable_oob: bool,
    #[serde(default = "default_true")]
    pub block_quic: bool,
    #[serde(default)]
    pub mix_sni: bool,
    #[serde(default = "default_true")]
    pub mix_host: bool,
    #[serde(default = "default_true")]
    pub host_space_trim: bool,
    #[serde(default)]
    pub extra_method_space: bool,
    #[serde(default)]
    pub newline_before_host: bool,
}

fn default_preset() -> String {
    "general".to_string()
}
fn default_split_mode() -> String {
    "sni".to_string()
}
fn default_chunk_size() -> usize {
    40
}
fn default_delay_ms() -> u64 {
    2
}
fn default_fake_sni() -> String {
    "www.microsoft.com".to_string()
}
fn default_fake_ttl() -> u32 {
    4
}
fn default_true() -> bool {
    true
}

impl Default for EvasionOptions {
    fn default() -> Self {
        Self {
            preset: default_preset(),
            split_mode: default_split_mode(),
            chunk_size: default_chunk_size(),
            custom_offsets: Vec::new(),
            split_offsets: Vec::new(),
            tlsrec_offset: None,
            delay_ms: default_delay_ms(),
            disorder: false,
            tls_record_split: false,
            enable_fake: false,
            fake_sni: default_fake_sni(),
            fake_ttl: default_fake_ttl(),
            enable_oob: false,
            block_quic: true,
            mix_sni: false,
            mix_host: true,
            host_space_trim: true,
            extra_method_space: false,
            newline_before_host: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsOptions {
    #[serde(default = "default_true")]
    pub enable_doh: bool,
    #[serde(default = "default_doh_provider")]
    pub doh_provider: String,
    #[serde(default = "default_true")]
    pub prefer_ipv4: bool,
}

fn default_doh_provider() -> String {
    "cloudflare".to_string()
}

impl Default for DnsOptions {
    fn default() -> Self {
        Self {
            enable_doh: true,
            doh_provider: default_doh_provider(),
            prefer_ipv4: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesOptions {
    pub rules_file: Option<String>,
    #[serde(default = "default_scope")]
    pub scope: String,
}

fn default_scope() -> String {
    "all".to_string()
}

impl Default for RulesOptions {
    fn default() -> Self {
        Self {
            rules_file: None,
            scope: default_scope(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UiOptions {
    pub stats_interval: Option<u64>,
}

impl AppConfig {
    /// Load configuration from a TOML file.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: AppConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// Resolve socket address for binding.
    pub fn socket_addr(&self) -> Result<SocketAddr> {
        let addr_str = format!("{}:{}", self.server.bind, self.server.port);
        addr_str
            .parse()
            .map_err(|e| anyhow!("Invalid bind address '{}': {}", addr_str, e))
    }

    /// Build the core EvasionStrategy from configuration settings.
    pub fn build_evasion_strategy(&self) -> EvasionStrategy {
        // First, check if a preset was selected and apply its baseline
        let mut strat = match self.evasion.preset.to_ascii_lowercase().as_str() {
            "first-byte" => EvasionStrategy {
                split_mode: SplitMode::FirstByte,
                delay_ms: 2,
                ..Default::default()
            },
            "russia" => EvasionStrategy {
                split_mode: SplitMode::Sni,
                enable_fake: true,
                fake_sni: "www.microsoft.com".to_string(),
                fake_ttl: 4,
                delay_ms: 4,
                block_quic: true,
                ..Default::default()
            },
            "iran" => EvasionStrategy {
                split_mode: SplitMode::FirstByte,
                tls_record_split: true,
                delay_ms: 5,
                block_quic: true,
                ..Default::default()
            },
            "china" => EvasionStrategy {
                split_mode: SplitMode::Chunk,
                chunk_size: 20,
                enable_fake: true,
                fake_sni: "cloudflare.com".to_string(),
                fake_ttl: 5,
                delay_ms: 3,
                ..Default::default()
            },
            "turkey" => EvasionStrategy {
                split_mode: SplitMode::FirstByte,
                delay_ms: 2,
                http_evasion: HttpEvasionOptions {
                    mix_host: true,
                    host_space_trim: true,
                    extra_method_space: true,
                    newline_before_host: false,
                },
                ..Default::default()
            },
            "discord-youtube" | "youtube-discord" => EvasionStrategy {
                split_mode: SplitMode::MultiSplit,
                delay_ms: 2,
                mix_sni: true,
                enable_fake: true,
                fake_sni: "www.google.com".to_string(),
                fake_ttl: 4,
                block_quic: true,
                ..Default::default()
            },
            "extreme" => EvasionStrategy {
                split_mode: SplitMode::Sni,
                tls_record_split: true,
                disorder: true,
                enable_fake: true,
                fake_sni: "www.microsoft.com".to_string(),
                fake_ttl: 4,
                delay_ms: 4,
                block_quic: true,
                ..Default::default()
            },
            _ => EvasionStrategy::default(), // "general"
        };

        // If explicit split mode was passed (other than default "sni"), override preset
        if self.evasion.split_mode != "sni" || self.evasion.preset == "general" {
            strat.split_mode = match self.evasion.split_mode.to_ascii_lowercase().as_str() {
                "sni" => SplitMode::Sni,
                "mid-sni" | "midsni" => SplitMode::MidSni,
                "multisplit" | "multi-split" => SplitMode::MultiSplit,
                "first-byte" => SplitMode::FirstByte,
                "chunk" => SplitMode::Chunk,
                "random" => SplitMode::Random,
                "custom" => SplitMode::Custom,
                "none" => SplitMode::None,
                _ => SplitMode::Sni,
            };
        }

        // Apply fine-grained overrides
        strat.chunk_size = self.evasion.chunk_size;
        strat.custom_offsets = self.evasion.custom_offsets.clone();

        for off_str in &self.evasion.split_offsets {
            if let Ok(off) = SplitOffset::parse(off_str) {
                strat.dynamic_offsets.push(off);
            }
        }
        if !strat.dynamic_offsets.is_empty() && (self.evasion.split_mode == "sni" || self.evasion.split_mode == "custom") {
            strat.split_mode = SplitMode::Custom;
        }

        if let Some(ref rec_str) = self.evasion.tlsrec_offset {
            if let Ok(off) = SplitOffset::parse(rec_str) {
                strat.tlsrec_offset = Some(off);
                strat.tls_record_split = true;
            }
        }

        strat.delay_ms = self.evasion.delay_ms;
        if self.evasion.disorder {
            strat.disorder = true;
        }
        if self.evasion.tls_record_split {
            strat.tls_record_split = true;
        }
        if self.evasion.enable_fake {
            strat.enable_fake = true;
            strat.fake_sni = self.evasion.fake_sni.clone();
            strat.fake_ttl = self.evasion.fake_ttl;
        }
        if self.evasion.enable_oob {
            strat.enable_oob = true;
        }
        strat.block_quic = self.evasion.block_quic;
        if self.evasion.mix_sni {
            strat.mix_sni = true;
        }

        strat.http_evasion = HttpEvasionOptions {
            mix_host: self.evasion.mix_host,
            host_space_trim: self.evasion.host_space_trim,
            extra_method_space: self.evasion.extra_method_space,
            newline_before_host: self.evasion.newline_before_host,
        };

        strat
    }

    /// Resolve configured DoH provider.
    pub fn doh_provider(&self) -> Option<DohProvider> {
        if self.dns.enable_doh {
            Some(DohProvider::from_str_name(&self.dns.doh_provider))
        } else {
            None
        }
    }

    /// Resolve rule scope.
    pub fn rule_scope(&self) -> EvasionScope {
        match self.rules.scope.to_ascii_lowercase().as_str() {
            "allowlist" | "allow" | "only" => EvasionScope::AllowList,
            "blocklist" | "block" | "exclude" => EvasionScope::BlockList,
            _ => EvasionScope::All,
        }
    }

    /// Generate a well-commented TOML configuration string template.
    pub fn generate_template() -> String {
        r#"# EvadeDPI Configuration File (evadedpi.toml)
# Complete DPI Circumvention Suite

[server]
# IP address to listen on ("127.0.0.1" for local, "0.0.0.0" for LAN access)
bind = "127.0.0.1"
# Port for the unified SOCKS5 and HTTP/HTTPS proxy listener
port = 1080
# Connection idle timeout in seconds (reaps dead/abandoned tunnels)
idle_timeout_secs = 120
# Automatically configure OS system proxy while running and restore on exit
system_proxy = false

[evasion]
# Pre-configured profile: "general", "first-byte", "russia", "iran", "china", "turkey", "discord-youtube", "extreme"
preset = "general"

# Splitting mode: "sni", "mid-sni", "multisplit", "first-byte", "chunk", "random", "custom", "none"
split_mode = "sni"

# Randomize SNI hostname casing (RFC 6066 case-insensitive) to bypass case-sensitive DPI middleboxes
mix_sni = false

# Chunk size in bytes when split_mode = "chunk"
chunk_size = 40

# Custom byte split offsets when split_mode = "custom" (e.g. [1, 5, 20])
custom_offsets = []

# Dynamic SNI-relative split offsets (takes precedence over custom_offsets)
# Supports "N+s" (relative to SNI start), "N+se" (relative to SNI end), "+m" (mid-sni), and absolute numbers
# e.g., ["1+s", "3+s", "6+s", "9+s", "12+s", "15+s", "20+s", "30+s"]
split_offsets = []

# Delay between sending TCP segments in milliseconds (prevents packet coalescing)
delay_ms = 2

# Reverse transmission order of segments (disorder)
disorder = false

# Fragment TLS ClientHello across multiple TLS record layers (RFC compliant)
tls_record_split = false

# Split position for TLS record layer (e.g. "-5+se", "1+s", "+m", "sni", "mid-sni", "first-byte", "2")
# tlsrec_offset = "-5+se"

# Inject decoy packet with low TTL before real packet
enable_fake = false
fake_sni = "www.microsoft.com"
fake_ttl = 4

# Send 1 byte of Out-Of-Band (TCP Urgent) data
enable_oob = false

# Block QUIC (UDP port 443) so browsers fallback to TCP HTTPS
block_quic = true

# HTTP evasion mutations
mix_host = true
host_space_trim = true
extra_method_space = false
newline_before_host = false

[dns]
# Enable DNS-over-HTTPS to prevent ISP DNS hijacking/poisoning
enable_doh = true

# DoH provider: "cloudflare", "google", "quad9", "adguard", or full https URL
doh_provider = "cloudflare"

# Prefer IPv4 addresses over IPv6
prefer_ipv4 = true

[rules]
# Path to a text file containing domain rules (one per line)
# rules_file = "/etc/evadedpi/domains.txt"

# Rule scope: "all", "allowlist" (only listed), "blocklist" (exclude listed)
scope = "all"

[ui]
# Periodic status reporting interval in seconds (optional)
# stats_interval = 30
"#
        .to_string()
    }
}
