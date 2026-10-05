// -----------------------------------------------------------------------------
// File Name:      src/diagnostic/test_site.rs
// Description:    Diagnostic probe and censorship benchmark engine (`evadedpi test <domain>`).
// Author:         @tazihad
// Website:        https://zihad.com.bd
// License:        MIT License
// -----------------------------------------------------------------------------

// MIT License
//
// Copyright (c) 2024-2026 @tazihad
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
use colored::*;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::core::fake::generate_fake_client_hello;
use crate::core::socket::configure_evasion_socket;
use crate::core::strategy::{EvasionStrategy, SplitMode};
use crate::dns::{DohClient, DohProvider};

/// Normalizes an arbitrary user target input into a clean hostname.
///
/// Strips URL schemes (`https://`, `http://`), ports, path prefixes, query strings,
/// fragments, and trailing slashes/dots so probe operations can resolve DNS and
/// construct valid TLS ClientHello SNI headers.
pub fn normalize_target_domain(input: &str) -> Result<String> {
    let s = input.trim();
    if s.is_empty() {
        return Err(anyhow!("Target domain or URL cannot be empty"));
    }

    // Strip scheme if present (e.g. "https://", "http://", "ftp://")
    let without_scheme = if let Some(idx) = s.find("://") {
        &s[idx + 3..]
    } else {
        s
    };

    // Strip path, query string, or fragment (e.g. "/path?arg=1#hash")
    let host_part = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme);

    // Strip userinfo if present (e.g. "user:pass@host")
    let host_part = if let Some(idx) = host_part.rfind('@') {
        &host_part[idx + 1..]
    } else {
        host_part
    };

    // Strip port (handling bracketed IPv6 like "[::1]:443")
    let domain = if host_part.starts_with('[') {
        if let Some(closing) = host_part.find(']') {
            &host_part[1..closing]
        } else {
            host_part
        }
    } else if let Some(colon) = host_part.rfind(':') {
        &host_part[..colon]
    } else {
        host_part
    };

    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty() {
        return Err(anyhow!("Invalid domain extracted from '{}'", input));
    }

    Ok(domain.to_ascii_lowercase())
}

/// Deduplicates IP addresses and sorts IPv4 addresses before IPv6 addresses.
pub fn deduplicate_and_sort_ips(raw_ips: Vec<String>) -> Vec<String> {
    let mut ipv4s = Vec::new();
    let mut ipv6s = Vec::new();
    for ip in raw_ips {
        let clean = ip.trim().to_string();
        if clean.is_empty() {
            continue;
        }
        if clean.parse::<std::net::Ipv4Addr>().is_ok() {
            if !ipv4s.contains(&clean) {
                ipv4s.push(clean);
            }
        } else if clean.parse::<std::net::Ipv6Addr>().is_ok() {
            if !ipv6s.contains(&clean) {
                ipv6s.push(clean);
            }
        } else if !ipv4s.contains(&clean) && !ipv6s.contains(&clean) {
            ipv4s.push(clean);
        }
    }
    ipv4s.extend(ipv6s);
    ipv4s
}

/// Formats a list of IP addresses into a clean, concise, human-readable string.
///
/// Shows up to 3 addresses cleanly joined, summarizing any remainder (e.g. `1.1.1.1, 1.0.0.1 (+10 more)`)
/// to prevent terminal line clutter when resolving domains with dozens of CDN Anycast IPs.
pub fn format_ip_list(ips: &[String]) -> String {
    if ips.is_empty() {
        return "None".to_string();
    }
    if ips.len() <= 3 {
        ips.join(", ")
    } else {
        format!("{} (+{} more)", ips[..3].join(", "), ips.len() - 3)
    }
}

pub struct DiagnosticReport {
    pub target_domain: String,
    pub system_ips: Vec<String>,
    pub doh_ips: Vec<String>,
    pub dns_tampered: bool,
    pub direct_result: ProbeResult,
    pub strategy_results: Vec<(String, ProbeResult)>,
    pub recommended_command: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ProbeResult {
    Success { latency_ms: u128 },
    Reset,
    Timeout,
    ConnectionRefused,
    Error(String),
}

impl std::fmt::Display for ProbeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeResult::Success { latency_ms } => {
                write!(f, "{} ({}ms)", "PASS".green().bold(), latency_ms)
            }
            ProbeResult::Reset => write!(f, "{}", "RESET (DPI RST)".red().bold()),
            ProbeResult::Timeout => write!(f, "{}", "TIMEOUT (DPI Drop)".yellow().bold()),
            ProbeResult::ConnectionRefused => {
                write!(f, "{}", "REFUSED (Connection Refused)".red().bold())
            }
            ProbeResult::Error(e) => write!(f, "{}: {}", "FAIL".red(), e),
        }
    }
}

pub async fn run_diagnostic(target: &str) -> Result<DiagnosticReport> {
    let domain = match normalize_target_domain(target) {
        Ok(d) => d,
        Err(e) => {
            println!("{}", "==========================================================".cyan());
            println!("{} Invalid target: {}", "[!]".bold().red(), e);
            println!("{}", "==========================================================".cyan());
            return Err(e);
        }
    };

    println!("{}", "==========================================================".cyan());
    println!(
        "{} Running EvadeDPI Diagnostic Probe on '{}'",
        "[*]".bold().cyan(),
        domain.bold().yellow()
    );
    println!("{}", "==========================================================".cyan());

    // 1. DNS Resolution Probe
    print!("[1/4] Checking DNS Resolution... ");
    let host_port = format!("{}:443", domain);
    let raw_system_ips: Vec<String> = tokio::net::lookup_host(&host_port)
        .await
        .map(|iter| iter.map(|addr| addr.ip().to_string()).collect())
        .unwrap_or_default();
    let system_ips = deduplicate_and_sort_ips(raw_system_ips);

    let doh = DohClient::new(DohProvider::Cloudflare);
    let raw_doh_ips: Vec<String> = match doh.resolve(&domain).await {
        Ok((ips, _)) => ips.into_iter().map(|ip| ip.to_string()).collect(),
        Err(_) => Vec::new(),
    };
    let doh_ips = deduplicate_and_sort_ips(raw_doh_ips);

    if system_ips.is_empty() && doh_ips.is_empty() {
        println!("{}", "FAILED (NXDOMAIN / DNS Unreachable)".bold().red());
        println!("{}", "==========================================================".cyan());
        println!(
            "{} Could not resolve any IP address for '{}' via System DNS or DoH.",
            "[!]".bold().red(),
            domain
        );
        println!("    Please verify the domain name or check your internet connection.");
        println!("{}", "==========================================================".cyan());
        return Ok(DiagnosticReport {
            target_domain: domain,
            system_ips: vec![],
            doh_ips: vec![],
            dns_tampered: false,
            direct_result: ProbeResult::Error("DNS resolution failed".to_string()),
            strategy_results: vec![],
            recommended_command: None,
        });
    }

    let dns_tampered = if !system_ips.is_empty() && !doh_ips.is_empty() {
        // Check if system returns loopback, zero, or completely divergent IP
        system_ips.iter().any(|ip| ip == "127.0.0.1" || ip == "0.0.0.0")
            || (system_ips.len() == 1 && !doh_ips.contains(&system_ips[0]))
    } else {
        false
    };

    if dns_tampered {
        println!("{}", "POISONED / HIJACKED!".bold().red());
    } else {
        println!("{}", "OK".bold().green());
    }

    println!("      System DNS: {}", format_ip_list(&system_ips).cyan());
    println!("      DoH (Cloudflare): {}", format_ip_list(&doh_ips).cyan());

    // Pick candidate IPs, prioritizing IPv4 (since many networks lack functional IPv6)
    // and prefer DoH if system DNS is tampered
    let mut candidate_ips: Vec<String> = Vec::new();
    let preferred_list = if dns_tampered {
        doh_ips.iter().chain(system_ips.iter())
    } else {
        doh_ips.iter().chain(system_ips.iter())
    };

    for ip in preferred_list {
        if !candidate_ips.contains(ip) {
            candidate_ips.push(ip.clone());
        }
    }

    let first_ip = candidate_ips.first().unwrap();
    let target_addr: SocketAddr = format!("{}:443", first_ip).parse()?;

    // 2. Direct Connection (Baseline without evasion)
    print!("[2/4] Testing Direct TLS Handshake (No Evasion)... ");
    io::stdout().flush().unwrap();
    let direct_result = probe_tls_connection(&domain, target_addr, None).await;
    println!("{}", direct_result);

    // 3. Evasion Strategies Test - ALWAYS TEST ALL COMBOS
    println!("[3/4] Benchmarking Circumvention Strategies against Middlebox:");

    struct StrategyCandidate {
        name: &'static str,
        preset: Option<&'static str>,
        cli_args: &'static str,
        strategy: EvasionStrategy,
    }

    let candidates = vec![
        StrategyCandidate {
            name: "SNI Segmentation (Recommended)",
            preset: Some("general"),
            cli_args: "--preset general",
            strategy: EvasionStrategy {
                split_mode: SplitMode::Sni,
                delay_ms: 2,
                ..Default::default()
            },
        },
        StrategyCandidate {
            name: "First-Byte Split (1 + remainder)",
            preset: Some("first-byte"),
            cli_args: "--preset first-byte",
            strategy: EvasionStrategy {
                split_mode: SplitMode::FirstByte,
                delay_ms: 2,
                ..Default::default()
            },
        },
        StrategyCandidate {
            name: "Mid-SNI Split (Split inside SNI)",
            preset: None,
            cli_args: "-s mid-sni",
            strategy: EvasionStrategy {
                split_mode: SplitMode::MidSni,
                delay_ms: 2,
                ..Default::default()
            },
        },
        StrategyCandidate {
            name: "MultiSplit (3-chunk SNI split)",
            preset: None,
            cli_args: "-s multisplit",
            strategy: EvasionStrategy {
                split_mode: SplitMode::MultiSplit,
                delay_ms: 2,
                ..Default::default()
            },
        },
        StrategyCandidate {
            name: "TLS Record Layer Split",
            preset: None,
            cli_args: "--tlsrec",
            strategy: EvasionStrategy {
                tls_record_split: true,
                delay_ms: 2,
                ..Default::default()
            },
        },
        StrategyCandidate {
            name: "Mid-SNI + TLS Record Split",
            preset: None,
            cli_args: "-s mid-sni --tlsrec",
            strategy: EvasionStrategy {
                split_mode: SplitMode::MidSni,
                tls_record_split: true,
                delay_ms: 2,
                ..Default::default()
            },
        },
        StrategyCandidate {
            name: "Fake Decoy SNI (Low TTL)",
            preset: None,
            cli_args: "--fake --fake-ttl 4",
            strategy: EvasionStrategy {
                enable_fake: true,
                fake_sni: "www.microsoft.com".to_string(),
                fake_ttl: 4,
                split_mode: SplitMode::Sni,
                delay_ms: 2,
                ..Default::default()
            },
        },
        StrategyCandidate {
            name: "Fake Decoy + Mid-SNI Split",
            preset: None,
            cli_args: "--fake --fake-ttl 4 -s mid-sni",
            strategy: EvasionStrategy {
                enable_fake: true,
                fake_sni: "www.microsoft.com".to_string(),
                fake_ttl: 4,
                split_mode: SplitMode::MidSni,
                delay_ms: 2,
                ..Default::default()
            },
        },
        StrategyCandidate {
            name: "Mixed SNI Casing + MultiSplit",
            preset: None,
            cli_args: "-s multisplit --mix-sni",
            strategy: EvasionStrategy {
                split_mode: SplitMode::MultiSplit,
                mix_sni: true,
                delay_ms: 2,
                ..Default::default()
            },
        },
        StrategyCandidate {
            name: "Fake Decoy + Mixed SNI + MultiSplit",
            preset: Some("discord-youtube"),
            cli_args: "--preset discord-youtube",
            strategy: EvasionStrategy {
                split_mode: SplitMode::MultiSplit,
                mix_sni: true,
                enable_fake: true,
                fake_sni: "www.google.com".to_string(),
                fake_ttl: 4,
                delay_ms: 2,
                ..Default::default()
            },
        },
        StrategyCandidate {
            name: "Fake Decoy + Mid-SNI + TLS Record",
            preset: None,
            cli_args: "--fake --fake-ttl 4 -s mid-sni --tlsrec",
            strategy: EvasionStrategy {
                enable_fake: true,
                fake_sni: "www.microsoft.com".to_string(),
                fake_ttl: 4,
                split_mode: SplitMode::MidSni,
                tls_record_split: true,
                delay_ms: 2,
                ..Default::default()
            },
        },
        StrategyCandidate {
            name: "First-Byte + TLS Record (Iran profile)",
            preset: Some("iran"),
            cli_args: "--preset iran",
            strategy: EvasionStrategy {
                split_mode: SplitMode::FirstByte,
                tls_record_split: true,
                delay_ms: 5,
                ..Default::default()
            },
        },
        StrategyCandidate {
            name: "Small Chunks (20-byte chunks)",
            preset: None,
            cli_args: "--split-mode chunk --chunk-size 20",
            strategy: EvasionStrategy {
                split_mode: SplitMode::Chunk,
                chunk_size: 20,
                delay_ms: 2,
                ..Default::default()
            },
        },
        StrategyCandidate {
            name: "Disorder (Reverse Segment Order)",
            preset: None,
            cli_args: "-s sni --disorder",
            strategy: EvasionStrategy {
                split_mode: SplitMode::Sni,
                disorder: true,
                delay_ms: 2,
                ..Default::default()
            },
        },
        StrategyCandidate {
            name: "Extreme Desync (All Techniques)",
            preset: Some("extreme"),
            cli_args: "--preset extreme",
            strategy: EvasionStrategy {
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
        },
    ];

    // Spawn all candidate probes concurrently with a small stagger to prevent SYN burst filtering
    let mut tasks = Vec::new();
    for candidate in &candidates {
        let domain_clone = domain.clone();
        let strat_clone = candidate.strategy.clone();
        tasks.push(tokio::spawn(async move {
            probe_tls_connection(&domain_clone, target_addr, Some(strat_clone)).await
        }));
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let mut strategy_results = Vec::new();
    let mut successes: Vec<(&StrategyCandidate, u128)> = Vec::new();

    for (i, task) in tasks.into_iter().enumerate() {
        let candidate = &candidates[i];
        print!("      Testing {:<38} ... ", candidate.name);
        io::stdout().flush().unwrap();
        let res = task
            .await
            .unwrap_or_else(|_| ProbeResult::Error("Benchmark probe task panicked".to_string()));
        println!("{}", res);
        if let ProbeResult::Success { latency_ms } = res {
            successes.push((candidate, latency_ms));
        }
        strategy_results.push((candidate.name.to_string(), res));
    }

    println!("\n[4/4] Summary & Recommendations:");
    let recommended_command = if !successes.is_empty() {
        // Sort successes by latency
        successes.sort_by_key(|s| s.1);

        let direct_blocked = matches!(
            direct_result,
            ProbeResult::Reset
                | ProbeResult::Timeout
                | ProbeResult::ConnectionRefused
                | ProbeResult::Error(_)
        );

        // If direct is blocked, prefer the fastest evasion strategy that succeeded.
        // If a named preset (e.g. general, first-byte, discord-youtube, iran) is within 10ms of fastest, prefer it for simplicity.
        let fastest_latency = successes[0].1;
        let best_candidate = successes
            .iter()
            .find(|(c, lat)| c.preset.is_some() && (*lat <= fastest_latency + 10))
            .map(|(c, _)| *c)
            .unwrap_or(successes[0].0);

        let best_latency = successes
            .iter()
            .find(|(c, _)| c.name == best_candidate.name)
            .map(|(_, lat)| *lat)
            .unwrap_or(fastest_latency);

        println!("{}", "==========================================================".cyan());
        if direct_blocked {
            println!(
                "{} {}",
                "[!]".bold().red(),
                format!("DPI Censorship Confirmed on '{}'!", domain).bold().red()
            );
            println!(
                "    Direct connection was blocked/reset by ISP middlebox. Circumvention is required."
            );
        } else {
            println!(
                "{} {}",
                "[*]".bold().green(),
                format!("'{}' is reachable directly; DPI bypass also works.", domain).bold().green()
            );
            println!(
                "    No active censorship detected (direct: {}). EvadeDPI is optional here.",
                direct_result
            );
        }

        println!(
            "    Recommended strategy: {} ({}ms, fastest reliable option)",
            best_candidate.name.bold().green(),
            best_latency.to_string().bold().yellow()
        );
        println!("{}", "----------------------------------------------------------".cyan());
        println!(
            "{}",
            format!(">>> RECOMMENDED COMMAND TO UNBLOCK '{}':", domain.to_uppercase())
                .bold()
                .yellow()
        );
        println!();
        println!(
            "    {}",
            format!("evadedpi {}", best_candidate.cli_args)
                .bold()
                .green()
        );
        println!();
        println!("  Run options:");
        println!(
            "    • Automatically configure OS system proxy while running (-S / --system-proxy):"
        );
        println!(
            "      {}",
            format!("evadedpi -S {}", best_candidate.cli_args).cyan()
        );
        println!();
        println!(
            "    • Apply circumvention ONLY to '{}' (other traffic direct):",
            domain
        );
        println!(
            "      {}",
            format!(
                "evadedpi {} --rules \"{},*.{}\" --scope allowlist",
                best_candidate.cli_args, domain, domain
            )
            .cyan()
        );

        if dns_tampered {
            println!();
            println!(
                "  {} DNS poisoning detected on this network. EvadeDPI's built-in DoH",
                "Note:".bold().yellow()
            );
            println!("        resolves untampered IP addresses for this site automatically.");
        }

        println!("{}", "==========================================================".cyan());

        Some(format!("evadedpi {}", best_candidate.cli_args))
    } else {
        println!("{}", "==========================================================".cyan());
        println!(
            "{}",
            format!(
                "  ==> All tested circumvention strategies failed against '{}'.",
                domain
            )
            .bold()
            .red()
        );
        println!(
            "      Target IP {}:443 did not respond to any attempted evasion method.",
            first_ip
        );
        println!(
            "      The destination IP appears to be dropped/blackholed by your ISP (IP-level blocking)"
        );
        println!(
            "      or the server is currently unreachable. EvadeDPI circumvents Layer 7 DPI (SNI/HTTP inspection),"
        );
        println!(
            "      but cannot bypass Layer 3 IP routing null-routes. A VPN or encrypted tunnel is required."
        );
        println!("{}", "==========================================================".cyan());
        None
    };

    Ok(DiagnosticReport {
        target_domain: domain,
        system_ips,
        doh_ips,
        dns_tampered,
        direct_result,
        strategy_results,
        recommended_command,
    })
}

async fn probe_tls_connection(
    domain: &str,
    target_addr: SocketAddr,
    strategy: Option<EvasionStrategy>,
) -> ProbeResult {
    let connect_timeout = Duration::from_millis(2500);
    let handshake_timeout = Duration::from_millis(3000);

    // Step 1: Establish TCP connection
    let mut stream = match timeout(connect_timeout, TcpStream::connect(target_addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                return ProbeResult::ConnectionRefused;
            }
            if e.kind() == std::io::ErrorKind::ConnectionReset {
                return ProbeResult::Reset;
            }
            return ProbeResult::Error(e.to_string());
        }
        Err(_) => return ProbeResult::Timeout,
    };

    if let Err(e) = configure_evasion_socket(&stream) {
        return ProbeResult::Error(e.to_string());
    }

    // Step 2: Desynchronize and send ClientHello
    let handshake_future = async {
        let start = Instant::now();
        let client_hello = generate_fake_client_hello(domain);

        if let Some(strat) = strategy {
            if let Err(e) = strat.desync_and_send(&mut stream, &client_hello).await {
                return ProbeResult::Error(e.to_string());
            }
        } else {
            // Direct write
            if let Err(e) = stream.write_all(&client_hello).await {
                return ProbeResult::Error(e.to_string());
            }
            let _ = stream.flush().await;
        }

        // Step 3: Expect ServerHello from upstream
        let mut resp = [0u8; 1024];
        match stream.read(&mut resp).await {
            Ok(n) if n > 0 => {
                if resp[0] == 0x16 || resp[0] == 0x15 {
                    ProbeResult::Success {
                        latency_ms: start.elapsed().as_millis(),
                    }
                } else if resp.starts_with(b"HTTP/1.") {
                    ProbeResult::Error("DPI Blockpage / HTTP redirect injected".to_string())
                } else {
                    ProbeResult::Error(format!("Unexpected byte 0x{:02x} received", resp[0]))
                }
            }
            Ok(_) => ProbeResult::Reset,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::ConnectionReset {
                    ProbeResult::Reset
                } else {
                    ProbeResult::Error(e.to_string())
                }
            }
        }
    };

    match timeout(handshake_timeout, handshake_future).await {
        Ok(res) => res,
        Err(_) => ProbeResult::Timeout,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_target_domain() {
        assert_eq!(
            normalize_target_domain("https://www.example.com/").unwrap(),
            "www.example.com"
        );
        assert_eq!(
            normalize_target_domain("http://example.org:8080/path?query=1").unwrap(),
            "example.org"
        );
        assert_eq!(
            normalize_target_domain("sub.domain.co.uk").unwrap(),
            "sub.domain.co.uk"
        );
        assert_eq!(
            normalize_target_domain("https://user:pass@test.org:443/page#section").unwrap(),
            "test.org"
        );
        assert_eq!(
            normalize_target_domain("HTTPS://WWW.EXAMPLE.COM/").unwrap(),
            "www.example.com"
        );
        assert_eq!(
            normalize_target_domain("example.com.").unwrap(),
            "example.com"
        );
        assert_eq!(
            normalize_target_domain("[2001:db8::1]:443").unwrap(),
            "2001:db8::1"
        );
        assert!(normalize_target_domain("").is_err());
        assert!(normalize_target_domain("   ").is_err());
    }

    #[test]
    fn test_format_ip_list() {
        assert_eq!(format_ip_list(&[]), "None");
        assert_eq!(format_ip_list(&["192.0.2.1".to_string()]), "192.0.2.1");
        assert_eq!(
            format_ip_list(&["192.0.2.1".to_string(), "192.0.2.2".to_string()]),
            "192.0.2.1, 192.0.2.2"
        );
        let ips: Vec<String> = (1..=15).map(|i| format!("192.0.2.{}", i)).collect();
        assert_eq!(
            format_ip_list(&ips),
            "192.0.2.1, 192.0.2.2, 192.0.2.3 (+12 more)"
        );
    }

    #[test]
    fn test_deduplicate_and_sort_ips() {
        let raw = vec![
            "192.0.2.1".to_string(),
            "2001:db8::1".to_string(),
            "192.0.2.1".to_string(),
            "192.0.2.2".to_string(),
            "2001:db8::1".to_string(),
        ];
        let sorted = deduplicate_and_sort_ips(raw);
        assert_eq!(
            sorted,
            vec![
                "192.0.2.1".to_string(),
                "192.0.2.2".to_string(),
                "2001:db8::1".to_string(),
            ]
        );
    }
}
