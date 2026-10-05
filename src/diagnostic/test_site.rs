// -----------------------------------------------------------------------------
// File Name:      src/diagnostic/test_site.rs
// Description:    Diagnostic probe and censorship benchmark engine (`evadedpi test <domain>`).
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

use anyhow::Result;
use colored::*;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::core::fake::generate_fake_client_hello;
use crate::core::socket::configure_evasion_socket;
use crate::core::strategy::{EvasionStrategy, SplitMode};
use crate::dns::{DohClient, DohProvider};

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
            ProbeResult::Error(e) => write!(f, "{}: {}", "FAIL".red(), e),
        }
    }
}

pub async fn run_diagnostic(domain: &str) -> Result<DiagnosticReport> {
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
    let system_ips: Vec<String> = tokio::net::lookup_host(&host_port)
        .await
        .map(|iter| iter.map(|addr| addr.ip().to_string()).collect())
        .unwrap_or_default();

    let doh = DohClient::new(DohProvider::Cloudflare);
    let doh_ips: Vec<String> = match doh.resolve(domain).await {
        Ok((ips, _)) => ips.into_iter().map(|ip| ip.to_string()).collect(),
        Err(_) => Vec::new(),
    };

    let dns_tampered = if !system_ips.is_empty() && !doh_ips.is_empty() {
        // Simple check if system returns loopback or differs drastically
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

    println!("      System DNS: {:?}", system_ips);
    println!("      DoH (Cloudflare): {:?}", doh_ips);

    // Pick best IP for TCP tests (prefer DoH to test actual web server)
    let test_ip = doh_ips
        .first()
        .or_else(|| system_ips.first())
        .cloned()
        .unwrap_or_else(|| "1.1.1.1".to_string());

    let target_addr: SocketAddr = format!("{}:443", test_ip).parse()?;

    // 2. Direct Connection (Baseline without evasion)
    print!("[2/4] Testing Direct TLS Handshake (No Evasion)... ");
    let direct_result = probe_tls_connection(domain, target_addr, None).await;
    println!("{}", direct_result);

    // 3. Evasion Strategies Test
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
                delay_ms: 5,
                ..Default::default()
            },
        },
        StrategyCandidate {
            name: "First-Byte Split (1 + remainder)",
            preset: Some("first-byte"),
            cli_args: "--preset first-byte",
            strategy: EvasionStrategy {
                split_mode: SplitMode::FirstByte,
                delay_ms: 5,
                ..Default::default()
            },
        },
        StrategyCandidate {
            name: "Small Chunks (20-byte chunks)",
            preset: None,
            cli_args: "--split-mode chunk --chunk-size 20 --delay-ms 3",
            strategy: EvasionStrategy {
                split_mode: SplitMode::Chunk,
                chunk_size: 20,
                delay_ms: 3,
                ..Default::default()
            },
        },
        StrategyCandidate {
            name: "TLS Record Layer Split",
            preset: None,
            cli_args: "--tlsrec --delay-ms 5",
            strategy: EvasionStrategy {
                tls_record_split: true,
                delay_ms: 5,
                ..Default::default()
            },
        },
        StrategyCandidate {
            name: "Disorder (Reverse Segment Order)",
            preset: None,
            cli_args: "--split-mode sni --disorder --delay-ms 5",
            strategy: EvasionStrategy {
                split_mode: SplitMode::Sni,
                disorder: true,
                delay_ms: 5,
                ..Default::default()
            },
        },
        StrategyCandidate {
            name: "Fake Decoy SNI (Low TTL)",
            preset: None,
            cli_args: "--fake --fake-ttl 4 --delay-ms 5",
            strategy: EvasionStrategy {
                enable_fake: true,
                fake_sni: "www.microsoft.com".to_string(),
                fake_ttl: 4,
                split_mode: SplitMode::Sni,
                delay_ms: 5,
                ..Default::default()
            },
        },
        StrategyCandidate {
            name: "Mid-SNI Split (Split inside SNI)",
            preset: None,
            cli_args: "--split-mode mid-sni --delay-ms 5",
            strategy: EvasionStrategy {
                split_mode: SplitMode::MidSni,
                delay_ms: 5,
                ..Default::default()
            },
        },
        StrategyCandidate {
            name: "MultiSplit (3-chunk SNI split)",
            preset: None,
            cli_args: "--split-mode multisplit --delay-ms 5",
            strategy: EvasionStrategy {
                split_mode: SplitMode::MultiSplit,
                delay_ms: 5,
                ..Default::default()
            },
        },
        StrategyCandidate {
            name: "Mixed SNI Casing + MultiSplit",
            preset: None,
            cli_args: "--split-mode multisplit --mix-sni --delay-ms 5",
            strategy: EvasionStrategy {
                split_mode: SplitMode::MultiSplit,
                mix_sni: true,
                delay_ms: 5,
                ..Default::default()
            },
        },
    ];

    let mut strategy_results = Vec::new();
    let mut successes: Vec<(&StrategyCandidate, u128)> = Vec::new();

    for candidate in &candidates {
        print!("      Testing {:<34} ... ", candidate.name);
        let res = probe_tls_connection(domain, target_addr, Some(candidate.strategy.clone())).await;
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

        // Pick best candidate: prefer general or first-byte if they are within 30ms of fastest
        let fastest_latency = successes[0].1;
        let best_candidate = successes
            .iter()
            .find(|(c, lat)| {
                (c.preset == Some("general") || c.preset == Some("first-byte"))
                    && (*lat <= fastest_latency + 30)
            })
            .map(|(c, _)| *c)
            .unwrap_or(successes[0].0);

        let best_latency = successes
            .iter()
            .find(|(c, _)| c.name == best_candidate.name)
            .map(|(_, lat)| *lat)
            .unwrap_or(fastest_latency);

        let direct_blocked = matches!(direct_result, ProbeResult::Reset | ProbeResult::Timeout | ProbeResult::Error(_));

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
            format!("evadedpi {} --system-proxy", best_candidate.cli_args)
                .bold()
                .green()
        );
        println!();
        println!("  Alternative run modes:");
        println!(
            "    • Standalone proxy (configure browser or app manually to 127.0.0.1:1080):"
        );
        println!(
            "      {}",
            format!("evadedpi {}", best_candidate.cli_args).cyan()
        );
        println!();
        println!(
            "    • Apply circumvention ONLY to '{}' (other traffic direct):",
            domain
        );
        println!(
            "      {}",
            format!("evadedpi {} --rules \"{},*.{}\" --scope allowlist --system-proxy", best_candidate.cli_args, domain, domain).cyan()
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

        Some(format!("evadedpi {} --system-proxy", best_candidate.cli_args))
    } else {
        println!("{}", "==========================================================".cyan());
        println!(
            "{}",
            "  ==> All tested strategies failed. The IP itself may be blocked or network down."
                .bold()
                .red()
        );
        println!(
            "      Target domain '{}' may be completely unreachable from this network.",
            domain
        );
        println!("{}", "==========================================================".cyan());
        None
    };

    Ok(DiagnosticReport {
        target_domain: domain.to_string(),
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
    let timeout_duration = Duration::from_millis(3500);

    let test_future = async {
        let start = Instant::now();
        let mut stream = match TcpStream::connect(target_addr).await {
            Ok(s) => s,
            Err(e) => return ProbeResult::Error(e.to_string()),
        };

        if let Err(e) = configure_evasion_socket(&stream) {
            return ProbeResult::Error(e.to_string());
        }

        // Generate a TLS ClientHello for the target domain
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

        // Expect ServerHello from upstream
        let mut resp = [0u8; 1024];
        match stream.read(&mut resp).await {
            Ok(n) if n > 0 => {
                // If it's a TLS Handshake ServerHello (0x16) or Alert (0x15)
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

    match timeout(timeout_duration, test_future).await {
        Ok(result) => result,
        Err(_) => ProbeResult::Timeout,
    }
}
