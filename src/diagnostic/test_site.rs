// EvadeDPI: Modern Deep Packet Inspection Circumvention Engine
// Diagnostic & Censorship Probe Engine (`evadedpi test <domain>`)

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

    let strategies = vec![
        (
            "SNI Segmentation (Recommended)",
            EvasionStrategy {
                split_mode: SplitMode::Sni,
                delay_ms: 5,
                ..Default::default()
            },
        ),
        (
            "First-Byte Split (1 + remainder)",
            EvasionStrategy {
                split_mode: SplitMode::FirstByte,
                delay_ms: 5,
                ..Default::default()
            },
        ),
        (
            "Small Chunks (20-byte chunks)",
            EvasionStrategy {
                split_mode: SplitMode::Chunk,
                chunk_size: 20,
                delay_ms: 3,
                ..Default::default()
            },
        ),
        (
            "TLS Record Layer Split",
            EvasionStrategy {
                tls_record_split: true,
                delay_ms: 5,
                ..Default::default()
            },
        ),
        (
            "Disorder (Reverse Segment Order)",
            EvasionStrategy {
                split_mode: SplitMode::Sni,
                disorder: true,
                delay_ms: 5,
                ..Default::default()
            },
        ),
        (
            "Fake Decoy SNI (Low TTL)",
            EvasionStrategy {
                enable_fake: true,
                fake_sni: "www.microsoft.com".to_string(),
                fake_ttl: 4,
                split_mode: SplitMode::Sni,
                delay_ms: 5,
                ..Default::default()
            },
        ),
    ];

    let mut strategy_results = Vec::new();
    for (name, strat) in strategies {
        print!("      Testing {:<34} ... ", name);
        let res = probe_tls_connection(domain, target_addr, Some(strat)).await;
        println!("{}", res);
        strategy_results.push((name.to_string(), res));
    }

    println!("[4/4] Summary & Recommendations:");
    let any_success = strategy_results
        .iter()
        .any(|(_, r)| matches!(r, ProbeResult::Success { .. }));

    if any_success {
        println!(
            "{}",
            "  ==> SUCCESS: DPI bypass confirmed working on this network!".bold().green()
        );
    } else {
        println!(
            "{}",
            "  ==> All tested strategies failed. The IP itself may be blocked or network down."
                .bold()
                .red()
        );
    }

    Ok(DiagnosticReport {
        target_domain: domain.to_string(),
        system_ips,
        doh_ips,
        dns_tampered,
        direct_result,
        strategy_results,
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
