// -----------------------------------------------------------------------------
// File Name:      src/ui/banner.rs
// Description:    Terminal user interface, ASCII banner, and live statistics display.
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

use colored::*;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::sleep;

use crate::core::strategy::EvasionStrategy;
use crate::proxy::SessionTracker;

pub fn print_banner() {
    let logo = r#"
  ______               _      _____  _____ _____ 
 |  ____|             | |    |  __ \|  __ \_   _|
 | |__ __   ____ _  __| | ___| |  | | |__) || |  
 |  __|\ \ / / _` |/ _` |/ _ \ |  | |  ___/ | |  
 | |____\ V / (_| | (_| |  __/ |__| | |    _| |_ 
 |______|\_/ \__,_|\__,_|\___|_____/|_|   |_____|
"#;
    println!("{}", logo.bold().cyan());
    println!(
        "   {} v{} by {} - Deep Packet Inspection Evasion Suite",
        "EvadeDPI".bold().yellow(),
        env!("CARGO_PKG_VERSION").bold().white(),
        "tazihad".bold().green()
    );
    println!(
        "   Written in Rust. Cross-Platform SOCKS5 & HTTP Proxy\n"
    );
}

pub fn print_startup_summary(
    bind_addr: SocketAddr,
    preset_name: &str,
    strategy: &EvasionStrategy,
    doh_endpoint: Option<&str>,
    rules_count: usize,
) {
    println!("{}", "╭─── Active Configuration ─────────────────────────────────────╮".cyan());
    println!(
        "│ {} {:<47} │",
        "Listen Address:  ".bold().white(),
        format!("http/socks5://{}", bind_addr).green().bold()
    );
    println!(
        "│ {} {:<47} │",
        "Active Profile:  ".bold().white(),
        preset_name.yellow().bold()
    );
    println!(
        "│ {} {:<47} │",
        "Split Strategy:  ".bold().white(),
        format!("{} (delay: {}ms)", strategy.split_mode, strategy.delay_ms).cyan()
    );
    println!(
        "│ {} {:<47} │",
        "Mix SNI Casing:  ".bold().white(),
        if strategy.mix_sni {
            "Enabled (Case mutation)".green().bold()
        } else {
            "Disabled".dimmed()
        }
    );
    println!(
        "│ {} {:<47} │",
        "Fake Decoy SNI:  ".bold().white(),
        if strategy.enable_fake {
            format!("{} (TTL: {})", strategy.fake_sni, strategy.fake_ttl)
                .magenta()
                .bold()
        } else {
            "Disabled".dimmed()
        }
    );
    println!(
        "│ {} {:<47} │",
        "TLS Record Split:".bold().white(),
        if strategy.tls_record_split {
            "Enabled".green().bold()
        } else {
            "Disabled".dimmed()
        }
    );
    println!(
        "│ {} {:<47} │",
        "Disorder Delivery".bold().white(),
        if strategy.disorder {
            "Enabled".green().bold()
        } else {
            "Disabled".dimmed()
        }
    );
    println!(
        "│ {} {:<47} │",
        "QUIC/HTTP3 Block:".bold().white(),
        if strategy.block_quic {
            "Enabled (Forces TCP fallback)".green().bold()
        } else {
            "Disabled".dimmed()
        }
    );
    println!(
        "│ {} {:<47} │",
        "Secure DNS (DoH):".bold().white(),
        doh_endpoint.unwrap_or("System DNS").cyan()
    );
    println!(
        "│ {} {:<47} │",
        "Domain Filtering:".bold().white(),
        if rules_count > 0 {
            format!("{} custom rules loaded", rules_count).cyan()
        } else {
            "Evade All Domains (Default)".white()
        }
    );
    println!("{}", "╰──────────────────────────────────────────────────────────────╯".cyan());
    println!(
        "\n{} EvadeDPI is running. Configure your system or browser proxy to:",
        "[*Ready*]".bold().green()
    );
    println!("          Host: {}", bind_addr.ip().to_string().bold().yellow());
    println!("          Port: {}", bind_addr.port().to_string().bold().yellow());
    println!("          Type: HTTP or SOCKS5 (Both automatically supported)\n");
}

/// Spawns a background task that displays periodic statistics if enabled.
pub fn start_stats_display(stats: SessionTracker, interval_secs: u64) {
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(interval_secs)).await;
            let active = stats.active_connections();
            let total = stats.total_connections();
            let bypassed = stats.bypassed_requests();
            let up_mb = (stats.bytes_sent() as f64) / 1024.0 / 1024.0;
            let down_mb = (stats.bytes_received() as f64) / 1024.0 / 1024.0;

            println!(
                "{} Active: {} | Total Conns: {} | DPI Bypassed: {} | Up: {:.2} MB | Down: {:.2} MB",
                "[Stats]".bold().magenta(),
                active.to_string().bold().green(),
                total.to_string().cyan(),
                bypassed.to_string().bold().yellow(),
                up_mb,
                down_mb
            );
        }
    });
}
