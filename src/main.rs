// -----------------------------------------------------------------------------
// File Name:      src/main.rs
// Description:    Main application entry point, CLI dispatcher, and runtime orchestrator.
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

#![allow(dead_code)]

use anyhow::Result;
use clap::{CommandFactory, Parser};
use colored::*;
use std::fs;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

mod cli;
mod config;
mod core;
mod diagnostic;
mod dns;
mod proxy;
mod rules;
mod ui;

use cli::{Cli, Commands, RunArgs};
use config::AppConfig;
use dns::Resolver;
use proxy::{print_env_hints, run_server, ServerConfig, SessionTracker, SystemProxyGuard};
use rules::RuleFilter;
use ui::{print_banner, print_startup_summary, start_stats_display};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Determine log level
    let log_level = if cli.run_args.quiet {
        Level::WARN
    } else {
        match cli.run_args.verbose {
            0 => Level::INFO,
            1 => Level::DEBUG,
            _ => Level::TRACE,
        }
    };

    // Initialize tracing subscriber
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    // Route command
    match cli.command {
        Some(Commands::Test { domain }) => {
            print_banner();
            diagnostic::run_diagnostic(&domain).await?;
        }
        Some(Commands::Presets) => {
            print_banner();
            print_presets();
        }
        Some(Commands::ResetProxy) => {
            proxy::system_proxy::disable_system_proxy();
            println!("{} System proxy disabled.", "✓".bold().green());
        }
        Some(Commands::GenerateConfig { output }) => {
            let template = AppConfig::generate_template();
            if let Some(path) = output {
                fs::write(&path, &template)?;
                println!(
                    "{} Configuration template written to {}",
                    "✓".bold().green(),
                    path.bold().yellow()
                );
            } else {
                println!("{}", template);
            }
        }
        Some(Commands::Completions { shell }) => {
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "evadedpi", &mut io::stdout());
        }
        Some(Commands::Run(args)) => {
            run_evadedpi(args).await?;
        }
        None => {
            // Default command is Run with root flags
            run_evadedpi(cli.run_args).await?;
        }
    }

    Ok(())
}

async fn run_evadedpi(args: RunArgs) -> Result<()> {
    print_banner();

    // 1. Load config file if specified
    let mut config = if let Some(ref path) = args.config {
        info!("Loading configuration from {}", path);
        AppConfig::load_from_file(path)?
    } else {
        AppConfig::default()
    };

    // 2. Override config with CLI flags
    if args.bind != "127.0.0.1" || config.server.bind.is_empty() {
        config.server.bind = args.bind;
    }
    if args.port != 1080 || config.server.port == 0 {
        config.server.port = args.port;
    }
    if args.preset != "general" {
        config.evasion.preset = args.preset.clone();
    }
    if args.split_mode != "sni" {
        config.evasion.split_mode = args.split_mode;
    }
    if args.chunk_size != 40 {
        config.evasion.chunk_size = args.chunk_size;
    }
    if args.delay_ms != 2 {
        config.evasion.delay_ms = args.delay_ms;
    }
    if args.disorder {
        config.evasion.disorder = true;
    }
    if args.tlsrec {
        config.evasion.tls_record_split = true;
    }
    if args.mix_sni {
        config.evasion.mix_sni = true;
    }
    if args.fake {
        config.evasion.enable_fake = true;
    }
    if args.fake_sni != "www.microsoft.com" {
        config.evasion.fake_sni = args.fake_sni;
    }
    if args.fake_ttl != 4 {
        config.evasion.fake_ttl = args.fake_ttl;
    }
    if args.oob {
        config.evasion.enable_oob = true;
    }
    if args.allow_quic {
        config.evasion.block_quic = false;
    }
    if args.idle_timeout != 120 {
        config.server.idle_timeout_secs = args.idle_timeout;
    }
    if args.doh != "cloudflare" {
        config.dns.doh_provider = args.doh;
    }
    if args.no_doh {
        config.dns.enable_doh = false;
    }
    if let Some(r) = args.rules {
        config.rules.rules_file = Some(r);
    }
    if args.scope != "all" {
        config.rules.scope = args.scope;
    }
    if args.system_proxy {
        config.server.system_proxy = true;
    }

    // 3. Build Core Components
    let bind_addr = config.socket_addr()?;
    let strategy = config.build_evasion_strategy();
    let doh_provider = config.doh_provider();
    let resolver = Arc::new(Resolver::new(doh_provider.clone(), config.dns.prefer_ipv4));

    // 4. Load Domain Rules Filter
    let (filter, rules_count) = if let Some(ref source) = config.rules.rules_file {
        let scope = config.rule_scope();
        let rf = RuleFilter::load(scope, source)?;
        let count = rf.len();
        (Arc::new(rf), count)
    } else {
        (Arc::new(RuleFilter::default()), 0)
    };

    let stats = SessionTracker::new();

    // 5. Setup System Proxy if enabled
    let mut proxy_guard: Option<SystemProxyGuard> = if config.server.system_proxy {
        match SystemProxyGuard::enable(&config.server.bind, config.server.port) {
            Ok(guard) => {
                println!(
                    "{} System proxy successfully enabled ({}:{})",
                    "[✓]".bold().green(),
                    config.server.bind.bold().yellow(),
                    config.server.port.to_string().bold().yellow()
                );
                print_env_hints(&config.server.bind, config.server.port);
                Some(guard)
            }
            Err(e) => {
                eprintln!(
                    "{} Failed to configure system proxy: {}",
                    "[!]".bold().red(),
                    e
                );
                None
            }
        }
    } else {
        None
    };

    // 6. Print Startup Summary
    let doh_desc = doh_provider.as_ref().map(|p| p.endpoint());
    print_startup_summary(
        bind_addr,
        &config.evasion.preset,
        &strategy,
        doh_desc,
        rules_count,
        config.server.system_proxy,
    );

    // 7. Optional Live Stats Display
    if args.stats || config.ui.stats_interval.is_some() {
        let interval = config.ui.stats_interval.unwrap_or(10);
        start_stats_display(stats.clone(), interval);
    }

    // 8. Start Proxy Server with Ctrl+C graceful shutdown
    let server_cfg = ServerConfig {
        bind_addr,
        strategy,
        resolver,
        filter,
        stats,
        idle_timeout: Duration::from_secs(config.server.idle_timeout_secs),
    };

    tokio::select! {
        res = run_server(server_cfg) => {
            if let Err(e) = res {
                error!("Server error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            println!("\n{}", "Received shutdown signal (Ctrl+C). Terminating EvadeDPI gracefully.".yellow());
        }
        _ = wait_for_terminate() => {
            println!("\n{}", "Received SIGTERM. Terminating EvadeDPI gracefully.".yellow());
        }
    }

    if let Some(mut guard) = proxy_guard.take() {
        guard.restore();
    }

    Ok(())
}

#[cfg(unix)]
async fn wait_for_terminate() {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut s) => {
            s.recv().await;
        }
        Err(_) => std::future::pending::<()>().await,
    }
}

#[cfg(not(unix))]
async fn wait_for_terminate() {
    std::future::pending::<()>().await
}

fn print_presets() {
    println!("{}", "==========================================================".cyan());
    println!("{}", "               EvadeDPI Evasion Profiles                  ".bold().yellow());
    println!("{}", "==========================================================".cyan());
    println!(
        "{:<15} : {}\n  {}",
        "general".bold().green(),
        "Balanced SNI splitting with 2ms delay and DoH.",
        "Recommended default for most ISPs (bypasses standard SNI inspection)."
    );
    println!(
        "{:<15} : {}\n  {}",
        "first-byte".bold().green(),
        "1-byte TCP payload splitting (1 byte + remaining handshake).",
        "Classic SpoofDPI approach, highly effective against simple middleboxes."
    );
    println!(
        "{:<15} : {}\n  {}",
        "russia".bold().green(),
        "SNI split + decoy TLS ClientHello injection with low TTL (TTL=4).",
        "Optimized for Russian TSPU / RKN hardware middleboxes."
    );
    println!(
        "{:<15} : {}\n  {}",
        "discord-youtube".bold().green(),
        "MultiSplit (3-chunk SNI) + Decoy injection + SNI casing randomization.",
        "Engineered to bypass throttling and blocking on YouTube and Discord."
    );
    println!(
        "{:<15} : {}\n  {}",
        "iran".bold().green(),
        "First-byte split + TLS record layer fragmentation + 5ms delay.",
        "Engineered for deep multi-layered packet inspection in Iran."
    );
    println!(
        "{:<15} : {}\n  {}",
        "china".bold().green(),
        "Chunked TLS segmentation (20 bytes) + decoy packet + DoH.",
        "Tailored to evade stateful flow reassembly engines."
    );
    println!(
        "{:<15} : {}\n  {}",
        "turkey".bold().green(),
        "First-byte split + HTTP Host casing & space trickery + DoH.",
        "Bypasses ISP filtering in Turkey."
    );
    println!(
        "{:<15} : {}\n  {}",
        "extreme".bold().green(),
        "All techniques combined: SNI split, TLS record split, fake packet, disorder.",
        "Maximum desynchronization for highly restrictive censorship."
    );
    println!("{}", "----------------------------------------------------------".cyan());
    println!(
        "Usage: evadedpi --preset <name>  (e.g., evadedpi --preset discord-youtube)"
    );
    println!("{}", "==========================================================".cyan());
}

