// -----------------------------------------------------------------------------
// File Name:      src/cli.rs
// Description:    Command-line interface definition and argument parsing via Clap.
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

use clap::{Args, Parser, Subcommand};
use clap_complete::Shell;

#[derive(Parser, Debug)]
#[command(
    name = "evadedpi",
    author = "EvadeDPI Contributors",
    version,
    about = "Next-generation Deep Packet Inspection (DPI) circumvention tool and cross-platform proxy",
    long_about = "EvadeDPI (evadedpi) is a modern, high-performance DPI circumvention suite written in Rust.\n\
It intercepts and desynchronizes TLS ClientHello and HTTP requests via SNI segmentation, fake packet injection, \
disordering, TLS record splitting, and DNS-over-HTTPS (DoH) to defeat stateful and stateless DPI firewalls."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[command(flatten)]
    pub run_args: RunArgs,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start the EvadeDPI proxy server (default command)
    Run(RunArgs),

    /// Probe a website to test censorship and benchmark circumvention techniques
    Test {
        /// Target domain name to probe (e.g. "youtube.com" or "x.com")
        domain: String,
    },

    /// List all built-in circumvention presets and their characteristics
    Presets,

    /// Generate a documented configuration file template (evadedpi.toml)
    GenerateConfig {
        /// Optional path to write configuration file to (defaults to stdout)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Generate shell auto-completions for your shell
    Completions {
        /// Target shell (bash, zsh, fish, powershell, elvish)
        shell: Shell,
    },
}

#[derive(Args, Debug, Clone)]
pub struct RunArgs {
    /// IP address to bind proxy server
    #[arg(short, long, default_value = "127.0.0.1")]
    pub bind: String,

    /// Port to listen on (serves both SOCKS5 and HTTP/HTTPS CONNECT)
    #[arg(short, long, default_value_t = 1080)]
    pub port: u16,

    /// Evasion preset profile
    #[arg(long, default_value = "general", value_parser = ["general", "first-byte", "russia", "iran", "china", "turkey", "discord-youtube", "extreme"])]
    pub preset: String,

    /// Splitting mode for TLS ClientHello
    #[arg(short, long, default_value = "sni", value_parser = ["sni", "mid-sni", "multisplit", "first-byte", "chunk", "random", "custom", "none"])]
    pub split_mode: String,

    /// Chunk size in bytes when split-mode is "chunk"
    #[arg(long, default_value_t = 40)]
    pub chunk_size: usize,

    /// Delay between sending TCP segments in milliseconds
    #[arg(short, long, default_value_t = 2)]
    pub delay_ms: u64,

    /// Send packet segments in reverse order (disorder)
    #[arg(long)]
    pub disorder: bool,

    /// Split ClientHello into multiple TLS record layer headers
    #[arg(long)]
    pub tlsrec: bool,

    /// Randomize SNI hostname character casing (RFC 6066 case-insensitive) to evade case-sensitive DPI
    #[arg(long)]
    pub mix_sni: bool,

    /// Enable fake decoy ClientHello packet injection
    #[arg(long)]
    pub fake: bool,

    /// Decoy SNI for fake packet injection
    #[arg(long, default_value = "www.microsoft.com")]
    pub fake_sni: String,

    /// Time-To-Live (TTL) for fake decoy packets
    #[arg(long, default_value_t = 4)]
    pub fake_ttl: u32,

    /// Send 1 byte of TCP Out-Of-Band (urgent) data
    #[arg(long)]
    pub oob: bool,

    /// Disable QUIC (UDP 443) blocking (QUIC blocking is enabled by default)
    #[arg(long)]
    pub allow_quic: bool,

    /// Connection idle timeout in seconds (reaps dead/abandoned tunnels)
    #[arg(long, default_value_t = 120)]
    pub idle_timeout: u64,

    /// DNS-over-HTTPS provider
    #[arg(long, default_value = "cloudflare")]
    pub doh: String,

    /// Disable DNS-over-HTTPS (use system DNS)
    #[arg(long)]
    pub no_doh: bool,

    /// Path to file containing domain rules
    #[arg(short, long)]
    pub rules: Option<String>,

    /// Rule matching scope (all, allowlist, blocklist)
    #[arg(long, default_value = "all", value_parser = ["all", "allowlist", "blocklist"])]
    pub scope: String,

    /// Path to a TOML configuration file
    #[arg(short, long)]
    pub config: Option<String>,

    /// Print live connection and throughput statistics every 10 seconds
    #[arg(long)]
    pub stats: bool,

    /// Enable verbose debug logging (-v for DEBUG, -vv for TRACE)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Quiet mode (only log warnings and errors)
    #[arg(short, long)]
    pub quiet: bool,
}
