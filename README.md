# 🛡️ EvadeDPI (`evadedpi`)

[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker Image](https://img.shields.io/docker/v/tazihad/evadedpi?label=docker&logo=docker)](https://hub.docker.com/r/tazihad/evadedpi)
[![Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)]()

> **EvadeDPI** is a modern, high-performance Deep Packet Inspection (DPI) circumvention suite written in pure Rust. It combines the most effective packet manipulation, segmentation, decoy injection, and transport desynchronization techniques into a unified, cross-platform CLI tool.

📖 **Comprehensive Documentation**: Complete guides are available in the [`docs/`](docs/) directory:
- [Architecture & Design](docs/architecture.md)
- [Evasion Techniques Deep Dive](docs/techniques.md)
- [CLI Reference Manual](docs/cli-reference.md)
- [Configuration Guide](docs/configuration.md)
- [Client Setup Guide](docs/client-setup.md)
- [Troubleshooting & Diagnostics](docs/troubleshooting.md)

---

## 📑 Table of Contents

- [Deep Packet Inspection Overview](#-deep-packet-inspection-overview)
- [How EvadeDPI Works](#-how-evadedpi-works)
  - [1. Dual-Protocol Unified Proxy](#1-dual-protocol-unified-proxy)
  - [2. TLS ClientHello & SNI Segmentation](#2-tls-clienthello--sni-segmentation)
  - [3. TLS Record Layer Fragmentation (`--tlsrec`)](#3-tls-record-layer-fragmentation---tlsrec)
  - [4. Decoy / Fake ClientHello Injection](#4-decoy--fake-clienthello-injection)
  - [5. Out-of-Order Delivery & TCP Disordering](#5-out-of-order-delivery--tcp-disordering)
  - [6. TCP Out-Of-Band Data (`--oob`)](#6-tcp-out-of-band-data---oob)
  - [7. QUIC / HTTP3 Blocking](#7-quic--http3-blocking)
  - [8. HTTP/1.1 Protocol Mutations](#8-http11-protocol-mutations)
  - [9. Built-in DNS-over-HTTPS (DoH)](#9-built-in-dns-over-https-doh)
- [Quick Start](#-quick-start)
- [Evasion Presets](#-evasion-presets)
- [Diagnostic Censorship Probe (`evadedpi test`)](#-diagnostic-censorship-probe-evadedpi-test)
- [Configuration File (`evadedpi.toml`)](#-configuration-file-evadedpitoml)
- [Full Command-Line Reference](#-full-command-line-reference)
- [Client Configuration](#-client-configuration)
- [License](#-license)

---

## 🔍 Deep Packet Inspection Overview

Deep Packet Inspection (DPI) systems used by Internet Service Providers (ISPs) and state-level firewalls (such as Russia's TSPU / RKN, China's GFW, Iran, Turkey, and university/corporate firewalls) inspect plaintext fields in network traffic:
1. **Plaintext DNS Queries (UDP Port 53)**: Hijacked or poisoned with fake IP addresses (redirecting to blockpages or `127.0.0.1`).
2. **TLS ClientHello SNI (Server Name Indication)**: Inspected during the TLS handshake before encryption is established. If the SNI matches a blacklist, the middlebox injects a TCP RST or silently drops packets.
3. **HTTP `Host` Headers**: Inspected in plaintext HTTP/1.1 traffic.
4. **QUIC / HTTP/3 (UDP Port 443)**: Encrypted transport that cannot be easily segmented; middleboxes often block UDP 443 entirely or inspect initial QUIC frames.

---

## ⚡ How EvadeDPI Works

### 1. Dual-Protocol Unified Proxy
EvadeDPI listens on a single port (default `127.0.0.1:9090`). When a client connects, EvadeDPI peeks at the initial handshake bytes:
- If byte `0x05` is observed, it transparently negotiates **SOCKS5** (RFC 1928).
- If ASCII HTTP verbs (`CONNECT`, `GET`, `POST`) are observed, it transparently handles **HTTP/HTTPS CONNECT Proxy** requests.

Any browser, application, or CLI tool can point to `127.0.0.1:9090` regardless of whether it uses HTTP or SOCKS5!

### 2. TLS ClientHello & SNI Segmentation
When a client begins a TLS connection, it sends an unencrypted `ClientHello` containing the domain name inside the Server Name Indication (SNI) extension. 
Stateless and simple stateful DPI boxes inspect this packet to identify blocked domains. EvadeDPI parses the ClientHello structure and splits the packet into multiple TCP segments:
- **`sni` (default)**: Splits right at the beginning of the SNI domain string. The DPI buffer only sees `[Handshake Header + Ciphers]` in packet 1 and `[SNI String + Remainder]` in packet 2.
- **`mid-sni`**: Splits directly at the midpoint of the SNI domain string (e.g. `yout` in packet 1, `ube.com` in packet 2).
- **`multisplit`**: Partitions across 3 segments (before SNI, mid-SNI, and remainder).
- **`first-byte`**: Splits 1 byte into packet 1 and the rest into packet 2.
- **`chunk`**: Chunks the handshake into $N$-byte segments (e.g. 20 or 40 bytes).
- **`--split-offsets`**: Dynamically cuts the ClientHello at custom byte offsets relative to the SNI extension (`1+s`, `3+s`, `-5+se`, `+m`, or absolute numbers). Enables micro-chunking across the SNI.
- **`delay-ms`**: Adds an inter-segment delay (e.g. 2ms) with `TCP_NODELAY` to force the kernel to transmit distinct IP packets.

### 3. TLS Record Layer Fragmentation (`--tlsrec`, `--tlsrec-offset`)
Under RFC 5246 (TLS 1.2) and RFC 8446 (TLS 1.3), a handshake message **may be partitioned across multiple TLS record headers**.
EvadeDPI wraps the first portion of the ClientHello into TLS Record 1 and the remainder into TLS Record 2. Destination web servers reassemble the records effortlessly, while DPI hardware fails to detect the SNI because the extension is fragmented across record boundaries.
- **`--tlsrec-offset <OFFSET>`**: Position the record boundary dynamically relative to the SNI domain (e.g. `--tlsrec-offset "-5+se"`, `1+s`, `mid-sni`, or absolute byte index `2`).

### 4. Decoy / Fake ClientHello Injection
For stateful middleboxes (such as Russia's TSPU):
EvadeDPI transmits a realistic fake TLS ClientHello with a whitelisted domain (e.g. `www.microsoft.com` or `cloudflare.com`) with a low IP Time-To-Live (`--fake-ttl 4`).
- The DPI middlebox (typically 2–5 hops away) inspects the decoy SNI, marks the TCP connection as permitted in its state table, and allows it through.
- Because the TTL is low, the decoy packet dies in transit before reaching the origin server.
- EvadeDPI immediately sends the genuine ClientHello with normal TTL. The DPI middlebox has already whitelisted the flow and lets it pass!

### 5. Out-of-Order Delivery & TCP Disordering
EvadeDPI can transmit the second fragment of the ClientHello first, followed by the first fragment. Destination TCP stacks reassemble the stream in sequence number order, but DPI hardware expecting sequential data fails to parse the out-of-order stream.

### 6. TCP Out-Of-Band Data (`--oob`)
Sends 1 byte of urgent data (`MSG_OOB`). Middleboxes tracking TCP sequence streams become desynchronized, while target web servers discard or ignore the urgent byte.

### 7. QUIC / HTTP3 Blocking
Modern browsers attempt QUIC (UDP 443) before TCP HTTPS. Because QUIC packets cannot be segmented using TCP evasion tricks, EvadeDPI blocks QUIC UDP traffic, forcing browsers to immediately fall back to TCP HTTPS where evasion works 100% reliably.

### 8. HTTP/1.1 Protocol Mutations
For plaintext HTTP connections:
- Host header casing: `Host:` ➔ `hoSt:`
- Colon space trimming: `Host: example.com` ➔ `Host:example.com`
- Extra method spacing: `GET / HTTP/1.1` ➔ `GET  / HTTP/1.1`
- Prepending extra newlines before `Host:`.

### 9. Built-in DNS-over-HTTPS (DoH)
To bypass DNS poisoning and tampering by local ISPs, EvadeDPI resolves all target addresses via encrypted DNS-over-HTTPS (Cloudflare, Google, Quad9, AdGuard, or custom endpoints) and maintains a high-speed in-memory cache with TTL expiration.

---

## 🚀 Quick Start

### 1. Download Pre-Built Release (Recommended)

Pre-compiled, standalone binaries are packaged with high-efficiency `.tar.xz` compression and hosted on the [GitHub Releases](https://github.com/tazihad/evadedpi/releases) page. No dependencies, runtimes, or kernel drivers are required.

#### Option A: One-Liner Download & Extract (Linux x86_64)

```bash
# Download the latest v0.4.0 release archive
curl -sLO https://github.com/tazihad/evadedpi/releases/download/v0.4.0/evadedpi-v0.4.0-linux-x86_64.tar.xz

# Extract the archive
tar -xJf evadedpi-v0.4.0-linux-x86_64.tar.xz

# (Optional) Install system-wide to /usr/local/bin
sudo install -m 755 evadedpi /usr/local/bin/
```

#### Option B: Dynamic Latest Release Fetch via `curl`

```bash
# Dynamically queries GitHub API for the latest .tar.xz asset
curl -s https://api.github.com/repos/tazihad/evadedpi/releases/latest \
  | grep "browser_download_url.*linux-x86_64.tar.xz" \
  | cut -d : -f 2,3 \
  | tr -d \" \
  | xargs curl -LO

# Extract the downloaded archive
tar -xJf evadedpi-*-linux-x86_64.tar.xz
```

#### Option C: GitHub CLI (`gh`)

```bash
gh release download -R tazihad/evadedpi --pattern "*.tar.xz"
tar -xJf evadedpi-*-linux-x86_64.tar.xz
```

---

### 2. Build from Source (Cargo)

If you have Rust (1.75+) installed and prefer compiling directly:

```bash
# Clone the repository
git clone https://github.com/tazihad/evadedpi.git
cd evadedpi

# Build optimized release binary
cargo build --release

# The compiled binary is located at target/release/evadedpi
./target/release/evadedpi --help
```

---

### 3. Run EvadeDPI

Start the proxy server with default recommended settings:

```bash
# If installed system-wide:
evadedpi

# Or if running from extracted archive / source directory:
./evadedpi
```

Output:
```text
  ______               _      _____  _____ _____ 
 |  ____|             | |    |  __ \|  __ \_   _|
 | |__ __   ____ _  __| | ___| |  | | |__) || |  
 |  __|\ \ / / _` |/ _` |/ _ \ |  | |  ___/ | |  
 | |____\ V / (_| | (_| |  __/ |__| | |    _| |_ 
 |______|\_/ \__,_|\__,_|\___|_____/|_|   |_____|

   EvadeDPI v0.4.0 by tazihad - Deep Packet Inspection Evasion Suite
   Written in Rust. Cross-Platform SOCKS5 & HTTP Proxy

╭─── Active Configuration ─────────────────────────────────────╮
│ Listen Address:   http/socks5://127.0.0.1:9090               │
│ Active Profile:   general                                    │
│ Split Strategy:   sni (delay: 2ms)                           │
│ Mix SNI Casing:   Disabled                                   │
│ Fake Decoy SNI:   Disabled                                   │
│ TLS Record Split: Disabled                                   │
│ Disorder Delivery Disabled                                   │
│ QUIC/HTTP3 Block: Enabled (Forces TCP fallback)              │
│ Secure DNS (DoH): https://cloudflare-dns.com/dns-query        │
│ Domain Filtering: Evade All Domains (Default)                │
╰──────────────────────────────────────────────────────────────╯

[*Ready*] EvadeDPI is running. Configure your system or browser proxy to:
          Host: 127.0.0.1
          Port: 9090
          Type: HTTP or SOCKS5 (Both automatically supported)
```

---

### 4. Run via Docker / Podman (Containerized)

EvadeDPI is available on [Docker Hub](https://hub.docker.com/r/tazihad/evadedpi) as `tazihad/evadedpi` (and `ghcr.io/tazihad/evadedpi`):

```bash
# Run with default settings (port 9090):
docker run -d --name evadedpi -p 9090:9090 --restart unless-stopped tazihad/evadedpi

# Run with a specific circumvention preset:
docker run -d --name evadedpi -p 9090:9090 --restart unless-stopped tazihad/evadedpi --preset discord-youtube

# Or run with Docker Compose:
docker compose -f docker/docker-compose.yml up -d
```

---

### 5. Verify & Use

Once EvadeDPI is running:

```bash
# 1. Run a censorship diagnostic test against a domain
./evadedpi test youtube.com

# 2. Test fetching a blocked site through the proxy with curl
curl -x socks5h://127.0.0.1:9090 -I https://www.youtube.com
curl -x http://127.0.0.1:9090 -I https://www.youtube.com

# 3. Launch Chrome/Chromium through the proxy
google-chrome --proxy-server="socks5://127.0.0.1:9090"
```

---

## 🎯 Evasion Presets

EvadeDPI includes tuned, battle-tested presets for specific censorship regimes:

```bash
# View all presets
./target/release/evadedpi presets

# Run with a preset
./target/release/evadedpi --preset russia
```

| Preset | Description | Strategy Details |
| :--- | :--- | :--- |
| `general` | **Default balanced mode** | SNI split, 2ms delay, DoH, QUIC blocked. |
| `first-byte` | **Classic 1-byte split** | 1 byte + remaining handshake. High compatibility. |
| `russia` | **Optimized for Russian TSPU / RKN** | SNI split + Decoy ClientHello (`--fake-sni www.microsoft.com --fake-ttl 4`) + 4ms delay + DoH. |
| `discord-youtube` | **Bypass YouTube & Discord throttling** | MultiSplit (3-chunk SNI) + Decoy injection + SNI casing randomization (`--mix-sni`) + QUIC blocked. |
| `iran` | **Optimized for Iranian DPI** | First-byte split + TLS record layer fragmentation (`--tlsrec`) + 5ms delay + DoH. |
| `china` | **Optimized for GFW reassembly** | 20-byte chunk segmentation + decoy packet + DoH. |
| `turkey` | **Optimized for Turkish ISP blocks** | First-byte split + HTTP Host casing & space trickery + DoH. |
| `extreme` | **Maximum desynchronization** | SNI split + TLS record split + fake packet + disorder + DoH. |

---

## 🔬 Diagnostic Censorship Probe (`evadedpi test`)

EvadeDPI has a built-in diagnostic tool to test whether a domain is censored on your current network and benchmark which circumvention technique works best:

```bash
./target/release/evadedpi test youtube.com
```

Example Output:
```text
==========================================================
[*] Running EvadeDPI Diagnostic Probe on 'youtube.com'
==========================================================
[1/4] Checking DNS Resolution... OK
      System DNS: ["142.250.182.238"]
      DoH (Cloudflare): ["142.250.122.102", "142.250.122.139"]
[2/4] Testing Direct TLS Handshake (No Evasion)... RESET (DPI RST)
[3/4] Benchmarking Circumvention Strategies against Middlebox:
      Testing SNI Segmentation (Recommended)     ... PASS (145ms)
      Testing First-Byte Split (1 + remainder)   ... PASS (102ms)
      Testing Small Chunks (20-byte chunks)      ... PASS (868ms)
      Testing TLS Record Layer Split             ... PASS (484ms)
      Testing Disorder (Reverse Segment Order)   ... PASS (216ms)
      Testing Fake Decoy SNI (Low TTL)           ... PASS (1093ms)
[4/4] Summary & Recommendations:
==========================================================
[!] DPI Censorship Confirmed on 'youtube.com'!
    Direct connection was blocked/reset by ISP middlebox. Circumvention is required.
    Recommended strategy: First-Byte Split (1 + remainder) (102ms, fastest reliable option)
----------------------------------------------------------
>>> RECOMMENDED COMMAND TO UNBLOCK 'YOUTUBE.COM':

    evadedpi --preset first-byte --system-proxy

  Alternative run modes:
    • Standalone proxy (configure browser or app manually to 127.0.0.1:9090):
      evadedpi --preset first-byte

    • Apply circumvention ONLY to 'youtube.com' (other traffic direct):
      evadedpi --preset first-byte --rules "youtube.com,*.youtube.com" --scope allowlist --system-proxy
==========================================================
```

> If evadedpi is force-killed (e.g. `kill -9`) while `--system-proxy` is active, run `evadedpi reset-proxy` to turn the OS proxy back off.

---

## ⚙️ Configuration File (`evadedpi.toml`)

Generate a sample configuration template:
```bash
./target/release/evadedpi generate-config -o evadedpi.toml
```

Run with the configuration file:
```bash
./target/release/evadedpi -c evadedpi.toml
```

---

## 📖 Full Command-Line Reference

```text
Usage: evadedpi [OPTIONS] [COMMAND]

Commands:
  run              Start the EvadeDPI proxy server (default command)
  test             Probe a website to test censorship and benchmark circumvention techniques
  presets          List all built-in circumvention presets and their characteristics
  reset-proxy      Disable the OS system proxy (recovery if evadedpi was force-killed)
  generate-config  Generate a documented configuration file template (evadedpi.toml)
  completions      Generate shell auto-completions for your shell
  help             Print this message or the help of the given subcommand(s)

Options:
  -b, --bind <BIND>              IP address to bind [default: 127.0.0.1]
  -p, --port <PORT>              Port to listen on [default: 9090]
  -S, --system-proxy             Set the OS system proxy while running; restored on exit
                                 (GNOME/gsettings, KDE Plasma, macOS, Windows)
      --preset <PRESET>          Evasion preset profile [default: general]
                                 [values: general, first-byte, russia, iran, china, turkey, discord-youtube, extreme]
  -s, --split-mode <SPLIT_MODE>  Splitting mode [default: sni]
                                  [values: sni, mid-sni, multisplit, first-byte, chunk, random, custom, none]
      --chunk-size <BYTES>       Chunk size when split-mode is chunk [default: 40]
      --split-offsets <OFFSETS>  Custom split offsets, comma-separated (e.g. "1+s,3+s,6+s" or "20,40,60")
      --tlsrec                   Split ClientHello across TLS record headers
      --tlsrec-offset <OFFSET>   Split position for TLS record layer (e.g. "sni", "mid-sni", "-5+se", "2")
  -d, --delay-ms <MS>            Delay between segments in ms [default: 2]
      --disorder                 Send packet segments in reverse order
      --mix-sni                  Randomize SNI character casing to bypass case-sensitive DPI
      --fake                     Enable fake decoy ClientHello injection
      --fake-sni <HOST>          Decoy SNI for fake packet [default: www.microsoft.com]
      --fake-ttl <TTL>           Time-To-Live for fake decoy packet [default: 4]
      --oob                      Send 1 byte of TCP Out-Of-Band (urgent) data
      --allow-quic               Disable QUIC (UDP 443) blocking
      --idle-timeout <SECS>      Connection idle timeout in seconds [default: 120]
      --doh <PROVIDER>           DoH provider [default: cloudflare]
                                 [values: cloudflare, google, quad9, adguard, or https URL]
      --no-doh                   Disable DoH (use system DNS)
  -r, --rules <FILE>             Path to domain rules file
      --scope <SCOPE>            Rule scope [default: all] [values: all, allowlist, blocklist]
  -c, --config <FILE>            Path to TOML configuration file
      --stats                    Print live connection and throughput stats every 10s
  -v, --verbose...               Verbose logging (-v DEBUG, -vv TRACE)
  -q, --quiet                    Quiet mode (warnings and errors only)
  -h, --help                     Print help
  -V, --version                  Print version
```

---

## 🌐 Client Configuration

### Command Line (`curl` / `git` / `env`)
```bash
# SOCKS5 Proxy
export all_proxy="socks5h://127.0.0.1:9090"
curl -I https://www.google.com

# HTTP Proxy
export http_proxy="http://127.0.0.1:9090"
export https_proxy="http://127.0.0.1:9090"
curl -I https://www.google.com
```

### Web Browsers
1. **Firefox**:
   - Settings ➔ Network Settings ➔ Manual proxy configuration
   - **SOCKS Host**: `127.0.0.1`, Port: `9090`, SOCKS v5
   - Check **"Proxy DNS when using SOCKS v5"**
2. **Google Chrome / Chromium**:
   ```bash
   google-chrome --proxy-server="socks5://127.0.0.1:9090"
   ```

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

Copyright (c) 2024-2026 Tazihad ([@tazihad](https://github.com/tazihad)).
