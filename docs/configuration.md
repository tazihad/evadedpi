# ⚙️ Configuration Guide

EvadeDPI can be configured entirely via command-line arguments, a TOML configuration file, or a combination of both (CLI arguments take precedence over file settings).

---

## 1. The Configuration File (`evadedpi.toml`)

To generate a sample configuration file, run:
```bash
evadedpi generate-config -o evadedpi.toml
```

Here is a full breakdown of the configuration structure:

```toml
# =====================================================================
# EvadeDPI Configuration File
# =====================================================================

[server]
# IP address to bind the listener to.
# Use "127.0.0.1" for local machine only, or "0.0.0.0" to share across LAN / router.
bind = "127.0.0.1"

# Port to listen on.
# Handles both SOCKS5 and HTTP CONNECT proxy protocols simultaneously.
port = 9090

# TCP tunnel idle reaper timeout in seconds. Automatically closes dead/hanging tunnels.
idle_timeout_secs = 120

# Automatically configure OS system proxy while running and restore on exit
system_proxy = false


[evasion]
# Predefined baseline profile:
# "general", "first-byte", "russia", "iran", "china", "turkey", "discord-youtube", "extreme"
preset = "general"

# TLS ClientHello splitting mode:
# - "sni"        : Split precisely before the SNI domain (Recommended)
# - "mid-sni"    : Split right in the middle of the SNI domain string
# - "multisplit" : Split before and in the middle of the SNI (3 segments)
# - "first-byte" : Split 1 byte + remaining handshake
# - "chunk"      : Split into uniform chunk_size bytes
# - "random"     : Split into randomized chunk sizes (1-15 bytes)
# - "custom"     : Split at user-defined byte offsets
# - "none"       : Raw passthrough without segmentation
split_mode = "sni"

# Randomize letter casing within the SNI hostname (RFC 6066 case-insensitive)
# Evades middleboxes relying on exact case-sensitive string matching
mix_sni = false

# Chunk size in bytes when split_mode = "chunk"
chunk_size = 40

# Custom byte split offsets when split_mode = "custom"
# e.g., [1, 5, 20] splits at byte 1, byte 5, and byte 20
custom_offsets = []

# Dynamic SNI-relative split offsets (takes precedence over custom_offsets)
# Supports "N+s" (relative to SNI start), "N+se" (relative to SNI end), "+m" (mid-sni), and absolute numbers
# e.g., ["1+s", "3+s", "6+s", "9+s", "12+s", "15+s", "20+s", "30+s"]
split_offsets = []

# Delay between sending TCP segments in milliseconds.
# 2-5ms is recommended to ensure packets are not coalesced by middleboxes.
delay_ms = 2

# Transmit segments in reverse order (segment 2 first, then segment 1)
disorder = false

# Fragment the ClientHello across multiple TLS record layer headers
tls_record_split = false

# Split position for TLS record layer (e.g. "-5+se", "1+s", "+m", "sni", "mid-sni", "first-byte", "2")
# tlsrec_offset = "-5+se"

# Inject decoy fake ClientHello packet with low TTL before the real packet
enable_fake = false
fake_sni = "www.microsoft.com"
fake_ttl = 4

# Send 1 byte of TCP Out-Of-Band (urgent) data
enable_oob = false

# Block QUIC (UDP 443) to force browsers to fallback to TCP HTTPS
block_quic = true

# HTTP/1.1 Header & Protocol Mutations
mix_host = true             # Replace "Host:" with "hoSt:"
host_space_trim = true      # Trim space: "Host:example.com"
extra_method_space = false  # "GET  / HTTP/1.1"
newline_before_host = false # Insert \r\n before Host header


[dns]
# Enable encrypted DNS-over-HTTPS (DoH) to prevent ISP DNS poisoning
enable_doh = true

# DoH endpoint provider:
# "cloudflare" (https://cloudflare-dns.com/dns-query)
# "google"     (https://dns.google/dns-query)
# "quad9"      (https://dns.quad9.net/dns-query)
# "adguard"    (https://dns.adguard.com/dns-query)
# Or enter a custom HTTPS URL
doh_provider = "cloudflare"

# Prefer IPv4 (A records) over IPv6 (AAAA records)
prefer_ipv4 = true


[rules]
# Path to a text file containing domain names to match (optional)
# rules_file = "/etc/evadedpi/domains.txt"

# Scope for rule matching:
# - "all"       : Evade all traffic (rules_file ignored)
# - "allowlist" : Evade ONLY domains matching rules_file
# - "blocklist" : Evade all domains EXCEPT those in rules_file
scope = "all"


[ui]
# Interval in seconds to print live connection & bandwidth statistics
# stats_interval = 10
```

---

## 2. Evasion Presets & Regional Profiles

EvadeDPI includes tuned presets for common censorship deployments:

### `general` (Recommended Default)
- **Settings**: SNI splitting, 2ms inter-segment delay, DoH enabled, QUIC blocked.
- **Intended Use**: Standard ISP firewalls and DPI middleboxes worldwide.

### `russia`
- **Settings**: SNI split + Decoy ClientHello injection (`www.microsoft.com`, TTL=4) + 4ms delay + DoH + QUIC blocked.
- **Intended Use**: Russian ISPs equipped with TSPU hardware (RKN) which inspect stateful flows.

### `discord-youtube`
- **Settings**: MultiSplit (3-chunk SNI) + Decoy ClientHello injection (`www.google.com`, TTL=4) + SNI casing randomization (`--mix-sni`) + QUIC blocked.
- **Intended Use**: Evades middlebox throttling and DPI signature blocking targeted at Discord and YouTube (`googlevideo.com`, `discord.gg`).

### `iran`
- **Settings**: First-byte split + TLS record layer fragmentation (`--tlsrec`) + 5ms delay + DoH.
- **Intended Use**: Iranian filtering infrastructure which performs deep multi-stage stream inspection.

### `china`
- **Settings**: 20-byte chunk segmentation + decoy packet + DoH.
- **Intended Use**: Circumventing flow reassembly buffers.

### `turkey`
- **Settings**: First-byte split + HTTP Host header casing and spacing mutations + DoH.
- **Intended Use**: Turkish ISP filtering systems.

### `extreme`
- **Settings**: SNI split + TLS record split + Decoy injection + TCP disordering + DoH.
- **Intended Use**: Maximum desynchronization for aggressively locked networks.

---

## 3. Domain Filtering Rules (`--rules` & `--scope`)

When running in `allowlist` or `blocklist` mode, EvadeDPI evaluates destination hostnames against a rule list.

### Rule File Format (`domains.txt`)
Create a plain text file with one pattern per line. Lines starting with `#` are treated as comments:

```text
# Exact domain match
twitter.com
x.com

# Subdomain wildcard
*.googlevideo.com
.youtube.com

# Substring wildcard
*discord*
*torrent*
```

### Supported Pattern Syntax
1. **Exact match**: `example.com` matches `example.com` (case-insensitive).
2. **Subdomain suffix**: `.example.com` or `*.example.com` matches `api.example.com`, `sub.domain.example.com`.
3. **Substring wildcard**: `*keyword*` matches any domain containing `keyword`.
