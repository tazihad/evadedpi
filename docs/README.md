# 📚 EvadeDPI Documentation

Welcome to the official documentation for **EvadeDPI** (`evadedpi`), a modern, high-performance Deep Packet Inspection (DPI) circumvention suite written in pure Rust.

---

## 🗂️ Documentation Sections

1. [**Architecture & Design**](architecture.md)
   - Core design and subsystem breakdown of EvadeDPI
   - User-space proxy vs. Kernel-level driver architecture
   - Unified multi-protocol listener and flow pipeline

2. [**Evasion Techniques Deep Dive**](techniques.md)
   - TLS ClientHello SNI segmentation mechanics
   - RFC-compliant TLS record layer fragmentation (`--tlsrec`)
   - Decoy / Fake packet injection with TTL hop manipulation
   - TCP disordering & out-of-order segment delivery
   - TCP Out-Of-Band (OOB / Urgent pointer) desynchronization
   - HTTP/1.1 header casing, spacing, and newline mutations
   - QUIC (UDP 443) blocking rationale
   - Encrypted DNS-over-HTTPS (DoH) architecture

3. [**CLI Reference**](cli-reference.md)
   - Complete manual of all command-line arguments, flags, and options
   - Subcommands: `run`, `test`, `presets`, `reset-proxy`, `generate-config`, `completions`
   - Dynamic SNI-relative offset syntax (`--split-offsets`, `--tlsrec-offset`)
   - Exit codes and logging levels

4. [**Configuration Guide**](configuration.md)
   - Structure of `evadedpi.toml`
   - Pre-configured regional profiles (`general`, `first-byte`, `russia`, `iran`, `china`, `turkey`, `discord-youtube`, `extreme`)
   - Domain rule filtering syntax (exact match, wildcard, suffixes, allowlist/blocklist)

5. [**Client Setup Guide**](client-setup.md)
   - Browser configuration (Firefox, Chrome, Chromium, Brave, Edge)
   - Operating system setup (Linux systemd daemon, macOS, Windows)
   - Command-line tool integration (`curl`, `git`, `docker`, package managers)

6. [**Troubleshooting & Censorship Diagnostics**](troubleshooting.md)
   - Using the built-in diagnostic probe (`evadedpi test <domain>`)
   - Identifying block types: DNS poisoning vs. passive TCP RST vs. active drop / blackhole
   - Diagnosing connection failures and tuning parameters

---

## ⚡ Quick Navigation

- Want to run EvadeDPI immediately? See [Client Setup](client-setup.md).
- Want to understand how DPI is bypassed without a VPN? See [Evasion Techniques](techniques.md).
- Experiencing issues with a specific website? See [Troubleshooting](troubleshooting.md).
