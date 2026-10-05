# 🏛️ Architecture & Lineage

## 1. Background & Context

Deep Packet Inspection (DPI) equipment deployed by Internet Service Providers (ISPs) and nation-state firewalls operates at various layers of the OSI model:
- **Layer 3/4**: Filtering IP destinations, inspecting TCP flags, and dropping UDP traffic.
- **Layer 7**: Inspecting plaintext transport security metadata (such as the TLS ClientHello Server Name Indication) or application-layer data (such as HTTP `Host` headers and request URIs).

Unlike Virtual Private Networks (VPNs) or Tor—which route traffic through remote intermediary servers and encrypt all data end-to-end—**DPI circumvention tools manipulate packets locally on the client system**. They exploit fundamental protocol parsing discrepancies between standard end-host TCP/IP implementations and DPI middleboxes to trick the middlebox into ignoring or misinterpreting the traffic without changing the user's external IP address.

---

## 2. Analysis of Existing DPI Circumvention Tools

### GoodbyeDPI (ValdikSS)
- **Primary Platform**: Windows (requires Administrator privileges).
- **Core Technology**: Written in C; intercepts raw packets using the `WinDivert` Windows Filtering Platform driver.
- **Key Techniques**:
  - Passive DPI evasion: Drops fake HTTP 302 redirects and injected TCP RST packets by matching IP ID and TCP window size.
  - HTTP header mutations: Replaces `Host: ` with `hoSt: `, strips whitespace after colon (`Host:example.com`), inserts spaces before request URI.
  - HTTPS evasion: Native TCP fragmentation of the ClientHello, reverse fragmentation (second segment first), and fake packet injection with low TTL or incorrect TCP checksums.
  - QUIC blocking: Drops UDP port 443 packets to force browsers to fallback to standard TCP HTTPS.
- **Limitations**:
  - Bound exclusively to Windows due to WinDivert driver dependency.
  - Kernel driver lockups (`WinDivert64.sys` driver locks on uninstall or crash).
  - High complexity for everyday users who lack admin rights.

---

### ByeDPI / ciadpi (hufrea)
- **Primary Platform**: Linux, Windows, macOS, Android (multi-platform).
- **Core Technology**: Written in C; operates as a local user-space SOCKS5 / SOCKS4 / HTTP proxy server or Linux `TPROXY` transparent proxy.
- **Key Techniques**:
  - Fine-grained split expressions: `--split 1+s` (split 1 byte into SNI), `+sm` (split mid-SNI), `+se` (split end-SNI).
  - TLS record layer splitting (`--tlsrec`): Splits the ClientHello into two RFC-compliant TLS record headers.
  - TCP out-of-band injection (`--oob`): Sends urgent data to desynchronize stream reassembly.
  - TCP disordering (`--disorder`): Sends segments in reverse order.
  - Fake request injection (`--fake`, `--ttl`): Injects decoy HTTP/TLS data with custom TTL.
- **Limitations**:
  - Command-line syntax is terse and difficult for non-technical users.
  - Written in C with manual memory management and single/multi-thread event loops without modern async safety.

---

### SpoofDPI (xvzc)
- **Primary Platform**: macOS, Linux (cross-platform).
- **Core Technology**: Written in Go; operates as a local HTTP and SOCKS proxy.
- **Key Techniques**:
  - Clean TLS ClientHello parsing: Identifies SNI offset and splits payload into segments (`first-byte`, `sni`, `chunk`, `random`).
  - Built-in DNS-over-HTTPS (DoH) client to bypass ISP DNS hijacking.
  - QUIC blocking.
- **Limitations**:
  - Lacks TLS record-layer fragmentation (`tlsrec`).
  - Minimal HTTP/1.1 header mutation support.
  - No built-in diagnostic probe tool.

---

### DPIBreak (dilluti0n)
- **Primary Platform**: Linux and Windows.
- **Core Technology**: Written in Rust; utilizes Linux `NFQUEUE` and Windows `WinDivert` with `etherparse`.
- **Key Techniques**:
  - Kernel-level packet interception of outgoing TLS ClientHello packets.
  - Segment ordering (`-o 0,1` or `-o 5,0`) and automated TTL distance calculation (`infer_hops`).
- **Limitations**:
  - Requires `sudo` / root privileges on Linux and WinDivert driver on Windows.
  - System-wide interception can conflict with local VPNs or WireGuard interfaces.

---

### Zapret (bol-van)
- **Primary Platform**: Linux, OpenWrt routers.
- **Core Technology**: Written in C; operates via `nfqws` (NFQUEUE worker) and `tpws` (transparent proxy).
- **Key Techniques**:
  - State-of-the-art packet desynchronization: multi-split, syndata, disorder, badsum, fake payloads with TCP MD5 signature fooling.
- **Limitations**:
  - Highly complex configuration syntax designed primarily for advanced network engineers and router firmware.

---

## 3. The EvadeDPI Architectural Paradigm

EvadeDPI was created to synthesize the best aspects of these tools into a single, cohesive, modern Rust application.

```mermaid
graph TD
    Client["Client (Browser / App / CLI)"]
    Listener["Unified Proxy Listener (port 1080)"]
    ProtocolDetect{"Protocol Peek Byte 0"}
    SocksHandler["SOCKS5 Handler (RFC 1928)"]
    HttpHandler["HTTP CONNECT / Forward Handler"]
    DNSResolver["Unified DNS Resolver (DoH + Cache)"]
    RuleEngine["Domain Filtering Engine (Allow/Block)"]
    DesyncEngine["Desynchronization Engine"]
    Upstream["Upstream Server / Origin Web Host"]
    Middlebox["ISP DPI Middlebox (Passive/Active)"]

    Client -->|TCP Connection| Listener
    Listener --> ProtocolDetect
    ProtocolDetect -->|0x05| SocksHandler
    ProtocolDetect -->|ASCII HTTP| HttpHandler

    SocksHandler --> DNSResolver
    HttpHandler --> DNSResolver

    SocksHandler --> RuleEngine
    HttpHandler --> RuleEngine

    RuleEngine -->|Match Rule| DesyncEngine
    RuleEngine -->|Bypass Rule| Upstream

    DesyncEngine -->|1. Fake Decoy Packet (TTL=4)| Middlebox
    Middlebox -.->|Drop before origin| Upstream
    DesyncEngine -->|2. Fragmented ClientHello (SNI Split)| Upstream
```

### Why User-Space Proxy vs. Kernel Drivers?

1. **True Cross-Platform Portability**:
   - Kernel drivers (like `WinDivert` on Windows or `NFQUEUE` on Linux) require administrative/root privileges, kernel headers, and signing certificates.
   - EvadeDPI runs completely in user space without requiring root or administrator privileges (unless binding to privileged ports < 1024). It runs identically on Linux, macOS, Windows, and BSD.
2. **Safety & System Stability**:
   - Kernel driver crashes result in Blue Screens of Death (BSOD) or kernel panics. A user-space crash simply closes the proxy connection.
3. **Seamless Integration**:
   - Modern browsers and operating systems natively support HTTP and SOCKS5 proxies. Setting a proxy is non-destructive, does not interfere with routing tables, and works cleanly alongside WireGuard/VPNs.
4. **Unified Single-Port Listener**:
   - Rather than forcing users to remember whether they configured port 1080 for SOCKS5 or port 8080 for HTTP, EvadeDPI inspects the initial handshake byte and services both protocols on the exact same port.
