# 🏛️ Architecture & Design

## 1. Background & Context

Deep Packet Inspection (DPI) equipment deployed by Internet Service Providers (ISPs) and nation-state firewalls operates at various layers of the OSI model:
- **Layer 3/4**: Filtering IP destinations, inspecting TCP flags, and dropping UDP traffic.
- **Layer 7**: Inspecting plaintext transport security metadata (such as the TLS ClientHello Server Name Indication) or application-layer data (such as HTTP `Host` headers and request URIs).

Unlike Virtual Private Networks (VPNs) or Tor—which route traffic through remote intermediary servers and encrypt all data end-to-end—**DPI circumvention tools manipulate packets locally on the client system**. They exploit fundamental protocol parsing discrepancies between standard end-host TCP/IP implementations and DPI middleboxes to trick the middlebox into ignoring or misinterpreting the traffic without changing the user's external IP address.

---

## 2. The EvadeDPI Architectural Paradigm

EvadeDPI is designed as a unified, high-performance desynchronization proxy written in pure Rust.

```mermaid
graph TD
    Client["Client (Browser / App / CLI)"]
    Listener["Unified Proxy Listener (port 9090)"]
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
   - Rather than forcing users to remember whether they configured port 9090 for SOCKS5 or port 8080 for HTTP, EvadeDPI inspects the initial handshake byte and services both protocols on the exact same port.
