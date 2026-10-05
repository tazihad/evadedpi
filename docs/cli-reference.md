# 💻 CLI Reference Manual

Complete reference for all command-line arguments, options, and subcommands in **EvadeDPI** (`evadedpi`).

```text
Usage: evadedpi [OPTIONS] [COMMAND]
```

---

## 🎯 Subcommands

### 1. `run` (Default Subcommand)
Starts the EvadeDPI proxy server. If no subcommand is specified, `run` is invoked by default.

```bash
evadedpi run [OPTIONS]
evadedpi [OPTIONS]
```

### 2. `test`
Launches the built-in diagnostic censorship probe against a specified domain. Tests DNS integrity, probes direct handshake, and benchmarks each evasion strategy.

```bash
evadedpi test <DOMAIN>
```
**Example**:
```bash
evadedpi test youtube.com
```

### 3. `presets`
Lists all built-in circumvention profiles and displays their operational parameters.

```bash
evadedpi presets
```

### 4. `generate-config`
Generates a fully commented TOML configuration file template (`evadedpi.toml`).

```bash
evadedpi generate-config [-o <PATH>]
```
**Example**:
```bash
evadedpi generate-config -o /etc/evadedpi/evadedpi.toml
```

### 5. `completions`
Generates shell autocompletion scripts for supported shells.

```bash
evadedpi completions <SHELL>
```
**Supported Shells**: `bash`, `zsh`, `fish`, `powershell`, `elvish`.

**Example (Bash)**:
```bash
evadedpi completions bash > /etc/bash_completion.d/evadedpi
```

---

## ⚙️ Options & Flags

### Server Options

* **`-b, --bind <IP>`**
  - IP address to bind the proxy server listener.
  - *Default*: `127.0.0.1` (Localhost only)
  - *Example*: `--bind 0.0.0.0` (Expose to local network / LAN)

* **`-p, --port <PORT>`**
  - TCP port to listen on. Serves both SOCKS5 and HTTP/HTTPS CONNECT on this single port.
  - *Default*: `1080`
  - *Example*: `-p 8080`

* **`--idle-timeout <SECS>`**
  - TCP tunnel idle reaper timeout in seconds. Automatically terminates abandoned or hanging connections to prevent resource leaks.
  - *Default*: `120`

### Evasion Options

* **`--preset <NAME>`**
  - Selects a predefined profile optimized for specific censorship patterns.
  - *Values*: `general`, `first-byte`, `russia`, `iran`, `china`, `turkey`, `discord-youtube`, `extreme`
  - *Default*: `general`

* **`-s, --split-mode <MODE>`**
  - Specifies the segmentation strategy for the TLS ClientHello.
  - *Values*:
    - `sni`: Splits right at the SNI domain boundary (Recommended default).
    - `mid-sni`: Splits right in the middle of the SNI domain string.
    - `multisplit`: Splits before and in the middle of the SNI into 3 distinct segments.
    - `first-byte`: Splits 1 byte into packet 1, remainder into packet 2.
    - `chunk`: Slices payload into uniform chunks.
    - `random`: Slices payload into randomized chunk sizes (1–15 bytes).
    - `custom`: Uses offsets supplied in configuration.
    - `none`: Disables segmentation (raw passthrough).
  - *Default*: `sni`

* **`--mix-sni`**
  - Randomizes letter casing within the SNI hostname (e.g. `yOuTuBe.cOm`). Compliant with RFC 6066 case-insensitivity while evading case-sensitive DPI string matchers.

* **`--chunk-size <BYTES>`**
  - Size of each chunk in bytes when `--split-mode chunk` is active.
  - *Default*: `40`

* **`-d, --delay-ms <MS>`**
  - Inter-segment delay in milliseconds between transmitting chunks. Prevents Nagle's algorithm and kernel packet coalescing.
  - *Default*: `2`

* **`--disorder`**
  - Inverts transmission order of segments (sends segment 2, then segment 1).

* **`--tlsrec`**
  - Enables RFC-compliant TLS record layer fragmentation. Wraps the ClientHello across two separate TLS record headers.

* **`--fake`**
  - Enables decoy packet injection before transmitting the genuine ClientHello.

* **`--fake-sni <DOMAIN>`**
  - Domain name to embed in the decoy ClientHello packet.
  - *Default*: `www.microsoft.com`

* **`--fake-ttl <TTL>`**
  - IP Time-To-Live (or IPv6 Hop Limit) for the decoy packet. Should be sufficiently low that the packet reaches the ISP middlebox but expires before reaching the destination host.
  - *Default*: `4`

* **`--oob`**
  - Sends 1 byte of TCP Out-Of-Band (urgent) data before payload transmission.

* **`--allow-quic`**
  - Disables QUIC (UDP port 443) blocking. By default, EvadeDPI blocks QUIC to force browsers to use TCP HTTPS.

### DNS Options

* **`--doh <PROVIDER>`**
  - Configures the DNS-over-HTTPS provider.
  - *Values*: `cloudflare`, `google`, `quad9`, `adguard`, or any full HTTPS URL (e.g. `https://dns.nextdns.io/...`).
  - *Default*: `cloudflare`

* **`--no-doh`**
  - Disables DoH; uses standard operating system DNS resolution.

### Rules & Filtering Options

* **`-r, --rules <PATH>`**
  - Path to a plain text file containing domain names and wildcard rules (one per line).

* **`--scope <SCOPE>`**
  - Scope determining which traffic receives circumvention tricks:
    - `all`: Apply evasion to all traffic (Default).
    - `allowlist`: Apply evasion ONLY to domains listed in `--rules`.
    - `blocklist`: Apply evasion to all domains EXCEPT those in `--rules`.
  - *Default*: `all`

### General & Logging Options

* **`-c, --config <FILE>`**
  - Path to a TOML configuration file (`evadedpi.toml`).

* **`--stats`**
  - Spawns a background logger printing live connection count and throughput metrics every 10 seconds.

* **`-v, --verbose`**
  - Increases logging verbosity (`-v` for DEBUG, `-vv` for TRACE).

* **`-q, --quiet`**
  - Suppresses informational output; logs warnings and errors only.

* **`-V, --version`**
  - Prints version information and exits.

* **`-h, --help`**
  - Prints help summary and exits.
