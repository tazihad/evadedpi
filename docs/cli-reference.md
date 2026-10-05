# 💻 CLI Reference Manual

Complete reference manual for all command-line flags, options, subcommands, and parameter syntax in **EvadeDPI** (`evadedpi`).

```text
Usage: evadedpi [OPTIONS] [COMMAND]
```

---

## 🎯 Subcommands

### 1. `run` (Default Subcommand)
Starts the unified proxy listener serving both SOCKS5 and HTTP/HTTPS CONNECT requests. If no subcommand is specified, `run` is invoked automatically.

```bash
evadedpi run [OPTIONS]
evadedpi [OPTIONS]
```

---

### 2. `test <DOMAIN>`
Launches the built-in diagnostic censorship probe against a target hostname to detect active censorship mechanisms (DNS poisoning, TCP SYN blackholes, DPI RST injections, HTTP blockpage redirects) and benchmarks circumvention strategies to identify the fastest working option.

```bash
evadedpi test <DOMAIN>
```

**Examples**:
```bash
evadedpi test example.com
evadedpi test https://example.com
```

---

### 3. `presets`
Lists all built-in circumvention profiles, describing their target censorship systems and exact parameters.

```bash
evadedpi presets
```

---

### 4. `reset-proxy`
Restores operating system proxy configurations to their original disabled state. Useful for recovery if EvadeDPI was killed abruptly (`kill -9`) while running with `--system-proxy`. Supports GNOME (`gsettings`), KDE Plasma, macOS (`networksetup`), and Windows (`inetcpl.cpl` registry).

```bash
evadedpi reset-proxy
```

---

### 5. `generate-config`
Generates a fully commented TOML configuration file template (`evadedpi.toml`).

```bash
evadedpi generate-config [-o <PATH>]
```

**Examples**:
```bash
# Print template to stdout
evadedpi generate-config

# Write to file
evadedpi generate-config -o evadedpi.toml
```

---

### 6. `completions <SHELL>`
Generates shell auto-completion scripts.

```bash
evadedpi completions <SHELL>
```

**Supported Shells**: `bash`, `zsh`, `fish`, `powershell`, `elvish`.

**Example (Bash)**:
```bash
evadedpi completions bash | sudo tee /etc/bash_completion.d/evadedpi > /dev/null
```

---

## ⚙️ Command-Line Options & Flags

### Server & System Integration

| Flag | Short | Default | Description |
| :--- | :---: | :---: | :--- |
| `--bind <IP>` | `-b` | `127.0.0.1` | Local IP address to bind listener. Use `0.0.0.0` to share proxy across LAN. |
| `--port <PORT>` | `-p` | `9090` | Port to listen on. Handles SOCKS5 and HTTP CONNECT simultaneously on this port. |
| `--system-proxy` | `-S` | `false` | Automatically configures OS system proxy while EvadeDPI runs, restoring previous state on graceful exit. Alias: `--sysproxy`. |
| `--idle-timeout <SECS>` | — | `120` | TCP tunnel idle reaper timeout in seconds. Cleans up abandoned or dead connections. |

---

### Evasion Strategy & Segmentation

| Flag | Short | Default | Description |
| :--- | :---: | :---: | :--- |
| `--preset <PRESET>` | — | `general` | Selects a preset: `general`, `first-byte`, `russia`, `iran`, `china`, `turkey`, `discord-youtube`, `extreme`. |
| `--split-mode <MODE>` | `-s` | `sni` | Segmentation mode: `sni`, `mid-sni`, `multisplit`, `first-byte`, `chunk`, `random`, `custom`, `none`. |
| `--split-offsets <OFFSETS>` | — | None | Custom split offsets (comma-separated). Automatically sets `--split-mode custom`. Supports dynamic SNI-relative offsets. |
| `--chunk-size <BYTES>` | — | `40` | Fixed segment size in bytes when `--split-mode chunk` is selected. |
| `--delay-ms <MS>` | `-d` | `2` | Inter-segment transmission delay in milliseconds to prevent middlebox packet reassembly. |
| `--disorder` | — | `false` | Transmits segment chunks in reverse / out-of-order sequence (sends segment 2, then segment 1). |

#### Dynamic Offset Syntax for `--split-offsets`
When using `--split-offsets`, offsets can be anchored to the Server Name Indication (SNI) extension in the TLS ClientHello or defined as static byte indices:

* **`N+s`**: Offset relative to the start of the SNI domain name.
  * *Example*: `1+s` (splits 1 byte after SNI starts), `3+s`, `6+s`.
* **`N+se`**: Offset relative to the end of the SNI domain name.
  * *Example*: `-5+se` (splits 5 bytes before the end of the SNI string), `0+se`.
* **`+m` / `mid-sni`**: Splits at the dynamic center of the SNI hostname.
* **`N`**: Static absolute byte index from the start of the payload.
  * *Example*: `20`, `40`, `60`.

**Multi-Split Example**:
```bash
evadedpi --split-offsets "1+s,3+s,6+s,9+s,12+s,15+s,20+s,30+s"
```

---

### TLS Record Layer Fragmentation

| Flag | Default | Description |
| :--- | :---: | :--- |
| `--tlsrec` | `false` | Wraps the TLS ClientHello into multiple RFC-compliant TLS record headers before transmission. |
| `--tlsrec-offset <OFFSET>` | `None` (auto) | Precise split point for the TLS record layer. Accepts dynamic offsets (`-5+se`, `1+s`, `+m`, `sni`, `mid-sni`, `first-byte`, or absolute byte numbers like `2`). |

**Example**:
```bash
# Split TLS record 5 bytes before the end of the SNI hostname
evadedpi --tlsrec --tlsrec-offset "-5+se"
```

---

### Decoy Packet & Header Obfuscation

| Flag | Default | Description |
| :--- | :---: | :--- |
| `--fake` | `false` | Injects a decoy TLS ClientHello before transmitting genuine payload. |
| `--fake-sni <HOST>` | `www.microsoft.com` | Decoy SNI domain name embedded in fake packets. |
| `--fake-ttl <TTL>` | `4` | IP Time-To-Live for decoy packets (must expire before reaching destination server). |
| `--mix-sni` | `false` | Randomizes casing of SNI hostname characters (e.g. `eXaMpLe.CoM`). RFC 6066 compliant, evades case-sensitive DPI. |
| `--oob` | `false` | Transmits 1 byte of TCP Out-Of-Band (urgent) data (`libc::MSG_OOB`) to desynchronize stateful TCP reassembly engines. |
| `--allow-quic` | `false` | Disables QUIC (UDP 443) blocking. By default, EvadeDPI blocks QUIC to force browsers to use TCP HTTPS where evasion works. |

---

### DNS-over-HTTPS (DoH) Options

| Flag | Default | Description |
| :--- | :---: | :--- |
| `--doh <PROVIDER>` | `cloudflare` | DoH resolver endpoint: `cloudflare`, `google`, `quad9`, `adguard`, or custom HTTPS URL (e.g. `https://dns.nextdns.io/...`). |
| `--no-doh` | `false` | Disables encrypted DoH and falls back to standard operating system DNS. |

---

### Domain Rules & Scopes

| Flag | Short | Default | Description |
| :--- | :---: | :---: | :--- |
| `--rules <PATH>` | `-r` | `None` | Path to a file containing domain rules or inline comma-separated domains (`"example.com,*.example.com"`). |
| `--scope <SCOPE>` | — | `all` | Matching scope: `all` (evade everything), `allowlist` (evade matched domains only; others direct), `blocklist` (evade unmatched domains only). |

---

### Logging, Statistics & Debugging

| Flag | Short | Default | Description |
| :--- | :---: | :---: | :--- |
| `--config <FILE>` | `-c` | `None` | Path to a TOML configuration file (`evadedpi.toml`). |
| `--stats` | — | `false` | Prints live connection count, throughput, and bypass statistics every 10 seconds. |
| `--verbose` | `-v` | `0` | Logging verbosity: `-v` for DEBUG level, `-vv` for TRACE level (logs raw chunk bytes). |
| `--quiet` | `-q` | `false` | Quiet mode: suppresses informational banner and logs warnings/errors only. |
| `--help` | `-h` | — | Prints command summary and options. |
| `--version` | `-V` | — | Prints version number (`evadedpi 0.4.0`). |

---

## 💡 Practical CLI Examples

### 1. YouTube & Streaming Video Throttling Bypass
```bash
evadedpi \
  --split-offsets "1+s,3+s,6+s,9+s,12+s,15+s,20+s,30+s" \
  --oob \
  --system-proxy
```

### 2. TLS Record Splitting with Low-TTL Fake Packet Injection
```bash
evadedpi \
  --tlsrec \
  --tlsrec-offset "-5+se" \
  --fake \
  --fake-sni "www.microsoft.com" \
  --fake-ttl 4 \
  --delay-ms 3
```

### 3. Selective Bypass for Specific Domains Only
```bash
evadedpi \
  --preset first-byte \
  --rules "blocked-site.com,*.blocked-site.com" \
  --scope allowlist \
  --system-proxy
```

### 4. Running as a LAN Proxy on Port 8080 with Live Statistics
```bash
evadedpi \
  --bind 0.0.0.0 \
  --port 8080 \
  --preset general \
  --stats
```
