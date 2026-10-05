# 🔧 Troubleshooting & Censorship Diagnostics

When a website is inaccessible, censorship can be occurring at multiple stages along the network path. This guide provides diagnostic procedures to identify and overcome network blocks.

---

## 1. Using the Built-In Probe (`evadedpi test`)

EvadeDPI includes an automated diagnostic probe that tests each layer of communication:

```bash
evadedpi test blocked-site.com
```

### Interpreting Probe Output

#### Step 1: DNS Resolution
```text
[1/4] Checking DNS Resolution... OK
      System DNS: ["142.250.182.238"]
      DoH (Cloudflare): ["142.250.122.102"]
```
- **If output states `POISONED / HIJACKED!`**:
  Your local ISP is tampering with plaintext DNS queries on UDP port 53.
  - *Fix*: EvadeDPI's DoH is already protecting proxy traffic. Ensure your browser is configured to **"Proxy DNS when using SOCKS v5"** so local DNS lookups don't leak to your ISP.

#### Step 2: Direct TLS Handshake
```text
[2/4] Testing Direct TLS Handshake (No Evasion)... RESET (DPI RST)
```
- **`RESET (DPI RST)`**: The ISP DPI middlebox actively injected a TCP RST packet upon detecting the target domain.
- **`TIMEOUT (DPI Drop)`**: The ISP dropped outgoing packets silently upon seeing the SNI.
- **`DPI Blockpage / HTTP redirect injected`**: The ISP intercepted the stream and replied with an HTTP 302/403 redirect to a censorship notice.

#### Step 3: Benchmarking Strategies
```text
[3/4] Benchmarking Circumvention Strategies against Middlebox:
      Testing SNI Segmentation (Recommended)     ... PASS (145ms)
      Testing First-Byte Split (1 + remainder)   ... PASS (102ms)
      Testing Small Chunks (20-byte chunks)      ... PASS (868ms)
      Testing TLS Record Layer Split             ... PASS (484ms)
      Testing Disorder (Reverse Segment Order)   ... PASS (216ms)
      Testing Fake Decoy SNI (Low TTL)           ... PASS (1093ms)
      Testing Mid-SNI Split (Split inside SNI)   ... PASS (110ms)
      Testing MultiSplit (3-chunk SNI split)     ... PASS (115ms)
      Testing Mixed SNI Casing + MultiSplit      ... PASS (112ms)
```
- Compare the results: whichever strategy indicates `PASS` with the lowest latency is the optimal strategy for your ISP!
  - If **Fake Decoy SNI** passes while **SNI Segmentation** fails: your ISP utilizes stateful flow tracking (e.g. Russia TSPU). Launch with:
    ```bash
    evadedpi --preset russia
    ```
  - If **TLS Record Layer Split** passes: launch with:
    ```bash
    evadedpi --tlsrec
    # or with custom record split offset:
    evadedpi --tlsrec --tlsrec-offset "-5+se"
    ```
  - If **MultiSplit / Mixed SNI** passes: launch with:
    ```bash
    evadedpi -s multisplit --mix-sni
    ```

---

## 2. Common Scenarios & Solutions

### Website Works in `evadedpi test`, but Browser Still Fails
1. **DNS Leak in Browser**:
   Your browser may be resolving the domain through local system DNS before sending the connection to the proxy.
   - *Fix for Firefox*: Enable **"Proxy DNS when using SOCKS v5"** in Firefox Network Settings.
   - *Fix for Chromium*: Launch with `--proxy-server="socks5://127.0.0.1:1080"` (SOCKS5 natively forwards hostnames for remote resolution).
2. **Browser Cached QUIC (HTTP/3)**:
   The browser may have previously established a QUIC connection that was cached.
   - *Fix*: Restart your browser or clear recent connection sockets (`chrome://net-internals/#sockets`).
   - EvadeDPI blocks QUIC by default to force TCP HTTPS.
3. **Encrypted Client Hello (ECH)**:
   If your browser has ECH enabled, some DPI hardware drops unrecognized grease packets.
   - *Fix*: In Firefox `about:config`, set `network.dns.echconfig.enabled` to `false`.

---

### "Address already in use (os error 98)"
Another service or previous proxy process is already using port 1080.
- *Fix*: Bind to another port using `-p`:
  ```bash
  evadedpi -p 1088
  ```

---

### Connections are Slow or Timing Out
If high latency occurs:
- Decrease `--delay-ms` (e.g., `--delay-ms 1` or `--delay-ms 2`).
- Switch split mode from `chunk` to `sni` or `first-byte`.
- Test an alternate DoH provider:
  ```bash
  evadedpi --doh google
  # or
  evadedpi --doh 1.1.1.1
  ```

---

## 3. Verifying with cURL

Run cURL in verbose mode to verify handshake segmentation:
```bash
curl -v -x socks5h://127.0.0.1:1080 -I https://www.google.com
```

Look for:
```text
* Connected to 127.0.0.1 (127.0.0.1) port 1080
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
...
* SSL certificate verify ok.
< HTTP/2 200
```
This confirms end-to-end TLS negotiation succeeded through EvadeDPI's desynchronization engine.
