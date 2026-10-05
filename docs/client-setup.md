# 🌐 Client Setup & System Configuration

EvadeDPI acts as a local proxy server. Because it supports **both SOCKS5 and HTTP CONNECT proxy protocols simultaneously on the same port** (default `127.0.0.1:9090`), configuring applications is fast and simple.

---

## 1. Web Browsers

### Mozilla Firefox (Recommended)
Firefox has native, independent proxy configuration with remote DNS support:
1. Open Firefox **Settings** (`about:preferences`).
2. Scroll to the bottom to **Network Settings** and click **Settings...**.
3. Select **Manual proxy configuration**.
4. Set:
   - **SOCKS Host**: `127.0.0.1`
   - **Port**: `9090`
   - Select **SOCKS v5**
5. Check **"Proxy DNS when using SOCKS v5"** (This ensures DNS queries are routed through EvadeDPI's DoH engine).
6. Click **OK**.

### Google Chrome / Chromium / Brave / Edge
Chromium-based browsers can be launched with proxy flags directly:

```bash
# Launch with SOCKS5 proxy
google-chrome --proxy-server="socks5://127.0.0.1:9090"

# Or with HTTP proxy
google-chrome --proxy-server="http://127.0.0.1:9090"
```

Alternatively, use popular proxy switcher browser extensions such as **SwitchyOmega** or **FoxyProxy**:
- Profile Type: SOCKS5 (or HTTP)
- Server: `127.0.0.1`, Port: `9090`

---

## 2. Command-Line Tools & Terminal

### Environment Variables
Set standard proxy environment variables in your current shell or `~/.bashrc` / `~/.zshrc`:

```bash
# SOCKS5 (with remote DNS resolution - notice socks5h://)
export all_proxy="socks5h://127.0.0.1:9090"

# Standard HTTP/HTTPS
export http_proxy="http://127.0.0.1:9090"
export https_proxy="http://127.0.0.1:9090"
```

To unset:
```bash
unset all_proxy http_proxy https_proxy
```

### Git
Configure Git to route HTTPS and SSH traffic through EvadeDPI:

```bash
# Set HTTP/HTTPS proxy
git config --global http.proxy "http://127.0.0.1:9090"

# Or SOCKS5 proxy
git config --global http.proxy "socks5h://127.0.0.1:9090"

# Unset when done
git config --global --unset http.proxy
```

### cURL
```bash
# Using HTTP CONNECT proxy
curl -x http://127.0.0.1:9090 -I https://www.google.com

# Using SOCKS5 proxy with remote DNS
curl -x socks5h://127.0.0.1:9090 -I https://www.google.com
```

---

## 3. Running as a Linux Systemd Service

To run EvadeDPI continuously in the background on Linux:

1. Copy the compiled binary to `/usr/local/bin`:
   ```bash
   sudo cp target/release/evadedpi /usr/local/bin/
   ```

2. Create a systemd service file `/etc/systemd/system/evadedpi.service`:
   ```ini
   [Unit]
   Description=EvadeDPI Circumvention Proxy Service
   After=network.target

   [Service]
   Type=simple
   User=nobody
   ExecStart=/usr/local/bin/evadedpi --preset general
   Restart=always
   RestartSec=3
   LimitNOFILE=65535

   [Install]
   WantedBy=multi-user.target
   ```

3. Enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now evadedpi
   sudo systemctl status evadedpi
   ```

---

## 4. System-Wide OS Settings

### Linux (GNOME / KDE)
- **GNOME**: Settings ➔ Network ➔ Network Proxy ➔ Manual
  - Socks Host: `127.0.0.1`, Port: `9090`
- **KDE Plasma**: System Settings ➔ Network ➔ Proxy ➔ Manually specify the proxy settings
  - SOCKS Proxy: `127.0.0.1`, Port: `9090`

### macOS
1. Open **System Settings** ➔ **Network**.
2. Select your active connection (Wi-Fi or Ethernet) ➔ **Details...** ➔ **Proxies**.
3. Toggle **SOCKS Proxy**:
   - Server: `127.0.0.1`, Port: `9090`
4. Click **OK** and **Apply**.

### Windows
1. Open **Settings** ➔ **Network & internet** ➔ **Proxy**.
2. Under **Manual proxy setup**, click **Set up**.
3. Toggle **Use a proxy server** ON.
4. Proxy IP address: `127.0.0.1`, Port: `9090`.
5. Click **Save**.
