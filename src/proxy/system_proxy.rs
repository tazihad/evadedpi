// -----------------------------------------------------------------------------
// File Name:      src/proxy/system_proxy.rs
// Description:    Cross-platform OS system proxy manager with RAII auto-restore.
// Author:         @tazihad
// Website:        https://zihad.com.bd
// License:        MIT License
// -----------------------------------------------------------------------------

// MIT License
//
// Copyright (c) 2024-2026 @tazihad
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

use anyhow::Result;
use colored::*;
use std::process::Command;
use sysproxy::Sysproxy;
use tracing::{debug, info, warn};

/// System proxy state guard implementing RAII cleanup.
/// When dropped or explicitly restored, it safely unsets the system proxy
/// back to its original state.
pub struct SystemProxyGuard {
    active: bool,
    host: String,
    port: u16,
    prev_sysproxy: Option<Sysproxy>,
    #[cfg(target_os = "linux")]
    kde_backup: Option<KdeBackup>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct KdeBackup {
    is_kwriteconfig6: bool,
    prev_proxy_type: String,
    prev_http_proxy: String,
    prev_https_proxy: String,
    prev_socks_proxy: String,
}

pub fn normalize_host(bind_host: &str) -> &str {
    if bind_host == "0.0.0.0" || bind_host == "::" || bind_host.is_empty() {
        "127.0.0.1"
    } else {
        bind_host
    }
}

impl SystemProxyGuard {
    /// Enable system-wide proxy pointing to the designated host and port.
    pub fn enable(bind_host: &str, bind_port: u16) -> Result<Self> {
        let normalized_host = normalize_host(bind_host);

        let mut guard = Self {
            active: false,
            host: normalized_host.to_string(),
            port: bind_port,
            prev_sysproxy: None,
            #[cfg(target_os = "linux")]
            kde_backup: None,
        };

        guard.apply()?;
        Ok(guard)
    }

    /// Apply the system proxy settings across detected desktop/system backends.
    fn apply(&mut self) -> Result<()> {
        let mut any_applied = false;

        // 1. Primary cross-platform engine (GNOME/gsettings on Linux, WinINet/Registry on Windows, networksetup on macOS)
        if Sysproxy::is_support() {
            // Save original settings if possible
            if let Ok(prev) = Sysproxy::get_system_proxy() {
                debug!("Saved previous system proxy state: {:?}", prev);
                self.prev_sysproxy = Some(prev);
            }

            let new_proxy = Sysproxy {
                enable: true,
                host: self.host.clone(),
                port: self.port,
                bypass: "localhost,127.0.0.1,::1".to_string(),
            };

            match new_proxy.set_system_proxy() {
                Ok(_) => {
                    info!("Cross-platform system proxy successfully applied");
                    any_applied = true;
                }
                Err(e) => {
                    warn!("sysproxy set_system_proxy returned: {}", e);
                }
            }
        }

        // 2. Linux KDE Plasma specific handling (kioslaverc)
        #[cfg(target_os = "linux")]
        {
            if let Some(kde_backup) = configure_kde_proxy(&self.host, self.port) {
                self.kde_backup = Some(kde_backup);
                any_applied = true;
                info!("KDE Plasma system proxy successfully applied");
            }
        }

        if !any_applied {
            warn!("Could not detect a supported GUI desktop proxy engine. Shell environment variables may be used instead.");
        }

        self.active = true;
        Ok(())
    }

    /// Restore previous system proxy settings.
    pub fn restore(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;

        println!(
            "\n{} Restoring system proxy settings to original state...",
            "[*]".bold().yellow()
        );

        // 1. Restore cross-platform sysproxy
        if let Some(ref prev) = self.prev_sysproxy {
            if prev.enable {
                let _ = prev.set_system_proxy();
            } else {
                let disabled = Sysproxy {
                    enable: false,
                    host: String::new(),
                    port: 0,
                    bypass: String::new(),
                };
                let _ = disabled.set_system_proxy();
            }
        } else {
            let disabled = Sysproxy {
                enable: false,
                host: String::new(),
                port: 0,
                bypass: String::new(),
            };
            let _ = disabled.set_system_proxy();
        }

        // 2. Restore Linux KDE proxy
        #[cfg(target_os = "linux")]
        if let Some(ref kde) = self.kde_backup {
            restore_kde_proxy(kde);
        }

        println!(
            "{} System proxy successfully disabled and restored.",
            "[✓]".bold().green()
        );
    }
}

impl Drop for SystemProxyGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

#[cfg(target_os = "linux")]
fn configure_kde_proxy(host: &str, port: u16) -> Option<KdeBackup> {
    let has_kwrite6 = command_available("kwriteconfig6");
    let has_kwrite5 = command_available("kwriteconfig5");

    if !has_kwrite6 && !has_kwrite5 {
        return None;
    }

    let is_k6 = has_kwrite6;
    let read_cmd = if is_k6 { "kreadconfig6" } else { "kreadconfig5" };
    let write_cmd = if is_k6 { "kwriteconfig6" } else { "kwriteconfig5" };

    // Read previous settings
    let prev_proxy_type = run_read_cmd(read_cmd, "ProxyType").unwrap_or_else(|| "0".to_string());
    let prev_http_proxy = run_read_cmd(read_cmd, "httpProxy").unwrap_or_default();
    let prev_https_proxy = run_read_cmd(read_cmd, "httpsProxy").unwrap_or_default();
    let prev_socks_proxy = run_read_cmd(read_cmd, "socksProxy").unwrap_or_default();

    let backup = KdeBackup {
        is_kwriteconfig6: is_k6,
        prev_proxy_type,
        prev_http_proxy,
        prev_https_proxy,
        prev_socks_proxy,
    };

    let proxy_url_http = format!(" http://{}:{}", host, port);
    let proxy_url_socks = format!(" socks://{}:{}", host, port);

    // Apply manual proxy mode (1 = Manual)
    let _ = Command::new(write_cmd)
        .args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "1"])
        .status();

    let _ = Command::new(write_cmd)
        .args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpProxy", &proxy_url_http])
        .status();

    let _ = Command::new(write_cmd)
        .args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpsProxy", &proxy_url_http])
        .status();

    let _ = Command::new(write_cmd)
        .args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "socksProxy", &proxy_url_socks])
        .status();

    let _ = Command::new(write_cmd)
        .args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "NoProxyFor", "localhost,127.0.0.1,::1"])
        .status();

    notify_kde(is_k6);

    Some(backup)
}

#[cfg(target_os = "linux")]
fn restore_kde_proxy(backup: &KdeBackup) {
    let write_cmd = if backup.is_kwriteconfig6 {
        "kwriteconfig6"
    } else {
        "kwriteconfig5"
    };

    let _ = Command::new(write_cmd)
        .args([
            "--file",
            "kioslaverc",
            "--group",
            "Proxy Settings",
            "--key",
            "ProxyType",
            &backup.prev_proxy_type,
        ])
        .status();

    if backup.prev_proxy_type == "0" {
        // Direct / No proxy: clear or delete keys
        let _ = Command::new(write_cmd)
            .args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpProxy", "--delete"])
            .status();
        let _ = Command::new(write_cmd)
            .args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpsProxy", "--delete"])
            .status();
        let _ = Command::new(write_cmd)
            .args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "socksProxy", "--delete"])
            .status();
    } else {
        let _ = Command::new(write_cmd)
            .args([
                "--file",
                "kioslaverc",
                "--group",
                "Proxy Settings",
                "--key",
                "httpProxy",
                &backup.prev_http_proxy,
            ])
            .status();
        let _ = Command::new(write_cmd)
            .args([
                "--file",
                "kioslaverc",
                "--group",
                "Proxy Settings",
                "--key",
                "httpsProxy",
                &backup.prev_https_proxy,
            ])
            .status();
        let _ = Command::new(write_cmd)
            .args([
                "--file",
                "kioslaverc",
                "--group",
                "Proxy Settings",
                "--key",
                "socksProxy",
                &backup.prev_socks_proxy,
            ])
            .status();
    }

    notify_kde(backup.is_kwriteconfig6);
}

#[cfg(target_os = "linux")]
fn notify_kde(is_k6: bool) {
    let kded_dest = if is_k6 { "org.kde.kded6" } else { "org.kde.kded5" };
    let _ = Command::new("dbus-send")
        .args([
            "--type=signal",
            &format!("--dest={}", kded_dest),
            "/kded",
            &format!("{}.reloadConfiguration", kded_dest),
        ])
        .output();

    let _ = Command::new("dbus-send")
        .args([
            "--type=signal",
            "/KIO/Scheduler",
            "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
            "string:\"\"",
        ])
        .output();
}

#[cfg(target_os = "linux")]
fn command_available(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn run_read_cmd(cmd: &str, key: &str) -> Option<String> {
    let output = Command::new(cmd)
        .args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", key])
        .output()
        .ok()?;

    if output.status.success() {
        let val = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !val.is_empty() {
            return Some(val);
        }
    }
    None
}

/// Force-disable the OS system proxy on all supported backends (recovery helper).
pub fn disable_system_proxy() {
    let _ = Sysproxy {
        enable: false,
        host: String::new(),
        port: 0,
        bypass: String::new(),
    }
    .set_system_proxy();

    #[cfg(target_os = "linux")]
    for (is_k6, cmd) in [(true, "kwriteconfig6"), (false, "kwriteconfig5")] {
        if command_available(cmd) {
            let _ = Command::new(cmd)
                .args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "0"])
                .status();
            notify_kde(is_k6);
        }
    }
}

/// Print helpful shell export hints for terminal sessions.
pub fn print_env_hints(host: &str, port: u16) {
    let host = if host == "0.0.0.0" || host == "::" || host.is_empty() {
        "127.0.0.1"
    } else {
        host
    };

    println!(
        "{} System proxy is active on {}:{}",
        "[*]".bold().green(),
        host.bold().yellow(),
        port.to_string().bold().yellow()
    );
    println!(
        "    {} For CLI tools in new terminal tabs, export:",
        "→".cyan()
    );
    println!(
        "      export http_proxy=http://{}:{} https_proxy=http://{}:{} all_proxy=socks5://{}:{}",
        host, port, host, port, host, port
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_host() {
        assert_eq!(normalize_host("0.0.0.0"), "127.0.0.1");
        assert_eq!(normalize_host("::"), "127.0.0.1");
        assert_eq!(normalize_host(""), "127.0.0.1");
        assert_eq!(normalize_host("127.0.0.1"), "127.0.0.1");
        assert_eq!(normalize_host("192.168.1.5"), "192.168.1.5");
    }
}
