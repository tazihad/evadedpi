// EvadeDPI: Modern Deep Packet Inspection Circumvention Engine
// Unified Dual-Protocol Proxy Server (SOCKS5 + HTTP CONNECT Auto-Detect)

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, trace, warn};

use super::http_proxy::handle_http_proxy;
use super::session::SessionTracker;
use super::socks5::handle_socks5;
use crate::core::strategy::EvasionStrategy;
use crate::core::tls::parse_client_hello;
use crate::dns::Resolver;
use crate::rules::RuleFilter;

/// Configuration parameters for the running proxy server.
#[derive(Clone)]
pub struct ServerConfig {
    pub bind_addr: SocketAddr,
    pub strategy: EvasionStrategy,
    pub resolver: Arc<Resolver>,
    pub filter: Arc<RuleFilter>,
    pub stats: SessionTracker,
}

/// Start the EvadeDPI unified proxy listener.
pub async fn run_server(config: ServerConfig) -> Result<()> {
    let listener = TcpListener::bind(config.bind_addr).await?;
    info!(
        "EvadeDPI listening on {} (Unified SOCKS5 & HTTP/HTTPS Proxy)",
        config.bind_addr
    );

    loop {
        match listener.accept().await {
            Ok((client_stream, peer_addr)) => {
                let cfg = config.clone();
                tokio::spawn(async move {
                    cfg.stats.inc_active();
                    if let Err(err) = process_connection(client_stream, peer_addr, cfg.clone()).await {
                        trace!("Connection from {} closed: {}", peer_addr, err);
                    }
                    cfg.stats.dec_active();
                });
            }
            Err(e) => {
                warn!("Accept error on proxy listener: {}", e);
            }
        }
    }
}

async fn process_connection(
    mut client: TcpStream,
    peer_addr: SocketAddr,
    cfg: ServerConfig,
) -> Result<()> {
    trace!("Incoming connection from {}", peer_addr);

    // Peek at the first byte to auto-detect protocol (0x05 = SOCKS5, ASCII = HTTP)
    let mut peek_buf = [0u8; 1];
    let n = client.peek(&mut peek_buf).await?;
    if n == 0 {
        return Ok(());
    }

    let (upstream, target_host, direct_req) = if peek_buf[0] == 0x05 {
        // SOCKS5 Protocol
        trace!("Detected SOCKS5 connection from {}", peer_addr);
        let conn = handle_socks5(&mut client, &cfg.resolver, cfg.strategy.block_quic).await?;
        (conn.upstream_stream, conn.target_host, None)
    } else {
        // HTTP / HTTPS CONNECT Protocol
        trace!("Detected HTTP/HTTPS proxy connection from {}", peer_addr);
        // Read full HTTP request header
        let mut req_buf = vec![0u8; 4096];
        let bytes_read = client.read(&mut req_buf).await?;
        if bytes_read == 0 {
            return Ok(());
        }
        req_buf.truncate(bytes_read);

        let conn = handle_http_proxy(&mut client, &req_buf, &cfg.resolver).await?;
        (conn.upstream_stream, conn.target_host, conn.direct_request_payload)
    };

    // Tunnel and apply DPI circumvention
    run_tunnel(client, upstream, target_host, direct_req, cfg).await
}

async fn run_tunnel(
    mut client: TcpStream,
    mut upstream: TcpStream,
    target_host: String,
    direct_req: Option<Vec<u8>>,
    cfg: ServerConfig,
) -> Result<()> {
    let should_evade = cfg.filter.should_evade(&target_host);

    // Handle initial client payload
    let initial_data = if let Some(req) = direct_req {
        // Direct plain HTTP request was already parsed
        req
    } else {
        // Wait for first data packet from client (typically TLS ClientHello in HTTPS tunnels)
        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        buf.truncate(n);
        buf
    };

    // If TLS, check if SNI is present for better logging/metrics
    let identified_sni = parse_client_hello(&initial_data).and_then(|info| info.sni);
    let effective_host = identified_sni.as_deref().unwrap_or(&target_host);

    if should_evade {
        debug!(
            "Applying DPI circumvention to host '{}' (SNI: {:?}, Strategy: {})",
            effective_host, identified_sni, cfg.strategy.split_mode
        );
        let sent = cfg.strategy.desync_and_send(&mut upstream, &initial_data).await?;
        cfg.stats.record_bypassed();
        cfg.stats.add_bytes_sent(sent as u64);
    } else {
        trace!("Bypassing evasion for whitelisted host '{}'", effective_host);
        upstream.write_all(&initial_data).await?;
        upstream.flush().await?;
        cfg.stats.add_bytes_sent(initial_data.len() as u64);
    }

    // Now establish full bidirectional streaming for remaining traffic
    let (mut client_rd, mut client_wr) = client.into_split();
    let (mut upstream_rd, mut upstream_wr) = upstream.into_split();

    let stats_c2u = cfg.stats.clone();
    let client_to_upstream = async move {
        let mut buf = vec![0u8; 16384];
        let mut total = 0u64;
        loop {
            match client_rd.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if upstream_wr.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    total += n as u64;
                    stats_c2u.add_bytes_sent(n as u64);
                }
                Err(_) => break,
            }
        }
        let _ = upstream_wr.shutdown().await;
        total
    };

    let stats_u2c = cfg.stats.clone();
    let upstream_to_client = async move {
        let mut buf = vec![0u8; 16384];
        let mut total = 0u64;
        loop {
            match upstream_rd.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if client_wr.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    total += n as u64;
                    stats_u2c.add_bytes_received(n as u64);
                }
                Err(_) => break,
            }
        }
        let _ = client_wr.shutdown().await;
        total
    };

    tokio::select! {
        _ = client_to_upstream => {},
        _ = upstream_to_client => {},
    }

    trace!("Finished session for {}", effective_host);
    Ok(())
}
