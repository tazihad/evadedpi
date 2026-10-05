// EvadeDPI: Modern Deep Packet Inspection Circumvention Engine
// RFC 1928 SOCKS5 Protocol Handler

use anyhow::{anyhow, Result};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::core::socket::configure_evasion_socket;
use crate::dns::Resolver;

/// Result of a successful SOCKS5 handshake and connection to upstream.
pub struct Socks5Connection {
    pub target_host: String,
    pub target_port: u16,
    pub upstream_stream: TcpStream,
}

/// Handle SOCKS5 handshake, address parsing, and upstream connection.
pub async fn handle_socks5(
    client: &mut TcpStream,
    resolver: &Resolver,
    block_quic: bool,
) -> Result<Socks5Connection> {
    // 1. Negotiation of Authentication Method
    // We already peeked 0x05, now read NMETHODS
    let mut header = [0u8; 2]; // VER, NMETHODS
    client.read_exact(&mut header).await?;

    if header[0] != 0x05 {
        return Err(anyhow!("Invalid SOCKS version: {}", header[0]));
    }

    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    client.read_exact(&mut methods).await?;

    // We only support NO AUTH (0x00)
    if !methods.contains(&0x00) {
        client.write_all(&[0x05, 0xff]).await?; // No acceptable methods
        return Err(anyhow!("No acceptable SOCKS5 authentication method"));
    }

    // Reply: VER = 0x05, METHOD = 0x00 (NO AUTH)
    client.write_all(&[0x05, 0x00]).await?;

    // 2. Client Request (VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT)
    let mut req_header = [0u8; 4];
    client.read_exact(&mut req_header).await?;

    let cmd = req_header[1];
    let atyp = req_header[3];

    // Check CMD
    if cmd == 0x03 {
        // UDP ASSOCIATE
        if block_quic {
            debug!("Blocking SOCKS5 UDP ASSOCIATE request to disable QUIC/HTTP3");
            client.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err(anyhow!("UDP ASSOCIATE blocked (QUIC blocking enabled)"));
        }
    }

    if cmd != 0x01 {
        // Only CONNECT (0x01) supported
        client.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Err(anyhow!("Unsupported SOCKS5 command: 0x{:02x}", cmd));
    }

    // Parse Address
    let (target_host, target_addr) = match atyp {
        0x01 => {
            // IPv4 (4 bytes)
            let mut ip_bytes = [0u8; 4];
            client.read_exact(&mut ip_bytes).await?;
            let ip = Ipv4Addr::from(ip_bytes);
            let mut port_bytes = [0u8; 2];
            client.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);
            let addr = SocketAddr::new(ip.into(), port);
            (ip.to_string(), addr)
        }
        0x03 => {
            // Domain name (1 byte length + string)
            let len = client.read_u8().await? as usize;
            let mut domain_bytes = vec![0u8; len];
            client.read_exact(&mut domain_bytes).await?;
            let domain = String::from_utf8(domain_bytes)?;
            let mut port_bytes = [0u8; 2];
            client.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);

            // Resolve domain using our unified resolver (DoH / cache)
            let addr = resolver.resolve_target(&domain, port).await?;
            (domain, addr)
        }
        0x04 => {
            // IPv6 (16 bytes)
            let mut ip_bytes = [0u8; 16];
            client.read_exact(&mut ip_bytes).await?;
            let ip = Ipv6Addr::from(ip_bytes);
            let mut port_bytes = [0u8; 2];
            client.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);
            let addr = SocketAddr::new(ip.into(), port);
            (ip.to_string(), addr)
        }
        _ => {
            client.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err(anyhow!("Unsupported SOCKS5 ATYP: 0x{:02x}", atyp));
        }
    };

    debug!("SOCKS5 CONNECT target: {}:{}", target_host, target_addr.port());

    // 3. Connect to Upstream Target
    let upstream = match TcpStream::connect(target_addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to connect to upstream {}: {}", target_addr, e);
            client.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err(e.into());
        }
    };

    configure_evasion_socket(&upstream)?;

    // Reply Success: VER = 5, REP = 0 (Success), RSV = 0, ATYP = 1 (IPv4 0.0.0.0:0)
    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    Ok(Socks5Connection {
        target_host,
        target_port: target_addr.port(),
        upstream_stream: upstream,
    })
}
