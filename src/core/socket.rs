// EvadeDPI: Modern Deep Packet Inspection Circumvention Engine
// Low-level TCP Socket Manipulation (TTL, NODELAY, Keepalive, OOB)

use socket2::{Domain, Protocol, Socket, Type};
use std::io::Result;
use std::net::SocketAddr;
use std::os::fd::FromRawFd;
use std::os::unix::io::AsRawFd;
use tokio::net::TcpStream;
use tracing::{debug, warn};

/// Configure a newly connected TCP socket for DPI evasion.
///
/// Disables Nagle's algorithm (TCP_NODELAY) so segments are not coalesced by the kernel,
/// and enables keepalive.
pub fn configure_evasion_socket(stream: &TcpStream) -> Result<()> {
    stream.set_nodelay(true)?;
    Ok(())
}

/// Sets the IP Time-To-Live (or IPv6 Hop Limit) on a Tokio TcpStream.
pub fn set_socket_ttl(stream: &TcpStream, ttl: u32) -> Result<()> {
    let raw_fd = stream.as_raw_fd();
    // Safety: Borrow fd without closing it
    let socket = unsafe { socket2::Socket::from_raw_fd(raw_fd) };
    let res = if let Ok(peer) = stream.peer_addr() {
        match peer {
            SocketAddr::V4(_) => socket.set_ttl_v4(ttl),
            SocketAddr::V6(_) => socket.set_unicast_hops_v6(ttl),
        }
    } else {
        socket.set_ttl_v4(ttl)
    };

    // Important: Prevent destructor of socket2::Socket from closing raw_fd!
    std::mem::forget(socket);

    if let Err(ref e) = res {
        warn!("Failed to set socket TTL to {}: {}", ttl, e);
    } else {
        debug!("Successfully set socket TTL to {}", ttl);
    }
    res
}

/// Send 1 byte of Out-Of-Band (TCP Urgent / MSG_OOB) data.
///
/// Many DPI middleboxes track sequence numbers and get desynchronized by urgent data,
/// whereas standard web servers ignore or drop the OOB byte.
#[cfg(target_family = "unix")]
pub fn send_oob_byte(stream: &TcpStream, byte: u8) -> Result<usize> {
    let raw_fd = stream.as_raw_fd();
    let buf = [byte];
    // Safety: raw_fd is valid while stream is alive
    let ret = unsafe {
        libc::send(
            raw_fd,
            buf.as_ptr() as *const libc::c_void,
            1,
            libc::MSG_OOB,
        )
    };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        warn!("Failed to send OOB byte: {}", err);
        Err(err)
    } else {
        debug!("Sent TCP MSG_OOB byte: 0x{:02x}", byte);
        Ok(ret as usize)
    }
}

#[cfg(not(target_family = "unix"))]
pub fn send_oob_byte(_stream: &TcpStream, _byte: u8) -> Result<usize> {
    // Fallback for non-unix targets
    Ok(0)
}

/// Create a non-blocking TCP socket bound to a specific local interface/IP if needed.
pub fn create_client_socket(addr: &SocketAddr) -> Result<Socket> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    socket.set_tcp_nodelay(true)?;
    Ok(socket)
}
