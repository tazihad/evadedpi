// -----------------------------------------------------------------------------
// File Name:      src/proxy/http_proxy.rs
// Description:    HTTP CONNECT tunneling and plain HTTP forward proxy handler.
// Author:         @tazihad
// Website:        https://zihad.com.bd
// License:        MIT License
// -----------------------------------------------------------------------------

// MIT License
//
// Copyright (c) 2024 @tazihad
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

use anyhow::{anyhow, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::core::socket::configure_evasion_socket;
use crate::dns::Resolver;

pub struct HttpProxyConnection {
    pub target_host: String,
    pub target_port: u16,
    pub upstream_stream: TcpStream,
    pub is_connect_tunnel: bool,
    /// If direct HTTP (non-CONNECT), contains the initial request to forward.
    pub direct_request_payload: Option<Vec<u8>>,
}

/// Handle HTTP CONNECT tunneling or direct HTTP proxy requests.
pub async fn handle_http_proxy(
    client: &mut TcpStream,
    initial_buffer: &[u8],
    resolver: &Resolver,
) -> Result<HttpProxyConnection> {
    let header_str = std::str::from_utf8(initial_buffer)
        .map_err(|_| anyhow!("Invalid non-UTF8 HTTP proxy request"))?;

    let mut lines = header_str.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| anyhow!("Empty HTTP request line"))?;

    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow!("Missing HTTP method"))?;
    let target = parts
        .next()
        .ok_or_else(|| anyhow!("Missing HTTP target"))?;

    if method.eq_ignore_ascii_case("CONNECT") {
        // HTTPS Tunneling: CONNECT host:port HTTP/1.1
        let (host, port) = parse_host_port(target, 443)?;
        debug!("HTTP CONNECT requested to {}:{}", host, port);

        let target_addr = resolver.resolve_target(&host, port).await?;
        let upstream = match TcpStream::connect(target_addr).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to connect to upstream {}: {}", target_addr, e);
                client
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    .await?;
                return Err(e.into());
            }
        };

        configure_evasion_socket(&upstream)?;

        // Send 200 Connection Established to client
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        Ok(HttpProxyConnection {
            target_host: host,
            target_port: port,
            upstream_stream: upstream,
            is_connect_tunnel: true,
            direct_request_payload: None,
        })
    } else {
        // Direct HTTP Forwarding (GET http://host/path HTTP/1.1)
        let (host, port, relative_uri) = parse_absolute_uri(target)?;
        debug!("Direct HTTP proxy requested: {} http://{}:{}{}", method, host, port, relative_uri);

        let target_addr = resolver.resolve_target(&host, port).await?;
        let upstream = TcpStream::connect(target_addr).await?;
        configure_evasion_socket(&upstream)?;

        // Rewrite request line to use relative URI
        let modified_req = rewrite_request_line(initial_buffer, method, &relative_uri)?;

        Ok(HttpProxyConnection {
            target_host: host,
            target_port: port,
            upstream_stream: upstream,
            is_connect_tunnel: false,
            direct_request_payload: Some(modified_req),
        })
    }
}

fn parse_host_port(target: &str, default_port: u16) -> Result<(String, u16)> {
    if let Some(idx) = target.rfind(':') {
        let host = &target[..idx];
        let port: u16 = target[idx + 1..].parse().map_err(|_| anyhow!("Invalid port"))?;
        Ok((host.to_string(), port))
    } else {
        Ok((target.to_string(), default_port))
    }
}

fn parse_absolute_uri(uri: &str) -> Result<(String, u16, String)> {
    let without_scheme = if let Some(stripped) = uri.strip_prefix("http://") {
        stripped
    } else if let Some(stripped) = uri.strip_prefix("https://") {
        stripped
    } else {
        uri
    };

    let (host_port, path) = if let Some(idx) = without_scheme.find('/') {
        (&without_scheme[..idx], &without_scheme[idx..])
    } else {
        (without_scheme, "/")
    };

    let (host, port) = parse_host_port(host_port, 80)?;
    Ok((host, port, path.to_string()))
}

fn rewrite_request_line(buffer: &[u8], method: &str, relative_uri: &str) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(buffer)?;
    if let Some(crlf_pos) = text.find("\r\n") {
        let rest = &buffer[crlf_pos..];
        let new_first_line = format!("{} {} HTTP/1.1", method, relative_uri);
        let mut rewritten = Vec::with_capacity(new_first_line.len() + rest.len());
        rewritten.extend_from_slice(new_first_line.as_bytes());
        rewritten.extend_from_slice(rest);
        Ok(rewritten)
    } else {
        Ok(buffer.to_vec())
    }
}
