// -----------------------------------------------------------------------------
// File Name:      src/core/strategy.rs
// Description:    Desynchronization strategy definitions and segment planning.
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

use std::fmt;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::sleep;
use tracing::{debug, trace};

use super::fake::generate_fake_client_hello;
use super::http::{is_http_request, mutate_http_request, parse_http_request, HttpEvasionOptions};
use super::socket::{send_oob_byte, set_socket_ttl};
use super::tls::{is_client_hello, mutate_sni_casing, parse_client_hello, split_into_tls_records};

/// Strategy used for segmenting TLS ClientHello and HTTP requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SplitMode {
    /// Split payload right at the Server Name Indication (SNI) extension boundary.
    #[default]
    Sni,
    /// Split payload right in the middle of the SNI domain name.
    MidSni,
    /// Multi-split: split before SNI, inside SNI, and after SNI.
    MultiSplit,
    /// Split the first byte into a separate packet (1 + remainder).
    FirstByte,
    /// Split payload into fixed-size chunks.
    Chunk,
    /// Split payload into randomly sized chunks.
    Random,
    /// User specified byte offsets.
    Custom,
    /// No segmentation.
    None,
}

impl fmt::Display for SplitMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SplitMode::Sni => write!(f, "sni"),
            SplitMode::MidSni => write!(f, "mid-sni"),
            SplitMode::MultiSplit => write!(f, "multisplit"),
            SplitMode::FirstByte => write!(f, "first-byte"),
            SplitMode::Chunk => write!(f, "chunk"),
            SplitMode::Random => write!(f, "random"),
            SplitMode::Custom => write!(f, "custom"),
            SplitMode::None => write!(f, "none"),
        }
    }
}

/// Represents a split offset position that can be absolute or relative to the SNI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SplitOffset {
    /// Absolute byte index from beginning of the payload.
    Absolute(usize),
    /// Relative offset from the start of the SNI hostname (e.g. "1+s", "3+s").
    SniStartRelative(i32),
    /// Relative offset from the end of the SNI hostname (e.g. "-5+se", "0+se").
    SniEndRelative(i32),
    /// Center / middle of the SNI hostname.
    SniMiddle,
}

impl SplitOffset {
    /// Parse a split offset expression (e.g. "1+s", "3+s", "-5+se", "+m", "40", "sni").
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let trimmed = s.trim();
        if trimmed.eq_ignore_ascii_case("+m")
            || trimmed.eq_ignore_ascii_case("midsni")
            || trimmed.eq_ignore_ascii_case("mid-sni")
        {
            return Ok(SplitOffset::SniMiddle);
        }
        if trimmed.eq_ignore_ascii_case("sni") {
            return Ok(SplitOffset::SniStartRelative(0));
        }
        if trimmed.eq_ignore_ascii_case("first-byte") || trimmed.eq_ignore_ascii_case("firstbyte") {
            return Ok(SplitOffset::Absolute(1));
        }

        if let Some(pos) = trimmed
            .strip_suffix("+se")
            .or_else(|| trimmed.strip_suffix("+es"))
            .or_else(|| trimmed.strip_suffix("+e"))
        {
            let offset: i32 = pos
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid SNI-end relative offset '{}': {}", s, e))?;
            return Ok(SplitOffset::SniEndRelative(offset));
        }

        if let Some(pos) = trimmed.strip_suffix("+s") {
            let offset: i32 = pos
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid SNI-start relative offset '{}': {}", s, e))?;
            return Ok(SplitOffset::SniStartRelative(offset));
        }

        let abs: usize = trimmed
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid byte offset '{}': {}", s, e))?;
        Ok(SplitOffset::Absolute(abs))
    }

    /// Resolve offset to an actual byte index within the buffer.
    pub fn resolve(&self, total_len: usize, sni_start: usize, sni_end: usize) -> Option<usize> {
        let raw = match *self {
            SplitOffset::Absolute(n) => n as i64,
            SplitOffset::SniStartRelative(offset) => {
                if sni_start == 0 {
                    return None;
                }
                (sni_start as i64) + (offset as i64)
            }
            SplitOffset::SniEndRelative(offset) => {
                if sni_end == 0 || sni_end < sni_start {
                    return None;
                }
                (sni_end as i64) + (offset as i64)
            }
            SplitOffset::SniMiddle => {
                if sni_start == 0 || sni_end <= sni_start {
                    return None;
                }
                (sni_start as i64) + ((sni_end - sni_start) / 2) as i64
            }
        };

        if raw > 0 && (raw as usize) < total_len {
            Some(raw as usize)
        } else {
            None
        }
    }
}

impl fmt::Display for SplitOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SplitOffset::Absolute(n) => write!(f, "{}", n),
            SplitOffset::SniStartRelative(n) => write!(f, "{}+s", n),
            SplitOffset::SniEndRelative(n) => write!(f, "{}+se", n),
            SplitOffset::SniMiddle => write!(f, "mid-sni"),
        }
    }
}

/// Comprehensive configuration for the evasion engine per-connection.
#[derive(Debug, Clone)]
pub struct EvasionStrategy {
    /// Splitting mode for TLS/HTTP payloads.
    pub split_mode: SplitMode,
    /// Fixed chunk size in bytes (used if split_mode == Chunk).
    pub chunk_size: usize,
    /// Custom split offsets (used if split_mode == Custom).
    pub custom_offsets: Vec<usize>,
    /// Dynamic split offsets (e.g. 1+s, 3+s, -5+se, or absolute numbers).
    pub dynamic_offsets: Vec<SplitOffset>,
    /// Custom TLS record split offset (e.g. -5+se, 2, sni, mid-sni).
    pub tlsrec_offset: Option<SplitOffset>,
    /// Delay between sending successive segments in milliseconds.
    pub delay_ms: u64,
    /// Whether to send segments in reverse / out-of-order.
    pub disorder: bool,
    /// Whether to split TLS ClientHello into multiple TLS records.
    pub tls_record_split: bool,
    /// Whether to inject a fake packet before the real packet.
    pub enable_fake: bool,
    /// Fake SNI domain name for decoy packets.
    pub fake_sni: String,
    /// Time-To-Live (TTL) for decoy fake packets.
    pub fake_ttl: u32,
    /// Whether to send an Out-Of-Band (TCP Urgent) byte.
    pub enable_oob: bool,
    /// HTTP header and line evasion mutations.
    pub http_evasion: HttpEvasionOptions,
    /// Block QUIC (UDP 443) to force browser TCP fallback.
    pub block_quic: bool,
    /// Randomize SNI domain name letter casing (RFC 6066 case-insensitive).
    pub mix_sni: bool,
}

impl Default for EvasionStrategy {
    fn default() -> Self {
        Self {
            split_mode: SplitMode::Sni,
            chunk_size: 40,
            custom_offsets: Vec::new(),
            dynamic_offsets: Vec::new(),
            tlsrec_offset: None,
            delay_ms: 2,
            disorder: false,
            tls_record_split: false,
            enable_fake: false,
            fake_sni: "www.microsoft.com".to_string(),
            fake_ttl: 4,
            enable_oob: false,
            http_evasion: HttpEvasionOptions {
                mix_host: true,
                host_space_trim: true,
                extra_method_space: false,
                newline_before_host: false,
            },
            block_quic: true,
            mix_sni: false,
        }
    }
}

/// A prepared data chunk ready to be transmitted over the socket.
#[derive(Debug, Clone)]
pub struct SegmentChunk {
    pub data: Vec<u8>,
    pub delay_after: Duration,
    pub is_fake: bool,
    pub custom_ttl: Option<u32>,
}

impl EvasionStrategy {
    /// Plans and sends an initial payload (TLS ClientHello or HTTP request)
    /// to the upstream server using configured circumvention techniques.
    pub async fn desync_and_send(
        &self,
        upstream: &mut TcpStream,
        initial_data: &[u8],
    ) -> std::io::Result<usize> {
        let is_tls = is_client_hello(initial_data);
        let is_http = !is_tls && is_http_request(initial_data);

        // 1. Send Out-Of-Band (TCP Urgent) byte if enabled
        if self.enable_oob {
            trace!("Sending TCP OOB byte");
            let _ = send_oob_byte(upstream, 0x00);
            if self.delay_ms > 0 {
                sleep(Duration::from_millis(self.delay_ms)).await;
            }
        }

        // 2. Fake Decoy Packet Injection (if enabled)
        if self.enable_fake && is_tls {
            debug!(
                "Injecting fake TLS ClientHello with SNI '{}' and TTL {}",
                self.fake_sni, self.fake_ttl
            );
            let fake_bytes = generate_fake_client_hello(&self.fake_sni);

            // Set low TTL so it dies before reaching server but triggers DPI middlebox
            let _ = set_socket_ttl(upstream, self.fake_ttl);
            upstream.write_all(&fake_bytes).await?;
            upstream.flush().await?;

            // Small delay so DPI commits state
            if self.delay_ms > 0 {
                sleep(Duration::from_millis(self.delay_ms)).await;
            }

            // Restore normal TTL (e.g. 64)
            let _ = set_socket_ttl(upstream, 64);
        }

        // 3. Process Payload & Apply SNI mutations if configured
        let mut processed_payload = initial_data.to_vec();
        if self.mix_sni && is_tls {
            if let Some(info) = parse_client_hello(&processed_payload) {
                if info.sni_offset_start < info.sni_offset_end {
                    mutate_sni_casing(&mut processed_payload, info.sni_offset_start, info.sni_offset_end);
                }
            }
        }

        // 4. Process Payload & Determine Chunks
        let chunks = if is_tls {
            self.plan_tls_segments(&processed_payload)
        } else if is_http {
            self.plan_http_segments(&processed_payload)
        } else {
            // Raw passthrough for unknown protocols
            vec![SegmentChunk {
                data: processed_payload,
                delay_after: Duration::ZERO,
                is_fake: false,
                custom_ttl: None,
            }]
        };

        // 5. Transmit Chunks with Inter-segment Delays
        let total_chunks = chunks.len();
        debug!(
            "Transmitting {} segment(s) (TLS: {}, HTTP: {}, Disorder: {})",
            total_chunks, is_tls, is_http, self.disorder
        );

        let mut sent_bytes = 0;
        let mut ordered_chunks = chunks;

        if self.disorder && ordered_chunks.len() == 2 {
            // Classic two-segment reverse disorder (send segment 2, then segment 1)
            ordered_chunks.swap(0, 1);
        }

        for (idx, chunk) in ordered_chunks.iter().enumerate() {
            if let Some(ttl) = chunk.custom_ttl {
                let _ = set_socket_ttl(upstream, ttl);
            }

            upstream.write_all(&chunk.data).await?;
            upstream.flush().await?;
            sent_bytes += chunk.data.len();

            trace!(
                "Sent chunk {}/{} ({} bytes)",
                idx + 1,
                total_chunks,
                chunk.data.len()
            );

            if chunk.delay_after > Duration::ZERO && idx + 1 < total_chunks {
                sleep(chunk.delay_after).await;
            }
        }

        Ok(sent_bytes)
    }

    /// Plans segment chunks for a TLS ClientHello.
    fn plan_tls_segments(&self, buffer: &[u8]) -> Vec<SegmentChunk> {
        let delay = Duration::from_millis(self.delay_ms);

        // A. If TLS Record splitting is enabled, wrap into multiple TLS records first!
        if self.tls_record_split {
            let split_pos = if let Some(ref custom_rec) = self.tlsrec_offset {
                if let Some(info) = parse_client_hello(buffer) {
                    custom_rec
                        .resolve(buffer.len(), info.sni_offset_start, info.sni_offset_end)
                        .unwrap_or(buffer.len() / 2)
                } else {
                    buffer.len() / 2
                }
            } else {
                match self.split_mode {
                    SplitMode::FirstByte => 6, // 1st byte of handshake payload
                    SplitMode::Sni => {
                        if let Some(info) = parse_client_hello(buffer) {
                            if info.sni_offset_start > 5 {
                                info.sni_offset_start
                            } else {
                                buffer.len() / 2
                            }
                        } else {
                            buffer.len() / 2
                        }
                    }
                    SplitMode::MidSni | SplitMode::MultiSplit => {
                        if let Some(info) = parse_client_hello(buffer) {
                            if info.sni_offset_start > 0 && info.sni_offset_end > info.sni_offset_start {
                                info.sni_offset_start + (info.sni_offset_end - info.sni_offset_start) / 2
                            } else {
                                buffer.len() / 2
                            }
                        } else {
                            buffer.len() / 2
                        }
                    }
                    _ => buffer.len() / 2,
                }
            };

            if let Some((rec1, rec2)) = split_into_tls_records(buffer, split_pos) {
                debug!("Split ClientHello into 2 TLS records at offset {}", split_pos);
                return vec![
                    SegmentChunk {
                        data: rec1,
                        delay_after: delay,
                        is_fake: false,
                        custom_ttl: None,
                    },
                    SegmentChunk {
                        data: rec2,
                        delay_after: Duration::ZERO,
                        is_fake: false,
                        custom_ttl: None,
                    },
                ];
            }
        }

        // B. Standard TCP stream segmentation
        match self.split_mode {
            SplitMode::Sni => {
                if let Some(info) = parse_client_hello(buffer) {
                    if info.sni_offset_start > 0 && info.sni_offset_start < buffer.len() {
                        debug!(
                            "Splitting TLS ClientHello at SNI boundary (offset {}) for SNI {:?}",
                            info.sni_offset_start, info.sni
                        );
                        return vec![
                            SegmentChunk {
                                data: buffer[..info.sni_offset_start].to_vec(),
                                delay_after: delay,
                                is_fake: false,
                                custom_ttl: None,
                            },
                            SegmentChunk {
                                data: buffer[info.sni_offset_start..].to_vec(),
                                delay_after: Duration::ZERO,
                                is_fake: false,
                                custom_ttl: None,
                            },
                        ];
                    }
                }
                // Fallback to first-byte split if SNI offset not found
                self.split_first_byte(buffer, delay)
            }
            SplitMode::MidSni => {
                if let Some(info) = parse_client_hello(buffer) {
                    if info.sni_offset_start > 0 && info.sni_offset_end > info.sni_offset_start {
                        let mid = info.sni_offset_start + (info.sni_offset_end - info.sni_offset_start) / 2;
                        debug!(
                            "Splitting TLS ClientHello in middle of SNI (offset {}) for SNI {:?}",
                            mid, info.sni
                        );
                        return vec![
                            SegmentChunk {
                                data: buffer[..mid].to_vec(),
                                delay_after: delay,
                                is_fake: false,
                                custom_ttl: None,
                            },
                            SegmentChunk {
                                data: buffer[mid..].to_vec(),
                                delay_after: Duration::ZERO,
                                is_fake: false,
                                custom_ttl: None,
                            },
                        ];
                    }
                }
                self.split_first_byte(buffer, delay)
            }
            SplitMode::MultiSplit => {
                if let Some(info) = parse_client_hello(buffer) {
                    if info.sni_offset_start > 0 && info.sni_offset_end > info.sni_offset_start {
                        let mid = info.sni_offset_start + (info.sni_offset_end - info.sni_offset_start) / 2;
                        debug!(
                            "Multi-splitting TLS ClientHello at offsets {} and {} for SNI {:?}",
                            info.sni_offset_start, mid, info.sni
                        );
                        return vec![
                            SegmentChunk {
                                data: buffer[..info.sni_offset_start].to_vec(),
                                delay_after: delay,
                                is_fake: false,
                                custom_ttl: None,
                            },
                            SegmentChunk {
                                data: buffer[info.sni_offset_start..mid].to_vec(),
                                delay_after: delay,
                                is_fake: false,
                                custom_ttl: None,
                            },
                            SegmentChunk {
                                data: buffer[mid..].to_vec(),
                                delay_after: Duration::ZERO,
                                is_fake: false,
                                custom_ttl: None,
                            },
                        ];
                    }
                }
                self.split_first_byte(buffer, delay)
            }
            SplitMode::FirstByte => self.split_first_byte(buffer, delay),
            SplitMode::Chunk => {
                let size = if self.chunk_size == 0 { 40 } else { self.chunk_size };
                let mut chunks = Vec::new();
                let mut cursor = 0;
                while cursor < buffer.len() {
                    let end = (cursor + size).min(buffer.len());
                    chunks.push(SegmentChunk {
                        data: buffer[cursor..end].to_vec(),
                        delay_after: delay,
                        is_fake: false,
                        custom_ttl: None,
                    });
                    cursor = end;
                }
                chunks
            }
            SplitMode::Random => {
                let mut chunks = Vec::new();
                let mut cursor = 0;
                while cursor < buffer.len() {
                    let step = (rand::random::<u32>() as usize % 15) + 1;
                    let end = (cursor + step).min(buffer.len());
                    chunks.push(SegmentChunk {
                        data: buffer[cursor..end].to_vec(),
                        delay_after: delay,
                        is_fake: false,
                        custom_ttl: None,
                    });
                    cursor = end;
                }
                chunks
            }
            SplitMode::Custom => {
                let resolved_offsets = if !self.dynamic_offsets.is_empty() {
                    let (sni_start, sni_end) = parse_client_hello(buffer)
                        .map(|info| (info.sni_offset_start, info.sni_offset_end))
                        .unwrap_or((0, 0));

                    let mut list: Vec<usize> = self
                        .dynamic_offsets
                        .iter()
                        .filter_map(|off| off.resolve(buffer.len(), sni_start, sni_end))
                        .collect();
                    list.sort_unstable();
                    list.dedup();
                    list
                } else {
                    self.custom_offsets.clone()
                };

                if resolved_offsets.is_empty() {
                    return vec![SegmentChunk {
                        data: buffer.to_vec(),
                        delay_after: Duration::ZERO,
                        is_fake: false,
                        custom_ttl: None,
                    }];
                }
                let mut chunks = Vec::new();
                let mut last = 0;
                for &offset in &resolved_offsets {
                    if offset > last && offset < buffer.len() {
                        chunks.push(SegmentChunk {
                            data: buffer[last..offset].to_vec(),
                            delay_after: delay,
                            is_fake: false,
                            custom_ttl: None,
                        });
                        last = offset;
                    }
                }
                if last < buffer.len() {
                    chunks.push(SegmentChunk {
                        data: buffer[last..].to_vec(),
                        delay_after: Duration::ZERO,
                        is_fake: false,
                        custom_ttl: None,
                    });
                }
                chunks
            }
            SplitMode::None => vec![SegmentChunk {
                data: buffer.to_vec(),
                delay_after: Duration::ZERO,
                is_fake: false,
                custom_ttl: None,
            }],
        }
    }

    fn split_first_byte(&self, buffer: &[u8], delay: Duration) -> Vec<SegmentChunk> {
        if buffer.len() <= 1 {
            return vec![SegmentChunk {
                data: buffer.to_vec(),
                delay_after: Duration::ZERO,
                is_fake: false,
                custom_ttl: None,
            }];
        }

        vec![
            SegmentChunk {
                data: buffer[..1].to_vec(),
                delay_after: delay,
                is_fake: false,
                custom_ttl: None,
            },
            SegmentChunk {
                data: buffer[1..].to_vec(),
                delay_after: Duration::ZERO,
                is_fake: false,
                custom_ttl: None,
            },
        ]
    }

    /// Plans segment chunks for an HTTP request.
    fn plan_http_segments(&self, buffer: &[u8]) -> Vec<SegmentChunk> {
        let delay = Duration::from_millis(self.delay_ms);
        let mutated = mutate_http_request(buffer, &self.http_evasion);

        // Split after the request line or before Host
        if let Some(info) = parse_http_request(&mutated) {
            if let Some(host_off) = info.host_header_offset {
                if host_off > 0 && host_off < mutated.len() {
                    return vec![
                        SegmentChunk {
                            data: mutated[..host_off].to_vec(),
                            delay_after: delay,
                            is_fake: false,
                            custom_ttl: None,
                        },
                        SegmentChunk {
                            data: mutated[host_off..].to_vec(),
                            delay_after: Duration::ZERO,
                            is_fake: false,
                            custom_ttl: None,
                        },
                    ];
                }
            }
        }

        // Default: split first 2 bytes
        if mutated.len() > 2 {
            vec![
                SegmentChunk {
                    data: mutated[..2].to_vec(),
                    delay_after: delay,
                    is_fake: false,
                    custom_ttl: None,
                },
                SegmentChunk {
                    data: mutated[2..].to_vec(),
                    delay_after: Duration::ZERO,
                    is_fake: false,
                    custom_ttl: None,
                },
            ]
        } else {
            vec![SegmentChunk {
                data: mutated,
                delay_after: Duration::ZERO,
                is_fake: false,
                custom_ttl: None,
            }]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::tls::tests::create_test_client_hello;

    #[test]
    fn test_mid_sni_split() {
        let pkt = create_test_client_hello("example.com");
        let strat = EvasionStrategy {
            split_mode: SplitMode::MidSni,
            delay_ms: 2,
            ..Default::default()
        };
        let segments = strat.plan_tls_segments(&pkt);
        assert_eq!(segments.len(), 2);
        let reconstructed: Vec<u8> = segments.iter().flat_map(|s| s.data.clone()).collect();
        assert_eq!(reconstructed, pkt);
    }

    #[test]
    fn test_multi_split() {
        let pkt = create_test_client_hello("example.com");
        let strat = EvasionStrategy {
            split_mode: SplitMode::MultiSplit,
            delay_ms: 2,
            ..Default::default()
        };
        let segments = strat.plan_tls_segments(&pkt);
        assert_eq!(segments.len(), 3);
        let reconstructed: Vec<u8> = segments.iter().flat_map(|s| s.data.clone()).collect();
        assert_eq!(reconstructed, pkt);
    }

    #[test]
    fn test_mid_sni_tls_record_split() {
        let pkt = create_test_client_hello("example.com");
        let strat = EvasionStrategy {
            split_mode: SplitMode::MidSni,
            tls_record_split: true,
            delay_ms: 2,
            ..Default::default()
        };
        let segments = strat.plan_tls_segments(&pkt);
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].data[0], 0x16);
        assert_eq!(segments[1].data[0], 0x16);
    }

    #[test]
    fn test_split_offset_parsing() {
        assert_eq!(SplitOffset::parse("40").unwrap(), SplitOffset::Absolute(40));
        assert_eq!(SplitOffset::parse("1+s").unwrap(), SplitOffset::SniStartRelative(1));
        assert_eq!(SplitOffset::parse("3+s").unwrap(), SplitOffset::SniStartRelative(3));
        assert_eq!(SplitOffset::parse("-5+se").unwrap(), SplitOffset::SniEndRelative(-5));
        assert_eq!(SplitOffset::parse("+m").unwrap(), SplitOffset::SniMiddle);
        assert_eq!(SplitOffset::parse("mid-sni").unwrap(), SplitOffset::SniMiddle);
        assert_eq!(SplitOffset::parse("sni").unwrap(), SplitOffset::SniStartRelative(0));
        assert_eq!(SplitOffset::parse("first-byte").unwrap(), SplitOffset::Absolute(1));
    }

    #[test]
    fn test_dynamic_custom_offsets_tls() {
        let pkt = create_test_client_hello("example.com");
        let strat = EvasionStrategy {
            split_mode: SplitMode::Custom,
            dynamic_offsets: vec![
                SplitOffset::parse("1+s").unwrap(),
                SplitOffset::parse("3+s").unwrap(),
                SplitOffset::parse("6+s").unwrap(),
            ],
            delay_ms: 2,
            ..Default::default()
        };
        let segments = strat.plan_tls_segments(&pkt);
        // 3 split points => 4 chunks
        assert_eq!(segments.len(), 4);
        let reconstructed: Vec<u8> = segments.iter().flat_map(|s| s.data.clone()).collect();
        assert_eq!(reconstructed, pkt);
    }

    #[test]
    fn test_custom_tlsrec_offset() {
        let pkt = create_test_client_hello("example.com");
        let strat = EvasionStrategy {
            split_mode: SplitMode::Sni,
            tls_record_split: true,
            tlsrec_offset: Some(SplitOffset::parse("-5+se").unwrap()),
            delay_ms: 2,
            ..Default::default()
        };
        let segments = strat.plan_tls_segments(&pkt);
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].data[0], 0x16);
        assert_eq!(segments[1].data[0], 0x16);
    }
}
