// EvadeDPI: Modern Deep Packet Inspection Circumvention Engine
// Desynchronization Strategy Definitions and Segment Planning

use std::fmt;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::sleep;
use tracing::{debug, trace};

use super::fake::generate_fake_client_hello;
use super::http::{is_http_request, mutate_http_request, parse_http_request, HttpEvasionOptions};
use super::socket::{send_oob_byte, set_socket_ttl};
use super::tls::{is_client_hello, parse_client_hello, split_into_tls_records};

/// Strategy used for segmenting TLS ClientHello and HTTP requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SplitMode {
    /// Split payload right at the Server Name Indication (SNI) extension boundary.
    #[default]
    Sni,
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
            SplitMode::FirstByte => write!(f, "first-byte"),
            SplitMode::Chunk => write!(f, "chunk"),
            SplitMode::Random => write!(f, "random"),
            SplitMode::Custom => write!(f, "custom"),
            SplitMode::None => write!(f, "none"),
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
}

impl Default for EvasionStrategy {
    fn default() -> Self {
        Self {
            split_mode: SplitMode::Sni,
            chunk_size: 40,
            custom_offsets: Vec::new(),
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

        // 3. Process Payload & Determine Chunks
        let chunks = if is_tls {
            self.plan_tls_segments(initial_data)
        } else if is_http {
            self.plan_http_segments(initial_data)
        } else {
            // Raw passthrough for unknown protocols
            vec![SegmentChunk {
                data: initial_data.to_vec(),
                delay_after: Duration::ZERO,
                is_fake: false,
                custom_ttl: None,
            }]
        };

        // 4. Transmit Chunks with Inter-segment Delays
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
            let split_pos = match self.split_mode {
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
                _ => buffer.len() / 2,
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
                if self.custom_offsets.is_empty() {
                    return vec![SegmentChunk {
                        data: buffer.to_vec(),
                        delay_after: Duration::ZERO,
                        is_fake: false,
                        custom_ttl: None,
                    }];
                }
                let mut chunks = Vec::new();
                let mut last = 0;
                for &offset in &self.custom_offsets {
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
