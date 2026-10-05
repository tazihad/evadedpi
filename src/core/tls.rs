// -----------------------------------------------------------------------------
// File Name:      src/core/tls.rs
// Description:    TLS ClientHello inspection, SNI extraction, and record fragmentation.
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

use tracing::trace;

/// Information extracted from a TLS ClientHello packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloInfo {
    /// The Server Name Indication (SNI) hostname, if found.
    pub sni: Option<String>,
    /// Byte offset in the input buffer where the SNI hostname string begins.
    pub sni_offset_start: usize,
    /// Byte offset in the input buffer where the SNI hostname string ends.
    pub sni_offset_end: usize,
    /// Byte offset in the input buffer where the SNI extension starts.
    pub sni_ext_offset: usize,
    /// Total length of the TLS record payload.
    pub record_len: usize,
    /// The legacy TLS record version.
    pub record_version: (u8, u8),
}

/// Helper parser to navigate byte slices safely without panic.
struct ByteReader<'a> {
    data: &'a [u8],
    cursor: usize,
}

impl<'a> ByteReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, cursor: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.cursor)
    }

    fn position(&self) -> usize {
        self.cursor
    }

    fn skip(&mut self, n: usize) -> bool {
        if self.remaining() >= n {
            self.cursor += n;
            true
        } else {
            false
        }
    }

    fn read_u8(&mut self) -> Option<u8> {
        if self.cursor < self.data.len() {
            let b = self.data[self.cursor];
            self.cursor += 1;
            Some(b)
        } else {
            None
        }
    }

    fn read_u16(&mut self) -> Option<u16> {
        if self.remaining() >= 2 {
            let val = u16::from_be_bytes([self.data[self.cursor], self.data[self.cursor + 1]]);
            self.cursor += 2;
            Some(val)
        } else {
            None
        }
    }

    fn read_u24(&mut self) -> Option<usize> {
        if self.remaining() >= 3 {
            let val = ((self.data[self.cursor] as usize) << 16)
                | ((self.data[self.cursor + 1] as usize) << 8)
                | (self.data[self.cursor + 2] as usize);
            self.cursor += 3;
            Some(val)
        } else {
            None
        }
    }

    fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() >= n {
            let slice = &self.data[self.cursor..self.cursor + n];
            self.cursor += n;
            Some(slice)
        } else {
            None
        }
    }
}

/// Parse a raw buffer to check if it contains a TLS ClientHello,
/// and extract detailed SNI and structural offsets.
pub fn parse_client_hello(buffer: &[u8]) -> Option<ClientHelloInfo> {
    let mut reader = ByteReader::new(buffer);

    // 1. TLS Record Header (5 bytes)
    // ContentType: 0x16 (Handshake)
    let content_type = reader.read_u8()?;
    if content_type != 0x16 {
        return None;
    }

    // Legacy record version (e.g. 0x03, 0x01 for TLS 1.0 or 0x03, 0x03 for TLS 1.2)
    let major = reader.read_u8()?;
    let minor = reader.read_u8()?;
    let record_version = (major, minor);

    // Record length
    let record_len = reader.read_u16()? as usize;
    if reader.remaining() < record_len {
        trace!(
            "Buffer contains partial TLS record (have {}, need {})",
            reader.remaining(),
            record_len
        );
        // We still attempt to parse what we have if long enough for SNI
    }

    // 2. Handshake Header (4 bytes)
    // Handshake Type: 0x01 (ClientHello)
    let handshake_type = reader.read_u8()?;
    if handshake_type != 0x01 {
        return None;
    }

    // Handshake length (3 bytes)
    let _handshake_len = reader.read_u24()?;

    // Client version (2 bytes)
    if !reader.skip(2) {
        return None;
    }

    // Random (32 bytes)
    if !reader.skip(32) {
        return None;
    }

    // Session ID length (1 byte) + Session ID
    let session_id_len = reader.read_u8()? as usize;
    if !reader.skip(session_id_len) {
        return None;
    }

    // Cipher Suites length (2 bytes) + Cipher Suites
    let cipher_suites_len = reader.read_u16()? as usize;
    if !reader.skip(cipher_suites_len) {
        return None;
    }

    // Compression Methods length (1 byte) + Compression Methods
    let comp_methods_len = reader.read_u8()? as usize;
    if !reader.skip(comp_methods_len) {
        return None;
    }

    // Extensions length (2 bytes)
    let extensions_len = reader.read_u16()? as usize;
    let extensions_end = reader.position() + extensions_len;

    // 3. Scan extensions for SNI (Type = 0x0000)
    let mut found_sni = None;
    let mut sni_offset_start = 0;
    let mut sni_offset_end = 0;
    let mut sni_ext_offset = 0;

    while reader.position() + 4 <= extensions_end && reader.position() + 4 <= buffer.len() {
        let ext_start = reader.position();
        let ext_type = reader.read_u16()?;
        let ext_len = reader.read_u16()? as usize;

        if reader.position() + ext_len > buffer.len() {
            break;
        }

        if ext_type == 0x0000 {
            // Found Server Name Indication (SNI) extension!
            sni_ext_offset = ext_start;
            let ext_data_reader_start = reader.position();

            // SNI extension structure:
            // Server Name list length (2 bytes)
            if let Some(_sni_list_len) = reader.read_u16() {
                // Server Name type (1 byte): 0x00 is host_name
                if let Some(sni_type) = reader.read_u8() {
                    if sni_type == 0x00 {
                        // Host name length (2 bytes)
                        if let Some(host_len) = reader.read_u16() {
                            let host_len = host_len as usize;
                            let host_start = reader.position();
                            if let Some(host_bytes) = reader.read_bytes(host_len) {
                                if let Ok(host_str) = std::str::from_utf8(host_bytes) {
                                    found_sni = Some(host_str.to_string());
                                    sni_offset_start = host_start;
                                    sni_offset_end = host_start + host_len;
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            // Restore position to after this extension if parsing inside failed
            reader.cursor = ext_data_reader_start + ext_len;
        } else {
            // Skip other extension
            reader.skip(ext_len);
        }
    }

    Some(ClientHelloInfo {
        sni: found_sni,
        sni_offset_start,
        sni_offset_end,
        sni_ext_offset,
        record_len,
        record_version,
    })
}

/// Checks if the payload starts with a valid TLS ClientHello.
pub fn is_client_hello(buffer: &[u8]) -> bool {
    parse_client_hello(buffer).is_some()
}

/// Mutates the SNI hostname inside the buffer by randomizing letter casing (e.g. `youtube.com` -> `yOuTuBe.cOm`).
/// RFC 6066 states SNI hostnames are ASCII case-insensitive, but DPI filters often use case-sensitive string matching.
pub fn mutate_sni_casing(buffer: &mut [u8], start: usize, end: usize) {
    if start >= end || end > buffer.len() {
        return;
    }
    for (i, b) in buffer[start..end].iter_mut().enumerate() {
        if b.is_ascii_alphabetic() {
            if (i % 2 == 0) ^ (rand::random::<bool>()) {
                *b = b.to_ascii_uppercase();
            } else {
                *b = b.to_ascii_lowercase();
            }
        }
    }
}

/// Splits a TLS ClientHello packet into multiple TLS records (`--tlsrec`).
///
/// Under RFC 5246 (TLS 1.2) and RFC 8446 (TLS 1.3), a handshake message
/// MAY be split across multiple TLS records. Many DPI engines fail to inspect
/// fragmented records or only inspect the first record.
pub fn split_into_tls_records(buffer: &[u8], split_pos: usize) -> Option<(Vec<u8>, Vec<u8>)> {
    if buffer.len() < 9 || split_pos <= 5 || split_pos >= buffer.len() {
        return None;
    }

    // Verify it's a TLS Handshake record (0x16)
    if buffer[0] != 0x16 {
        return None;
    }

    let version = [buffer[1], buffer[2]];
    let handshake_payload = &buffer[5..]; // The entire handshake data

    // The split position in the handshake payload
    let split_payload_pos = split_pos.saturating_sub(5);
    if split_payload_pos == 0 || split_payload_pos >= handshake_payload.len() {
        return None;
    }

    let part1_payload = &handshake_payload[..split_payload_pos];
    let part2_payload = &handshake_payload[split_payload_pos..];

    // Build Record 1
    let mut rec1 = Vec::with_capacity(5 + part1_payload.len());
    rec1.push(0x16); // Handshake
    rec1.extend_from_slice(&version);
    rec1.extend_from_slice(&(part1_payload.len() as u16).to_be_bytes());
    rec1.extend_from_slice(part1_payload);

    // Build Record 2
    let mut rec2 = Vec::with_capacity(5 + part2_payload.len());
    rec2.push(0x16); // Handshake
    rec2.extend_from_slice(&version);
    rec2.extend_from_slice(&(part2_payload.len() as u16).to_be_bytes());
    rec2.extend_from_slice(part2_payload);

    Some((rec1, rec2))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // A minimal valid TLS ClientHello with SNI "example.com"
    pub(crate) fn create_test_client_hello(hostname: &str) -> Vec<u8> {
        let host_bytes = hostname.as_bytes();
        let sni_ext_len = 2 + 1 + 2 + host_bytes.len(); // list_len + type + host_len + host
        let _ext_len = 2 + 2 + sni_ext_len; // ext_type + ext_len + sni_ext

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0x0000u16.to_be_bytes()); // Type: Server Name
        extensions.extend_from_slice(&(sni_ext_len as u16).to_be_bytes()); // Ext length
        extensions.extend_from_slice(&((1 + 2 + host_bytes.len()) as u16).to_be_bytes()); // Server Name List Length
        extensions.push(0x00); // Host Name type
        extensions.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        extensions.extend_from_slice(host_bytes);

        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        let handshake_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensions.len();
        handshake.extend_from_slice(&[
            (handshake_len >> 16) as u8,
            (handshake_len >> 8) as u8,
            handshake_len as u8,
        ]);
        handshake.extend_from_slice(&[0x03, 0x03]); // Client Version: TLS 1.2
        handshake.extend_from_slice(&[0xaa; 32]); // Random
        handshake.push(0x00); // Session ID len = 0
        handshake.extend_from_slice(&2u16.to_be_bytes()); // Cipher suites len
        handshake.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        handshake.push(0x01); // Compression methods len
        handshake.push(0x00); // None
        handshake.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        handshake.extend_from_slice(&extensions);

        let mut record = Vec::new();
        record.push(0x16); // Handshake record
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }

    #[test]
    fn test_parse_valid_client_hello() {
        let pkt = create_test_client_hello("example.com");
        let info = parse_client_hello(&pkt).expect("Should parse ClientHello");

        assert_eq!(info.sni.as_deref(), Some("example.com"));
        assert!(info.sni_offset_start > 0);
        assert!(info.sni_offset_end > info.sni_offset_start);
        assert_eq!(&pkt[info.sni_offset_start..info.sni_offset_end], b"example.com");
    }

    #[test]
    fn test_split_into_tls_records() {
        let pkt = create_test_client_hello("sub.blocked.org");
        let info = parse_client_hello(&pkt).unwrap();

        // Split right at SNI offset
        let (rec1, rec2) = split_into_tls_records(&pkt, info.sni_offset_start).unwrap();

        assert_eq!(rec1[0], 0x16);
        assert_eq!(rec2[0], 0x16);
        // Combined length of payload equals original payload + 5 bytes overhead for 2nd header
        assert_eq!(rec1.len() + rec2.len(), pkt.len() + 5);
    }

    #[test]
    fn test_mutate_sni_casing() {
        let mut pkt = create_test_client_hello("youtube.com");
        let info = parse_client_hello(&pkt).unwrap();
        mutate_sni_casing(&mut pkt, info.sni_offset_start, info.sni_offset_end);
        let mutated_sni = &pkt[info.sni_offset_start..info.sni_offset_end];
        // Must still match case-insensitively
        assert_eq!(
            std::str::from_utf8(mutated_sni).unwrap().to_ascii_lowercase(),
            "youtube.com"
        );
    }
}
