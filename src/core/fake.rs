// -----------------------------------------------------------------------------
// File Name:      src/core/fake.rs
// Description:    Decoy (fake) TLS ClientHello payload generation for stateful DPI desynchronization.
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


/// Generates a valid, realistic TLS 1.2/1.3 ClientHello payload with the specified fake SNI.
///
/// This payload is transmitted with a low TTL (or past TCP SEQ) to confuse stateful DPI
/// filters (e.g. TSPU, GFW) into whitelisting or ignoring the connection before the
/// real ClientHello arrives.
pub fn generate_fake_client_hello(fake_sni: &str) -> Vec<u8> {
    let mut random_bytes = [0u8; 32];
    for b in random_bytes.iter_mut() {
        *b = rand::random::<u8>();
    }

    let host_bytes = fake_sni.as_bytes();
    let sni_ext_len = 2 + 1 + 2 + host_bytes.len(); // list_len + type + host_len + host
    let mut extensions = Vec::with_capacity(256);

    // 1. SNI Extension (Type 0x0000)
    extensions.extend_from_slice(&0x0000u16.to_be_bytes());
    extensions.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
    extensions.extend_from_slice(&((1 + 2 + host_bytes.len()) as u16).to_be_bytes());
    extensions.push(0x00); // Host Name type
    extensions.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    extensions.extend_from_slice(host_bytes);

    // 2. EC Point Formats (Type 0x000b)
    extensions.extend_from_slice(&0x000bu16.to_be_bytes());
    extensions.extend_from_slice(&2u16.to_be_bytes());
    extensions.push(1); // len = 1
    extensions.push(0x00); // uncompressed

    // 3. Supported Groups (curves) Extension (Type 0x000a)
    let supported_groups: [u16; 3] = [0x001d, 0x0017, 0x0018]; // x25519, secp256r1, secp384r1
    extensions.extend_from_slice(&0x000au16.to_be_bytes());
    let groups_len = 2 + supported_groups.len() * 2;
    extensions.extend_from_slice(&(groups_len as u16).to_be_bytes());
    extensions.extend_from_slice(&((supported_groups.len() * 2) as u16).to_be_bytes());
    for group in supported_groups {
        extensions.extend_from_slice(&group.to_be_bytes());
    }

    // 4. Signature Algorithms Extension (Type 0x000d)
    let sig_algs: [u16; 6] = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501];
    extensions.extend_from_slice(&0x000du16.to_be_bytes());
    let sig_len = 2 + sig_algs.len() * 2;
    extensions.extend_from_slice(&(sig_len as u16).to_be_bytes());
    extensions.extend_from_slice(&((sig_algs.len() * 2) as u16).to_be_bytes());
    for s in sig_algs {
        extensions.extend_from_slice(&s.to_be_bytes());
    }

    // 5. Construct Handshake Message
    let ciphers: [u16; 6] = [0xc02f, 0xc030, 0xc02b, 0xc02c, 0xcca8, 0xcca9];
    let mut handshake = Vec::with_capacity(512);
    handshake.push(0x01); // ClientHello

    let handshake_len = 2 // version
        + 32 // random
        + 1 // session id len
        + 2 + (ciphers.len() * 2) // ciphers
        + 1 + 1 // compression
        + 2 + extensions.len(); // extensions

    // 3-byte handshake length
    handshake.extend_from_slice(&[
        (handshake_len >> 16) as u8,
        (handshake_len >> 8) as u8,
        handshake_len as u8,
    ]);

    // Client version: 0x0303 (TLS 1.2 for compatibility)
    handshake.extend_from_slice(&[0x03, 0x03]);
    // Random bytes
    handshake.extend_from_slice(&random_bytes);
    // Session ID length: 0
    handshake.push(0x00);
    // Cipher suites
    handshake.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
    for c in ciphers {
        handshake.extend_from_slice(&c.to_be_bytes());
    }
    // Compression methods
    handshake.push(0x01);
    handshake.push(0x00);
    // Extensions
    handshake.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    handshake.extend_from_slice(&extensions);

    // 5. Construct TLS Record Header (0x16, 0x03, 0x01, len)
    let mut record = Vec::with_capacity(5 + handshake.len());
    record.push(0x16); // Handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record layer version
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::tls::parse_client_hello;

    #[test]
    fn test_generate_fake_client_hello() {
        let fake = generate_fake_client_hello("www.microsoft.com");
        let info = parse_client_hello(&fake).expect("Fake ClientHello must be valid TLS");
        assert_eq!(info.sni.as_deref(), Some("www.microsoft.com"));
    }
}
