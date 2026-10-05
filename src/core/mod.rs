// -----------------------------------------------------------------------------
// File Name:      src/core/mod.rs
// Description:    Core evasion engine module definitions and re-exports.
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

#![allow(unused_imports)]

pub mod fake;
pub mod http;
pub mod socket;
pub mod strategy;
pub mod tls;

pub use fake::generate_fake_client_hello;
pub use http::{mutate_http_request, parse_http_request, HttpEvasionOptions, HttpRequestInfo};
pub use socket::{configure_evasion_socket, send_oob_byte, set_socket_ttl};
pub use strategy::{EvasionStrategy, SegmentChunk, SplitMode};
pub use tls::{is_client_hello, mutate_sni_casing, parse_client_hello, split_into_tls_records, ClientHelloInfo};
