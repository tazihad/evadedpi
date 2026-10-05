// EvadeDPI: Core Engine Module Exports
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
pub use tls::{is_client_hello, parse_client_hello, split_into_tls_records, ClientHelloInfo};
