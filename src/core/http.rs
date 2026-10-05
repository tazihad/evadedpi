// EvadeDPI: Modern Deep Packet Inspection Circumvention Engine
// Core HTTP Request Parsing and Evasion Mutations

/// Options for mutating HTTP headers and requests.
#[derive(Debug, Clone, Default)]
pub struct HttpEvasionOptions {
    /// Modify Host header casing (e.g., `Host` -> `hoSt` or `hOsT`).
    pub mix_host: bool,
    /// Trim space after Host: header (e.g., `Host: example.com` -> `Host:example.com`).
    pub host_space_trim: bool,
    /// Add an extra space between HTTP method and URI (e.g., `GET  /path HTTP/1.1`).
    pub extra_method_space: bool,
    /// Prepend a newline before the Host header.
    pub newline_before_host: bool,
}

/// Parsed HTTP request summary.
#[derive(Debug, Clone)]
pub struct HttpRequestInfo {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub host: Option<String>,
    pub host_header_offset: Option<usize>,
    pub host_value_offset: Option<usize>,
}

/// Detects if the buffer starts with a standard HTTP method.
pub fn is_http_request(buffer: &[u8]) -> bool {
    let methods: &[&[u8]] = &[
        b"GET ", b"POST ", b"HEAD ", b"OPTIONS ", b"PUT ", b"DELETE ", b"CONNECT ", b"PATCH ",
    ];
    methods.iter().any(|m| buffer.starts_with(*m))
}

/// Parse HTTP request headers from the raw byte buffer.
pub fn parse_http_request(buffer: &[u8]) -> Option<HttpRequestInfo> {
    if !is_http_request(buffer) {
        return None;
    }

    let text = std::str::from_utf8(buffer).ok()?;
    let mut lines = text.split("\r\n");

    // 1. Request Line (e.g., "GET /index.html HTTP/1.1")
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let uri = parts.next()?.to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();

    let mut host = None;
    let mut host_header_offset = None;
    let mut host_value_offset = None;

    // 2. Headers
    let mut current_offset = request_line.len() + 2; // +2 for \r\n
    for line in lines {
        if line.is_empty() {
            break;
        }

        if let Some(colon_idx) = line.find(':') {
            let header_name = &line[..colon_idx];
            if header_name.eq_ignore_ascii_case("host") {
                let val = line[colon_idx + 1..].trim();
                host = Some(val.to_string());
                host_header_offset = Some(current_offset);
                // Offset of the value itself after ':'
                let val_rel = line[colon_idx + 1..]
                    .find(|c: char| !c.is_whitespace())
                    .unwrap_or(0);
                host_value_offset = Some(current_offset + colon_idx + 1 + val_rel);
            }
        }

        current_offset += line.len() + 2;
    }

    Some(HttpRequestInfo {
        method,
        uri,
        version,
        host,
        host_header_offset,
        host_value_offset,
    })
}

/// Mutate HTTP request bytes according to the provided evasion options.
pub fn mutate_http_request(buffer: &[u8], opts: &HttpEvasionOptions) -> Vec<u8> {
    if !is_http_request(buffer) {
        return buffer.to_vec();
    }

    let text = match std::str::from_utf8(buffer) {
        Ok(t) => t,
        Err(_) => return buffer.to_vec(),
    };

    let lines: Vec<&str> = text.split("\r\n").collect();
    if lines.is_empty() {
        return buffer.to_vec();
    }

    let mut result = Vec::new();

    // 1. Modify Request Line
    let first_line = lines[0];
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if opts.extra_method_space && parts.len() >= 3 {
        // GET  /path HTTP/1.1
        let mutated_req_line = format!("{}  {} {}", parts[0], parts[1], parts[2]);
        result.extend_from_slice(mutated_req_line.as_bytes());
    } else {
        result.extend_from_slice(first_line.as_bytes());
    }
    result.extend_from_slice(b"\r\n");

    // 2. Modify Headers
    for line in &lines[1..] {
        if line.is_empty() {
            // End of headers
            result.extend_from_slice(b"\r\n");
            continue;
        }

        if let Some(colon_idx) = line.find(':') {
            let header_name = &line[..colon_idx];
            if header_name.eq_ignore_ascii_case("host") {
                let value = line[colon_idx + 1..].trim();

                let name_transformed = if opts.mix_host {
                    "hoSt" // GoodbyeDPI style Host header replacement
                } else {
                    header_name
                };

                let space = if opts.host_space_trim {
                    "" // No space after colon
                } else {
                    " "
                };

                if opts.newline_before_host {
                    result.extend_from_slice(b"\r\n");
                }

                let new_header = format!("{}{}{}\r\n", name_transformed, colon_idx_char(space), value);
                result.extend_from_slice(new_header.as_bytes());
                continue;
            }
        }

        result.extend_from_slice(line.as_bytes());
        result.extend_from_slice(b"\r\n");
    }

    result
}

fn colon_idx_char(space: &str) -> String {
    format!(":{}", space)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_get() {
        let req = b"GET /watch?v=123 HTTP/1.1\r\nHost: www.youtube.com\r\nUser-Agent: curl/7.68.0\r\n\r\n";
        let info = parse_http_request(req).expect("Should parse HTTP request");

        assert_eq!(info.method, "GET");
        assert_eq!(info.uri, "/watch?v=123");
        assert_eq!(info.host.as_deref(), Some("www.youtube.com"));
    }

    #[test]
    fn test_mutate_http() {
        let req = b"GET / HTTP/1.1\r\nHost: blocked.org\r\n\r\n";
        let opts = HttpEvasionOptions {
            mix_host: true,
            host_space_trim: true,
            extra_method_space: true,
            newline_before_host: false,
        };

        let mutated = mutate_http_request(req, &opts);
        let mutated_str = std::str::from_utf8(&mutated).unwrap();

        assert!(mutated_str.starts_with("GET  / HTTP/1.1"));
        assert!(mutated_str.contains("hoSt:blocked.org"));
    }
}
