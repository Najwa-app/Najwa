//! HTTP client over Tor.
//!
//! Provides URL validation (.onion only), header stripping, raw HTTP/1.1
//! request building, and response parsing. All headers that could fingerprint
//! the client are omitted (S04 §5.2).

use crate::error::{Result, TransportError};
use std::collections::HashMap;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};

const MAX_HEADER_BYTES: usize = 32 * 1024;
// A maximum fetch may contain 200 base64-encoded 256-KiB messages.
pub(crate) const MAX_BODY_BYTES: usize = 80 * 1024 * 1024;
const MAX_CHUNK_METADATA_BYTES: usize = 1024 * 1024;

/// An HTTP response received over Tor.
pub struct HttpResponse {
    /// HTTP status code (e.g. 200, 404).
    pub status: u16,
    /// Response headers (lower-cased keys).
    pub headers: HashMap<String, String>,
    /// Response body bytes.
    pub body: Vec<u8>,
}

// ---------------------------------------------------------------------------
// URL validation (S04 §5.4)
// ---------------------------------------------------------------------------

/// Parsed components of a `.onion` URL.
pub(crate) struct OnionUrl {
    pub host: String,
    pub authority: String,
    pub port: u16,
    pub path: String,
}

/// Validate that `url` is an `http://<host>.onion[:<port>][/path]` address.
///
/// Rejects any non-`.onion` URL to prevent clearnet leaks (S04 §5.4).
pub(crate) fn validate_onion_url(url: &str) -> Result<OnionUrl> {
    if !url.is_ascii() || url.bytes().any(|b| b <= b' ' || b == 0x7f) || url.contains('#') {
        return Err(TransportError::NotOnionAddress);
    }
    let stripped = url
        .strip_prefix("http://")
        .ok_or(TransportError::NotOnionAddress)?;

    // Split host+port from path
    let (host_port, suffix) = match stripped.find(['/', '?']) {
        Some(idx) => (&stripped[..idx], &stripped[idx..]),
        None => (stripped, "/"),
    };
    let path = if suffix.starts_with('?') {
        format!("/{suffix}")
    } else {
        suffix.to_owned()
    };

    // Split host from port
    let (host, port) = if let Some(colon) = host_port.rfind(':') {
        let port_str = &host_port[colon + 1..];
        if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err(TransportError::NotOnionAddress);
        }
        let port = port_str
            .parse::<u16>()
            .map_err(|_| TransportError::NotOnionAddress)?;
        (&host_port[..colon], port)
    } else {
        (host_port, 80u16)
    };

    // Must be a .onion address
    if port == 0 || !host.ends_with(".onion") {
        return Err(TransportError::NotOnionAddress);
    }

    // v3 onion (S04 §5.4): the label before ".onion" MUST be exactly 56 base32
    // characters in [a-z2-7]. This rejects v2 (16-char) and otherwise malformed
    // addresses before they are ever handed to Tor.
    let label = &host[..host.len() - ".onion".len()];
    if label.len() != 56
        || !label
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
    {
        return Err(TransportError::NotOnionAddress);
    }

    Ok(OnionUrl {
        host: host.to_string(),
        authority: if port == 80 {
            host.to_string()
        } else {
            format!("{host}:{port}")
        },
        port,
        path,
    })
}

// ---------------------------------------------------------------------------
// Request building (S04 §5.1, §5.2 — header stripping)
// ---------------------------------------------------------------------------

/// Build a minimal HTTP/1.1 GET request.
///
/// Omits User-Agent, Accept-Language, Accept-Encoding, Referer (S04 §5.2).
pub(crate) fn build_get_request(host: &str, path: &str) -> Result<Vec<u8>> {
    validate_request_parts(host, path)?;
    Ok(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").into_bytes())
}

/// Build a minimal HTTP/1.1 POST request.
///
/// Omits User-Agent, Accept-Language, Accept-Encoding, Referer (S04 §5.2).
pub(crate) fn build_post_request(
    host: &str,
    path: &str,
    body: &[u8],
    content_type: &str,
) -> Result<Vec<u8>> {
    validate_request_parts(host, path)?;
    if content_type.is_empty() || !content_type.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err(parse_error("invalid content type"));
    }
    let header = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    let mut req = header.into_bytes();
    req.extend_from_slice(body);
    Ok(req)
}

fn validate_request_parts(host: &str, path: &str) -> Result<()> {
    if host.is_empty()
        || !path.starts_with('/')
        || host
            .bytes()
            .chain(path.bytes())
            .any(|b| !(0x21..=0x7e).contains(&b))
    {
        return Err(parse_error("invalid request authority or target"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

/// Read exactly one final response, with bounded headers, framing and body.
/// Content-Length/chunked responses complete without waiting for peer EOF.
pub(crate) async fn parse_http_response<R: AsyncRead + Unpin>(reader: R) -> Result<HttpResponse> {
    read_response_with_limit(reader, MAX_BODY_BYTES).await
}

fn parse_error(message: &str) -> TransportError {
    TransportError::HttpParseError(message.into())
}

/// Extract the numeric status code from an HTTP status line.
fn parse_status_code(line: &str) -> Result<u16> {
    let mut parts = line.splitn(3, ' ');
    if !matches!(parts.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
        return Err(parse_error("invalid HTTP version"));
    }
    let code = parts
        .next()
        .ok_or_else(|| parse_error("missing status code"))?;
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(parse_error("invalid status code"));
    }
    let code: u16 = code
        .parse()
        .map_err(|_| parse_error("invalid status code"))?;
    if !(100..=599).contains(&code) {
        return Err(parse_error("invalid status code"));
    }
    Ok(code)
}

async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R, budget: &mut usize) -> Result<String> {
    let mut bytes = Vec::new();
    reader
        .take((*budget as u64) + 1)
        .read_until(b'\n', &mut bytes)
        .await?;
    if bytes.len() > *budget {
        return Err(parse_error("HTTP metadata limit exceeded"));
    }
    *budget -= bytes.len();
    if !bytes.ends_with(b"\r\n") {
        return Err(parse_error("truncated or malformed HTTP line"));
    }
    bytes.truncate(bytes.len() - 2);
    if bytes
        .iter()
        .any(|b| (*b < 0x20 && *b != b'\t') || *b == 0x7f)
    {
        return Err(parse_error("invalid control byte in HTTP line"));
    }
    String::from_utf8(bytes).map_err(|_| parse_error("invalid HTTP header encoding"))
}

fn header_pair(line: &str) -> Result<(String, String)> {
    let (key, value) = line
        .split_once(':')
        .ok_or_else(|| parse_error("malformed header"))?;
    if key.is_empty()
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    {
        return Err(parse_error("invalid header name"));
    }
    Ok((
        key.to_ascii_lowercase(),
        value.trim_matches([' ', '\t']).to_owned(),
    ))
}

async fn read_response_with_limit<R: AsyncRead + Unpin>(
    reader: R,
    max_body: usize,
) -> Result<HttpResponse> {
    let mut reader = BufReader::new(reader);
    let mut budget = MAX_HEADER_BYTES;
    for _ in 0..9 {
        let status = parse_status_code(&read_line(&mut reader, &mut budget).await?)?;
        let mut headers = HashMap::<String, String>::new();
        loop {
            let line = read_line(&mut reader, &mut budget).await?;
            if line.is_empty() {
                break;
            }
            let (key, value) = header_pair(&line)?;
            if headers.contains_key(&key)
                && matches!(key.as_str(), "content-length" | "transfer-encoding")
            {
                return Err(parse_error("duplicate HTTP framing header"));
            }
            headers
                .entry(key)
                .and_modify(|old| {
                    old.push_str(", ");
                    old.push_str(&value);
                })
                .or_insert(value);
        }
        let length = headers
            .get("content-length")
            .map(|value| {
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(parse_error("invalid Content-Length"));
                }
                value
                    .parse::<usize>()
                    .map_err(|_| parse_error("Content-Length overflow"))
            })
            .transpose()?;
        let transfer = headers.get("transfer-encoding");
        if transfer.is_some() && length.is_some() {
            return Err(parse_error("ambiguous HTTP framing"));
        }
        if transfer.is_some_and(|value| !value.eq_ignore_ascii_case("chunked")) {
            return Err(parse_error("unsupported Transfer-Encoding"));
        }
        if status == 101 {
            return Err(parse_error("protocol switching is unsupported"));
        }
        if status < 200 {
            if transfer.is_some() || length.is_some() {
                return Err(parse_error("body framing on informational response"));
            }
            continue;
        }
        let mut body = Vec::new();
        if status == 204 || status == 304 {
            if transfer.is_some() || (status == 204 && length.is_some_and(|n| n != 0)) {
                return Err(parse_error("body framing on bodyless response"));
            }
        } else if transfer.is_some() {
            let mut metadata_budget = MAX_CHUNK_METADATA_BYTES;
            loop {
                let line = read_line(&mut reader, &mut metadata_budget).await?;
                let size = line.split(';').next().unwrap_or_default();
                if size.is_empty() || !size.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(parse_error("invalid chunk size"));
                }
                let size = usize::from_str_radix(size, 16)
                    .map_err(|_| parse_error("chunk size overflow"))?;
                if size == 0 {
                    let mut trailer_budget = MAX_HEADER_BYTES.min(metadata_budget);
                    loop {
                        let line = read_line(&mut reader, &mut trailer_budget).await?;
                        if line.is_empty() {
                            break;
                        }
                        let (key, _) = header_pair(&line)?;
                        if matches!(
                            key.as_str(),
                            "content-length" | "transfer-encoding" | "host"
                        ) {
                            return Err(parse_error("forbidden trailer"));
                        }
                    }
                    break;
                }
                if size > max_body.saturating_sub(body.len()) {
                    return Err(parse_error("HTTP body limit exceeded"));
                }
                let start = body.len();
                body.resize(start + size, 0);
                reader.read_exact(&mut body[start..]).await?;
                let mut end = [0; 2];
                reader.read_exact(&mut end).await?;
                if end != *b"\r\n" {
                    return Err(parse_error("missing chunk terminator"));
                }
            }
        } else if let Some(length) = length {
            if length > max_body {
                return Err(parse_error("HTTP body limit exceeded"));
            }
            body.resize(length, 0);
            reader.read_exact(&mut body).await?;
        } else {
            reader
                .take(max_body as u64 + 1)
                .read_to_end(&mut body)
                .await?;
            if body.len() > max_body {
                return Err(parse_error("HTTP body limit exceeded"));
            }
        }
        return Ok(HttpResponse {
            status,
            headers,
            body,
        });
    }
    Err(parse_error("too many informational responses"))
}

/// The caller creates this deadline before connecting, so connection setup,
/// blocked writes, and slow/never-ending responses all spend the same budget.
pub(crate) async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    request: &[u8],
    deadline: tokio::time::Instant,
) -> Result<HttpResponse> {
    tokio::time::timeout_at(deadline, async {
        stream.write_all(request).await?;
        stream.flush().await?;
        parse_http_response(&mut stream).await
    })
    .await
    .map_err(|_| TransportError::Timeout)?
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A syntactically valid v3 onion label: exactly 56 chars, all in [a-z2-7].
    const V3_LABEL: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx";

    #[test]
    fn validate_onion_url_valid() {
        let url = format!("http://{V3_LABEL}.onion/test");
        let parsed = validate_onion_url(&url).unwrap();
        assert_eq!(parsed.host, format!("{V3_LABEL}.onion"));
        assert_eq!(parsed.port, 80);
        assert_eq!(parsed.path, "/test");
    }

    #[test]
    fn validate_onion_url_with_port() {
        let url = format!("http://{V3_LABEL}.onion:8080/api/v1");
        let parsed = validate_onion_url(&url).unwrap();
        assert_eq!(parsed.host, format!("{V3_LABEL}.onion"));
        assert_eq!(parsed.port, 8080);
        assert_eq!(parsed.path, "/api/v1");
    }

    #[test]
    fn validate_onion_url_no_path() {
        let url = format!("http://{V3_LABEL}.onion");
        let parsed = validate_onion_url(&url).unwrap();
        assert_eq!(parsed.path, "/");
    }

    #[test]
    fn reject_v2_length_label() {
        // A 16-char label must be rejected (S04 §5.4 requires 56).
        assert!(validate_onion_url("http://abcdefghijklmnop.onion/x").is_err());
    }

    #[test]
    fn reject_non_base32_label() {
        // 56 chars but containing '1', '8', '9', '0' (outside [a-z2-7]) is invalid.
        let bad = "1".repeat(56);
        assert!(validate_onion_url(&format!("http://{bad}.onion/x")).is_err());
    }

    #[test]
    fn reject_clearnet_url() {
        assert!(validate_onion_url("http://example.com/test").is_err());
    }

    #[test]
    fn reject_https_onion() {
        // We only support http:// to .onion (TLS is redundant over Tor)
        assert!(validate_onion_url("https://abcdef.onion/test").is_err());
    }

    #[test]
    fn reject_bare_onion() {
        assert!(validate_onion_url("http://.onion/test").is_err());
    }

    #[test]
    fn get_request_no_fingerprint_headers() {
        let req = String::from_utf8(build_get_request("host.onion", "/").unwrap()).unwrap();
        // Must NOT contain identifying headers
        let lower = req.to_ascii_lowercase();
        assert!(!lower.contains("user-agent"));
        assert!(!lower.contains("accept-language"));
        assert!(!lower.contains("accept-encoding"));
        assert!(!lower.contains("referer"));
        // Must contain required headers
        assert!(req.contains("Host: host.onion"));
        assert!(req.contains("Connection: close"));
    }

    #[test]
    fn post_request_includes_body() {
        let body = b"hello world";
        let req =
            build_post_request("host.onion", "/api", body, "application/octet-stream").unwrap();
        let req_str = String::from_utf8_lossy(&req);
        assert!(req_str.contains("Content-Length: 11"));
        assert!(req_str.contains("Content-Type: application/octet-stream"));
        assert!(req_str.ends_with("hello world"));
    }

    #[tokio::test]
    async fn parse_simple_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello";
        let resp = parse_http_response(raw.as_slice()).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("content-type").unwrap(), "text/plain");
        assert_eq!(resp.body, b"Hello");
    }

    #[tokio::test]
    async fn parse_404_response() {
        let raw = b"HTTP/1.1 404 Not Found\r\n\r\n";
        let resp = parse_http_response(raw.as_slice()).await.unwrap();
        assert_eq!(resp.status, 404);
        assert!(resp.body.is_empty());
    }

    #[tokio::test]
    async fn parse_response_missing_boundary() {
        let raw = b"HTTP/1.1 200 OK";
        assert!(parse_http_response(raw.as_slice()).await.is_err());
    }
}

#[cfg(test)]
#[path = "http_tests.rs"]
mod regression_tests;
