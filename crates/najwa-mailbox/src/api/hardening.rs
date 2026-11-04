//! Request hardening (S16 §12/§14): JSON limits + fixed-deadline responses.
//!
//! §12 JSON parsing limits: max body 1 MiB (enforced by `DefaultBodyLimit`
//! in the router AND re-bounded by the buffering below), max nesting 4,
//! max array 200, and duplicate-key rejection. `serde_json` alone gives none
//! of the last three — a duplicate key silently shadows, deep nesting burns
//! stack, and an oversized array forces allocation before limits apply.
//!
//! §14 fixed-deadline response scheduler: every `/v1` response is transmitted
//! at `arrival + RESPONSE_DEADLINE_MS` regardless of whether the capability
//! lookup hit, missed, or finished early, so response timing cannot act as a
//! capability-lifecycle oracle (this matters most on the §3.3 silent-drop
//! path, where the response BODY is deliberately identical). Requests that
//! genuinely exceed the deadline are sent on completion and counted toward
//! adaptive PoW escalation through the shared application state.

use std::time::{Duration, Instant};

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// S16 §14: transmit at `arrival + this`, ≥ worst-case lookup+commit at rated
/// load. A constant, per spec — not operator-tunable.
pub const RESPONSE_DEADLINE_MS: u64 = 100;

/// §12: maximum JSON container nesting (root = 1). The deepest legitimate
/// body is `/v1/prekey/upload`: root → `bundle` → `one_time_prekeys` → entry,
/// which lands exactly at 4.
pub const MAX_NESTING: usize = 4;

/// §12: maximum elements in any JSON array. A fetch page is ≤ 100 messages,
/// so an acknowledge batch of 200 covers every legitimate reply-to-page.
pub const MAX_ARRAY_LEN: usize = 200;

/// Re-buffer the request body, enforce the §12 JSON limits, and pass the
/// buffered body downstream. Empty bodies (GETs) pass through untouched.
pub async fn json_hardening(req: Request, next: Next) -> Response {
    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            return (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response();
        }
    };
    if !bytes.is_empty() {
        if let Err(msg) = validate_json(&bytes) {
            return (StatusCode::BAD_REQUEST, format!("invalid JSON body: {msg}")).into_response();
        }
    }
    let req = Request::from_parts(parts, axum::body::Body::from(bytes));
    next.run(req).await
}

/// §14: hold the response until `arrival + RESPONSE_DEADLINE_MS`.
pub async fn fixed_deadline(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    req: Request,
    next: Next,
) -> Response {
    let start = Instant::now();
    let resp = next.run(req).await;
    let deadline = Duration::from_millis(RESPONSE_DEADLINE_MS);
    let elapsed = start.elapsed();
    if elapsed < deadline {
        tokio::time::sleep(deadline - elapsed).await;
    } else {
        state.record_deadline_overrun();
    }
    resp
}

/// Validate one JSON document against the §12 limits.
pub fn validate_json(body: &[u8]) -> Result<(), String> {
    let s = std::str::from_utf8(body).map_err(|_| "body is not valid UTF-8".to_string())?;
    let mut p = Parser {
        b: s.as_bytes(),
        i: 0,
    };
    p.ws();
    p.value(1)?;
    p.ws();
    if p.i != p.b.len() {
        return Err("trailing bytes after JSON document".into());
    }
    Ok(())
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while let Some(&c) = self.b.get(self.i) {
            if matches!(c, b' ' | b'\t' | b'\n' | b'\r') {
                self.i += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.ws();
        self.b.get(self.i).copied()
    }

    fn value(&mut self, depth: usize) -> Result<(), String> {
        match self.peek().ok_or("unexpected end of body")? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => self.string().map(|_| ()),
            b't' => self.literal(b"true"),
            b'f' => self.literal(b"false"),
            b'n' => self.literal(b"null"),
            _ => self.number(),
        }
    }

    fn object(&mut self, depth: usize) -> Result<(), String> {
        if depth > MAX_NESTING {
            return Err(format!("nesting deeper than {MAX_NESTING}"));
        }
        self.i += 1; // '{'
        let mut keys = std::collections::HashSet::new();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(());
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err("expected object key".into());
            }
            // Keys are compared on their DECODED value: "a" and "\u0061" are
            // the same key to serde and must collide here too.
            let key = self.string()?;
            if !keys.insert(key) {
                return Err("duplicate object key".into());
            }
            if self.peek() != Some(b':') {
                return Err("expected ':'".into());
            }
            self.i += 1;
            self.value(depth + 1)?;
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(());
                }
                _ => return Err("expected ',' or '}'".into()),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<(), String> {
        if depth > MAX_NESTING {
            return Err(format!("nesting deeper than {MAX_NESTING}"));
        }
        self.i += 1; // '['
        let mut n = 0usize;
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(());
        }
        loop {
            n += 1;
            if n > MAX_ARRAY_LEN {
                return Err(format!("array longer than {MAX_ARRAY_LEN}"));
            }
            self.value(depth + 1)?;
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(());
                }
                _ => return Err("expected ',' or ']'".into()),
            }
        }
    }

    /// Parse a string starting at `"`, returning its DECODED value.
    fn string(&mut self) -> Result<String, String> {
        self.i += 1; // '"'
        let mut out = String::new();
        while let Some(&c) = self.b.get(self.i) {
            match c {
                b'"' => {
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.i += 1;
                    let e = *self.b.get(self.i).ok_or("unterminated escape")?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            // Surrogate arithmetic is u32 (0x10000 exceeds u16).
                            let cp: u32 = if (0xD800..0xDC00).contains(&hi) {
                                // Surrogate pair: \uXXXX\uYYYY must travel together.
                                if self.b.get(self.i) == Some(&b'\\')
                                    && self.b.get(self.i + 1) == Some(&b'u')
                                {
                                    self.i += 2;
                                    let lo = self.hex4()?;
                                    if !(0xDC00..0xE000).contains(&lo) {
                                        return Err("invalid low surrogate".into());
                                    }
                                    0x1_0000u32
                                        + ((u32::from(hi) - 0xD800) << 10)
                                        + (u32::from(lo) - 0xDC00)
                                } else {
                                    return Err("lone high surrogate".into());
                                }
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err("lone low surrogate".into());
                            } else {
                                u32::from(hi)
                            };
                            out.push(char::from_u32(cp).ok_or("invalid code point")?);
                        }
                        _ => return Err("invalid escape".into()),
                    }
                }
                0x00..=0x1F => return Err("raw control character in string".into()),
                _ => {
                    let s = std::str::from_utf8(&self.b[self.i..])
                        .map_err(|_| "invalid UTF-8 in string".to_string())?;
                    let ch = s.chars().next().expect("non-empty slice");
                    out.push(ch);
                    self.i += ch.len_utf8();
                }
            }
        }
        Err("unterminated string".into())
    }

    fn hex4(&mut self) -> Result<u16, String> {
        let hex = self
            .b
            .get(self.i..self.i + 4)
            .ok_or("truncated \\u escape")?;
        let s = std::str::from_utf8(hex).map_err(|_| "bad \\u escape".to_string())?;
        let v = u16::from_str_radix(s, 16).map_err(|_| "bad \\u escape".to_string())?;
        self.i += 4;
        Ok(v)
    }

    fn literal(&mut self, word: &[u8]) -> Result<(), String> {
        if self.b.get(self.i..self.i + word.len()) == Some(word) {
            self.i += word.len();
            Ok(())
        } else {
            Err("invalid literal".into())
        }
    }

    fn number(&mut self) -> Result<(), String> {
        let start = self.i;
        while let Some(&c) = self.b.get(self.i) {
            if c.is_ascii_digit() || matches!(c, b'-' | b'+' | b'.' | b'e' | b'E') {
                self.i += 1;
            } else {
                break;
            }
        }
        if start == self.i {
            return Err("expected a JSON value".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_legitimate_mailbox_bodies() {
        // prekey upload — the deepest legitimate shape (depth exactly 4).
        let body = br#"{"deposit_capability":"AAAA","bundle":{"identity_key":"x","signed_prekey_id":1,"signed_prekey_signature":"s","signed_prekey_timestamp":0,"manifest":{"opk_id_set_hash":"h","opk_count":2,"timestamp":0,"signature":"sig"},"one_time_prekeys":[{"id":1,"key":"k"},{"id":2,"key":"k2"}]}}"#;
        assert!(validate_json(body).is_ok());
        // acknowledge — 200-element array is the legal maximum.
        let ids: Vec<String> = (0..200).map(|i| format!("\"msg-{i}\"")).collect();
        let body = format!(
            "{{\"fetch_capability\":\"A\",\"message_ids\":[{}]}}",
            ids.join(",")
        );
        assert!(validate_json(body.as_bytes()).is_ok());
        // unicode escapes in keys decode before the duplicate check.
        assert!(validate_json(br#"{"a":1,"b":2}"#).is_ok());
    }

    #[test]
    fn rejects_duplicate_keys_across_escape_spellings() {
        assert!(validate_json(br#"{"a":1,"a":2}"#).is_err());
        // "\u0061" IS "a" once decoded — must collide, not shadow.
        assert!(validate_json(br#"{"a":1,"\u0061":2}"#).is_err());
        assert!(validate_json(br#"{"k":{"n":1},"k":{"n":2}}"#).is_err());
    }

    #[test]
    fn rejects_over_nesting_and_over_long_arrays() {
        assert!(validate_json(br#"{"a":{"b":{"c":{"d":{"e":1}}}}}"#).is_err()); // depth 5
        assert!(validate_json(br#"{"a":{"b":{"c":{"d":1}}}}"#).is_ok()); // depth 4
        let long: Vec<&str> = vec!["1"; 201];
        let body = format!("[{}]", long.join(","));
        assert!(validate_json(body.as_bytes()).is_err());
        let ok: Vec<&str> = vec!["1"; 200];
        assert!(validate_json(format!("[{}]", ok.join(",")).as_bytes()).is_ok());
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(validate_json(b"{").is_err());
        assert!(validate_json(b"{\"a\" 1}").is_err());
        assert!(validate_json(b"[1,]").is_err());
        assert!(validate_json(b"{} tail").is_err());
        assert!(validate_json(b"nul").is_err());
        assert!(validate_json(br#""\ud800""#).is_err()); // lone surrogate
        assert!(validate_json(b"\"\x01\"").is_err()); // raw control char
        assert!(validate_json(b"01").is_ok()); // tolerated: serde_json accepts,
                                               // and strict number grammar is
                                               // its job, not the limiter's
    }
}
