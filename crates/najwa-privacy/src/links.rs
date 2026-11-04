//! Library link-preview handling (off by default, Tor-routed when enabled).
//! The application does not generate link previews.
//!
//! Link previews are disabled by default.
//! When enabled, previews are generated sender-side over Tor
//! to avoid leaking URLs to third parties.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Link preview configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkPreviewConfig {
    /// Whether link previews are enabled. Default: false.
    pub enabled: bool,
    /// How previews are generated.
    pub generation_mode: PreviewMode,
}

impl Default for LinkPreviewConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            generation_mode: PreviewMode::SenderSide,
        }
    }
}

/// How link previews are generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PreviewMode {
    /// Sender generates the preview over Tor before sending. The ONLY permitted
    /// mode.
    #[default]
    SenderSide,
    /// **PERMANENTLY PROHIBITED.** Receiver-side fetching would leak
    /// the recipient's IP to the link's host and reveal that the URL was
    /// received. This variant exists only so the prohibition can be represented
    /// and rejected — no code may fetch on the receiver's behalf. Gate any
    /// generation path on [`PreviewMode::fetch_permitted`].
    ReceiverSide,
}

impl PreviewMode {
    /// Whether the client may fetch the link to build a preview in this mode.
    /// Only `SenderSide` is permitted; `ReceiverSide` is prohibited.
    pub fn fetch_permitted(&self) -> bool {
        matches!(self, PreviewMode::SenderSide)
    }
}

/// A generated link preview.
#[derive(Debug, Clone)]
pub struct LinkPreview {
    /// The original URL.
    pub url: String,
    /// Page title from OpenGraph or <title> tag.
    pub title: Option<String>,
    /// Page description from OpenGraph or meta description.
    pub description: Option<String>,
    /// Sanitized thumbnail bytes (metadata stripped).
    pub thumbnail: Option<Vec<u8>>,
    /// Domain extracted from the URL.
    pub domain: String,
}

/// Errors during link preview generation.
#[derive(Debug, Error)]
pub enum LinkError {
    /// URL could not be parsed.
    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    /// Network/transport error fetching the page.
    #[error("fetch error: {0}")]
    FetchError(String),

    /// HTML parsing error.
    #[error("parse error: {0}")]
    ParseError(String),

    /// Image sanitization failed.
    #[error("sanitization error: {0}")]
    SanitizationError(String),
}

/// Validate a URL for link preview generation.
///
/// Returns the domain if valid, or an error.
/// Fetch adapters must also enforce this policy on redirects and on remotely
/// resolved addresses; this parser performs no DNS lookup.
pub fn validate_preview_url(url: &str) -> Result<String, LinkError> {
    let parsed = url::Url::parse(url).map_err(|e| LinkError::InvalidUrl(e.to_string()))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(LinkError::InvalidUrl("only HTTP(S) URLs supported".into()));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(LinkError::InvalidUrl(
            "URL credentials are not allowed".into(),
        ));
    }
    let host = parsed
        .host()
        .ok_or_else(|| LinkError::InvalidUrl("empty host".into()))?;
    match host {
        url::Host::Domain(domain) => {
            let normalized = domain.trim_end_matches('.');
            if normalized == "localhost" || normalized.ends_with(".localhost") {
                return Err(LinkError::InvalidUrl("localhost is not allowed".into()));
            }
            Ok(normalized.to_owned())
        }
        url::Host::Ipv4(ip) => {
            if is_disallowed_ip(&ip.into()) {
                return Err(LinkError::InvalidUrl("private IP is not allowed".into()));
            }
            Ok(ip.to_string())
        }
        url::Host::Ipv6(ip) => {
            if is_disallowed_ip(&ip.into()) {
                return Err(LinkError::InvalidUrl("private IP is not allowed".into()));
            }
            Ok(ip.to_string())
        }
    }
}

/// True for IPs a link-preview fetch MUST NOT target (SSRF guard):
/// loopback, RFC1918 private, link-local, unique-local, and unspecified.
fn is_disallowed_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.octets()[0] == 0
                || v4.octets()[0] >= 240
                || (v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1]))
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| is_disallowed_ip(&std::net::IpAddr::V4(v4)))
        }
    }
}

/// Parse OpenGraph title and description from HTML content.
///
/// Looks for:
/// - `<meta property="og:title" content="...">`
/// - `<meta property="og:description" content="...">`
/// - Falls back to `<title>` and `<meta name="description">`
pub fn parse_og_tags(html: &str) -> (Option<String>, Option<String>) {
    let title = extract_meta_content(html, "og:title").or_else(|| extract_title_tag(html));
    let description = extract_meta_content(html, "og:description")
        .or_else(|| extract_meta_name_content(html, "description"));
    (title, description)
}

/// Parse OpenGraph image URL from HTML content.
pub fn parse_og_image(html: &str) -> Option<String> {
    extract_meta_content(html, "og:image")
}

/// Extract content attribute from a `<meta property="..." content="...">` tag.
fn extract_meta_content(html: &str, property: &str) -> Option<String> {
    // Search for property="<property>" pattern
    let property_pattern = format!("property=\"{}\"", property);
    let alt_pattern = format!("property='{}'", property);

    let search_from = html
        .find(&property_pattern)
        .or_else(|| html.find(&alt_pattern))?;

    // Find the enclosing <meta ...> tag
    let before = &html[..search_from];
    let tag_start = before.rfind('<')?;
    let after = &html[search_from..];
    let tag_end = after.find('>')? + search_from;

    let tag = &html[tag_start..=tag_end];

    // Extract content="..."
    extract_attribute_value(tag, "content")
}

/// Extract content from `<meta name="..." content="...">` tag.
fn extract_meta_name_content(html: &str, name: &str) -> Option<String> {
    let name_pattern = format!("name=\"{}\"", name);
    let alt_pattern = format!("name='{}'", name);

    let search_from = html
        .find(&name_pattern)
        .or_else(|| html.find(&alt_pattern))?;

    let before = &html[..search_from];
    let tag_start = before.rfind('<')?;
    let after = &html[search_from..];
    let tag_end = after.find('>')? + search_from;

    let tag = &html[tag_start..=tag_end];
    extract_attribute_value(tag, "content")
}

/// Extract the `<title>` tag content.
fn extract_title_tag(html: &str) -> Option<String> {
    let start = html.find("<title")?.checked_add(6)?;
    let rest = &html[start..];
    let content_start = rest.find('>')?.checked_add(1)?;
    let content = &rest[content_start..];
    let end = content.find("</title>")?;
    let title = content[..end].trim();
    if title.is_empty() {
        None
    } else {
        Some(title.to_string())
    }
}

/// Extract an attribute value from an HTML tag string.
fn extract_attribute_value(tag: &str, attr: &str) -> Option<String> {
    let dq_pattern = format!("{}=\"", attr);
    let sq_pattern = format!("{}='", attr);

    if let Some(pos) = tag.find(&dq_pattern) {
        let start = pos + dq_pattern.len();
        let rest = &tag[start..];
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    } else if let Some(pos) = tag.find(&sq_pattern) {
        let start = pos + sq_pattern.len();
        let rest = &tag[start..];
        let end = rest.find('\'')?;
        Some(rest[..end].to_string())
    } else {
        None
    }
}

/// Build a `LinkPreview` from parsed components.
pub fn build_preview(
    url: &str,
    domain: String,
    title: Option<String>,
    description: Option<String>,
    thumbnail: Option<Vec<u8>>,
) -> LinkPreview {
    LinkPreview {
        url: url.to_string(),
        title,
        description,
        thumbnail,
        domain,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_disabled() {
        let config = LinkPreviewConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.generation_mode, PreviewMode::SenderSide);
    }

    #[test]
    fn validate_url_accepts_https() {
        let domain = validate_preview_url("https://example.com/page").unwrap();
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn validate_url_accepts_http() {
        let domain = validate_preview_url("http://example.com").unwrap();
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn validate_url_rejects_ftp() {
        assert!(validate_preview_url("ftp://files.example.com").is_err());
    }

    #[test]
    fn validate_url_rejects_empty_domain() {
        assert!(validate_preview_url("https://").is_err());
    }

    #[test]
    fn validate_url_strips_port() {
        let domain = validate_preview_url("https://example.com:8080/path").unwrap();
        assert_eq!(domain, "example.com");
    }

    // SSRF guard — localhost + literal private/loopback/link-local IPs
    // are rejected; a normal public host is allowed.
    #[test]
    fn rejects_ssrf_targets() {
        for bad in [
            "http://localhost/x",
            "http://127.0.0.1/x",
            "https://192.168.1.1",
            "http://10.0.0.5:8080/p",
            "http://172.16.9.9",
            "http://169.254.1.1",
            "http://[::1]/x",
            "http://0.0.0.0",
        ] {
            assert!(validate_preview_url(bad).is_err(), "should reject {bad}");
        }
        assert!(validate_preview_url("https://example.com/page").is_ok());
    }

    #[test]
    fn parse_og_title_and_description() {
        let html = r#"
            <html><head>
            <meta property="og:title" content="Test Page">
            <meta property="og:description" content="A test description">
            </head></html>
        "#;
        let (title, desc) = parse_og_tags(html);
        assert_eq!(title, Some("Test Page".to_string()));
        assert_eq!(desc, Some("A test description".to_string()));
    }

    #[test]
    fn parse_fallback_title_tag() {
        let html = "<html><head><title>Fallback Title</title></head></html>";
        let (title, _) = parse_og_tags(html);
        assert_eq!(title, Some("Fallback Title".to_string()));
    }

    #[test]
    fn parse_fallback_meta_description() {
        let html = r#"
            <html><head>
            <meta name="description" content="Meta description">
            </head></html>
        "#;
        let (_, desc) = parse_og_tags(html);
        assert_eq!(desc, Some("Meta description".to_string()));
    }

    #[test]
    fn parse_og_image_tag() {
        let html = r#"<meta property="og:image" content="https://example.com/img.jpg">"#;
        let img = super::parse_og_image(html);
        assert_eq!(img, Some("https://example.com/img.jpg".to_string()));
    }

    #[test]
    fn parse_no_og_tags_returns_none() {
        let html = "<html><head></head><body>Hello</body></html>";
        let (title, desc) = parse_og_tags(html);
        assert!(title.is_none());
        assert!(desc.is_none());
    }

    #[test]
    fn build_preview_constructs_correctly() {
        let preview = build_preview(
            "https://example.com",
            "example.com".to_string(),
            Some("Title".to_string()),
            None,
            None,
        );
        assert_eq!(preview.url, "https://example.com");
        assert_eq!(preview.domain, "example.com");
        assert_eq!(preview.title, Some("Title".to_string()));
        assert!(preview.description.is_none());
        assert!(preview.thumbnail.is_none());
    }

    #[test]
    fn receiver_side_preview_fetch_is_prohibited() {
        // Only sender-side fetching is permitted.
        assert!(PreviewMode::SenderSide.fetch_permitted());
        assert!(!PreviewMode::ReceiverSide.fetch_permitted());
    }
}
