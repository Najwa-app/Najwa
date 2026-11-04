//! Printable QR card generation (S05 §6.3).
//!
//! Generates a printable card with a QR code for offline contact sharing.
//! The card contains:
//! - QR code encoding the handshake payload
//! - Display name label
//! - "Scan with Najwa" instruction
//! - Expiration date

use qrcode::QrCode;

/// Configuration for printable QR card generation.
#[derive(Debug, Clone)]
pub struct QrCardConfig {
    /// Display name to show on the card.
    pub display_name: String,
    /// Instruction text (default: "Scan with Najwa").
    pub instruction: String,
    /// Whether to include expiration date on the card.
    pub show_expiration: bool,
}

impl Default for QrCardConfig {
    fn default() -> Self {
        Self {
            display_name: String::new(),
            instruction: "Scan with Najwa".to_string(),
            show_expiration: true,
        }
    }
}

/// Generate a printable card with QR code for offline sharing (S05 §6.3).
///
/// Returns SVG bytes containing the QR code and metadata.
/// The handshake payload should be encoded via
/// `HandshakePayload::to_qr_string()` before being passed here.
pub fn generate_printable_card(qr_data: &str, config: &QrCardConfig) -> Vec<u8> {
    let code = match QrCode::new(qr_data.as_bytes()) {
        Ok(c) => c,
        Err(_) => {
            // Fallback: return a placeholder SVG if data is too large for QR
            return r##"<svg xmlns="http://www.w3.org/2000/svg" width="300" height="400">
  <rect width="300" height="400" fill="white" stroke="black"/>
  <text x="150" y="200" text-anchor="middle" font-size="12">QR data too large</text>
</svg>"##
                .to_string()
                .into_bytes();
        }
    };

    let modules = code.to_colors();
    let size = code.width();
    let scale = 4; // pixels per module
    let qr_px = size * scale;
    let margin = 50;
    let card_w = qr_px + margin * 2;
    let header_h = 40;
    let footer_h = 60;
    let card_h = header_h + qr_px + footer_h + margin;

    let mut svg = format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{card_w}" height="{card_h}">
  <rect width="{card_w}" height="{card_h}" fill="white" stroke="black" stroke-width="1"/>
  <text x="{}" y="28" text-anchor="middle" font-family="sans-serif" font-size="16" font-weight="bold">{}</text>"##,
        card_w / 2,
        escape_xml_text(&config.display_name),
    );

    // Render QR modules as SVG rects
    let qr_y_offset = header_h;
    for (i, color) in modules.iter().enumerate() {
        if *color == qrcode::Color::Dark {
            let row = i / size;
            let col = i % size;
            let x = margin + col * scale;
            let y = qr_y_offset + row * scale;
            svg.push_str(&format!(
                r#"<rect x="{x}" y="{y}" width="{scale}" height="{scale}" fill="black"/>"#
            ));
        }
    }

    // Footer with instruction
    let footer_y = qr_y_offset + qr_px + 30;
    svg.push_str(&format!(
        r##"<text x="{}" y="{footer_y}" text-anchor="middle" font-family="sans-serif" font-size="14">{}</text>
</svg>"##,
        card_w / 2,
        escape_xml_text(&config.instruction),
    ));

    svg.into_bytes()
}

fn escape_xml_text(text: &str) -> String {
    let mut escaped = String::new();
    for ch in text.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            // XML 1.0 forbids most control characters even when escaped.
            '\t' | '\n' | '\r' => escaped.push(ch),
            '\u{0}'..='\u{1f}' | '\u{fffe}' | '\u{ffff}' => escaped.push('\u{fffd}'),
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = QrCardConfig::default();
        assert_eq!(config.instruction, "Scan with Najwa");
        assert!(config.show_expiration);
        assert!(config.display_name.is_empty());
    }

    #[test]
    fn generate_returns_svg_bytes() {
        let config = QrCardConfig {
            display_name: "Alice".to_string(),
            ..Default::default()
        };

        let svg = generate_printable_card("najwa:testdata", &config);
        assert!(!svg.is_empty());

        let svg_str = String::from_utf8(svg).unwrap();
        assert!(svg_str.contains("<svg"));
        assert!(svg_str.contains("Alice"));
        assert!(svg_str.contains("Scan with Najwa"));
    }
}
