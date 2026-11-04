//! Universal image converter: any decodable format → stripped WebP
//! (S11 §7.16).
//!
//! JPEG, PNG, GIF, BMP and TIFF have no per-format stripper. The conversion is
//! **structurally safe**: the source file is decoded to raw pixel data (which
//! discards the entire container — EXIF, GPS, XMP, IPTC, thumbnails, color
//! profiles, everything) and re-encoded as WebP from those pixels alone. No
//! container bytes survive the round-trip, so metadata cannot leak even if a
//! future parser bug misses a chunk.
//!
//! HEIC is the known gap: the `image` crate does not decode HEIC natively
//! (it requires the C `libheif` library). The pipeline refuses HEIC with a
//! user-actionable message (S11 §7.14).

use crate::SanitizeError;
use image::ImageFormat;

/// Convert any decodable image to a stripped WebP.
///
/// The output is a valid WebP file containing only pixel data — no EXIF, no
/// XMP, no ICCP, no EXIF thumbnail, nothing. Metadata destruction is
/// structural (the source container is discarded during decode).
pub fn convert_to_webp(data: &[u8]) -> std::result::Result<Vec<u8>, SanitizeError> {
    let img = image::load_from_memory(data).map_err(|e| {
        SanitizeError::InvalidFormat(format!("image decode failed: {e}"))
    })?;

    let mut out = std::io::Cursor::new(Vec::new());
    img.write_to(&mut out, ImageFormat::WebP)
        .map_err(|e| SanitizeError::InvalidFormat(format!("WebP encode failed: {e}")))?;

    Ok(out.into_inner())
}

/// Check whether a byte slice is a format the `image` crate can decode.
/// The sanitizer pipeline does not call this; it dispatches on magic bytes
/// (S11 §6.2).
pub fn is_supported_image_format(data: &[u8]) -> bool {
    image::ImageReader::new(std::io::Cursor::new(data))
        .with_guessed_format()
        .ok()
        .map(|r| r.format().is_some())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid PNG using the `image` crate (always well-formed).
    fn make_png() -> Vec<u8> {
        let img = image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(1, 1, image::Rgb([200, 30, 30])));
        let mut buf = std::io::Cursor::new(Vec::new());
        img.write_to(&mut buf, image::ImageFormat::Png).unwrap();
        buf.into_inner()
    }

    #[test]
    fn png_to_webp_structural_metadata_destruction() {
        // Build a PNG with a tEXt metadata chunk injected before IEND.
        let mut png = make_png();
        // Pop the IEND chunk (12 bytes: 4 len + 4 type + 4 crc) and re-append later.
        let iend_len = 12usize;
        let png_len = png.len();
        png.truncate(png_len - iend_len);
        let text = b"Comment\0metadata-leak";
        let crc_input: Vec<u8> = [b"tEXt" as &[u8], text].concat();
        let crc = crc32(&crc_input);
        png.extend_from_slice(&(text.len() as u32).to_be_bytes());
        png.extend_from_slice(b"tEXt");
        png.extend_from_slice(text);
        png.extend_from_slice(&crc.to_be_bytes());
        // Re-append a fresh IEND (the image crate always produces one).
        // The tEXt chunk is inserted before IEND by this injection.
        // We need to re-add IEND after the tEXt chunk.
        // The IEND chunk is: length(4) + "IEND" + crc(4) = 12 bytes.
        png.extend_from_slice(&0u32.to_be_bytes()); // IEND length = 0
        png.extend_from_slice(b"IEND");
        let iend_crc = crc32(b"IEND");
        png.extend_from_slice(&iend_crc.to_be_bytes());

        let webp = convert_to_webp(&png).unwrap();
        assert!(webp.len() > 12, "WebP output must be non-trivial");
        assert_eq!(&webp[0..4], b"RIFF");
        assert_eq!(&webp[8..12], b"WEBP");
        // The metadata text MUST NOT survive the conversion.
        assert!(
            !webp.windows(text.len()).any(|w| w == text),
            "source metadata leaked into WebP output"
        );
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(convert_to_webp(&[0xDE; 64]).is_err());
        assert!(convert_to_webp(&[]).is_err());
    }

    #[test]
    fn supported_format_detection() {
        assert!(is_supported_image_format(&make_png()));
        assert!(!is_supported_image_format(&[0xDE; 64]));
    }

    fn crc32(data: &[u8]) -> u32 {
        let mut table = [0u32; 256];
        for i in 0..256u32 {
            let mut c = i;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            table[i as usize] = c;
        }
        let mut crc = 0xFFFF_FFFFu32;
        for &b in data {
            crc = table[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
        }
        crc ^ 0xFFFF_FFFF
    }
}
