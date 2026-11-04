//! Media metadata sanitization for Najwa (S11).
//!
//! Provides mandatory metadata sanitization before file encryption:
//! - Magic-byte file type detection (not extension-based)
//! - Images: structural conversion to WebP — the source container (EXIF, GPS,
//!   XMP, IPTC, thumbnails) is discarded wholesale during pixel decode.
//!   WebP, the canonical send format, is cleaned in place; HEIC is refused
//!   (S11 §7.14)
//! - MP4/MOV atom metadata stripping (GPS, device info, `udta`)
//! - PDF author/revision stripping
//! - DOCX/ODT archive rewriting, MP3 ID3 / FLAC / OGG / WAV tag stripping
//! - Post-strip verification against the OUTPUT format (defense in depth)
//!
//! **Sanitization cannot be disabled by the user** (S11 §5.2).

pub mod audio;
pub mod convert;
pub mod detect;
pub mod document;
pub mod image;
pub mod verify;
pub mod video;
pub mod stream;
pub mod zip;
mod pdf;
mod xml;

pub use detect::{detect_file_type, FileType};
pub use verify::VerificationResult;

/// Errors that can occur during sanitization.
#[derive(Debug, thiserror::Error)]
pub enum SanitizeError {
    /// File format is invalid or corrupted.
    #[error("invalid format: {0}")]
    InvalidFormat(String),

    /// Post-strip verification failed (residual metadata detected).
    #[error("verification failed: {residual_count} residual metadata fields found")]
    VerificationFailed {
        residual_count: usize,
        findings: Vec<String>,
    },

    /// File type is not supported for sanitization.
    #[error("unsupported file type: {0}")]
    UnsupportedType(String),

    /// Generic I/O or processing error.
    #[error("sanitization error: {0}")]
    Other(String),
}

/// Sanitization settings (S11 §5.2).
///
/// Sanitization itself cannot be disabled, weakened, or skipped by
/// configuration (S11 §5.2): image conversion is unconditional, and
/// unknown types are always refused. The only knob is how strictly residual
/// metadata is treated at the end of the pipeline.
#[derive(Debug, Clone)]
pub struct SanitizationSettings {
    /// Whether a verification finding refuses the file. When false, findings
    /// are ignored.
    pub strict_verification: bool,
}

impl Default for SanitizationSettings {
    fn default() -> Self {
        Self {
            strict_verification: true,
        }
    }
}

/// Result of a successful sanitization (S11 §5.1).
#[derive(Debug, Clone)]
pub struct SanitizationResult {
    /// The sanitized file bytes.
    pub sanitized_bytes: Vec<u8>,
    /// Detected file type of the INPUT.
    pub original_type: FileType,
    /// File type of [`SanitizationResult::sanitized_bytes`] — images are
    /// always [`FileType::WebP`] after conversion; non-image types keep the
    /// input type. This is the type that goes on the wire.
    pub output_type: FileType,
    /// List of metadata fields that were removed (or the conversion note).
    pub fields_removed: Vec<String>,
    /// Whether the file was structurally re-encoded (image → WebP conversion).
    pub re_encoded: bool,
    /// Original file size in bytes.
    pub size_before: usize,
    /// Sanitized file size in bytes.
    pub size_after: usize,
}

/// Sanitize a file by stripping all identifying metadata (S11 §5.1).
///
/// This is the main entry point for the sanitization pipeline:
/// 1. Detect file type by magic bytes
/// 2. Strip metadata — or, for decodable images, structurally convert to WebP
/// 3. Verify the OUTPUT format carries no residual metadata (S11 §8)
///
/// Strip-or-refuse: a file whose format cannot be processed is returned as an
/// error, never passed through (S11 §5.1).
///
/// **This function cannot be bypassed** — all files shared through Najwa
/// must pass through sanitization (S11 §5.1).
pub fn sanitize_file(
    data: &[u8],
    settings: &SanitizationSettings,
) -> Result<SanitizationResult, SanitizeError> {
    let size_before = data.len();

    // 1. Detect file type by magic bytes (not extension)
    let file_type = detect::detect_file_type(data);

    // 2. Strip / convert.
    //
    // Image pipeline: decodable images are converted
    // to WebP. Decoding to raw pixels discards the entire source container,
    // so metadata destruction is structural, not selective. There is NO
    // per-format stripper fallback: a file that cannot be decoded is refused
    // (S11 §5.1), never passed through with best-effort stripping. WebP itself —
    // the canonical send format — is cleaned in place instead.
    let (stripped, fields, output_type, re_encoded) = match file_type {
        FileType::WebP => {
            let (bytes, fields) = image::strip_webp_metadata(data)?;
            (bytes, fields, FileType::WebP, false)
        }
        FileType::Jpeg | FileType::Png | FileType::Gif | FileType::Bmp | FileType::Tiff => {
            let bytes = convert::convert_to_webp(data)?;
            (
                bytes,
                vec!["converted to WebP (structural strip)".into()],
                FileType::WebP,
                true,
            )
        }
        FileType::Heic => {
            // S11 §7.14: the `image` crate does not decode HEIC, so HEIC is
            // refused (S11 §5.1).
            return Err(SanitizeError::UnsupportedType(
                "HEIC: convert to JPEG/WebP before sending (no safe HEIC decoder available)"
                    .into(),
            ));
        }
        FileType::Mp4 | FileType::Mov => {
            let (bytes, fields) = video::strip_video_metadata(data)?;
            (bytes, fields, file_type, false)
        }
        FileType::Pdf => {
            let (bytes, fields) = document::strip_pdf_metadata(data)?;
            (bytes, fields, file_type, false)
        }
        FileType::Docx => {
            let (bytes, fields) = document::strip_docx_metadata(data)?;
            (bytes, fields, file_type, false)
        }
        FileType::Odt => {
            let (bytes, fields) = document::strip_odt_metadata(data)?;
            (bytes, fields, file_type, false)
        }
        FileType::Mp3 | FileType::Ogg | FileType::Flac | FileType::Wav => {
            let (bytes, fields) = audio::strip_audio_metadata(data, &file_type)?;
            (bytes, fields, file_type, false)
        }
        // S11 §5.1: never ship a file we cannot sanitize — reject unknown types
        // rather than passing metadata through.
        FileType::Unknown => {
            return Err(SanitizeError::UnsupportedType(
                "unrecognized file type; refusing to send unsanitized".into(),
            ));
        }
    };

    // 3. Post-strip verification (S11 §8) — runs against the OUTPUT format:
    // a converted image is verified as WebP, matching what actually goes on
    // the wire. Fail closed for ALL types when strict (the default): if we
    // cannot confirm the output carries no metadata, reject the file rather
    // than ship it.
    let verification = verify::verify_no_metadata(&stripped, &output_type)?;
    if !verification.passed && settings.strict_verification {
        return Err(SanitizeError::VerificationFailed {
            residual_count: verification.residual_findings.len(),
            findings: verification.residual_findings,
        });
    }

    let size_after = stripped.len();

    Ok(SanitizationResult {
        sanitized_bytes: stripped,
        original_type: file_type,
        output_type,
        fields_removed: fields,
        re_encoded,
        size_before,
        size_after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_unknown_type_rejected() {
        // S11 §5.1: an unrecognized type MUST be rejected, not passed through.
        let data = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let err = sanitize_file(&data, &SanitizationSettings::default()).unwrap_err();
        assert!(matches!(err, SanitizeError::UnsupportedType(_)));
    }

    #[test]
    fn sanitize_ogg_strips_tags_and_passes_strict_verification() {
        let mut tags = b"OpusTags".to_vec();
        tags.extend_from_slice(&6u32.to_le_bytes());
        tags.extend_from_slice(b"vendor");
        tags.extend_from_slice(&0u32.to_le_bytes());
        let mut ogg = b"OggS".to_vec();
        ogg.extend_from_slice(&[0, 0]);
        ogg.extend_from_slice(&0u64.to_le_bytes());
        ogg.extend_from_slice(&1u32.to_le_bytes());
        ogg.extend_from_slice(&0u32.to_le_bytes());
        ogg.extend_from_slice(&0u32.to_le_bytes());
        ogg.extend_from_slice(&[1, tags.len() as u8]);
        ogg.extend_from_slice(&tags);

        let result = sanitize_file(&ogg, &SanitizationSettings::default()).unwrap();
        assert_eq!(result.original_type, FileType::Ogg);
        assert_eq!(result.output_type, FileType::Ogg);
        assert!(!result.re_encoded);
        assert!(result
            .fields_removed
            .iter()
            .any(|field| field.contains("Opus")));
        assert!(
            verify::verify_no_metadata(&result.sanitized_bytes, &FileType::Ogg)
                .unwrap()
                .passed
        );
    }

    #[test]
    fn sanitize_docx_end_to_end_passes_strict_verification() {
        // S11 §7.5 + §5.4: a dirty DOCX (deflated entries, nonzero mtimes,
        // extra fields, author metadata) sanitizes to a stored, timestamp-free
        // archive that PASSES strict verification — DOCX is now sendable.
        let core = b"<cp:coreProperties><dc:creator>Jane Doe</dc:creator>\
            <cp:revision>7</cp:revision></cp:coreProperties>";
        let dirty = zip::build_dirty_zip(&[
            ("[Content_Types].xml", b"<Types/>"),
            ("docProps/core.xml", core),
            ("word/document.xml", b"<w:document>body</w:document>"),
        ]);
        assert_eq!(detect_file_type(&dirty), FileType::Docx);

        // The dirty input itself fails verification (residual metadata +
        // non-stored entries + mtimes)...
        let v = verify::verify_no_metadata(&dirty, &FileType::Docx).unwrap();
        assert!(!v.passed);

        // ...but the sanitize pipeline produces a passing archive.
        let result = sanitize_file(&dirty, &SanitizationSettings::default()).unwrap();
        assert_eq!(result.original_type, FileType::Docx);
        assert!(result.fields_removed.iter().any(|f| f == "DOCX:dc:creator"));
        let v2 = verify::verify_no_metadata(&result.sanitized_bytes, &FileType::Docx).unwrap();
        assert!(
            v2.passed,
            "sanitized DOCX must verify clean: {:?}",
            v2.residual_findings
        );
        assert!(!result.sanitized_bytes.windows(8).any(|w| w == b"Jane Doe"));
    }

    #[test]
    fn sanitize_pdf_strips_author() {
        let pdf = crate::pdf::fixture(lopdf::dictionary! {"Author" => lopdf::Object::string_literal("TestUser")});
        let result = sanitize_file(&pdf, &SanitizationSettings::default()).unwrap();
        assert_eq!(result.original_type, FileType::Pdf);
        assert!(result.fields_removed.iter().any(|f| f.contains("Author")));
        let stripped_str = String::from_utf8_lossy(&result.sanitized_bytes);
        assert!(!stripped_str.contains("TestUser"));
    }

    #[test]
    fn settings_default_values() {
        let settings = SanitizationSettings::default();
        assert!(settings.strict_verification);
    }

    #[test]
    fn sanitize_mp3_strips_id3() {
        let mut mp3 = Vec::new();
        mp3.extend_from_slice(b"ID3\x04\x00\x00");
        mp3.extend_from_slice(&[0x00, 0x00, 0x00, 0x14]); // syncsafe 20
        mp3.extend_from_slice(&[0u8; 20]); // tag data
        mp3.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]); // sync
        mp3.extend_from_slice(&[0u8; 50]); // audio data

        let result = sanitize_file(&mp3, &SanitizationSettings::default()).unwrap();
        assert_eq!(result.original_type, FileType::Mp3);
        assert!(result.fields_removed.iter().any(|f| f.contains("ID3v2")));
        assert!(result.size_after < result.size_before);
    }

    #[test]
    fn sanitize_result_sizes() {
        let pdf = crate::pdf::fixture(lopdf::dictionary! {"Author" => lopdf::Object::string_literal("LongAuthorName")});
        let result = sanitize_file(&pdf, &SanitizationSettings::default()).unwrap();
        assert_eq!(result.size_before, pdf.len());
        assert_eq!(result.size_after, result.sanitized_bytes.len());
    }

    #[test]
    fn sanitize_webp_with_exif_strips_and_passes() {
        // WebP is cleaned in place: EXIF chunks are dropped and verification
        // runs against the WebP output.
        let mut body = Vec::new();
        body.extend_from_slice(b"VP8X");
        body.extend_from_slice(&10u32.to_le_bytes());
        body.push(0x0C); // EXIF|XMP flags
        body.extend_from_slice(&[0u8; 9]); // reserved(3) + canvas(6)
        let exif = b"Exif\x00\x00MM\x00\x2A";
        body.extend_from_slice(b"EXIF");
        body.extend_from_slice(&(exif.len() as u32).to_le_bytes());
        body.extend_from_slice(exif);
        body.extend_from_slice(b"VP8 ");
        body.extend_from_slice(&4u32.to_le_bytes());
        body.extend_from_slice(&[0, 0, 0, 0]);
        let mut webp = b"RIFF".to_vec();
        webp.extend_from_slice(&((4 + body.len()) as u32).to_le_bytes());
        webp.extend_from_slice(b"WEBP");
        webp.extend_from_slice(&body);

        let result = sanitize_file(&webp, &SanitizationSettings::default()).unwrap();
        assert_eq!(result.original_type, FileType::WebP);
        assert_eq!(result.output_type, FileType::WebP);
        assert!(!result.re_encoded);
        assert!(result.fields_removed.iter().any(|f| f.contains("EXIF")));
        assert!(!result.sanitized_bytes.windows(4).any(|w| w == b"EXIF"));
    }

    #[test]
    fn sanitize_png_converts_to_webp_and_verifies_output_format() {
        // Regression for the verify-output-type fix: the converted bytes are
        // WebP, so strict verification must run verify_webp (verify_png on
        // WebP bytes would report "unverifiable PNG header" and refuse every
        // converted image).
        let mut buf = std::io::Cursor::new(Vec::new());
        // `::image` = the external crate (our `mod image` shadows the name).
        ::image::DynamicImage::ImageRgb8(::image::RgbImage::from_pixel(
            1,
            1,
            ::image::Rgb([12, 34, 56]),
        ))
        .write_to(&mut buf, ::image::ImageFormat::Png)
        .unwrap();
        let png = buf.into_inner();
        let result = sanitize_file(&png, &SanitizationSettings::default()).unwrap();
        assert_eq!(result.original_type, FileType::Png);
        assert_eq!(result.output_type, FileType::WebP);
        assert!(result.re_encoded);
        assert_eq!(&result.sanitized_bytes[0..4], b"RIFF");
        assert_eq!(&result.sanitized_bytes[8..12], b"WEBP");
    }

    #[test]
    fn sanitize_tiff_converts_to_webp_and_passes_strict_verification() {
        // TIFF has no byte-level verifier of its own; under input-type
        // verification a converted TIFF could never pass strict mode. Under
        // output-type verification it must.
        // Minimal 1×1 grayscale uncompressed TIFF: header + IFD (9 entries) + 1 pixel byte.
        let mut tiff = Vec::new();
        tiff.extend_from_slice(b"II"); // little-endian
        tiff.extend_from_slice(&42u16.to_le_bytes());
        tiff.extend_from_slice(&8u32.to_le_bytes()); // IFD offset
        // IFD: 2 + 9*12 + 4 = 114 bytes starting at 8 → strip data at 122.
        let strip_offset: u32 = 8 + 2 + 9 * 12 + 4;
        tiff.extend_from_slice(&9u16.to_le_bytes());
        let entry = |tag: u16, typ: u16, count: u32, value: u32| -> Vec<u8> {
            let mut e = Vec::new();
            e.extend_from_slice(&tag.to_le_bytes());
            e.extend_from_slice(&typ.to_le_bytes());
            e.extend_from_slice(&count.to_le_bytes());
            e.extend_from_slice(&value.to_le_bytes());
            e
        };
        // IFD entries MUST be in ascending tag order.
        tiff.extend_from_slice(&entry(256, 3, 1, 1)); // ImageWidth = 1
        tiff.extend_from_slice(&entry(257, 3, 1, 1)); // ImageLength = 1
        tiff.extend_from_slice(&entry(258, 3, 1, 8)); // BitsPerSample = 8
        tiff.extend_from_slice(&entry(259, 3, 1, 1)); // Compression = none
        tiff.extend_from_slice(&entry(262, 3, 1, 1)); // Photometric = BlackIsZero
        tiff.extend_from_slice(&entry(273, 4, 1, strip_offset)); // StripOffsets
        tiff.extend_from_slice(&entry(277, 3, 1, 1)); // SamplesPerPixel = 1
        tiff.extend_from_slice(&entry(278, 3, 1, 1)); // RowsPerStrip = 1
        tiff.extend_from_slice(&entry(279, 4, 1, 1)); // StripByteCounts = 1
        tiff.extend_from_slice(&0u32.to_le_bytes()); // no next IFD
        assert_eq!(tiff.len() as u32, strip_offset);
        tiff.push(0xA5); // the single pixel byte

        let result = sanitize_file(&tiff, &SanitizationSettings::default()).unwrap();
        assert_eq!(result.original_type, FileType::Tiff);
        assert_eq!(result.output_type, FileType::WebP);
        assert!(result.re_encoded);
        assert_eq!(&result.sanitized_bytes[8..12], b"WEBP");
    }

    #[test]
    fn sanitize_heic_refused() {
        // S11 §7.14: no HEIC decoder → refused.
        let mut heic = Vec::new();
        heic.extend_from_slice(&24u32.to_be_bytes());
        heic.extend_from_slice(b"ftyp");
        heic.extend_from_slice(b"heic");
        heic.extend_from_slice(&[0, 0, 0, 0]);
        heic.extend_from_slice(b"heicmif1");
        assert_eq!(detect_file_type(&heic), FileType::Heic);
        let err = sanitize_file(&heic, &SanitizationSettings::default()).unwrap_err();
        assert!(matches!(err, SanitizeError::UnsupportedType(_)));
    }
}
