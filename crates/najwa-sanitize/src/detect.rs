//! Magic-byte file type detection (S11 §6).
//!
//! Detects file types by examining magic bytes at the start of the file,
//! never relying on file extensions. This is critical for security: a
//! malicious file renamed to `.jpg` must still be correctly identified.

/// Supported file types for sanitization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Jpeg,
    Png,
    Gif,
    Bmp,
    WebP,
    Tiff,
    Heic,
    Mp4,
    Mov,
    Pdf,
    Docx,
    Odt,
    Mp3,
    Ogg,
    Flac,
    Wav,
    /// Unknown or unsupported file type.
    Unknown,
}

impl FileType {
    /// Whether this type is an image format.
    pub fn is_image(&self) -> bool {
        matches!(
            self,
            Self::Jpeg | Self::Png | Self::Gif | Self::Bmp | Self::WebP | Self::Tiff | Self::Heic
        )
    }

    /// Whether this type is a video format.
    pub fn is_video(&self) -> bool {
        matches!(self, Self::Mp4 | Self::Mov)
    }

    /// Whether this type is an audio format.
    pub fn is_audio(&self) -> bool {
        matches!(self, Self::Mp3 | Self::Ogg | Self::Flac | Self::Wav)
    }

    /// Whether this type is a document format.
    pub fn is_document(&self) -> bool {
        matches!(self, Self::Pdf | Self::Docx | Self::Odt)
    }

    /// Human-readable MIME type string.
    pub fn mime_type(&self) -> &'static str {
        match self {
            Self::Jpeg => "image/jpeg",
            Self::Png => "image/png",
            Self::Gif => "image/gif",
            Self::Bmp => "image/bmp",
            Self::WebP => "image/webp",
            Self::Tiff => "image/tiff",
            Self::Heic => "image/heic",
            Self::Mp4 => "video/mp4",
            Self::Mov => "video/quicktime",
            Self::Pdf => "application/pdf",
            Self::Docx => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            Self::Odt => "application/vnd.oasis.opendocument.text",
            Self::Mp3 => "audio/mpeg",
            Self::Ogg => "audio/ogg",
            Self::Flac => "audio/flac",
            Self::Wav => "audio/wav",
            Self::Unknown => "application/octet-stream",
        }
    }
}

impl std::fmt::Display for FileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.mime_type())
    }
}

/// Detect file type from magic bytes (S11 §6.2).
///
/// Examines the first bytes of the data to determine file type.
/// Returns `FileType::Unknown` if no known signature matches.
pub fn detect_file_type(data: &[u8]) -> FileType {
    if data.len() < 4 {
        return FileType::Unknown;
    }

    // JPEG: starts with FF D8 FF
    if data.len() >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
        return FileType::Jpeg;
    }

    // PNG: starts with 89 50 4E 47 0D 0A 1A 0A
    if data.len() >= 8 && data[..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
        return FileType::Png;
    }

    // GIF: starts with GIF87a or GIF89a
    if data.len() >= 6 && &data[..3] == b"GIF" && (&data[3..6] == b"87a" || &data[3..6] == b"89a") {
        return FileType::Gif;
    }

    // BMP: starts with BM
    if data.len() >= 2 && data[0] == 0x42 && data[1] == 0x4D {
        return FileType::Bmp;
    }

    // WebP: RIFF....WEBP
    if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        return FileType::WebP;
    }

    // TIFF: II (little-endian) or MM (big-endian)
    if data.len() >= 4
        && ((data[0] == 0x49 && data[1] == 0x49 && data[2] == 0x2A && data[3] == 0x00)
            || (data[0] == 0x4D && data[1] == 0x4D && data[2] == 0x00 && data[3] == 0x2A))
    {
        return FileType::Tiff;
    }

    // FLAC: starts with fLaC
    if data.len() >= 4 && &data[..4] == b"fLaC" {
        return FileType::Flac;
    }

    // OGG: starts with OggS
    if data.len() >= 4 && &data[..4] == b"OggS" {
        return FileType::Ogg;
    }

    // WAV: RIFF....WAVE
    if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WAVE" {
        return FileType::Wav;
    }

    // PDF: starts with %PDF
    if data.len() >= 5 && &data[..5] == b"%PDF-" {
        return FileType::Pdf;
    }

    // ZIP-based formats (DOCX, ODT): starts with PK (50 4B 03 04)
    if data.len() >= 4 && data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04 {
        // Try to distinguish DOCX vs ODT by looking for signatures deeper in
        return detect_zip_subtype(data);
    }

    // MP3: starts with ID3 tag or sync word (FF FB, FF FA, FF F3, FF F2)
    if data.len() >= 3 && &data[..3] == b"ID3" {
        return FileType::Mp3;
    }
    if data.len() >= 2 && data[0] == 0xFF && (data[1] & 0xE0) == 0xE0 {
        return FileType::Mp3;
    }

    // ISO Base Media File Format (MP4/MOV/HEIC): check for ftyp box
    if data.len() >= 12 && &data[4..8] == b"ftyp" {
        let brand = &data[8..12];
        if brand == b"heic" || brand == b"heix" || brand == b"mif1" {
            return FileType::Heic;
        }
        if brand == b"qt  " {
            return FileType::Mov;
        }
        // isom, mp41, mp42, M4V, etc. → MP4
        return FileType::Mp4;
    }

    FileType::Unknown
}

/// Distinguish ZIP-based document formats by checking internal structure.
fn detect_zip_subtype(data: &[u8]) -> FileType {
    // DOCX contains "[Content_Types].xml" or "word/" directory
    // ODT contains "mimetype" file with "application/vnd.oasis.opendocument"
    // Simple heuristic: search the first ~2KB for distinguishing strings
    let search_window = &data[..data.len().min(4096)];

    if find_subsequence(search_window, b"word/").is_some()
        || find_subsequence(search_window, b"[Content_Types].xml").is_some()
    {
        return FileType::Docx;
    }

    if find_subsequence(search_window, b"mimetype").is_some()
        || find_subsequence(search_window, b"opendocument").is_some()
    {
        return FileType::Odt;
    }

    // Generic ZIP — treat as unknown
    FileType::Unknown
}

/// Find a byte subsequence within a haystack.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_jpeg() {
        let data = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        assert_eq!(detect_file_type(&data), FileType::Jpeg);
    }

    #[test]
    fn detect_png() {
        let data = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00];
        assert_eq!(detect_file_type(&data), FileType::Png);
    }

    #[test]
    fn detect_gif89a() {
        let mut data = b"GIF89a".to_vec();
        data.extend_from_slice(&[0; 10]);
        assert_eq!(detect_file_type(&data), FileType::Gif);
    }

    #[test]
    fn detect_pdf() {
        let data = b"%PDF-1.4 some content";
        assert_eq!(detect_file_type(data), FileType::Pdf);
    }

    #[test]
    fn detect_mp3_id3() {
        let data = b"ID3\x04\x00\x00";
        assert_eq!(detect_file_type(data), FileType::Mp3);
    }

    #[test]
    fn detect_flac() {
        let data = b"fLaC\x00\x00\x00\x22";
        assert_eq!(detect_file_type(data), FileType::Flac);
    }

    #[test]
    fn detect_ogg() {
        let data = b"OggS\x00\x02\x00\x00";
        assert_eq!(detect_file_type(data), FileType::Ogg);
    }

    #[test]
    fn detect_wav() {
        let mut data = b"RIFF".to_vec();
        data.extend_from_slice(&[0; 4]); // size
        data.extend_from_slice(b"WAVE");
        assert_eq!(detect_file_type(&data), FileType::Wav);
    }

    #[test]
    fn detect_webp() {
        let mut data = b"RIFF".to_vec();
        data.extend_from_slice(&[0; 4]); // size
        data.extend_from_slice(b"WEBP");
        assert_eq!(detect_file_type(&data), FileType::WebP);
    }

    #[test]
    fn detect_mp4() {
        let mut data = vec![0x00, 0x00, 0x00, 0x18]; // box size
        data.extend_from_slice(b"ftypisom");
        assert_eq!(detect_file_type(&data), FileType::Mp4);
    }

    #[test]
    fn detect_heic() {
        let mut data = vec![0x00, 0x00, 0x00, 0x18];
        data.extend_from_slice(b"ftypheic");
        assert_eq!(detect_file_type(&data), FileType::Heic);
    }

    #[test]
    fn detect_mov() {
        let mut data = vec![0x00, 0x00, 0x00, 0x18];
        data.extend_from_slice(b"ftypqt  ");
        assert_eq!(detect_file_type(&data), FileType::Mov);
    }

    #[test]
    fn detect_bmp() {
        let data = [0x42, 0x4D, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(detect_file_type(&data), FileType::Bmp);
    }

    #[test]
    fn detect_tiff_le() {
        let data = [0x49, 0x49, 0x2A, 0x00, 0x08, 0x00];
        assert_eq!(detect_file_type(&data), FileType::Tiff);
    }

    #[test]
    fn detect_tiff_be() {
        let data = [0x4D, 0x4D, 0x00, 0x2A, 0x00, 0x08];
        assert_eq!(detect_file_type(&data), FileType::Tiff);
    }

    #[test]
    fn detect_unknown() {
        let data = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert_eq!(detect_file_type(&data), FileType::Unknown);
    }

    #[test]
    fn too_short_is_unknown() {
        assert_eq!(detect_file_type(&[0xFF]), FileType::Unknown);
        assert_eq!(detect_file_type(&[]), FileType::Unknown);
    }

    #[test]
    fn file_type_categories() {
        assert!(FileType::Jpeg.is_image());
        assert!(FileType::Png.is_image());
        assert!(!FileType::Mp4.is_image());
        assert!(FileType::Mp4.is_video());
        assert!(FileType::Mov.is_video());
        assert!(FileType::Mp3.is_audio());
        assert!(FileType::Ogg.is_audio());
        assert!(FileType::Pdf.is_document());
        assert!(FileType::Docx.is_document());
    }
}
