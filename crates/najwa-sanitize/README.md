# najwa-sanitize

Mandatory metadata removal before a file is encrypted and sent. Detects the
type from magic bytes, converts decodable JPEG, PNG, GIF, BMP and TIFF images to
WebP (cleaning WebP in place), strips metadata from MP4/MOV, PDF, DOCX, ODT,
MP3, OGG, FLAC and WAV, then verifies the output format. Unknown types, HEIC and
any output that fails verification are refused; nothing passes through
unsanitized.

Implements the sanitization part of [S11](../../docs/specs/11-file-transfer-sanitization.md).

Entry points: `sanitize_file` (in-memory pipeline), `stream::sanitize_seekable`
(seekable reader and writer for large files), `detect_file_type`,
`verify::verify_no_metadata`, `stream::verify_seekable` (verification of a
seekable file, streamed for the streamed formats).

License: GPL-3.0-or-later.
