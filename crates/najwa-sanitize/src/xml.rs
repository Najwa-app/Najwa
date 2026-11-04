//! Parse metadata XML before rewriting it. Unsupported encodings and DTDs
//! are refused; whitespace, namespace aliases, and CDATA cannot hide values.

use crate::SanitizeError;
use quick_xml::{events::Event, Reader, Writer};

pub(crate) fn empty_tag(xml: &[u8], tag: &str) -> Result<(Vec<u8>, bool), SanitizeError> {
    let invalid = |e: String| SanitizeError::InvalidFormat(format!("metadata XML: {e}"));
    std::str::from_utf8(xml).map_err(|e| invalid(e.to_string()))?;
    if xml.contains(&0) {
        return Err(invalid("only UTF-8 XML is supported".into()));
    }
    let mut reader = Reader::from_reader(xml);
    let mut writer = Writer::new(Vec::new());
    let local = tag.rsplit(':').next().unwrap_or(tag).as_bytes();
    let mut depth = 0usize;
    let mut skip_depth = None;
    let mut changed = false;
    let mut roots = 0;
    loop {
        let event = reader.read_event().map_err(|e| invalid(e.to_string()))?;
        match &event {
            Event::DocType(_) => return Err(invalid("DTDs are not supported".into())),
            Event::Decl(decl) => {
                if let Some(encoding) = decl.encoding() {
                    let encoding = encoding.map_err(|e| invalid(e.to_string()))?;
                    if !encoding.eq_ignore_ascii_case(b"utf-8")
                        && !encoding.eq_ignore_ascii_case(b"us-ascii")
                    {
                        return Err(invalid("only UTF-8 XML is supported".into()));
                    }
                }
            }
            Event::Start(start) | Event::Empty(start) => {
                for attribute in start.attributes() {
                    attribute.map_err(|e| invalid(e.to_string()))?;
                }
                if depth == 0 {
                    roots += 1;
                }
                if matches!(event, Event::Start(_)) {
                    depth += 1;
                    if depth > 128 {
                        return Err(invalid("nesting exceeds 128".into()));
                    }
                }
                if skip_depth.is_some() {
                    changed = true;
                    continue;
                }
                if matches!(event, Event::Start(_)) && start.local_name().as_ref() == local {
                    skip_depth = Some(depth);
                }
            }
            Event::End(_) => {
                if depth == 0 {
                    return Err(invalid("unbalanced end tag".into()));
                }
                if let Some(skip) = skip_depth {
                    if depth != skip {
                        depth -= 1;
                        continue;
                    }
                    skip_depth = None;
                }
                depth -= 1;
            }
            Event::Eof => {
                if depth != 0 || roots != 1 {
                    return Err(invalid("incomplete XML document".into()));
                }
                break;
            }
            _ if skip_depth.is_some() => {
                changed = true;
                continue;
            }
            _ => {}
        }
        writer
            .write_event(event)
            .map_err(|e| invalid(e.to_string()))?;
    }
    Ok((writer.into_inner(), changed))
}
