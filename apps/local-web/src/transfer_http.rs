//! Fixed-size upload parts and native browser download streams with HTTP Range.
use crate::profile::{Failure, Owner};
use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    session: String,
    generation: u64,
    action: Action,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Action {
    Begin {
        contact: String,
        manifest: najwa_ffi::desktop::UploadManifest,
    },
    List {
        contact: String,
    },
    Finish {
        id: String,
    },
    Cancel {
        contact: String,
        id: String,
    },
    Download {
        contact: String,
        message: String,
    },
}
fn response(value: crate::profile::Result<Value>) -> Json<Value> {
    Json(match value {
        Ok(v) => json!({"ok":v}),
        Err(e) => json!({"error":e}),
    })
}
pub async fn operation(
    State(owner): State<Arc<Owner>>,
    Json(request): Json<Request>,
) -> Json<Value> {
    response(
        tokio::task::spawn_blocking(move || {
            owner.validate(&request.session, request.generation, true)?;
            let value = match request.action {
                Action::Begin { contact, manifest } => owner
                    .client
                    .begin_upload(&contact, manifest)
                    .map(|v| json!(v)),
                Action::List { contact } => owner.client.list_transfers(&contact).map(|v| json!(v)),
                Action::Finish { id } => owner.client.seal_upload(&id).map(|_| Value::Null),
                Action::Cancel { contact, id } => owner
                    .client
                    .cancel_upload(&id, &contact)
                    .map(|_| Value::Null),
                Action::Download { contact, message } => {
                    owner.client.create_file_download(&contact, &message)
                }
            }
            .map_err(|e| Failure::new(e.code))?;
            owner.validate(&request.session, request.generation, true)?;
            Ok(value)
        })
        .await
        .unwrap_or_else(|_| Err(Failure::new("operation_failed"))),
    )
}
pub async fn upload_part(
    State(owner): State<Arc<Owner>>,
    Path((id, part)): Path<(String, u32)>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Json<Value> {
    let session = headers
        .get("x-najwa-identity")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let generation = headers
        .get("x-najwa-generation")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    let Some(generation) = generation else {
        return response(Err(Failure::new("invalid_request")));
    };
    response(
        tokio::task::spawn_blocking(move || {
            owner.validate(&session, generation, true)?;
            let bytes = zeroize::Zeroizing::new(bytes.to_vec());
            owner
                .client
                .upload_part(&id, part, &bytes)
                .map_err(|e| Failure::new(e.code))?;
            owner.validate(&session, generation, true)?;
            Ok(Value::Null)
        })
        .await
        .unwrap_or_else(|_| Err(Failure::new("operation_failed"))),
    )
}
fn range(value: Option<&str>, size: u64) -> Result<(u64, u64, bool), ()> {
    if size == 0 {
        return Err(());
    }
    let Some(value) = value else {
        return Ok((0, size - 1, false));
    };
    let value = value.strip_prefix("bytes=").ok_or(())?;
    let (start, end) = value.split_once('-').ok_or(())?;
    if start.is_empty() {
        let count = end.parse::<u64>().map_err(|_| ())?;
        if count == 0 {
            return Err(());
        }
        return Ok((size.saturating_sub(count), size - 1, true));
    }
    let start = start.parse::<u64>().map_err(|_| ())?;
    let end = if end.is_empty() {
        size - 1
    } else {
        end.parse::<u64>().map_err(|_| ())?.min(size - 1)
    };
    if start >= size || start > end {
        return Err(());
    }
    Ok((start, end, true))
}
pub async fn download(
    State(owner): State<Arc<Owner>>,
    Path(ticket): Path<String>,
    headers: HeaderMap,
) -> Response {
    let snapshot = owner.status();
    if owner
        .validate(&snapshot.session, snapshot.generation, true)
        .is_err()
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let task = owner.clone();
    let id = ticket.clone();
    let info = tokio::task::spawn_blocking(move || task.client.file_download_info(&id)).await;
    let Ok(Ok(info)) = info else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let etag = format!("\"{}\"", info.sha256);
    let requested = if headers
        .get(header::IF_RANGE)
        .is_none_or(|v| v.to_str().ok() == Some(etag.as_str()))
    {
        headers.get(header::RANGE).and_then(|v| v.to_str().ok())
    } else {
        None
    };
    let Ok((start, end, partial)) = range(requested, info.size) else {
        return (
            StatusCode::RANGE_NOT_SATISFIABLE,
            [(header::CONTENT_RANGE, format!("bytes */{}", info.size))],
        )
            .into_response();
    };
    let stream = futures_util::stream::try_unfold(
        (
            owner,
            ticket,
            snapshot.session,
            snapshot.generation,
            start,
            end,
        ),
        |(owner, ticket, session, generation, offset, end)| async move {
            if offset > end {
                return Ok::<_, std::io::Error>(None);
            }
            let task = owner.clone();
            let id = ticket.clone();
            let expected = session.clone();
            let mut bytes = tokio::task::spawn_blocking(move || {
                task.validate(&expected, generation, true)
                    .map_err(|_| std::io::Error::other("locked"))?;
                let bytes = task
                    .client
                    .file_download_part(&id, offset)
                    .map_err(|_| std::io::Error::other("file unavailable"))?;
                task.validate(&expected, generation, true)
                    .map_err(|_| std::io::Error::other("locked"))?;
                Ok::<_, std::io::Error>(bytes)
            })
            .await
            .map_err(std::io::Error::other)??;
            if bytes.is_empty() {
                return Err(std::io::Error::other("incomplete file"));
            }
            bytes.truncate(bytes.len().min((end - offset + 1) as usize));
            let next = offset + bytes.len() as u64;
            Ok(Some((
                Bytes::from(bytes),
                (owner, ticket, session, generation, next, end),
            )))
        },
    );
    let mut response = Body::from_stream(stream).into_response();
    *response.status_mut() = if partial {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    let escaped: String = info
        .filename
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    let headers = response.headers_mut();
    for (key, value) in [
        (header::CONTENT_TYPE, "application/octet-stream".to_string()),
        (header::CONTENT_LENGTH, (end - start + 1).to_string()),
        (
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"attachment\"; filename*=UTF-8''{escaped}"),
        ),
        (header::ACCEPT_RANGES, "bytes".into()),
        (header::ETAG, etag),
    ] {
        headers.insert(key, value.parse().unwrap());
    }
    if partial {
        headers.insert(
            header::CONTENT_RANGE,
            format!("bytes {start}-{end}/{}", info.size)
                .parse()
                .unwrap(),
        );
    }
    response
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ranges_are_bounded_and_reject_multiple_or_empty_ranges() {
        assert_eq!(range(None, 20), Ok((0, 19, false)));
        assert_eq!(range(Some("bytes=4-8"), 20), Ok((4, 8, true)));
        assert_eq!(range(Some("bytes=5-"), 20), Ok((5, 19, true)));
        assert_eq!(range(Some("bytes=-4"), 20), Ok((16, 19, true)));
        for v in ["bytes=20-", "bytes=4-2", "bytes=1-2,4-5", "bytes=-0"] {
            assert!(range(Some(v), 20).is_err());
        }
    }
}
