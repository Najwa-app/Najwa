use super::*;
use std::time::Duration;

#[test]
fn request_fields_reject_injection() {
    let host = format!("{}.onion", "a".repeat(56));
    for suffix in [
        "/x\r\nInjected: yes",
        "/x y",
        "/x\t",
        "/x\0",
        "/x\u{7f}",
        "/é",
        "/#fragment",
    ] {
        assert!(
            validate_onion_url(&format!("http://{host}{suffix}")).is_err(),
            "{suffix:?}"
        );
    }
    for value in [
        "text/plain\r\nInjected: yes",
        "text/plain\0",
        "text/plain\u{7f}",
        "",
    ] {
        assert!(build_post_request(&host, "/", b"body", value).is_err());
    }
    assert!(build_get_request("host\r\nInjected: yes", "/").is_err());
    assert!(build_get_request(&host, "/\r\n").is_err());
    // Escaped octets remain encoded on the wire.
    let parsed = validate_onion_url(&format!("http://{host}/x%0d%0a")).unwrap();
    assert!(
        String::from_utf8(build_get_request(&parsed.authority, &parsed.path).unwrap())
            .unwrap()
            .starts_with("GET /x%0d%0a HTTP/1.1\r\n")
    );
}

#[test]
fn nondefault_port_and_query_survive_request_building() {
    let host = format!("{}.onion", "a".repeat(56));
    let parsed = validate_onion_url(&format!("http://{host}:8080?key=value")).unwrap();
    assert_eq!(parsed.port, 8080);
    assert_eq!(parsed.host, host);
    for request in [
        build_get_request(&parsed.authority, &parsed.path).unwrap(),
        build_post_request(&parsed.authority, &parsed.path, b"{}", "application/json").unwrap(),
    ] {
        let request = String::from_utf8(request).unwrap();
        assert!(request.contains(&format!("Host: {host}:8080\r\n")));
        assert!(request.contains(" /?key=value HTTP/1.1\r\n"));
    }
    for port in ["0", "+80", "-80", "65536", "", "80x"] {
        assert!(validate_onion_url(&format!("http://{host}:{port}/")).is_err());
    }
}

#[tokio::test]
async fn framing_rejects_truncation_conflicts_and_malformed_lines() {
    for raw in [
        "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort",
        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx",
        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
        "HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\nx",
        "HTTP/1.1 200 OK\r\nContent-Length: 184467440737095516160\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
        "HTTP/1.1 200 OK\r\n Content-Length: 1\r\n\r\nx",
        "HTTP/1.1 200 OK\r\nContent-Length : 1\r\n\r\nx",
        "HTTP/1.1 200 OK\n\n",
        "NOTHTTP 200 OK\r\n\r\n",
        "HTTP/1.1 2000 OK\r\n\r\n",
        "HTTP/1.1 101 Switching\r\n\r\n",
    ] {
        assert!(
            parse_http_response(raw.as_bytes()).await.is_err(),
            "accepted {raw:?}"
        );
    }
}

#[tokio::test]
async fn chunked_response_decodes_extensions_and_trailers() {
    let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n3;name=value\r\nabc\r\n2\r\nde\r\n0\r\nX-Checksum: ignored\r\n\r\n";
    assert_eq!(
        parse_http_response(raw.as_slice()).await.unwrap().body,
        b"abcde"
    );
}

#[tokio::test]
async fn malformed_chunks_are_rejected() {
    for chunks in [
        "g\r\nx\r\n0\r\n\r\n",
        "3\r\nx",
        "1\r\nxZZ0\r\n\r\n",
        "1\r\nx\r\n",
        "0\r\nContent-Length: 0\r\n\r\n",
        "ffffffffffffffffffffffff\r\n",
    ] {
        let raw = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{chunks}");
        assert!(
            parse_http_response(raw.as_bytes()).await.is_err(),
            "{chunks:?}"
        );
    }
}

#[tokio::test]
async fn every_body_framing_has_a_size_limit() {
    for raw in [
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabcde",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\n\r\nabcde",
    ] {
        assert!(read_response_with_limit(raw.as_bytes(), 4).await.is_err());
        assert_eq!(
            read_response_with_limit(raw.as_bytes(), 5)
                .await
                .unwrap()
                .body,
            b"abcde"
        );
    }
    // Reject the declared length before allocating or reading its body.
    let raw = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
        MAX_BODY_BYTES + 1
    );
    assert!(parse_http_response(raw.as_bytes()).await.is_err());
}

#[tokio::test]
async fn header_and_chunk_metadata_are_bounded() {
    let raw = format!(
        "HTTP/1.1 200 OK\r\nX-Fill: {}\r\n\r\n",
        "a".repeat(MAX_HEADER_BYTES)
    );
    assert!(parse_http_response(raw.as_bytes()).await.is_err());
    let raw = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;{}\r\nx\r\n0\r\n\r\n",
        "a".repeat(MAX_CHUNK_METADATA_BYTES)
    );
    assert!(parse_http_response(raw.as_bytes()).await.is_err());
}

#[tokio::test]
async fn informational_and_bodyless_responses_finish_correctly() {
    let raw = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    assert_eq!(
        parse_http_response(raw.as_slice()).await.unwrap().body,
        b"ok"
    );
    let raw = "HTTP/1.1 100 Continue\r\n\r\n".repeat(10);
    assert!(parse_http_response(raw.as_bytes()).await.is_err());
    for raw in [
        "HTTP/1.1 204 No Content\r\n\r\n",
        "HTTP/1.1 304 Not Modified\r\nContent-Length: 123\r\n\r\n",
    ] {
        assert!(parse_http_response(raw.as_bytes())
            .await
            .unwrap()
            .body
            .is_empty());
    }
}

#[tokio::test]
async fn framed_responses_complete_while_peer_remains_open() {
    for raw in [
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
        "HTTP/1.1 204 No Content\r\n\r\n",
    ] {
        let (client, mut peer) = tokio::io::duplex(1024);
        peer.write_all(raw.as_bytes()).await.unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), parse_http_response(client))
            .await
            .unwrap()
            .unwrap();
        assert!(response.body.is_empty() || response.body == b"ok");
        drop(peer);
    }
}

#[tokio::test]
async fn stalled_reads_and_writes_share_a_deadline() {
    for request in [
        b"".as_slice(),
        b"request larger than duplex capacity".as_slice(),
    ] {
        let (client, _peer) = tokio::io::duplex(1);
        let result = exchange(
            client,
            request,
            tokio::time::Instant::now() + Duration::from_millis(30),
        )
        .await;
        assert!(matches!(result, Err(TransportError::Timeout)));
    }
}

#[tokio::test]
async fn slow_drip_response_cannot_extend_absolute_deadline() {
    let (client, mut peer) = tokio::io::duplex(1024);
    peer.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
    let producer = tokio::spawn(async move {
        loop {
            if peer.write_all(b"x").await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
    let result = exchange(
        client,
        b"",
        tokio::time::Instant::now() + Duration::from_millis(50),
    )
    .await;
    assert!(matches!(result, Err(TransportError::Timeout)));
    producer.await.unwrap();
}
