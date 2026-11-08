//! Raw HTTP/1.1 request sender — a SEPARATE path from the ureq-based `fetch`, for
//! exploits that need the request-line PATH sent verbatim (no normalization).
//!
//! ureq (and the `url` crate it parses through) canonicalizes the path: `%2e` and
//! `.%2e/` segments collapse, which defeats path-normalization-bypass bugs like
//! CVE-2021-41773 (Apache 2.4.49 mod_cgi) whose whole trick is encoded dots reaching
//! the server intact. This module writes the request line BYTE-FOR-BYTE over a
//! `TcpStream`, so `GET /cgi-bin/.%2e/.%2e/bin/sh` arrives exactly as given.
//!
//! It performs NO safety gating itself — the caller (`HttpClient::fetch_raw`) runs the
//! same scope/armed/rate-limit/audit pre-flight first, so this path is gated identically
//! to `fetch`. HTTP only (plaintext); the local/eval benchmark targets are HTTP on the
//! Docker network. `Connection: close` + read-to-EOF keeps response parsing simple.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub struct RawResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

/// Send one HTTP/1.1 request with `raw_path` placed in the request line UNCHANGED.
/// Reads the whole response (Connection: close). Never panics; returns Err(String) on
/// a connect/IO/parse failure. HTTP only — an `https` caller must not reach here.
pub fn send_raw(
    host: &str,
    port: u16,
    method: &str,
    raw_path: &str,
    headers: &HashMap<String, String>,
    body: Option<&str>,
    timeout_secs: u64,
) -> Result<RawResponse, String> {
    let mut stream = TcpStream::connect((host, port))
        .map_err(|e| format!("raw connect {host}:{port} failed: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(timeout_secs)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_secs(timeout_secs)))
        .ok();

    // Build the request. The path is written verbatim — no encoding, no collapsing.
    let mut req = format!("{} {} HTTP/1.1\r\n", method, raw_path);
    req.push_str(&format!("Host: {host}\r\n"));
    req.push_str("Connection: close\r\n");
    req.push_str("Accept: */*\r\n");
    // Caller headers, minus the ones we control (host/connection/content-length).
    for (k, v) in headers {
        let lk = k.to_ascii_lowercase();
        if lk == "host" || lk == "connection" || lk == "content-length" {
            continue;
        }
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(b) = body {
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }

    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("raw write failed: {e}"))?;

    // Read the whole response (server closes the connection). 10MB cap, matching fetch.
    let mut raw: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > 10_000_000 {
                    raw.truncate(10_000_000);
                    break;
                }
            }
            Err(e) => {
                // A timeout after we already have data is a normal keep-alive-less close;
                // only error out if we got nothing at all.
                if raw.is_empty() {
                    return Err(format!("raw read failed: {e}"));
                }
                break;
            }
        }
    }

    parse_response(&raw)
}

/// Raw byte exchange on a SINGLE TCP connection — the protocol-research primitive for
/// HTTP request smuggling / desync. Unlike `send_raw`, the caller supplies the COMPLETE
/// request bytes verbatim (no forced Host/Connection/Content-Length, no normalization),
/// so CL/TE mismatches and pipelined requests can be crafted. The `payloads` are written
/// in order on the SAME socket (keep-alive / pipelining), optionally spaced by
/// `inter_write_delay_ms` (connection-poisoning timing). Returns the RAW response bytes —
/// all responses concatenated, UNPARSED — because counting/splitting the responses is the
/// smuggling oracle the caller needs. Bounded by `read_timeout_secs` + `max_bytes`. Never
/// panics. Performs NO safety gating — the caller (`HttpClient::raw_exchange`) runs the
/// scope/armed/rate/audit pre-flight first. HTTP/plaintext only.
pub fn raw_exchange(
    host: &str,
    port: u16,
    payloads: &[Vec<u8>],
    read_timeout_secs: u64,
    inter_write_delay_ms: u64,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let mut stream = TcpStream::connect((host, port))
        .map_err(|e| format!("raw_exchange connect {host}:{port} failed: {e}"))?;
    let t = Duration::from_secs(read_timeout_secs.max(1));
    stream.set_read_timeout(Some(t)).ok();
    stream.set_write_timeout(Some(t)).ok();

    for (i, payload) in payloads.iter().enumerate() {
        stream
            .write_all(payload)
            .map_err(|e| format!("raw_exchange write {i} failed: {e}"))?;
        if inter_write_delay_ms > 0 && i + 1 < payloads.len() {
            std::thread::sleep(Duration::from_millis(inter_write_delay_ms));
        }
    }

    // Read everything until EOF or an idle read-timeout. A timeout (or reset) is a normal
    // end-of-stream here — return whatever bytes we have (possibly empty), so the caller
    // sees the server's raw reply (or its silence) rather than an error.
    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];
    let cap = max_bytes.max(1);
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if out.len() >= cap {
                    out.truncate(cap);
                    break;
                }
            }
            Err(_) => break,
        }
    }
    Ok(out)
}

/// Split a raw HTTP response into (status, headers, body). Lenient — a malformed head
/// still yields the body after the first blank line so a CGI flag echo isn't lost.
fn parse_response(raw: &[u8]) -> Result<RawResponse, String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "raw response has no header terminator".to_string())?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let body = String::from_utf8_lossy(&raw[split + 4..]).to_string();

    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or("");
    // "HTTP/1.1 200 OK" -> 200
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    Ok(RawResponse {
        status,
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn send_raw_preserves_the_encoded_path_verbatim() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel::<String>();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut chunk = [0u8; 2048];
            let n = stream.read(&mut chunk).unwrap();
            let req = String::from_utf8_lossy(&chunk[..n]).to_string();
            tx.send(req).unwrap();
            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nflag";
            stream.write_all(resp.as_bytes()).unwrap();
        });

        // The CVE-2021-41773 shape: encoded dots that ureq would collapse.
        let path = "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh";
        let resp = send_raw("127.0.0.1", port, "POST", path, &HashMap::new(), Some("x"), 5).unwrap();
        server.join().unwrap();

        let sent = rx.recv().unwrap();
        let req_line = sent.lines().next().unwrap();
        assert_eq!(req_line, format!("POST {path} HTTP/1.1"), "path was altered: {req_line}");
        assert!(sent.contains("Content-Length: 1"));
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "flag");
    }

    #[test]
    fn parse_response_extracts_status_and_body() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<h1>nope</h1>";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 404);
        assert_eq!(r.body, "<h1>nope</h1>");
        assert_eq!(r.headers.get("content-type").unwrap(), "text/html");
    }

    #[test]
    fn raw_exchange_sends_bytes_verbatim_and_returns_raw_response() {
        // The caller's bytes must arrive byte-for-byte (incl. a deliberately malformed
        // CL/TE header pair that send_raw could never produce), and the response comes
        // back as raw bytes.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut chunk = [0u8; 2048];
            let n = stream.read(&mut chunk).unwrap();
            tx.send(chunk[..n].to_vec()).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
        });

        let payload = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".to_vec();
        let out = raw_exchange("127.0.0.1", port, &[payload.clone()], 5, 0, 1_000_000).unwrap();
        server.join().unwrap();

        let sent = rx.recv().unwrap();
        assert_eq!(sent, payload, "bytes were altered on the wire");
        assert!(String::from_utf8_lossy(&out).starts_with("HTTP/1.1 200 OK"));
        assert!(out.ends_with(b"ok"));
    }

    #[test]
    fn raw_exchange_reuses_one_connection_for_multiple_payloads() {
        // Two requests on ONE socket (keep-alive) → the raw buffer holds BOTH responses,
        // which is the smuggling/desync oracle (counting responses).
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_millis(500))).ok();
            let mut chunk = [0u8; 4096];
            // Respond once per request line seen (read a couple of times).
            for _ in 0..2 {
                match stream.read(&mut chunk) {
                    Ok(n) if n > 0 => {
                        stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: keep-alive\r\n\r\nACK")
                            .ok();
                    }
                    _ => break,
                }
            }
        });

        let r1 = b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
        let r2 = b"GET /b HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
        let out = raw_exchange("127.0.0.1", port, &[r1, r2], 2, 20, 1_000_000).unwrap();
        server.join().unwrap();

        let body = String::from_utf8_lossy(&out);
        assert_eq!(body.matches("HTTP/1.1 200 OK").count(), 2, "expected two responses: {body:?}");
    }
}
