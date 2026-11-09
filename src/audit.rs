//! Append-only JSONL audit log for all outbound requests.
//!
//! Every HTTP request is logged BEFORE it leaves the box, with the response
//! appended after completion. One file per day: `YYYY-MM-DD.jsonl`.
//!
//! Body and headers are hashed (SHA-256), not stored in full — the audit log
//! records WHAT was done, not the full payload content.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{BufRead, Write};
use std::path::PathBuf;

/// A single audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub target: String,
    pub method: String,
    pub url: String,
    /// SHA-256 of request body, or null if no body.
    pub body_hash: Option<String>,
    /// HTTP response status code, or null if request failed before response.
    pub response_status: Option<u16>,
    /// Request duration in milliseconds.
    pub elapsed_ms: Option<u64>,
    /// Error message if the request failed.
    pub error: Option<String>,
}

/// Append-only JSONL audit log.
#[derive(Debug)]
pub struct AuditLog {
    dir: PathBuf,
    /// Serializes concurrent `log` calls. Sweep/burst drive many threads
    /// through the shared `AuditLog`; without this they would interleave their
    /// writes and corrupt or drop records, defeating the append-only guarantee.
    write_lock: std::sync::Mutex<()>,
}

impl AuditLog {
    /// Create a new audit log writer. Creates the directory if needed.
    pub fn new(dir: PathBuf) -> Result<Self, AuditError> {
        std::fs::create_dir_all(&dir).map_err(|e| AuditError::Io(e.to_string()))?;
        Ok(AuditLog {
            dir,
            write_lock: std::sync::Mutex::new(()),
        })
    }

    /// Log a request entry. Appends one JSON line to today's log file.
    ///
    /// The whole record (including its trailing newline) is written in a single
    /// `write_all` under a lock, so concurrent callers never interleave bytes or
    /// drop a line. A malformed timestamp never panics — the date falls back to
    /// the raw timestamp rather than a byte slice.
    pub fn log(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        // YYYY-MM-DD from an ISO-8601 timestamp — defensively, so a short or
        // non-ASCII timestamp can never panic a byte slice.
        let date = entry
            .timestamp
            .get(..10)
            .unwrap_or(entry.timestamp.as_str());
        let path = self.dir.join(format!("{date}.jsonl"));

        let mut line = serde_json::to_string(entry).map_err(|e| AuditError::Io(e.to_string()))?;
        line.push('\n');

        // Serialize the open+append+write so records are atomic w.r.t. each
        // other across threads.
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| AuditError::Io(e.to_string()))?;
        file.write_all(line.as_bytes())
            .map_err(|e| AuditError::Io(e.to_string()))?;
        Ok(())
    }

    /// Create a pre-request audit entry (before HTTP call).
    pub fn pre_request_entry(
        target: &str,
        method: &str,
        url: &str,
        body: Option<&str>,
    ) -> AuditEntry {
        AuditEntry {
            timestamp: Utc::now().to_rfc3339(),
            target: target.to_string(),
            method: method.to_string(),
            url: url.to_string(),
            body_hash: body.map(hash_sha256),
            response_status: None,
            elapsed_ms: None,
            error: None,
        }
    }

    /// Create a post-request audit entry (after HTTP call completes).
    pub fn post_request_entry(
        target: &str,
        method: &str,
        url: &str,
        body: Option<&str>,
        status: u16,
        elapsed_ms: u64,
    ) -> AuditEntry {
        AuditEntry {
            timestamp: Utc::now().to_rfc3339(),
            target: target.to_string(),
            method: method.to_string(),
            url: url.to_string(),
            body_hash: body.map(hash_sha256),
            response_status: Some(status),
            elapsed_ms: Some(elapsed_ms),
            error: None,
        }
    }

    /// Create an error audit entry (request failed).
    pub fn error_entry(
        target: &str,
        method: &str,
        url: &str,
        body: Option<&str>,
        error: &str,
        elapsed_ms: Option<u64>,
    ) -> AuditEntry {
        AuditEntry {
            timestamp: Utc::now().to_rfc3339(),
            target: target.to_string(),
            method: method.to_string(),
            url: url.to_string(),
            body_hash: body.map(hash_sha256),
            response_status: None,
            elapsed_ms,
            error: Some(error.to_string()),
        }
    }

    /// Query audit entries for a given date, optionally filtered by target.
    ///
    /// `date` must be a literal `YYYY-MM-DD` — it is validated before being
    /// joined into the log path, so a caller-supplied value cannot traverse the
    /// filesystem (`../`, absolute paths) or read an arbitrary file.
    pub fn query(
        &self,
        date: &str,
        target_filter: Option<&str>,
    ) -> Result<Vec<AuditEntry>, AuditError> {
        if !is_valid_log_date(date) {
            return Err(AuditError::BadDate(date.to_string()));
        }
        let path = self.dir.join(format!("{date}.jsonl"));
        if !path.exists() {
            return Ok(vec![]);
        }

        let file = std::fs::File::open(&path).map_err(|e| AuditError::Io(e.to_string()))?;
        let reader = std::io::BufReader::new(file);
        let mut entries = Vec::new();

        for line in reader.lines() {
            let line = line.map_err(|e| AuditError::Io(e.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }
            // Skip corrupt lines gracefully
            if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) {
                if let Some(filter) = target_filter {
                    if entry.target == filter {
                        entries.push(entry);
                    }
                } else {
                    entries.push(entry);
                }
            }
        }

        Ok(entries)
    }
}

/// SHA-256 hash of a string, returned as hex.
fn hash_sha256(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// True for a literal `YYYY-MM-DD` date: exactly 10 chars, digits with `-` at
/// positions 4 and 7. Rejects anything with a path separator, `.`, or other
/// bytes that could escape the log directory.
fn is_valid_log_date(date: &str) -> bool {
    let b = date.as_bytes();
    b.len() == 10
        && b.iter().enumerate().all(|(i, c)| {
            if i == 4 || i == 7 {
                *c == b'-'
            } else {
                c.is_ascii_digit()
            }
        })
}

#[derive(Debug)]
#[non_exhaustive]
pub enum AuditError {
    Io(String),
    /// A query date was not a literal `YYYY-MM-DD`.
    BadDate(String),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditError::Io(msg) => write!(f, "Audit log error: {msg}"),
            AuditError::BadDate(d) => {
                write!(f, "Invalid audit date (expected YYYY-MM-DD): {d:?}")
            }
        }
    }
}

impl std::error::Error for AuditError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic() {
        let h1 = hash_sha256("hello world");
        let h2 = hash_sha256("hello world");
        assert_eq!(h1, h2);
        assert_ne!(h1, hash_sha256("different"));
    }

    #[test]
    fn write_and_read_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().to_path_buf()).unwrap();

        let entry = AuditLog::post_request_entry(
            "linkedin",
            "GET",
            "https://api.linkedin.com/foo",
            None,
            200,
            150,
        );
        log.log(&entry).unwrap();

        let date = &entry.timestamp[..10];
        let entries = log.query(date, None).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].target, "linkedin");
        assert_eq!(entries[0].response_status, Some(200));
        assert_eq!(entries[0].elapsed_ms, Some(150));
    }

    #[test]
    fn multiple_entries_same_day() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().to_path_buf()).unwrap();

        for i in 0..5 {
            let entry = AuditLog::post_request_entry(
                "test",
                "GET",
                &format!("https://example.com/{i}"),
                None,
                200,
                100,
            );
            log.log(&entry).unwrap();
        }

        let date = &Utc::now().to_rfc3339()[..10];
        let entries = log.query(date, None).unwrap();
        assert_eq!(entries.len(), 5);
    }

    #[test]
    fn filter_by_target() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().to_path_buf()).unwrap();

        log.log(&AuditLog::post_request_entry(
            "linkedin",
            "GET",
            "https://linkedin.com/a",
            None,
            200,
            50,
        ))
        .unwrap();
        log.log(&AuditLog::post_request_entry(
            "cloudflare",
            "GET",
            "https://cloudflare.com/b",
            None,
            200,
            60,
        ))
        .unwrap();
        log.log(&AuditLog::post_request_entry(
            "linkedin",
            "POST",
            "https://linkedin.com/c",
            Some("body"),
            201,
            70,
        ))
        .unwrap();

        let date = &Utc::now().to_rfc3339()[..10];
        let linkedin = log.query(date, Some("linkedin")).unwrap();
        assert_eq!(linkedin.len(), 2);

        let cloudflare = log.query(date, Some("cloudflare")).unwrap();
        assert_eq!(cloudflare.len(), 1);
    }

    #[test]
    fn query_missing_date_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().to_path_buf()).unwrap();
        let entries = log.query("1999-01-01", None).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn body_hash_present_when_body_given() {
        let entry = AuditLog::pre_request_entry(
            "test",
            "POST",
            "https://example.com",
            Some("secret payload"),
        );
        assert!(entry.body_hash.is_some());
        // Hash should be 64 hex chars (SHA-256)
        assert_eq!(entry.body_hash.as_ref().unwrap().len(), 64);
    }

    #[test]
    fn body_hash_none_when_no_body() {
        let entry = AuditLog::pre_request_entry("test", "GET", "https://example.com", None);
        assert!(entry.body_hash.is_none());
    }

    #[test]
    fn error_entry_captures_error() {
        let entry = AuditLog::error_entry(
            "test",
            "GET",
            "https://example.com",
            None,
            "connection refused",
            Some(50),
        );
        assert_eq!(entry.error.as_deref(), Some("connection refused"));
        assert!(entry.response_status.is_none());
    }

    #[test]
    fn corrupt_lines_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().to_path_buf()).unwrap();

        // Write a valid entry
        let entry =
            AuditLog::post_request_entry("test", "GET", "https://example.com", None, 200, 100);
        log.log(&entry).unwrap();

        // Manually append a corrupt line
        let date = &entry.timestamp[..10];
        let path = dir.path().join(format!("{date}.jsonl"));
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(f, "{{this is not valid json").unwrap();

        // Write another valid entry
        let entry2 =
            AuditLog::post_request_entry("test", "GET", "https://example.com/2", None, 201, 200);
        log.log(&entry2).unwrap();

        // Query should return 2 valid entries, skipping the corrupt line
        let entries = log.query(date, None).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn concurrent_logs_are_not_lost_or_corrupted() {
        // Many threads writing through the shared AuditLog must not interleave
        // or drop records — every line stays a parseable JSON entry.
        let dir = tempfile::tempdir().unwrap();
        let log = std::sync::Arc::new(AuditLog::new(dir.path().to_path_buf()).unwrap());
        let date = Utc::now().to_rfc3339()[..10].to_string();

        let mut handles = Vec::new();
        for t in 0..8 {
            let log = log.clone();
            handles.push(std::thread::spawn(move || {
                for i in 0..50 {
                    let e = AuditLog::post_request_entry(
                        "t",
                        "GET",
                        &format!("https://example.com/{t}-{i}"),
                        None,
                        200,
                        1,
                    );
                    log.log(&e).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let entries = log.query(&date, None).unwrap();
        assert_eq!(
            entries.len(),
            400,
            "all concurrent entries must be present and parseable"
        );
    }

    #[test]
    fn log_does_not_panic_on_short_or_non_ascii_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().to_path_buf()).unwrap();
        let mut e = AuditLog::post_request_entry("t", "GET", "https://example.com", None, 200, 1);
        e.timestamp = "é".to_string(); // multi-byte and shorter than 10 bytes
        assert!(log.log(&e).is_ok());
    }

    #[test]
    fn query_rejects_malformed_date() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().to_path_buf()).unwrap();
        assert!(matches!(
            log.query("../secret", None),
            Err(AuditError::BadDate(_))
        ));
        assert!(matches!(
            log.query("2026/01/01", None),
            Err(AuditError::BadDate(_))
        ));
        assert!(matches!(
            log.query("not-a-date", None),
            Err(AuditError::BadDate(_))
        ));
        // A well-formed date is still accepted (empty when no file exists).
        assert!(log.query("2026-01-01", None).unwrap().is_empty());
    }
}
