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
}

impl AuditLog {
    /// Create a new audit log writer. Creates the directory if needed.
    pub fn new(dir: PathBuf) -> Result<Self, AuditError> {
        std::fs::create_dir_all(&dir).map_err(|e| AuditError::Io(e.to_string()))?;
        Ok(AuditLog { dir })
    }

    /// Log a request entry. Appends one JSON line to today's log file.
    pub fn log(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        let date = &entry.timestamp[..10]; // YYYY-MM-DD from ISO 8601
        let path = self.dir.join(format!("{date}.jsonl"));

        let line = serde_json::to_string(entry).map_err(|e| AuditError::Io(e.to_string()))?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| AuditError::Io(e.to_string()))?;

        writeln!(file, "{line}").map_err(|e| AuditError::Io(e.to_string()))?;
        Ok(())
    }

    /// Create a pre-request audit entry (before HTTP call).
    pub fn pre_request_entry(target: &str, method: &str, url: &str, body: Option<&str>) -> AuditEntry {
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
    pub fn query(&self, date: &str, target_filter: Option<&str>) -> Result<Vec<AuditEntry>, AuditError> {
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

#[derive(Debug)]
pub enum AuditError {
    Io(String),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditError::Io(msg) => write!(f, "Audit log error: {msg}"),
        }
    }
}

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

        let entry = AuditLog::post_request_entry("linkedin", "GET", "https://api.linkedin.com/foo", None, 200, 150);
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

        log.log(&AuditLog::post_request_entry("linkedin", "GET", "https://linkedin.com/a", None, 200, 50)).unwrap();
        log.log(&AuditLog::post_request_entry("cloudflare", "GET", "https://cloudflare.com/b", None, 200, 60)).unwrap();
        log.log(&AuditLog::post_request_entry("linkedin", "POST", "https://linkedin.com/c", Some("body"), 201, 70)).unwrap();

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
        let entry = AuditLog::pre_request_entry("test", "POST", "https://example.com", Some("secret payload"));
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
        let entry = AuditLog::error_entry("test", "GET", "https://example.com", None, "connection refused", Some(50));
        assert_eq!(entry.error.as_deref(), Some("connection refused"));
        assert!(entry.response_status.is_none());
    }

    #[test]
    fn corrupt_lines_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().to_path_buf()).unwrap();

        // Write a valid entry
        let entry = AuditLog::post_request_entry("test", "GET", "https://example.com", None, 200, 100);
        log.log(&entry).unwrap();

        // Manually append a corrupt line
        let date = &entry.timestamp[..10];
        let path = dir.path().join(format!("{date}.jsonl"));
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(f, "{{this is not valid json").unwrap();

        // Write another valid entry
        let entry2 = AuditLog::post_request_entry("test", "GET", "https://example.com/2", None, 201, 200);
        log.log(&entry2).unwrap();

        // Query should return 2 valid entries, skipping the corrupt line
        let entries = log.query(date, None).unwrap();
        assert_eq!(entries.len(), 2);
    }
}
