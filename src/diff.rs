//! Response diffing engine for smart_repeater.
//!
//! Compares a baseline HTTP response against a mutation response and produces
//! a structured diff. JSON-aware: if both responses are valid JSON, the engine
//! extracts key/value differences up to 2 levels deep.
//!
//! The diff is designed to be context-efficient for LLM consumption — it
//! summarizes what changed, not the full response bodies.

#![allow(dead_code)]

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Mutation must take at least this many times longer than baseline...
const TIMING_MULTIPLIER: f64 = 2.0;
/// ...AND be at least this much slower in absolute terms, to avoid noise on
/// fast endpoints where a 2x ratio is just a few milliseconds of jitter.
/// Mirrors intruder.py's own `_TIMING_MULTIPLIER`/`_TIMING_MIN_DELTA_MS`.
const TIMING_MIN_DELTA_MS: i64 = 500;

/// Security-relevant headers to include in diff (lowercase).
const SECURITY_HEADERS: &[&str] = &[
    "content-type",
    "server",
    "x-powered-by",
    "set-cookie",
    "location",
    "www-authenticate",
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "x-xss-protection",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "retry-after",
];

/// A change in a response header.
#[derive(Debug, Clone, Serialize)]
pub struct HeaderChange {
    pub key: String,
    /// Value in baseline (None if header was absent).
    pub baseline: Option<String>,
    /// Value in mutation (None if header was absent).
    pub mutation: Option<String>,
}

/// A change in a JSON value.
#[derive(Debug, Clone, Serialize)]
pub struct JsonValueChange {
    pub path: String,
    pub baseline: String,
    pub mutation: String,
}

/// JSON structural diff.
#[derive(Debug, Clone, Serialize, Default)]
pub struct JsonDiff {
    /// Keys present in mutation but not in baseline.
    pub keys_added: Vec<String>,
    /// Keys present in baseline but not in mutation.
    pub keys_removed: Vec<String>,
    /// Keys with different values.
    pub values_changed: Vec<JsonValueChange>,
}

impl JsonDiff {
    pub fn is_empty(&self) -> bool {
        self.keys_added.is_empty() && self.keys_removed.is_empty() && self.values_changed.is_empty()
    }

    pub fn change_count(&self) -> usize {
        self.keys_added.len() + self.keys_removed.len() + self.values_changed.len()
    }
}

/// Full response diff.
#[derive(Debug, Clone, Serialize)]
pub struct ResponseDiff {
    pub status_match: bool,
    pub status_baseline: u16,
    pub status_mutation: u16,
    pub body_len_baseline: usize,
    pub body_len_mutation: usize,
    pub body_len_delta: i64,
    pub header_changes: Vec<HeaderChange>,
    pub json_diff: Option<JsonDiff>,
    pub elapsed_ms_baseline: u64,
    pub elapsed_ms_mutation: u64,
    /// mutation elapsed - baseline elapsed. Negative means mutation was faster.
    pub timing_delta_ms: i64,
    /// True when the mutation is reproducibly slower than baseline by both a
    /// multiplier and an absolute floor — the confirmation signal for
    /// time-based blind injection (cmdi/sqli/ssrf-timing) when status/body
    /// give no other signal (molly#23).
    pub timing_anomaly: bool,
    pub verdict: String,
}

/// Compare two HTTP responses and produce a structured diff.
#[allow(clippy::too_many_arguments)] // a response is (status, headers, body, elapsed) x2
pub fn diff_responses(
    baseline_status: u16,
    baseline_headers: &HashMap<String, String>,
    baseline_body: &str,
    baseline_elapsed_ms: u64,
    mutation_status: u16,
    mutation_headers: &HashMap<String, String>,
    mutation_body: &str,
    mutation_elapsed_ms: u64,
) -> ResponseDiff {
    let status_match = baseline_status == mutation_status;
    let body_len_baseline = baseline_body.len();
    let body_len_mutation = mutation_body.len();
    let body_len_delta = body_len_mutation as i64 - body_len_baseline as i64;

    let header_changes = diff_headers(baseline_headers, mutation_headers);
    let json_diff = diff_json_bodies(baseline_body, mutation_body);

    let timing_delta_ms = mutation_elapsed_ms as i64 - baseline_elapsed_ms as i64;
    let timing_anomaly = baseline_elapsed_ms > 0
        && (mutation_elapsed_ms as f64) > (baseline_elapsed_ms as f64) * TIMING_MULTIPLIER
        && timing_delta_ms > TIMING_MIN_DELTA_MS;

    let verdict = compute_verdict(
        status_match,
        baseline_status,
        mutation_status,
        body_len_baseline,
        body_len_mutation,
        &json_diff,
        timing_anomaly,
        timing_delta_ms,
    );

    ResponseDiff {
        status_match,
        status_baseline: baseline_status,
        status_mutation: mutation_status,
        body_len_baseline,
        body_len_mutation,
        body_len_delta,
        header_changes,
        json_diff,
        elapsed_ms_baseline: baseline_elapsed_ms,
        elapsed_ms_mutation: mutation_elapsed_ms,
        timing_delta_ms,
        timing_anomaly,
        verdict,
    }
}

/// Diff security-relevant headers between baseline and mutation.
fn diff_headers(
    baseline: &HashMap<String, String>,
    mutation: &HashMap<String, String>,
) -> Vec<HeaderChange> {
    let mut changes = Vec::new();
    let security_set: BTreeSet<&str> = SECURITY_HEADERS.iter().copied().collect();

    // Normalize to lowercase keys
    let base_lower: HashMap<String, &str> = baseline
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.as_str()))
        .collect();
    let mut_lower: HashMap<String, &str> = mutation
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.as_str()))
        .collect();

    // Check all security-relevant headers
    for &header in &security_set {
        let base_val = base_lower.get(header);
        let mut_val = mut_lower.get(header);

        match (base_val, mut_val) {
            (Some(b), Some(m)) if b != m => {
                changes.push(HeaderChange {
                    key: header.to_string(),
                    baseline: Some(b.to_string()),
                    mutation: Some(m.to_string()),
                });
            }
            (Some(b), None) => {
                changes.push(HeaderChange {
                    key: header.to_string(),
                    baseline: Some(b.to_string()),
                    mutation: None,
                });
            }
            (None, Some(m)) => {
                changes.push(HeaderChange {
                    key: header.to_string(),
                    baseline: None,
                    mutation: Some(m.to_string()),
                });
            }
            _ => {} // Same or both absent
        }
    }

    changes
}

/// Bodies larger than this are NOT parsed as JSON for diffing — a sweep worker
/// runs this on an attacker-controlled response body, and parsing a multi-MB
/// document into an owned `serde_json::Value` tree is unbounded memory/CPU. The
/// status/length/header diff still applies above the threshold.
const MAX_JSON_DIFF_BYTES: usize = 512 * 1024;

/// Try to parse both bodies as JSON and compute a structural diff.
/// Returns None if either body is not valid JSON or is too large to diff.
fn diff_json_bodies(baseline_body: &str, mutation_body: &str) -> Option<JsonDiff> {
    if baseline_body.len() > MAX_JSON_DIFF_BYTES || mutation_body.len() > MAX_JSON_DIFF_BYTES {
        return None;
    }
    let base_val: serde_json::Value = serde_json::from_str(baseline_body).ok()?;
    let mut_val: serde_json::Value = serde_json::from_str(mutation_body).ok()?;

    let base_flat = flatten_json(&base_val, "", 0, 2);
    let mut_flat = flatten_json(&mut_val, "", 0, 2);

    let base_keys: BTreeSet<&str> = base_flat.keys().map(|s| s.as_str()).collect();
    let mut_keys: BTreeSet<&str> = mut_flat.keys().map(|s| s.as_str()).collect();

    let keys_added: Vec<String> = mut_keys
        .difference(&base_keys)
        .map(|s| s.to_string())
        .collect();
    let keys_removed: Vec<String> = base_keys
        .difference(&mut_keys)
        .map(|s| s.to_string())
        .collect();

    let mut values_changed = Vec::new();
    for key in base_keys.intersection(&mut_keys) {
        let bv = &base_flat[*key];
        let mv = &mut_flat[*key];
        if bv != mv {
            values_changed.push(JsonValueChange {
                path: key.to_string(),
                baseline: value_summary(bv),
                mutation: value_summary(mv),
            });
        }
    }

    Some(JsonDiff {
        keys_added,
        keys_removed,
        values_changed,
    })
}

/// Flatten a JSON value into dotted-path keys, up to `max_depth` levels.
fn flatten_json(
    val: &serde_json::Value,
    prefix: &str,
    depth: usize,
    max_depth: usize,
) -> BTreeMap<String, serde_json::Value> {
    let mut map = BTreeMap::new();

    match val {
        serde_json::Value::Object(obj) if depth < max_depth => {
            for (key, child) in obj {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                map.extend(flatten_json(child, &path, depth + 1, max_depth));
            }
        }
        serde_json::Value::Array(arr) if depth < max_depth => {
            // For arrays, store length and first few element summaries
            map.insert(
                if prefix.is_empty() {
                    "[length]".to_string()
                } else {
                    format!("{prefix}.[length]")
                },
                serde_json::Value::Number(serde_json::Number::from(arr.len())),
            );
            for (i, child) in arr.iter().enumerate().take(3) {
                let path = if prefix.is_empty() {
                    format!("[{i}]")
                } else {
                    format!("{prefix}.[{i}]")
                };
                map.extend(flatten_json(child, &path, depth + 1, max_depth));
            }
        }
        _ => {
            let key = if prefix.is_empty() {
                "(root)".to_string()
            } else {
                prefix.to_string()
            };
            map.insert(key, val.clone());
        }
    }

    map
}

/// Summarize a JSON value as a short string for diff display.
fn value_summary(val: &serde_json::Value) -> String {
    match val {
        serde_json::Value::String(s) => {
            if s.len() > 50 {
                // Truncate to 47 *characters*, not bytes. A raw byte slice
                // `&s[..47]` panics when a multi-byte UTF-8 character straddles
                // byte 47; taking whole chars can never split a codepoint.
                let truncated: String = s.chars().take(47).collect();
                format!("\"{truncated}...\"")
            } else {
                format!("\"{s}\"")
            }
        }
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Array(a) => format!("[{} items]", a.len()),
        serde_json::Value::Object(o) => format!("{{{} keys}}", o.len()),
    }
}

/// Determine a verdict string based on the diff.
#[allow(clippy::too_many_arguments)] // signal inputs are intentionally explicit
fn compute_verdict(
    status_match: bool,
    _baseline_status: u16,
    mutation_status: u16,
    body_len_baseline: usize,
    body_len_mutation: usize,
    json_diff: &Option<JsonDiff>,
    timing_anomaly: bool,
    timing_delta_ms: i64,
) -> String {
    // Blocked by server
    if mutation_status == 401 || mutation_status == 403 {
        return "BLOCKED".to_string();
    }

    // Server error
    if mutation_status >= 500 {
        return "SERVER ERROR".to_string();
    }

    // Status changed
    if !status_match {
        return "STATUS CHANGE".to_string();
    }

    // JSON structural changes
    if let Some(diff) = json_diff {
        if !diff.is_empty() {
            let count = diff.change_count();
            return format!(
                "SIGNIFICANT CHANGE ({count} diff{})",
                if count == 1 { "" } else { "s" }
            );
        }
    }

    // Body length changed significantly (>20%)
    if body_len_baseline > 0 {
        let ratio =
            (body_len_mutation as f64 - body_len_baseline as f64).abs() / body_len_baseline as f64;
        if ratio > 0.2 {
            return "BODY SIZE CHANGE".to_string();
        }
    }

    // Timing anomaly: status and body gave no signal, but the mutation took
    // reproducibly longer — the only confirmation path for a blind sink
    // (unreflected cmdi/sqli/ssrf-timing) whose response is otherwise
    // identical to baseline (molly#23: a `sleep 3` on a real vulnerable
    // endpoint read as "NO CHANGE" because timing was never checked here).
    if timing_anomaly {
        return format!("TIMING ANOMALY (+{timing_delta_ms}ms vs baseline)");
    }

    "NO CHANGE".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// Old 6-arg shape for tests that don't care about timing — elapsed_ms=0
    /// on both sides means `timing_anomaly` can never fire (see the `> 0`
    /// guard on baseline_elapsed_ms in `diff_responses`).
    fn diff0(
        baseline_status: u16,
        baseline_headers: &HashMap<String, String>,
        baseline_body: &str,
        mutation_status: u16,
        mutation_headers: &HashMap<String, String>,
        mutation_body: &str,
    ) -> ResponseDiff {
        diff_responses(
            baseline_status,
            baseline_headers,
            baseline_body,
            0,
            mutation_status,
            mutation_headers,
            mutation_body,
            0,
        )
    }

    #[test]
    fn identical_responses() {
        let diff = diff0(
            200,
            &headers(&[("content-type", "application/json")]),
            r#"{"id": 1}"#,
            200,
            &headers(&[("content-type", "application/json")]),
            r#"{"id": 1}"#,
        );
        assert!(diff.status_match);
        assert_eq!(diff.body_len_delta, 0);
        assert!(diff.header_changes.is_empty());
        assert!(diff.json_diff.as_ref().unwrap().is_empty());
        assert_eq!(diff.verdict, "NO CHANGE");
    }

    #[test]
    fn status_change() {
        let diff = diff0(200, &headers(&[]), "ok", 404, &headers(&[]), "not found");
        assert!(!diff.status_match);
        assert_eq!(diff.status_baseline, 200);
        assert_eq!(diff.status_mutation, 404);
        assert_eq!(diff.verdict, "STATUS CHANGE");
    }

    #[test]
    fn blocked_403() {
        let diff = diff0(200, &headers(&[]), "ok", 403, &headers(&[]), "forbidden");
        assert_eq!(diff.verdict, "BLOCKED");
    }

    #[test]
    fn blocked_401() {
        let diff = diff0(200, &headers(&[]), "ok", 401, &headers(&[]), "unauthorized");
        assert_eq!(diff.verdict, "BLOCKED");
    }

    #[test]
    fn server_error_500() {
        let diff = diff0(200, &headers(&[]), "ok", 500, &headers(&[]), "error");
        assert_eq!(diff.verdict, "SERVER ERROR");
    }

    #[test]
    fn json_value_change() {
        let diff = diff0(
            200,
            &headers(&[("content-type", "application/json")]),
            r#"{"user": {"id": 123, "name": "Alice"}}"#,
            200,
            &headers(&[("content-type", "application/json")]),
            r#"{"user": {"id": 456, "name": "Bob"}}"#,
        );
        assert!(diff.status_match);
        let jd = diff.json_diff.as_ref().unwrap();
        assert!(jd.keys_added.is_empty());
        assert!(jd.keys_removed.is_empty());
        assert_eq!(jd.values_changed.len(), 2); // user.id + user.name
        assert!(diff.verdict.starts_with("SIGNIFICANT CHANGE"));
    }

    #[test]
    fn json_key_added() {
        let diff = diff0(
            200,
            &headers(&[]),
            r#"{"id": 1}"#,
            200,
            &headers(&[]),
            r#"{"id": 1, "role": "admin"}"#,
        );
        let jd = diff.json_diff.as_ref().unwrap();
        assert!(jd.keys_added.contains(&"role".to_string()));
        assert!(diff.verdict.starts_with("SIGNIFICANT CHANGE"));
    }

    #[test]
    fn json_key_removed() {
        let diff = diff0(
            200,
            &headers(&[]),
            r#"{"id": 1, "secret": "xyz"}"#,
            200,
            &headers(&[]),
            r#"{"id": 1}"#,
        );
        let jd = diff.json_diff.as_ref().unwrap();
        assert!(jd.keys_removed.contains(&"secret".to_string()));
    }

    #[test]
    fn header_change_detected() {
        let diff = diff0(
            200,
            &headers(&[("server", "nginx"), ("content-type", "text/html")]),
            "hello",
            200,
            &headers(&[("server", "apache"), ("content-type", "text/html")]),
            "hello",
        );
        assert_eq!(diff.header_changes.len(), 1);
        assert_eq!(diff.header_changes[0].key, "server");
        assert_eq!(diff.header_changes[0].baseline.as_deref(), Some("nginx"));
        assert_eq!(diff.header_changes[0].mutation.as_deref(), Some("apache"));
    }

    #[test]
    fn header_added_in_mutation() {
        let diff = diff0(
            200,
            &headers(&[]),
            "",
            200,
            &headers(&[("set-cookie", "session=abc")]),
            "",
        );
        assert_eq!(diff.header_changes.len(), 1);
        assert_eq!(diff.header_changes[0].key, "set-cookie");
        assert!(diff.header_changes[0].baseline.is_none());
        assert!(diff.header_changes[0].mutation.is_some());
    }

    #[test]
    fn header_removed_in_mutation() {
        let diff = diff0(
            200,
            &headers(&[("x-powered-by", "Express")]),
            "",
            200,
            &headers(&[]),
            "",
        );
        assert_eq!(diff.header_changes.len(), 1);
        assert_eq!(diff.header_changes[0].key, "x-powered-by");
        assert!(diff.header_changes[0].baseline.is_some());
        assert!(diff.header_changes[0].mutation.is_none());
    }

    #[test]
    fn non_json_body_size_change() {
        let baseline = "a".repeat(100);
        let mutation = "b".repeat(200);
        let diff = diff0(200, &headers(&[]), &baseline, 200, &headers(&[]), &mutation);
        assert!(diff.json_diff.is_none()); // Not JSON
        assert_eq!(diff.body_len_delta, 100);
        assert_eq!(diff.verdict, "BODY SIZE CHANGE");
    }

    #[test]
    fn non_json_same_size() {
        let diff = diff0(
            200,
            &headers(&[]),
            "hello world",
            200,
            &headers(&[]),
            "hello there",
        );
        assert!(diff.json_diff.is_none());
        assert_eq!(diff.verdict, "NO CHANGE"); // Same size, not JSON
    }

    #[test]
    fn json_array_diff() {
        let diff = diff0(
            200,
            &headers(&[]),
            r#"{"items": [1, 2, 3]}"#,
            200,
            &headers(&[]),
            r#"{"items": [1, 2, 3, 4, 5]}"#,
        );
        let jd = diff.json_diff.as_ref().unwrap();
        // Array length should differ
        let length_changes: Vec<_> = jd
            .values_changed
            .iter()
            .filter(|c| c.path.contains("[length]"))
            .collect();
        assert!(!length_changes.is_empty());
    }

    #[test]
    fn nested_json_respects_depth_limit() {
        // Only 2 levels deep
        let diff = diff0(
            200,
            &headers(&[]),
            r#"{"a": {"b": {"c": {"d": 1}}}}"#,
            200,
            &headers(&[]),
            r#"{"a": {"b": {"c": {"d": 2}}}}"#,
        );
        let jd = diff.json_diff.as_ref().unwrap();
        // At depth 2, a.b is the leaf — the inner {"c":...} is treated as a whole value
        // So values_changed should have a.b with different values
        assert!(!jd.is_empty());
    }

    #[test]
    fn value_summary_truncation() {
        let long_str = serde_json::Value::String("x".repeat(100));
        let summary = value_summary(&long_str);
        assert!(summary.len() < 60);
        assert!(summary.ends_with("...\""));
    }

    #[test]
    fn value_summary_does_not_panic_on_multibyte_boundary() {
        // Regression: a multi-byte char straddling byte 47 used to panic the
        // raw slice `&s[..47]`. 46 ASCII bytes + 'é' (2 bytes) puts a codepoint
        // boundary across byte 47; the summary must truncate safely instead.
        let s = format!("{}é{}", "a".repeat(46), "b".repeat(60));
        assert!(s.len() > 50);
        let summary = value_summary(&serde_json::Value::String(s));
        assert!(summary.ends_with("...\""));
        // Bounded: two quotes + up to 47 chars + "..." = at most 52 chars.
        assert!(
            summary.chars().count() <= 47 + 5,
            "len was {}",
            summary.chars().count()
        );
    }

    #[test]
    fn diff_bodies_with_multibyte_values_do_not_panic() {
        // End-to-end through diff_responses: a changed JSON string value with a
        // multi-byte char near the truncation boundary must diff, not panic.
        let base = format!(r#"{{"k":"{}"}}"#, "a".repeat(80));
        let mutant = format!(r#"{{"k":"{}é{}"}}"#, "a".repeat(46), "b".repeat(40));
        let diff = diff0(200, &headers(&[]), &base, 200, &headers(&[]), &mutant);
        let jd = diff.json_diff.as_ref().unwrap();
        assert_eq!(jd.values_changed.len(), 1);
    }

    #[test]
    fn empty_bodies() {
        let diff = diff0(200, &headers(&[]), "", 200, &headers(&[]), "");
        assert!(diff.json_diff.is_none());
        assert_eq!(diff.body_len_delta, 0);
        assert_eq!(diff.verdict, "NO CHANGE");
    }

    #[test]
    fn oversized_json_bodies_are_not_diffed() {
        // Above the JSON-diff size cap, parsing is skipped (no unbounded
        // alloc), but the overall diff still works via status/length.
        let big = format!(r#"{{"k":"{}"}}"#, "a".repeat(600_000));
        let diff = diff0(200, &headers(&[]), &big, 200, &headers(&[]), &big);
        assert!(
            diff.json_diff.is_none(),
            "oversized bodies must not be JSON-diffed"
        );
        assert_eq!(diff.verdict, "NO CHANGE"); // same body, same size
    }

    // --- Timing anomaly (molly#23) ---

    #[test]
    fn blind_timing_delay_flagged_when_body_identical() {
        // XBEN-037 shape: `; sleep 3` on a blind cmdi sink returns the exact
        // same body/status as baseline, just slower. Ground truth from the
        // issue: baseline ~1056ms, `sleep 3` mutation ~4000ms+.
        let diff = diff_responses(
            200,
            &headers(&[]),
            "Host is reachable!",
            1056,
            200,
            &headers(&[]),
            "Host is reachable!",
            4080,
        );
        assert!(diff.timing_anomaly);
        assert_eq!(diff.timing_delta_ms, 3024);
        assert_eq!(diff.verdict, "TIMING ANOMALY (+3024ms vs baseline)");
    }

    #[test]
    fn timing_delta_tracks_larger_sleep() {
        let diff = diff_responses(
            200,
            &headers(&[]),
            "Host is reachable!",
            1056,
            200,
            &headers(&[]),
            "Host is reachable!",
            6100,
        );
        assert!(diff.timing_anomaly);
        assert_eq!(diff.timing_delta_ms, 5044);
    }

    #[test]
    fn minor_jitter_is_not_a_timing_anomaly() {
        // Same order of magnitude, well under both the 2x multiplier and the
        // 500ms floor — ordinary network jitter, not a signal.
        let diff = diff_responses(200, &headers(&[]), "ok", 200, 200, &headers(&[]), "ok", 260);
        assert!(!diff.timing_anomaly);
        assert_eq!(diff.verdict, "NO CHANGE");
    }

    #[test]
    fn large_absolute_delta_below_multiplier_is_not_anomaly() {
        // 2x+ the absolute floor but well under the 2x multiplier — a slow
        // baseline (2000ms) getting a bit slower (2600ms) isn't reproducible
        // injection evidence, it's normal endpoint variance.
        let diff = diff_responses(
            200,
            &headers(&[]),
            "ok",
            2000,
            200,
            &headers(&[]),
            "ok",
            2600,
        );
        assert!(!diff.timing_anomaly);
    }

    #[test]
    fn zero_baseline_elapsed_never_flags_timing_anomaly() {
        // Guards the `baseline_elapsed_ms > 0` check — an unset/zero baseline
        // timing must never produce a spurious multiplier-based anomaly.
        let diff = diff_responses(200, &headers(&[]), "ok", 0, 200, &headers(&[]), "ok", 5000);
        assert!(!diff.timing_anomaly);
    }

    #[test]
    fn timing_anomaly_does_not_override_a_status_change() {
        // A more specific, stronger signal (status change) still wins even
        // when timing also looks anomalous.
        let diff = diff_responses(
            200,
            &headers(&[]),
            "ok",
            1000,
            500,
            &headers(&[]),
            "error",
            9000,
        );
        assert_eq!(diff.verdict, "SERVER ERROR");
        assert!(diff.timing_anomaly); // still computed/surfaced, just not the verdict
    }
}
