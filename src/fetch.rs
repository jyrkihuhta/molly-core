//! HTTP client with safety gates — the core of Molly's outbound request pipeline.
//!
//! Every outbound request passes through:
//! 1. Target resolution (which scope checker matches this URL?)
//! 2. Armed state check — **skipped in Passive mode** (enumeration/recon)
//! 3. Rate limit check (does the target have tokens?)
//! 4. Audit log (pre-request)
//! 5. HTTP request via ureq
//! 6. Audit log (post-request)
//!
//! If any gate fails, the request is blocked and an error is returned.
//!
//! ## Request modes
//!
//! - `Active` (default): full safety gates including armed check. Used by the
//!   testing pipeline (smart_repeater, offensive tools).
//! - `Passive`: scope + rate limit + audit, but **no armed check**. Used by
//!   enumeration tools (crt, dns, fingerprint, headers, exposed files) that
//!   perform passive reconnaissance without offensive payloads.

#![allow(dead_code)] // Public API surface — some methods used only from Python via lib.rs

use crate::armed::{ArmedError, ArmedState};
use crate::audit::AuditLog;
use crate::rate_limiter::{RateLimitError, RateLimiter};
use crate::scope::ScopeChecker;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex, RwLock};
use std::time::{Duration, Instant};

/// A request body: UTF-8 text, raw bytes, or none. Bytes go out via ureq's
/// `send_bytes` so a binary payload (a magic-byte file-upload polyglot, say)
/// survives intact — encoding it as a `&str` would mangle non-UTF-8 bytes like
/// a JPEG's leading `0xFF 0xD8`. Same safety gates as a text body.
pub enum ReqBody<'a> {
    None,
    Text(&'a str),
    Bytes(&'a [u8]),
}

/// Collect all response headers into a name -> value map, joining repeated
/// headers (e.g. multiple `Set-Cookie`s on a login response) with `\n`
/// instead of silently dropping all but one. `headers_names()` yields one
/// entry per *occurrence*, and `header()` only ever returns the first value
/// for a name — naively looping both, as this used to, re-inserts the same
/// first value once per occurrence rather than collecting the rest.
fn collect_headers(resp: &ureq::Response) -> HashMap<String, String> {
    let mut seen = HashSet::new();
    let mut out = HashMap::new();
    for name in resp.headers_names() {
        if !seen.insert(name.clone()) {
            continue;
        }
        let values = resp.all(&name);
        if !values.is_empty() {
            out.insert(name, values.join("\n"));
        }
    }
    out
}

/// Controls which safety gates a request passes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestMode {
    /// Full safety gates: scope + armed + rate limit + audit.
    /// Used by the testing pipeline for offensive operations.
    Active,
    /// Reduced gates: scope + rate limit + audit (no armed check).
    /// Used by enumeration tools for passive reconnaissance.
    Passive,
}

impl RequestMode {
    pub fn from_str(s: &str) -> Result<Self, FetchError> {
        match s.to_lowercase().as_str() {
            "active" => Ok(RequestMode::Active),
            "passive" => Ok(RequestMode::Passive),
            other => Err(FetchError::InvalidMethod(format!(
                "Invalid request mode: '{other}' — use active/passive"
            ))),
        }
    }
}

/// HTTP response returned to Python.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub elapsed_ms: u64,
}

/// Errors from the fetch pipeline.
#[derive(Debug)]
pub enum FetchError {
    /// URL is not in any target's scope.
    NoMatchingTarget(String),
    /// URL matches a scope but is explicitly denied.
    ScopeViolation(String),
    /// Target is not armed.
    NotArmed(String),
    /// Target is paused.
    Paused(String),
    /// Rate limit exceeded — includes retry duration in ms.
    RateLimited {
        target: String,
        retry_after_ms: u64,
    },
    /// HTTP request failed.
    HttpError(String),
    /// Invalid HTTP method.
    InvalidMethod(String),
    /// The pre-request audit entry could not be written. Fail closed: an
    /// active request is aborted rather than firing unlogged, preserving the
    /// "log BEFORE it leaves the box" guarantee.
    AuditWriteFailed(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::NoMatchingTarget(url) => {
                write!(f, "No target in scope for URL: {url}")
            }
            FetchError::ScopeViolation(msg) => write!(f, "Scope violation: {msg}"),
            FetchError::NotArmed(target) => {
                write!(f, "Target '{target}' is UNARMED — no requests allowed")
            }
            FetchError::Paused(target) => {
                write!(f, "Target '{target}' is PAUSED — requests halted")
            }
            FetchError::RateLimited {
                target,
                retry_after_ms,
            } => write!(
                f,
                "Rate limited on '{target}' — retry after {retry_after_ms}ms"
            ),
            FetchError::HttpError(msg) => write!(f, "HTTP error: {msg}"),
            FetchError::InvalidMethod(m) => write!(f, "Invalid HTTP method: {m}"),
            FetchError::AuditWriteFailed(msg) => {
                write!(f, "Pre-request audit write failed, aborting request: {msg}")
            }
        }
    }
}

/// Target configuration for the HTTP client.
pub struct TargetConfig {
    pub handle: String,
    pub scope_checker: ScopeChecker,
}

/// The safe HTTP client — all outbound requests go through here.
pub struct HttpClient {
    targets: Vec<TargetConfig>,
    armed: Arc<RwLock<ArmedState>>,
    limiter: Arc<Mutex<RateLimiter>>,
    audit: AuditLog,
    agent: ureq::Agent,
}

/// Result of `pre_flight_check` — identifies which target matched.
#[derive(Debug, Clone)]
pub struct PreFlightResult {
    pub target_handle: String,
}

/// One request in a batch (`sweep`) or the template for a `burst`.
#[derive(Debug, Clone)]
pub struct Req {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

/// One result from `sweep` — a fetched mutation, optionally diffed against the
/// baseline. On a request error, `status` is 0, `body` empty, and `error` set.
#[derive(Debug, Clone)]
pub struct SweepOutcome {
    /// Position of this request in the input `mutations` slice (results are
    /// returned in input order regardless of completion order).
    pub index: usize,
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    /// Network time for the final (successful or terminal) attempt, in ms —
    /// excludes any rate-limit backoff sleeping.
    pub elapsed_ms: u64,
    /// Serialized `ResponseDiff` vs the baseline (JSON), or None if no baseline
    /// was supplied or the request errored. Elapsed times are passed as 0/0 so
    /// the diff is a pure status/body/JSON comparison with no timing verdict —
    /// matching `intruder._default_diff`; callers that want timing use
    /// `elapsed_ms` directly.
    pub diff_json: Option<String>,
    pub error: Option<String>,
}

/// One result from `burst` — an identical request fired in a barrier-synchronized
/// wave. `send_offset_ns`/`recv_offset_ns` are nanoseconds from a common origin
/// captured just before the wave, so the spread across outcomes measures how
/// simultaneously the requests actually left.
#[derive(Debug, Clone)]
pub struct BurstOutcome {
    pub index: usize,
    pub status: u16,
    pub body: String,
    pub send_offset_ns: u128,
    pub recv_offset_ns: u128,
    pub elapsed_ms: u64,
    pub error: Option<String>,
}

/// Read a whole-seconds duration from `env_var`, falling back to `default_secs`.
///
/// A value below `floor_secs` is clamped *up* to the floor, and a non-numeric or
/// empty value is ignored — so a misconfiguration can never drive the timeout so
/// low that a legitimately-slow-but-valid response is truncated. In particular the
/// read-timeout floor must stay comfortably above any blind-SQLi `SLEEP(delay)`
/// probe (default 1.5s, `MOLLY_BLIND_SQLI_DELAY`), or those probes would read as
/// "no sleep" and corrupt the time-oracle extraction.
fn env_duration_secs(env_var: &str, default_secs: u64, floor_secs: u64) -> std::time::Duration {
    let secs = std::env::var(env_var)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|v| v.max(floor_secs))
        .unwrap_or(default_secs);
    std::time::Duration::from_secs(secs)
}

impl HttpClient {
    /// Create a new HTTP client.
    ///
    /// `targets` is a list of (handle, scope_rules, requests_per_second).
    pub fn new(
        target_configs: Vec<(String, Vec<String>, f64)>,
        armed: Arc<RwLock<ArmedState>>,
        limiter: Arc<Mutex<RateLimiter>>,
        audit_dir: std::path::PathBuf,
    ) -> Result<Self, FetchError> {
        let targets: Vec<TargetConfig> = target_configs
            .iter()
            .map(|(handle, rules, _rps)| TargetConfig {
                handle: handle.clone(),
                scope_checker: ScopeChecker::new(rules),
            })
            .collect();

        let audit =
            AuditLog::new(audit_dir).map_err(|e| FetchError::HttpError(e.to_string()))?;

        // Per-request timeouts. The read timeout caps how long a *hanging*
        // endpoint costs us: at the old 60s, one dead endpoint burned a full
        // minute per request, so a single deterministic sweep of a hanging path
        // could stall a run by ~500s (observed on the recon sweeps). 20s still
        // clears the slowest legitimate benchmark responses (a few seconds) and
        // the blind-SQLi SLEEP probes, while turning a hang from a minute into
        // ~20s. Both are env-tunable so the eval can trade recall for speed
        // without a rebuild (floor keeps read above the blind-SQLi delay).
        let connect_timeout = env_duration_secs("MOLLY_HTTP_CONNECT_TIMEOUT_SECS", 30, 2);
        let read_timeout = env_duration_secs("MOLLY_HTTP_READ_TIMEOUT_SECS", 20, 5);
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(connect_timeout)
            .timeout_read(read_timeout)
            .redirects(0) // LLM should see redirects explicitly
            .user_agent("molly/0.1.0")
            .build();

        Ok(HttpClient {
            targets,
            armed,
            limiter,
            audit,
            agent,
        })
    }

    /// Pre-flight check: resolve target, check scope, armed state, and rate limit.
    /// Does NOT make an HTTP request. Useful for testing gate logic independently.
    ///
    /// In `Passive` mode, the armed state check is skipped — only scope and
    /// rate limit are enforced. This allows enumeration tools to run freely
    /// on scoped-but-unarmed targets.
    pub fn pre_flight_check(
        &self,
        url: &str,
        mode: RequestMode,
    ) -> Result<PreFlightResult, FetchError> {
        self.pre_flight_check_inner(url, mode, true)
    }

    /// Pre-flight with an explicit rate-limit toggle. `enforce_rate = false`
    /// runs scope (+ armed in Active mode) but consumes no token — used by
    /// `burst`, which deliberately bypasses the per-target limiter for the
    /// race window.
    fn pre_flight_check_inner(
        &self,
        url: &str,
        mode: RequestMode,
        enforce_rate: bool,
    ) -> Result<PreFlightResult, FetchError> {
        // 1. Resolve which target's scope matches this URL
        let target_handle = self.resolve_target(url)?;

        // 2. Check armed state (Active mode only)
        if mode == RequestMode::Active {
            let armed = self.armed.read().map_err(|e| {
                FetchError::HttpError(format!("Armed state lock poisoned: {e}"))
            })?;
            armed.check(&target_handle).map_err(|e| match e {
                ArmedError::Unarmed(t) => FetchError::NotArmed(t),
                ArmedError::Paused(t) => FetchError::Paused(t),
                ArmedError::UnknownTarget(t) => FetchError::NoMatchingTarget(t),
                other => FetchError::HttpError(other.to_string()),
            })?;
            drop(armed);
        }

        // 3. Check rate limit (unless the caller opts out, e.g. burst)
        if enforce_rate {
            let mut limiter = self.limiter.lock().map_err(|e| {
                FetchError::HttpError(format!("Rate limiter lock poisoned: {e}"))
            })?;
            limiter.try_acquire(&target_handle).map_err(|e| match e {
                RateLimitError::RetryAfter(d) => FetchError::RateLimited {
                    target: target_handle.clone(),
                    retry_after_ms: d.as_millis() as u64,
                },
                RateLimitError::UnknownTarget(t) => FetchError::NoMatchingTarget(t),
            })?;
        }

        Ok(PreFlightResult {
            target_handle,
        })
    }

    /// Make an HTTP request through all safety gates.
    ///
    /// Uses `Active` mode by default — see `fetch_with_mode` for passive recon.
    pub fn fetch(
        &self,
        method: &str,
        url: &str,
        headers: &HashMap<String, String>,
        body: Option<&str>,
    ) -> Result<HttpResponse, FetchError> {
        self.fetch_with_mode(method, url, headers, body, RequestMode::Active)
    }

    /// Make an HTTP request with an explicit request mode.
    ///
    /// `Passive` mode skips the armed check — used by enumeration tools.
    /// `Active` mode enforces all safety gates — used by the testing pipeline.
    pub fn fetch_with_mode(
        &self,
        method: &str,
        url: &str,
        headers: &HashMap<String, String>,
        body: Option<&str>,
        mode: RequestMode,
    ) -> Result<HttpResponse, FetchError> {
        let req_body = body.map_or(ReqBody::None, ReqBody::Text);
        self.fetch_core(method, url, headers, req_body, body, mode, true)
    }

    /// Make an HTTP request through the FAIR ADMISSION QUEUE: instead of failing
    /// immediately when the per-target bucket is empty (`fetch`'s behaviour), the
    /// caller BLOCKS until it is admitted — served by (priority desc, FIFO) and
    /// paced at exactly the configured rate. This is how concurrent producers
    /// (the systematic + artistic duel personalities, or many eval workers) share
    /// one target's rate budget without racing and spamming `RateLimited`; a
    /// higher `priority` (e.g. a flag-read probe) jumps ahead of a broad sweep.
    ///
    /// Scope + armed are checked FIRST (fail fast, before queuing — an unarmed or
    /// out-of-scope target never waits and never consumes a token). Then one token
    /// is taken from the fair queue and the request executes WITHOUT consuming a
    /// second token. On the admission deadline it returns `RateLimited` (same
    /// give-up shape as `fetch`), so a caller keeps a defined fallback. Same audit
    /// guarantees as `fetch` (log-before-send, fail-closed in Active mode).
    pub fn fetch_fair(
        &self,
        method: &str,
        url: &str,
        headers: &HashMap<String, String>,
        body: Option<&str>,
        mode: RequestMode,
        priority: i64,
    ) -> Result<HttpResponse, FetchError> {
        // Fail fast on scope/armed before we ever queue or consume a token.
        self.pre_flight_check_inner(url, mode, false)?;
        // Fair, blocking rate admission (consumes the token honoring priority+FIFO).
        self.fair_admit(url, priority)?;
        // Audit + execute; enforce_rate=false — fair_admit already took the token.
        let req_body = body.map_or(ReqBody::None, ReqBody::Text);
        self.fetch_core(method, url, headers, req_body, body, mode, false)
    }

    /// Block until a fair-queue admission token is available for `url`'s target
    /// (honoring priority + FIFO + pacing), or a bounded deadline passes. Clones
    /// the per-target `Arc<FairBucket>` under the brief global limiter lock, then
    /// releases that lock BEFORE blocking — so a waiting request never holds the
    /// global lock and never stalls other targets. The wait budget is
    /// `MOLLY_FAIR_ADMISSION_MAX_WAIT_SECS` (default 60s, floor 1s); on the
    /// deadline it returns `RateLimited` carrying the remaining token-wait.
    fn fair_admit(&self, url: &str, priority: i64) -> Result<(), FetchError> {
        let target = self.resolve_target(url)?;
        let bucket = {
            let limiter = self.limiter.lock().map_err(|e| {
                FetchError::HttpError(format!("Rate limiter lock poisoned: {e}"))
            })?;
            limiter.bucket_for(&target)
        };
        let bucket = bucket.ok_or_else(|| FetchError::NoMatchingTarget(target.clone()))?;
        let max_wait = env_duration_secs("MOLLY_FAIR_ADMISSION_MAX_WAIT_SECS", 60, 1);
        let deadline = Instant::now() + max_wait;
        bucket
            .acquire_blocking(priority, deadline)
            .map_err(|remaining| FetchError::RateLimited {
                target,
                retry_after_ms: remaining.as_millis() as u64,
            })
    }

    /// Like `fetch_with_mode` but with a RAW BYTES body — for binary uploads
    /// (magic-byte polyglots, file submissions) that a UTF-8 `&str` would
    /// corrupt. Same scope/armed/rate-limit/audit gates; the audit logs a
    /// `[binary body, N bytes]` note rather than the raw bytes.
    pub fn fetch_bytes_with_mode(
        &self,
        method: &str,
        url: &str,
        headers: &HashMap<String, String>,
        body: Option<&[u8]>,
        mode: RequestMode,
    ) -> Result<HttpResponse, FetchError> {
        let note = body.map(|b| format!("[binary body, {} bytes]", b.len()));
        let req_body = body.map_or(ReqBody::None, ReqBody::Bytes);
        self.fetch_core(method, url, headers, req_body, note.as_deref(), mode, true)
    }

    /// Shared request path for `fetch_with_mode` / `fetch_bytes_with_mode`:
    /// pre-flight gates → fail-closed pre-audit → execute → post-audit.
    /// `body_audit` is the string form recorded in the audit log (the text body
    /// itself, or a synthesized note for a binary one).
    fn fetch_core(
        &self,
        method: &str,
        url: &str,
        headers: &HashMap<String, String>,
        body: ReqBody<'_>,
        body_audit: Option<&str>,
        mode: RequestMode,
        enforce_rate: bool,
    ) -> Result<HttpResponse, FetchError> {
        // Pre-flight checks (scope, armed if active, rate limit). `enforce_rate`
        // is false only when the caller already consumed a token via the fair
        // admission queue (see `fetch_fair`) — never skip scope/armed.
        let pre_flight = self.pre_flight_check_inner(url, mode, enforce_rate)?;
        let target = &pre_flight.target_handle;

        // Audit log: pre-request. For Active requests this is fail-closed —
        // if we can't record that the request is about to leave the box, we
        // abort rather than fire unlogged ("log BEFORE it leaves"). Passive
        // recon keeps best-effort logging.
        let pre_entry = AuditLog::pre_request_entry(target, method, url, body_audit);
        match self.audit.log(&pre_entry) {
            Ok(()) => {}
            Err(e) => {
                if mode == RequestMode::Active {
                    return Err(FetchError::AuditWriteFailed(e.to_string()));
                }
                // Passive: best effort — don't fail recon on a log error.
            }
        }

        let start = Instant::now();

        // Build and execute the HTTP request
        let result = self.execute_request(method, url, headers, body);
        let elapsed_ms = start.elapsed().as_millis() as u64;

        match &result {
            Ok(response) => {
                let post_entry = AuditLog::post_request_entry(
                    target,
                    method,
                    url,
                    body_audit,
                    response.status,
                    elapsed_ms,
                );
                let _ = self.audit.log(&post_entry);
            }
            Err(e) => {
                let err_entry = AuditLog::error_entry(
                    target,
                    method,
                    url,
                    body_audit,
                    &e.to_string(),
                    Some(elapsed_ms),
                );
                let _ = self.audit.log(&err_entry);
            }
        }

        result
    }

    /// Make an HTTP request with the request-line PATH sent VERBATIM — no
    /// normalization — for path-normalization-bypass exploits (CVE-2021-41773's
    /// `%2e`/`.%2e/` traversal that ureq would collapse). Same scope/armed/rate-limit/
    /// audit gates as `fetch`; the raw send lives in the separate `raw_request` module
    /// (hand-rolled HTTP/1.1 over TcpStream) and never touches the ureq path. `url` is
    /// used for scope resolution + the host/port to connect to; `raw_path` is the exact
    /// request-line target. HTTP only.
    pub fn fetch_raw_path(
        &self,
        method: &str,
        url: &str,
        raw_path: &str,
        headers: &HashMap<String, String>,
        body: Option<&str>,
        mode: RequestMode,
    ) -> Result<HttpResponse, FetchError> {
        // Same gates as fetch: scope + armed (active) + rate limit.
        let pre_flight = self.pre_flight_check(url, mode)?;
        let target = &pre_flight.target_handle;

        let parsed = url::Url::parse(url)
            .map_err(|e| FetchError::HttpError(format!("fetch_raw: bad url {url}: {e}")))?;
        if parsed.scheme() != "http" {
            return Err(FetchError::HttpError(
                "fetch_raw supports http only (benchmark targets are http)".to_string(),
            ));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| FetchError::HttpError("fetch_raw: url has no host".to_string()))?
            .to_string();
        let port = parsed.port_or_known_default().unwrap_or(80);
        let audit_url = format!("http://{host}:{port}{raw_path}");

        // Fail-closed pre-audit (log BEFORE it leaves), same as fetch_core.
        let pre_entry = AuditLog::pre_request_entry(target, method, &audit_url, body);
        if let Err(e) = self.audit.log(&pre_entry) {
            if mode == RequestMode::Active {
                return Err(FetchError::AuditWriteFailed(e.to_string()));
            }
        }

        let start = Instant::now();
        let result = crate::raw_request::send_raw(&host, port, method, raw_path, headers, body, 20)
            .map(|r| HttpResponse {
                status: r.status,
                headers: r.headers,
                body: r.body,
                elapsed_ms: 0,
            })
            .map_err(FetchError::HttpError);
        let elapsed_ms = start.elapsed().as_millis() as u64;

        match &result {
            Ok(resp) => {
                let e = AuditLog::post_request_entry(
                    target, method, &audit_url, body, resp.status, elapsed_ms,
                );
                let _ = self.audit.log(&e);
            }
            Err(e) => {
                let e2 = AuditLog::error_entry(
                    target, method, &audit_url, body, &e.to_string(), Some(elapsed_ms),
                );
                let _ = self.audit.log(&e2);
            }
        }
        result
    }

    /// Raw byte exchange on ONE TCP connection — the protocol-research primitive for HTTP
    /// request smuggling / desync. The caller controls every request byte verbatim (CL/TE
    /// framing, pipelining, multiple requests on one socket), so this is the one primitive
    /// that can craft a desync. Gated EXACTLY like `fetch_raw_path`: `url` is scope-resolved
    /// (host-only) + armed-checked (Active) + rate-limited, the raw bytes are fail-closed
    /// pre-audited ("log BEFORE it leaves the box"), and the socket connects to that same
    /// `url` host:port. HTTP/plaintext only. Returns the raw response bytes (all responses
    /// concatenated, UNPARSED — counting them is the caller's oracle). ONE rate token is
    /// consumed PER payload, acquired up front so rate-waiting never desyncs the exchange.
    pub fn raw_exchange(
        &self,
        url: &str,
        payloads: &[Vec<u8>],
        read_timeout_secs: u64,
        inter_write_delay_ms: u64,
        max_bytes: usize,
        mode: RequestMode,
    ) -> Result<Vec<u8>, FetchError> {
        if payloads.is_empty() {
            return Err(FetchError::HttpError("raw_exchange: no payloads".to_string()));
        }
        // 1. Scope + armed (no token yet) — fail fast before any connection.
        let pre_flight = self.pre_flight_check_inner(url, mode, false)?;
        let target = pre_flight.target_handle;

        // 2. Resolve host:port from the (scoped) url. HTTP only — no TLS on the raw path.
        let parsed = url::Url::parse(url)
            .map_err(|e| FetchError::HttpError(format!("raw_exchange: bad url {url}: {e}")))?;
        if parsed.scheme() != "http" {
            return Err(FetchError::HttpError(
                "raw_exchange supports http only (benchmark targets are http)".to_string(),
            ));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| FetchError::HttpError("raw_exchange: url has no host".to_string()))?
            .to_string();
        let port = parsed.port_or_known_default().unwrap_or(80);

        // 3. Rate: one token PER payload, acquired up front so no rate-sleep desyncs the
        //    timing-sensitive exchange (acquire_token_blocking resolves the same target).
        for _ in 0..payloads.len() {
            self.acquire_token_blocking(url)?;
        }

        // 4. Fail-closed pre-audit (log BEFORE the bytes leave). One entry; the raw bytes
        //    are summarized as a note (hashed), matching fetch_bytes' binary-body note.
        let total: usize = payloads.iter().map(|p| p.len()).sum();
        let note = format!("[raw_exchange: {} payload(s), {} bytes]", payloads.len(), total);
        let audit_url = format!("http://{host}:{port}/");
        let pre_entry = AuditLog::pre_request_entry(&target, "RAW", &audit_url, Some(&note));
        if let Err(e) = self.audit.log(&pre_entry) {
            if mode == RequestMode::Active {
                return Err(FetchError::AuditWriteFailed(e.to_string()));
            }
        }

        // 5. Execute the raw exchange.
        let start = Instant::now();
        let result = crate::raw_request::raw_exchange(
            &host, port, payloads, read_timeout_secs, inter_write_delay_ms, max_bytes,
        )
        .map_err(FetchError::HttpError);
        let elapsed_ms = start.elapsed().as_millis() as u64;

        // 6. Post-audit (best effort).
        match &result {
            Ok(bytes) => {
                let e = AuditLog::post_request_entry(
                    &target, "RAW", &audit_url, Some(&note),
                    if bytes.is_empty() { 0 } else { 200 }, elapsed_ms,
                );
                let _ = self.audit.log(&e);
            }
            Err(e) => {
                let e2 = AuditLog::error_entry(
                    &target, "RAW", &audit_url, Some(&note), &e.to_string(), Some(elapsed_ms),
                );
                let _ = self.audit.log(&e2);
            }
        }
        result
    }

    /// Run an SSH command on the target's host, through the SAME gates as an HTTP
    /// request — for credential-reuse exploits where the flag is only reachable over
    /// SSH (XBEN-042). `url` is the target's in-scope web URL: it's scope/armed/rate
    /// checked, and the SSH connection goes to THAT url's host (never an arbitrary one,
    /// so an in-scope url can't be used to SSH elsewhere) on `port`. The audit records
    /// the command, never the password. The SSH itself lives in the `ssh_exec` module.
    pub fn ssh_exec_gated(
        &self,
        url: &str,
        username: &str,
        password: &str,
        command: &str,
        port: u16,
        mode: RequestMode,
    ) -> Result<crate::ssh_exec::SshResult, FetchError> {
        let pre_flight = self.pre_flight_check(url, mode)?;
        let target = &pre_flight.target_handle;

        let parsed = url::Url::parse(url)
            .map_err(|e| FetchError::HttpError(format!("ssh_exec: bad url {url}: {e}")))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| FetchError::HttpError("ssh_exec: url has no host".to_string()))?
            .to_string();

        let audit_target = format!("ssh://{host}:{port}");
        let audit_cmd = format!("ssh {username}@{host} -- {command}");  // no password
        let pre_entry = AuditLog::pre_request_entry(target, "SSH", &audit_target, Some(&audit_cmd));
        if let Err(e) = self.audit.log(&pre_entry) {
            if mode == RequestMode::Active {
                return Err(FetchError::AuditWriteFailed(e.to_string()));
            }
        }

        let start = Instant::now();
        let result = crate::ssh_exec::ssh_exec(&host, port, username, password, command, 10)
            .map_err(FetchError::HttpError);
        let elapsed_ms = start.elapsed().as_millis() as u64;

        match &result {
            Ok(r) => {
                let e = AuditLog::post_request_entry(
                    target, "SSH", &audit_target, Some(&audit_cmd),
                    if r.exit_status == 0 { 200 } else { 500 }, elapsed_ms,
                );
                let _ = self.audit.log(&e);
            }
            Err(e) => {
                let e2 = AuditLog::error_entry(
                    target, "SSH", &audit_target, Some(&audit_cmd), &e.to_string(),
                    Some(elapsed_ms),
                );
                let _ = self.audit.log(&e2);
            }
        }
        result
    }

    /// Resolve which target's scope checker matches this URL.
    ///
    /// When multiple targets share scope (e.g. `whatnot` + `whatnot-anon`),
    /// armed targets win over unarmed ones. This is the right call because
    /// the typical layout is one auth target armed and the anon sibling
    /// disarmed-on-purpose; routing to the unarmed sibling would make all
    /// authed coverage fail at pre-flight. Order within the armed (or
    /// within the unarmed) bucket falls back to config order.
    ///
    /// Deny rules are still checked first across all targets — an explicit
    /// out-of-scope rule on any matching target wins regardless of armed
    /// state.
    fn resolve_target(&self, url: &str) -> Result<String, FetchError> {
        let mut armed_match: Option<String> = None;
        let mut unarmed_match: Option<String> = None;

        let armed_state = self.armed.read().ok();
        for target in &self.targets {
            match target.scope_checker.check(url) {
                Ok(()) => {
                    let is_armed = armed_state
                        .as_ref()
                        .map(|s| {
                            // Treat any non-Unarmed state (Armed, Paused) as
                            // "preferred over Unarmed" — Paused targets are
                            // intentionally configured even if not actively
                            // sweeping right now.
                            !matches!(s.check(&target.handle), Err(ArmedError::Unarmed(_)))
                        })
                        .unwrap_or(true);
                    if is_armed && armed_match.is_none() {
                        armed_match = Some(target.handle.clone());
                    } else if !is_armed && unarmed_match.is_none() {
                        unarmed_match = Some(target.handle.clone());
                    }
                }
                Err(crate::scope::ScopeError::ExplicitlyDenied(msg)) => {
                    return Err(FetchError::ScopeViolation(msg));
                }
                Err(_) => continue, // Not in this target's scope, try next
            }
        }
        armed_match
            .or(unarmed_match)
            .ok_or_else(|| FetchError::NoMatchingTarget(url.to_string()))
    }

    /// Execute the actual HTTP request via ureq.
    fn execute_request(
        &self,
        method: &str,
        url: &str,
        headers: &HashMap<String, String>,
        body: ReqBody<'_>,
    ) -> Result<HttpResponse, FetchError> {
        let request = match method.to_uppercase().as_str() {
            "GET" => self.agent.get(url),
            "POST" => self.agent.post(url),
            "PUT" => self.agent.put(url),
            "DELETE" => self.agent.delete(url),
            "PATCH" => self.agent.request("PATCH", url),
            "HEAD" => self.agent.head(url),
            "OPTIONS" => self.agent.request("OPTIONS", url),
            other => return Err(FetchError::InvalidMethod(other.to_string())),
        };

        // Set headers
        let mut request = request;
        for (key, value) in headers {
            request = request.set(key, value);
        }

        // Send request — bytes go out raw (send_bytes) so a binary payload isn't
        // mangled; text uses send_string; none calls with no body.
        let response = match body {
            ReqBody::None => request.call(),
            ReqBody::Text(s) => request.send_string(s),
            ReqBody::Bytes(b) => request.send_bytes(b),
        };

        match response {
            Ok(resp) => {
                let status = resp.status();
                let resp_headers = collect_headers(&resp);

                // Read body with size limit (10MB)
                let body = resp
                    .into_string()
                    .map_err(|e| FetchError::HttpError(format!("Failed to read response body: {e}")))?;

                // Truncate if over 10MB (shouldn't happen with ureq defaults but safety)
                let body = if body.len() > 10_000_000 {
                    body[..10_000_000].to_string()
                } else {
                    body
                };

                Ok(HttpResponse {
                    status,
                    headers: resp_headers,
                    body,
                    elapsed_ms: 0, // Filled by caller
                })
            }
            Err(ureq::Error::Status(status, resp)) => {
                // Non-2xx response — still a valid response, return it
                let resp_headers = collect_headers(&resp);
                let body = resp.into_string().unwrap_or_default();

                Ok(HttpResponse {
                    status,
                    headers: resp_headers,
                    body,
                    elapsed_ms: 0,
                })
            }
            Err(ureq::Error::Transport(e)) => {
                Err(FetchError::HttpError(format!("Transport error: {e}")))
            }
        }
    }

    /// Get a reference to the audit log for querying.
    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    /// Get the shared armed state.
    pub fn armed(&self) -> &Arc<RwLock<ArmedState>> {
        &self.armed
    }

    /// Fetch once, timing only the network call, and transparently wait out the
    /// per-target rate limiter instead of failing on it. Returns the result of
    /// the final attempt plus its network time in ms (backoff sleeping excluded).
    /// Bounded: gives up waiting after `MAX_BACKOFF_MS` total and returns the
    /// last `RateLimited` error rather than blocking forever.
    fn fetch_timed_with_backoff(
        &self,
        method: &str,
        url: &str,
        headers: &HashMap<String, String>,
        body: Option<&str>,
        mode: RequestMode,
    ) -> (Result<HttpResponse, FetchError>, u64) {
        const MAX_BACKOFF_MS: u64 = 60_000;
        let mut waited: u64 = 0;
        loop {
            let call_start = Instant::now();
            let res = self.fetch_with_mode(method, url, headers, body, mode);
            let call_elapsed = call_start.elapsed().as_millis() as u64;
            match res {
                Err(FetchError::RateLimited { retry_after_ms, .. })
                    if waited + retry_after_ms <= MAX_BACKOFF_MS =>
                {
                    let sleep_ms = retry_after_ms.max(1);
                    std::thread::sleep(Duration::from_millis(sleep_ms));
                    waited += sleep_ms;
                }
                other => return (other, call_elapsed),
            }
        }
    }

    /// Block until a rate-limit token is available for `url`'s target, or the
    /// wait budget is exhausted. Used by `burst` when it is asked to *respect*
    /// the limiter (each thread acquires before the barrier so rate-waiting
    /// doesn't desync the simultaneous fire).
    fn acquire_token_blocking(&self, url: &str) -> Result<(), FetchError> {
        let target = self.resolve_target(url)?;
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let wait = {
                let mut limiter = self.limiter.lock().map_err(|e| {
                    FetchError::HttpError(format!("Rate limiter lock poisoned: {e}"))
                })?;
                match limiter.try_acquire(&target) {
                    Ok(()) => return Ok(()),
                    Err(RateLimitError::RetryAfter(d)) => d,
                    Err(RateLimitError::UnknownTarget(t)) => {
                        return Err(FetchError::NoMatchingTarget(t))
                    }
                }
            };
            if Instant::now() + wait > deadline {
                return Err(FetchError::RateLimited {
                    target,
                    retry_after_ms: wait.as_millis() as u64,
                });
            }
            std::thread::sleep(wait);
        }
    }

    /// Batch-fetch many *different* requests with bounded concurrency, diffing
    /// each against an optional baseline. This is the deterministic-sweep
    /// primitive: no LLM, fully in Rust, rate-limiter honored per target.
    ///
    /// - `baseline`: fetched once up front; every mutation is diffed against it.
    ///   If supplied and the baseline request errors, the whole sweep fails
    ///   (a sweep with no baseline to compare against is meaningless). Pass
    ///   `None` for a pure batch fetch (e.g. IDOR id-enumeration, which
    ///   clusters by shape rather than diffing vs one baseline).
    /// - `workers`: max in-flight requests. Clamped to `[1, mutations.len()]`.
    ///   Per-target rate limits still apply, so within one target this mostly
    ///   fills the rate budget without idle gaps; cross-target parallelism is
    ///   the scheduler's job.
    ///
    /// Results are returned in input order (each carries its `index`).
    /// The caller is expected to release the GIL (see `lib.rs`).
    pub fn sweep(
        &self,
        baseline: Option<&Req>,
        mutations: &[Req],
        workers: usize,
        mode: RequestMode,
    ) -> Result<Vec<SweepOutcome>, FetchError> {
        // Baseline first (timed, rate-limit-aware). A supplied-but-failing
        // baseline aborts the sweep.
        let baseline_resp: Option<HttpResponse> = match baseline {
            Some(b) => {
                let (res, elapsed) =
                    self.fetch_timed_with_backoff(&b.method, &b.url, &b.headers, b.body.as_deref(), mode);
                let mut r = res?;
                r.elapsed_ms = elapsed;
                Some(r)
            }
            None => None,
        };

        let n = mutations.len();
        if n == 0 {
            return Ok(Vec::new());
        }
        let worker_count = workers.clamp(1, n);
        let cursor = AtomicUsize::new(0);
        let baseline_ref = baseline_resp.as_ref();

        // Scoped threads borrow `&self`, `&mutations`, `&cursor`, `baseline_ref`
        // directly — no 'static/Arc needed, and all joins complete before the
        // scope returns.
        let chunks: Vec<Vec<(usize, SweepOutcome)>> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..worker_count)
                .map(|_| {
                    s.spawn(|| {
                        let mut local: Vec<(usize, SweepOutcome)> = Vec::new();
                        loop {
                            let i = cursor.fetch_add(1, Ordering::Relaxed);
                            if i >= n {
                                break;
                            }
                            let m = &mutations[i];
                            let (res, elapsed) = self.fetch_timed_with_backoff(
                                &m.method,
                                &m.url,
                                &m.headers,
                                m.body.as_deref(),
                                mode,
                            );
                            let outcome = match res {
                                Ok(resp) => {
                                    let diff_json = baseline_ref.map(|b| {
                                        let d = crate::diff::diff_responses(
                                            b.status, &b.headers, &b.body, 0, resp.status,
                                            &resp.headers, &resp.body, 0,
                                        );
                                        serde_json::to_string(&d).unwrap_or_default()
                                    });
                                    SweepOutcome {
                                        index: i,
                                        status: resp.status,
                                        headers: resp.headers,
                                        body: resp.body,
                                        elapsed_ms: elapsed,
                                        diff_json,
                                        error: None,
                                    }
                                }
                                Err(e) => SweepOutcome {
                                    index: i,
                                    status: 0,
                                    headers: HashMap::new(),
                                    body: String::new(),
                                    elapsed_ms: elapsed,
                                    diff_json: None,
                                    error: Some(e.to_string()),
                                },
                            };
                            local.push((i, outcome));
                        }
                        local
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap_or_default())
                .collect()
        });

        let mut all: Vec<(usize, SweepOutcome)> = chunks.into_iter().flatten().collect();
        all.sort_by_key(|(i, _)| *i);
        Ok(all.into_iter().map(|(_, o)| o).collect())
    }

    /// Fire `count` *identical* requests in a barrier-synchronized wave — the
    /// TOCTOU/race primitive. Scope (and armed, in Active mode) are checked once
    /// up front; then `count` threads each prepare, block on a shared barrier,
    /// and fire together, so the requests hit the target as close to
    /// simultaneously as the OS allows.
    ///
    /// `bypass_rate_limit` (the default use) skips the per-target limiter for
    /// the wave — winning a race is the whole point. When false, each thread
    /// acquires a token *before* the barrier so rate-waiting doesn't desync the
    /// fire.
    ///
    /// Intended for modest `count` (race windows are typically 2–50); it spawns
    /// one thread per request.
    pub fn burst(
        &self,
        req: &Req,
        count: usize,
        bypass_rate_limit: bool,
        mode: RequestMode,
    ) -> Result<Vec<BurstOutcome>, FetchError> {
        if count == 0 {
            return Ok(Vec::new());
        }
        // Fail fast on scope/armed once — every request is identical.
        // (No token consumed here; per-thread acquisition happens below when
        // the limiter is being enforced.)
        self.pre_flight_check_inner(&req.url, mode, false)?;

        // Pre-request audit entries, one per wave member, written BEFORE the
        // wave fires — so a mid-wave crash still leaves a record of every
        // request that was about to leave the box. The concurrent path used
        // to write nothing until after the wave completed. For Active mode
        // this is fail-closed (abort if the trail can't be written), matching
        // fetch_with_mode.
        let target = self.resolve_target(&req.url).unwrap_or_default();
        for _ in 0..count {
            let pre_entry =
                AuditLog::pre_request_entry(&target, &req.method, &req.url, req.body.as_deref());
            if let Err(e) = self.audit.log(&pre_entry) {
                if mode == RequestMode::Active {
                    return Err(FetchError::AuditWriteFailed(e.to_string()));
                }
            }
        }

        let enforce_rate = !bypass_rate_limit;
        let barrier = Barrier::new(count);
        let t0 = Instant::now();

        let mut results: Vec<BurstOutcome> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..count)
                .map(|idx| {
                    let barrier = &barrier;
                    s.spawn(move || {
                        // Acquire a token before the barrier if enforcing, so the
                        // wait doesn't push this thread out of the wave.
                        let preflight_err = if enforce_rate {
                            self.acquire_token_blocking(&req.url).err().map(|e| e.to_string())
                        } else {
                            None
                        };
                        barrier.wait();
                        let send_offset_ns = t0.elapsed().as_nanos();
                        if let Some(err) = preflight_err {
                            return BurstOutcome {
                                index: idx,
                                status: 0,
                                body: String::new(),
                                send_offset_ns,
                                recv_offset_ns: t0.elapsed().as_nanos(),
                                elapsed_ms: 0,
                                error: Some(err),
                            };
                        }
                        let call_start = Instant::now();
                        let res = self.execute_request(
                            &req.method,
                            &req.url,
                            &req.headers,
                            req.body.as_deref().map_or(ReqBody::None, ReqBody::Text),
                        );
                        let elapsed_ms = call_start.elapsed().as_millis() as u64;
                        let recv_offset_ns = t0.elapsed().as_nanos();
                        match res {
                            Ok(resp) => BurstOutcome {
                                index: idx,
                                status: resp.status,
                                body: resp.body,
                                send_offset_ns,
                                recv_offset_ns,
                                elapsed_ms,
                                error: None,
                            },
                            Err(e) => BurstOutcome {
                                index: idx,
                                status: 0,
                                body: String::new(),
                                send_offset_ns,
                                recv_offset_ns,
                                elapsed_ms,
                                error: Some(e.to_string()),
                            },
                        }
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });

        // Audit the wave post-hoc (best effort) — keep the trail even though we
        // bypassed the per-request path for simultaneity. `target` was resolved
        // above for the pre-request entries.
        for o in &results {
            let entry = match &o.error {
                Some(err) => AuditLog::error_entry(
                    &target, &req.method, &req.url, req.body.as_deref(), err, Some(o.elapsed_ms),
                ),
                None => AuditLog::post_request_entry(
                    &target, &req.method, &req.url, req.body.as_deref(), o.status, o.elapsed_ms,
                ),
            };
            let _ = self.audit.log(&entry);
        }

        results.sort_by_key(|o| o.index);
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::armed::ArmedLevel;

    fn make_client(
        targets: Vec<(String, Vec<String>, f64)>,
        armed_targets: &[String],
    ) -> (HttpClient, Arc<RwLock<ArmedState>>, Arc<Mutex<RateLimiter>>) {
        let armed = Arc::new(RwLock::new(ArmedState::new(armed_targets)));
        let rate_configs: Vec<(String, f64)> = targets
            .iter()
            .map(|(h, _, rps)| (h.clone(), *rps))
            .collect();
        let limiter = Arc::new(Mutex::new(RateLimiter::new(&rate_configs)));
        // keep() the tempdir so it persists for the client's lifetime — the
        // audit dir must exist on disk, otherwise the fail-closed pre-request
        // audit write (Active mode) would abort every request. Leaks the dir
        // at test-process exit, which is fine for a test.
        let dir = tempfile::tempdir().unwrap().keep();

        let client = HttpClient::new(
            targets,
            armed.clone(),
            limiter.clone(),
            dir,
        )
        .unwrap();

        (client, armed, limiter)
    }

    #[test]
    fn env_duration_secs_parses_clamps_and_defaults() {
        // Unique var name so parallel tests never race on it.
        let var = "MOLLY_TEST_ENV_DURATION_SECS_XYZ";
        std::env::remove_var(var);
        // Unset -> default.
        assert_eq!(env_duration_secs(var, 20, 5), Duration::from_secs(20));
        // Valid value above the floor -> honored.
        std::env::set_var(var, "12");
        assert_eq!(env_duration_secs(var, 20, 5), Duration::from_secs(12));
        // Below the floor -> clamped up (protects the blind-SQLi SLEEP probe).
        std::env::set_var(var, "1");
        assert_eq!(env_duration_secs(var, 20, 5), Duration::from_secs(5));
        // Whitespace tolerated.
        std::env::set_var(var, "  30 ");
        assert_eq!(env_duration_secs(var, 20, 5), Duration::from_secs(30));
        // Garbage -> default (never truncates everything on a typo).
        std::env::set_var(var, "notanumber");
        assert_eq!(env_duration_secs(var, 20, 5), Duration::from_secs(20));
        std::env::remove_var(var);
    }

    #[test]
    fn active_fetch_fails_closed_when_pre_request_audit_write_fails() {
        // "Log BEFORE it leaves the box": if the pre-request audit entry can't
        // be written, an Active request must abort rather than fire unlogged.
        let armed = Arc::new(RwLock::new(ArmedState::new(&["example".to_string()])));
        armed
            .write()
            .unwrap()
            .set("example", ArmedLevel::Armed, None)
            .unwrap();
        let limiter = Arc::new(Mutex::new(RateLimiter::new(&[("example".into(), 10.0)])));
        let dir = tempfile::tempdir().unwrap();
        let audit_dir = dir.path().join("audit");
        let client = HttpClient::new(
            vec![("example".into(), vec!["example.com".into()], 10.0)],
            armed.clone(),
            limiter.clone(),
            audit_dir.clone(),
        )
        .unwrap();

        // Remove the audit directory out from under the client so the
        // pre-request append fails with a filesystem error.
        std::fs::remove_dir_all(&audit_dir).unwrap();

        let result = client.fetch("GET", "https://example.com/api", &HashMap::new(), None);
        assert!(
            matches!(result, Err(FetchError::AuditWriteFailed(_))),
            "expected AuditWriteFailed, got {result:?}"
        );
    }

    // --- Active mode tests (existing behavior) ---

    #[test]
    fn pre_flight_rejects_out_of_scope() {
        let (client, armed, _) = make_client(
            vec![("example".into(), vec!["example.com".into()], 10.0)],
            &["example".into()],
        );
        armed.write().unwrap().set("example", ArmedLevel::Armed, None).unwrap();

        let result = client.pre_flight_check("https://evil.com/hack", RequestMode::Active);
        assert!(matches!(result, Err(FetchError::NoMatchingTarget(_))));
    }

    #[test]
    fn pre_flight_rejects_explicitly_denied() {
        let (client, armed, _) = make_client(
            vec![(
                "example".into(),
                vec!["*.example.com".into(), "!admin.example.com".into()],
                10.0,
            )],
            &["example".into()],
        );
        armed.write().unwrap().set("example", ArmedLevel::Armed, None).unwrap();

        let result = client.pre_flight_check("https://admin.example.com/secret", RequestMode::Active);
        assert!(matches!(result, Err(FetchError::ScopeViolation(_))));
    }

    #[test]
    fn pre_flight_rejects_unarmed() {
        let (client, _, _) = make_client(
            vec![("example".into(), vec!["example.com".into()], 10.0)],
            &["example".into()],
        );
        // Default is unarmed

        let result = client.pre_flight_check("https://example.com/api", RequestMode::Active);
        assert!(matches!(result, Err(FetchError::NotArmed(_))));
    }

    #[test]
    fn pre_flight_rejects_paused() {
        let (client, armed, _) = make_client(
            vec![("example".into(), vec!["example.com".into()], 10.0)],
            &["example".into()],
        );
        armed.write().unwrap().set("example", ArmedLevel::Armed, None).unwrap();
        armed.write().unwrap().set("example", ArmedLevel::Paused, None).unwrap();

        let result = client.pre_flight_check("https://example.com/api", RequestMode::Active);
        assert!(matches!(result, Err(FetchError::Paused(_))));
    }

    #[test]
    fn pre_flight_rejects_expired_armed_target() {
        // Bounded-campaign TTL (the fleet optimizer): an armed target past its
        // expires_at must be rejected exactly like an unarmed one — the
        // safety guarantee is enforced at check time, not by a background
        // sweep having already run.
        let (client, armed, _) = make_client(
            vec![("example".into(), vec!["example.com".into()], 10.0)],
            &["example".into()],
        );
        let past = (chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
        armed.write().unwrap().set("example", ArmedLevel::Armed, Some(past)).unwrap();

        let result = client.pre_flight_check("https://example.com/api", RequestMode::Active);
        assert!(matches!(result, Err(FetchError::NotArmed(_))));
    }

    #[test]
    fn pre_flight_passes_armed_with_future_expiry() {
        let (client, armed, _) = make_client(
            vec![("example".into(), vec!["example.com".into()], 10.0)],
            &["example".into()],
        );
        let future = (chrono::Utc::now() + chrono::Duration::seconds(3600)).to_rfc3339();
        armed.write().unwrap().set("example", ArmedLevel::Armed, Some(future)).unwrap();

        let result = client.pre_flight_check("https://example.com/api", RequestMode::Active);
        assert!(result.is_ok());
    }

    #[test]
    fn pre_flight_passes_armed_in_scope() {
        let (client, armed, _) = make_client(
            vec![("example".into(), vec!["example.com".into()], 10.0)],
            &["example".into()],
        );
        armed.write().unwrap().set("example", ArmedLevel::Armed, None).unwrap();

        let result = client.pre_flight_check("https://example.com/api", RequestMode::Active);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().target_handle, "example");
    }

    #[test]
    fn pre_flight_rate_limits() {
        // Very low rate: 0.5 RPS, burst = 1
        let (client, armed, _) = make_client(
            vec![("example".into(), vec!["example.com".into()], 0.5)],
            &["example".into()],
        );
        armed.write().unwrap().set("example", ArmedLevel::Armed, None).unwrap();

        // First request should pass
        assert!(client.pre_flight_check("https://example.com/1", RequestMode::Active).is_ok());
        // Drain the bucket
        while client.pre_flight_check("https://example.com/x", RequestMode::Active).is_ok() {}

        let result = client.pre_flight_check("https://example.com/y", RequestMode::Active);
        assert!(matches!(
            result,
            Err(FetchError::RateLimited { .. })
        ));
    }

    #[test]
    fn resolves_correct_target() {
        let (client, armed, _) = make_client(
            vec![
                ("linkedin".into(), vec!["api.linkedin.com".into()], 10.0),
                ("cloudflare".into(), vec!["*.cloudflare.com".into()], 10.0),
            ],
            &["linkedin".into(), "cloudflare".into()],
        );
        armed.write().unwrap().set("linkedin", ArmedLevel::Armed, None).unwrap();
        armed.write().unwrap().set("cloudflare", ArmedLevel::Armed, None).unwrap();

        let r1 = client.pre_flight_check("https://api.linkedin.com/foo", RequestMode::Active).unwrap();
        assert_eq!(r1.target_handle, "linkedin");

        let r2 = client.pre_flight_check("https://dash.cloudflare.com/bar", RequestMode::Active).unwrap();
        assert_eq!(r2.target_handle, "cloudflare");
    }

    #[test]
    fn resolves_armed_over_unarmed_when_scope_overlaps() {
        // Reproduces the doppler vs doppler-anon collision: two targets share
        // identical scope_rules (typical for auth + auto-spawned anon
        // siblings). The armed one must win, otherwise authed coverage
        // routes to an unarmed sibling and fails at pre-flight.
        let (client, armed, _) = make_client(
            vec![
                ("doppler-anon".into(), vec!["api.doppler.com".into()], 10.0),
                ("doppler".into(), vec!["api.doppler.com".into()], 10.0),
            ],
            &["doppler-anon".into(), "doppler".into()],
        );
        armed.write().unwrap().set("doppler", ArmedLevel::Armed, None).unwrap();
        // doppler-anon stays Unarmed (default)

        let r = client.pre_flight_check("https://api.doppler.com/v3/me", RequestMode::Active).unwrap();
        assert_eq!(r.target_handle, "doppler",
            "armed sibling should win over unarmed when scope overlaps");
    }

    #[test]
    fn resolves_unarmed_sibling_once_the_armed_ones_expiry_passes() {
        // Same collision as above, but the "armed" one's TTL has lapsed —
        // resolve_target must treat it as unarmed too, with no special-casing
        // needed there (it just calls armed.check(), which is expiry-aware).
        let (client, armed, _) = make_client(
            vec![
                ("doppler-anon".into(), vec!["api.doppler.com".into()], 10.0),
                ("doppler".into(), vec!["api.doppler.com".into()], 10.0),
            ],
            &["doppler-anon".into(), "doppler".into()],
        );
        let past = (chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
        armed.write().unwrap().set("doppler", ArmedLevel::Armed, Some(past)).unwrap();

        let r = client.pre_flight_check("https://api.doppler.com/v3/me", RequestMode::Active);
        // Both siblings are now effectively unarmed — pre_flight_check
        // rejects with NotArmed (still resolves to a target, just not armed).
        assert!(matches!(r, Err(FetchError::NotArmed(_))));
    }

    #[test]
    fn resolves_armed_over_unarmed_regardless_of_config_order() {
        // Same as above but flipped order — exercises the loop preferring
        // armed even when the unarmed target appears second.
        let (client, armed, _) = make_client(
            vec![
                ("doppler".into(), vec!["api.doppler.com".into()], 10.0),
                ("doppler-anon".into(), vec!["api.doppler.com".into()], 10.0),
            ],
            &["doppler".into(), "doppler-anon".into()],
        );
        armed.write().unwrap().set("doppler", ArmedLevel::Armed, None).unwrap();

        let r = client.pre_flight_check("https://api.doppler.com/v3/me", RequestMode::Active).unwrap();
        assert_eq!(r.target_handle, "doppler");
    }

    #[test]
    fn falls_back_to_unarmed_when_no_armed_match() {
        // If nothing's armed, the unarmed match is still returned (so passive
        // mode and pre-flight-check inspection still work).
        let (client, _, _) = make_client(
            vec![
                ("doppler-anon".into(), vec!["api.doppler.com".into()], 10.0),
                ("doppler".into(), vec!["api.doppler.com".into()], 10.0),
            ],
            &[],
        );

        let r = client.pre_flight_check("https://api.doppler.com/v3/me", RequestMode::Passive).unwrap();
        // Either is acceptable — both unarmed, both match. Test for stability:
        // first-defined wins among unarmed, matching the pre-fix behavior.
        assert!(r.target_handle == "doppler-anon" || r.target_handle == "doppler");
    }

    #[test]
    fn paused_target_counts_as_armed_for_resolution() {
        // A Paused target is still "configured / arming complete", just
        // intentionally on hold. It should be preferred over a fully Unarmed
        // sibling so paused-then-resumed cycles route correctly.
        let (client, armed, _) = make_client(
            vec![
                ("doppler-anon".into(), vec!["api.doppler.com".into()], 10.0),
                ("doppler".into(), vec!["api.doppler.com".into()], 10.0),
            ],
            &["doppler-anon".into(), "doppler".into()],
        );
        armed.write().unwrap().set("doppler", ArmedLevel::Armed, None).unwrap();
        armed.write().unwrap().set("doppler", ArmedLevel::Paused, None).unwrap();

        // Pre-flight in Passive mode (skips the armed check) — should still
        // resolve to the paused target, not the fully-unarmed sibling.
        let r = client.pre_flight_check("https://api.doppler.com/v3/me", RequestMode::Passive).unwrap();
        assert_eq!(r.target_handle, "doppler");
    }

    #[test]
    fn invalid_method_rejected() {
        let (client, armed, _) = make_client(
            vec![("example".into(), vec!["example.com".into()], 10.0)],
            &["example".into()],
        );
        armed.write().unwrap().set("example", ArmedLevel::Armed, None).unwrap();

        let result = client.fetch("FOOBAR", "https://example.com/api", &HashMap::new(), None);
        assert!(matches!(result, Err(FetchError::InvalidMethod(_))));
    }

    // --- Passive mode tests ---

    #[test]
    fn passive_mode_skips_armed_check() {
        let (client, _, _) = make_client(
            vec![("example".into(), vec!["example.com".into()], 10.0)],
            &["example".into()],
        );
        // Target is UNARMED (default) — active would reject, passive should pass

        let result = client.pre_flight_check("https://example.com/api", RequestMode::Passive);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().target_handle, "example");
    }

    #[test]
    fn passive_mode_skips_paused_check() {
        let (client, armed, _) = make_client(
            vec![("example".into(), vec!["example.com".into()], 10.0)],
            &["example".into()],
        );
        armed.write().unwrap().set("example", ArmedLevel::Armed, None).unwrap();
        armed.write().unwrap().set("example", ArmedLevel::Paused, None).unwrap();

        let result = client.pre_flight_check("https://example.com/api", RequestMode::Passive);
        assert!(result.is_ok());
    }

    #[test]
    fn passive_mode_still_enforces_scope() {
        let (client, _, _) = make_client(
            vec![("example".into(), vec!["example.com".into()], 10.0)],
            &["example".into()],
        );

        let result = client.pre_flight_check("https://evil.com/hack", RequestMode::Passive);
        assert!(matches!(result, Err(FetchError::NoMatchingTarget(_))));
    }

    #[test]
    fn passive_mode_still_enforces_deny_rules() {
        let (client, _, _) = make_client(
            vec![(
                "example".into(),
                vec!["*.example.com".into(), "!admin.example.com".into()],
                10.0,
            )],
            &["example".into()],
        );

        let result = client.pre_flight_check("https://admin.example.com/secret", RequestMode::Passive);
        assert!(matches!(result, Err(FetchError::ScopeViolation(_))));
    }

    #[test]
    fn passive_mode_still_enforces_rate_limit() {
        let (client, _, _) = make_client(
            vec![("example".into(), vec!["example.com".into()], 0.5)],
            &["example".into()],
        );

        // Drain the bucket
        while client.pre_flight_check("https://example.com/x", RequestMode::Passive).is_ok() {}

        let result = client.pre_flight_check("https://example.com/y", RequestMode::Passive);
        assert!(matches!(result, Err(FetchError::RateLimited { .. })));
    }

    #[test]
    fn request_mode_from_str() {
        assert_eq!(RequestMode::from_str("active").unwrap(), RequestMode::Active);
        assert_eq!(RequestMode::from_str("PASSIVE").unwrap(), RequestMode::Passive);
        assert_eq!(RequestMode::from_str("Passive").unwrap(), RequestMode::Passive);
        assert!(RequestMode::from_str("invalid").is_err());
    }

    // --- collect_headers: multi-value header collection (M36 prerequisite) ---
    //
    // Form-login responses commonly set more than one Set-Cookie header (a
    // session cookie plus a CSRF token, say). Regression coverage for the bug
    // this replaced: looping headers_names() + header() re-inserted the same
    // *first* value once per occurrence instead of collecting the rest.

    #[test]
    fn collect_headers_joins_multiple_set_cookie_values() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let body = "ok";
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Set-Cookie: session=abc123; Path=/\r\n\
                 Set-Cookie: csrftoken=xyz789; Path=/\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });

        let (client, armed, _) = make_client(
            vec![("local".into(), vec![format!("http://127.0.0.1:{port}/*")], 10.0)],
            &["local".into()],
        );
        armed.write().unwrap().set("local", ArmedLevel::Armed, None).unwrap();

        let resp = client
            .fetch_with_mode(
                "GET",
                &format!("http://127.0.0.1:{port}/login"),
                &HashMap::new(),
                None,
                RequestMode::Active,
            )
            .unwrap();

        server.join().unwrap();

        let cookies = resp.headers.get("set-cookie").expect("set-cookie header missing");
        assert!(cookies.contains("session=abc123"), "cookies was: {cookies:?}");
        assert!(cookies.contains("csrftoken=xyz789"), "cookies was: {cookies:?}");
        assert_eq!(
            cookies.matches('\n').count(),
            1,
            "expected exactly two values joined by one newline, got: {cookies:?}"
        );
    }

    #[test]
    fn fetch_bytes_sends_raw_binary_body_intact() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::mpsc;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel::<Vec<u8>>();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut chunk = [0u8; 4096];
            let n = stream.read(&mut chunk).unwrap();
            let buf = &chunk[..n];
            let body = buf
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|i| buf[i + 4..].to_vec())
                .unwrap_or_default();
            tx.send(body).unwrap();
            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            stream.write_all(resp.as_bytes()).unwrap();
        });

        let (client, armed, _) = make_client(
            vec![("local".into(), vec![format!("http://127.0.0.1:{port}/*")], 10.0)],
            &["local".into()],
        );
        armed.write().unwrap().set("local", ArmedLevel::Armed, None).unwrap();

        // JPEG magic 0xFF 0xD8 + text — exactly the payload a UTF-8 str body mangles.
        let payload: Vec<u8> = vec![0xFF, 0xD8, b'<', b'?', b'p', b'h', b'p'];
        let resp = client
            .fetch_bytes_with_mode(
                "POST",
                &format!("http://127.0.0.1:{port}/upload"),
                &HashMap::new(),
                Some(&payload),
                RequestMode::Active,
            )
            .unwrap();
        assert_eq!(resp.status, 200);

        server.join().unwrap();
        let received = rx.recv().unwrap();
        assert_eq!(received, payload, "binary body not transmitted intact");
        assert_eq!(&received[..2], &[0xFF, 0xD8], "magic bytes mangled");
    }

    #[test]
    fn ssh_exec_gated_enforces_armed_before_connecting() {
        // The SSH path must refuse an unarmed target at pre-flight — before any
        // sshpass/ssh spawn — exactly like an HTTP fetch.
        let (client, _armed, _) = make_client(
            vec![("local".into(), vec!["http://127.0.0.1:1/*".into()], 10.0)],
            &["local".into()],
        );
        let err = client
            .ssh_exec_gated("http://127.0.0.1:1/", "pedro", "pw", "id", 22, RequestMode::Active)
            .unwrap_err();
        assert!(matches!(err, FetchError::NotArmed(_)), "expected NotArmed, got {err:?}");
    }

    #[test]
    fn ssh_exec_gated_refuses_out_of_scope_host() {
        // An in-scope url can't be used to SSH an out-of-scope host: the connection
        // targets the url's own host, and an out-of-scope url fails scope first.
        let (client, armed, _) = make_client(
            vec![("local".into(), vec!["http://127.0.0.1:1/*".into()], 10.0)],
            &["local".into()],
        );
        armed.write().unwrap().set("local", ArmedLevel::Armed, None).unwrap();
        let err = client
            .ssh_exec_gated("http://evil.example.com/", "u", "p", "id", 22, RequestMode::Active)
            .unwrap_err();
        assert!(matches!(err, FetchError::NoMatchingTarget(_)), "expected scope reject, got {err:?}");
    }

    #[test]
    fn fetch_bytes_still_enforces_armed_gate() {
        // An unarmed target refuses a bytes upload exactly like a text fetch.
        let (client, _armed, _) = make_client(
            vec![("local".into(), vec!["http://127.0.0.1:1/*".into()], 10.0)],
            &["local".into()],
        );
        let err = client
            .fetch_bytes_with_mode(
                "POST",
                "http://127.0.0.1:1/upload",
                &HashMap::new(),
                Some(&[0xFF, 0xD8]),
                RequestMode::Active,
            )
            .unwrap_err();
        assert!(matches!(err, FetchError::NotArmed(_)), "expected NotArmed, got {err:?}");
    }

    // --- sweep / burst (deterministic concurrency primitives) ---

    /// Throwaway HTTP server: accepts `conns` connections, each handled on its
    /// own thread, replying `200` with a body echoing the request path after
    /// `delay_ms`. Detached (not joined) so a test never hangs waiting on it.
    fn spawn_multi_server(conns: usize, delay_ms: u64) -> u16 {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut workers = Vec::new();
            for _ in 0..conns {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        workers.push(std::thread::spawn(move || {
                            let mut buf = [0u8; 2048];
                            let n = stream.read(&mut buf).unwrap_or(0);
                            let req = String::from_utf8_lossy(&buf[..n]);
                            let path = req
                                .lines()
                                .next()
                                .and_then(|l| l.split_whitespace().nth(1))
                                .unwrap_or("/")
                                .to_string();
                            if delay_ms > 0 {
                                std::thread::sleep(Duration::from_millis(delay_ms));
                            }
                            let body = format!("path={path}");
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = stream.write_all(response.as_bytes());
                        }));
                    }
                    Err(_) => break,
                }
            }
            for w in workers {
                let _ = w.join();
            }
        });
        port
    }

    fn armed_client(port: u16, rps: f64) -> HttpClient {
        let (client, armed, _) = make_client(
            vec![("local".into(), vec![format!("http://127.0.0.1:{port}/*")], rps)],
            &["local".into()],
        );
        armed.write().unwrap().set("local", ArmedLevel::Armed, None).unwrap();
        client
    }

    fn get_req(port: u16, path: &str) -> Req {
        Req {
            method: "GET".into(),
            url: format!("http://127.0.0.1:{port}{path}"),
            headers: HashMap::new(),
            body: None,
        }
    }

    #[test]
    fn sweep_runs_all_and_preserves_order() {
        let port = spawn_multi_server(5, 0);
        let client = armed_client(port, 100.0);
        let muts: Vec<Req> = (0..5).map(|i| get_req(port, &format!("/item/{i}"))).collect();

        let out = client.sweep(None, &muts, 4, RequestMode::Active).unwrap();

        assert_eq!(out.len(), 5);
        for (i, o) in out.iter().enumerate() {
            assert_eq!(o.index, i);
            assert_eq!(o.status, 200, "outcome {i} errored: {:?}", o.error);
            assert!(o.body.contains(&format!("/item/{i}")), "body was: {}", o.body);
            assert!(o.error.is_none());
            assert!(o.diff_json.is_none(), "no baseline was supplied");
        }
    }

    #[test]
    fn sweep_is_concurrent() {
        // 8 requests, each held 150ms server-side. Serial would be ~1200ms;
        // with 8 workers it should finish near 150ms. Generous CI headroom.
        let port = spawn_multi_server(8, 150);
        let client = armed_client(port, 1000.0); // burst cap 2000 — no rate wait
        let muts: Vec<Req> = (0..8).map(|i| get_req(port, &format!("/{i}"))).collect();

        let start = Instant::now();
        let out = client.sweep(None, &muts, 8, RequestMode::Active).unwrap();
        let elapsed = start.elapsed();

        assert_eq!(out.len(), 8);
        assert!(out.iter().all(|o| o.status == 200), "some failed: {out:?}");
        assert!(
            elapsed < Duration::from_millis(700),
            "sweep took {elapsed:?} — expected concurrent execution, not serial"
        );
    }

    #[test]
    fn sweep_respects_rate_limit() {
        // rps=2 => burst capacity 4. 8 requests: 4 immediate, the rest paced at
        // ~2/s, so the batch can't finish in under ~1s even though workers=8.
        let port = spawn_multi_server(8, 0);
        let client = armed_client(port, 2.0);
        let muts: Vec<Req> = (0..8).map(|i| get_req(port, &format!("/{i}"))).collect();

        let start = Instant::now();
        let out = client.sweep(None, &muts, 8, RequestMode::Active).unwrap();
        let elapsed = start.elapsed();

        assert_eq!(out.len(), 8);
        assert!(
            out.iter().all(|o| o.status == 200),
            "rate backoff should wait, not fail: {:?}",
            out.iter().filter(|o| o.error.is_some()).collect::<Vec<_>>()
        );
        assert!(
            elapsed >= Duration::from_millis(1000),
            "expected the limiter to pace the batch; took only {elapsed:?}"
        );
    }

    #[test]
    fn sweep_reports_errors_without_aborting() {
        // Bind then immediately drop the listener so connects are refused.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let client = armed_client(port, 100.0);
        let muts = vec![get_req(port, "/x")];

        let out = client.sweep(None, &muts, 1, RequestMode::Active).unwrap();

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].status, 0);
        assert!(out[0].error.is_some(), "a refused connection should surface an error");
    }

    #[test]
    fn sweep_diffs_against_baseline() {
        let port = spawn_multi_server(2, 0); // baseline + 1 mutation = 2 conns
        let client = armed_client(port, 100.0);
        let baseline = get_req(port, "/a");
        let muts = vec![get_req(port, "/aaaaaaaaaaaaaaaaaaaa")]; // longer echoed path

        let out = client.sweep(Some(&baseline), &muts, 1, RequestMode::Active).unwrap();

        assert_eq!(out.len(), 1);
        let dj = out[0].diff_json.as_ref().expect("baseline supplied => diff present");
        assert!(dj.contains("\"verdict\""), "diff json: {dj}");
        assert!(dj.contains("body_len_delta"), "diff json: {dj}");
    }

    #[test]
    fn burst_fires_simultaneously() {
        let k = 6usize;
        let port = spawn_multi_server(k, 50);
        // Low rps, but bypass_rate_limit=true means the wave ignores it.
        let client = armed_client(port, 1.0);

        let out = client
            .burst(&get_req(port, "/race"), k, true, RequestMode::Active)
            .unwrap();

        assert_eq!(out.len(), k);
        assert!(
            out.iter().all(|o| o.status == 200),
            "errors: {:?}",
            out.iter().filter_map(|o| o.error.as_ref()).collect::<Vec<_>>()
        );
        let sends: Vec<u128> = out.iter().map(|o| o.send_offset_ns).collect();
        let spread_ms = (sends.iter().max().unwrap() - sends.iter().min().unwrap()) as f64 / 1e6;
        assert!(
            spread_ms < 50.0,
            "barrier release should be near-simultaneous; send spread was {spread_ms}ms"
        );
    }

    #[test]
    fn burst_enforces_scope_and_armed() {
        // Configured but NOT armed — an Active burst must fail fast, before any
        // request leaves.
        let (client, _armed, _) = make_client(
            vec![("local".into(), vec!["example.com".into()], 10.0)],
            &["local".into()],
        );
        let res = client.burst(
            &Req {
                method: "GET".into(),
                url: "https://example.com/x".into(),
                headers: HashMap::new(),
                body: None,
            },
            3,
            true,
            RequestMode::Active,
        );
        assert!(matches!(res, Err(FetchError::NotArmed(_))));
    }

    #[test]
    fn sweep_empty_mutations_is_empty() {
        let port = spawn_multi_server(0, 0);
        let client = armed_client(port, 100.0);
        let out = client.sweep(None, &[], 4, RequestMode::Active).unwrap();
        assert!(out.is_empty());
    }

    // --- fetch_fair (fair admission queue wired into the fetch path) ---------

    #[test]
    fn fetch_fair_succeeds_and_paces_instead_of_erroring() {
        // rps=5 => burst 10. 14 fair fetches: 10 immediate, the other 4 BLOCK and
        // wait (~0.2s each at 5/s) rather than returning RateLimited. All succeed.
        let port = spawn_multi_server(14, 0);
        let client = armed_client(port, 5.0);
        let start = Instant::now();
        for i in 0..14 {
            let resp = client
                .fetch_fair(
                    "GET",
                    &format!("http://127.0.0.1:{port}/{i}"),
                    &HashMap::new(),
                    None,
                    RequestMode::Active,
                    0,
                )
                .unwrap_or_else(|e| panic!("fetch_fair {i} should block, not fail: {e:?}"));
            assert_eq!(resp.status, 200);
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(500),
            "expected the fair queue to pace past the burst; took only {elapsed:?}"
        );
    }

    #[test]
    fn fetch_fair_fails_fast_on_unarmed_without_blocking() {
        // An unarmed Active target must be rejected at pre-flight, BEFORE queuing —
        // so it returns immediately (not after the admission deadline).
        let (client, _armed, _) = make_client(
            vec![("example".into(), vec!["example.com".into()], 10.0)],
            &["example".into()],
        );
        let start = Instant::now();
        let r = client.fetch_fair(
            "GET",
            "https://example.com/api",
            &HashMap::new(),
            None,
            RequestMode::Active,
            0,
        );
        assert!(matches!(r, Err(FetchError::NotArmed(_))), "got {r:?}");
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "unarmed must fail fast, not wait in the queue"
        );
    }

    #[test]
    fn fetch_fair_enforces_scope() {
        let (client, armed, _) = make_client(
            vec![("example".into(), vec!["example.com".into()], 10.0)],
            &["example".into()],
        );
        armed.write().unwrap().set("example", ArmedLevel::Armed, None).unwrap();
        let r = client.fetch_fair(
            "GET",
            "https://evil.com/hack",
            &HashMap::new(),
            None,
            RequestMode::Active,
            0,
        );
        assert!(matches!(r, Err(FetchError::NoMatchingTarget(_))), "got {r:?}");
    }

    #[test]
    fn fetch_fair_admits_two_contending_threads_fairly() {
        // Two producers (the duel shape) hammer one low-rps target through the
        // fair queue. Every request must be admitted (none dropped/errored) and
        // the aggregate must be paced by the single shared bucket.
        let port = spawn_multi_server(16, 0);
        let client = Arc::new(armed_client(port, 4.0)); // burst 8
        let start = Instant::now();
        let mut handles = vec![];
        for who in 0..2 {
            let client = Arc::clone(&client);
            handles.push(std::thread::spawn(move || {
                for i in 0..8 {
                    let resp = client
                        .fetch_fair(
                            "GET",
                            &format!("http://127.0.0.1:{port}/{who}-{i}"),
                            &HashMap::new(),
                            None,
                            RequestMode::Active,
                            0,
                        )
                        .expect("contending fair fetch should block, not fail");
                    assert_eq!(resp.status, 200);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // 16 requests, burst 8, remaining 8 paced at 4/s ≈ 2s. Require pacing.
        assert!(
            start.elapsed() >= Duration::from_millis(1500),
            "shared bucket should pace both producers; took {:?}",
            start.elapsed()
        );
    }
}
