//! PyO3 bindings for molly-core — the `molly_core._core` extension module.
//!
//! Built only under `--features python`. Every `#[pyclass]` here is a thin
//! wrapper over a pure-Rust core type (`crate::scope::ScopeChecker`,
//! `crate::fetch::HttpClient`, …); the safety gates live in the core and cannot
//! be bypassed from Python or an LLM.

use crate::{armed, diff, fetch, scope, scope_lock};
use pyo3::prelude::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

// --- ScopeChecker ---

/// Rust-backed scope checker exposed to Python.
#[pyclass]
struct ScopeChecker {
    inner: scope::ScopeChecker,
}

#[pymethods]
impl ScopeChecker {
    /// Create a new scope checker from a list of rule strings.
    ///
    /// Rule format:
    /// - `"example.com"` — allow exact domain (https only)
    /// - `"*.example.com"` — allow any subdomain
    /// - `"example.com/api/*"` — allow domain with path prefix
    /// - `"!admin.example.com"` — deny (overrides allows)
    #[new]
    fn new(rules: Vec<String>) -> Self {
        ScopeChecker {
            inner: scope::ScopeChecker::new(&rules),
        }
    }

    /// Check if a URL is in scope. Raises ValueError if not.
    fn check(&self, url: &str) -> PyResult<()> {
        self.inner
            .check(url)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    /// Returns True if the URL is in scope, False otherwise.
    fn is_allowed(&self, url: &str) -> bool {
        self.inner.is_allowed(url)
    }
}

// --- HttpResponse ---

/// HTTP response from a fetch call.
#[pyclass(skip_from_py_object)]
#[derive(Clone)]
struct HttpResponse {
    #[pyo3(get)]
    status: u16,
    #[pyo3(get)]
    headers: HashMap<String, String>,
    #[pyo3(get)]
    body: String,
    #[pyo3(get)]
    elapsed_ms: u64,
}

#[pymethods]
impl HttpResponse {
    fn __repr__(&self) -> String {
        format!(
            "HttpResponse(status={}, body_len={}, elapsed_ms={})",
            self.status,
            self.body.len(),
            self.elapsed_ms
        )
    }
}

// --- Sweep / Burst outcomes ---

/// One result from `HttpClient.sweep` — a fetched mutation, optionally diffed
/// against the baseline.
#[pyclass(skip_from_py_object)]
#[derive(Clone)]
struct SweepOutcome {
    /// Position in the input `mutations` list (results come back in order).
    #[pyo3(get)]
    index: usize,
    /// HTTP status, or 0 if the request errored.
    #[pyo3(get)]
    status: u16,
    #[pyo3(get)]
    headers: HashMap<String, String>,
    #[pyo3(get)]
    body: String,
    /// Network time of the final attempt in ms (rate-limit backoff excluded).
    #[pyo3(get)]
    elapsed_ms: u64,
    /// Serialized ResponseDiff (JSON) vs the baseline, or None if no baseline
    /// was supplied or the request errored. `json.loads` it exactly like the
    /// output of `diff_responses`.
    #[pyo3(get)]
    diff_json: Option<String>,
    /// Error message, or None on success.
    #[pyo3(get)]
    error: Option<String>,
}

#[pymethods]
impl SweepOutcome {
    fn __repr__(&self) -> String {
        format!(
            "SweepOutcome(index={}, status={}, body_len={}, elapsed_ms={}, error={:?})",
            self.index,
            self.status,
            self.body.len(),
            self.elapsed_ms,
            self.error
        )
    }
}

impl From<fetch::SweepOutcome> for SweepOutcome {
    fn from(o: fetch::SweepOutcome) -> Self {
        SweepOutcome {
            index: o.index,
            status: o.status,
            headers: o.headers,
            body: o.body,
            elapsed_ms: o.elapsed_ms,
            diff_json: o.diff_json,
            error: o.error,
        }
    }
}

/// One result from `HttpClient.burst` — an identical request fired in a
/// barrier-synchronized wave. Offsets are nanoseconds from a common origin
/// captured just before the wave; their spread measures simultaneity.
#[pyclass(skip_from_py_object)]
#[derive(Clone)]
struct BurstOutcome {
    #[pyo3(get)]
    index: usize,
    #[pyo3(get)]
    status: u16,
    #[pyo3(get)]
    body: String,
    #[pyo3(get)]
    send_offset_ns: u128,
    #[pyo3(get)]
    recv_offset_ns: u128,
    #[pyo3(get)]
    elapsed_ms: u64,
    #[pyo3(get)]
    error: Option<String>,
}

#[pymethods]
impl BurstOutcome {
    fn __repr__(&self) -> String {
        format!(
            "BurstOutcome(index={}, status={}, send_offset_ns={}, elapsed_ms={}, error={:?})",
            self.index, self.status, self.send_offset_ns, self.elapsed_ms, self.error
        )
    }
}

impl From<fetch::BurstOutcome> for BurstOutcome {
    fn from(o: fetch::BurstOutcome) -> Self {
        BurstOutcome {
            index: o.index,
            status: o.status,
            body: o.body,
            send_offset_ns: o.send_offset_ns,
            recv_offset_ns: o.recv_offset_ns,
            elapsed_ms: o.elapsed_ms,
            error: o.error,
        }
    }
}

/// Parse an optional "active"/"passive" mode string (default Active).
fn parse_mode(mode: Option<&str>) -> PyResult<fetch::RequestMode> {
    match mode {
        Some(m) => fetch::RequestMode::from_str(m)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string())),
        None => Ok(fetch::RequestMode::Active),
    }
}

/// Convert a (method, url, headers, body) tuple from Python into a fetch::Req.
fn tuple_to_req(t: (String, String, HashMap<String, String>, Option<String>)) -> fetch::Req {
    fetch::Req {
        method: t.0,
        url: t.1,
        headers: t.2,
        body: t.3,
    }
}

// --- HttpClient ---

/// Safe HTTP client with scope enforcement, armed state, rate limiting, and audit logging.
///
/// All outbound requests MUST go through this client. The safety gates are
/// enforced in Rust and cannot be bypassed from Python or the LLM.
#[pyclass]
struct HttpClient {
    inner: fetch::HttpClient,
    armed: Arc<RwLock<armed::ArmedState>>,
}

#[pymethods]
impl HttpClient {
    /// Create a new HTTP client.
    ///
    /// Args:
    ///     targets: List of (handle, scope_rules, requests_per_second) tuples.
    ///     audit_dir: Path to the audit log directory.
    #[new]
    fn new(targets: Vec<(String, Vec<String>, f64)>, audit_dir: String) -> PyResult<Self> {
        // MOLLY_ENV=staging hard scope lock — checked before anything else
        // is constructed, so a locked instance configured with even one
        // out-of-allowlist rule refuses to start at all. See scope_lock.rs.
        let lock_targets: Vec<(String, Vec<String>)> = targets
            .iter()
            .map(|(handle, rules, _)| (handle.clone(), rules.clone()))
            .collect();
        scope_lock::enforce(&lock_targets).map_err(pyo3::exceptions::PyRuntimeError::new_err)?;

        let target_handles: Vec<String> = targets.iter().map(|(h, _, _)| h.clone()).collect();
        let rate_configs: Vec<(String, f64)> = targets
            .iter()
            .map(|(h, _, rps)| (h.clone(), *rps))
            .collect();

        let armed = Arc::new(RwLock::new(armed::ArmedState::new(&target_handles)));
        let limiter = Arc::new(Mutex::new(crate::rate_limiter::RateLimiter::new(
            &rate_configs,
        )));

        let inner = fetch::HttpClient::new(
            targets,
            armed.clone(),
            limiter,
            std::path::PathBuf::from(audit_dir),
        )
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;

        Ok(HttpClient { inner, armed })
    }

    /// Make an HTTP request through safety gates.
    ///
    /// Args:
    ///     method: HTTP method (GET, POST, etc.)
    ///     url: Target URL
    ///     headers: Optional request headers
    ///     body: Optional request body
    ///     mode: "active" (default) or "passive". Passive skips the armed
    ///           check — used by enumeration tools for recon on scoped-but-
    ///           unarmed targets. Active enforces all gates.
    ///     priority: Optional. When set, the request goes through the FAIR
    ///           ADMISSION QUEUE: instead of raising on an empty rate bucket, it
    ///           BLOCKS (up to MOLLY_FAIR_ADMISSION_MAX_WAIT_SECS, default 60s)
    ///           until admitted, served by (priority desc, FIFO) and paced at the
    ///           rate limit. Higher = served sooner. Used so concurrent producers
    ///           (the duel personalities) contend fairly instead of racing. When
    ///           None (default), behaviour is unchanged (non-blocking, may raise).
    ///
    /// Raises:
    ///     ValueError: URL is out of scope or no matching target
    ///     PermissionError: Target is not armed (active mode only)
    ///     RuntimeError: Rate limited, paused (active mode only), or HTTP error
    #[pyo3(signature = (method, url, headers=None, body=None, mode=None, priority=None))]
    fn fetch(
        &self,
        py: Python<'_>,
        method: &str,
        url: &str,
        headers: Option<HashMap<String, String>>,
        body: Option<&str>,
        mode: Option<&str>,
        priority: Option<i64>,
    ) -> PyResult<HttpResponse> {
        let headers = headers.unwrap_or_default();
        let request_mode = parse_mode(mode)?;
        let start = std::time::Instant::now();

        // Release the GIL for the blocking network call so other Python threads
        // (and concurrent tools) make progress during I/O. With a `priority` the
        // call routes through the fair admission queue (blocks instead of raising).
        let inner = &self.inner;
        let result = py.detach(|| match priority {
            Some(p) => inner.fetch_fair(method, url, &headers, body, request_mode, p),
            None => inner.fetch_with_mode(method, url, &headers, body, request_mode),
        });
        let elapsed_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(resp) => Ok(HttpResponse {
                status: resp.status,
                headers: resp.headers,
                body: resp.body,
                elapsed_ms,
            }),
            Err(e) => Err(map_fetch_error(e)),
        }
    }

    /// Make an HTTP request with a RAW BYTES body — for binary uploads (magic-byte
    /// file polyglots, file submissions) a UTF-8 `str` body would corrupt. Same
    /// safety gates as `fetch`; the audit logs a `[binary body, N bytes]` note.
    ///
    /// Args:
    ///     method: HTTP method
    ///     url: Target URL
    ///     headers: Optional request headers (set Content-Type for multipart)
    ///     body: Optional request body as `bytes`
    ///     mode: "active" (default) or "passive"
    #[pyo3(signature = (method, url, headers=None, body=None, mode=None))]
    fn fetch_bytes(
        &self,
        py: Python<'_>,
        method: &str,
        url: &str,
        headers: Option<HashMap<String, String>>,
        body: Option<Vec<u8>>,
        mode: Option<&str>,
    ) -> PyResult<HttpResponse> {
        let headers = headers.unwrap_or_default();
        let request_mode = parse_mode(mode)?;
        let start = std::time::Instant::now();

        let inner = &self.inner;
        let result = py.detach(|| {
            inner.fetch_bytes_with_mode(method, url, &headers, body.as_deref(), request_mode)
        });
        let elapsed_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(resp) => Ok(HttpResponse {
                status: resp.status,
                headers: resp.headers,
                body: resp.body,
                elapsed_ms,
            }),
            Err(e) => Err(map_fetch_error(e)),
        }
    }

    /// Make an HTTP request with the request-line PATH sent VERBATIM (no
    /// normalization) — for path-normalization-bypass exploits like CVE-2021-41773,
    /// where ureq/`fetch` would collapse the `%2e`/`.%2e/` traversal. Same safety gates
    /// as `fetch`; the raw send is a separate module (`raw_request`), HTTP only.
    ///
    /// Args:
    ///     method: HTTP method
    ///     url: used for scope resolution + the host/port to connect to (http://host:port)
    ///     raw_path: the exact request-line target, sent byte-for-byte (e.g.
    ///               "/cgi-bin/.%2e/.%2e/bin/sh")
    ///     headers: optional request headers
    ///     body: optional request body (str)
    ///     mode: "active" (default) or "passive"
    #[pyo3(signature = (method, url, raw_path, headers=None, body=None, mode=None))]
    fn fetch_raw(
        &self,
        py: Python<'_>,
        method: &str,
        url: &str,
        raw_path: &str,
        headers: Option<HashMap<String, String>>,
        body: Option<&str>,
        mode: Option<&str>,
    ) -> PyResult<HttpResponse> {
        let headers = headers.unwrap_or_default();
        let request_mode = parse_mode(mode)?;
        let start = std::time::Instant::now();

        let inner = &self.inner;
        let result =
            py.detach(|| inner.fetch_raw_path(method, url, raw_path, &headers, body, request_mode));
        let elapsed_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(resp) => Ok(HttpResponse {
                status: resp.status,
                headers: resp.headers,
                body: resp.body,
                elapsed_ms,
            }),
            Err(e) => Err(map_fetch_error(e)),
        }
    }

    /// Raw byte exchange on ONE TCP connection — the protocol-research primitive for HTTP
    /// request smuggling / desync. `payloads` is a list of `bytes`, each a COMPLETE request
    /// written verbatim on the SAME socket (you control CL/TE framing + pipelining). Same
    /// safety gates as `fetch_raw` (scope + armed + rate + audit; one rate token PER
    /// payload). Returns the RAW response bytes (all responses concatenated, UNPARSED —
    /// counting them is the desync oracle). HTTP/plaintext only.
    ///
    /// Args:
    ///     url: scope + host:port target (http://host:port)
    ///     payloads: list[bytes] — raw request bytes, sent in order on one connection
    ///     read_timeout_secs: per-read timeout / idle cutoff (default 10)
    ///     inter_write_delay_ms: delay between payload writes (poisoning timing; default 0)
    ///     max_bytes: cap on the returned buffer (default 1 MiB)
    ///     mode: "active" (default) or "passive"
    #[pyo3(signature = (url, payloads, read_timeout_secs=10, inter_write_delay_ms=0, max_bytes=1048576, mode=None))]
    fn raw_exchange(
        &self,
        py: Python<'_>,
        url: &str,
        payloads: Vec<Vec<u8>>,
        read_timeout_secs: u64,
        inter_write_delay_ms: u64,
        max_bytes: usize,
        mode: Option<&str>,
    ) -> PyResult<pyo3::Py<pyo3::types::PyBytes>> {
        let request_mode = parse_mode(mode)?;
        let inner = &self.inner;
        let result = py.detach(|| {
            inner.raw_exchange(
                url,
                &payloads,
                read_timeout_secs,
                inter_write_delay_ms,
                max_bytes,
                request_mode,
            )
        });
        match result {
            Ok(bytes) => Ok(pyo3::types::PyBytes::new(py, &bytes).unbind()),
            Err(e) => Err(map_fetch_error(e)),
        }
    }

    /// Run an SSH command on the target over the SAME safety gates as `fetch` — for
    /// credential-reuse exploits where the flag is only reachable via SSH (XBEN-042).
    /// `url` is the target's in-scope web URL (scope/armed/rate/audit apply to it); the
    /// SSH connects to THAT url's host on `port`. Returns (stdout, exit_status). The
    /// audit records the command, never the password. Needs sshpass + openssh-client.
    #[pyo3(signature = (url, username, password, command, port=22, mode=None))]
    fn ssh_exec(
        &self,
        py: Python<'_>,
        url: &str,
        username: &str,
        password: &str,
        command: &str,
        port: u16,
        mode: Option<&str>,
    ) -> PyResult<(String, i32)> {
        let request_mode = parse_mode(mode)?;
        let inner = &self.inner;
        let result = py
            .detach(|| inner.ssh_exec_gated(url, username, password, command, port, request_mode));
        match result {
            Ok(r) => Ok((r.stdout, r.exit_status)),
            Err(e) => Err(map_fetch_error(e)),
        }
    }

    /// Batch-fetch many requests concurrently, diffing each against an optional
    /// baseline. Deterministic (no LLM), rate-limiter honored per target, GIL
    /// released for the whole batch.
    ///
    /// Args:
    ///     mutations: list of (method, url, headers, body) tuples. `headers` is
    ///                a dict; `body` is a str or None.
    ///     baseline: optional (method, url, headers, body) tuple — each mutation
    ///               is diffed against it. None for a pure batch fetch (e.g. IDOR
    ///               id-enumeration that clusters by shape).
    ///     workers: max concurrent in-flight requests (default 8).
    ///     mode: "active" (default) or "passive".
    ///
    /// Returns: list of SweepOutcome, in input order.
    #[pyo3(signature = (mutations, baseline=None, workers=8, mode=None))]
    fn sweep(
        &self,
        py: Python<'_>,
        mutations: Vec<(String, String, HashMap<String, String>, Option<String>)>,
        baseline: Option<(String, String, HashMap<String, String>, Option<String>)>,
        workers: usize,
        mode: Option<&str>,
    ) -> PyResult<Vec<SweepOutcome>> {
        let request_mode = parse_mode(mode)?;
        let muts: Vec<fetch::Req> = mutations.into_iter().map(tuple_to_req).collect();
        let base: Option<fetch::Req> = baseline.map(tuple_to_req);
        let inner = &self.inner;
        let raw = py
            .detach(|| inner.sweep(base.as_ref(), &muts, workers, request_mode))
            .map_err(map_fetch_error)?;
        Ok(raw.into_iter().map(SweepOutcome::from).collect())
    }

    /// Fire `count` identical requests in a barrier-synchronized wave — the
    /// TOCTOU/race primitive. GIL released for the wave.
    ///
    /// Args:
    ///     method, url, headers, body: the request to replicate.
    ///     count: how many copies to fire simultaneously.
    ///     bypass_rate_limit: skip the per-target limiter for the wave (default
    ///                        True — winning a race is the point).
    ///     mode: "active" (default) or "passive".
    ///
    /// Returns: list of BurstOutcome, in index order, each with send/recv
    /// nanosecond offsets from a common origin so simultaneity is measurable.
    #[pyo3(signature = (method, url, count, headers=None, body=None, bypass_rate_limit=true, mode=None))]
    fn burst(
        &self,
        py: Python<'_>,
        method: &str,
        url: &str,
        count: usize,
        headers: Option<HashMap<String, String>>,
        body: Option<String>,
        bypass_rate_limit: bool,
        mode: Option<&str>,
    ) -> PyResult<Vec<BurstOutcome>> {
        let request_mode = parse_mode(mode)?;
        let req = fetch::Req {
            method: method.to_string(),
            url: url.to_string(),
            headers: headers.unwrap_or_default(),
            body,
        };
        let inner = &self.inner;
        let raw = py
            .detach(|| inner.burst(&req, count, bypass_rate_limit, request_mode))
            .map_err(map_fetch_error)?;
        Ok(raw.into_iter().map(BurstOutcome::from).collect())
    }

    /// Run pre-flight checks without making a request. Returns the target handle.
    ///
    /// Args:
    ///     url: Target URL
    ///     mode: "active" (default) or "passive"
    #[pyo3(signature = (url, mode=None))]
    fn pre_flight_check(&self, url: &str, mode: Option<&str>) -> PyResult<String> {
        let request_mode = match mode {
            Some(m) => fetch::RequestMode::from_str(m)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?,
            None => fetch::RequestMode::Active,
        };
        self.inner
            .pre_flight_check(url, request_mode)
            .map(|r| r.target_handle)
            .map_err(map_fetch_error)
    }

    /// Set the armed state for a target, optionally bounded by a
    /// bounded-campaign expiry (the fleet optimizer).
    ///
    /// Args:
    ///     target: Target handle (e.g., "linkedin")
    ///     state: "armed", "unarmed", or "paused"
    ///     expires_at: optional RFC3339 timestamp — the state reverts to
    ///                 unarmed once this time passes. None = never expires
    ///                 (original behavior).
    #[pyo3(signature = (target, state, expires_at=None))]
    fn set_armed(&self, target: &str, state: &str, expires_at: Option<String>) -> PyResult<()> {
        let level = armed::ArmedLevel::from_str(state)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        let mut armed = self
            .armed
            .write()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        armed
            .set(target, level, expires_at)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    /// Get the armed state for a target. Returns "armed", "unarmed", or
    /// "paused" — expiry-aware: an armed target past its expiry reads back
    /// as "unarmed" here even before any sweep has run.
    fn get_armed(&self, target: &str) -> PyResult<String> {
        let armed = self
            .armed
            .read()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        armed
            .get(target)
            .map(|l| l.to_string())
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    /// Get the expiry timestamp (RFC3339) for a target's current armed
    /// state, or None if it never expires (or isn't armed/paused).
    fn get_armed_expiry(&self, target: &str) -> PyResult<Option<String>> {
        let armed = self
            .armed
            .read()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        armed
            .get_expiry(target)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    /// Flip any expired armed/paused targets to unarmed in the stored state.
    /// Returns the handles that were just auto-disarmed. Purely for
    /// persistence/observability tidiness — get_armed/set_armed already
    /// compute expiry lazily on every read, so this is never required for
    /// the actual safety guarantee. Callers should persist
    /// (save_armed_state) afterward if they want the change on disk
    /// immediately.
    fn sweep_expired_armed(&self) -> PyResult<Vec<String>> {
        let mut armed = self
            .armed
            .write()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(armed.sweep_expired())
    }

    /// Get all targets and their armed states.
    fn get_all_armed(&self) -> PyResult<HashMap<String, String>> {
        let armed = self
            .armed
            .read()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(armed
            .all()
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect())
    }

    /// Load armed state from a JSON file. Missing file leaves state unchanged.
    fn load_armed_state(&self, path: &str) -> PyResult<()> {
        let mut armed = self
            .armed
            .write()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        armed
            .load(std::path::Path::new(path))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    /// Save armed state to a JSON file.
    fn save_armed_state(&self, path: &str) -> PyResult<()> {
        let armed = self
            .armed
            .read()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        armed
            .save(std::path::Path::new(path))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    /// Query audit log entries for a given date. Returns JSON string.
    ///
    /// Args:
    ///     date: Date string "YYYY-MM-DD"
    ///     target: Optional target filter
    #[pyo3(signature = (date, target=None))]
    fn query_audit(&self, date: &str, target: Option<&str>) -> PyResult<String> {
        let entries = self
            .inner
            .audit()
            .query(date, target)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;

        serde_json::to_string(&entries)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }
}

/// Map FetchError to appropriate Python exception types.
fn map_fetch_error(e: fetch::FetchError) -> PyErr {
    match e {
        fetch::FetchError::NoMatchingTarget(_) | fetch::FetchError::ScopeViolation(_) => {
            pyo3::exceptions::PyValueError::new_err(e.to_string())
        }
        fetch::FetchError::NotArmed(_) => {
            pyo3::exceptions::PyPermissionError::new_err(e.to_string())
        }
        fetch::FetchError::Paused(_)
        | fetch::FetchError::RateLimited { .. }
        | fetch::FetchError::HttpError(_)
        | fetch::FetchError::InvalidMethod(_)
        | fetch::FetchError::AuditWriteFailed(_) => {
            pyo3::exceptions::PyRuntimeError::new_err(e.to_string())
        }
    }
}

// --- diff_responses ---

/// Compare two HTTP responses and return a structured diff as JSON.
///
/// Args:
///     baseline_status: HTTP status of the baseline response
///     baseline_headers: Headers from baseline response
///     baseline_body: Body of baseline response
///     baseline_elapsed_ms: How long the baseline request took
///     mutation_status: HTTP status of the mutation response
///     mutation_headers: Headers from mutation response
///     mutation_body: Body of mutation response
///     mutation_elapsed_ms: How long the mutation request took
///
/// Returns: JSON string with the diff (status, headers, body, timing, json_diff, verdict)
#[pyfunction]
#[pyo3(signature = (baseline_status, baseline_headers, baseline_body, baseline_elapsed_ms, mutation_status, mutation_headers, mutation_body, mutation_elapsed_ms))]
fn diff_responses(
    baseline_status: u16,
    baseline_headers: HashMap<String, String>,
    baseline_body: &str,
    baseline_elapsed_ms: u64,
    mutation_status: u16,
    mutation_headers: HashMap<String, String>,
    mutation_body: &str,
    mutation_elapsed_ms: u64,
) -> PyResult<String> {
    let result = diff::diff_responses(
        baseline_status,
        &baseline_headers,
        baseline_body,
        baseline_elapsed_ms,
        mutation_status,
        &mutation_headers,
        mutation_body,
        mutation_elapsed_ms,
    );
    serde_json::to_string(&result)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

/// The native core module for Molly.
#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ScopeChecker>()?;
    m.add_class::<HttpClient>()?;
    m.add_class::<HttpResponse>()?;
    m.add_class::<SweepOutcome>()?;
    m.add_class::<BurstOutcome>()?;
    m.add_function(wrap_pyfunction!(diff_responses, m)?)?;
    Ok(())
}
