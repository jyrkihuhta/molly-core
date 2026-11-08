//! # molly-core
//!
//! A Rust-enforced **safety cage** for autonomous agents that make outbound
//! network requests. Every request passes through five gates, enforced in Rust
//! so they cannot be bypassed from a higher-level language or an LLM:
//!
//! 1. **Scope** — the destination host/path must match a compiled-in allowlist
//!    ([`scope::ScopeChecker`]).
//! 2. **Armed** — a target starts *unarmed* and refuses active traffic until an
//!    operator explicitly arms it ([`armed::ArmedState`]).
//! 3. **Rate limit** — a per-target token bucket with a fair admission queue
//!    ([`rate_limiter::RateLimiter`]).
//! 4. **Audit** — every request is written to an append-only log *before* it
//!    leaves the box ([`audit::AuditLog`]).
//! 5. **One gated client** — all of the above are wired into a single
//!    [`fetch::HttpClient`]; there is no other way out.
//!
//! The crate also bundles the active security-testing primitives that are built
//! on top of the gate (`sweep`/`burst`, `raw_exchange`, `fetch_raw`, `ssh_exec`).
//! They are commodity techniques — the point of molly-core is that even these run
//! *only* through the scope/armed/rate/audit path.
//!
//! > **Authorized use only.** This crate is for testing systems you own or are
//! > explicitly authorized to assess. See the README.
//!
//! ## Rust usage
//!
//! The pure-Rust API lives in the modules below and is re-exported here. The
//! optional `python` feature additionally builds a PyO3 extension module
//! (`molly_core._core`); it is off by default.

pub mod armed;
pub mod audit;
pub mod diff;
pub mod fetch;
pub mod rate_limiter;
pub mod raw_request;
pub mod scope;
pub mod scope_lock;
pub mod ssh_exec;

// --- Ergonomic re-exports: the main public API ---
pub use armed::{ArmedError, ArmedLevel, ArmedState};
pub use audit::{AuditEntry, AuditError, AuditLog};
pub use diff::{diff_responses, ResponseDiff};
pub use fetch::{
    BurstOutcome, FetchError, HttpClient, HttpResponse, PreFlightResult, Req, RequestMode,
    SweepOutcome,
};
pub use rate_limiter::{RateLimitError, RateLimiter};
pub use scope::{ScopeChecker, ScopeError};

/// The PyO3 bindings — built only with `--features python`.
#[cfg(feature = "python")]
mod python;
