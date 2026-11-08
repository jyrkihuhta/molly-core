//! Per-target token bucket rate limiter with a FAIR admission queue.
//!
//! Two ways to get a token for a target:
//!
//! * [`RateLimiter::try_acquire`] — NON-blocking (unchanged): take a token now or
//!   report a retry-after duration. The caller (Python `rl_fetch`, the sweep
//!   backoff) decides whether to wait. No ordering guarantee between callers.
//!
//! * [`FairBucket::acquire_blocking`] — the admission QUEUE. The caller blocks
//!   until it is at the front of the per-target queue AND a token is available
//!   (paced at the refill rate), or a deadline passes. Waiters are served by
//!   (priority desc, arrival order) — so N producers (e.g. the systematic +
//!   artistic personalities, or many eval workers) are admitted to the network
//!   fairly, at exactly the rate limit, and a higher-priority request (a flag-read
//!   probe) jumps ahead of a broad sweep. This is wired into the fetch path via
//!   [`crate::fetch::HttpClient::fetch_fair`] (opt-in, by passing a `priority`);
//!   `try_acquire` and the default `fetch` path are unchanged.
//!
//! Burst allowance: 2× the per-second rate (2 seconds of burst capacity).

use std::cmp::Reverse;
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum RateLimitError {
    /// Bucket empty / deadline reached — retry after this duration.
    RetryAfter(Duration),
    /// No bucket configured for this target.
    UnknownTarget(String),
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RateLimitError::RetryAfter(d) => {
                write!(f, "Rate limited — retry after {:.1}s", d.as_secs_f64())
            }
            RateLimitError::UnknownTarget(t) => write!(f, "No rate limit bucket for target: {t}"),
        }
    }
}

/// Smallest refill rate a bucket may run at (requests/second). A configured
/// rate of zero or negative is clamped up to this so token-wait math stays
/// finite and positive instead of panicking.
const REFILL_RATE_FLOOR: f64 = 1e-6;

/// A non-front waiter re-checks the queue at least this often, so it notices the
/// front being served or abandoning even though refill is time-based (no explicit
/// "token available" notification fires on refill).
const WAITER_RECHECK: Duration = Duration::from_millis(25);

/// Waiter ordering key: highest priority first (`Reverse`), then earliest arrival
/// (`seq`) — FIFO within a priority band.
type WaiterKey = (Reverse<i64>, u64);

#[derive(Debug)]
struct BucketInner {
    /// Current token count (can be fractional).
    tokens: f64,
    /// Maximum tokens (burst capacity).
    max_tokens: f64,
    /// Tokens added per second.
    refill_rate: f64,
    /// Last time tokens were refilled.
    last_refill: Instant,
    /// Monotonic arrival counter for FIFO ordering within a priority.
    next_seq: u64,
    /// Currently-waiting admission tickets, ordered (priority desc, seq asc).
    waiters: BTreeSet<WaiterKey>,
}

impl BucketInner {
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = (now - self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
    }

    /// Seconds until at least one whole token is available (0 if already).
    fn secs_until_token(&self) -> f64 {
        let needed = 1.0 - self.tokens;
        if needed <= 0.0 {
            0.0
        } else {
            (needed / self.refill_rate).max(0.0)
        }
    }
}

/// One target's bucket: interior-mutable so a blocking waiter holds only this
/// target's lock (never a global one), plus a condvar to wake the next waiter.
#[derive(Debug)]
pub struct FairBucket {
    inner: Mutex<BucketInner>,
    cv: Condvar,
}

impl FairBucket {
    fn new(requests_per_second: f64) -> Arc<Self> {
        // Clamp the refill rate to a small positive floor. A rate <= 0 (or a
        // non-finite value) would make needed/refill_rate non-finite/negative, so
        // Duration::from_secs_f64 panics — poisoning the mutex and bricking ALL
        // outbound traffic. Config load also rejects rateLimitRps <= 0.
        let rps = if requests_per_second.is_finite() && requests_per_second > 0.0 {
            requests_per_second
        } else {
            REFILL_RATE_FLOOR
        };
        let max_tokens = (rps * 2.0).max(1.0);
        Arc::new(FairBucket {
            inner: Mutex::new(BucketInner {
                tokens: max_tokens, // start full
                max_tokens,
                refill_rate: rps,
                last_refill: Instant::now(),
                next_seq: 0,
                waiters: BTreeSet::new(),
            }),
            cv: Condvar::new(),
        })
    }

    #[allow(dead_code)] // backs the public RateLimiter::rate_for accessor
    fn refill_rate(&self) -> f64 {
        // lock is never held long; unwrap_or keeps a poisoned lock from panicking
        // the reader (defence-in-depth; the write paths already guard poisoning).
        self.inner
            .lock()
            .map(|g| g.refill_rate)
            .unwrap_or(REFILL_RATE_FLOOR)
    }

    /// Non-blocking: take one token now, or report how long until one is free.
    /// Ignores the fairness queue by design — this is the legacy fast path.
    fn try_acquire(&self) -> Result<(), Duration> {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return Err(Duration::from_secs_f64(1.0)),
        };
        g.refill();
        if g.tokens >= 1.0 {
            g.tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64(g.secs_until_token().max(1e-6)))
        }
    }

    /// Fair, blocking admission. Blocks until this caller is the front of the
    /// queue AND a token is available (paced at the refill rate), or `deadline`
    /// passes. `priority` higher = served sooner; ties break FIFO. On the deadline
    /// it returns the remaining token-wait as a courtesy retry-after.
    ///
    /// Takes `&Arc<Self>` so the RAII ticket can keep the bucket alive and remove
    /// this waiter from the queue on ANY exit (success, deadline, or panic) — a
    /// stale waiter would otherwise block everyone behind it.
    pub fn acquire_blocking(self: &Arc<Self>, priority: i64, deadline: Instant) -> Result<(), Duration> {
        let key: WaiterKey = {
            let mut g = match self.inner.lock() {
                Ok(g) => g,
                Err(_) => return Err(Duration::from_secs_f64(1.0)),
            };
            let seq = g.next_seq;
            g.next_seq = g.next_seq.wrapping_add(1);
            let key = (Reverse(priority), seq);
            g.waiters.insert(key);
            key
        };
        // Declared before `g` below so, on return, `g` (the lock) drops FIRST, then
        // this ticket re-locks to remove the waiter + wake the next front.
        let _ticket = Ticket { bucket: Arc::clone(self), key };

        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return Err(Duration::from_secs_f64(1.0)),
        };
        loop {
            g.refill();
            let is_front = g.waiters.iter().next() == Some(&key);
            if is_front && g.tokens >= 1.0 {
                g.tokens -= 1.0;
                return Ok(()); // _ticket drop removes the key + notifies the next waiter
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Duration::from_secs_f64(g.secs_until_token()));
            }
            let remaining = deadline - now;
            let timeout = if is_front {
                // Front: sleep just long enough for the next token (capped by the
                // deadline). A positive floor avoids a busy spin on a full-ish rate.
                Duration::from_secs_f64(g.secs_until_token().max(0.001)).min(remaining)
            } else {
                // Behind the front: re-check periodically so we notice the front
                // being served or abandoning even without a token-refill event.
                WAITER_RECHECK.min(remaining)
            };
            let (ng, _) = match self.cv.wait_timeout(g, timeout) {
                Ok(pair) => pair,
                Err(_) => return Err(Duration::from_secs_f64(1.0)),
            };
            g = ng;
        }
    }
}

/// RAII cleanup for one admission attempt: removes the waiter key and wakes the
/// next front on drop, so no exit path (success, deadline, panic) can leave a
/// stale waiter wedging the queue.
struct Ticket {
    bucket: Arc<FairBucket>,
    key: WaiterKey,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if let Ok(mut g) = self.bucket.inner.lock() {
            g.waiters.remove(&self.key);
        }
        self.bucket.cv.notify_all();
    }
}

/// Rate limiter managing per-target fair buckets.
#[derive(Debug)]
pub struct RateLimiter {
    buckets: HashMap<String, Arc<FairBucket>>,
}

impl RateLimiter {
    /// Create a new rate limiter.
    /// `targets` is a list of (target_handle, requests_per_second) pairs.
    pub fn new(targets: &[(String, f64)]) -> Self {
        let buckets = targets
            .iter()
            .map(|(handle, rps)| (handle.clone(), FairBucket::new(*rps)))
            .collect();
        RateLimiter { buckets }
    }

    /// Try to acquire a token for a target. Non-blocking (legacy fast path).
    pub fn try_acquire(&mut self, target: &str) -> Result<(), RateLimitError> {
        match self.buckets.get(target) {
            Some(bucket) => bucket.try_acquire().map_err(RateLimitError::RetryAfter),
            None => Err(RateLimitError::UnknownTarget(target.to_string())),
        }
    }

    /// The per-target fair bucket, for the blocking admission queue. The caller
    /// clones this Arc under the (brief) global RateLimiter lock, releases that
    /// lock, then calls `acquire_blocking` on the Arc — so the blocking wait never
    /// holds the global lock and never blocks other targets.
    pub fn bucket_for(&self, target: &str) -> Option<Arc<FairBucket>> {
        self.buckets.get(target).cloned()
    }

    /// Get the configured rate for a target (requests per second).
    #[allow(dead_code)] // public accessor (telemetry/callers outside the crate)
    pub fn rate_for(&self, target: &str) -> Option<f64> {
        self.buckets.get(target).map(|b| b.refill_rate())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(rps: f64) -> RateLimiter {
        RateLimiter::new(&[("test-target".into(), rps)])
    }

    #[test]
    fn allows_burst_up_to_capacity() {
        let mut lim = limiter(2.0); // 2 RPS, burst = 4
        assert!(lim.try_acquire("test-target").is_ok());
        assert!(lim.try_acquire("test-target").is_ok());
        assert!(lim.try_acquire("test-target").is_ok());
        assert!(lim.try_acquire("test-target").is_ok());
        let err = lim.try_acquire("test-target").unwrap_err();
        assert!(matches!(err, RateLimitError::RetryAfter(_)));
    }

    #[test]
    fn retry_after_duration_is_reasonable() {
        let mut lim = limiter(1.0); // 1 RPS, burst = 2
        lim.try_acquire("test-target").unwrap();
        lim.try_acquire("test-target").unwrap();
        let err = lim.try_acquire("test-target").unwrap_err();
        match err {
            RateLimitError::RetryAfter(d) => {
                assert!(d.as_secs_f64() > 0.0);
                assert!(d.as_secs_f64() <= 1.1);
            }
            _ => panic!("Expected RetryAfter"),
        }
    }

    #[test]
    fn refills_over_time() {
        let mut lim = limiter(10.0); // 10 RPS, burst = 20
        for _ in 0..20 {
            lim.try_acquire("test-target").unwrap();
        }
        assert!(lim.try_acquire("test-target").is_err());
        std::thread::sleep(Duration::from_millis(200));
        assert!(lim.try_acquire("test-target").is_ok());
    }

    #[test]
    fn unknown_target_rejected() {
        let mut lim = limiter(1.0);
        let err = lim.try_acquire("nonexistent").unwrap_err();
        assert!(matches!(err, RateLimitError::UnknownTarget(_)));
    }

    #[test]
    fn multiple_targets_independent() {
        let mut lim = RateLimiter::new(&[("target-a".into(), 1.0), ("target-b".into(), 1.0)]);
        lim.try_acquire("target-a").unwrap();
        lim.try_acquire("target-a").unwrap();
        assert!(lim.try_acquire("target-a").is_err());
        assert!(lim.try_acquire("target-b").is_ok());
    }

    #[test]
    fn rate_for_returns_configured_rate() {
        let lim = limiter(5.0);
        assert_eq!(lim.rate_for("test-target"), Some(5.0));
        assert_eq!(lim.rate_for("nonexistent"), None);
    }

    #[test]
    fn very_low_rate() {
        let mut lim = limiter(0.1); // 1 per 10s, burst = 1
        assert!(lim.try_acquire("test-target").is_ok());
        let err = lim.try_acquire("test-target").unwrap_err();
        match err {
            RateLimitError::RetryAfter(d) => assert!(d.as_secs_f64() > 1.0),
            _ => panic!("Expected RetryAfter"),
        }
    }

    #[test]
    fn zero_and_negative_rate_do_not_panic() {
        for bad_rps in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            let mut lim = limiter(bad_rps);
            assert!(lim.try_acquire("test-target").is_ok());
            for _ in 0..5 {
                match lim.try_acquire("test-target") {
                    Ok(()) => {}
                    Err(RateLimitError::RetryAfter(d)) => {
                        assert!(d.as_secs_f64().is_finite());
                        assert!(d.as_secs_f64() >= 0.0);
                    }
                    Err(other) => panic!("unexpected error: {other}"),
                }
            }
            assert!(lim.rate_for("test-target").unwrap() > 0.0);
        }
    }

    #[test]
    fn display_format() {
        let err = RateLimitError::RetryAfter(Duration::from_millis(1500));
        assert!(err.to_string().contains("1.5s"));
        let err = RateLimitError::UnknownTarget("foo".into());
        assert!(err.to_string().contains("foo"));
    }

    // --- fair admission queue (acquire_blocking) ---------------------------

    #[test]
    fn acquire_blocking_grants_immediately_when_tokens_available() {
        let lim = limiter(5.0);
        let b = lim.bucket_for("test-target").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        assert!(b.acquire_blocking(0, deadline).is_ok());
    }

    #[test]
    fn acquire_blocking_paces_at_the_rate() {
        // 5 RPS, burst 10: 12 blocking acquires must take >= ~2 tokens' worth of
        // refill time (the 2 beyond burst wait ~1/5s each).
        let lim = limiter(5.0);
        let b = lim.bucket_for("test-target").unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let start = Instant::now();
        for _ in 0..12 {
            b.acquire_blocking(0, deadline).unwrap();
        }
        let elapsed = start.elapsed().as_secs_f64();
        // 10 free (burst) + 2 paced at 5/s ≈ 0.4s. Allow slack but require pacing.
        assert!(elapsed >= 0.3, "expected pacing, took {elapsed}s");
    }

    #[test]
    fn acquire_blocking_deadline_returns_err() {
        let lim = limiter(1.0); // burst 2
        let b = lim.bucket_for("test-target").unwrap();
        // Drain the burst via blocking grants.
        let far = Instant::now() + Duration::from_secs(5);
        b.acquire_blocking(0, far).unwrap();
        b.acquire_blocking(0, far).unwrap();
        // Now empty; a near deadline must return Err rather than block forever.
        let near = Instant::now() + Duration::from_millis(50);
        assert!(b.acquire_blocking(0, near).is_err());
    }

    #[test]
    fn acquire_blocking_is_fifo_within_a_priority() {
        use std::sync::mpsc;
        // 1 RPS, burst 2. Drain the 2 burst tokens, then 3 threads queue; they
        // must be served in arrival order (t0, t1, t2) as tokens refill.
        let lim = limiter(1.0);
        let b = lim.bucket_for("test-target").unwrap();
        let far = Instant::now() + Duration::from_secs(30);
        b.acquire_blocking(0, far).unwrap();
        b.acquire_blocking(0, far).unwrap();

        let (tx, rx) = mpsc::channel();
        let mut handles = vec![];
        for id in 0..3 {
            let b = Arc::clone(&b);
            let tx = tx.clone();
            handles.push(std::thread::spawn(move || {
                // Stagger starts so arrival order is deterministic.
                std::thread::sleep(Duration::from_millis(40 * id as u64));
                b.acquire_blocking(0, Instant::now() + Duration::from_secs(30)).unwrap();
                tx.send(id).unwrap();
            }));
        }
        drop(tx);
        let order: Vec<i32> = rx.iter().collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(order, vec![0, 1, 2], "FIFO order within one priority");
    }

    #[test]
    fn acquire_blocking_priority_jumps_the_queue() {
        use std::sync::mpsc;
        // Empty the burst, enqueue a low-priority waiter first, then a
        // high-priority one that arrived later — high priority must be served
        // first once a token refills.
        let lim = limiter(2.0); // burst 4
        let b = lim.bucket_for("test-target").unwrap();
        let far = Instant::now() + Duration::from_secs(30);
        for _ in 0..4 {
            b.acquire_blocking(0, far).unwrap();
        }
        let (tx, rx) = mpsc::channel();

        let b_low = Arc::clone(&b);
        let tx_low = tx.clone();
        let low = std::thread::spawn(move || {
            b_low.acquire_blocking(0, Instant::now() + Duration::from_secs(30)).unwrap();
            tx_low.send("low").unwrap();
        });
        std::thread::sleep(Duration::from_millis(50)); // low enqueues first
        let b_high = Arc::clone(&b);
        let tx_high = tx.clone();
        let high = std::thread::spawn(move || {
            b_high.acquire_blocking(10, Instant::now() + Duration::from_secs(30)).unwrap();
            tx_high.send("high").unwrap();
        });
        drop(tx);

        let first = rx.recv().unwrap();
        low.join().unwrap();
        high.join().unwrap();
        assert_eq!(first, "high", "higher priority served before an earlier low one");
    }

    #[test]
    fn abandoned_waiter_does_not_wedge_the_queue() {
        // A waiter that hits its deadline must be removed so a later waiter is
        // still served. Drain burst, let one waiter give up, then another wins.
        let lim = limiter(2.0); // burst 4
        let b = lim.bucket_for("test-target").unwrap();
        let far = Instant::now() + Duration::from_secs(30);
        for _ in 0..4 {
            b.acquire_blocking(0, far).unwrap();
        }
        // This one gives up quickly.
        assert!(b
            .acquire_blocking(0, Instant::now() + Duration::from_millis(30))
            .is_err());
        // A fresh waiter with a generous deadline still gets served.
        assert!(b
            .acquire_blocking(0, Instant::now() + Duration::from_secs(5))
            .is_ok());
    }
}
