# molly-core

**A Rust-enforced safety cage for autonomous agents that make outbound network requests.**

Every request an agent makes passes through five gates, enforced in Rust so they
cannot be bypassed from a higher-level language or a language model:

1. **Scope** — the destination must match a compiled-in host/path allowlist.
2. **Armed** — a target starts *unarmed* and refuses active traffic until an operator explicitly arms it.
3. **Rate limit** — a per-target token bucket with a fair admission queue.
4. **Audit** — every request is written to an append-only log *before* it leaves the box.
5. **One gated client** — all of the above are wired into a single `HttpClient`. There is no other way out.

This is the safety layer extracted from [Molly](https://medium.com/@jyrkihuhta), an
offensive-security agent whose design rule is that *the language model never touches
the target*: the model reasons, deterministic code acts, and everything the code does
goes through this cage.

---

> ## ⚠️ Authorized use only
>
> molly-core bundles **active security-testing primitives** on top of the gate —
> batch request sweeps (`sweep`/`burst`), raw-byte exchange for protocol research
> (`raw_exchange`), un-normalized request paths (`fetch_raw`), and gated SSH
> command execution (`ssh_exec`). These are commodity techniques (your `curl
> --path-as-is`, `netcat`, `ffuf`), but the point of this crate is that **even
> these run only through the scope → armed → rate → audit path**.
>
> Use it exclusively against systems you **own** or are **explicitly authorized**
> to test. The scope allowlist, the unarmed-by-default gate, and the audit log
> exist to make "controllably dangerous" a true statement — not to be switched off.

---

## Why

Most agent frameworks gate dangerous actions *by convention*: a prompt that says
"only touch in-scope hosts," a Python wrapper that *should* be the only egress. A
convention is not an enforcement. molly-core moves the boundary into a compiled
Rust layer: the agent (and any LLM driving it) can only reach the network through a
`HttpClient` that has already checked scope, arming, and rate, and has journaled the
request. Out-of-scope, unarmed, or over-rate requests return an error instead of a
packet.

## Use cases

molly-core is useful anywhere code — especially code an LLM can steer — makes
outbound requests you need to *bound and account for*:

- **Caging an LLM agent's web access.** Give a tool-using or autonomous agent a
  `fetch` it can call freely, knowing the model can only ever reach allowlisted
  hosts, at a capped rate, with every call journaled. The model decides *what* to
  request; the cage decides *whether it may*.
- **An authorized-testing / pentest harness.** A scoped, armed, audited HTTP
  client (plus `sweep`/`burst`/`raw_exchange`/`fetch_raw`) where every request is
  provably in-scope, paced so you don't knock the target over, and backed by a
  complete audit trail you can attach to the report.
- **A hard "staging can't touch prod" lock.** The `scope_lock` pattern compiles an
  allowlist into the binary: under `MOLLY_ENV=staging` the process *refuses to
  start* if any configured target is outside it. Retargeting is a source change
  and a rebuild — not a config edit someone can fat-finger at 3 a.m.
- **Fair, rate-limited shared egress.** When several workers or agents share one
  target's budget, the fair admission queue (priority, then FIFO) paces them so
  none starves and none stampedes — respectful crawling and shared-quota API use
  without a central coordinator.
- **An append-only record of what left the box.** Even in a non-agent service, the
  audit log gives you a per-request ledger — target, method, URL, body hash,
  written *before* the request goes out — for forensics or regulated environments.

## Install (Rust)

```toml
[dependencies]
molly-core = { git = "https://github.com/jyrkihuhta/molly-core" }
```

The default build is **pure Rust** — no Python, no pyo3.

## Quickstart

```rust
use std::sync::{Arc, Mutex, RwLock};
use molly_core::{ArmedLevel, ArmedState, HttpClient, RateLimiter, RequestMode};

// One target: handle "demo", scoped to example.com, 2 requests/second.
let targets = vec![(
    "demo".to_string(),
    vec!["example.com".to_string(), "*.example.com".to_string()],
    2.0,
)];
let armed   = Arc::new(RwLock::new(ArmedState::new(&["demo".to_string()])));
let limiter = Arc::new(Mutex::new(RateLimiter::new(&[("demo".to_string(), 2.0)])));

let client = HttpClient::new(targets, armed.clone(), limiter, "/tmp/audit".into())?;

// Out of scope → Err, before any packet is sent.
assert!(client.pre_flight_check("https://evil.test/", RequestMode::Active).is_err());

// In scope but UNARMED → Err in active mode.
assert!(client.pre_flight_check("https://example.com/", RequestMode::Active).is_err());

// The operator arms the target — the authorization gesture — then it passes.
armed.write().unwrap().set("demo", ArmedLevel::Armed, None)?;
let pre = client.pre_flight_check("https://example.com/", RequestMode::Active)?;
assert_eq!(pre.target_handle, "demo");

// A real request runs the identical gate path and then performs the call:
// let resp = client.fetch_with_mode("GET", "https://example.com/", &headers, None, RequestMode::Active)?;
```

Run the full tour offline (no network):

```
cargo run --example gated_client
```

## Python

molly-core is primarily a Rust crate; an **optional** `python` feature builds a
PyO3 extension module (`molly_core._core`) exposing the same gated `HttpClient`,
`ScopeChecker`, and `diff_responses`. Build it with [maturin](https://www.maturin.rs/):

```
maturin develop --release        # turns on the `python` feature
```

```python
from molly_core._core import HttpClient
client = HttpClient([("demo", ["example.com"], 2.0)], "/tmp/audit")
client.set_armed("demo", "armed")
resp = client.fetch("GET", "https://example.com/")
```

## Modules

| Module | Role |
|---|---|
| `scope` | URL allowlist (`example.com`, `*.example.com`, path prefixes, `!deny` rules). |
| `armed` | Per-target armed/unarmed/paused state, with optional expiry. The authorization gate. |
| `rate_limiter` | Per-target token bucket + fair (priority, FIFO) admission queue. |
| `audit` | Append-only JSONL log of every request, written before it leaves. |
| `fetch` | The `HttpClient` that wires the gates together — `fetch`, `sweep`, `burst`, `raw_exchange`, `fetch_raw`, `ssh_exec`. |
| `diff` | Baseline-vs-mutation response diffing (status/headers/body/JSON/timing). |
| `scope_lock` | Optional compile-time lock: under `MOLLY_ENV=staging`, refuse to start unless every configured host is in a hardcoded test allowlist. |
| `raw_request` | Verbatim HTTP/1.1 sender (no path normalization / no forced framing) used by `fetch_raw` / `raw_exchange`. |
| `ssh_exec` | Gated SSH command execution. |

## Modes

- **Active** — full gates: scope + armed + rate + audit. For operations that act on the target.
- **Passive** — scope + rate + audit, *armed skipped*. For read-only reconnaissance on a scoped-but-unarmed host.

## Contributing

Contributions, issues, and bug reports are all welcome — this is a young crate
(0.1), and more eyes on the cage is exactly the point.

The most valuable contribution is an **attempt to get around a gate.** If you find
a way to make a request that skips scope, arming, the rate limiter, or the audit
log, that isn't an embarrassment to report — it's the whole reason the code is in
the open. Open an issue, or better, a failing test.

**New features are welcome, too.** Built something useful on top of the gate?
Open a PR. Have an idea but not the time to build it? Open an issue and suggest
it. For anything substantial, a quick issue to sketch the approach first saves us
both rework.

Ground rules, so the cage stays a cage:

- New network capability goes **through the gated client**, never around it. A
  primitive that opens its own socket defeats the purpose.
- Keep it **authorized-use-first.** This crate is for systems you own or are
  cleared to test; a contribution shouldn't make the unsafe path the easy one.
- Add or update tests, and keep the suite green.

Getting set up:

```sh
git clone https://github.com/jyrkihuhta/molly-core
cd molly-core
cargo test                         # pure-Rust unit tests
cargo run --example gated_client   # the offline gate tour
cargo build --features python      # the optional PyO3 extension
```

PRs: fork, branch, make the tests pass, and run `cargo fmt` and `cargo clippy`
before you push. For a security-sensitive gate bypass you'd rather not post in
public, use this repo's private vulnerability reporting (GitHub → Security →
Report a vulnerability), or reach me via [Medium](https://medium.com/@jyrkihuhta).

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
