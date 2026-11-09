//! A pure-Rust tour of the molly-core safety cage — no Python, no network.
//!
//! Run with:  `cargo run --example gated_client`
//!
//! It builds a gated [`HttpClient`] for one scoped target, then uses
//! `pre_flight_check` (which runs scope + armed + rate, but sends nothing on
//! the wire) to show each gate's decision:
//!
//!   1. an out-of-scope URL is rejected,
//!   2. an in-scope but UNARMED target is rejected in Active mode,
//!   3. the same target passes once an operator arms it,
//!   4. Passive mode skips the armed gate (recon on a scoped-but-unarmed host).
//!
//! A real request would be `client.fetch_with_mode("GET", url, ...)`, which
//! runs the identical gate path and *then* performs the network call.

use std::sync::{Arc, Mutex, RwLock};

use molly_core::{ArmedLevel, ArmedState, HttpClient, RateLimiter, RequestMode};

fn main() {
    // A scratch audit directory — every allowed request is journaled here
    // before it would leave the box.
    let audit_dir = std::env::temp_dir().join("molly-core-example-audit");
    let _ = std::fs::create_dir_all(&audit_dir);

    // One target: handle "demo", scoped to example.com, 2 requests/second.
    let targets = vec![(
        "demo".to_string(),
        vec!["example.com".to_string(), "*.example.com".to_string()],
        2.0,
    )];

    let armed = Arc::new(RwLock::new(ArmedState::new(&["demo".to_string()])));
    let limiter = Arc::new(Mutex::new(RateLimiter::new(&[("demo".to_string(), 2.0)])));

    let client = HttpClient::new(targets, armed.clone(), limiter, audit_dir)
        .expect("client construction (scope lock is a no-op unless MOLLY_ENV=staging)");

    println!("molly-core — gated client tour\n");

    // 1) Out of scope → rejected before anything else.
    report(
        "out-of-scope URL (active)",
        client.pre_flight_check("https://not-in-scope.test/admin", RequestMode::Active),
    );

    // 2) In scope, but the target starts UNARMED → rejected in active mode.
    report(
        "in-scope, unarmed (active)",
        client.pre_flight_check("https://example.com/", RequestMode::Active),
    );

    // 3) Operator arms the target — the authorization gesture — then it passes.
    armed
        .write()
        .unwrap()
        .set("demo", ArmedLevel::Armed, None)
        .expect("arm demo");
    report(
        "in-scope, now armed (active)",
        client.pre_flight_check("https://example.com/", RequestMode::Active),
    );

    // 4) Passive mode skips the armed gate — recon on a scoped host.
    armed
        .write()
        .unwrap()
        .set("demo", ArmedLevel::Unarmed, None)
        .expect("disarm demo");
    report(
        "in-scope, unarmed (passive)",
        client.pre_flight_check("https://example.com/", RequestMode::Passive),
    );

    println!(
        "\nThe checks above are pre-flight only — no request left the box, so\n\
         nothing was written to the audit log. A real fetch/sweep/burst journals\n\
         every request (before it leaves) under the configured audit directory,\n\
         e.g.:\n  {}",
        std::env::temp_dir()
            .join("molly-core-example-audit")
            .display()
    );
}

fn report<T: std::fmt::Debug, E: std::fmt::Display>(label: &str, result: Result<T, E>) {
    match result {
        Ok(ok) => println!("  ALLOW  {label:<32} -> {ok:?}"),
        Err(e) => println!("  DENY   {label:<32} -> {e}"),
    }
}
