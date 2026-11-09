//! Hard scope lock for a staging Molly instance.
//!
//! This is the actual enforcement of the operator's hard safety invariant
//! #1 — "Staging Molly may only fire at TEST targets... Enforcement belongs
//! at Molly's Rust scope layer, not convention."
//!
//! When the `MOLLY_ENV=staging` environment variable is set, every
//! configured scope rule's host must be one of the hardcoded target-dummy
//! hostnames below. The allowlist is compiled into this binary, not read
//! from JSON — retargeting a locked instance at a real domain requires a
//! source change and rebuild, not just a config edit. Enforced once, at
//! `HttpClient` construction (Molly startup), covering every target the
//! process was configured with.
//!
//! Fails loud: a violation returns `Err`, which the PyO3 `HttpClient`
//! constructor turns into a Python exception that crashes Molly at startup.
//! A misconfigured locked instance must refuse to start, not silently narrow
//! its own scope down to the rules that happen to be allowed.

use crate::scope::ScopeChecker;

/// The only hostnames a `MOLLY_ENV=staging` instance may ever
/// target — the target-dummy shooting range (see
/// `target-dummy/molly-config.json`, which lists exactly these entries).
const TEST_DUMMY_HOSTS: &[&str] = &[
    "notekeeper",
    "taskboard",
    "dashql",
    "couponshop",
    "ssrfbox",
    "jwtlab",
    // Damn Vulnerable GraphQL Application — added 2026-09-09 as the
    // "tier 1" range's dedicated GraphQL-abuse member (see
    // target-dummy/dvga/Dockerfile). Same test-only status as the six above.
    "dvga",
];

const LOCK_ENV_VAR: &str = "MOLLY_ENV";
const LOCK_ENV_VALUE: &str = "staging";

/// Process-global lock serializing every test that reads or mutates `MOLLY_ENV`.
/// Because `HttpClient::new` now reads it (the scope lock runs in the primary
/// constructor), any test that constructs a client must hold this while a
/// scope-lock test might have `MOLLY_ENV=staging` set — otherwise the client's
/// lock check could see a transient `staging` and spuriously reject. Test-only;
/// production never coordinates on it.
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// XBOW validation-benchmark challenges, deployed as `xben-NNN-...`
/// containers on `target-dummy_range` — deliberately-vulnerable TEST
/// targets, same status as `TEST_DUMMY_HOSTS` above. Matched by prefix
/// (there are ~104 of them, an explicit per-host allowlist entry each isn't
/// practical) AND required to be a bare internal docker hostname with no
/// dot: a real bug-bounty domain always has one, so `xben-foo.example.com`
/// is still rejected — the prefix alone would otherwise be a scope-lock
/// bypass for anyone who registers a domain starting with "xben-".
fn is_xbow_test_host(host: &str) -> bool {
    host.starts_with("xben-") && !host.contains('.')
}

/// True if this process is running as a scope-locked staging instance.
pub fn is_locked() -> bool {
    std::env::var(LOCK_ENV_VAR)
        .map(|v| v == LOCK_ENV_VALUE)
        .unwrap_or(false)
}

/// Validate that every rule for every target references only an allowed
/// test-dummy host. `targets` is (handle, effective_scope_rules) pairs —
/// "effective" meaning allow rules and `!`-prefixed deny rules alike (a deny
/// rule naming a real domain still proves the config intends to reach it,
/// so it's checked too).
///
/// No-op (always `Ok`) when [`is_locked`] is false.
pub fn enforce(targets: &[(String, Vec<String>)]) -> Result<(), String> {
    if !is_locked() {
        return Ok(());
    }
    for (handle, rules) in targets {
        for raw in rules {
            let rule = ScopeChecker::parse_rule(raw);
            let host = rule
                .domain
                .strip_prefix("*.")
                .unwrap_or(rule.domain.as_str());
            if !TEST_DUMMY_HOSTS.contains(&host) && !is_xbow_test_host(host) {
                return Err(format!(
                    "{LOCK_ENV_VAR}={LOCK_ENV_VALUE}: target '{handle}' scope rule \
                     '{raw}' references host '{host}', which is not in the \
                     test-dummy allowlist {TEST_DUMMY_HOSTS:?} (nor a dotless \
                     xben-* XBOW test host). A locked instance may only ever \
                     target the test-dummy range — this requires a source \
                     change to src/scope_lock.rs, not a config edit."
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Environment variables are process-global — tests that touch MOLLY_ENV
    // must not run concurrently with each other, and must restore it even if
    // the test body panics (an assertion failure), or every test after the
    // first panicking one would silently inherit a mutated MOLLY_ENV. An RAII
    // guard makes that unconditional via Drop; a plain "restore after f()"
    // helper does not — this file's history has already hit that exact bug.
    use std::sync::MutexGuard;

    struct LockEnvGuard<'a> {
        _mutex_guard: MutexGuard<'a, ()>,
        prev: Option<String>,
    }

    impl Drop for LockEnvGuard<'_> {
        fn drop(&mut self) {
            match self.prev.take() {
                Some(v) => std::env::set_var(LOCK_ENV_VAR, v),
                None => std::env::remove_var(LOCK_ENV_VAR),
            }
        }
    }

    fn with_lock_env(value: Option<&str>) -> LockEnvGuard<'static> {
        let mutex_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var(LOCK_ENV_VAR).ok();
        match value {
            Some(v) => std::env::set_var(LOCK_ENV_VAR, v),
            None => std::env::remove_var(LOCK_ENV_VAR),
        }
        LockEnvGuard {
            _mutex_guard: mutex_guard,
            prev,
        }
    }

    #[test]
    fn unlocked_by_default() {
        let _guard = with_lock_env(None);
        assert!(!is_locked());
        let targets = vec![("whatnot".to_string(), vec!["*.whatnot.com".to_string()])];
        assert!(enforce(&targets).is_ok());
    }

    #[test]
    fn locked_allows_test_dummy_hosts() {
        let _guard = with_lock_env(Some("staging"));
        assert!(is_locked());
        let targets = vec![
            (
                "notekeeper".to_string(),
                vec!["http://notekeeper:5000/*".to_string()],
            ),
            ("ssrfbox".to_string(), vec!["ssrfbox".to_string()]),
            ("jwtlab".to_string(), vec!["*.jwtlab".to_string()]),
        ];
        assert!(enforce(&targets).is_ok());
    }

    #[test]
    fn locked_allows_dvga() {
        let _guard = with_lock_env(Some("staging"));
        let targets = vec![("dvga".to_string(), vec!["http://dvga:5013/*".to_string()])];
        assert!(enforce(&targets).is_ok());
    }

    #[test]
    fn locked_allows_xbow_challenge_hosts() {
        let _guard = with_lock_env(Some("staging"));
        let targets = vec![(
            "xben-005-24".to_string(),
            vec!["http://xben-005-24-app-1:80/*".to_string()],
        )];
        assert!(enforce(&targets).is_ok());
    }

    #[test]
    fn locked_rejects_a_real_domain_disguised_with_xben_prefix() {
        // The prefix check alone would be a scope-lock bypass for anyone who
        // registers a domain starting with "xben-" — the dotless requirement
        // is the actual safety boundary here, not the prefix.
        let _guard = with_lock_env(Some("staging"));
        let targets = vec![(
            "evil".to_string(),
            vec!["http://xben-foo.example.com/*".to_string()],
        )];
        let err = enforce(&targets).unwrap_err();
        assert!(err.contains("example.com"));
    }

    #[test]
    fn locked_rejects_a_real_domain_hidden_in_an_xben_deny_rule() {
        let _guard = with_lock_env(Some("staging"));
        let targets = vec![(
            "xben-005-24".to_string(),
            vec![
                "http://xben-005-24-app-1:80/*".to_string(),
                "!xben-005-24.example.com".to_string(),
            ],
        )];
        assert!(enforce(&targets).is_err());
    }

    #[test]
    fn locked_allows_bare_xben_prefix_with_nothing_after_it() {
        // is_xbow_test_host is a prefix + dotless check, not a shape check —
        // "xben-" alone matches the prefix trivially and is dotless, so it
        // passes, same as any other xben-* string would. Documents current
        // (loose) behavior rather than asserting a stricter one; harmless in
        // practice since a bare "xben-" host can't resolve to anything real.
        let _guard = with_lock_env(Some("staging"));
        let targets = vec![("weird".to_string(), vec!["xben-".to_string()])];
        assert!(enforce(&targets).is_ok());
    }

    #[test]
    fn locked_rejects_a_real_target_domain() {
        let _guard = with_lock_env(Some("staging"));
        let targets = vec![("whatnot".to_string(), vec!["*.whatnot.com".to_string()])];
        let err = enforce(&targets).unwrap_err();
        assert!(err.contains("whatnot.com"));
        assert!(err.contains("test-dummy"));
    }

    #[test]
    fn locked_rejects_a_real_domain_hidden_in_a_deny_rule() {
        // A deny rule still names a real domain the config author intended
        // to reach — must be caught the same as an allow rule would be.
        let _guard = with_lock_env(Some("staging"));
        let targets = vec![(
            "notekeeper".to_string(),
            vec![
                "http://notekeeper:5000/*".to_string(),
                "!admin.whatnot.com".to_string(),
            ],
        )];
        assert!(enforce(&targets).is_err());
    }

    #[test]
    fn other_env_values_do_not_activate_the_lock() {
        // MOLLY_ENV is an enum-style var (like NODE_ENV), not a boolean flag
        // — only the exact value "staging" activates the lock. A value like
        // "true" or "1" must not be treated as truthy here; that would make
        // it too easy to *think* you'd locked an instance by setting some
        // plausible-looking value when you actually hadn't.
        let _guard = with_lock_env(Some("true"));
        assert!(!is_locked());
    }
}
