//! URL scope enforcement for bug bounty targets.
//!
//! Every outbound request must pass the scope check before leaving the box.
//! Scope rules are loaded from config and compiled into an allowlist.
//!
//! Supports:
//! - Exact domain matching: `api.example.com`
//! - Wildcard subdomains: `*.example.com` (matches any subdomain, not the apex)
//! - Path prefixes: `https://example.com/api/v1/*`
//! - Exclusions: `!admin.example.com` (deny even if parent wildcard allows)

use url::Url;

/// A single scope rule — either an allow or deny pattern.
#[derive(Debug, Clone)]
pub struct ScopeRule {
    /// If true, this is a deny rule (overrides allows).
    pub deny: bool,
    /// Domain pattern — lowercase, may start with `*.` for wildcard.
    pub domain: String,
    /// Optional explicit port. When set (e.g. `host:8080`), only requests to
    /// that exact port match; when `None`, the rule matches any port on the
    /// host. Note: scope is gated on the URL *host*, not the resolved IP, so it
    /// does not by itself defend against DNS rebinding — see the module docs.
    pub port: Option<u16>,
    /// Optional path prefix — if set, only URLs under this path match.
    pub path_prefix: Option<String>,
    /// Allowed schemes (default: https only).
    pub schemes: Vec<String>,
}

/// Compiled scope checker — holds all rules and provides fast lookups.
#[derive(Debug, Clone)]
pub struct ScopeChecker {
    rules: Vec<ScopeRule>,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum ScopeError {
    /// URL is not in any allow rule.
    NotInScope(String),
    /// URL matches a deny rule.
    ExplicitlyDenied(String),
    /// URL is malformed or uses a blocked scheme.
    InvalidUrl(String),
}

impl std::fmt::Display for ScopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScopeError::NotInScope(url) => write!(f, "URL not in scope: {url}"),
            ScopeError::ExplicitlyDenied(url) => write!(f, "URL explicitly denied: {url}"),
            ScopeError::InvalidUrl(msg) => write!(f, "Invalid URL: {msg}"),
        }
    }
}

impl std::error::Error for ScopeError {}

impl ScopeChecker {
    /// Create a new scope checker from a list of rule strings.
    ///
    /// Rule format:
    /// - `example.com` — allow exact domain, any path, https only
    /// - `*.example.com` — allow any subdomain
    /// - `example.com/api/*` — allow domain with path prefix
    /// - `http://example.com/*` — explicit scheme (only way to allow http)
    /// - `!admin.example.com` — deny (overrides allows)
    pub fn new(rules: &[String]) -> Self {
        let parsed: Vec<ScopeRule> = rules.iter().map(|r| Self::parse_rule(r)).collect();
        ScopeChecker { rules: parsed }
    }

    /// Check if a URL is in scope. Returns Ok(()) if allowed, Err(ScopeError) if not.
    pub fn check(&self, url_str: &str) -> Result<(), ScopeError> {
        let url = Url::parse(url_str).map_err(|e| ScopeError::InvalidUrl(e.to_string()))?;

        let scheme = url.scheme().to_lowercase();
        let host = url
            .host_str()
            .ok_or_else(|| ScopeError::InvalidUrl("no host".to_string()))?
            .to_lowercase();
        let port = url.port_or_known_default();
        let path = url.path();

        // Check deny rules first — they override everything
        for rule in &self.rules {
            if rule.deny && Self::matches_rule(rule, &scheme, &host, port, path) {
                return Err(ScopeError::ExplicitlyDenied(url_str.to_string()));
            }
        }

        // Check allow rules
        for rule in &self.rules {
            if !rule.deny && Self::matches_rule(rule, &scheme, &host, port, path) {
                return Ok(());
            }
        }

        Err(ScopeError::NotInScope(url_str.to_string()))
    }

    /// Returns true if the URL is in scope, false otherwise.
    pub fn is_allowed(&self, url_str: &str) -> bool {
        self.check(url_str).is_ok()
    }

    /// Authorize a literal request-line path, for raw/verbatim request
    /// primitives (`fetch_raw_path`, `raw_exchange`).
    ///
    /// `url_str` supplies the scheme + host (resolved exactly as [`check`]), but
    /// the path tested is the caller's verbatim `raw_path` — the one that will
    /// actually be written on the wire — instead of the URL's own, already-
    /// authorized path. This closes the gap where a path-restricted scope
    /// (`example.com/api/*`) is satisfied by an in-prefix `url` while the raw
    /// request line targets a different path on the same in-scope host. Same
    /// deny-then-allow decision as [`check`]; a host-only rule still grants any
    /// path (that is its documented meaning).
    ///
    /// [`check`]: ScopeChecker::check
    pub fn check_raw_path(&self, url_str: &str, raw_path: &str) -> Result<(), ScopeError> {
        let url = Url::parse(url_str).map_err(|e| ScopeError::InvalidUrl(e.to_string()))?;
        let scheme = url.scheme().to_lowercase();
        let host = url
            .host_str()
            .ok_or_else(|| ScopeError::InvalidUrl("no host".to_string()))?
            .to_lowercase();
        let port = url.port_or_known_default();
        // Compare the prefix against the path portion of the raw target only,
        // excluding any `?query`/`#fragment`, mirroring how `url.path()` works.
        let path = raw_path.split(['?', '#']).next().unwrap_or(raw_path);

        // When the host is authorized only under a path PREFIX (not host-wide),
        // the raw path must not use traversal (`..`, encoded dots, `%2f`,
        // backslash) to climb out of the prefix after a textual `starts_with`
        // match — the verbatim transports send the path un-normalized, so the
        // server would resolve it elsewhere. Fail closed. (For a host-wide
        // scope this is the intended path-normalization-bypass use, so it is
        // only enforced when a genuine allow-prefix restriction is in force.)
        if self.allow_is_path_restricted(&scheme, &host, port) && has_traversal(path) {
            return Err(ScopeError::NotInScope(format!(
                "{url_str} (raw path {raw_path} uses traversal under a path-restricted scope)"
            )));
        }

        for rule in &self.rules {
            if rule.deny && Self::matches_rule(rule, &scheme, &host, port, path) {
                return Err(ScopeError::ExplicitlyDenied(format!(
                    "{url_str} (raw path {raw_path})"
                )));
            }
        }
        for rule in &self.rules {
            if !rule.deny && Self::matches_rule(rule, &scheme, &host, port, path) {
                return Ok(());
            }
        }
        Err(ScopeError::NotInScope(format!(
            "{url_str} (raw path {raw_path})"
        )))
    }

    /// Whether a verbatim primitive must authorize each on-the-wire request
    /// path for `url_str` (via [`check_raw_path`]), rather than relying on the
    /// URL's own path having been checked.
    ///
    /// Returns `true` when the host is authorized only under a path prefix more
    /// specific than `/` (so paths must stay within it), OR when any deny rule
    /// could match this host+scheme (so a host-wide allow plus a path-scoped
    /// deny still forces per-request-line authorization — otherwise the deny
    /// would be silently skipped on the raw primitives). Returns `false` only
    /// when some allow rule grants arbitrary paths AND no deny rule applies.
    /// Fails closed (`true`) on a parse failure.
    ///
    /// [`check_raw_path`]: ScopeChecker::check_raw_path
    pub fn requires_path_check(&self, url_str: &str) -> bool {
        let Ok(url) = Url::parse(url_str) else {
            return true;
        };
        let scheme = url.scheme().to_lowercase();
        let Some(host) = url.host_str().map(|h| h.to_lowercase()) else {
            return true;
        };
        let port = url.port_or_known_default();
        let (_matched_allow, grants_any_path) = self.allow_coverage(&scheme, &host, port);
        let any_deny_matches = self
            .rules
            .iter()
            .any(|rule| rule.deny && Self::host_scheme_matches(rule, &scheme, &host, port));
        // Needs per-path checking unless some allow rule grants arbitrary paths
        // and no deny rule applies. An unknown host (no matching allow) yields
        // grants_any_path = false, so this fails closed to `true`.
        !grants_any_path || any_deny_matches
    }

    /// `(matched_allow, grants_any_path)` for a host+scheme+port: whether any
    /// allow rule matches it at all, and whether any matching allow rule grants
    /// arbitrary paths (host-only or a `/*` catch-all prefix).
    fn allow_coverage(&self, scheme: &str, host: &str, port: Option<u16>) -> (bool, bool) {
        let mut matched_allow = false;
        let mut grants_any_path = false;
        for rule in &self.rules {
            if rule.deny || !Self::host_scheme_matches(rule, scheme, host, port) {
                continue;
            }
            matched_allow = true;
            if match &rule.path_prefix {
                None => true,
                Some(p) => p == "/",
            } {
                grants_any_path = true;
            }
        }
        (matched_allow, grants_any_path)
    }

    /// True when some allow rule matches the host but NONE grants arbitrary
    /// paths — every path must then stay within a prefix, so the verbatim
    /// transports authorize the exact path and reject traversal.
    fn allow_is_path_restricted(&self, scheme: &str, host: &str, port: Option<u16>) -> bool {
        let (matched_allow, grants_any_path) = self.allow_coverage(scheme, host, port);
        matched_allow && !grants_any_path
    }

    /// Exposed at crate visibility so scope_lock can validate which host a
    /// rule references without duplicating this parsing logic.
    pub(crate) fn parse_rule(raw: &str) -> ScopeRule {
        let trimmed = raw.trim();
        let (deny, rest) = if let Some(stripped) = trimmed.strip_prefix('!') {
            (true, stripped.trim())
        } else {
            (false, trimmed)
        };

        // Optional explicit scheme prefix, e.g. `http://notekeeper:5000/*`
        // (the module doc comment above has always shown this form). Without
        // one, default to https-only — the safety-relevant default for real
        // bug-bounty targets, which are always production HTTPS sites. An
        // explicit `http://` is how a rule opts into matching plain HTTP,
        // needed for the local target-dummy range (internal Docker network,
        // no TLS). Previously this prefix was never actually parsed out —
        // it silently became part of a garbage "domain" (e.g. `http:`),
        // so every target-dummy rule failed every scope check unnoticed.
        let (scheme, rest) = if let Some(r) = rest.strip_prefix("https://") {
            ("https", r)
        } else if let Some(r) = rest.strip_prefix("http://") {
            ("http", r)
        } else {
            ("https", rest)
        };

        // Split domain (+ optional port) and optional path
        let (domain_and_port, path_prefix) = if let Some(pos) = rest.find('/') {
            let d = &rest[..pos];
            let p = &rest[pos..];
            // Normalize path prefix: strip trailing * but keep the /
            let prefix = p.trim_end_matches('*').to_string();
            (d.to_lowercase(), Some(prefix))
        } else {
            (rest.to_lowercase(), None)
        };

        // Split off an explicit port (e.g. `notekeeper:5000`). When present it
        // is ENFORCED: the rule then matches only that port on the host. When
        // absent the rule matches any port (the common case for bare domains).
        let (domain, port) = match domain_and_port.rsplit_once(':') {
            Some((host, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
                (host.to_string(), p.parse::<u16>().ok())
            }
            _ => (domain_and_port, None),
        };

        ScopeRule {
            deny,
            domain,
            port,
            path_prefix,
            schemes: vec![scheme.to_string()],
        }
    }

    /// Scheme + domain + port match for a rule, ignoring any path prefix. Split
    /// out so `requires_path_check` can ask "does this rule cover the host?"
    /// without also committing to a path. `port` is the request's resolved port
    /// (scheme default when the URL omits one).
    fn host_scheme_matches(rule: &ScopeRule, scheme: &str, host: &str, port: Option<u16>) -> bool {
        // Scheme check
        if !rule.schemes.iter().any(|s| s == scheme) {
            return false;
        }

        // Port check: a rule with an explicit port matches only that port; a
        // rule without one matches any port.
        if let Some(rule_port) = rule.port {
            if port != Some(rule_port) {
                return false;
            }
        }

        // Domain check
        if rule.domain.starts_with("*.") {
            let parent = &rule.domain[2..]; // strip "*."
                                            // Must be a subdomain — "foo.example.com" matches "*.example.com"
                                            // but "example.com" does NOT match "*.example.com"
                                            // Wildcard requires a subdomain — apex must NOT match
            host.ends_with(&format!(".{parent}"))
        } else {
            host == rule.domain
        }
    }

    fn matches_rule(
        rule: &ScopeRule,
        scheme: &str,
        host: &str,
        port: Option<u16>,
        path: &str,
    ) -> bool {
        if !Self::host_scheme_matches(rule, scheme, host, port) {
            return false;
        }

        // Path prefix check (if specified), segment-aware so a prefix without a
        // trailing slash (e.g. `host/api`) does NOT over-grant sibling paths
        // like `/api-secret` or `/apifoo`: the match must end at the prefix or
        // continue on a `/` boundary. A prefix ending in `/` is already
        // boundary-safe under `starts_with`.
        if let Some(ref prefix) = rule.path_prefix {
            let ok = if prefix.ends_with('/') {
                path.starts_with(prefix.as_str())
            } else {
                path == prefix || path.starts_with(&format!("{prefix}/"))
            };
            if !ok {
                return false;
            }
        }

        true
    }
}

/// True if a request-line path uses a traversal construct that could, after a
/// textual prefix match, resolve to a different path on the server when sent
/// un-normalized by the verbatim transports: a `..` segment, percent-encoded
/// dots (`%2e`), an encoded slash (`%2f`), or a backslash.
fn has_traversal(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("..") || lower.contains("%2e") || lower.contains("%2f") || lower.contains('\\')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checker(rules: &[&str]) -> ScopeChecker {
        let rules: Vec<String> = rules.iter().map(|s| s.to_string()).collect();
        ScopeChecker::new(&rules)
    }

    #[test]
    fn exact_domain_allows() {
        let sc = checker(&["api.example.com"]);
        assert!(sc.is_allowed("https://api.example.com/foo"));
        assert!(sc.is_allowed("https://api.example.com/"));
    }

    #[test]
    fn exact_domain_rejects_other() {
        let sc = checker(&["api.example.com"]);
        assert!(!sc.is_allowed("https://evil.com/foo"));
        assert!(!sc.is_allowed("https://other.example.com/foo"));
    }

    #[test]
    fn wildcard_allows_subdomains() {
        let sc = checker(&["*.example.com"]);
        assert!(sc.is_allowed("https://api.example.com/foo"));
        assert!(sc.is_allowed("https://deep.sub.example.com/bar"));
    }

    #[test]
    fn wildcard_does_not_match_apex() {
        let sc = checker(&["*.example.com"]);
        // Apex domain should NOT match *.example.com
        assert!(!sc.is_allowed("https://example.com/foo"));
    }

    #[test]
    fn path_prefix_restricts() {
        let sc = checker(&["example.com/api/v1/*"]);
        assert!(sc.is_allowed("https://example.com/api/v1/users"));
        assert!(sc.is_allowed("https://example.com/api/v1/"));
        assert!(!sc.is_allowed("https://example.com/admin"));
        assert!(!sc.is_allowed("https://example.com/api/v2/users"));
    }

    #[test]
    fn deny_overrides_allow() {
        let sc = checker(&["*.example.com", "!admin.example.com"]);
        assert!(sc.is_allowed("https://api.example.com/foo"));
        assert!(!sc.is_allowed("https://admin.example.com/foo"));
    }

    #[test]
    fn http_rejected_by_default() {
        let sc = checker(&["example.com"]);
        assert!(!sc.is_allowed("http://example.com/foo"));
    }

    #[test]
    fn invalid_url_rejected() {
        let sc = checker(&["example.com"]);
        assert!(sc.check("not a url").is_err());
    }

    #[test]
    fn empty_rules_rejects_all() {
        let sc = checker(&[]);
        assert!(!sc.is_allowed("https://anything.com"));
    }

    #[test]
    fn case_insensitive() {
        let sc = checker(&["API.Example.COM"]);
        assert!(sc.is_allowed("https://api.example.com/foo"));
    }

    // Regression tests for the 2026-09-05 target-dummy scope bug (the operator's config
    // invariant): every existing target-dummy molly-config.json rule uses
    // `http://<handle>:<port>/*` (matching this module's own doc comment
    // example), but neither the scheme prefix nor the port were ever
    // actually parsed — every such rule silently became a garbage domain
    // and every scope check against it failed, unnoticed, for every local
    // test target.

    #[test]
    fn explicit_http_scheme_is_respected() {
        let sc = checker(&["http://notekeeper/*"]);
        assert!(sc.is_allowed("http://notekeeper/api/notes"));
        // Still https-rejecting unless https is also explicitly allowed —
        // an http:// rule opts a domain into http, not into "any scheme".
        assert!(!sc.is_allowed("https://notekeeper/api/notes"));
    }

    #[test]
    fn bare_domain_without_scheme_still_defaults_to_https_only() {
        // No regression: every real-target rule today has no scheme prefix
        // and must keep defaulting to https-only.
        let sc = checker(&["notekeeper"]);
        assert!(sc.is_allowed("https://notekeeper/foo"));
        assert!(!sc.is_allowed("http://notekeeper/foo"));
    }

    #[test]
    fn explicit_port_in_rule_is_matched() {
        // A rule with an explicit port matches that port — the format every
        // target-dummy config uses.
        let sc = checker(&["http://notekeeper:5000/*"]);
        assert!(sc.is_allowed("http://notekeeper:5000/api/notes"));
    }

    #[test]
    fn explicit_port_in_rule_is_enforced() {
        // When a rule names a port, a request to a DIFFERENT port on the same
        // in-scope host is rejected (no more port-agnostic over-grant).
        let sc = checker(&["http://notekeeper:5000/*"]);
        assert!(!sc.is_allowed("http://notekeeper:22/api/notes"));
        assert!(!sc.is_allowed("http://notekeeper/api/notes")); // defaults to :80
    }

    #[test]
    fn portless_rule_matches_any_port() {
        // A rule without a port keeps the permissive any-port behavior.
        let sc = checker(&["http://notekeeper/*"]);
        assert!(sc.is_allowed("http://notekeeper:5000/api"));
        assert!(sc.is_allowed("http://notekeeper/api"));
    }

    #[test]
    fn path_prefix_match_is_segment_aware() {
        // `host/api` must NOT over-grant sibling paths like `/api-secret`.
        let sc = checker(&["example.com/api"]);
        assert!(sc.is_allowed("https://example.com/api"));
        assert!(sc.is_allowed("https://example.com/api/users"));
        assert!(!sc.is_allowed("https://example.com/api-secret"));
        assert!(!sc.is_allowed("https://example.com/apifoo"));
    }

    #[test]
    fn check_raw_path_rejects_traversal_under_path_restricted_scope() {
        // Under a path-restricted scope, a raw path that textually starts with
        // the prefix but uses traversal to climb out must be refused.
        let sc = checker(&["http://h:5000/api/*"]);
        assert!(matches!(
            sc.check_raw_path("http://h:5000/api/x", "/api/../admin"),
            Err(ScopeError::NotInScope(_))
        ));
        assert!(matches!(
            sc.check_raw_path("http://h:5000/api/x", "/api/%2e%2e/admin"),
            Err(ScopeError::NotInScope(_))
        ));
        // A clean in-prefix path is still fine.
        assert!(sc.check_raw_path("http://h:5000/api/x", "/api/ok").is_ok());
    }

    #[test]
    fn check_raw_path_allows_traversal_on_host_wide_scope() {
        // The path-normalization-bypass use case: a host-wide scope deliberately
        // permits encoded-dot raw paths (CVE-2021-41773-style testing).
        let sc = checker(&["http://h:5000/*"]);
        assert!(sc
            .check_raw_path("http://h:5000/x", "/cgi-bin/.%2e/.%2e/bin/sh")
            .is_ok());
    }

    #[test]
    fn requires_path_check_true_when_host_wide_allow_has_a_path_deny() {
        // A host-wide allow plus a path-scoped deny must still force per-request
        // -line authorization on the verbatim primitives, or the deny is skipped.
        let sc = checker(&["http://h:5000/*", "!http://h:5000/admin/*"]);
        assert!(sc.requires_path_check("http://h:5000/x"));
        assert!(matches!(
            sc.check_raw_path("http://h:5000/x", "/admin/secret"),
            Err(ScopeError::ExplicitlyDenied(_))
        ));
        assert!(sc.check_raw_path("http://h:5000/x", "/public").is_ok());
    }

    #[test]
    fn full_target_dummy_style_rule_end_to_end() {
        // The exact rule shape from target-dummy/*/molly-config.json.
        let sc = checker(&["http://dashql:5000/*"]);
        assert!(sc.is_allowed("http://dashql:5000/graphql"));
        assert!(!sc.is_allowed("http://evil.com:5000/graphql"));
        assert!(!sc.is_allowed("https://dashql:5000/graphql"));
    }

    // --- Raw-path authorization (verbatim request-line target checks) ---------

    #[test]
    fn check_raw_path_rejects_out_of_prefix_path() {
        // The path-prefix scope-bypass: scope authorizes on the url, but the raw
        // request line must be authorized against the *same* prefix. An
        // in-prefix url with an out-of-prefix raw path must be refused.
        let sc = checker(&["example.com/api/v1/*"]);
        assert!(sc.check("https://example.com/api/v1/x").is_ok());
        assert!(matches!(
            sc.check_raw_path("https://example.com/api/v1/x", "/admin/secret"),
            Err(ScopeError::NotInScope(_))
        ));
    }

    #[test]
    fn check_raw_path_allows_in_prefix_path() {
        let sc = checker(&["example.com/api/v1/*"]);
        assert!(sc
            .check_raw_path("https://example.com/api/v1/x", "/api/v1/users")
            .is_ok());
        // Query/fragment on the raw target don't defeat the prefix check.
        assert!(sc
            .check_raw_path("https://example.com/api/v1/x", "/api/v1/users?q=1")
            .is_ok());
    }

    #[test]
    fn check_raw_path_host_only_scope_allows_any_path() {
        // A host-only rule grants arbitrary paths by design; raw paths too.
        let sc = checker(&["example.com"]);
        assert!(sc
            .check_raw_path("https://example.com/", "/anything/at/all")
            .is_ok());
    }

    #[test]
    fn check_raw_path_catch_all_prefix_allows_any_path() {
        // `/*` (prefix "/") is the common target-dummy shape — no real path
        // restriction, so any `/...` raw path is allowed.
        let sc = checker(&["http://dashql:5000/*"]);
        assert!(sc
            .check_raw_path("http://dashql:5000/graphql", "/admin")
            .is_ok());
    }

    #[test]
    fn check_raw_path_honors_deny_rules() {
        let sc = checker(&["*.example.com", "!*.example.com/internal/*"]);
        assert!(sc
            .check_raw_path("https://api.example.com/public", "/public/ok")
            .is_ok());
        assert!(matches!(
            sc.check_raw_path("https://api.example.com/public", "/internal/secret"),
            Err(ScopeError::ExplicitlyDenied(_))
        ));
    }

    #[test]
    fn requires_path_check_reflects_restriction() {
        // Host-only and `/*` scopes grant arbitrary paths -> no per-path check.
        assert!(!checker(&["example.com"]).requires_path_check("https://example.com/x"));
        assert!(!checker(&["http://h:5000/*"]).requires_path_check("http://h:5000/x"));
        // A genuine path restriction -> callers must check the wire path.
        assert!(checker(&["example.com/api/*"]).requires_path_check("https://example.com/x"));
        // Unknown host -> fail closed.
        assert!(checker(&["example.com/api/*"]).requires_path_check("https://other.com/x"));
    }
}
