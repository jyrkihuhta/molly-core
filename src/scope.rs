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
        let path = url.path();

        // Check deny rules first — they override everything
        for rule in &self.rules {
            if rule.deny && Self::matches_rule(rule, &scheme, &host, path) {
                return Err(ScopeError::ExplicitlyDenied(url_str.to_string()));
            }
        }

        // Check allow rules
        for rule in &self.rules {
            if !rule.deny && Self::matches_rule(rule, &scheme, &host, path) {
                return Ok(());
            }
        }

        Err(ScopeError::NotInScope(url_str.to_string()))
    }

    /// Returns true if the URL is in scope, false otherwise.
    pub fn is_allowed(&self, url_str: &str) -> bool {
        self.check(url_str).is_ok()
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

        // Strip an explicit port (e.g. `notekeeper:5000` -> `notekeeper`).
        // Matching is host-only (see matches_rule), mirroring how
        // Url::host_str() never includes the port either — a rule with a
        // port left in place could never match any real request URL.
        let domain = match domain_and_port.rsplit_once(':') {
            Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
                host.to_string()
            }
            _ => domain_and_port,
        };

        ScopeRule {
            deny,
            domain,
            path_prefix,
            schemes: vec![scheme.to_string()],
        }
    }

    fn matches_rule(rule: &ScopeRule, scheme: &str, host: &str, path: &str) -> bool {
        // Scheme check
        if !rule.schemes.iter().any(|s| s == scheme) {
            return false;
        }

        // Domain check
        if rule.domain.starts_with("*.") {
            let parent = &rule.domain[2..]; // strip "*."
            // Must be a subdomain — "foo.example.com" matches "*.example.com"
            // but "example.com" does NOT match "*.example.com"
            // Wildcard requires a subdomain — apex must NOT match
            if !host.ends_with(&format!(".{parent}")) {
                return false;
            }
        } else if host != rule.domain {
            return false;
        }

        // Path prefix check (if specified)
        if let Some(ref prefix) = rule.path_prefix {
            if !path.starts_with(prefix.as_str()) {
                return false;
            }
        }

        true
    }
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
    fn port_in_rule_is_stripped_for_matching() {
        // Url::host_str() never includes the port, so a rule that keeps one
        // could never match any real request — this is exactly the format
        // every target-dummy config actually uses.
        let sc = checker(&["http://notekeeper:5000/*"]);
        assert!(sc.is_allowed("http://notekeeper:5000/api/notes"));
    }

    #[test]
    fn full_target_dummy_style_rule_end_to_end() {
        // The exact rule shape from target-dummy/*/molly-config.json.
        let sc = checker(&["http://dashql:5000/*"]);
        assert!(sc.is_allowed("http://dashql:5000/graphql"));
        assert!(!sc.is_allowed("http://evil.com:5000/graphql"));
        assert!(!sc.is_allowed("https://dashql:5000/graphql"));
    }
}
