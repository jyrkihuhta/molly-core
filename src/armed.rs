//! Per-target armed state — the hard safety gate.
//!
//! Every target starts UNARMED. Only the operator (via API) can arm a target.
//! The LLM cannot change armed state. Rust enforces this — Python cannot bypass it.
//!
//! States:
//! - `Unarmed` — Molly can plan but no outbound requests leave the box
//! - `Armed` — free fire within scope rules
//! - `Paused` — temporarily halted, can resume to Armed without re-confirming scope
//!
//! An armed/paused target may carry an `expires_at` (RFC3339, bounded-campaign
//! TTL — the fleet optimizer needs this to safely automate the
//! arm/disarm cycle without a human or a cron job remembering to revert it).
//! Expiry is computed LAZILY on every read (`check`/`get`/`all`) — the actual
//! safety guarantee never depends on a background sweep having already run.
//! `sweep_expired` exists purely to keep the persisted JSON file and any
//! direct-file reader honest over time.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// One target's armed state plus its optional bounded-campaign expiry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmedEntry {
    pub level: ArmedLevel,
    /// RFC3339 timestamp (matches audit.rs's own `Utc::now().to_rfc3339()`
    /// convention — this codebase stores timestamps as plain strings, not
    /// typed `DateTime<Utc>` fields). `None` = never expires (today's
    /// original, still-default behavior).
    #[serde(default)]
    pub expires_at: Option<String>,
}

impl ArmedEntry {
    fn unarmed() -> Self {
        ArmedEntry {
            level: ArmedLevel::Unarmed,
            expires_at: None,
        }
    }

    /// True once `expires_at` has passed. A malformed timestamp is treated
    /// as ALREADY expired — this is a safety gate, so an unparseable expiry
    /// must never be silently read as "armed forever."
    fn is_expired(&self) -> bool {
        match &self.expires_at {
            None => false,
            Some(ts) => match chrono::DateTime::parse_from_rfc3339(ts) {
                Ok(dt) => chrono::Utc::now() >= dt.with_timezone(&chrono::Utc),
                Err(_) => true,
            },
        }
    }

    /// The level this entry should be treated as RIGHT NOW, accounting for
    /// expiry — computed on every call, not cached.
    fn effective_level(&self) -> ArmedLevel {
        if self.level != ArmedLevel::Unarmed && self.is_expired() {
            ArmedLevel::Unarmed
        } else {
            self.level
        }
    }
}

/// Back-compat deserialization: an armed-state.json written before the TTL
/// feature has bare-string values (`{"handle": "armed"}`); a new one has
/// `{"handle": {"level": "armed", "expires_at": "..."}}`. `save()` always
/// writes the new shape, so a file upgrades in place the next time anything
/// is armed/disarmed (which already rewrites the whole file today).
#[derive(Deserialize)]
#[serde(untagged)]
enum ArmedEntryRaw {
    Legacy(String),
    Full(ArmedEntry),
}

impl From<ArmedEntryRaw> for ArmedEntry {
    fn from(raw: ArmedEntryRaw) -> Self {
        match raw {
            ArmedEntryRaw::Legacy(s) => ArmedEntry {
                level: ArmedLevel::from_str(&s).unwrap_or(ArmedLevel::Unarmed),
                expires_at: None,
            },
            ArmedEntryRaw::Full(entry) => entry,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArmedLevel {
    Unarmed,
    Armed,
    Paused,
}

impl std::fmt::Display for ArmedLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArmedLevel::Unarmed => write!(f, "unarmed"),
            ArmedLevel::Armed => write!(f, "armed"),
            ArmedLevel::Paused => write!(f, "paused"),
        }
    }
}

impl ArmedLevel {
    // Inherent `from_str` is kept (fallible, domain-specific error) rather than
    // the `FromStr` trait to avoid churning the public API.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, ArmedError> {
        match s.to_lowercase().as_str() {
            "unarmed" => Ok(ArmedLevel::Unarmed),
            "armed" => Ok(ArmedLevel::Armed),
            "paused" => Ok(ArmedLevel::Paused),
            _ => Err(ArmedError::InvalidState(s.to_string())),
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum ArmedError {
    /// Target is not armed — no outbound requests allowed.
    Unarmed(String),
    /// Target is paused — temporarily halted.
    Paused(String),
    /// Target not found in the armed state map.
    UnknownTarget(String),
    /// Invalid state string.
    InvalidState(String),
    /// IO error during load/save.
    Io(String),
}

impl std::fmt::Display for ArmedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArmedError::Unarmed(t) => write!(f, "Target '{t}' is UNARMED — no requests allowed"),
            ArmedError::Paused(t) => write!(f, "Target '{t}' is PAUSED — requests halted"),
            ArmedError::UnknownTarget(t) => write!(f, "Unknown target: '{t}'"),
            ArmedError::InvalidState(s) => {
                write!(f, "Invalid armed state '{s}' — use armed/unarmed/paused")
            }
            ArmedError::Io(msg) => write!(f, "Armed state IO error: {msg}"),
        }
    }
}

impl std::error::Error for ArmedError {}

/// Per-target armed state manager.
#[derive(Debug)]
pub struct ArmedState {
    targets: HashMap<String, ArmedEntry>,
}

impl ArmedState {
    /// Create a new armed state with all known targets set to UNARMED.
    pub fn new(target_handles: &[String]) -> Self {
        let targets = target_handles
            .iter()
            .map(|h| (h.clone(), ArmedEntry::unarmed()))
            .collect();
        ArmedState { targets }
    }

    /// Check if a target is armed. Returns Ok(()) only if ARMED (expiry-aware —
    /// an armed target past its expires_at is treated as UNARMED here).
    pub fn check(&self, target: &str) -> Result<(), ArmedError> {
        let entry = self
            .targets
            .get(target)
            .ok_or_else(|| ArmedError::UnknownTarget(target.to_string()))?;
        match entry.effective_level() {
            ArmedLevel::Armed => Ok(()),
            ArmedLevel::Unarmed => Err(ArmedError::Unarmed(target.to_string())),
            ArmedLevel::Paused => Err(ArmedError::Paused(target.to_string())),
        }
    }

    /// Get the current (expiry-aware) armed level for a target.
    pub fn get(&self, target: &str) -> Result<ArmedLevel, ArmedError> {
        self.targets
            .get(target)
            .map(|e| e.effective_level())
            .ok_or_else(|| ArmedError::UnknownTarget(target.to_string()))
    }

    /// Get the expiry timestamp for a target's current state — `None` if it
    /// never expires, or if it already has (no point reporting a past time
    /// as if it still applied).
    pub fn get_expiry(&self, target: &str) -> Result<Option<String>, ArmedError> {
        self.targets
            .get(target)
            .map(|e| {
                if e.is_expired() {
                    None
                } else {
                    e.expires_at.clone()
                }
            })
            .ok_or_else(|| ArmedError::UnknownTarget(target.to_string()))
    }

    /// Set the armed level for a target, optionally bounded by an RFC3339
    /// expiry (bounded-campaign TTL) — `None` means "no expiry," matching
    /// today's original always-on-until-disarmed behavior.
    pub fn set(
        &mut self,
        target: &str,
        level: ArmedLevel,
        expires_at: Option<String>,
    ) -> Result<(), ArmedError> {
        match self.targets.get_mut(target) {
            Some(current) => {
                current.level = level;
                current.expires_at = expires_at;
                Ok(())
            }
            None => Err(ArmedError::UnknownTarget(target.to_string())),
        }
    }

    /// Get all targets and their CURRENT (expiry-aware) armed levels.
    pub fn all(&self) -> HashMap<String, ArmedLevel> {
        self.targets
            .iter()
            .map(|(k, v)| (k.clone(), v.effective_level()))
            .collect()
    }

    /// Flip any expired entries to UNARMED in the STORED state and clear
    /// their expiry. Returns the handles that were just auto-disarmed.
    /// Purely for persistence/observability tidiness — `check`/`get`/`all`
    /// already compute expiry lazily on every read, so this is never
    /// required for the actual safety guarantee.
    pub fn sweep_expired(&mut self) -> Vec<String> {
        let mut expired = Vec::new();
        for (handle, entry) in self.targets.iter_mut() {
            if entry.level != ArmedLevel::Unarmed && entry.is_expired() {
                entry.level = ArmedLevel::Unarmed;
                entry.expires_at = None;
                expired.push(handle.clone());
            }
        }
        expired
    }

    /// Load armed state from a JSON file. Only updates targets that exist in the map.
    /// Missing file is not an error — all targets stay UNARMED. Accepts both
    /// the legacy bare-string format and the new {level, expires_at} object.
    pub fn load(&mut self, path: &Path) -> Result<(), ArmedError> {
        if !path.exists() {
            return Ok(());
        }
        let data = std::fs::read_to_string(path).map_err(|e| ArmedError::Io(e.to_string()))?;
        let saved: HashMap<String, ArmedEntryRaw> =
            serde_json::from_str(&data).map_err(|e| ArmedError::Io(e.to_string()))?;

        for (handle, raw) in saved {
            if let Some(current) = self.targets.get_mut(&handle) {
                *current = raw.into();
            }
        }
        Ok(())
    }

    /// Save armed state to a JSON file. Always writes the current
    /// {level, expires_at} object shape — a legacy file upgrades in place
    /// the next time anything here changes.
    pub fn save(&self, path: &Path) -> Result<(), ArmedError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ArmedError::Io(e.to_string()))?;
        }
        let data = serde_json::to_string_pretty(&self.targets)
            .map_err(|e| ArmedError::Io(e.to_string()))?;
        std::fs::write(path, data).map_err(|e| ArmedError::Io(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn targets() -> Vec<String> {
        vec!["linkedin".into(), "cloudflare".into(), "wordpress".into()]
    }

    #[test]
    fn new_starts_unarmed() {
        let state = ArmedState::new(&targets());
        assert_eq!(state.get("linkedin").unwrap(), ArmedLevel::Unarmed);
        assert_eq!(state.get("cloudflare").unwrap(), ArmedLevel::Unarmed);
    }

    #[test]
    fn check_rejects_unarmed() {
        let state = ArmedState::new(&targets());
        let err = state.check("linkedin").unwrap_err();
        assert!(matches!(err, ArmedError::Unarmed(_)));
    }

    #[test]
    fn check_passes_armed() {
        let mut state = ArmedState::new(&targets());
        state.set("linkedin", ArmedLevel::Armed, None).unwrap();
        assert!(state.check("linkedin").is_ok());
    }

    #[test]
    fn check_rejects_paused() {
        let mut state = ArmedState::new(&targets());
        state.set("linkedin", ArmedLevel::Armed, None).unwrap();
        state.set("linkedin", ArmedLevel::Paused, None).unwrap();
        let err = state.check("linkedin").unwrap_err();
        assert!(matches!(err, ArmedError::Paused(_)));
    }

    #[test]
    fn unknown_target_rejected() {
        let state = ArmedState::new(&targets());
        let err = state.check("nonexistent").unwrap_err();
        assert!(matches!(err, ArmedError::UnknownTarget(_)));
    }

    #[test]
    fn set_unknown_target_rejected() {
        let mut state = ArmedState::new(&targets());
        let err = state
            .set("nonexistent", ArmedLevel::Armed, None)
            .unwrap_err();
        assert!(matches!(err, ArmedError::UnknownTarget(_)));
    }

    #[test]
    fn state_transitions() {
        let mut state = ArmedState::new(&targets());
        // unarmed -> armed
        state.set("linkedin", ArmedLevel::Armed, None).unwrap();
        assert_eq!(state.get("linkedin").unwrap(), ArmedLevel::Armed);
        // armed -> paused
        state.set("linkedin", ArmedLevel::Paused, None).unwrap();
        assert_eq!(state.get("linkedin").unwrap(), ArmedLevel::Paused);
        // paused -> armed (resume)
        state.set("linkedin", ArmedLevel::Armed, None).unwrap();
        assert_eq!(state.get("linkedin").unwrap(), ArmedLevel::Armed);
        // armed -> unarmed
        state.set("linkedin", ArmedLevel::Unarmed, None).unwrap();
        assert_eq!(state.get("linkedin").unwrap(), ArmedLevel::Unarmed);
    }

    #[test]
    fn persistence_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("armed-state.json");

        let mut state = ArmedState::new(&targets());
        state.set("linkedin", ArmedLevel::Armed, None).unwrap();
        state.set("cloudflare", ArmedLevel::Paused, None).unwrap();
        state.save(&path).unwrap();

        let mut loaded = ArmedState::new(&targets());
        loaded.load(&path).unwrap();
        assert_eq!(loaded.get("linkedin").unwrap(), ArmedLevel::Armed);
        assert_eq!(loaded.get("cloudflare").unwrap(), ArmedLevel::Paused);
        assert_eq!(loaded.get("wordpress").unwrap(), ArmedLevel::Unarmed);
    }

    #[test]
    fn load_missing_file_is_ok() {
        let mut state = ArmedState::new(&targets());
        let result = state.load(Path::new("/nonexistent/armed-state.json"));
        assert!(result.is_ok());
        assert_eq!(state.get("linkedin").unwrap(), ArmedLevel::Unarmed);
    }

    #[test]
    fn load_ignores_unknown_targets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("armed-state.json");

        // Write a file with a target we don't know about
        let mut f = std::fs::File::create(&path).unwrap();
        write!(f, r#"{{"unknown_target": "armed", "linkedin": "armed"}}"#).unwrap();

        let mut state = ArmedState::new(&targets());
        state.load(&path).unwrap();
        assert_eq!(state.get("linkedin").unwrap(), ArmedLevel::Armed);
        // unknown_target is silently ignored
    }

    #[test]
    fn armed_level_from_str() {
        assert_eq!(ArmedLevel::from_str("armed").unwrap(), ArmedLevel::Armed);
        assert_eq!(
            ArmedLevel::from_str("UNARMED").unwrap(),
            ArmedLevel::Unarmed
        );
        assert_eq!(ArmedLevel::from_str("Paused").unwrap(), ArmedLevel::Paused);
        assert!(ArmedLevel::from_str("invalid").is_err());
    }

    #[test]
    fn display() {
        assert_eq!(ArmedLevel::Unarmed.to_string(), "unarmed");
        assert_eq!(ArmedLevel::Armed.to_string(), "armed");
        assert_eq!(ArmedLevel::Paused.to_string(), "paused");
    }

    // --- Bounded-campaign TTL (the fleet optimizer) ---

    fn future_ts(secs: i64) -> String {
        (chrono::Utc::now() + chrono::Duration::seconds(secs)).to_rfc3339()
    }

    fn past_ts(secs: i64) -> String {
        (chrono::Utc::now() - chrono::Duration::seconds(secs)).to_rfc3339()
    }

    #[test]
    fn armed_with_future_expiry_still_checks_and_gets_as_armed() {
        let mut state = ArmedState::new(&targets());
        state
            .set("linkedin", ArmedLevel::Armed, Some(future_ts(3600)))
            .unwrap();
        assert!(state.check("linkedin").is_ok());
        assert_eq!(state.get("linkedin").unwrap(), ArmedLevel::Armed);
        assert_eq!(state.all().get("linkedin").unwrap(), &ArmedLevel::Armed);
    }

    #[test]
    fn armed_with_past_expiry_reads_as_unarmed_via_check() {
        let mut state = ArmedState::new(&targets());
        state
            .set("linkedin", ArmedLevel::Armed, Some(past_ts(1)))
            .unwrap();
        let err = state.check("linkedin").unwrap_err();
        assert!(matches!(err, ArmedError::Unarmed(_)));
    }

    #[test]
    fn armed_with_past_expiry_reads_as_unarmed_via_get() {
        let mut state = ArmedState::new(&targets());
        state
            .set("linkedin", ArmedLevel::Armed, Some(past_ts(1)))
            .unwrap();
        assert_eq!(state.get("linkedin").unwrap(), ArmedLevel::Unarmed);
    }

    #[test]
    fn armed_with_past_expiry_reads_as_unarmed_via_all() {
        let mut state = ArmedState::new(&targets());
        state
            .set("linkedin", ArmedLevel::Armed, Some(past_ts(1)))
            .unwrap();
        assert_eq!(state.all().get("linkedin").unwrap(), &ArmedLevel::Unarmed);
    }

    #[test]
    fn paused_with_past_expiry_reads_as_unarmed() {
        let mut state = ArmedState::new(&targets());
        state
            .set("linkedin", ArmedLevel::Paused, Some(past_ts(1)))
            .unwrap();
        assert_eq!(state.get("linkedin").unwrap(), ArmedLevel::Unarmed);
    }

    #[test]
    fn malformed_expiry_fails_closed_as_expired() {
        // A safety gate must never silently treat an unparseable expiry as
        // "armed forever."
        let mut state = ArmedState::new(&targets());
        state
            .set(
                "linkedin",
                ArmedLevel::Armed,
                Some("not-a-timestamp".to_string()),
            )
            .unwrap();
        assert_eq!(state.get("linkedin").unwrap(), ArmedLevel::Unarmed);
    }

    #[test]
    fn no_expiry_means_armed_forever() {
        let mut state = ArmedState::new(&targets());
        state.set("linkedin", ArmedLevel::Armed, None).unwrap();
        assert_eq!(state.get("linkedin").unwrap(), ArmedLevel::Armed);
        assert!(state.check("linkedin").is_ok());
    }

    #[test]
    fn get_expiry_returns_the_stored_timestamp() {
        let mut state = ArmedState::new(&targets());
        let ts = future_ts(3600);
        state
            .set("linkedin", ArmedLevel::Armed, Some(ts.clone()))
            .unwrap();
        assert_eq!(state.get_expiry("linkedin").unwrap(), Some(ts));
    }

    #[test]
    fn get_expiry_returns_none_once_past() {
        let mut state = ArmedState::new(&targets());
        state
            .set("linkedin", ArmedLevel::Armed, Some(past_ts(1)))
            .unwrap();
        assert_eq!(state.get_expiry("linkedin").unwrap(), None);
    }

    #[test]
    fn get_expiry_returns_none_when_never_set() {
        let mut state = ArmedState::new(&targets());
        state.set("linkedin", ArmedLevel::Armed, None).unwrap();
        assert_eq!(state.get_expiry("linkedin").unwrap(), None);
    }

    #[test]
    fn sweep_expired_flips_stored_state_and_returns_handles() {
        let mut state = ArmedState::new(&targets());
        state
            .set("linkedin", ArmedLevel::Armed, Some(past_ts(1)))
            .unwrap();
        state
            .set("cloudflare", ArmedLevel::Armed, Some(future_ts(3600)))
            .unwrap();

        let swept = state.sweep_expired();
        assert_eq!(swept, vec!["linkedin".to_string()]);
        // Second call: nothing left to sweep.
        assert!(state.sweep_expired().is_empty());
        // Stored state itself is now Unarmed, not just the computed read.
        assert_eq!(state.all().get("linkedin").unwrap(), &ArmedLevel::Unarmed);
        assert_eq!(state.all().get("cloudflare").unwrap(), &ArmedLevel::Armed);
    }

    #[test]
    fn sweep_expired_ignores_already_unarmed_targets() {
        let mut state = ArmedState::new(&targets());
        assert!(state.sweep_expired().is_empty());
    }

    #[test]
    fn persistence_round_trip_preserves_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("armed-state.json");
        let ts = future_ts(3600);

        let mut state = ArmedState::new(&targets());
        state
            .set("linkedin", ArmedLevel::Armed, Some(ts.clone()))
            .unwrap();
        state.save(&path).unwrap();

        let mut loaded = ArmedState::new(&targets());
        loaded.load(&path).unwrap();
        assert_eq!(loaded.get("linkedin").unwrap(), ArmedLevel::Armed);
        assert_eq!(loaded.get_expiry("linkedin").unwrap(), Some(ts));
    }

    #[test]
    fn load_legacy_bare_string_format_still_works() {
        // Pre-TTL armed-state.json shape: {"handle": "armed"} — must still
        // load, and be treated as "armed forever" (no expiry), matching the
        // original behavior for every existing persisted file.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("armed-state.json");
        std::fs::write(&path, r#"{"linkedin": "armed", "cloudflare": "paused"}"#).unwrap();

        let mut state = ArmedState::new(&targets());
        state.load(&path).unwrap();
        assert_eq!(state.get("linkedin").unwrap(), ArmedLevel::Armed);
        assert_eq!(state.get_expiry("linkedin").unwrap(), None);
        assert_eq!(state.get("cloudflare").unwrap(), ArmedLevel::Paused);
        assert!(state.check("linkedin").is_ok()); // no expiry -> never lapses
    }

    #[test]
    fn save_writes_the_new_object_shape() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("armed-state.json");

        let mut state = ArmedState::new(&targets());
        state.set("linkedin", ArmedLevel::Armed, None).unwrap();
        state.save(&path).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert!(
            parsed["linkedin"].is_object(),
            "expected an object, got: {raw}"
        );
        assert_eq!(parsed["linkedin"]["level"], "armed");
        assert!(parsed["linkedin"]["expires_at"].is_null());
    }
}
