use serde::Serialize;

/// Prefix used for signals that describe the scan itself rather than the
/// package. A `Z-` signal is always a `Fact`, so it can never change a tier:
/// "the scan was incomplete" is reported, not scored.
pub const META_SIGNAL_PREFIX: &str = "Z-";

/// A signal emitted by a feature during analysis.
#[derive(Debug, Clone, Serialize)]
pub struct Signal {
    pub id: String,
    pub category: SignalCategory,
    pub role: SignalRole,
    pub points: u32,
    pub description: String,
    pub is_override_gate: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_line: Option<String>,
}

impl Signal {
    /// Build a signal, taking the role from the registry where known.
    pub fn new(id: &str, category: SignalCategory, points: u32) -> Self {
        Signal {
            id: id.to_string(),
            category,
            role: SignalRole::for_signal(id, points),
            points,
            description: String::new(),
            is_override_gate: false,
            matched_line: None,
        }
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    pub fn with_role(mut self, role: SignalRole) -> Self {
        self.role = role;
        self
    }

    pub fn with_line(mut self, line: impl Into<String>) -> Self {
        self.matched_line = Some(line.into());
        self
    }

    pub fn as_gate(mut self) -> Self {
        self.is_override_gate = true;
        self.role = SignalRole::OverrideGate;
        self
    }
}

/// What a signal is evidence *of*.
///
/// This axis is orthogonal to [`SignalCategory`], which keeps the weighted
/// buckets and the `ignored.categories` config working. The distinction it
/// draws is the one that decides false positives:
///
/// - `Fact`: a declaration or an AUR lifecycle convention. Shipping a systemd
///   unit, installing a pacman hook, `SKIP` checksums on a `-bin` package.
///   These are what a package *is*, not what its code *does*. They never add
///   risk; they are shown so the report stays complete.
/// - `Capability`: the code can do something (download, decode, exec).
///   Weighted as before.
/// - `Composition`: linked capabilities inside one region, such as reading
///   `~/.ssh` and sending it out. May gate.
/// - `Provenance`: metadata, git and GitHub facts. Suppressors only.
/// - `OverrideGate`: hard evidence. Forces MALICIOUS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SignalRole {
    Fact,
    Capability,
    Composition,
    Provenance,
    OverrideGate,
}

impl SignalRole {
    /// Role for a signal id as used when the emitting site does not say.
    ///
    /// Overrides on our own classification always force MALICIOUS regardless
    /// of role; the guard below makes that explicit instead of incidental.
    pub fn for_signal(id: &str, points: u32) -> SignalRole {
        if id.starts_with(META_SIGNAL_PREFIX) {
            return SignalRole::Fact;
        }
        match id {
            // Lifecycle and packaging conventions. These describe what the
            // package legitimately does; see PLAN.md N4.2.
            "P-SYSTEMD-CREATE"
            | "P-PACMAN-HOOK"
            | "P-SUID-BIT"
            | "P-SKIP-ALL"
            | "P-WEAK-CHECKSUMS"
            | "P-CHECKSUM-MISMATCH"
            | "T-AUTHOR-CHANGE"
            | "T-DIFF-MAJOR-REWRITE" => SignalRole::Fact,
            // Anything else is a capability. `P-EVAL-VAR` is superseded by
            // `eval_analysis` and kept at zero points, so the role axis (which
            // zeroes zero-point patterns) is where it becomes a fact.
            _ => {
                let _ = points;
                SignalRole::Capability
            }
        }
    }

    /// Whether this role may contribute to the risk score.
    pub fn adds_risk(self) -> bool {
        matches!(
            self,
            SignalRole::Capability | SignalRole::Composition | SignalRole::OverrideGate
        )
    }
}

/// The four weighted signal categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SignalCategory {
    Metadata,
    Pkgbuild,
    Behavioral,
    Temporal,
}

/// Trust tier derived from the final score.
///
/// `Unknown` is not a score and is not ordered with the others: it means the
/// scan could not conclude because inputs were missing (an unreachable AUR, an
/// unreadable PKGBUILD). It must never be rendered as `Suspicious` (the package
/// was not judged) and never as `Trusted` (it was not verified).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Tier {
    Trusted,
    Ok,
    Sketchy,
    Suspicious,
    Malicious,
    #[serde(rename = "Unknown")]
    Unknown,
}

/// Current JSON contract version.
///
/// 2 re-based the score: `Fact` signals no longer add risk (PLAN.md N4.1).
/// `score`, `tier`, `signals[].id` and `override_gate_fired` remain stable for
/// the `makepkg` wrapper and user scripts.
pub const SCHEMA_VERSION: u32 = 2;

/// Whether a scan reached a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    /// The scan completed and the tier is a judgement.
    Complete,
    /// Inputs were missing; `tier` is `Unknown` and `reason` says why.
    Incomplete,
}

/// Complete result of scanning a package.
#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub package: String,
    pub score: u32,
    pub tier: Tier,
    pub signals: Vec<Signal>,
    pub override_gate_fired: Option<String>,
    pub schema_version: u32,
    pub status: ScanStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Category weights for the composite score.
const WEIGHT_METADATA: f64 = 0.15;
const WEIGHT_PKGBUILD: f64 = 0.45;
const WEIGHT_BEHAVIORAL: f64 = 0.25;
const WEIGHT_TEMPORAL: f64 = 0.15;

/// Compute the final score and tier from a list of signals.
pub fn compute_score(package_name: &str, signals: &[Signal]) -> ScanResult {
    compute_score_with_status(package_name, signals, ScanStatus::Complete, None)
}

/// Compute the final score, tier and status from a list of signals.
///
/// An incomplete scan yields `Tier::Unknown`. That guard lives here, at the one
/// place tiers are produced, so no feature or caller can accidentally emit a
/// verdict for a scan that did not finish.
pub fn compute_score_with_status(
    package_name: &str,
    signals: &[Signal],
    status: ScanStatus,
    reason: Option<String>,
) -> ScanResult {
    if status == ScanStatus::Incomplete {
        return ScanResult {
            package: package_name.to_string(),
            // Deliberately 0: an inconclusive scan has no trust value, and a
            // number here would invite sorting or thresholding it.
            score: 0,
            tier: Tier::Unknown,
            signals: signals.to_vec(),
            override_gate_fired: None,
            schema_version: SCHEMA_VERSION,
            status,
            reason,
        };
    }

    let weighted_score = compute_weighted(signals);

    // Find the highest-scoring override gate. Facts never gate, even if a
    // pattern was mistakenly marked as one: the role axis wins.
    let best_override = signals
        .iter()
        .filter(|s| s.is_override_gate && s.role.adds_risk())
        .max_by_key(|s| s.points);

    if let Some(signal) = best_override {
        // Use the higher of the override gate score and the weighted score
        let risk = signal.points.max(weighted_score).min(100);
        return ScanResult {
            package: package_name.to_string(),
            score: 100 - risk,
            tier: Tier::Malicious,
            signals: signals.to_vec(),
            override_gate_fired: Some(signal.id.clone()),
            schema_version: SCHEMA_VERSION,
            status,
            reason,
        };
    }

    let trust = 100 - weighted_score;
    let tier = score_to_tier(trust);

    ScanResult {
        package: package_name.to_string(),
        score: trust,
        tier,
        signals: signals.to_vec(),
        override_gate_fired: None,
        schema_version: SCHEMA_VERSION,
        status,
        reason,
    }
}

/// Compute the weighted composite score from signals (without override gate logic).
///
/// Only roles that `adds_risk()` participate. Facts and provenance are shown in
/// the report but add nothing, which is what keeps normal packaging conventions
/// from dragging a package out of OK.
fn compute_weighted(signals: &[Signal]) -> u32 {
    let mut meta_total: u32 = 0;
    let mut pkgbuild_total: u32 = 0;
    let mut behavioral_total: u32 = 0;
    let mut temporal_total: u32 = 0;

    for signal in signals {
        if !signal.role.adds_risk() {
            continue;
        }
        match signal.category {
            SignalCategory::Metadata => meta_total += signal.points,
            SignalCategory::Pkgbuild => pkgbuild_total += signal.points,
            SignalCategory::Behavioral => behavioral_total += signal.points,
            SignalCategory::Temporal => temporal_total += signal.points,
        }
    }

    meta_total = meta_total.min(100);
    pkgbuild_total = pkgbuild_total.min(100);
    behavioral_total = behavioral_total.min(100);
    temporal_total = temporal_total.min(100);

    let weighted = (WEIGHT_METADATA * meta_total as f64)
        + (WEIGHT_PKGBUILD * pkgbuild_total as f64)
        + (WEIGHT_BEHAVIORAL * behavioral_total as f64)
        + (WEIGHT_TEMPORAL * temporal_total as f64);

    (weighted.round() as u32).min(100)
}

fn score_to_tier(trust: u32) -> Tier {
    match trust {
        0..=20 => Tier::Malicious,
        21..=40 => Tier::Suspicious,
        41..=60 => Tier::Sketchy,
        61..=80 => Tier::Ok,
        _ => Tier::Trusted,
    }
}

/// Parsing tier names, for corpus manifests and config files.
#[allow(dead_code)]
pub struct TierName;

impl TierName {
    /// Parse a tier name case-insensitively. `UNSAFE-TO-CONCLUDE` and
    /// `INCONCLUSIVE` both mean `Unknown`.
    #[allow(dead_code)] // used by corpus manifests and config parsing
    pub fn parse(value: &str) -> Option<Tier> {
        match value.trim().to_ascii_lowercase().as_str() {
            "trusted" => Some(Tier::Trusted),
            "ok" => Some(Tier::Ok),
            "sketchy" => Some(Tier::Sketchy),
            "suspicious" => Some(Tier::Suspicious),
            "malicious" => Some(Tier::Malicious),
            "unknown" | "unsafe-to-conclude" | "inconclusive" => Some(Tier::Unknown),
            // Ordering sentinels for corpus bounds: `min_tier=trusted` means
            // "any tier is acceptable".
            "any" | "none" => Some(Tier::Trusted),
            _ => None,
        }
    }
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Tier::Trusted => write!(f, "TRUSTED"),
            Tier::Ok => write!(f, "OK"),
            Tier::Sketchy => write!(f, "SKETCHY"),
            Tier::Suspicious => write!(f, "SUSPICIOUS"),
            Tier::Malicious => write!(f, "MALICIOUS"),
            Tier::Unknown => write!(f, "UNSAFE-TO-CONCLUDE"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal(id: &str, category: SignalCategory, points: u32, override_gate: bool) -> Signal {
        Signal {
            id: id.to_string(),
            category,
            role: SignalRole::for_signal(id, points),
            points,
            description: String::new(),
            is_override_gate: override_gate,
            matched_line: None,
        }
    }

    #[test]
    fn no_signals_scores_full_trust() {
        let result = compute_score("pkg", &[]);
        assert_eq!(result.score, 100);
        assert_eq!(result.tier, Tier::Trusted);
        assert!(result.override_gate_fired.is_none());
    }

    #[test]
    fn override_gate_picks_highest() {
        let signals = vec![
            signal("P-CURL-PIPE", SignalCategory::Pkgbuild, 90, true),
            signal("P-REVSHELL-DEVTCP", SignalCategory::Pkgbuild, 95, true),
        ];
        let result = compute_score("pkg", &signals);
        assert_eq!(result.tier, Tier::Malicious);
        assert_eq!(result.override_gate_fired.as_deref(), Some("P-REVSHELL-DEVTCP"));
        assert!(result.score <= 5, "Trust {} should be <= 5", result.score);
    }

    #[test]
    fn override_gate_uses_weighted_when_higher() {
        // Override gate (85) + lots of other signals that push weighted above 85
        let signals = vec![
            signal("P-REVSHELL-PYTHON", SignalCategory::Pkgbuild, 85, true),
            signal("P-EVAL-BASE64", SignalCategory::Pkgbuild, 85, false),
            signal("B-NAME-IMPERSONATE", SignalCategory::Behavioral, 65, false),
            signal("M-VOTES-ZERO", SignalCategory::Metadata, 30, false),
            signal("T-MALICIOUS-DIFF", SignalCategory::Temporal, 55, false),
        ];
        let result = compute_score("pkg", &signals);
        assert_eq!(result.tier, Tier::Malicious);
        // Weighted risk: 0.45*100 + 0.25*65 + 0.15*30 + 0.15*55 = 74
        // Override gate risk: 85. Max(85, 74) = 85. Trust = 100 - 85 = 15
        assert!(result.score <= 15, "Trust {} should be <= 15", result.score);
    }

    #[test]
    fn category_caps_at_100() {
        let signals = vec![
            signal("P-A", SignalCategory::Pkgbuild, 80, false),
            signal("P-B", SignalCategory::Pkgbuild, 80, false),
        ];
        let result = compute_score("pkg", &signals);
        // Pkgbuild: min(160, 100) = 100 -> 0.45 * 100 = 45 risk -> 55 trust
        assert_eq!(result.score, 55);
        assert_eq!(result.tier, Tier::Sketchy);
    }

    #[test]
    fn tier_boundaries() {
        assert_eq!(score_to_tier(0), Tier::Malicious);
        assert_eq!(score_to_tier(20), Tier::Malicious);
        assert_eq!(score_to_tier(21), Tier::Suspicious);
        assert_eq!(score_to_tier(40), Tier::Suspicious);
        assert_eq!(score_to_tier(41), Tier::Sketchy);
        assert_eq!(score_to_tier(60), Tier::Sketchy);
        assert_eq!(score_to_tier(61), Tier::Ok);
        assert_eq!(score_to_tier(80), Tier::Ok);
        assert_eq!(score_to_tier(81), Tier::Trusted);
        assert_eq!(score_to_tier(100), Tier::Trusted);
    }

    #[test]
    fn min_trust_is_zero() {
        let signals = vec![
            signal("P", SignalCategory::Pkgbuild, 200, false),
            signal("M", SignalCategory::Metadata, 200, false),
            signal("B", SignalCategory::Behavioral, 200, false),
            signal("T", SignalCategory::Temporal, 200, false),
        ];
        let result = compute_score("pkg", &signals);
        assert_eq!(result.score, 0);
    }
}

#[cfg(test)]
mod role_tests {
    use super::*;

    fn sig(id: &str, points: u32, role: SignalRole) -> Signal {
        Signal {
            id: id.to_string(),
            category: SignalCategory::Pkgbuild,
            role,
            points,
            description: String::new(),
            is_override_gate: false,
            matched_line: None,
        }
    }

    #[test]
    fn lifecycle_facts_do_not_lower_the_score() {
        // llama.cpp-vulkan shape: a shipped .service plus an npm build dep.
        let signals = vec![
            sig("P-SYSTEMD-CREATE", 35, SignalRole::Fact),
            sig("P-PACMAN-HOOK", 25, SignalRole::Fact),
            sig("P-SKIP-ALL", 10, SignalRole::Fact),
            sig("T-AUTHOR-CHANGE", 25, SignalRole::Fact),
        ];
        let result = compute_score("pkg", &signals);
        assert_eq!(result.score, 100);
        assert_eq!(result.tier, Tier::Trusted);
        assert_eq!(result.signals.len(), 4, "facts are still reported");
    }

    #[test]
    fn capabilities_still_score() {
        let signals = vec![sig("P-EVAL-VAR", 50, SignalRole::Capability)];
        let result = compute_score("pkg", &signals);
        // 0.45 * 50 = 22.5 -> 23 risk
        assert_eq!(result.score, 77);
        assert_eq!(result.tier, Tier::Ok);
    }

    #[test]
    fn facts_never_gate_even_if_marked_as_gate() {
        let mut s = sig("P-SYSTEMD-CREATE", 95, SignalRole::Fact);
        s.is_override_gate = true;
        let result = compute_score("pkg", &[s]);
        assert_eq!(result.tier, Tier::Trusted);
        assert!(result.override_gate_fired.is_none());
    }

    #[test]
    fn provenance_only_suppresses() {
        let signals = vec![
            sig("B-TYPOSQUAT", 55, SignalRole::Provenance),
            sig("M-VOTES-ZERO", 30, SignalRole::Provenance),
        ];
        let result = compute_score("pkg", &signals);
        assert_eq!(result.score, 100);
        assert_eq!(result.tier, Tier::Trusted);
    }

    #[test]
    fn meta_signals_are_facts() {
        assert_eq!(
            SignalRole::for_signal("Z-NETWORK-FAILED", 50),
            SignalRole::Fact
        );
        let result = compute_score("pkg", &[sig("Z-NETWORK-FAILED", 50, SignalRole::Fact)]);
        assert_eq!(result.tier, Tier::Trusted);
    }

    #[test]
    fn incomplete_scan_is_unknown_not_suspicious_and_not_trusted() {
        let result = compute_score_with_status(
            "pkg",
            &[sig("P-CURL-PIPE", 90, SignalRole::OverrideGate)],
            ScanStatus::Incomplete,
            Some("AUR unreachable".into()),
        );
        assert_eq!(result.tier, Tier::Unknown);
        assert_ne!(result.tier, Tier::Suspicious);
        assert_ne!(result.tier, Tier::Trusted);
        assert!(result.override_gate_fired.is_none());
        assert_eq!(result.status, ScanStatus::Incomplete);
        assert_eq!(result.reason.as_deref(), Some("AUR unreachable"));
    }

    #[test]
    fn complete_scan_carries_schema_version() {
        let result = compute_score("pkg", &[]);
        assert_eq!(result.schema_version, SCHEMA_VERSION);
        assert_eq!(result.status, ScanStatus::Complete);
        assert_eq!(result.reason, None);
    }

    #[test]
    fn unknown_tier_has_a_non_alarming_label() {
        assert_eq!(Tier::Unknown.to_string(), "UNSAFE-TO-CONCLUDE");
    }

    #[test]
    fn json_contract_keeps_the_documented_keys() {
        let result = compute_score("pkg", &[]);
        let json = serde_json::to_value(&result).unwrap();
        for key in [
            "package",
            "score",
            "tier",
            "signals",
            "override_gate_fired",
            "schema_version",
            "status",
        ] {
            assert!(json.get(key).is_some(), "missing {key}");
        }
        assert_eq!(json["schema_version"], SCHEMA_VERSION);
        assert_eq!(json["status"], "complete");
    }

    #[test]
    fn unknown_serializes_in_camel_form() {
        let result = compute_score_with_status(
            "pkg",
            &[],
            ScanStatus::Incomplete,
            Some("x".into()),
        );
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["tier"], "Unknown");
        assert_eq!(json["status"], "incomplete");
    }
}
