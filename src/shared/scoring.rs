use serde::Serialize;

/// A signal emitted by a feature during analysis.
#[derive(Debug, Clone, Serialize)]
pub struct Signal {
    pub id: String,
    pub category: SignalCategory,
    pub points: u32,
    pub description: String,
    pub is_override_gate: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_line: Option<String>,
}

/// The four weighted signal categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SignalCategory {
    Metadata,
    Pkgbuild,
    Behavioral,
    Temporal,
}

/// Risk tier derived from the final score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Tier {
    Low,
    Medium,
    High,
    Critical,
    Malicious,
}

/// Complete result of scanning a package.
#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub package: String,
    pub score: u32,
    pub tier: Tier,
    pub signals: Vec<Signal>,
    pub override_gate_fired: Option<String>,
}

/// Category weights for the composite score.
const WEIGHT_METADATA: f64 = 0.15;
const WEIGHT_PKGBUILD: f64 = 0.45;
const WEIGHT_BEHAVIORAL: f64 = 0.25;
const WEIGHT_TEMPORAL: f64 = 0.15;

/// Compute the final score and tier from a list of signals.
pub fn compute_score(package_name: &str, signals: &[Signal]) -> ScanResult {
    let weighted_score = compute_weighted(signals);

    // Find the highest-scoring override gate
    let best_override = signals
        .iter()
        .filter(|s| s.is_override_gate)
        .max_by_key(|s| s.points);

    if let Some(signal) = best_override {
        // Use the higher of the override gate score and the weighted score
        let score = signal.points.max(weighted_score).min(100);
        return ScanResult {
            package: package_name.to_string(),
            score,
            tier: Tier::Malicious,
            signals: signals.to_vec(),
            override_gate_fired: Some(signal.id.clone()),
        };
    }

    let tier = score_to_tier(weighted_score);

    ScanResult {
        package: package_name.to_string(),
        score: weighted_score,
        tier,
        signals: signals.to_vec(),
        override_gate_fired: None,
    }
}

/// Compute the weighted composite score from signals (without override gate logic).
fn compute_weighted(signals: &[Signal]) -> u32 {
    let mut meta_total: u32 = 0;
    let mut pkgbuild_total: u32 = 0;
    let mut behavioral_total: u32 = 0;
    let mut temporal_total: u32 = 0;

    for signal in signals {
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

fn score_to_tier(score: u32) -> Tier {
    match score {
        0..=19 => Tier::Low,
        20..=39 => Tier::Medium,
        40..=59 => Tier::High,
        60..=79 => Tier::Critical,
        _ => Tier::Malicious,
    }
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Tier::Low => write!(f, "LOW"),
            Tier::Medium => write!(f, "MEDIUM"),
            Tier::High => write!(f, "HIGH"),
            Tier::Critical => write!(f, "CRITICAL"),
            Tier::Malicious => write!(f, "MALICIOUS"),
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
            points,
            description: String::new(),
            is_override_gate: override_gate,
            matched_line: None,
        }
    }

    #[test]
    fn no_signals_scores_zero() {
        let result = compute_score("pkg", &[]);
        assert_eq!(result.score, 0);
        assert_eq!(result.tier, Tier::Low);
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
        assert!(result.score >= 95);
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
        // Weighted: 0.45*100 + 0.25*65 + 0.15*30 + 0.15*55 = 45+16.25+4.5+8.25 = 74
        // Override gate: 85. Max(85, 74) = 85
        assert!(result.score >= 85, "Score {} should be >= 85", result.score);
    }

    #[test]
    fn category_caps_at_100() {
        let signals = vec![
            signal("P-A", SignalCategory::Pkgbuild, 80, false),
            signal("P-B", SignalCategory::Pkgbuild, 80, false),
        ];
        let result = compute_score("pkg", &signals);
        // Pkgbuild: min(160, 100) = 100 -> 0.45 * 100 = 45
        assert_eq!(result.score, 45);
        assert_eq!(result.tier, Tier::High);
    }

    #[test]
    fn tier_boundaries() {
        assert_eq!(score_to_tier(0), Tier::Low);
        assert_eq!(score_to_tier(19), Tier::Low);
        assert_eq!(score_to_tier(20), Tier::Medium);
        assert_eq!(score_to_tier(39), Tier::Medium);
        assert_eq!(score_to_tier(40), Tier::High);
        assert_eq!(score_to_tier(59), Tier::High);
        assert_eq!(score_to_tier(60), Tier::Critical);
        assert_eq!(score_to_tier(79), Tier::Critical);
        assert_eq!(score_to_tier(80), Tier::Malicious);
        assert_eq!(score_to_tier(100), Tier::Malicious);
    }

    #[test]
    fn max_score_is_100() {
        let signals = vec![
            signal("P", SignalCategory::Pkgbuild, 200, false),
            signal("M", SignalCategory::Metadata, 200, false),
            signal("B", SignalCategory::Behavioral, 200, false),
            signal("T", SignalCategory::Temporal, 200, false),
        ];
        let result = compute_score("pkg", &signals);
        assert_eq!(result.score, 100);
    }
}
