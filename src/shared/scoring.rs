use serde::Serialize;

/// A signal emitted by a feature during analysis.
#[derive(Debug, Clone, Serialize)]
pub struct Signal {
    pub id: String,
    pub category: SignalCategory,
    pub points: u32,
    pub description: String,
    pub is_override_gate: bool,
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
    // Check override gates first — they bypass weighted scoring
    for signal in signals {
        if signal.is_override_gate {
            return ScanResult {
                package: package_name.to_string(),
                score: signal.points.min(100),
                tier: Tier::Malicious,
                signals: signals.to_vec(),
                override_gate_fired: Some(signal.id.clone()),
            };
        }
    }

    // Aggregate points per category (capped at 100 each)
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

    let score = (weighted.round() as u32).min(100);
    let tier = score_to_tier(score);

    ScanResult {
        package: package_name.to_string(),
        score,
        tier,
        signals: signals.to_vec(),
        override_gate_fired: None,
    }
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
