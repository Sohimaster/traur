use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;

/// A single pattern rule loaded from patterns.toml.
#[derive(Debug, Deserialize)]
pub struct PatternRule {
    pub id: String,
    pub pattern: String,
    pub points: u32,
    pub description: String,
    #[serde(default)]
    pub override_gate: bool,
    #[serde(default)]
    pub is_critical: bool,
}

/// Collection of pattern rules keyed by feature name.
#[derive(Debug, Deserialize)]
pub struct PatternDatabase {
    #[serde(flatten)]
    pub sections: HashMap<String, Vec<PatternRule>>,
}

/// A compiled pattern ready for matching.
pub struct CompiledPattern {
    pub id: String,
    pub regex: Regex,
    pub points: u32,
    pub description: String,
    pub override_gate: bool,
    pub is_critical: bool,
}

/// Load and compile patterns for a given section from the database.
pub fn load_patterns(section: &str) -> Vec<CompiledPattern> {
    let toml_str = include_str!("../../data/patterns.toml");
    let db: PatternDatabase =
        toml::from_str(toml_str).expect("Failed to parse patterns.toml");

    let Some(rules) = db.sections.get(section) else {
        return Vec::new();
    };

    rules
        .iter()
        .filter_map(|rule| {
            let regex = Regex::new(&rule.pattern).ok()?;
            Some(CompiledPattern {
                id: rule.id.clone(),
                regex,
                points: rule.points,
                description: rule.description.clone(),
                override_gate: rule.override_gate,
                is_critical: rule.is_critical,
            })
        })
        .collect()
}

/// Load high-severity patterns (points >= 60) from pkgbuild_analysis for diff detection.
/// Intended for coordinator use when computing has_new_malicious_diff.
pub fn load_high_severity_diff_patterns() -> Vec<CompiledPattern> {
    load_patterns("pkgbuild_analysis")
        .into_iter()
        .filter(|p| p.points >= 60)
        .collect()
}
