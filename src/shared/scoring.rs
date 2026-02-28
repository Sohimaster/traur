use serde::Serialize;
use crate::shared::rules::{Verdict, Detection};

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

/// Complete result of scanning a package.
#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub package: String,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fired_rule: Option<String>,
    pub detections: Vec<Detection>,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Malicious => write!(f, "MALICIOUS"),
            Verdict::Suspicious => write!(f, "SUSPICIOUS"),
            Verdict::Ok => write!(f, "OK"),
            Verdict::Trusted => write!(f, "TRUSTED"),
        }
    }
}
