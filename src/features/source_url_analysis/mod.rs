pub mod patterns;

use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory};
use regex::Regex;
use std::sync::LazyLock;

static SOURCE_ARRAY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?ms)^source=\((.*?)\)").unwrap()
});

pub struct SourceUrlAnalysis;

impl Feature for SourceUrlAnalysis {
    fn name(&self) -> &str {
        "source_url_analysis"
    }

    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        let Some(ref content) = ctx.pkgbuild_content else {
            return Vec::new();
        };

        // Only match against the source=() array, not comments or other code
        let source_content = match SOURCE_ARRAY_RE.captures(content) {
            Some(caps) => caps[1].to_string(),
            None => return Vec::new(),
        };

        let compiled = patterns::compiled_patterns();
        let mut signals = Vec::new();

        for pat in compiled {
            if pat.regex.is_match(&source_content) {
                signals.push(Signal {
                    id: pat.id.clone(),
                    category: SignalCategory::Pkgbuild,
                    points: pat.points,
                    description: pat.description.clone(),
                    is_override_gate: pat.override_gate,
                });
            }
        }

        signals
    }
}
