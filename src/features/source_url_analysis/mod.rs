use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::patterns::load_patterns;
use crate::shared::scoring::{Signal, SignalCategory};

pub struct SourceUrlAnalysis;

impl Feature for SourceUrlAnalysis {
    fn name(&self) -> &str {
        "source_url_analysis"
    }

    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        let Some(ref content) = ctx.pkgbuild_content else {
            return Vec::new();
        };

        let compiled = load_patterns("source_url_analysis");
        let mut signals = Vec::new();

        for pat in &compiled {
            if pat.regex.is_match(content) {
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
