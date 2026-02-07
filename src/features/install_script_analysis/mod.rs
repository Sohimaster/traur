pub mod patterns;

use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory};

pub struct InstallScriptAnalysis;

impl Feature for InstallScriptAnalysis {
    fn name(&self) -> &str {
        "install_script_analysis"
    }

    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        let Some(ref content) = ctx.install_script_content else {
            return Vec::new();
        };

        let compiled = patterns::compiled_patterns();
        let mut signals = Vec::new();

        for pat in compiled {
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
