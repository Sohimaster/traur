use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory};

pub struct MetadataAnalysis;

impl Feature for MetadataAnalysis {
    fn name(&self) -> &str {
        "metadata_analysis"
    }

    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        let Some(ref meta) = ctx.metadata else {
            return Vec::new();
        };

        let mut signals = Vec::new();

        // Vote signals
        if meta.num_votes == 0 {
            signals.push(Signal {
                id: "M-VOTES-ZERO".to_string(),
                category: SignalCategory::Metadata,
                points: 30,
                description: "Package has zero votes".to_string(),
                is_override_gate: false,
            });
        } else if meta.num_votes < 5 {
            signals.push(Signal {
                id: "M-VOTES-LOW".to_string(),
                category: SignalCategory::Metadata,
                points: 20,
                description: format!("Package has very few votes ({})", meta.num_votes),
                is_override_gate: false,
            });
        }

        // Popularity
        if meta.popularity == 0.0 {
            signals.push(Signal {
                id: "M-POP-ZERO".to_string(),
                category: SignalCategory::Metadata,
                points: 25,
                description: "Popularity is 0 (no recent usage)".to_string(),
                is_override_gate: false,
            });
        }

        // Orphaned
        if meta.maintainer.is_none() {
            signals.push(Signal {
                id: "M-NO-MAINTAINER".to_string(),
                category: SignalCategory::Metadata,
                points: 20,
                description: "Package is orphaned (no maintainer)".to_string(),
                is_override_gate: false,
            });
        }

        // Missing URL
        if meta.url.as_ref().is_none_or(|u| u.is_empty()) {
            signals.push(Signal {
                id: "M-NO-URL".to_string(),
                category: SignalCategory::Metadata,
                points: 15,
                description: "No upstream URL provided".to_string(),
                is_override_gate: false,
            });
        }

        // Missing license
        if meta.license.as_ref().is_none_or(|l| l.is_empty()) {
            signals.push(Signal {
                id: "M-NO-LICENSE".to_string(),
                category: SignalCategory::Metadata,
                points: 10,
                description: "No license specified".to_string(),
                is_override_gate: false,
            });
        }

        // Out of date
        if meta.out_of_date.is_some() {
            signals.push(Signal {
                id: "M-OUT-OF-DATE".to_string(),
                category: SignalCategory::Metadata,
                points: 5,
                description: "Package is flagged as out of date".to_string(),
                is_override_gate: false,
            });
        }

        signals
    }
}
