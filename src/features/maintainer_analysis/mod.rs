use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct MaintainerAnalysis;

impl Feature for MaintainerAnalysis {
    fn name(&self) -> &str {
        "maintainer_analysis"
    }

    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        let mut signals = Vec::new();

        let Some(ref meta) = ctx.metadata else {
            return signals;
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let maintainer_pkgs = &ctx.maintainer_packages;

        // Single-package maintainer with new package
        if maintainer_pkgs.len() == 1 {
            let age_days = (now - meta.first_submitted) / 86400;
            if age_days < 30 {
                signals.push(Signal {
                    id: "B-MAINTAINER-NEW".to_string(),
                    category: SignalCategory::Behavioral,
                    points: 30,
                    description: format!(
                        "Maintainer has only 1 package, created {age_days} days ago"
                    ),
                    is_override_gate: false,
                });
            } else {
                signals.push(Signal {
                    id: "B-MAINTAINER-SINGLE".to_string(),
                    category: SignalCategory::Behavioral,
                    points: 15,
                    description: "Maintainer has only 1 package".to_string(),
                    is_override_gate: false,
                });
            }
        }

        // Batch upload detection: 3+ packages created within 48 hours
        if maintainer_pkgs.len() >= 3 {
            let mut timestamps: Vec<u64> =
                maintainer_pkgs.iter().map(|p| p.first_submitted).collect();
            timestamps.sort();

            let mut batch_count = 1;
            for window in timestamps.windows(2) {
                if window[1] - window[0] < 48 * 3600 {
                    batch_count += 1;
                } else {
                    batch_count = 1;
                }
                if batch_count >= 3 {
                    signals.push(Signal {
                        id: "B-MAINTAINER-BATCH".to_string(),
                        category: SignalCategory::Behavioral,
                        points: 45,
                        description: format!(
                            "Maintainer created {batch_count}+ packages within 48 hours"
                        ),
                        is_override_gate: false,
                    });
                    break;
                }
            }
        }

        signals
    }
}
