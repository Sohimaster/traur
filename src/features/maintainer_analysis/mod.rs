use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct MaintainerAnalysis;

impl Feature for MaintainerAnalysis {
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
                    matched_line: None,
                });
            } else {
                signals.push(Signal {
                    id: "B-MAINTAINER-SINGLE".to_string(),
                    category: SignalCategory::Behavioral,
                    points: 15,
                    description: "Maintainer has only 1 package".to_string(),
                    is_override_gate: false,
                    matched_line: None,
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
                        matched_line: None,
                    });
                    break;
                }
            }
        }

        signals
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::models::AurPackage;

    fn make_pkg(name: &str, first_submitted: u64) -> AurPackage {
        AurPackage {
            name: name.into(),
            package_base: None,
            url: None,
            num_votes: 0,
            popularity: 0.0,
            out_of_date: None,
            maintainer: Some("testuser".into()),
            first_submitted,
            license: None,
        }
    }

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    fn has(ids: &[String], id: &str) -> bool {
        ids.iter().any(|s| s == id)
    }

    #[test]
    fn maintainer_new() {
        let ts = now();
        let pkg = make_pkg("evil", ts - 86400); // 1 day old
        let ctx = PackageContext {
            name: "evil".into(),
            metadata: Some(pkg.clone()),
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![pkg],
        };
        let ids: Vec<String> = MaintainerAnalysis.analyze(&ctx).iter().map(|s| s.id.clone()).collect();
        assert!(has(&ids, "B-MAINTAINER-NEW"));
    }

    #[test]
    fn maintainer_single() {
        let ts = now();
        let pkg = make_pkg("old-pkg", ts - 90 * 86400); // 90 days old
        let ctx = PackageContext {
            name: "old-pkg".into(),
            metadata: Some(pkg.clone()),
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![pkg],
        };
        let ids: Vec<String> = MaintainerAnalysis.analyze(&ctx).iter().map(|s| s.id.clone()).collect();
        assert!(has(&ids, "B-MAINTAINER-SINGLE"));
    }

    #[test]
    fn maintainer_batch() {
        let ts = now();
        let pkgs = vec![
            make_pkg("pkg1", ts - 3600),
            make_pkg("pkg2", ts - 7200),
            make_pkg("pkg3", ts - 10800),
        ];
        let ctx = PackageContext {
            name: "pkg1".into(),
            metadata: Some(pkgs[0].clone()),
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: pkgs,
        };
        let ids: Vec<String> = MaintainerAnalysis.analyze(&ctx).iter().map(|s| s.id.clone()).collect();
        assert!(has(&ids, "B-MAINTAINER-BATCH"));
    }
}
