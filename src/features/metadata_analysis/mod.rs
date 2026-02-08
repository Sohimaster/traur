use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory};

pub struct MetadataAnalysis;

impl Feature for MetadataAnalysis {
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
                matched_line: None,
            });
        } else if meta.num_votes < 5 {
            signals.push(Signal {
                id: "M-VOTES-LOW".to_string(),
                category: SignalCategory::Metadata,
                points: 20,
                description: format!("Package has very few votes ({})", meta.num_votes),
                is_override_gate: false,
                matched_line: None,
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
                matched_line: None,
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
                matched_line: None,
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
                matched_line: None,
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
                matched_line: None,
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
                matched_line: None,
            });
        }

        signals
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::models::AurPackage;

    fn make_meta(votes: u32, popularity: f64, maintainer: Option<&str>, url: Option<&str>, license: Option<Vec<String>>, out_of_date: Option<u64>) -> AurPackage {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        AurPackage {
            name: "test-pkg".into(),
            package_base: None,
            url: url.map(|s| s.to_string()),
            num_votes: votes,
            popularity,
            out_of_date,
            maintainer: maintainer.map(|s| s.to_string()),
            submitter: None,
            first_submitted: now - 86400, // 1 day ago
            last_modified: now,
            license,
        }
    }

    fn analyze_meta(meta: AurPackage) -> Vec<String> {
        let ctx = PackageContext {
            name: "test-pkg".into(),
            metadata: Some(meta),
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
        };
        MetadataAnalysis.analyze(&ctx).iter().map(|s| s.id.clone()).collect()
    }

    fn has(ids: &[String], id: &str) -> bool {
        ids.iter().any(|s| s == id)
    }

    #[test]
    fn votes_zero() {
        let ids = analyze_meta(make_meta(0, 1.0, Some("user"), Some("https://example.com"), Some(vec!["MIT".into()]), None));
        assert!(has(&ids, "M-VOTES-ZERO"));
    }

    #[test]
    fn votes_low() {
        let ids = analyze_meta(make_meta(3, 1.0, Some("user"), Some("https://example.com"), Some(vec!["MIT".into()]), None));
        assert!(has(&ids, "M-VOTES-LOW"));
    }

    #[test]
    fn pop_zero() {
        let ids = analyze_meta(make_meta(10, 0.0, Some("user"), Some("https://example.com"), Some(vec!["MIT".into()]), None));
        assert!(has(&ids, "M-POP-ZERO"));
    }

    #[test]
    fn no_maintainer() {
        let ids = analyze_meta(make_meta(10, 1.0, None, Some("https://example.com"), Some(vec!["MIT".into()]), None));
        assert!(has(&ids, "M-NO-MAINTAINER"));
    }

    #[test]
    fn no_url() {
        let ids = analyze_meta(make_meta(10, 1.0, Some("user"), None, Some(vec!["MIT".into()]), None));
        assert!(has(&ids, "M-NO-URL"));
    }

    #[test]
    fn no_license() {
        let ids = analyze_meta(make_meta(10, 1.0, Some("user"), Some("https://example.com"), None, None));
        assert!(has(&ids, "M-NO-LICENSE"));
    }

    #[test]
    fn out_of_date() {
        let ids = analyze_meta(make_meta(10, 1.0, Some("user"), Some("https://example.com"), Some(vec!["MIT".into()]), Some(1700000000)));
        assert!(has(&ids, "M-OUT-OF-DATE"));
    }

    #[test]
    fn healthy_package_no_signals() {
        let ids = analyze_meta(make_meta(100, 5.0, Some("user"), Some("https://example.com"), Some(vec!["MIT".into()]), None));
        assert!(ids.is_empty(), "Healthy package should trigger no signals, got: {ids:?}");
    }
}
