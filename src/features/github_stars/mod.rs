use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory};

pub struct GitHubStars;

impl Feature for GitHubStars {
    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        let mut signals = Vec::new();

        if ctx.github_not_found {
            signals.push(Signal {
                id: "M-GITHUB-NOT-FOUND".to_string(),
                category: SignalCategory::Metadata,
                points: 25,
                description: "Upstream URL points to GitHub but repo does not exist".to_string(),
                is_override_gate: false,
                matched_line: ctx
                    .metadata
                    .as_ref()
                    .and_then(|m| m.url.clone()),
            });
            return signals;
        }

        if let Some(stars) = ctx.github_stars {
            if stars == 0 {
                signals.push(Signal {
                    id: "M-GITHUB-STARS-ZERO".to_string(),
                    category: SignalCategory::Metadata,
                    points: 20,
                    description: "Upstream GitHub repo has 0 stars".to_string(),
                    is_override_gate: false,
                    matched_line: None,
                });
            } else if stars < 10 {
                signals.push(Signal {
                    id: "M-GITHUB-STARS-LOW".to_string(),
                    category: SignalCategory::Metadata,
                    points: 10,
                    description: format!("Upstream GitHub repo has very few stars ({stars})"),
                    is_override_gate: false,
                    matched_line: None,
                });
            }
        }

        signals
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has(ids: &[String], id: &str) -> bool {
        ids.iter().any(|s| s == id)
    }

    fn analyze_stars(stars: Option<u32>, not_found: bool) -> Vec<String> {
        let ctx = PackageContext {
            name: "test".into(),
            metadata: None,
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: stars,
            github_not_found: not_found,
            aur_comments: vec![],
        };
        GitHubStars
            .analyze(&ctx)
            .iter()
            .map(|s| s.id.clone())
            .collect()
    }

    #[test]
    fn zero_stars() {
        assert!(has(&analyze_stars(Some(0), false), "M-GITHUB-STARS-ZERO"));
    }

    #[test]
    fn low_stars() {
        assert!(has(&analyze_stars(Some(5), false), "M-GITHUB-STARS-LOW"));
    }

    #[test]
    fn enough_stars_no_signal() {
        assert!(analyze_stars(Some(50), false).is_empty());
    }

    #[test]
    fn not_found() {
        assert!(has(&analyze_stars(None, true), "M-GITHUB-NOT-FOUND"));
    }

    #[test]
    fn non_github_no_signal() {
        assert!(analyze_stars(None, false).is_empty());
    }
}
