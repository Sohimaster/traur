use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory};
use std::collections::HashSet;

pub struct OrphanTakeoverAnalysis;

impl Feature for OrphanTakeoverAnalysis {
    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        let mut signals = Vec::new();

        let Some(ref meta) = ctx.metadata else {
            return signals;
        };

        let Some(ref submitter) = meta.submitter else {
            return signals;
        };

        let Some(ref maintainer) = meta.maintainer else {
            return signals;
        };

        if submitter == maintainer {
            return signals;
        }

        // Submitter differs from current maintainer — package was adopted
        signals.push(Signal {
            id: "B-SUBMITTER-CHANGED".to_string(),
            category: SignalCategory::Behavioral,
            points: 15,
            description: format!(
                "Package maintainer ({maintainer}) differs from original submitter ({submitter})"
            ),
            is_override_gate: false,
            matched_line: None,
        });

        // Composite: orphan takeover pattern
        // Requires: adopted + git author change + established package (>90 days)
        if ctx.git_log.len() >= 2 && is_established(meta.first_submitted) {
            let latest_author = ctx.git_log[0].author.as_str();
            let prior_authors: HashSet<&str> = ctx.git_log[1..]
                .iter()
                .map(|c| c.author.as_str())
                .collect();

            if !prior_authors.contains(latest_author) {
                signals.push(Signal {
                    id: "B-ORPHAN-TAKEOVER".to_string(),
                    category: SignalCategory::Behavioral,
                    points: 50,
                    description: format!(
                        "Adopted package with new git author ({latest_author}) — orphan takeover pattern"
                    ),
                    is_override_gate: false,
                    matched_line: None,
                });
            }
        }

        signals
    }
}

/// Package is established if first_submitted is more than 90 days ago.
fn is_established(first_submitted: u64) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    now.saturating_sub(first_submitted) > 90 * 86400
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::models::{AurPackage, GitCommit};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    fn make_pkg(maintainer: &str, submitter: Option<&str>, first_submitted: u64) -> AurPackage {
        AurPackage {
            name: "test-pkg".into(),
            package_base: None,
            url: None,
            num_votes: 10,
            popularity: 1.0,
            out_of_date: None,
            maintainer: Some(maintainer.into()),
            submitter: submitter.map(|s| s.into()),
            first_submitted,
            last_modified: now(),
            license: None,
        }
    }

    fn make_commit(author: &str, ts: u64) -> GitCommit {
        GitCommit {
            author: author.into(),
            timestamp: ts,
            diff: None,
        }
    }

    fn has(ids: &[String], id: &str) -> bool {
        ids.iter().any(|s| s == id)
    }

    fn signal_ids(ctx: &PackageContext) -> Vec<String> {
        OrphanTakeoverAnalysis
            .analyze(ctx)
            .iter()
            .map(|s| s.id.clone())
            .collect()
    }

    #[test]
    fn same_submitter_maintainer() {
        let ts = now();
        let ctx = PackageContext {
            name: "pkg".into(),
            metadata: Some(make_pkg("alice", Some("alice"), ts - 180 * 86400)),
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        };
        assert!(signal_ids(&ctx).is_empty());
    }

    #[test]
    fn no_submitter_field() {
        let ts = now();
        let ctx = PackageContext {
            name: "pkg".into(),
            metadata: Some(make_pkg("alice", None, ts - 180 * 86400)),
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        };
        assert!(signal_ids(&ctx).is_empty());
    }

    #[test]
    fn submitter_changed() {
        let ts = now();
        let ctx = PackageContext {
            name: "pkg".into(),
            metadata: Some(make_pkg("bob", Some("alice"), ts - 180 * 86400)),
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        };
        let ids = signal_ids(&ctx);
        assert!(has(&ids, "B-SUBMITTER-CHANGED"));
        assert!(!has(&ids, "B-ORPHAN-TAKEOVER"));
    }

    #[test]
    fn orphan_takeover_composite() {
        let ts = now();
        let ctx = PackageContext {
            name: "pkg".into(),
            metadata: Some(make_pkg("attacker", Some("original"), ts - 365 * 86400)),
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![
                make_commit("attacker", ts - 3600),
                make_commit("original", ts - 180 * 86400),
            ],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        };
        let ids = signal_ids(&ctx);
        assert!(has(&ids, "B-SUBMITTER-CHANGED"));
        assert!(has(&ids, "B-ORPHAN-TAKEOVER"));
    }

    #[test]
    fn new_package_no_composite() {
        let ts = now();
        let ctx = PackageContext {
            name: "pkg".into(),
            metadata: Some(make_pkg("bob", Some("alice"), ts - 30 * 86400)),
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![
                make_commit("bob", ts - 3600),
                make_commit("alice", ts - 30 * 86400),
            ],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        };
        let ids = signal_ids(&ctx);
        assert!(has(&ids, "B-SUBMITTER-CHANGED"));
        assert!(!has(&ids, "B-ORPHAN-TAKEOVER"), "New package should not trigger composite signal");
    }

    #[test]
    fn same_git_author_no_composite() {
        let ts = now();
        let ctx = PackageContext {
            name: "pkg".into(),
            metadata: Some(make_pkg("bob", Some("alice"), ts - 365 * 86400)),
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![
                make_commit("shared-author", ts - 3600),
                make_commit("shared-author", ts - 180 * 86400),
            ],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        };
        let ids = signal_ids(&ctx);
        assert!(has(&ids, "B-SUBMITTER-CHANGED"));
        assert!(!has(&ids, "B-ORPHAN-TAKEOVER"), "Same git author should not trigger composite");
    }
}
