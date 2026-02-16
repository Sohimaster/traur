use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory};

const SECURITY_KEYWORDS: &[&str] = &[
    "malware",
    "backdoor",
    "trojan",
    "keylogger",
    "cryptominer",
    "ransomware",
    "rootkit",
    "compromised",
    "virus",
    "suspicious",
    "malicious",
    "spyware",
    "unsafe",
    "dangerous",
    "phishing",
    "exploit",
];

pub struct AurCommentsAnalysis;

impl Feature for AurCommentsAnalysis {
    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        if ctx.aur_comments.is_empty() {
            return Vec::new();
        }

        for comment in &ctx.aur_comments {
            let lower = comment.to_lowercase();
            for keyword in SECURITY_KEYWORDS {
                if lower.contains(keyword) {
                    let truncated = if comment.len() > 120 {
                        format!("{}...", &comment[..120])
                    } else {
                        comment.clone()
                    };
                    return vec![Signal {
                        id: "M-COMMENTS-SECURITY".to_string(),
                        category: SignalCategory::Metadata,
                        points: 40,
                        description: format!(
                            "AUR comment mentions security concern (keyword: {keyword})"
                        ),
                        is_override_gate: false,
                        matched_line: Some(truncated),
                    }];
                }
            }
        }

        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has(ids: &[String], id: &str) -> bool {
        ids.iter().any(|s| s == id)
    }

    fn analyze_comments(comments: Vec<&str>) -> Vec<String> {
        let ctx = PackageContext {
            name: "test".into(),
            metadata: None,
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: comments.into_iter().map(|s| s.to_string()).collect(),
        };
        AurCommentsAnalysis
            .analyze(&ctx)
            .iter()
            .map(|s| s.id.clone())
            .collect()
    }

    #[test]
    fn detects_malware_keyword() {
        assert!(has(
            &analyze_comments(vec!["This package contains malware!"]),
            "M-COMMENTS-SECURITY"
        ));
    }

    #[test]
    fn detects_backdoor_keyword() {
        assert!(has(
            &analyze_comments(vec!["Found a backdoor in the install script"]),
            "M-COMMENTS-SECURITY"
        ));
    }

    #[test]
    fn case_insensitive() {
        assert!(has(
            &analyze_comments(vec!["MALICIOUS code detected"]),
            "M-COMMENTS-SECURITY"
        ));
    }

    #[test]
    fn no_keywords_no_signal() {
        assert!(analyze_comments(vec!["Great package, works perfectly!"]).is_empty());
    }

    #[test]
    fn empty_comments_no_signal() {
        assert!(analyze_comments(vec![]).is_empty());
    }

    #[test]
    fn emits_only_one_signal() {
        let ids = analyze_comments(vec![
            "This is malware",
            "Also a trojan",
            "And a backdoor",
        ]);
        assert_eq!(ids.len(), 1);
    }
}
