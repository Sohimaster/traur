use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::patterns;
use crate::shared::scoring::{Signal, SignalCategory};
use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

static CHECKSUM_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^(md5|sha1|sha224|sha256|sha384|sha512|b2)sums(_[a-z0-9_]+)?=").unwrap());

static SOURCE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^source(_[a-z0-9_]+)?\s*=\s*\(([^)]*)\)").unwrap());

static URL_DOMAIN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"https?://([^/\s'"]+)"#).unwrap());

/// Loaded once: high-severity pkgbuild patterns (points >= 60) for diff detection.
static HIGH_SEVERITY_PATTERNS: LazyLock<Vec<patterns::CompiledPattern>> = LazyLock::new(|| {
    patterns::load_patterns("pkgbuild_analysis")
        .into_iter()
        .filter(|p| p.points >= 60)
        .collect()
});

pub struct PkgbuildDiffAnalysis;

impl Feature for PkgbuildDiffAnalysis {
    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        let (Some(new_content), Some(old_content)) =
            (&ctx.pkgbuild_content, &ctx.prior_pkgbuild_content)
        else {
            return Vec::new();
        };

        let mut signals = Vec::new();

        check_new_suspicious(new_content, old_content, &mut signals);
        check_checksum_removed(new_content, old_content, &mut signals);
        check_source_domain_changed(new_content, old_content, &mut signals);
        check_major_rewrite(new_content, old_content, &mut signals);

        signals
    }
}

/// Flag high-severity patterns newly introduced in the current version.
fn check_new_suspicious(new: &str, old: &str, signals: &mut Vec<Signal>) {
    for pattern in HIGH_SEVERITY_PATTERNS.iter() {
        if pattern.regex.is_match(new) && !pattern.regex.is_match(old) {
            let matched_line = new
                .lines()
                .find(|line| pattern.regex.is_match(line))
                .map(|l| l.trim().to_string());
            signals.push(Signal {
                id: "T-DIFF-NEW-SUSPICIOUS".to_string(),
                category: SignalCategory::Temporal,
                points: 40,
                description: format!(
                    "Newly introduced suspicious pattern: {} ({})",
                    pattern.id, pattern.description
                ),
                is_override_gate: false,
                matched_line,
            });
            return; // one signal is enough
        }
    }
}

/// Flag if checksums were removed or all changed to SKIP.
fn check_checksum_removed(new: &str, old: &str, signals: &mut Vec<Signal>) {
    let old_has_checksums = CHECKSUM_RE.is_match(old);
    let new_has_checksums = CHECKSUM_RE.is_match(new);

    if old_has_checksums && !new_has_checksums {
        signals.push(Signal {
            id: "T-DIFF-CHECKSUM-REMOVED".to_string(),
            category: SignalCategory::Temporal,
            points: 35,
            description: "Checksum array removed in latest update".to_string(),
            is_override_gate: false,
            matched_line: None,
        });
        return;
    }

    // Check if checksums all changed to SKIP
    if old_has_checksums && new_has_checksums {
        let old_has_skip_only = has_only_skip_checksums(old);
        let new_has_skip_only = has_only_skip_checksums(new);
        if !old_has_skip_only && new_has_skip_only {
            signals.push(Signal {
                id: "T-DIFF-CHECKSUM-REMOVED".to_string(),
                category: SignalCategory::Temporal,
                points: 35,
                description: "All checksums changed to SKIP in latest update".to_string(),
                is_override_gate: false,
                matched_line: None,
            });
        }
    }
}

/// Check if all checksum entries are 'SKIP'.
fn has_only_skip_checksums(content: &str) -> bool {
    // Find checksum arrays and check if they only contain SKIP
    for cap in CHECKSUM_RE.find_iter(content) {
        let rest = &content[cap.end()..];
        // Find the matching parenthesized array
        if let Some(paren_start) = rest.find('(') {
            let after_paren = &rest[paren_start + 1..];
            if let Some(paren_end) = after_paren.find(')') {
                let array_content = &after_paren[..paren_end];
                let entries: Vec<&str> = array_content
                    .split_whitespace()
                    .map(|s| s.trim_matches('\'').trim_matches('\"'))
                    .filter(|s| !s.is_empty())
                    .collect();
                if !entries.is_empty() && entries.iter().all(|e| *e == "SKIP") {
                    continue;
                }
                return false;
            }
        }
    }
    true
}

/// Flag if source domains changed between versions.
fn check_source_domain_changed(new: &str, old: &str, signals: &mut Vec<Signal>) {
    let old_domains = extract_source_domains(old);
    let new_domains = extract_source_domains(new);

    if old_domains.is_empty() || new_domains.is_empty() {
        return;
    }

    // Flag if new introduces domains not in old
    let added: Vec<&String> = new_domains.difference(&old_domains).collect();
    if !added.is_empty() {
        signals.push(Signal {
            id: "T-DIFF-SOURCE-DOMAIN-CHANGED".to_string(),
            category: SignalCategory::Temporal,
            points: 30,
            description: format!(
                "Source URLs changed to new domain(s): {}",
                added.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            ),
            is_override_gate: false,
            matched_line: None,
        });
    }
}

/// Extract domains from source=() arrays.
fn extract_source_domains(content: &str) -> HashSet<String> {
    let mut domains = HashSet::new();
    for cap in SOURCE_RE.captures_iter(content) {
        let array_content = &cap[2];
        for url_match in URL_DOMAIN_RE.captures_iter(array_content) {
            let domain = url_match[1].to_lowercase();
            // Strip common variable-containing prefixes
            if !domain.contains('$') {
                domains.insert(domain);
            }
        }
    }
    domains
}

/// Flag if >50% of lines changed (unusual for a version bump).
fn check_major_rewrite(new: &str, old: &str, signals: &mut Vec<Signal>) {
    let old_lines: HashSet<&str> = old
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();
    let new_lines: HashSet<&str> = new
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();

    if old_lines.is_empty() {
        return;
    }

    let common = old_lines.intersection(&new_lines).count();
    let total = old_lines.len().max(new_lines.len());
    let changed_pct = ((total - common) as f64 / total as f64 * 100.0) as u32;

    if changed_pct > 50 {
        signals.push(Signal {
            id: "T-DIFF-MAJOR-REWRITE".to_string(),
            category: SignalCategory::Temporal,
            points: 15,
            description: format!("{}% of PKGBUILD lines changed (unusual for version bump)", changed_pct),
            is_override_gate: false,
            matched_line: None,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has(ids: &[String], id: &str) -> bool {
        ids.iter().any(|s| s == id)
    }

    fn analyze(new: &str, old: &str) -> Vec<String> {
        let ctx = PackageContext {
            name: "test".into(),
            metadata: None,
            pkgbuild_content: Some(new.to_string()),
            install_script_content: None,
            prior_pkgbuild_content: Some(old.to_string()),
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        };
        PkgbuildDiffAnalysis
            .analyze(&ctx)
            .iter()
            .map(|s| s.id.clone())
            .collect()
    }

    #[test]
    fn no_prior_pkgbuild() {
        let ctx = PackageContext {
            name: "test".into(),
            metadata: None,
            pkgbuild_content: Some("pkgname=test".into()),
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        };
        assert!(PkgbuildDiffAnalysis.analyze(&ctx).is_empty());
    }

    #[test]
    fn checksum_removed() {
        let old = "pkgname=test\nsha256sums=('abc123')";
        let new = "pkgname=test\n";
        assert!(has(&analyze(new, old), "T-DIFF-CHECKSUM-REMOVED"));
    }

    #[test]
    fn checksum_changed_to_skip() {
        let old = "pkgname=test\nsha256sums=('abc123def456')";
        let new = "pkgname=test\nsha256sums=('SKIP')";
        assert!(has(&analyze(new, old), "T-DIFF-CHECKSUM-REMOVED"));
    }

    #[test]
    fn checksum_unchanged_no_signal() {
        let old = "pkgname=test\nsha256sums=('abc123')";
        let new = "pkgname=test\nsha256sums=('def456')";
        assert!(!has(&analyze(new, old), "T-DIFF-CHECKSUM-REMOVED"));
    }

    #[test]
    fn source_domain_changed() {
        let old = "pkgname=test\nsource=('https://github.com/owner/repo/v1.tar.gz')";
        let new = "pkgname=test\nsource=('https://evil.com/repo/v1.tar.gz')";
        assert!(has(&analyze(new, old), "T-DIFF-SOURCE-DOMAIN-CHANGED"));
    }

    #[test]
    fn source_domain_same_no_signal() {
        let old = "pkgname=test\nsource=('https://github.com/owner/repo/v1.tar.gz')";
        let new = "pkgname=test\nsource=('https://github.com/owner/repo/v2.tar.gz')";
        assert!(!has(&analyze(new, old), "T-DIFF-SOURCE-DOMAIN-CHANGED"));
    }

    #[test]
    fn major_rewrite_detected() {
        let old = (1..=20).map(|i| format!("line{i}=old")).collect::<Vec<_>>().join("\n");
        let new = (1..=20).map(|i| format!("line{i}=new")).collect::<Vec<_>>().join("\n");
        assert!(has(&analyze(&new, &old), "T-DIFF-MAJOR-REWRITE"));
    }

    #[test]
    fn minor_change_no_rewrite_signal() {
        let mut lines: Vec<String> = (1..=20).map(|i| format!("line{i}=value")).collect();
        let old = lines.join("\n");
        lines[0] = "line1=changed".to_string();
        let new = lines.join("\n");
        assert!(!has(&analyze(&new, &old), "T-DIFF-MAJOR-REWRITE"));
    }
}
