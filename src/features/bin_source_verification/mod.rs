use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory};
use regex::Regex;
use std::sync::LazyLock;

/// Matches all source array variants: source=(), source_x86_64=(), etc.
static SOURCE_ARRAYS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?ms)^source(?:_[a-zA-Z0-9_]+)?\s*=\s*\((.*?)\)").unwrap()
});

/// Extracts URLs from quoted or unquoted tokens inside a source array.
static URL_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"['"]([^'"]+)['"]|(\S+)"#).unwrap()
});

/// Matches ${url} or $url variable references.
static URL_VAR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{url\}|\$url").unwrap()
});

/// Matches any remaining unresolvable bash variable.
static UNRESOLVED_VAR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{?\w+\}?").unwrap()
});

pub struct BinSourceVerification;

impl Feature for BinSourceVerification {
    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        if !ctx.name.ends_with("-bin") {
            return Vec::new();
        }

        let Some(ref content) = ctx.pkgbuild_content else {
            return Vec::new();
        };

        let Some(ref meta) = ctx.metadata else {
            return Vec::new();
        };

        let Some(ref upstream_url) = meta.url else {
            return Vec::new();
        };

        let upstream_domain = match extract_domain(upstream_url) {
            Some(d) => d,
            None => return Vec::new(),
        };
        let upstream_org = extract_github_org(upstream_url);

        let source_urls = extract_source_urls(content, upstream_url);
        let mut signals = Vec::new();
        let mut saw_github_org_mismatch = false;

        for raw_url in &source_urls {
            // Skip non-HTTP sources (local files, etc.)
            if !raw_url.contains("://") {
                continue;
            }

            let Some(src_domain) = extract_domain(raw_url) else {
                continue;
            };

            // GitHub org comparison (higher confidence)
            if normalize_domain(&src_domain) == "github.com"
                && normalize_domain(&upstream_domain) == "github.com"
            {
                let src_org = extract_github_org(raw_url);
                if let (Some(u_org), Some(s_org)) = (&upstream_org, &src_org) {
                    if !u_org.eq_ignore_ascii_case(s_org) && !saw_github_org_mismatch {
                        saw_github_org_mismatch = true;
                        signals.push(Signal {
                            id: "B-BIN-GITHUB-ORG-MISMATCH".to_string(),
                            category: SignalCategory::Behavioral,
                            points: 50,
                            description: format!(
                                "-bin package upstream is github.com/{u_org} but source downloads from github.com/{s_org}"
                            ),
                            is_override_gate: false,
                            matched_line: Some(raw_url.clone()),
                        });
                    }
                }
                continue; // Already compared at org level, skip domain check
            }

            // Domain-level comparison
            if normalize_domain(&src_domain) != normalize_domain(&upstream_domain) {
                signals.push(Signal {
                    id: "B-BIN-DOMAIN-MISMATCH".to_string(),
                    category: SignalCategory::Behavioral,
                    points: 30,
                    description: format!(
                        "-bin package upstream is {upstream_domain} but source downloads from {src_domain}"
                    ),
                    is_override_gate: false,
                    matched_line: Some(raw_url.clone()),
                });
            }
        }

        signals
    }
}

/// Extract all URLs from source=() arrays, resolving $url/${url} variables.
fn extract_source_urls(content: &str, upstream_url: &str) -> Vec<String> {
    let mut urls = Vec::new();

    for caps in SOURCE_ARRAYS_RE.captures_iter(content) {
        let body = &caps[1];
        for token_cap in URL_TOKEN_RE.captures_iter(body) {
            let raw = token_cap
                .get(1)
                .or_else(|| token_cap.get(2))
                .unwrap()
                .as_str();

            // Strip VCS prefix (git+https://, svn+https://, etc.)
            let raw = raw
                .split_once("+http")
                .map(|(_, rest)| format!("http{rest}"))
                .unwrap_or_else(|| raw.to_string());

            // Resolve ${url}/$url to the upstream URL
            let resolved = URL_VAR_RE.replace_all(&raw, upstream_url).to_string();

            // Skip if unresolvable variables remain
            if UNRESOLVED_VAR_RE.is_match(&resolved) {
                continue;
            }

            // Skip rename-prefix entries like "tool::https://..."
            let resolved = resolved
                .split_once("::")
                .map(|(_, url)| url.to_string())
                .unwrap_or(resolved);

            urls.push(resolved);
        }
    }

    urls
}

/// Extract the domain from a URL string.
fn extract_domain(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1)?;
    let host = after_scheme.split('/').next()?;
    // Strip port if present
    let host = host.split(':').next()?;
    if host.is_empty() {
        return None;
    }
    Some(host.to_lowercase())
}

/// Extract the GitHub org/user from a github.com URL.
fn extract_github_org(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1)?;
    let host = after_scheme.split('/').next()?;
    if !normalize_domain(host).ends_with("github.com") {
        return None;
    }
    let path_part = after_scheme.split('/').nth(1)?;
    if path_part.is_empty() {
        return None;
    }
    Some(path_part.to_lowercase())
}

/// Normalize domain by stripping common prefixes (www., dl., download.).
fn normalize_domain(domain: &str) -> String {
    let d = domain.to_lowercase();
    for prefix in &["www.", "dl.", "download."] {
        if let Some(rest) = d.strip_prefix(prefix) {
            return rest.to_string();
        }
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::models::AurPackage;

    fn make_pkg(url: Option<&str>) -> AurPackage {
        AurPackage {
            name: "test-bin".into(),
            package_base: None,
            url: url.map(|s| s.into()),
            num_votes: 10,
            popularity: 1.0,
            out_of_date: None,
            maintainer: Some("user".into()),
            submitter: Some("user".into()),
            first_submitted: 0,
            last_modified: 0,
            license: None,
        }
    }

    fn analyze(name: &str, url: Option<&str>, pkgbuild: &str) -> Vec<Signal> {
        let ctx = PackageContext {
            name: name.into(),
            metadata: Some(make_pkg(url)),
            pkgbuild_content: Some(pkgbuild.into()),
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
        };
        BinSourceVerification.analyze(&ctx)
    }

    fn ids(signals: &[Signal]) -> Vec<String> {
        signals.iter().map(|s| s.id.clone()).collect()
    }

    fn has(ids: &[String], id: &str) -> bool {
        ids.iter().any(|s| s == id)
    }

    #[test]
    fn skips_non_bin_package() {
        let signals = analyze(
            "tool",
            Some("https://github.com/official/tool"),
            "source=('https://github.com/attacker/tool/archive/v1.0.tar.gz')",
        );
        assert!(signals.is_empty());
    }

    #[test]
    fn github_org_mismatch() {
        let signals = analyze(
            "tool-bin",
            Some("https://github.com/official/tool"),
            "source=('https://github.com/attacker/tool-bin/releases/download/v1.0/tool.tar.gz')",
        );
        let ids = ids(&signals);
        assert!(has(&ids, "B-BIN-GITHUB-ORG-MISMATCH"));
    }

    #[test]
    fn github_org_match() {
        let signals = analyze(
            "tool-bin",
            Some("https://github.com/official/tool"),
            "source=('https://github.com/official/tool/releases/download/v1.0/tool.tar.gz')",
        );
        assert!(signals.is_empty());
    }

    #[test]
    fn github_org_case_insensitive() {
        let signals = analyze(
            "tool-bin",
            Some("https://github.com/Official/tool"),
            "source=('https://github.com/official/tool/releases/download/v1.0/tool.tar.gz')",
        );
        assert!(signals.is_empty());
    }

    #[test]
    fn domain_mismatch() {
        let signals = analyze(
            "tool-bin",
            Some("https://example.com/tool"),
            "source=('https://evil.org/tool-bin-v1.0.tar.gz')",
        );
        let ids = ids(&signals);
        assert!(has(&ids, "B-BIN-DOMAIN-MISMATCH"));
    }

    #[test]
    fn domain_match() {
        let signals = analyze(
            "tool-bin",
            Some("https://example.com/tool"),
            "source=('https://example.com/releases/tool-v1.0.tar.gz')",
        );
        assert!(signals.is_empty());
    }

    #[test]
    fn domain_match_with_www_prefix() {
        let signals = analyze(
            "tool-bin",
            Some("https://www.example.com/tool"),
            "source=('https://example.com/releases/tool-v1.0.tar.gz')",
        );
        assert!(signals.is_empty());
    }

    #[test]
    fn domain_match_with_dl_prefix() {
        let signals = analyze(
            "tool-bin",
            Some("https://example.com/tool"),
            "source=('https://dl.example.com/releases/tool-v1.0.tar.gz')",
        );
        assert!(signals.is_empty());
    }

    #[test]
    fn resolves_url_variable() {
        let signals = analyze(
            "tool-bin",
            Some("https://github.com/official/tool"),
            "source=(\"${url}/releases/download/v1.0/tool.tar.gz\")",
        );
        assert!(signals.is_empty());
    }

    #[test]
    fn resolves_url_variable_short() {
        let signals = analyze(
            "tool-bin",
            Some("https://github.com/official/tool"),
            "source=(\"$url/releases/download/v1.0/tool.tar.gz\")",
        );
        assert!(signals.is_empty());
    }

    #[test]
    fn skips_unresolvable_variables() {
        let signals = analyze(
            "tool-bin",
            Some("https://github.com/official/tool"),
            "source=(\"https://github.com/${_owner}/${pkgname}/releases/v${pkgver}.tar.gz\")",
        );
        // Should not emit any signal since variables can't be resolved
        assert!(signals.is_empty());
    }

    #[test]
    fn handles_arch_specific_source() {
        let signals = analyze(
            "tool-bin",
            Some("https://github.com/official/tool"),
            "source_x86_64=('https://github.com/attacker/tool-bin/releases/download/v1.0/tool-x86_64.tar.gz')",
        );
        let ids = ids(&signals);
        assert!(has(&ids, "B-BIN-GITHUB-ORG-MISMATCH"));
    }

    #[test]
    fn handles_git_plus_prefix() {
        let signals = analyze(
            "tool-bin",
            Some("https://github.com/official/tool"),
            "source=('git+https://github.com/attacker/tool-bin.git')",
        );
        let ids = ids(&signals);
        assert!(has(&ids, "B-BIN-GITHUB-ORG-MISMATCH"));
    }

    #[test]
    fn skips_local_file_sources() {
        let signals = analyze(
            "tool-bin",
            Some("https://github.com/official/tool"),
            "source=('tool.desktop' 'https://github.com/official/tool/releases/download/v1.0/tool.tar.gz')",
        );
        assert!(signals.is_empty());
    }

    #[test]
    fn handles_rename_prefix() {
        let signals = analyze(
            "tool-bin",
            Some("https://github.com/official/tool"),
            "source=('tool-v1.0.tar.gz::https://github.com/official/tool/archive/v1.0.tar.gz')",
        );
        assert!(signals.is_empty());
    }

    #[test]
    fn no_metadata_url() {
        let signals = analyze(
            "tool-bin",
            None,
            "source=('https://github.com/attacker/tool-bin/releases/download/v1.0/tool.tar.gz')",
        );
        assert!(signals.is_empty());
    }

    #[test]
    fn emits_only_one_github_org_signal() {
        let signals = analyze(
            "tool-bin",
            Some("https://github.com/official/tool"),
            "source_x86_64=('https://github.com/attacker/tool-bin/releases/download/v1.0/tool-x86_64.tar.gz')\nsource_aarch64=('https://github.com/attacker/tool-bin/releases/download/v1.0/tool-aarch64.tar.gz')",
        );
        let org_signals: Vec<_> = signals
            .iter()
            .filter(|s| s.id == "B-BIN-GITHUB-ORG-MISMATCH")
            .collect();
        assert_eq!(org_signals.len(), 1);
    }
}
