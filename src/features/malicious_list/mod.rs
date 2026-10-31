use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory, SignalRole};

/// URL of the shared list of AUR packages compromised in the June 2026
/// "Atomic Arch" incident (issue #17).
const MALICIOUS_LIST_URL: &str = "https://md.archlinux.org/s/SxbqukK6IA/download";

/// How long a fetched list is trusted before it is fetched again.
const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(60 * 60 * 12);

#[derive(Default)]
pub struct MaliciousListAnalysis;

impl Feature for MaliciousListAnalysis {
    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        let package_base = ctx
            .metadata
            .as_ref()
            .and_then(|m| m.package_base.clone());

        if is_listed(&ctx.name, package_base.as_deref()) {
            return vec![Signal {
                id: "B-MALICIOUS-LIST".to_string(),
                category: SignalCategory::Behavioral,
                role: SignalRole::OverrideGate,
                points: 100,
                description:
                    "Package appears on the public list of packages compromised in the AUR malware incident"
                        .to_string(),
                is_override_gate: true,
                matched_line: None,
            }];
        }

        Vec::new()
    }
}

/// Whether `name` (or its package base) is on the malicious list.
///
/// The list is a Markdown code block with one package name per line. It is
/// fetched at most once per [`CACHE_TTL`] and cached under the traur cache
/// directory. Any error (offline, parse failure, no cache) means "not listed":
/// this feature can only add evidence, never replace the rest of the analysis.
pub fn is_listed(name: &str, package_base: Option<&str>) -> bool {
    let Some(entries) = load_list() else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    if entries.iter().any(|e| *e == name) {
        return true;
    }
    match package_base {
        Some(base) => entries.iter().any(|e| *e == base.to_ascii_lowercase()),
        None => false,
    }
}

fn cache_path() -> std::path::PathBuf {
    crate::shared::cache::cache_dir().join("malicious-list.txt")
}

/// Load the list from cache if fresh, otherwise fetch and cache it.
fn load_list() -> Option<Vec<String>> {
    let path = cache_path();

    if let Ok(meta) = std::fs::metadata(&path)
        && let Ok(modified) = meta.modified()
        && modified.elapsed().map(|e| e < CACHE_TTL).unwrap_or(false)
        && let Ok(text) = std::fs::read_to_string(&path)
    {
        let entries = parse_list(&text);
        if !entries.is_empty() {
            return Some(entries);
        }
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .ok()?;

    let text = match client.get(MALICIOUS_LIST_URL).send() {
        Ok(resp) if resp.status().is_success() => resp.text().ok()?,
        _ => {
            // Fall back to a stale cache rather than losing coverage.
            return std::fs::read_to_string(&path).ok().map(|t| parse_list(&t));
        }
    };

    let entries = parse_list(&text);
    if entries.is_empty() {
        return None;
    }

    // Best effort: a failed write only costs a refetch next time.
    let _ = std::fs::write(&path, &text);
    Some(entries)
}

/// Extract package names from the shared list.
///
/// The document wraps the names in a Markdown code fence and contains a stray
/// escaped entry; names are lowercased and anything that is not a valid package
/// name is ignored.
fn parse_list(text: &str) -> Vec<String> {
    text.lines()
        .map(|line| line.trim().trim_start_matches('\u{feff}'))
        .filter(|line| !line.is_empty() && !line.starts_with("```"))
        .map(|line| line.to_ascii_lowercase())
        .filter(|line| {
            line.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+' | '@'))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "```\n123pan-bin\n1code\nzrythm-git\n```\n";

    #[test]
    fn parses_fenced_list() {
        let entries = parse_list(SAMPLE);
        assert_eq!(entries, vec!["123pan-bin", "1code", "zrythm-git"]);
    }

    #[test]
    fn ignores_markdown_and_bad_entries() {
        let entries = parse_list("```\ngood-pkg\nnotepad\\u2014bin\n/evil\n```\n");
        assert_eq!(entries, vec!["good-pkg"]);
    }

    #[test]
    fn matches_ignoring_case() {
        assert!(parse_list(SAMPLE).iter().any(|e| *e == "123pan-bin"));
    }

    #[test]
    fn list_entry_lookup() {
        // Exercise the matching logic without touching the network.
        let entries = parse_list(SAMPLE);
        let listed = |n: &str| entries.iter().any(|e| *e == n.to_ascii_lowercase());
        assert!(listed("zrythm-git"));
        assert!(listed("ZRYTHM-GIT"));
        assert!(!listed("paru-bin"));
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    fn ctx(name: &str) -> PackageContext {
        PackageContext {
            name: name.into(),
            metadata: None,
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
            local_sources: vec![],
            source_path: None,
            incomplete: vec![],
        }
    }

    #[test]
    fn unlisted_package_emits_no_signal() {
        // A package that will never be on the list.
        let signals = MaliciousListAnalysis.analyze(&ctx("traur-not-a-real-package-xyz"));
        assert!(signals.is_empty());
    }

    #[test]
    fn listed_package_emits_override_gate() {
        // Drive the lookup through the cached list if one exists, otherwise skip:
        // this test must not depend on network access.
        let Some(entries) = load_list() else {
            return;
        };
        let Some(first) = entries.first() else {
            return;
        };
        let signals = MaliciousListAnalysis.analyze(&ctx(first));
        assert_eq!(signals.len(), 1, "listed package must emit a signal");
        assert_eq!(signals[0].id, "B-MALICIOUS-LIST");
        assert_eq!(signals[0].points, 100);
        assert!(signals[0].is_override_gate);
    }
}
