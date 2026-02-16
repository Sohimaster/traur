use crate::shared::patterns::PatternDatabase;
use crate::shared::scoring::SignalCategory;

/// A signal definition (metadata only, no compiled regex).
pub struct SignalDef {
    pub id: String,
    pub category: SignalCategory,
    #[allow(dead_code)]
    pub points: u32,
    pub description: String,
    #[allow(dead_code)]
    pub is_override_gate: bool,
}

/// Return all known signal definitions (pattern-based + hardcoded).
pub fn all_signal_definitions() -> Vec<SignalDef> {
    let mut defs = pattern_signals();
    defs.extend(hardcoded_signals());
    defs.sort_by(|a, b| a.id.cmp(&b.id));
    defs
}

/// Load signal definitions from patterns.toml without compiling regexes.
fn pattern_signals() -> Vec<SignalDef> {
    let toml_str = include_str!("../../data/patterns.toml");
    let db: PatternDatabase = toml::from_str(toml_str).expect("Failed to parse patterns.toml");

    let mut defs = Vec::new();
    for (section, rules) in &db.sections {
        let category = match section.as_str() {
            "pkgbuild_analysis" | "install_script_analysis" | "source_url_analysis"
            | "gtfobins_analysis" => SignalCategory::Pkgbuild,
            _ => SignalCategory::Pkgbuild, // safe default for any future sections
        };
        for rule in rules {
            defs.push(SignalDef {
                id: rule.id.clone(),
                category,
                points: rule.points,
                description: rule.description.clone(),
                is_override_gate: rule.override_gate,
            });
        }
    }
    defs
}

/// Hardcoded signals defined directly in feature code.
/// Keep in sync when adding/changing signals in feature analyze() methods.
fn hardcoded_signals() -> Vec<SignalDef> {
    use SignalCategory::*;
    let defs: Vec<(&str, SignalCategory, u32, &str, bool)> = vec![
        // metadata_analysis
        ("M-VOTES-ZERO", Metadata, 30, "Package has zero votes", false),
        ("M-VOTES-LOW", Metadata, 20, "Package has very few votes", false),
        ("M-POP-ZERO", Metadata, 25, "Popularity is 0 (no recent usage)", false),
        ("M-NO-MAINTAINER", Metadata, 20, "Package is orphaned (no maintainer)", false),
        ("M-NO-URL", Metadata, 15, "No upstream URL provided", false),
        ("M-NO-LICENSE", Metadata, 10, "No license specified", false),
        ("M-OUT-OF-DATE", Metadata, 5, "Package is flagged as out of date", false),
        // name_analysis
        ("B-NAME-IMPERSONATE", Behavioral, 65, "Name looks like impersonation of a popular package", false),
        ("B-TYPOSQUAT", Behavioral, 55, "Name is suspiciously similar to a popular package", false),
        // maintainer_analysis
        ("B-MAINTAINER-NEW", Behavioral, 30, "Maintainer has only 1 package, created recently", false),
        ("B-MAINTAINER-SINGLE", Behavioral, 15, "Maintainer has only 1 package", false),
        ("B-MAINTAINER-BATCH", Behavioral, 45, "Maintainer created 3+ packages in the last 48 hours", false),
        // orphan_takeover_analysis
        ("B-SUBMITTER-CHANGED", Behavioral, 15, "Package maintainer differs from original submitter", false),
        ("B-ORPHAN-TAKEOVER", Behavioral, 50, "Adopted package with new git author (orphan takeover pattern)", false),
        // bin_source_verification
        ("B-BIN-GITHUB-ORG-MISMATCH", Behavioral, 50, "-bin package source downloads from different GitHub org than upstream", false),
        ("B-BIN-DOMAIN-MISMATCH", Behavioral, 30, "-bin package source downloads from different domain than upstream", false),
        // git_history_analysis
        ("T-SINGLE-COMMIT", Temporal, 20, "Git history has only 1 commit", false),
        ("T-NEW-PACKAGE", Temporal, 25, "Package is very new (< 7 days old)", false),
        ("T-MALICIOUS-DIFF", Temporal, 55, "Latest commit introduces network code not present in prior history", false),
        ("T-AUTHOR-CHANGE", Temporal, 25, "Git history shows multiple different authors", false),
        // aur_comments_analysis
        ("M-COMMENTS-SECURITY", Metadata, 40, "Recent AUR comments contain security-related warnings", false),
        // github_stars
        ("M-GITHUB-STARS-ZERO", Metadata, 20, "Upstream GitHub repo has 0 stars", false),
        ("M-GITHUB-STARS-LOW", Metadata, 10, "Upstream GitHub repo has very few stars (<10)", false),
        ("M-GITHUB-NOT-FOUND", Metadata, 25, "Upstream URL points to GitHub but repo does not exist", false),
        // pkgbuild_diff_analysis
        ("T-DIFF-NEW-SUSPICIOUS", Temporal, 40, "Newly introduced suspicious pattern not in prior version", false),
        ("T-DIFF-CHECKSUM-REMOVED", Temporal, 35, "Checksum array removed or all entries changed to SKIP", false),
        ("T-DIFF-SOURCE-DOMAIN-CHANGED", Temporal, 30, "Source URLs changed to a different domain", false),
        ("T-DIFF-MAJOR-REWRITE", Temporal, 15, ">50% of PKGBUILD lines changed (unusual for version bump)", false),
        // checksum_analysis
        ("P-NO-CHECKSUMS", Pkgbuild, 30, "No checksum array found in PKGBUILD", false),
        ("P-SKIP-ALL", Pkgbuild, 25, "All checksums are SKIP (no integrity verification)", false),
        ("P-WEAK-CHECKSUMS", Pkgbuild, 10, "Using weak checksums (md5/sha1) without stronger alternative", false),
        ("P-CHECKSUM-MISMATCH", Pkgbuild, 25, "Source count != checksum count", false),
        // shell_analysis
        ("SA-VAR-CONCAT-EXEC", Pkgbuild, 85, "Variable concatenation resolves to download-and-execute", true),
        ("SA-VAR-CONCAT-CMD", Pkgbuild, 55, "Variable concatenation resolves to dangerous command", false),
        ("SA-INDIRECT-EXEC", Pkgbuild, 70, "Variable with dangerous command in execution position", false),
        ("SA-CHARBYCHAR-CONSTRUCT", Pkgbuild, 75, "Printf/echo subshell char-by-char command construction", false),
        ("SA-DATA-BLOB-HEX", Pkgbuild, 50, "Embedded long hex string (possible encoded payload)", false),
        ("SA-DATA-BLOB-BASE64", Pkgbuild, 50, "Embedded long base64 string (possible encoded payload)", false),
        ("SA-HIGH-ENTROPY-HEREDOC", Pkgbuild, 55, "Heredoc with high entropy content", false),
        ("SA-BINARY-DOWNLOAD-NOCOMPILE", Pkgbuild, 60, "Downloads file and chmod +x with no compilation step", false),
    ];

    defs.into_iter()
        .map(|(id, cat, pts, desc, gate)| SignalDef {
            id: id.to_string(),
            category: cat,
            points: pts,
            description: desc.to_string(),
            is_override_gate: gate,
        })
        .collect()
}

/// Check if a signal ID is known (either exact match or IS-prefixed variant).
pub fn is_known_signal(id: &str) -> bool {
    let base = id.strip_prefix("IS-").unwrap_or(id);
    all_signal_definitions().iter().any(|d| d.id == base)
}

/// Parse a category name string into a SignalCategory.
pub fn category_from_str(s: &str) -> Option<SignalCategory> {
    match s.to_lowercase().as_str() {
        "metadata" => Some(SignalCategory::Metadata),
        "pkgbuild" => Some(SignalCategory::Pkgbuild),
        "behavioral" => Some(SignalCategory::Behavioral),
        "temporal" => Some(SignalCategory::Temporal),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_pattern_and_hardcoded_signals() {
        let defs = all_signal_definitions();
        // Should have pattern-based signals from patterns.toml
        assert!(defs.iter().any(|d| d.id == "P-CURL-PIPE"));
        // Should have hardcoded signals
        assert!(defs.iter().any(|d| d.id == "M-VOTES-ZERO"));
        assert!(defs.iter().any(|d| d.id == "SA-VAR-CONCAT-EXEC"));
        // Reasonable total count (239 patterns + 32 hardcoded)
        assert!(defs.len() > 250, "Expected 250+ signals, got {}", defs.len());
    }

    #[test]
    fn known_signal_check() {
        assert!(is_known_signal("P-CURL-PIPE"));
        assert!(is_known_signal("IS-SA-VAR-CONCAT-EXEC"));
        assert!(!is_known_signal("NONEXISTENT"));
    }
}
