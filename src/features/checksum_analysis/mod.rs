use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory};
use regex::Regex;
use std::sync::LazyLock;

static HAS_CHECKSUMS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^(md5|sha1|sha224|sha256|sha384|sha512|b2)sums=").unwrap()
});

static WEAK_CHECKSUMS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^(md5|sha1)sums=").unwrap()
});

static STRONG_CHECKSUMS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^(sha(256|384|512)|b2)sums=").unwrap()
});

static CHECKSUM_ARRAY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?ms)^(md5|sha\d+|b2)sums=\((.*?)\)").unwrap()
});

static ENTRY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"'([^']*)'").unwrap()
});

static TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"['"][^'"]*['"]|[^\s'")()]+"#).unwrap()
});

pub struct ChecksumAnalysis;

impl Feature for ChecksumAnalysis {
    fn name(&self) -> &str {
        "checksum_analysis"
    }

    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        let Some(ref content) = ctx.pkgbuild_content else {
            return Vec::new();
        };

        let mut signals = Vec::new();
        let is_vcs = ctx.name.ends_with("-git")
            || ctx.name.ends_with("-svn")
            || ctx.name.ends_with("-hg")
            || ctx.name.ends_with("-bzr");

        // Check for any checksum arrays
        if !HAS_CHECKSUMS_RE.is_match(content) && !is_vcs {
            signals.push(Signal {
                id: "P-NO-CHECKSUMS".to_string(),
                category: SignalCategory::Pkgbuild,
                points: 30,
                description: "No checksum array found in PKGBUILD".to_string(),
                is_override_gate: false,
            });
        }

        // Check if all checksums are SKIP (only flag for non-VCS)
        if !is_vcs && has_all_skip_checksums(content) {
            signals.push(Signal {
                id: "P-SKIP-ALL".to_string(),
                category: SignalCategory::Pkgbuild,
                points: 25,
                description: "All checksums are SKIP (no integrity verification)".to_string(),
                is_override_gate: false,
            });
        }

        // Check for weak checksums (md5 or sha1) without stronger alternative
        if WEAK_CHECKSUMS_RE.is_match(content) && !STRONG_CHECKSUMS_RE.is_match(content) {
            signals.push(Signal {
                id: "P-WEAK-CHECKSUMS".to_string(),
                category: SignalCategory::Pkgbuild,
                points: 10,
                description: "Using weak checksums (md5/sha1) without stronger alternative"
                    .to_string(),
                is_override_gate: false,
            });
        }

        // Check source count vs checksum count mismatch
        let source_count = count_array_entries(content, "source");
        if source_count > 0 {
            for algo in &["md5sums", "sha256sums", "sha512sums", "b2sums"] {
                let checksum_count = count_array_entries(content, algo);
                if checksum_count > 0 && checksum_count != source_count {
                    signals.push(Signal {
                        id: "P-CHECKSUM-MISMATCH".to_string(),
                        category: SignalCategory::Pkgbuild,
                        points: 40,
                        description: format!(
                            "Source count ({source_count}) != {algo} count ({checksum_count})"
                        ),
                        is_override_gate: false,
                    });
                    break;
                }
            }
        }

        signals
    }
}

/// Check if the package has checksum arrays where ALL entries are 'SKIP'.
fn has_all_skip_checksums(content: &str) -> bool {
    let mut found_any = false;

    for caps in CHECKSUM_ARRAY_RE.captures_iter(content) {
        let body = &caps[2];
        let entries: Vec<&str> = ENTRY_RE
            .captures_iter(body)
            .map(|c| c.get(1).unwrap().as_str())
            .collect();

        if entries.is_empty() {
            continue;
        }

        found_any = true;

        // If any array has a non-SKIP entry, the package has real checksums
        if entries.iter().any(|e| *e != "SKIP") {
            return false;
        }
    }

    found_any
}

/// Count entries in a bash array like source=(...) or sha256sums=(...)
fn count_array_entries(content: &str, array_name: &str) -> usize {
    let pattern = format!(r"(?ms)^{array_name}=\((.*?)\)");
    let re = Regex::new(&pattern).unwrap();
    let Some(caps) = re.captures(content) else {
        return 0;
    };
    let body = &caps[1];
    TOKEN_RE.find_iter(body).count()
}
