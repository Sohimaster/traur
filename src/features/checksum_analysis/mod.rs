use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory};
use regex::Regex;

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
        let has_checksums = Regex::new(r"(?m)^(md5|sha1|sha224|sha256|sha384|sha512|b2)sums=")
            .unwrap()
            .is_match(content);

        if !has_checksums && !is_vcs {
            signals.push(Signal {
                id: "P-NO-CHECKSUMS".to_string(),
                category: SignalCategory::Pkgbuild,
                points: 30,
                description: "No checksum array found in PKGBUILD".to_string(),
                is_override_gate: false,
            });
        }

        // Check if all checksums are SKIP (only flag for non-VCS)
        if !is_vcs {
            let skip_re = Regex::new(r"(?m)^(md5|sha\d+|b2)sums=\(\s*'SKIP'").unwrap();
            let non_skip_re =
                Regex::new(r"(?m)^(md5|sha\d+|b2)sums=\(\s*'[0-9a-fA-F]").unwrap();

            if skip_re.is_match(content) && !non_skip_re.is_match(content) {
                signals.push(Signal {
                    id: "P-SKIP-ALL".to_string(),
                    category: SignalCategory::Pkgbuild,
                    points: 25,
                    description: "All checksums are SKIP (no integrity verification)".to_string(),
                    is_override_gate: false,
                });
            }
        }

        // Check for weak md5sums usage
        if Regex::new(r"(?m)^md5sums=").unwrap().is_match(content)
            && !Regex::new(r"(?m)^sha(256|512)sums=").unwrap().is_match(content)
        {
            signals.push(Signal {
                id: "P-WEAK-CHECKSUMS".to_string(),
                category: SignalCategory::Pkgbuild,
                points: 10,
                description: "Using md5sums without stronger alternative".to_string(),
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

/// Count entries in a bash array like source=(...) or sha256sums=(...)
fn count_array_entries(content: &str, array_name: &str) -> usize {
    let pattern = format!(r"(?ms)^{array_name}=\((.*?)\)");
    let re = Regex::new(&pattern).unwrap();
    let Some(caps) = re.captures(content) else {
        return 0;
    };
    let body = &caps[1];
    // Count quoted strings or unquoted non-whitespace tokens
    let entry_re = Regex::new(r#"['"][^'"]*['"]|[^\s'")()]+"#).unwrap();
    entry_re.find_iter(body).count()
}
