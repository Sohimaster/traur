//! The single normalized view of a script that every feature matches against.
//!
//! Before this module existed, checksum masking and header-comment masking
//! lived only in `pkgbuild_analysis`, so the gtfobins, install-script, shell
//! and diff features matched raw text. That is why the `google-chrome` wallet
//! false positive (#27) could be fixed for one pattern set and keep recurring
//! on another. Features now declare which views they read and never touch the
//! raw source directly.
//!
//! Three views are derived, all with the same line structure as the input so
//! line numbers and `matched_line` extraction keep working:
//!
//! - `raw`: untouched source.
//! - `masked`: checksum arrays and heredoc bodies replaced with `x`, and the
//!   leading comment block blanked. These hold only data bash cannot execute
//!   as code in the enclosing context, so patterns must not match them.
//! - `plain`: `masked` with the quoting bash would remove already removed, so
//!   `cu""rl` reads as `curl`.
//!
//! Masking preserves character length exactly, including newlines.

use crate::shared::regions::{self, RegionKind, ScriptStructure};
use crate::shared::shell_normalize;

/// The text a feature should match against.
#[derive(Debug, Clone)]
pub struct NormalizedView {
    raw: String,
    masked: String,
    plain: String,
    structure: ScriptStructure,
    /// Character offsets where masking actually changed content.
    masked_ranges: Vec<std::ops::Range<usize>>,
}

impl NormalizedView {
    /// Derive all views for one script.
    pub fn new(raw: &str) -> Self {
        let structure = regions::parse(raw);
        let mut masked = raw.to_string();
        let mut masked_ranges = Vec::new();

        // Checksum arrays: hashes are opaque data. A 128-char sha512 can
        // contain anything that looks like a wallet address or an IP address.
        for span in structure.array_ranges() {
            blank(&mut masked, span.clone());
            masked_ranges.push(span);
        }

        // Heredoc bodies are literal data. The opening line (`cat <<EOF > x`)
        // stays readable; only the body is blanked.
        for region in &structure.regions {
            let is_heredoc = region
                .name
                .as_deref()
                .is_some_and(|n| n.starts_with("heredoc:"));
            if is_heredoc {
                blank(&mut masked, region.span.clone());
                masked_ranges.push(region.span.clone());
            }
        }

        // The leading comment block holds maintainer headers, which sometimes
        // carry base64-encoded email addresses to evade scrapers (#12). Only
        // the *leading* block is blanked: a `#` further down may be inside a
        // multiline string where it is not a comment.
        if let Some(span) = leading_comment_span(raw) {
            blank(&mut masked, span.clone());
            masked_ranges.push(span);
        }

        let plain = shell_normalize::strip_quotes(&masked);

        NormalizedView {
            raw: raw.to_string(),
            masked,
            plain,
            structure,
            masked_ranges,
        }
    }

    /// The untouched source.
    #[allow(dead_code)] // exposed for callers that need the original bytes
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Source with non-executable data blanked.
    pub fn masked(&self) -> &str {
        &self.masked
    }

    /// `masked` with quoting removed.
    pub fn plain(&self) -> &str {
        &self.plain
    }

    /// The region structure, for composites that need scoping.
    pub fn structure(&self) -> &ScriptStructure {
        &self.structure
    }

    /// Whether the text balanced enough for region scoping to be trusted.
    #[allow(dead_code)] // part of the view's public contract
    pub fn structure_ok(&self) -> bool {
        self.structure.structure_ok
    }

    /// True when `range` overlaps a masked span, i.e. the match is data.
    ///
    /// Callers use this when they want to reject a match that only exists
    /// because a pattern reached into a checksum array or heredoc body.
    pub fn is_masked_at(&self, range: &std::ops::Range<usize>) -> bool {
        self.masked_ranges
            .iter()
            .any(|m| m.start < range.end && range.start < m.end)
    }

    /// First line matching `pattern`, preferring a line that differs between
    /// raw and masked text. Used for `matched_line` in reports.
    pub fn first_matching_line(&self, re: &regex::Regex) -> Option<String> {
        self.masked
            .lines()
            .zip(self.raw.lines())
            .find(|(masked_line, _)| re.is_match(masked_line))
            .map(|(_, raw_line)| raw_line.trim().to_string())
            .or_else(|| {
                self.plain
                    .lines()
                    .zip(self.raw.lines())
                    .find(|(plain_line, _)| re.is_match(plain_line))
                    .map(|(_, raw_line)| raw_line.trim().to_string())
            })
    }
}

/// Replace every character except newlines with `x`, preserving offsets.
fn blank(text: &mut String, span: std::ops::Range<usize>) {
    let mut chars: Vec<char> = std::mem::take(text).chars().collect();
    let end = span.end.min(chars.len());
    for c in chars.iter_mut().take(end).skip(span.start) {
        if *c != '\n' {
            *c = 'x';
        }
    }
    *text = chars.into_iter().collect();
}

/// Character span of the leading run of comment and blank lines.
///
/// Returns `None` when the file starts with code, so a `#` later in the file
/// is never treated as a header comment.
fn leading_comment_span(raw: &str) -> Option<std::ops::Range<usize>> {
    let mut offset = 0usize;
    let mut end = 0usize;
    let mut saw_comment = false;

    for line in raw.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let is_blank = trimmed.trim().is_empty();
        let is_comment = trimmed.starts_with('#');
        if is_comment {
            saw_comment = true;
        }
        if !is_blank && !is_comment {
            break;
        }
        end = offset + line.chars().count();
        offset = end;
    }

    if saw_comment && end > 0 {
        Some(0..end)
    } else {
        None
    }
}

/// Whether a function-body region's body is mostly a heredoc, used by
/// composites that need to know whether a body has real statements.
pub fn has_statements(view: &NormalizedView) -> bool {
    view.structure()
        .regions
        .iter()
        .any(|r| r.kind == RegionKind::Function && r.name.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;
    use std::sync::LazyLock;

    static WALLET: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\bbc1[a-zA-HJ-NP-Z0-9]{39,59}\b").unwrap()
    });
    static BASE64_EMAIL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"echo\s+[A-Za-z0-9+/]{8,}={0,2}\s*\|\s*base64\s+-d").unwrap()
    });
    static CURL_PIPE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"curl\s+[^|\n]*\|\s*(ba)?sh").unwrap());

    // 42 chars after the bc1 prefix, which is the minimum the pattern accepts.
    const WALLET_HASH: &str =
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq88ff9";

    #[test]
    fn wallet_inside_checksum_array_is_masked() {
        let text = format!("pkgname=x\nsha512sums=('{WALLET_HASH}')\nbuild() {{\n :\n}}\n");
        let view = NormalizedView::new(&text);
        assert!(!WALLET.is_match(view.masked()), "checksum must be masked");
        assert!(WALLET.is_match(view.raw()), "raw still contains the hash");
    }

    #[test]
    fn wallet_in_function_body_is_not_masked() {
        let text = format!("build() {{\n  echo {WALLET_HASH}\n}}\n");
        let view = NormalizedView::new(&text);
        assert!(WALLET.is_match(view.masked()), "code must stay visible");
    }

    #[test]
    fn header_base64_is_masked_but_body_base64_is_not() {
        let header = "# Maintainer: someone <$(echo bnhoc2R1QHFxLmNvbQo= | base64 -d)>\n";
        let body = "build() {\n  echo c2FuZGFydWthc2ErYXVyQHlhLnJ1Cg== | base64 -d\n}\n";
        let view = NormalizedView::new(&format!("{header}{body}"));
        let header_line = view.masked().lines().next().unwrap();
        assert!(
            !BASE64_EMAIL.is_match(header_line),
            "header comment must be blanked: {header_line}"
        );
        assert!(
            BASE64_EMAIL.is_match(view.masked()),
            "build() base64 must still match"
        );
    }

    #[test]
    fn masking_preserves_line_count_and_length() {
        let text = format!(
            "# Maintainer: x\npkgname=x\nsha256sums=('{}')\nbuild() {{\n  :\n}}\n",
            "a".repeat(64)
        );
        let view = NormalizedView::new(&text);
        assert_eq!(view.masked().lines().count(), text.lines().count());
        assert_eq!(view.masked().chars().count(), text.chars().count());
        assert_eq!(view.plain().lines().count(), text.lines().count());
    }

    #[test]
    fn quote_splitting_is_visible_in_plain() {
        let view = NormalizedView::new("build() {\n  cu\"\"rl -s x | ba\"\"sh\n}\n");
        assert!(!CURL_PIPE.is_match(view.masked()));
        assert!(CURL_PIPE.is_match(view.plain()));
    }

    #[test]
    fn hash_comment_later_in_file_is_not_masked() {
        // A `#` after code starts is not a header comment.
        let text = "pkgname=x\n# sha256 inside comment\ncurl x | bash\n";
        let view = NormalizedView::new(text);
        assert!(view.masked().contains("# sha256 inside comment"));
    }

    #[test]
    fn array_containing_subshell_is_fully_masked() {
        // Regression for the old `[^)]*` regex which left the tail unmasked.
        let text = format!(
            "source=(\"a::https://x/$(echo 1)\" '{WALLET_HASH}')\nbuild() {{\n :\n}}\n"
        );
        let view = NormalizedView::new(&text);
        assert!(!WALLET.is_match(view.masked()), "tail of array must be masked");
    }

    #[test]
    fn unterminated_file_still_normalizes() {
        let view = NormalizedView::new("build() {\n  cu\"\"rl x | sh\n");
        assert!(!view.structure_ok());
        assert!(CURL_PIPE.is_match(view.plain()));
    }
}
