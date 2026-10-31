//! Lightweight shell normalisation for pattern matching.
//!
//! Patterns are regexes over source text, so anything that changes the bytes
//! without changing the executed command evades them. The most common case is
//! quote splitting: `cu""rl -s x | ba""sh` runs `curl -s x | bash`, but the
//! literal substring `curl` never appears in the source.
//!
//! This module removes the quoting that bash would remove anyway, so that the
//! remaining text contains the command bash will actually run. It is not a
//! shell parser: `$'...'` escapes, nested `$(...)`, heredocs and runtime
//! variable values are all out of scope. It handles the quoting forms that
//! actually show up in PKGBUILD obfuscation.

/// Remove concatenating quotes from shell source.
///
/// Adjacent quoted segments are joined, which turns `cu""rl`, `c"url"` and
/// `'cu'rl` into `curl`. Single quotes, double quotes and backslashes that
/// escape a quote inside a quoted string are handled.
///
/// The returned string has the same line structure as the input: newlines are
/// always preserved so that line-oriented callers keep their line numbers.
pub fn strip_quotes(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let mut quote: Option<char> = None;

    while i < chars.len() {
        let c = chars[i];

        match quote {
            // Inside '...' everything is literal, and the closing quote ends it.
            Some('\'') => {
                if c == '\'' {
                    quote = None;
                } else {
                    out.push(c);
                }
            }
            // Inside "...": backslash escapes only $ ` " \ and newline.
            Some('"') => {
                if c == '\\' && i + 1 < chars.len() {
                    let next = chars[i + 1];
                    if matches!(next, '$' | '`' | '"' | '\\') {
                        out.push(next);
                        i += 2;
                        continue;
                    }
                    out.push('\\');
                } else if c == '"' {
                    quote = None;
                } else {
                    out.push(c);
                }
            }
            // Unquoted: quotes open a quoted region and are dropped.
            _ => match c {
                '\'' | '"' => quote = Some(c),
                '\\' if i + 1 < chars.len() => {
                    // Backslash outside quotes escapes the next character.
                    let next = chars[i + 1];
                    if next == '\n' {
                        // Line continuation: drop both.
                        i += 2;
                        continue;
                    }
                    out.push(next);
                    i += 2;
                    continue;
                }
                _ => out.push(c),
            },
        }

        i += 1;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejoins_split_command_names() {
        assert_eq!(strip_quotes(r#"cu""rl -s x | ba""sh"#), "curl -s x | bash");
        assert_eq!(strip_quotes(r#"c"url" -O x"#), "curl -O x");
        assert_eq!(strip_quotes(r#"'cu'rl x"#), "curl x");
        assert_eq!(strip_quotes(r#"s"ud"o rm"#), "sudo rm");
    }

    #[test]
    fn strips_normal_quoted_arguments() {
        assert_eq!(strip_quotes(r#"echo "hello world""#), "echo hello world");
        assert_eq!(strip_quotes(r#"echo 'a b'"#), "echo a b");
    }

    #[test]
    fn keeps_single_quoted_content_literal() {
        // A double quote inside single quotes is data, not a quote delimiter.
        assert_eq!(strip_quotes(r#"echo '"'"#), "echo \"");
    }

    #[test]
    fn preserves_newlines_and_line_count() {
        let input = "cu\"\"rl x | ba\"\"sh\necho \"a\"\n";
        let out = strip_quotes(input);
        assert_eq!(out.lines().count(), input.lines().count());
        assert!(out.contains('\n'));
    }

    #[test]
    fn handles_line_continuation() {
        assert_eq!(strip_quotes("curl \\\n  -O x"), "curl   -O x");
    }

    #[test]
    fn unquoted_text_is_unchanged() {
        let s = "make -j4 && cd $srcdir";
        assert_eq!(strip_quotes(s), s);
    }

    #[test]
    fn preserves_utf8_content() {
        // AUR PKGBUILDs carry non-ASCII in comments and descriptions.
        let input = "# Contributor: Özgür Sarıer\npkgdesc='fixes для браузера'\ncu\"\"rl x | ba\"\"sh\n";
        let out = strip_quotes(input);
        assert!(out.contains("Özgür Sarıer"), "utf8 mangled: {out:?}");
        assert!(out.contains("для браузера"), "utf8 mangled: {out:?}");
        assert!(out.contains("curl x | bash"));
    }

    #[test]
    fn unmatched_quote_does_not_panic() {
        assert_eq!(strip_quotes(r#"echo "unterminated"#), "echo unterminated");
    }
}
