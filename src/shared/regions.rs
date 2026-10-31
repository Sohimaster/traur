//! Lexical regions of a shell script (PKGBUILD or `.install`).
//!
//! Patterns are regexes over source text, so distinguishing "this line runs"
//! from "this line is data" needs a view of the file's structure. This module
//! provides that view without a shell parser: a state machine over quotes,
//! `${...}`, comments and heredocs that splits the file into function bodies,
//! array data and everything else.
//!
//! It is deliberately conservative. `structure_ok` is false when the text does
//! not balance (an unterminated function, an unbalanced array), and callers
//! must then treat the whole file as executable code. Guessing wrong towards
//! "code" costs false positives; guessing wrong towards "data" would hide a
//! payload, so the fallback never classifies anything as data.

use std::ops::Range;

/// What kind of source a region holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    /// A function body: `build()`, `package()`, `package_$pkgname()`, `.install` hooks.
    Function,
    /// An array assignment: `source=(...)`, `sha256sums=(...)`.
    Array,
}

/// A contiguous character range of the analysed text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region {
    pub kind: RegionKind,
    /// Function name for `Function` regions, variable name for `Array` regions.
    pub name: Option<String>,
    /// Character offsets, end exclusive.
    pub span: Range<usize>,
    /// Ordering hint for callers that need deterministic ordering (e.g. heredoc ids).
    pub index: usize,
}

impl Region {
}

/// The structural view of one script.
#[derive(Debug, Clone)]
pub struct ScriptStructure {
    pub regions: Vec<Region>,
    /// False when the text did not balance; callers must treat everything as code.
    pub structure_ok: bool,
}

impl ScriptStructure {
    /// A structure that makes the whole text one executable region.
    pub fn whole_file_as_code(len: usize) -> Self {
        // A single range covering the file: the fallback must classify the
        // whole file as code, so this is intentionally not an empty list.
        #[allow(clippy::single_range_in_vec_init)]
        ScriptStructure {
            regions: vec![Region {
                kind: RegionKind::Function,
                name: None,
                span: 0..len,
                index: 0,
            }],
            structure_ok: false,
        }
    }

    /// Character ranges that hold executable code.
    #[allow(dead_code)] // part of the structure's contract; used by callers that
    // want only function bodies rather than the broader statement ranges.
    ///
    /// When `structure_ok` is false this is the whole file: the fallback must
    /// never narrow the search space for a payload.
    pub fn executable_ranges(&self) -> Vec<Range<usize>> {
        if !self.structure_ok {
            return vec![0..self.regions.last().map_or(0, |r| r.span.end)];
        }
        self.regions
            .iter()
            .filter(|r| r.kind == RegionKind::Function)
            .map(|r| r.span.clone())
            .collect()
    }

    /// Character ranges that may contain executable statements.
    ///
    /// Function bodies plus top-level text. Array and heredoc regions are
    /// excluded because they are data. A sourced config file or a build step
    /// can run a pipeline with no function wrapper, which a strict
    /// inside-a-function rule would miss.
    pub fn statement_ranges(&self) -> Vec<Range<usize>> {
        if !self.structure_ok {
            return vec![0..self.regions.last().map_or(0, |r| r.span.end)];
        }
        let data: Vec<Range<usize>> = self
            .regions
            .iter()
            .filter(|r| r.kind == RegionKind::Array)
            .map(|r| r.span.clone())
            .collect();
        // Everything outside the data spans, as a set of gaps.
        let mut spans: Vec<Range<usize>> = self
            .regions
            .iter()
            .filter(|r| r.kind == RegionKind::Function)
            .map(|r| r.span.clone())
            .collect();
        let end = self.regions.iter().map(|r| r.span.end).max().unwrap_or(0);
        spans.push(0..end);
        let mut out = Vec::new();
        for span in spans {
            let mut cursor = span.start;
            for d in &data {
                if d.end <= span.start || d.start >= span.end {
                    continue;
                }
                if cursor < d.start {
                    out.push(cursor..d.start);
                }
                cursor = cursor.max(d.end);
            }
            if cursor < span.end {
                out.push(cursor..span.end);
            }
        }
        out
    }

    /// Character ranges that hold array data.
    pub fn array_ranges(&self) -> Vec<Range<usize>> {
        if !self.structure_ok {
            return Vec::new();
        }
        self.regions
            .iter()
            .filter(|r| r.kind == RegionKind::Array)
            .map(|r| r.span.clone())
            .collect()
    }

    /// The name of the innermost function region containing `pos`.
    #[allow(dead_code)] // used by tests and by future per-subpackage reporting
    pub fn function_at(&self, pos: usize) -> Option<&str> {
        self.regions
            .iter()
            .filter(|r| r.kind == RegionKind::Function && r.span.contains(&pos))
            .filter_map(|r| r.name.as_deref())
            .next()
    }
}

/// Characters, not bytes, so offsets are directly usable with `chars()`.
#[derive(Clone, Copy)]
struct Chars<'a> {
    chars: &'a [char],
}

impl<'a> Chars<'a> {
    fn at(&self, i: usize) -> Option<char> {
        self.chars.get(i).copied()
    }

    /// Find the end of a string starting at `i` (the index of the opening quote).
    fn skip_string(&self, mut i: usize, quote: char) -> Option<usize> {
        i += 1;
        while let Some(c) = self.at(i) {
            if quote == '"' && c == '\\' {
                i += 2;
                continue;
            }
            if c == quote {
                return Some(i + 1);
            }
            if c == '\n' && quote != '\'' {
                // A newline inside an unquoted-continuation string is legal but
                // unusual; keep scanning so we do not mis-split statements.
            }
            i += 1;
        }
        None
    }

    /// Find the end of a comment starting at `i` (the index of `#`).
    fn skip_comment(&self, mut i: usize) -> usize {
        while let Some(c) = self.at(i) {
            if c == '\n' {
                return i;
            }
            i += 1;
        }
        i
    }

    /// Find the `)` matching the `(` at `i`, skipping nested strings and `$()`.
    fn matching_paren(&self, i: usize) -> Option<usize> {
        let mut depth = 0usize;
        let mut j = i;
        while let Some(c) = self.at(j) {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(j);
                    }
                }
                '\'' | '"' => match self.skip_string(j, c) {
                    Some(end) => {
                        j = end;
                        continue;
                    }
                    None => return None,
                },
                '#' => {
                    j = self.skip_comment(j);
                    continue;
                }
                _ => {}
            }
            j += 1;
        }
        None
    }

    /// Find the `}` matching the `{` at `i`, skipping nested braces and strings.
    fn matching_brace(&self, i: usize) -> Option<usize> {
        let mut depth = 0usize;
        let mut j = i;
        while let Some(c) = self.at(j) {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(j);
                    }
                }
                '\'' | '"' => match self.skip_string(j, c) {
                    Some(end) => {
                        j = end;
                        continue;
                    }
                    None => return None,
                },
                '#' => {
                    // A `#` mid-word is not a comment (e.g. URL fragments).
                    let prev = self.chars.get(j.wrapping_sub(1)).copied();
                    let is_comment = j == 0 || matches!(prev, Some(' ') | Some('\n') | Some('\t'));
                    if is_comment {
                        j = self.skip_comment(j);
                        continue;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        None
    }

    /// Skip a heredoc body started by `<<DELIM` at `i`, returning the index
    /// after the terminating delimiter line.
    fn skip_heredoc(&self, i: usize, delim: &str) -> Option<usize> {
        let mut j = i;
        // Advance to the end of the current line first.
        while let Some(c) = self.at(j) {
            if c == '\n' {
                j += 1;
                break;
            }
            j += 1;
        }
        while j < self.chars.len() {
            let line_start = j;
            while j < self.chars.len() && self.chars[j] != '\n' {
                j += 1;
            }
            let line: String = self.chars[line_start..j].iter().collect();
            if line.trim().trim_start_matches('\t') == delim {
                return Some(j);
            }
            j += 1; // skip newline
        }
        None
    }
}

/// Split a script into regions.
///
/// Recognised constructs:
/// - `name() {` / `function name {` / `function name() {` function bodies
/// - `name=(` array assignments, including `+=` and `name_arch=(`
/// - heredoc bodies (`<<EOF`), which are data
/// - strings and comments, which are skipped so their contents cannot
///   open a region
pub fn parse(text: &str) -> ScriptStructure {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let src = Chars { chars: &chars };
    let mut regions: Vec<Region> = Vec::new();
    let mut i = 0usize;
    let mut ok = true;
    let mut index = 0usize;

    while i < n {
        let c = chars[i];

        // Skip strings and comments so their contents are not parsed as syntax.
        if c == '\'' || c == '"' {
            match src.skip_string(i, c) {
                Some(end) => {
                    i = end;
                    continue;
                }
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if c == '#' {
            i = src.skip_comment(i);
            continue;
        }

        // Heredoc: data, not code. Skip to the terminating delimiter.
        if c == '<' && chars.get(i + 1) == Some(&'<') && chars.get(i + 2) != Some(&'<') {
            if let Some((delim, after)) = read_heredoc_delimiter(src, i + 2) {
                match src.skip_heredoc(after, &delim) {
                    Some(end) => {
                        index += 1;
                        regions.push(Region {
                            kind: RegionKind::Array,
                            name: Some(format!("heredoc:{delim}")),
                            span: i..end,
                            index,
                        });
                        i = end;
                        continue;
                    }
                    None => {
                        ok = false;
                        break;
                    }
                }
            }
        }

        // Identifier at the start of a line, followed by `()` and `{`.
        if c.is_alphabetic() || c == '_' {
            let starts_line = {
                let mut k = i;
                while k > 0 && matches!(chars[k - 1], ' ' | '\t') {
                    k -= 1;
                }
                k == 0 || chars[k - 1] == '\n' || chars[k - 1] == ';'
            };
            let mut j = i;
            while j < n && (chars[j].is_alphanumeric() || matches!(chars[j], '_' | '-' | '.' | '+')) {
                j += 1;
            }
            let word: String = chars[i..j].iter().collect();

            if starts_line {
                // `name=(...)` array
                let mut k = j;
                while k < n && matches!(chars[k], ' ' | '\t') {
                    k += 1;
                }
                let mut plus = false;
                if k < n && chars[k] == '+' && chars.get(k + 1) == Some(&'=') {
                    plus = true;
                    k += 1;
                }
                if k < n && chars[k] == '=' && chars.get(k + 1) == Some(&'(') {
                    let open = k + 1;
                    match src.matching_paren(open) {
                        Some(close) => {
                            index += 1;
                            regions.push(Region {
                                kind: RegionKind::Array,
                                name: Some(word.clone()),
                                span: open..close + 1,
                                index,
                            });
                            i = close + 1;
                            continue;
                        }
                        None => {
                            ok = false;
                            break;
                        }
                    }
                }
                let _ = plus;

                // `name() {` or `function name() {` or `function name {`
                let mut k = j;
                while k < n && matches!(chars[k], ' ' | '\t') {
                    k += 1;
                }
                let mut has_parens = false;
                if k < n && chars[k] == '(' {
                    if let Some(close) = src.matching_paren(k) {
                        let empty = chars[k + 1..close].iter().all(|c| c.is_whitespace());
                        if empty {
                            has_parens = true;
                            k = close + 1;
                        }
                    }
                }
                let name_ok = has_parens || word == "function";
                if name_ok {
                    while k < n && matches!(chars[k], ' ' | '\t' | '\n') {
                        k += 1;
                    }
                    // `function name {` form: the word is `function`, the name is next.
                    let mut fname = word.clone();
                    if word == "function" {
                        let mut m = j;
                        while m < n && matches!(chars[m], ' ' | '\t') {
                            m += 1;
                        }
                        let start = m;
                        while m < n && (chars[m].is_alphanumeric() || matches!(chars[m], '_' | '-' | '.' | '+')) {
                            m += 1;
                        }
                        fname = chars[start..m].iter().collect();
                        let mut mm = m;
                        while mm < n && matches!(chars[mm], ' ' | '\t') {
                            mm += 1;
                        }
                        if mm < n && chars[mm] == '(' {
                            if let Some(close) = src.matching_paren(mm) {
                                mm = close + 1;
                            }
                        }
                        k = mm;
                        while k < n && matches!(chars[k], ' ' | '\t' | '\n') {
                            k += 1;
                        }
                    }
                    if k < n && chars[k] == '{' {
                        match src.matching_brace(k) {
                            Some(close) => {
                                index += 1;
                                regions.push(Region {
                                    kind: RegionKind::Function,
                                    name: Some(fname),
                                    span: k..close + 1,
                                    index,
                                });
                                // Heredoc bodies inside the function are data.
                                // Skipping them here keeps a `}` in a payload
                                // from ending the function, and lets callers
                                // mask the body instead of matching inside it.
                                for (hstart, hend, delim) in heredocs_in(&src, k, close) {
                                    index += 1;
                                    regions.push(Region {
                                        kind: RegionKind::Array,
                                        name: Some(format!("heredoc:{delim}")),
                                        span: hstart..hend,
                                        index,
                                    });
                                }
                                i = close + 1;
                                continue;
                            }
                            None => {
                                ok = false;
                                break;
                            }
                        }
                    }
                }
            }

            i = j;
            continue;
        }

        i += 1;
    }

    if regions.is_empty() || !ok {
        // Nothing to work with, or the file did not balance. Callers must see
        // the whole file as code.
        return ScriptStructure::whole_file_as_code(n);
    }

    ScriptStructure {
        regions,
        structure_ok: ok,
    }
}


/// Find heredoc bodies between `start` and `end`.
///
/// Returns `(start, end, delimiter)` where the span covers the body up to and
/// including the terminating delimiter line.
fn heredocs_in(src: &Chars, start: usize, end: usize) -> Vec<(usize, usize, String)> {
    let mut found = Vec::new();
    let mut i = start;
    while i < end {
        let c = src.at(i);
        // Skip strings so `echo "<<EOF"` does not register.
        if c == Some('\'') || c == Some('"') {
            match src.skip_string(i, c.unwrap()) {
                Some(next) => {
                    i = next;
                    continue;
                }
                None => break,
            }
        }
        if c == Some('#') {
            i = src.skip_comment(i);
            continue;
        }
        if c == Some('<') && src.at(i + 1) == Some('<') && src.at(i + 2) != Some('<') {
            if let Some((delim, after)) = read_heredoc_delimiter(*src, i + 2) {
                if let Some(body_end) = src.skip_heredoc(after, &delim) {
                    if body_end <= end {
                        found.push((i, body_end, delim));
                        i = body_end;
                        continue;
                    }
                }
            }
        }
        i += 1;
    }
    found
}

/// Read `<<EOF`, `<<'EOF'`, `<<-EOF` starting at `i` (index just after `<<`).
/// Returns the delimiter and the index at which the body starts.
fn read_heredoc_delimiter(src: Chars, mut i: usize) -> Option<(String, usize)> {
    if src.at(i) == Some('-') {
        i += 1;
    }
    while matches!(src.at(i), Some(' ') | Some('\t')) {
        i += 1;
    }
    let quote = match src.at(i) {
        Some(c @ ('\'' | '"')) => {
            i += 1;
            Some(c)
        }
        _ => None,
    };
    let start = i;
    while let Some(c) = src.at(i) {
        if c.is_alphanumeric() || c == '_' {
            i += 1;
        } else {
            break;
        }
    }
    if i == start {
        return None;
    }
    let delim: String = src.chars[start..i].iter().collect();
    if let Some(q) = quote {
        if src.at(i) != Some(q) {
            return None;
        }
        i += 1;
    }
    Some((delim, i))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn funcs(s: &ScriptStructure) -> Vec<String> {
        s.regions
            .iter()
            .filter(|r| r.kind == RegionKind::Function)
            .filter_map(|r| r.name.clone())
            .collect()
    }

    #[test]
    fn finds_standard_functions() {
        let text = "build() {\n  make\n}\n\npackage() {\n  make install\n}\n";
        let s = parse(text);
        assert!(s.structure_ok);
        assert_eq!(funcs(&s), vec!["build", "package"]);
    }

    #[test]
    fn finds_split_package_functions_with_hyphens() {
        let text = "package_foo() {\n  :\n}\npackage_foo-extra() {\n  :\n}\n";
        let s = parse(text);
        assert_eq!(funcs(&s), vec!["package_foo", "package_foo-extra"]);
    }

    #[test]
    fn finds_function_keyword_forms() {
        let text = "function build {\n :\n}\nfunction prepare() {\n :\n}\n";
        let s = parse(text);
        assert!(s.structure_ok, "{s:?}");
        assert_eq!(funcs(&s), vec!["build", "prepare"]);
    }

    #[test]
    fn arrays_are_data() {
        let text = "source=('a' 'b')\nsha256sums_x86_64=('x')\nbuild() {\n :\n}\n";
        let s = parse(text);
        let arrays: Vec<_> = s
            .regions
            .iter()
            .filter(|r| r.kind == RegionKind::Array)
            .map(|r| r.name.clone().unwrap())
            .collect();
        assert_eq!(arrays, vec!["source", "sha256sums_x86_64"]);
    }

    #[test]
    fn array_with_parens_inside_is_masked_whole() {
        // The old regex stopped at the first `)`, leaving the tail unmasked.
        let text = "source=(\"a::https://x/$(echo 1)\" 'b')\nbuild() {\n :\n}\n";
        let s = parse(text);
        let arr = s
            .regions
            .iter()
            .find(|r| r.kind == RegionKind::Array)
            .expect("array");
        let body: String = text
            .chars()
            .skip(arr.span.start)
            .take(arr.span.end - arr.span.start)
            .collect();
        assert!(body.contains("'b'"), "array span should include the tail: {body}");
    }

    #[test]
    fn brace_inside_string_does_not_end_function() {
        let text = "build() {\n  echo \"}\"\n  echo ok\n}\npackage() {\n :\n}\n";
        let s = parse(text);
        assert!(s.structure_ok);
        assert_eq!(funcs(&s), vec!["build", "package"]);
    }

    #[test]
    fn brace_inside_heredoc_does_not_end_function() {
        let text = "build() {\n  cat <<EOF > x\n}\nEOF\n  echo done\n}\npackage() {\n :\n}\n";
        let s = parse(text);
        assert!(s.structure_ok, "{s:?}");
        assert_eq!(funcs(&s), vec!["build", "package"]);
    }

    #[test]
    fn parameter_expansion_braces_are_not_function_braces() {
        let text = "build() {\n  echo \"${foo}\" ${bar}\n}\n";
        let s = parse(text);
        assert!(s.structure_ok);
        assert_eq!(funcs(&s), vec!["build"]);
    }

    #[test]
    fn unterminated_function_falls_back_to_whole_file() {
        let text = "build() {\n  make\n";
        let s = parse(text);
        assert!(!s.structure_ok);
        assert_eq!(s.executable_ranges(), vec![0..text.chars().count()]);
    }

    #[test]
    fn no_functions_means_whole_file_is_code() {
        let text = "curl x | bash\n";
        let s = parse(text);
        assert!(!s.structure_ok);
        assert_eq!(s.executable_ranges().len(), 1);
    }

    #[test]
    fn hash_in_url_is_not_a_comment() {
        let text = "source=('https://x/y#frag')\nbuild() {\n :\n}\npackage() {\n :\n}\n";
        let s = parse(text);
        assert!(s.structure_ok, "{s:?}");
        assert_eq!(funcs(&s), vec!["build", "package"]);
    }

    #[test]
    fn function_at_maps_position() {
        let text = "build() {\n  x\n}\npackage() {\n  y\n}\n";
        let s = parse(text);
        let pos = text.find('y').unwrap();
        // char offset, so convert
        let char_pos = text[..pos].chars().count();
        assert_eq!(s.function_at(char_pos), Some("package"));
    }
}
