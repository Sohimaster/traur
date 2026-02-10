use crate::shared::models::GitCommit;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const AUR_GIT_BASE: &str = "https://aur.archlinux.org";
const GIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Clone or update the AUR git repo for a package. Returns the local path.
pub fn ensure_repo(package_base: &str, cache_dir: &str) -> Result<PathBuf, String> {
    if package_base.is_empty()
        || !package_base
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+' | '@'))
        || package_base.contains("..")
    {
        return Err(format!("invalid package name: {package_base}"));
    }

    let repo_path = PathBuf::from(cache_dir).join(package_base);

    if repo_path.join(".git").exists() {
        // Pull latest
        let output = run_with_timeout(
            Command::new("git")
                .args(["pull", "--ff-only"])
                .current_dir(&repo_path),
        )?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("git pull failed: {stderr}"));
        }
    } else {
        // Shallow clone
        let url = format!("{AUR_GIT_BASE}/{package_base}.git");
        let output = run_with_timeout(
            Command::new("git")
                .args(["clone", "--depth=50", &url, repo_path.to_str().unwrap()]),
        )?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("git clone failed: {stderr}"));
        }
    }

    Ok(repo_path)
}

/// Run a command with a timeout. Kills the process if it exceeds GIT_TIMEOUT.
fn run_with_timeout(cmd: &mut Command) -> Result<Output, String> {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn git: {e}"))?;

    let start = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child
                    .wait_with_output()
                    .map_err(|e| format!("git failed: {e}"));
            }
            Ok(None) => {
                if start.elapsed() > GIT_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "git operation timed out after {}s",
                        GIT_TIMEOUT.as_secs()
                    ));
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => return Err(format!("failed to wait for git: {e}")),
        }
    }
}

/// Read PKGBUILD content from a cloned repo.
pub fn read_pkgbuild(repo_path: &std::path::Path) -> Result<String, String> {
    std::fs::read_to_string(repo_path.join("PKGBUILD"))
        .map_err(|e| format!("Failed to read PKGBUILD: {e}"))
}

/// Read .install script if present.
pub fn read_install_script(repo_path: &std::path::Path, pkgbuild_content: &str) -> Option<String> {
    // Try to find install= directive in PKGBUILD
    for line in pkgbuild_content.lines() {
        let trimmed = line.trim();
        if let Some(install_file) = trimmed.strip_prefix("install=") {
            let install_file = install_file.trim_matches(|c| c == '\'' || c == '"');
            return std::fs::read_to_string(repo_path.join(install_file)).ok();
        }
    }

    // Fallback: check common names
    for name in &[
        format!("{}.install", repo_path.file_name()?.to_str()?),
        "install".to_string(),
    ] {
        let path = repo_path.join(name);
        if path.exists() {
            return std::fs::read_to_string(path).ok();
        }
    }

    None
}

/// Parse git log into structured commits.
pub fn read_git_log(repo_path: &std::path::Path, max_commits: usize) -> Vec<GitCommit> {
    let output = Command::new("git")
        .args([
            "log",
            &format!("-{max_commits}"),
            "--format=%H%n%an%n%at%n%s%n---END---",
        ])
        .current_dir(repo_path)
        .output();

    let Ok(output) = output else {
        return Vec::new();
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut commits = Vec::new();

    let mut lines = stdout.lines().peekable();
    while lines.peek().is_some() {
        // hash
        match lines.next() {
            Some(h) if !h.is_empty() => {}
            _ => break,
        };
        let author = lines.next().unwrap_or("").to_string();
        let timestamp: u64 = lines.next().unwrap_or("0").parse().unwrap_or(0);
        // message
        let _ = lines.next();

        // Skip the ---END--- delimiter
        while let Some(line) = lines.peek() {
            if *line == "---END---" {
                lines.next();
                break;
            }
            lines.next();
        }

        commits.push(GitCommit {
            author,
            timestamp,
            diff: None,
        });
    }

    commits
}

/// Read the PKGBUILD content at a specific git revision (e.g., "HEAD~1").
pub fn read_pkgbuild_at_revision(repo_path: &std::path::Path, revision: &str) -> Option<String> {
    let output = Command::new("git")
        .args(["show", &format!("{revision}:PKGBUILD")])
        .current_dir(repo_path)
        .output()
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        None
    }
}

/// Get the diff of the most recent commit.
pub fn get_latest_diff(repo_path: &std::path::Path) -> Option<String> {
    let output = Command::new("git")
        .args(["diff", "HEAD~1..HEAD"])
        .current_dir(repo_path)
        .output()
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_path_traversal() {
        assert!(ensure_repo("../../etc/shadow", "/tmp").is_err());
    }

    #[test]
    fn rejects_slash() {
        assert!(ensure_repo("foo/bar", "/tmp").is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(ensure_repo("", "/tmp").is_err());
    }

    #[test]
    fn accepts_valid_package_name() {
        // Should pass validation — may succeed or fail on clone, but not on validation
        if let Err(e) = ensure_repo("yay", "/tmp/traur-test-nonexistent") {
            assert!(!e.contains("invalid package name"), "valid name rejected: {e}");
        }
    }

    #[test]
    fn accepts_complex_valid_name() {
        if let Err(e) = ensure_repo("lib32-mesa+utils", "/tmp/traur-test-nonexistent") {
            assert!(!e.contains("invalid package name"), "valid name rejected: {e}");
        }
    }
}
