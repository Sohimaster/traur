use std::path::PathBuf;

/// Returns the cache directory, creating it if needed.
pub fn cache_dir() -> PathBuf {
    let dir = dirs_or_default();
    std::fs::create_dir_all(&dir).ok();
    dir
}

/// Returns the git clone cache subdirectory.
pub fn git_cache_dir() -> PathBuf {
    let dir = cache_dir().join("git");
    std::fs::create_dir_all(&dir).ok();
    dir
}

pub fn clean_git_cache(package: Option<&str>) -> std::io::Result<()> {
    let git_dir = git_cache_dir();
    match package {
        Some(pkg) => {
            let repo_path = git_dir.join(pkg);
            if repo_path.exists() {
                std::fs::remove_dir_all(&repo_path)?;
            }
        }
        None => {
            if git_dir.exists() {
                std::fs::remove_dir_all(&git_dir)?;
                std::fs::create_dir_all(&git_dir)?;
            }
        }
    }
    Ok(())
}

fn dirs_or_default() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        PathBuf::from(xdg).join("traur")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".cache").join("traur")
    } else {
        PathBuf::from("/tmp/traur-cache")
    }
}
