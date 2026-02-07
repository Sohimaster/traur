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

fn dirs_or_default() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        PathBuf::from(xdg).join("traur")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".cache").join("traur")
    } else {
        PathBuf::from("/tmp/traur-cache")
    }
}
