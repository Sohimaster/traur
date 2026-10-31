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

/// Remove cached git clones: one package if named, otherwise the whole cache.
///
/// A package name is only ever a single path component (the rule `aur_git`
/// already enforces), and the resolved target must stay inside the cache
/// directory. Without both checks `traur clean ../../x` would delete an
/// arbitrary directory.
pub fn clean_git_cache(package: Option<&str>) -> std::io::Result<()> {
    let git_dir = git_cache_dir();
    match package {
        Some(pkg) => {
            if !is_valid_package_name(pkg) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid package name: {pkg}"),
                ));
            }
            let repo_path = git_dir.join(pkg);
            if repo_path.exists() {
                let root = git_dir.canonicalize()?;
                let target = repo_path.canonicalize()?;
                if !target.starts_with(&root) || target == root {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("refusing to remove {pkg}: outside the cache directory"),
                    ));
                }
                std::fs::remove_dir_all(&target)?;
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

/// AUR package names are alphanumeric plus `-_.+@`, and never contain a path
/// separator or a `..` component.
pub fn is_valid_package_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+' | '@'))
        && !name.contains("..")
        && name != "."
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_package_names() {
        for name in ["paru", "google-chrome", "python-steam", "lib32-glibc", "a_b.c+d@e"] {
            assert!(is_valid_package_name(name), "{name} should be valid");
        }
    }

    #[test]
    fn rejects_path_traversal_and_separators() {
        for name in ["", ".", "..", "../evil", "../../tmp/x", "a/b", "/etc", "..\\.."] {
            assert!(!is_valid_package_name(name), "{name} should be rejected");
        }
    }

    #[test]
    fn clean_rejects_traversal_without_deleting() {
        let outside = std::env::temp_dir().join("traur-clean-guard-test");
        std::fs::create_dir_all(&outside).unwrap();
        let target = outside.join("victim");
        std::fs::create_dir_all(&target).unwrap();

        let result = clean_git_cache(Some("../../../../../victim"));
        assert!(result.is_err(), "traversal must be refused");
        assert!(target.exists(), "directory outside the cache must survive");

        std::fs::remove_dir_all(&outside).ok();
    }
}
