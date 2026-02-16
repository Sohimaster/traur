use regex::Regex;
use serde::Deserialize;
use std::sync::LazyLock;

static GITHUB_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)github\.com/([^/\s]+)/([^/\s#?.]+)"#).unwrap()
});

#[derive(Debug)]
pub struct GitHubInfo {
    pub stars: u32,
    pub found: bool,
}

#[derive(Deserialize)]
struct RepoResponse {
    stargazers_count: u32,
}

/// Fetch GitHub star count for a URL. Returns None for non-GitHub URLs or errors.
pub fn fetch_github_stars(url: &str) -> Option<GitHubInfo> {
    let (owner, repo) = parse_github_url(url)?;

    let api_url = format!("https://api.github.com/repos/{owner}/{repo}");

    let client = reqwest::blocking::Client::new();
    let mut request = client
        .get(&api_url)
        .header("User-Agent", "traur")
        .header("Accept", "application/vnd.github.v3+json");

    // Support GITHUB_TOKEN for higher rate limits
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        if !token.is_empty() {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
    }

    let resp = match request.timeout(std::time::Duration::from_secs(10)).send() {
        Ok(r) => r,
        Err(_) => return None, // network error, graceful skip
    };

    if resp.status() == 404 {
        return Some(GitHubInfo {
            stars: 0,
            found: false,
        });
    }

    if !resp.status().is_success() {
        return None; // rate limit or other error, graceful skip
    }

    let repo_data: RepoResponse = match resp.json() {
        Ok(d) => d,
        Err(_) => return None,
    };

    Some(GitHubInfo {
        stars: repo_data.stargazers_count,
        found: true,
    })
}

/// Parse a GitHub URL to extract owner and repo.
fn parse_github_url(url: &str) -> Option<(String, String)> {
    let caps = GITHUB_URL_RE.captures(url)?;
    let owner = caps[1].to_string();
    let mut repo = caps[2].to_string();
    // Strip .git suffix
    if repo.ends_with(".git") {
        repo.truncate(repo.len() - 4);
    }
    Some((owner, repo))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_standard_url() {
        let (owner, repo) = parse_github_url("https://github.com/user/project").unwrap();
        assert_eq!(owner, "user");
        assert_eq!(repo, "project");
    }

    #[test]
    fn parse_git_suffix() {
        let (owner, repo) = parse_github_url("https://github.com/user/project.git").unwrap();
        assert_eq!(owner, "user");
        assert_eq!(repo, "project");
    }

    #[test]
    fn parse_deep_path() {
        let (owner, repo) =
            parse_github_url("https://github.com/user/project/tree/main/subdir").unwrap();
        assert_eq!(owner, "user");
        assert_eq!(repo, "project");
    }

    #[test]
    fn non_github_returns_none() {
        assert!(parse_github_url("https://gitlab.com/user/project").is_none());
    }

    #[test]
    fn empty_returns_none() {
        assert!(parse_github_url("").is_none());
    }
}
