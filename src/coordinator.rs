use crate::shared::models::PackageContext;
use crate::shared::output;
use crate::shared::scoring::ScanResult;
use crate::shared::rules::Verdict;

/// Scan a package by name, printing results. Returns the computed verdict.
pub fn scan_package(package_name: &str, json: bool, verbose: bool) -> Result<Verdict, String> {
    let ctx = build_context(package_name)?;
    let result = run_analysis(&ctx);

    if json {
        output::print_json(&result);
    } else {
        output::print_text(&result, verbose);
    }

    Ok(result.verdict)
}

/// Build a PackageContext by fetching all data needed for analysis.
pub fn build_context(package_name: &str) -> Result<PackageContext, String> {
    use crate::shared::{aur_comments, aur_git, aur_rpc, cache, github};

    let metadata = aur_rpc::fetch_package_info(package_name)?;

    // Determine package base (for split packages)
    let package_base = metadata
        .package_base
        .as_deref()
        .unwrap_or(package_name);

    // Clone/pull the AUR git repo
    let git_cache = cache::git_cache_dir();
    let cache_str = git_cache.to_str().unwrap_or("/tmp/traur-git");

    let repo_path = aur_git::ensure_repo(package_base, cache_str)?;

    let pkgbuild_content = aur_git::read_pkgbuild(&repo_path).ok();
    let install_script_content = pkgbuild_content
        .as_deref()
        .and_then(|content| aur_git::read_install_script(&repo_path, content));
    let mut git_log = aur_git::read_git_log(&repo_path, 20);

    // Attach diff to the latest commit
    if let Some(first) = git_log.first_mut() {
        first.diff = aur_git::get_latest_diff(&repo_path);
    }

    // Read prior PKGBUILD for diff comparison
    let prior_pkgbuild_content = if git_log.len() >= 2 {
        aur_git::read_pkgbuild_at_revision(&repo_path, "HEAD~1")
    } else {
        None
    };

    // Fetch maintainer's other packages for reputation analysis
    let maintainer_packages = metadata
        .maintainer
        .as_deref()
        .and_then(|m| aur_rpc::fetch_maintainer_packages(m).ok())
        .unwrap_or_default();

    // Fetch GitHub stars if upstream URL points to GitHub
    let (github_stars, github_not_found) = metadata
        .url
        .as_deref()
        .and_then(|url| github::fetch_github_stars(url))
        .map(|info| (if info.found { Some(info.stars) } else { None }, !info.found))
        .unwrap_or((None, false));

    // Fetch recent AUR comments
    let aur_comments = aur_comments::fetch_recent_comments(package_base);

    Ok(PackageContext {
        name: package_name.to_string(),
        metadata: Some(metadata),
        pkgbuild_content,
        install_script_content,
        prior_pkgbuild_content,
        git_log,
        maintainer_packages,
        github_stars,
        github_not_found,
        aur_comments,
    })
}

/// Build context using pre-fetched metadata. Only the git clone hits the network.
/// Returns Err if git clone fails — no PKGBUILD means no meaningful analysis.
pub fn build_context_prefetched(
    package_name: &str,
    metadata: crate::shared::models::AurPackage,
    maintainer_packages: Vec<crate::shared::models::AurPackage>,
) -> Result<PackageContext, String> {
    use crate::shared::{aur_comments, aur_git, cache, github};

    let package_base = metadata
        .package_base
        .as_deref()
        .unwrap_or(package_name);

    let git_cache = cache::git_cache_dir();
    let cache_str = git_cache.to_str().unwrap_or("/tmp/traur-git");

    let repo_path = aur_git::ensure_repo(package_base, cache_str)?;

    let pkgbuild = aur_git::read_pkgbuild(&repo_path).ok();
    let install = pkgbuild
        .as_deref()
        .and_then(|content| aur_git::read_install_script(&repo_path, content));
    let mut log = aur_git::read_git_log(&repo_path, 20);

    if let Some(first) = log.first_mut() {
        first.diff = aur_git::get_latest_diff(&repo_path);
    }

    let prior = if log.len() >= 2 {
        aur_git::read_pkgbuild_at_revision(&repo_path, "HEAD~1")
    } else {
        None
    };

    let (gh_stars, gh_not_found) = metadata
        .url
        .as_deref()
        .and_then(|url| github::fetch_github_stars(url))
        .map(|info| (if info.found { Some(info.stars) } else { None }, !info.found))
        .unwrap_or((None, false));

    let comments = aur_comments::fetch_recent_comments(package_base);

    Ok(PackageContext {
        name: package_name.to_string(),
        metadata: Some(metadata),
        pkgbuild_content: pkgbuild,
        install_script_content: install,
        prior_pkgbuild_content: prior,
        git_log: log,
        maintainer_packages,
        github_stars: gh_stars,
        github_not_found: gh_not_found,
        aur_comments: comments,
    })
}

/// Scan a local PKGBUILD string without network access.
pub fn scan_pkgbuild(name: &str, pkgbuild_content: &str) -> ScanResult {
    let ctx = PackageContext {
        name: name.to_string(),
        metadata: None,
        pkgbuild_content: Some(pkgbuild_content.to_string()),
        install_script_content: None,
        prior_pkgbuild_content: None,
        git_log: Vec::new(),
        maintainer_packages: Vec::new(),
        github_stars: None,
        github_not_found: false,
        aur_comments: vec![],
    };
    run_analysis(&ctx)
}

/// Run all registered features against the context and compute a verdict.
pub fn run_analysis(ctx: &PackageContext) -> ScanResult {
    let config = crate::shared::config::load_config();
    run_analysis_with_config(ctx, &config)
}

/// Run analysis with a pre-loaded config (avoids reloading per package in bulk scans).
pub fn run_analysis_with_config(
    ctx: &PackageContext,
    config: &crate::shared::config::Config,
) -> ScanResult {
    use crate::shared::rules::Verdict;
    
    // Check git commit hash override first
    if let Some(first_commit) = ctx.git_log.first() {
        if is_hash_in_override_list(&first_commit.hash, config) {
            return ScanResult {
                package: ctx.name.clone(),
                verdict: Verdict::Trusted,
                fired_rule: Some("OVERRIDE-COMMIT-HASH".to_string()),
                detections: Vec::new(),
            };
        }
    }
    
    // Evaluate all rules and collect detections
    let rules = crate::shared::rule_registry::all_rules();
    let mut all_detections = Vec::new();
    
    for rule in &rules {
        let detections = rule.evaluate(ctx);
        all_detections.extend(detections);
    }
    
    // Add whitelist rule check (highest salience)
    if let Some(whitelist_detection) = check_repo_maintainer_whitelist(ctx, config) {
        all_detections.push(whitelist_detection);
    }
    
    // Sort detections by salience (highest first)
    all_detections.sort_by(|a, b| b.salience.cmp(&a.salience));
    
    // First detection with highest salience wins
    let verdict = if let Some(detection) = all_detections.first() {
        detection.verdict
    } else {
        Verdict::Ok // Default if no detections
    };
    
    let fired_rule = all_detections.first().map(|d| d.rule_id.clone());
    
    ScanResult {
        package: ctx.name.clone(),
        verdict,
        fired_rule,
        detections: all_detections,
    }
}

fn is_hash_in_override_list(_hash: &str, _config: &crate::shared::config::Config) -> bool {
    // TODO: Load from config or allowlist file
    false
}

fn check_repo_maintainer_whitelist(
    _ctx: &PackageContext,
    _config: &crate::shared::config::Config,
) -> Option<crate::shared::rules::Detection> {
    // TODO: Load whitelist, check repo name + maintainer combo
    // For now, return None (not in whitelist)
    None
}
