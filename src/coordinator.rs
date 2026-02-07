use crate::features;
use crate::shared::models::PackageContext;
use crate::shared::output;
use crate::shared::scoring::{self, ScanResult, Tier};

/// Scan a package by name, printing results. Returns the computed tier.
pub fn scan_package(package_name: &str, json: bool) -> Result<Tier, String> {
    let ctx = build_context(package_name)?;
    let result = run_analysis(&ctx);

    if json {
        output::print_json(&result);
    } else {
        output::print_text(&result);
    }

    Ok(result.tier)
}

/// Scan a package silently, returning the ScanResult without printing.
pub fn scan_package_silent(package_name: &str) -> Result<ScanResult, String> {
    let ctx = build_context(package_name)?;
    Ok(run_analysis(&ctx))
}

/// Scan with pre-fetched metadata and maintainer packages (only git clone hits the network).
/// Returns Err if git clone fails — no PKGBUILD means no meaningful scan.
pub fn scan_package_prefetched(
    package_name: &str,
    metadata: crate::shared::models::AurPackage,
    maintainer_packages: Vec<crate::shared::models::AurPackage>,
) -> Result<ScanResult, String> {
    let ctx = build_context_prefetched(package_name, metadata, maintainer_packages)?;
    Ok(run_analysis(&ctx))
}

/// Build a PackageContext by fetching all data needed for analysis.
fn build_context(package_name: &str) -> Result<PackageContext, String> {
    use crate::shared::{aur_git, aur_rpc, cache};

    let metadata = aur_rpc::fetch_package_info(package_name)?;

    // Determine package base (for split packages)
    let package_base = metadata
        .package_base
        .as_deref()
        .unwrap_or(package_name);

    // Clone/pull the AUR git repo
    let git_cache = cache::git_cache_dir();
    let cache_str = git_cache.to_str().unwrap_or("/tmp/traur-git");

    let (pkgbuild_content, install_script_content, git_log, prior_pkgbuild_content) =
        match aur_git::ensure_repo(package_base, cache_str) {
            Ok(repo_path) => {
                let pkgbuild = aur_git::read_pkgbuild(&repo_path).ok();
                let install = pkgbuild
                    .as_deref()
                    .and_then(|content| aur_git::read_install_script(&repo_path, content));
                let mut log = aur_git::read_git_log(&repo_path, 20);

                // Attach diff to the latest commit
                if let Some(first) = log.first_mut() {
                    first.diff = aur_git::get_latest_diff(&repo_path);
                }

                // Read prior PKGBUILD for diff comparison
                let prior = if log.len() >= 2 {
                    aur_git::read_pkgbuild_at_revision(&repo_path, "HEAD~1")
                } else {
                    None
                };

                (pkgbuild, install, log, prior)
            }
            Err(e) => {
                eprintln!("Warning: failed to clone AUR repo for {package_base}: {e}");
                (None, None, Vec::new(), None)
            }
        };

    // Fetch maintainer's other packages for reputation analysis
    let maintainer_packages = metadata
        .maintainer
        .as_deref()
        .and_then(|m| aur_rpc::fetch_maintainer_packages(m).ok())
        .unwrap_or_default();

    Ok(PackageContext {
        name: package_name.to_string(),
        metadata: Some(metadata),
        pkgbuild_content,
        install_script_content,
        prior_pkgbuild_content,
        git_log,
        maintainer_packages,
    })
}

/// Build context using pre-fetched metadata. Only the git clone hits the network.
/// Returns Err if git clone fails — no PKGBUILD means no meaningful analysis.
pub fn build_context_prefetched(
    package_name: &str,
    metadata: crate::shared::models::AurPackage,
    maintainer_packages: Vec<crate::shared::models::AurPackage>,
) -> Result<PackageContext, String> {
    use crate::shared::{aur_git, cache};

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

    Ok(PackageContext {
        name: package_name.to_string(),
        metadata: Some(metadata),
        pkgbuild_content: pkgbuild,
        install_script_content: install,
        prior_pkgbuild_content: prior,
        git_log: log,
        maintainer_packages,
    })
}

/// Scan a local PKGBUILD string without network access. Used for testing and --pkgbuild.
pub fn scan_pkgbuild(name: &str, pkgbuild_content: &str) -> ScanResult {
    let ctx = PackageContext {
        name: name.to_string(),
        metadata: None,
        pkgbuild_content: Some(pkgbuild_content.to_string()),
        install_script_content: None,
        prior_pkgbuild_content: None,
        git_log: Vec::new(),
        maintainer_packages: Vec::new(),
    };
    run_analysis(&ctx)
}

/// Run all registered features against the context and compute a score.
pub fn run_analysis(ctx: &PackageContext) -> ScanResult {
    let all_features = features::all_features();

    let mut all_signals = Vec::new();
    for feature in &all_features {
        let signals = feature.analyze(ctx);
        all_signals.extend(signals);
    }

    scoring::compute_score(&ctx.name, &all_signals)
}
