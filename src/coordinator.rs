use crate::features;
use crate::shared::models::PackageContext;
use crate::shared::output;
use crate::shared::scoring::{self, ScanResult, Tier};

/// Scan a package by name, printing results. Returns the computed tier.
pub fn scan_package(package_name: &str, json: bool, verbose: bool) -> Result<Tier, String> {
    let ctx = build_context(package_name)?;
    let result = run_analysis(&ctx);

    if json {
        output::print_json(&result);
    } else {
        output::print_text(&result, verbose);
    }

    Ok(result.tier)
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

    let mut incomplete: Vec<String> = Vec::new();
    let pkgbuild_content = match aur_git::read_pkgbuild(&repo_path) {
        Ok(c) => Some(c),
        Err(e) => {
            // No PKGBUILD means nothing was analysed. This must not become a
            // clean verdict.
            incomplete.push(format!("PKGBUILD unreadable: {e}"));
            None
        }
    };
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
        // Local sources are only available when scanning a directory; a clone
        // has not downloaded them yet.
        local_sources: Vec::new(),
        source_path: Some(repo_path.clone()),
        incomplete,
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

    let mut incomplete: Vec<String> = Vec::new();
    let pkgbuild = match aur_git::read_pkgbuild(&repo_path) {
        Ok(c) => Some(c),
        Err(e) => {
            incomplete.push(format!("PKGBUILD unreadable: {e}"));
            None
        }
    };
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
        // A clone has not downloaded sources yet; absence is not "clean".
        local_sources: Vec::new(),
        source_path: Some(repo_path.clone()),
        incomplete,
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
        local_sources: Vec::new(),
        source_path: None,
        incomplete: Vec::new(),
    };
    run_analysis(&ctx)
}

/// Analyse one committed `source=()` file by treating it as a script.
///
/// A local source is executed by makepkg at least as readily as the PKGBUILD:
/// the build function can `source` it, or an interpreter can run it. The same
/// engines therefore run over it, with an `LS-` prefix so reports say where the
/// finding came from. A `.install`-shape file is not special-cased: the region
/// scanner follows function bodies and the whole-file fallback covers the rest.
fn analyze_local_source(source: &crate::shared::local_scan::LocalSource) -> Vec<crate::shared::scoring::Signal> {
    use crate::shared::scoring::SignalCategory;

    let mut signals = Vec::new();
    let content = &source.content;

    for pat in crate::shared::patterns::load_patterns("pkgbuild_analysis") {
        let view = crate::shared::normalize::NormalizedView::new(content);
        if pat.regex.is_match(view.masked()) || pat.regex.is_match(view.plain()) {
            let mut signal = crate::shared::scoring::Signal::new(
                &format!("LS-{}", pat.id),
                SignalCategory::Pkgbuild,
                pat.points,
            )
            .with_description(format!(
                "{} (in local source file {})",
                pat.description, source.name
            ));
            signal.is_override_gate = pat.override_gate;
            signal.matched_line = view.first_matching_line(&pat.regex);
            signals.push(signal);
        }
    }

    // Composition engines treat the file as its own script. The content goes in
    // *both* slots because a local source may be sourced directly (top-level
    // statements, no function) or define `.install`-style hooks; the region
    // scanner's whole-file fallback covers the first case.
    let inner = crate::shared::models::PackageContext {
        name: format!("local:{}", source.name),
        install_script_content: Some(content.clone()),
        pkgbuild_content: Some(content.clone()),
        ..Default::default()
    };
    let composed: [Box<dyn crate::features::Feature>; 2] = [
        Box::new(crate::features::eval_analysis::EvalAnalysis),
        Box::new(crate::features::pipe_chain_analysis::PipeChainAnalysis),
    ];
    for feature in composed.iter() {
        for mut sig in feature.analyze(&inner) {
            if sig.id.starts_with("IS-") {
                sig.id = format!("LS-{}", sig.id.trim_start_matches("IS-"));
            } else {
                sig.id = format!("LS-{}", sig.id);
            }
            sig.description = format!("{} (in local source file {})", sig.description, source.name);
            signals.push(sig);
        }
    }

    signals
}

/// Run all registered features against the context and compute a score.
pub fn run_analysis(ctx: &PackageContext) -> ScanResult {
    let config = crate::shared::config::load_config();
    run_analysis_with_config(ctx, &config)
}

/// Run analysis with a pre-loaded config (avoids reloading per package in bulk scans).
pub fn run_analysis_with_config(
    ctx: &PackageContext,
    config: &crate::shared::config::Config,
) -> ScanResult {
    let all_features = features::all_features();

    let mut all_signals = Vec::new();
    for feature in &all_features {
        let signals = feature.analyze(ctx);
        all_signals.extend(signals);
    }

    for source in &ctx.local_sources {
        all_signals.extend(analyze_local_source(source));
    }

    // A declaration in the PKGBUILD can turn a lifecycle capability into a
    // fact (npm listed in makedepends). Runs before scoring and can only
    // lower roles, never raise them.
    crate::shared::contextual_facts::apply(ctx, &mut all_signals);

    if !config.ignored.signals.is_empty() || !config.ignored.categories.is_empty() {
        all_signals
            .retain(|s| !crate::shared::config::is_signal_ignored(config, &s.id, &s.category));
    }

    // Missing inputs make the scan inconclusive. Enforcement lives here, at
    // the single place every caller goes through, so no path can emit a
    // verdict from an incompletely analysed package.
    if !ctx.incomplete.is_empty() {
        return scoring::compute_score_with_status(
            &ctx.name,
            &all_signals,
            scoring::ScanStatus::Incomplete,
            Some(ctx.incomplete.join("; ")),
        );
    }

    scoring::compute_score(&ctx.name, &all_signals)
}
