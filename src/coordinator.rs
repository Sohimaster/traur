use crate::features;
use crate::shared::models::{MaintainerInfo, PackageContext};
use crate::shared::{npm, output};
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

    let (maint_info, has_orphan, has_mal_diff) = compute_context_meta(
        &metadata,
        &maintainer_packages,
        &git_log,
        prior_pkgbuild_content.as_deref(),
    );

    let npm_info = pkgbuild_content
        .as_deref()
        .and_then(|content| npm::fetch_npm_info(content));

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
        maintainer_info: maint_info,
        has_orphan_takeover: has_orphan,
        has_new_malicious_diff: has_mal_diff,
        npm_info,
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

    let (maint_info, has_orphan, has_mal_diff) = compute_context_meta(
        &metadata,
        &maintainer_packages,
        &log,
        prior.as_deref(),
    );

    let npm_info = pkgbuild
        .as_deref()
        .and_then(|content| npm::fetch_npm_info(content));

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
        maintainer_info: maint_info,
        has_orphan_takeover: has_orphan,
        has_new_malicious_diff: has_mal_diff,
        npm_info,
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
        maintainer_info: None,
        has_orphan_takeover: false,
        has_new_malicious_diff: false,
        npm_info: None,
    };
    run_analysis(&ctx)
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

    if !config.ignored.signals.is_empty() || !config.ignored.categories.is_empty() {
        all_signals
            .retain(|s| !crate::shared::config::is_signal_ignored(config, &s.id, &s.category));
    }

    let (votes, popularity) = ctx
        .metadata
        .as_ref()
        .map(|m| (m.num_votes, m.popularity))
        .unwrap_or((0, 0.0));

    // ── NPM dynamic penalty: if PKGBUILD uses npm install/npx, check legitimacy ──
    let has_npm_suspicious = all_signals.iter().any(|s| s.id == "P-NPM-SUSPICIOUS-SCRIPT");
    if has_npm_suspicious {
        if let Some(ref npm) = ctx.npm_info {
            let npm_risk = scoring::npm_suspicion_risk(npm);

            if npm_risk >= 25 {
                // Malicious npm deps: escalate to critical gate (Step 2 -> Malicious)
                for signal in &mut all_signals {
                    if signal.id == "P-NPM-SUSPICIOUS-SCRIPT" {
                        signal.is_critical = true;
                        signal.points = 90;
                        signal.description = format!(
                            "NPM package {} has suspicious install scripts (npm risk {}) – possible payload vector",
                            npm.package_name,
                            npm_risk
                        );
                    }
                }
            } else {
                // Legitimate npm deps: downgrade to minor warning
                for signal in &mut all_signals {
                    if signal.id == "P-NPM-SUSPICIOUS-SCRIPT" {
                        signal.points = 10;
                        signal.description = format!(
                            "Running npm lifecycle scripts for {} – legitimate deps verified, but still bad practice (offline-build violation)",
                            npm.package_name
                        );
                    }
                }
            }

            // Emit N-NPM-LEGITIMACY-CHECKED signal to show the fork did its job
            let npm_desc = if npm_risk >= 25 {
                format!("NPM legitimacy check: SUSPICIOUS (npm suspicion risk {})", npm_risk)
            } else {
                format!("NPM legitimacy check: legitimate (npm suspicion risk {})", npm_risk)
            };
            all_signals.push(scoring::Signal {
                id: "N-NPM-LEGITIMACY-CHECKED".to_string(),
                category: scoring::SignalCategory::Pkgbuild,
                points: 0,
                description: npm_desc,
                is_override_gate: false,
                is_critical: false,
                matched_line: None,
            });
        }
        // else: no npm_info fetched (network issue or unrecognized package),
        // keep P-NPM-SUSPICIOUS-SCRIPT as-is (static analysis penalty)

        // ── B-SUBMITTER-CHANGED amplification: only severe if npm install was added by new maintainer ──
        let has_submitter_changed = all_signals.iter().any(|s| s.id == "B-SUBMITTER-CHANGED");
        if has_submitter_changed {
            // Check if npm/yarn/npx was already in the prior PKGBUILD
            let npm_was_always_there = ctx.prior_pkgbuild_content.as_deref().is_some_and(|prior| {
                let re = regex::Regex::new(r"(?i)(npm\s+(install|run)|npx\s+|yarn\s+(install|add))").unwrap();
                re.is_match(prior)
            });

            if npm_was_always_there {
                // npm install was always there, not added by new maintainer → reduce severity
                for signal in &mut all_signals {
                    if signal.id == "B-SUBMITTER-CHANGED" {
                        signal.points = 5;
                        signal.description = "Package maintainer differs from original submitter (npm install pre-dates maintainer change)".to_string();
                    }
                }
            }
        }
    }

    // Apply time-aware comment threat evaluation
    let comment_verdict =
        scoring::evaluate_comment_threat(&ctx.aur_comments, votes, popularity);
    let has_malware_warning = match comment_verdict {
        scoring::CommentSecurityVerdict::OverrideFire => true,
        scoring::CommentSecurityVerdict::Degraded { points } => {
            // Find M-COMMENTS-SECURITY signal and degrade it
            for signal in &mut all_signals {
                if signal.id == "M-COMMENTS-SECURITY" {
                    signal.is_override_gate = false;
                    signal.points = points;
                }
            }
            false
        }
        scoring::CommentSecurityVerdict::Ignored => {
            // Remove M-COMMENTS-SECURITY signal entirely
            all_signals.retain(|s| s.id != "M-COMMENTS-SECURITY");
            false
        }
        scoring::CommentSecurityVerdict::Clean => false,
    };

    let score_input = scoring::ScoreInput {
        maintainer_info: ctx.maintainer_info.as_ref(),
        votes,
        popularity,
        has_orphan_takeover: ctx.has_orphan_takeover,
        has_new_malicious_diff: ctx.has_new_malicious_diff,
        npm_info: ctx.npm_info.as_ref(),
        has_community_malware_warning: has_malware_warning,
    };

    scoring::compute_score(&ctx.name, &all_signals, &score_input)
}

/// Pre-compute maintainer info and context flags from fetched data.
/// This avoids recomputing the same logic in the scoring engine.
fn compute_context_meta(
    metadata: &crate::shared::models::AurPackage,
    maintainer_packages: &[crate::shared::models::AurPackage],
    git_log: &[crate::shared::models::GitCommit],
    prior_pkgbuild_content: Option<&str>,
) -> (Option<MaintainerInfo>, bool, bool) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Compute maintainer info
    let maint_info = {
        let is_original = metadata.submitter.as_ref() == metadata.maintainer.as_ref();

        // Account age proxy: oldest first_submitted among maintainer's packages
        let account_created = maintainer_packages
            .iter()
            .map(|p| p.first_submitted)
            .min()
            .unwrap_or(metadata.first_submitted);

        let number_of_packages = maintainer_packages.len() as u32;

        // Days since takeover: if submitter changed, use time since latest git commit with new author
        let days_since_takeover = if !is_original && git_log.len() >= 2 {
            let latest_author = git_log[0].author.as_str();
            let prior_authors: std::collections::HashSet<&str> = git_log[1..]
                .iter()
                .map(|c| c.author.as_str())
                .collect();
            if !prior_authors.contains(latest_author) {
                let takeover_ts = git_log[0].timestamp;
                Some(((now.saturating_sub(takeover_ts)) / 86400) as u32)
            } else {
                None
            }
        } else if !is_original && metadata.submitter.is_some() {
            // Submitter changed but no author change in git — use last modified as rough estimate
            Some(((now.saturating_sub(metadata.last_modified)) / 86400) as u32)
        } else {
            None
        };

        Some(MaintainerInfo {
            account_created_date: account_created,
            number_of_packages,
            is_original_submitter: is_original,
            days_since_takeover,
        })
    };

    // Check orphan takeover: same logic as OrphanTakeoverAnalysis
    let has_orphan_takeover = {
        let submitter_changed = metadata.submitter.as_ref() != metadata.maintainer.as_ref()
            && metadata.submitter.is_some()
            && metadata.maintainer.is_some();
        let established = now.saturating_sub(metadata.first_submitted) > 90 * 86400;
        let author_changed = git_log.len() >= 2 && {
            let latest_author = git_log[0].author.as_str();
            let prior_authors: std::collections::HashSet<&str> = git_log[1..]
                .iter()
                .map(|c| c.author.as_str())
                .collect();
            !prior_authors.contains(latest_author)
        };
        submitter_changed && established && author_changed
    };

    // Check new malicious diff: any newly-added line matching a high-severity pattern (>=60pts)
    // or network code pattern from pkgbuild_analysis that wasn't in the prior PKGBUILD.
    let has_new_malicious_diff = {
        static HIGH_SEV_PATTERNS: std::sync::LazyLock<Vec<crate::shared::patterns::CompiledPattern>> =
            std::sync::LazyLock::new(|| crate::shared::patterns::load_high_severity_diff_patterns());

        if let Some(newest) = git_log.first() {
            if let Some(ref diff) = newest.diff {
                let has_new = HIGH_SEV_PATTERNS.iter().any(|pat| {
                    // Check if any newly-added line in diff matches this pattern
                    let in_diff = diff
                        .lines()
                        .filter(|l| l.starts_with('+') && !l.starts_with("+++"))
                        .any(|l| pat.regex.is_match(&l[1..])); // strip the + prefix
                    // Check if the pattern was already in the prior PKGBUILD
                    let in_prior = prior_pkgbuild_content
                        .is_some_and(|content| pat.regex.is_match(content));
                    in_diff && !in_prior
                });

                // Also keep the original network code check for T-MALICIOUS-DIFF compatibility
                let has_net_diff = {
                    let net_diff_re = regex::Regex::new(
                        r"\+.*(curl|wget|nc\s|ncat|socat|/dev/tcp|python.*socket|ruby.*socket)"
                    ).ok();
                    let net_content_re = regex::Regex::new(
                        r"(curl|wget|nc\s|ncat|socat|/dev/tcp|python.*socket|ruby.*socket)"
                    ).ok();

                    if let (Some(nd_re), Some(nc_re)) = (net_diff_re, net_content_re) {
                        let has_net = nd_re.is_match(diff);
                        let has_prior_net = prior_pkgbuild_content
                            .is_some_and(|content| nc_re.is_match(content));
                        has_net && !has_prior_net
                    } else {
                        false
                    }
                };

                has_new || has_net_diff
            } else {
                false
            }
        } else {
            false
        }
    };

    (maint_info, has_orphan_takeover, has_new_malicious_diff)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::models::{AurPackage, GitCommit};

    fn now_ts() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn make_pkg(submitter: &str, maintainer: &str, days_old: u32) -> AurPackage {
        let ts = now_ts();
        AurPackage {
            name: "test-pkg".into(),
            package_base: None,
            url: Some("https://github.com/org/repo".into()),
            num_votes: 0,
            popularity: 0.0,
            out_of_date: None,
            maintainer: Some(maintainer.into()),
            submitter: Some(submitter.into()),
            first_submitted: ts - days_old as u64 * 86400,
            last_modified: ts - 86400,
            license: None,
        }
    }

    fn make_commit(author: &str, diff: Option<&str>) -> GitCommit {
        let ts = now_ts();
        GitCommit {
            author: author.into(),
            timestamp: if diff.is_some() { ts - 3600 } else { ts - 90 * 86400 },
            diff: diff.map(|s| s.to_string()),
        }
    }

    /// Real malicious commit: anythingllm-cli-bin attacker added
    /// a .install script running `npm install atomic-lockfile minimist`.
    /// This test bypasses community comments to prove diff detection works.
    #[test]
    fn detects_malicious_diff_with_atomic_lockfile() {
        let ts = now_ts();
        let metadata = AurPackage {
            name: "anythingllm-cli-bin".into(),
            package_base: None,
            url: Some("https://github.com/Mintplex-Labs/anything-llm-cli".into()),
            num_votes: 0,
            popularity: 0.0,
            out_of_date: None,
            maintainer: Some("meryemplath".into()),  // attacker's email
            submitter: Some("richc".into()),         // original submitter
            first_submitted: ts - 365 * 86400,      // 1 year old — established
            last_modified: ts - 3600,
            license: None,
        };

        let prior_pkgbuild = r#"# Maintainer: Julian Corbet <julian.corbet@gmail.com>
pkgname=anythingllm-cli-bin
_pkgname=anything-llm-cli
pkgver=0.0.13
pkgrel=1
arch=('x86_64' 'aarch64')
depends=('glibc')
"#;

        let diff = r#"diff --git a/PKGBUILD b/PKGBUILD
index af217ae..e9a0f65 100644
--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,4 +1,4 @@
-# Maintainer: Julian Corbet <julian.corbet@gmail.com>
+# Maintainer: Julian Corbet <meryemplath@gmail.com>
 pkgname=anythingllm-cli-bin
@@ -7 +7 @@ arch=('x86_64' 'aarch64')
-depends=('glibc')
+depends=('npm' 'glibc')
@@ -23,3 +23,4 @@ package() {
     install -Dm755 binary "${pkgdir}/usr/bin/any"
 }
+install=anythingllm-cli-bin-deps.install
diff --git a/anythingllm-cli-bin-deps.install b/anythingllm-cli-bin-deps.install
new file mode 100644
index 0000000..fff7451
--- /dev/null
+++ b/anythingllm-cli-bin-deps.install
@@ -0,0 +1,4 @@
+post_install() {
+  cd /tmp
+  npm install atomic-lockfile minimist
+}
"#;

        let git_log = vec![
            make_commit("meryemplath", Some(diff)),
            make_commit("richc", None),
        ];

        let (maint_info, has_orphan, has_mal_diff) = compute_context_meta(
            &metadata,
            &[],
            &git_log,
            Some(prior_pkgbuild),
        );

        assert!(
            has_mal_diff,
            "has_new_malicious_diff: diff introduces atomic-lockfile \
             (P-NPM-ATOMIC-LOCKFILE 60pts) not in prior PKGBUILD"
        );
        assert!(
            has_orphan,
            "has_orphan_takeover: submitter changed (richc -> meryemplath) \
             + new git author + established package"
        );

        // Prove the full pipeline: orphan + malicious diff = Malicious
        // Simulate what run_analysis_with_config does, but skip comments gate
        let signals: Vec<scoring::Signal> = Vec::new(); // no signals needed for this test
        let (votes, popularity) = (metadata.num_votes, metadata.popularity);

        let score_input = scoring::ScoreInput {
            maintainer_info: maint_info.as_ref(),
            votes,
            popularity,
            has_orphan_takeover: has_orphan,
            has_new_malicious_diff: has_mal_diff,
            npm_info: None,
            has_community_malware_warning: false,  // deliberately bypass comments
        };

        let result = scoring::compute_score("anythingllm-cli-bin", &signals, &score_input);
        // orphan + malicious diff -> risk = max(0, 95) = 95 -> trust = 5 -> Malicious
        assert_eq!(
            result.tier,
            scoring::Tier::Malicious,
            "orphan takeover + new malicious diff should be Malicious (trust {})",
            result.score
        );
        assert!(
            result.score <= 5,
            "Expected trust <= 5, got {}", result.score
        );
    }

    /// Without the high-severity pattern, a benign diff should not trigger.
    #[test]
    fn benign_diff_no_new_high_sev_pattern() {
        let metadata = make_pkg("orig", "orig", 365);
        let prior = r#"pkgname=test
pkgver=1.0
depends=('glibc')
"#;
        let diff = r#"diff --git a/PKGBUILD b/PKGBUILD
--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1 +1 @@
-pkgver=1.0
+pkgver=1.1
"#;

        let git_log = vec![
            make_commit("orig", Some(diff)),
            make_commit("orig", None),
        ];

        let (_, _, has_mal_diff) = compute_context_meta(
            &metadata,
            &[],
            &git_log,
            Some(prior),
        );

        assert!(
            !has_mal_diff,
            "Benign version bump should not trigger has_new_malicious_diff"
        );
    }
}
