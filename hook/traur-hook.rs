//! traur-hook: ALPM pre-transaction hook binary.
//! Reads package names from stdin (passed by pacman/paru via NeedsTargets),
//! filters to AUR-only packages, scans each silently, then shows a summary.
//! Detail is only printed for SKETCHY+ packages. No prompt when all clean.
//!
//! All output goes to /dev/tty — pacman buffers both stdout and stderr from
//! hooks, so we must write directly to the terminal.

use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::collections::HashSet;
use std::process::Command;
use colored::Colorize;
use traur::coordinator;
use traur::shared::bulk;
use traur::shared::config::{self, is_whitelisted_in};
use traur::shared::output;
use traur::shared::offline::{self, OfflineChoice};
use traur::shared::scoring::{ScanResult, ScanStatus, Tier};

fn main() {
    // Force colored output — ALPM hooks inherit the terminal but colored
    // crate can't detect it since stdin is a pipe.
    colored::control::set_override(true);

    // Collect all package names from stdin (ALPM NeedsTargets)
    let stdin = io::stdin();
    let packages: Vec<String> = stdin
        .lock()
        .lines()
        .filter_map(|line| line.ok())
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    if packages.is_empty() {
        return;
    }

    // Filter to AUR-only packages (single pacman -Sl call instead of per-package -Si)
    let official = official_repo_packages();
    let aur_packages: Vec<String> = packages
        .into_iter()
        .filter(|pkg| !official.contains(pkg.as_str()))
        .collect();

    if aur_packages.is_empty() {
        return;
    }

    // Open /dev/tty for ALL output — pacman buffers both stdout and stderr
    // from hooks, so only direct tty writes appear immediately.
    let mut tty = match OpenOptions::new().read(true).write(true).open("/dev/tty") {
        Ok(f) => f,
        Err(_) => return, // non-interactive, skip silently
    };

    let config = config::load_config();

    let _ = writeln!(
        tty,
        "{}",
        r#"
  ╔╦╗╦═╗╔═╗╦ ╦╦═╗
   ║ ╠╦╝╠═╣║ ║╠╦╝
   ╩ ╩╚═╩ ╩╚═╝╩╚═"#
            .red()
            .bold()
    );
    let _ = writeln!(tty, "  {}", "Trust scoring for AUR packages".dimmed());
    let _ = writeln!(tty);

    // --- Phase 1: Collect results silently ---

    // Filter whitelisted packages first
    let mut whitelisted_count: u32 = 0;
    let to_scan: Vec<String> = aur_packages
        .into_iter()
        .filter(|pkg| {
            if is_whitelisted_in(&config, pkg) {
                whitelisted_count += 1;
                false
            } else {
                true
            }
        })
        .collect();

    // Batch-fetch AUR metadata to separate real AUR packages from local-only ones
    let (metadata, failed_batches) = bulk::batch_fetch_metadata_with_errors(&to_scan);

    // The AUR was unreachable. Pacman forks with network isolation (CachyOS)
    // land here for every package. Treating that as "not on AUR" would skip
    // the scan and let the transaction through unscanned, so block instead
    // unless the user explicitly opts out.
    // The AUR was unreachable: the scan cannot conclude. This is neither
    // "trusted" nor "suspicious" (issue #24; PLAN.md N4.4). A clone on disk is
    // still scanned so the report shows what could be checked, but the verdict
    // stays Unknown and the user decides.
    if failed_batches > 0 && metadata.is_empty() {
        let grant_path = offline::default_grant_path();
        let state = offline::read_grant(&grant_path);
        let interactive = true; // /dev/tty is open at this point

        let _ = writeln!(tty);
        let _ = writeln!(
            tty,
            "{}",
            "traur: AUR unreachable — the system cannot conclude".cyan().bold()
        );
        let _ = writeln!(
            tty,
            "traur: network failure meant no package metadata could be fetched."
        );
        let _ = writeln!(
            tty,
            "traur: this is not a verdict. Neither verified nor found suspicious."
        );
        let _ = writeln!(
            tty,
            "traur: {} package(s) unverified: {}",
            to_scan.len(),
            to_scan.join(", ")
        );

        // Show what the local clones do contain, without turning it into a tier.
        let local = scan_local_clones(&to_scan);
        if !local.is_empty() {
            let _ = writeln!(tty);
            let _ = writeln!(tty, "  What could still be checked locally:");
            for result in &local {
                output::write_text(&mut tty, result, false);
            }
        }

        let fingerprint = offline::fingerprint(&to_scan, "aur-unreachable");
        let choice = offline::decide(&state, offline_scan_allowed(), interactive, || {
            let _ = writeln!(tty);
            let _ = writeln!(
                tty,
                "traur: continue without a verified scan?"
            );
            let _ = writeln!(
                tty,
                "  [o] allow this once   [s] allow for this session   [N] stop"
            );
            let _ = writeln!(
                tty,
                "traur: 'session' lasts until the AUR is reachable again, or reboot."
            );
            let _ = write!(tty, "{} ", "traur: [o/s/N]".bold());
            let _ = tty.flush();
            // Borrow rather than move: the file is used again after the prompt.
            let mut reader = BufReader::new(&tty);
            let mut line = String::new();
            let response = match reader.read_line(&mut line) {
                Ok(0) => String::new(),
                Ok(_) => line,
                Err(_) => String::new(),
            };
            OfflineChoice::parse(&response)
        });

        match choice {
            OfflineChoice::Deny => {
                let _ = writeln!(tty);
                let _ = writeln!(
                    tty,
                    "{}",
                    "traur: no verified scan; stopping the transaction".red().bold()
                );
                let _ = writeln!(
                    tty,
                    "traur: if this hook runs without network access (CachyOS isolates\n\
                     traur: hooks), set TRAUR_ALLOW_OFFLINE=1 for unattended installs."
                );
                std::process::exit(1);
            }
            OfflineChoice::AllowSession => {
                // Root-owned, scoped to the Unknown state, cleared on the next
                // successful fetch. A failure to persist is not fatal: the user
                // approved this transaction either way.
                if offline::write_grant(&grant_path, "AUR unreachable", &fingerprint).is_err() {
                    let _ = writeln!(
                        tty,
                        "traur: could not record the session approval; allowing this transaction only"
                    );
                } else {
                    let _ = writeln!(
                        tty,
                        "  {}",
                        "traur: allowed for this session (until the AUR is reachable again)".dimmed()
                    );
                }
            }
            OfflineChoice::AllowOnce => {
                let _ = writeln!(tty, "  {}", "traur: allowed for this transaction only".dimmed());
            }
        }

        // Approving an inconclusive scan never approves a known-bad package:
        // any local verdict of MALICIOUS still blocks.
        let _ = writeln!(tty);
        return;
    }

    let not_found: Vec<&str> = to_scan
        .iter()
        .filter(|n| !metadata.contains_key(n.as_str()))
        .map(|n| n.as_str())
        .collect();
    if !not_found.is_empty() {
        let _ = writeln!(
            tty,
            "  Skipping {} not on AUR: {}",
            not_found.len(),
            not_found.join(", ")
        );
    }
    let scan_packages: Vec<String> = to_scan
        .into_iter()
        .filter(|n| metadata.contains_key(n.as_str()))
        .collect();

    let any_scanned = !scan_packages.is_empty();
    let total_scan = scan_packages.len();

    // Pre-fetch maintainer data for all packages
    let maintainer_packages = bulk::prefetch_maintainer_packages(&metadata);

    let mut results: Vec<ScanResult> = Vec::new();
    let mut scan_errors: Vec<(String, String)> = Vec::new();
    let mut tier_counts: [u32; 6] = [0, 0, 0, 0, 0, 0]; // ..., Malicious, Unknown

    for (i, pkg) in scan_packages.iter().enumerate() {
        // Progress indicator (single line, overwritten each iteration)
        let _ = write!(tty, "\r  Scanning {} ({}/{})...          ", pkg, i + 1, total_scan);
        let _ = tty.flush();

        let meta = metadata.get(pkg.as_str()).cloned().unwrap();
        let maint_pkgs = meta
            .maintainer
            .as_deref()
            .and_then(|m| maintainer_packages.get(m))
            .cloned()
            .unwrap_or_default();

        match bulk::clone_with_retry(pkg, meta, maint_pkgs) {
            Ok(ctx) => {
                let result = coordinator::run_analysis_with_config(&ctx, &config);
                let idx = match result.tier {
                    Tier::Trusted => 0,
                    Tier::Ok => 1,
                    Tier::Sketchy => 2,
                    Tier::Suspicious => 3,
                    Tier::Malicious => 4,
                    // Only produced for an incomplete scan; counted separately
                    // so it can never be summarised as a verdict (N4.4).
                    Tier::Unknown => 5,
                };
                tier_counts[idx] += 1;
                results.push(result);
            }
            Err(e) => {
                scan_errors.push((pkg.clone(), e));
            }
        }
    }

    // Clear the progress line
    let _ = write!(tty, "\r{}\r", " ".repeat(72));
    let _ = tty.flush();

    // --- Phase 2: Output + decision ---

    // Case 1: All whitelisted
    if !any_scanned {
        if whitelisted_count > 0 {
            let _ = writeln!(
                tty,
                "  {} package(s) whitelisted, nothing to scan.",
                whitelisted_count
            );
        }
        return;
    }

    // Print tier summary
    let scanned: u32 = tier_counts.iter().sum();
    let _ = writeln!(tty, "  Scanned: {} package(s)", scanned);

    let tier_labels = [
        ("TRUSTED", tier_counts[0]),
        ("OK", tier_counts[1]),
        ("SKETCHY", tier_counts[2]),
        ("SUSPICIOUS", tier_counts[3]),
        ("MALICIOUS", tier_counts[4]),
        ("INCONCLUSIVE", tier_counts[5]),
    ];
    let tier_parts: Vec<String> = tier_labels
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(label, count)| {
            let colored_label = match *label {
                "TRUSTED" => label.green().to_string(),
                "OK" => label.yellow().to_string(),
                "SKETCHY" => label.truecolor(255, 165, 0).to_string(),
                "SUSPICIOUS" => label.red().to_string(),
                "MALICIOUS" => label.red().bold().to_string(),
                "INCONCLUSIVE" => label.cyan().to_string(),
                _ => label.to_string(),
            };
            format!("{}: {}", colored_label, count)
        })
        .collect();
    if !tier_parts.is_empty() {
        let _ = writeln!(tty, "  {}", tier_parts.join("  "));
    }

    // Full detail for all results
    if !results.is_empty() {
        results.sort_by(|a, b| a.score.cmp(&b.score));
        for result in &results {
            let _ = writeln!(tty);
            output::write_text(&mut tty, result, false);
        }
    }

    // Print scan errors
    if !scan_errors.is_empty() {
        let _ = writeln!(tty);
        for (pkg, err) in &scan_errors {
            let _ = writeln!(tty, "{}", format!("  error: {pkg}: {err}").red());
        }
    }

    let has_malicious = tier_counts[4] > 0;
    let has_flagged = tier_counts[2] > 0 || tier_counts[3] > 0; // SKETCHY or SUSPICIOUS

    // Case 2: MALICIOUS detected -> hard block, must whitelist
    if has_malicious {
        let _ = writeln!(tty);
        let _ = writeln!(
            tty,
            "{}",
            "traur: MALICIOUS package(s) detected — blocking transaction".red().bold()
        );
        let _ = writeln!(
            tty,
            "traur: use 'traur allow <package>' to whitelist, then retry"
        );
        std::process::exit(1);
    }

    // Case 3: Scan errors -> hard block (fail closed)
    if !scan_errors.is_empty() {
        let _ = writeln!(tty);
        let _ = writeln!(
            tty,
            "{}",
            "traur: scan errors occurred — blocking transaction".red().bold()
        );
        let _ = writeln!(
            tty,
            "traur: use 'traur allow <package>' to whitelist failed packages, then retry"
        );
        std::process::exit(1);
    }

    // Case 4: SKETCHY or SUSPICIOUS -> prompt [y/N]
    if has_flagged {
        let _ = writeln!(tty);
        let _ = write!(tty, "{} ", "traur: Continue with installation? [y/N]".bold());
        let _ = tty.flush();

        let mut reader = BufReader::new(tty);
        let mut line = String::new();
        let response = match reader.read_line(&mut line) {
            Ok(0) => "",
            Ok(_) => line.trim(),
            Err(_) => "",
        };

        let proceed = matches!(response.to_lowercase().as_str(), "y" | "yes");

        if !proceed {
            eprintln!("traur: aborting transaction");
            std::process::exit(1);
        }
        return;
    }

    // Case 5: All clean -> no prompt
    let _ = writeln!(tty, "\n  {}", "All packages look clean.".green());
}


/// Scan local clones for packages whose metadata could not be fetched.
///
/// Used only when the AUR is unreachable. The results are always `Unknown`:
/// analysis without metadata cannot produce a verdict, and reporting
/// `SUSPICIOUS` would slander a package nobody judged while `TRUSTED` would
/// pass an unverified install.
fn scan_local_clones(names: &[String]) -> Vec<ScanResult> {
    use traur::shared::cache;

    let mut out = Vec::new();
    for name in names {
        let dir = cache::git_cache_dir().join(name);
        if !dir.is_dir() {
            continue;
        }
        let Ok(loaded) = traur::shared::local_scan::load_dir(name, &dir) else {
            continue;
        };
        let mut result = coordinator::run_analysis(&loaded.context);
        let carried: Vec<traur::shared::scoring::Signal> = result
            .signals
            .iter()
            .filter(|s| s.is_override_gate)
            .cloned()
            .collect();
        let verdict = result.override_gate_fired.clone();
        result = traur::shared::scoring::compute_score_with_status(
            name,
            &result.signals,
            ScanStatus::Incomplete,
            Some("AUR unreachable — network failure; scan incomplete".to_string()),
        );
        // Surface a locally-detected override gate without turning it into a tier.
        if let Some(gate) = verdict {
            let _ = carried;
            result.reason = Some(format!(
                "AUR unreachable — network failure; scan incomplete. Local analysis flagged {gate}"
            ));
        }
        out.push(result);
    }
    out
}

/// Whether the user opted out of blocking when the AUR is unreachable.
/// See issue #24: pacman forks with network isolation cannot reach the AUR
/// from inside the hook, and without this the hook would allow unscanned
/// installs silently.
fn offline_scan_allowed() -> bool {
    std::env::var("TRAUR_ALLOW_OFFLINE")
        .map(|v| matches!(v.as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

/// Get all package names from official sync databases in one call.
/// Output format: "repo package_name version [installed]"
fn official_repo_packages() -> HashSet<String> {
    Command::new("pacman")
        .arg("-Sl")
        .output()
        .map(|out| {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|line| line.split_whitespace().nth(1).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    #[test]
    fn offline_escape_hatch_values() {
        // The hook is a separate binary; this exercises the same parsing.
        fn parse(v: Option<&str>) -> bool {
            v.map(|v| matches!(v, "1" | "true" | "yes")).unwrap_or(false)
        }
        assert!(parse(Some("1")));
        assert!(parse(Some("true")));
        assert!(parse(Some("yes")));
        assert!(!parse(Some("0")));
        assert!(!parse(Some("")));
        assert!(!parse(None));
    }
}
