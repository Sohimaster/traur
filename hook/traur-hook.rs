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
use traur::shared::config::{self, is_whitelisted_in};
use traur::shared::output;
use traur::shared::scoring::{ScanResult, Tier};

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
    let total_aur = aur_packages.len();
    let mut flagged: Vec<ScanResult> = Vec::new();
    let mut scan_errors: Vec<(String, String)> = Vec::new();
    let mut whitelisted_count: u32 = 0;
    let mut tier_counts: [u32; 5] = [0, 0, 0, 0, 0]; // Trusted, Ok, Sketchy, Suspicious, Malicious
    let mut any_scanned = false;

    for (i, pkg) in aur_packages.iter().enumerate() {
        if is_whitelisted_in(&config, pkg) {
            whitelisted_count += 1;
            continue;
        }

        any_scanned = true;

        // Progress indicator (single line, overwritten each iteration)
        let _ = write!(tty, "\r  Scanning {} ({}/{})...          ", pkg, i + 1, total_aur);
        let _ = tty.flush();

        match coordinator::build_context(pkg) {
            Ok(ctx) => {
                let result = coordinator::run_analysis_with_config(&ctx, &config);
                let idx = match result.tier {
                    Tier::Trusted => 0,
                    Tier::Ok => 1,
                    Tier::Sketchy => 2,
                    Tier::Suspicious => 3,
                    Tier::Malicious => 4,
                };
                tier_counts[idx] += 1;

                if result.tier >= Tier::Sketchy {
                    flagged.push(result);
                }
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
                _ => label.to_string(),
            };
            format!("{}: {}", colored_label, count)
        })
        .collect();
    if !tier_parts.is_empty() {
        let _ = writeln!(tty, "  {}", tier_parts.join("  "));
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
        flagged.sort_by(|a, b| a.score.cmp(&b.score));
        let _ = writeln!(tty);
        for result in &flagged {
            output::write_text(&mut tty, result, false);
            let _ = writeln!(tty);
        }
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

    // Case 4: SKETCHY or SUSPICIOUS -> show detail, prompt [y/N]
    if has_flagged {
        flagged.sort_by(|a, b| a.score.cmp(&b.score));
        let _ = writeln!(tty);
        for result in &flagged {
            output::write_text(&mut tty, result, false);
            let _ = writeln!(tty);
        }

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
    let _ = writeln!(tty, "  {}", "All packages look clean.".green());
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
