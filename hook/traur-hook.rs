//! traur-hook: ALPM pre-transaction hook binary.
//! Reads package names from stdin (passed by pacman/paru via NeedsTargets),
//! filters to AUR-only packages, scans each using the traur library directly,
//! shows all results, and prompts the user before continuing.
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
use traur::shared::scoring::Tier;

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
    let mut has_critical = false;
    let mut has_high = false;
    let mut has_scan_error = false;
    let mut any_scanned = false;

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

    for pkg in &aur_packages {
        if is_whitelisted_in(&config, pkg) {
            let _ = writeln!(tty, "traur: {pkg} (whitelisted, skipping scan)");
            continue;
        }

        any_scanned = true;

        match coordinator::build_context(pkg) {
            Ok(ctx) => {
                let result = coordinator::run_analysis(&ctx);
                output::write_text(&mut tty, &result, false);
                if result.tier >= Tier::Suspicious {
                    has_critical = true;
                } else if result.tier >= Tier::Sketchy {
                    has_high = true;
                }
            }
            Err(e) => {
                let _ = writeln!(tty, "{}", format!("traur: failed to scan '{pkg}': {e}").red());
                has_scan_error = true;
            }
        }
    }

    if !any_scanned {
        return; // All packages were whitelisted
    }

    if has_critical {
        let _ = writeln!(tty);
        let _ = writeln!(
            tty,
            "{}",
            "traur: SUSPICIOUS/MALICIOUS packages detected above".red().bold()
        );
        let _ = writeln!(
            tty,
            "traur: use 'traur allow <package>' to whitelist, then retry"
        );
        std::process::exit(1);
    }

    if has_scan_error {
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

    // Prompt: default Y for trusted, default N for SKETCHY
    let default_yes = !has_high;
    let prompt_text = if default_yes {
        "traur: Continue with installation? [Y/n]"
    } else {
        "traur: Continue with installation? [y/N]"
    };

    let _ = writeln!(tty);
    let _ = write!(tty, "{} ", prompt_text.bold());
    let _ = tty.flush();

    let mut reader = BufReader::new(tty);
    let mut line = String::new();
    let response = match reader.read_line(&mut line) {
        Ok(0) => "",
        Ok(_) => line.trim(),
        Err(_) => "",
    };

    let proceed = match response.to_lowercase().as_str() {
        "y" | "yes" => true,
        "n" | "no" => false,
        "" => default_yes, // Enter = use default
        _ => default_yes,
    };

    if !proceed {
        eprintln!("traur: aborting transaction");
        std::process::exit(1);
    }
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
