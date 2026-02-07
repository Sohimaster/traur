//! traur-hook: ALPM pre-transaction hook binary.
//! Reads package names from stdin (passed by pacman/paru via NeedsTargets),
//! filters to AUR-only packages, scans each using the traur library directly,
//! shows all results, and prompts the user before continuing.
//!
//! All output goes to /dev/tty — pacman buffers both stdout and stderr from
//! hooks, so we must write directly to the terminal.

use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
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

    // Filter to AUR-only packages
    let aur_packages: Vec<String> = packages
        .into_iter()
        .filter(|pkg| !is_in_official_repos(pkg))
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
    let _ = writeln!(tty, "  {}", "AUR Package Security Scanner".dimmed());
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
                if result.tier >= Tier::Critical {
                    has_critical = true;
                }
            }
            Err(e) => {
                let _ = writeln!(tty, "traur: failed to scan '{pkg}': {e}");
                // Fail open on scan errors
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
            "traur: CRITICAL/MALICIOUS packages detected above".red().bold()
        );
        let _ = writeln!(
            tty,
            "traur: use 'traur allow <package>' to whitelist, then retry"
        );
        std::process::exit(1);
    }

    // Prompt and read response via the same /dev/tty fd
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

    match response.to_lowercase().as_str() {
        "y" | "yes" => {} // proceed
        _ => {
            eprintln!("traur: aborting transaction");
            std::process::exit(1);
        }
    }
}

/// Check if a package exists in the official sync databases.
fn is_in_official_repos(pkg_name: &str) -> bool {
    Command::new("pacman")
        .args(["-Si", pkg_name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}
