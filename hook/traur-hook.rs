//! traur-hook: ALPM pre-transaction hook binary.
//! Reads package names from stdin (passed by pacman/paru via NeedsTargets),
//! filters to AUR-only packages, runs traur scan on each, and exits non-zero
//! if any package scores CRITICAL or higher.

use std::io::{self, BufRead};
use std::process::Command;

fn main() {
    let stdin = io::stdin();
    let mut failed = false;

    for line in stdin.lock().lines() {
        let Ok(pkg_name) = line else { continue };
        let pkg_name = pkg_name.trim().to_string();
        if pkg_name.is_empty() {
            continue;
        }

        // Skip packages in official repos (core, extra, multilib)
        if is_in_official_repos(&pkg_name) {
            continue;
        }

        // Run traur scan on AUR packages
        let status = Command::new("traur")
            .args(["scan", &pkg_name])
            .status();

        match status {
            Ok(s) if !s.success() => {
                eprintln!("traur: package '{pkg_name}' flagged as suspicious");
                failed = true;
            }
            Err(e) => {
                eprintln!("traur: failed to scan '{pkg_name}': {e}");
                // Don't block on scan failures — fail open
            }
            _ => {}
        }
    }

    if failed {
        eprintln!("traur: aborting transaction due to suspicious packages");
        eprintln!("traur: use 'traur allow <package>' to whitelist, then retry");
        std::process::exit(1);
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
