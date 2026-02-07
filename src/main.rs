mod bench;
mod coordinator;
mod features;
mod shared;

use clap::{Parser, Subcommand};
use std::process;

#[derive(Parser)]
#[command(name = "traur", about = "Trust scoring for AUR packages")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a package (or all installed AUR packages if none specified)
    Scan {
        /// Package name to scan (or --pkgbuild for local)
        package: Option<String>,

        /// Scan a local PKGBUILD directory
        #[arg(long)]
        pkgbuild: Option<String>,

        /// Scan all installed AUR packages (default when no package given)
        #[arg(long)]
        all_installed: bool,

        /// Number of concurrent scan threads (for bulk scanning)
        #[arg(long, default_value_t = 4)]
        jobs: usize,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Show the exact line that triggered each signal
        #[arg(short = 'v', long)]
        verbose: bool,

        /// Show all packages (including LOW and MEDIUM)
        #[arg(short = 'a', long)]
        all: bool,
    },
    /// Whitelist a package (skip future scans)
    Allow {
        /// Package name to whitelist
        package: String,
    },
    /// Benchmark scanning the N most recently modified AUR packages
    Bench {
        /// Number of packages to scan
        #[arg(long, default_value_t = 1000)]
        count: usize,

        /// Number of concurrent scan threads
        #[arg(long, default_value_t = 8)]
        jobs: usize,
    },
}

fn main() {
    let cli = Cli::parse();

    let exit_code = match cli.command {
        Commands::Scan {
            package,
            pkgbuild,
            all_installed,
            jobs,
            json,
            verbose,
            all,
        } => cmd_scan(package, pkgbuild, all_installed, jobs, json, verbose, all),
        Commands::Allow { package } => cmd_allow(&package),
        Commands::Bench { count, jobs } => bench::run(count, jobs),
    };

    process::exit(exit_code);
}

fn cmd_scan(
    package: Option<String>,
    pkgbuild: Option<String>,
    _all_installed: bool,
    jobs: usize,
    json: bool,
    verbose: bool,
    all: bool,
) -> i32 {
    if let Some(path) = pkgbuild {
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error reading {path}: {e}");
                return 1;
            }
        };
        let name = std::path::Path::new(&path)
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("local");
        let result = coordinator::scan_pkgbuild(name, &content);
        if json {
            shared::output::print_json(&result);
        } else {
            shared::output::print_text(&result, verbose);
        }
        return if result.tier >= shared::scoring::Tier::Suspicious { 1 } else { 0 };
    }

    if let Some(pkg) = package {
        return cmd_scan_single(&pkg, json, verbose);
    }

    // No package, no pkgbuild -> scan all installed AUR packages
    cmd_scan_all_installed(jobs, json, verbose, all)
}

fn cmd_scan_single(pkg: &str, json: bool, verbose: bool) -> i32 {
    match coordinator::scan_package(pkg, json, verbose) {
        Ok(tier) => {
            use shared::scoring::Tier;
            match tier {
                Tier::Trusted | Tier::Ok | Tier::Sketchy => 0,
                Tier::Suspicious | Tier::Malicious => 1,
            }
        }
        Err(e) => {
            eprintln!("Error scanning {pkg}: {e}");
            1
        }
    }
}

fn cmd_scan_all_installed(jobs: usize, json: bool, verbose: bool, all: bool) -> i32 {
    use crate::shared::bulk::{batch_fetch_metadata, clone_with_retry, prefetch_maintainer_packages};
    use crate::shared::scoring::{ScanResult, Tier};
    use colored::Colorize;
    use indicatif::{ProgressBar, ProgressStyle};
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    let names = match get_installed_aur_packages() {
        Ok(names) if names.is_empty() => {
            eprintln!("No AUR packages installed.");
            return 0;
        }
        Ok(names) => names,
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };

    let total = names.len();
    eprintln!(
        "{}",
        format!("Scanning {} installed AUR packages...", total).bold()
    );

    eprintln!("  Fetching package metadata...");
    let metadata = batch_fetch_metadata(&names);
    eprintln!("  Got metadata for {}/{} packages", metadata.len(), total);

    let maintainer_packages = prefetch_maintainer_packages(&metadata);

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(jobs)
        .build()
        .expect("Failed to build thread pool");

    let pb = ProgressBar::new(total as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({per_sec})")
            .unwrap()
            .progress_chars("##-"),
    );

    let tier_counts: [AtomicU64; 5] = std::array::from_fn(|_| AtomicU64::new(0));
    let error_count = AtomicU64::new(0);
    let flagged = std::sync::Mutex::new(Vec::<ScanResult>::new());

    pool.install(|| {
        names.par_iter().for_each(|name| {
            let result = if let Some(meta) = metadata.get(name).cloned() {
                let maint_pkgs = meta
                    .maintainer
                    .as_deref()
                    .and_then(|m| maintainer_packages.get(m))
                    .cloned()
                    .unwrap_or_default();

                match clone_with_retry(name, meta, maint_pkgs) {
                    Ok(ctx) => Ok(coordinator::run_analysis(&ctx)),
                    Err(e) => Err(e),
                }
            } else {
                Err("not found on AUR".to_string())
            };

            match result {
                Ok(scan) => {
                    let idx = match scan.tier {
                        Tier::Trusted => 0,
                        Tier::Ok => 1,
                        Tier::Sketchy => 2,
                        Tier::Suspicious => 3,
                        Tier::Malicious => 4,
                    };
                    tier_counts[idx].fetch_add(1, Ordering::Relaxed);

                    if all || scan.tier >= Tier::Sketchy {
                        flagged.lock().unwrap().push(scan);
                    }
                }
                Err(_) => {
                    error_count.fetch_add(1, Ordering::Relaxed);
                }
            }

            pb.inc(1);
        });
    });

    pb.finish_and_clear();

    let mut flagged = flagged.into_inner().unwrap();
    let errors = error_count.load(Ordering::Relaxed) as usize;
    let scanned = total - errors;

    if json {
        flagged.sort_by(|a, b| a.score.cmp(&b.score));
        let json_str = serde_json::to_string_pretty(&flagged).expect("Failed to serialize");
        println!("{json_str}");
    } else {
        println!();
        println!("{}", "=== traur scan results ===".bold());
        println!("  Scanned: {} packages ({} errors)", scanned, errors);
        println!(
            "  TRUSTED: {}  OK: {}  SKETCHY: {}  SUSPICIOUS: {}  MALICIOUS: {}",
            tier_counts[0].load(Ordering::Relaxed),
            tier_counts[1].load(Ordering::Relaxed),
            tier_counts[2].load(Ordering::Relaxed),
            tier_counts[3].load(Ordering::Relaxed),
            tier_counts[4].load(Ordering::Relaxed),
        );

        if !flagged.is_empty() {
            flagged.sort_by(|a, b| a.score.cmp(&b.score));
            println!();
            println!(
                "{}",
                format!(
                    "=== {} {} ===",
                    flagged.len(),
                    if all { "packages" } else { "flagged packages (SKETCHY+)" }
                )
                .bold()
            );
            for result in &flagged {
                println!();
                shared::output::print_text(result, verbose);
            }
        } else {
            println!();
            println!("{}", "All packages look clean.".green());
        }
    }

    let has_critical = tier_counts[3].load(Ordering::Relaxed) > 0
        || tier_counts[4].load(Ordering::Relaxed) > 0;
    if has_critical { 1 } else { 0 }
}

/// Get list of installed AUR (foreign) package names via `pacman -Qm`.
fn get_installed_aur_packages() -> Result<Vec<String>, String> {
    use std::process::Command;

    let output = Command::new("pacman")
        .args(["-Qm"])
        .output()
        .map_err(|e| format!("Failed to run pacman: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("pacman -Qm failed: {stderr}"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let names: Vec<String> = stdout
        .lines()
        .filter_map(|line| {
            let name = line.split_whitespace().next()?;
            if name.is_empty() {
                None
            } else {
                Some(name.to_string())
            }
        })
        .collect();

    Ok(names)
}

fn cmd_allow(package: &str) -> i32 {
    match shared::config::add_to_whitelist(package) {
        Ok(()) => {
            eprintln!("Whitelisted: {package}");
            eprintln!("  Saved to {}", shared::config::config_path().display());
            0
        }
        Err(e) => {
            eprintln!("Error: {e}");
            1
        }
    }
}
