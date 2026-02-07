mod bench;
mod coordinator;
mod features;
mod shared;

use clap::{Parser, Subcommand};
use std::process;

#[derive(Parser)]
#[command(name = "traur", about = "Heuristic security scanner for AUR packages")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a package for security issues
    Scan {
        /// Package name to scan (or --pkgbuild for local)
        package: Option<String>,

        /// Scan a local PKGBUILD directory
        #[arg(long)]
        pkgbuild: Option<String>,

        /// Scan all installed AUR packages
        #[arg(long)]
        all_installed: bool,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show detailed signal breakdown for a package
    Report {
        /// Package name
        package: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,
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
            json,
        } => cmd_scan(package, pkgbuild, all_installed, json),
        Commands::Report { package, json } => cmd_report(&package, json),
        Commands::Allow { package } => cmd_allow(&package),
        Commands::Bench { count, jobs } => bench::run(count, jobs),
    };

    process::exit(exit_code);
}

fn cmd_scan(
    package: Option<String>,
    pkgbuild: Option<String>,
    all_installed: bool,
    json: bool,
) -> i32 {
    if all_installed {
        eprintln!("Scanning all installed AUR packages...");
        // TODO: enumerate installed AUR packages
        return 0;
    }

    if let Some(path) = pkgbuild {
        eprintln!("Scanning local PKGBUILD at {path}...");
        // TODO: local PKGBUILD scan
        return 0;
    }

    let Some(pkg) = package else {
        eprintln!("Error: provide a package name, --pkgbuild path, or --all-installed");
        return 1;
    };

    match coordinator::scan_package(&pkg, json) {
        Ok(tier) => {
            use shared::scoring::Tier;
            match tier {
                Tier::Low | Tier::Medium => 0,
                Tier::High => 0,
                Tier::Critical | Tier::Malicious => 1,
            }
        }
        Err(e) => {
            eprintln!("Error scanning {pkg}: {e}");
            1
        }
    }
}

fn cmd_report(package: &str, json: bool) -> i32 {
    match coordinator::scan_package(package, json) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("Error: {e}");
            1
        }
    }
}

fn cmd_allow(package: &str) -> i32 {
    eprintln!("Whitelisted: {package}");
    // TODO: persist to config
    0
}
