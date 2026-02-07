use crate::coordinator;
use crate::shared::bulk::{
    batch_fetch_metadata, clone_with_retry, prefetch_maintainer_packages, RPC_BATCH_SIZE,
};
use crate::shared::models::MetaDumpPackage;
use crate::shared::output;
use crate::shared::scoring::{ScanResult, Tier};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::collections::HashSet;
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const META_DUMP_URL: &str = "https://aur.archlinux.org/packages-meta-v1.json.gz";

struct BenchStats {
    total: usize,
    scanned: usize,
    errors: usize,
    tier_counts: [usize; 5],
    total_time: Duration,
    prefetch_time: Duration,
    clone_time_us: u64,
    analysis_time_us: u64,
    scan_wall_time: Duration,
    error_samples: Vec<(String, String)>,
}

fn fetch_recent_packages(count: usize) -> Result<Vec<MetaDumpPackage>, String> {
    eprintln!("  Fetching AUR package metadata dump...");

    let response = reqwest::blocking::get(META_DUMP_URL)
        .map_err(|e| format!("Failed to fetch metadata dump: {e}"))?;

    let decoder = flate2::read::GzDecoder::new(response);
    let mut json_str = String::new();
    std::io::BufReader::new(decoder)
        .read_to_string(&mut json_str)
        .map_err(|e| format!("Failed to decompress metadata: {e}"))?;

    let mut packages: Vec<MetaDumpPackage> = serde_json::from_str(&json_str)
        .map_err(|e| format!("Failed to parse metadata JSON: {e}"))?;

    packages.sort_unstable_by(|a, b| b.last_modified.cmp(&a.last_modified));

    let mut seen = HashSet::new();
    packages.retain(|p| seen.insert(p.package_base.clone()));

    packages.truncate(count);
    Ok(packages)
}

pub fn run(count: usize, jobs: usize) -> i32 {
    let start = Instant::now();

    // Phase 1: prefetch all metadata
    eprintln!("{}", "Phase 1: Prefetching metadata...".bold());

    let packages = match fetch_recent_packages(count) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };

    let total = packages.len();
    eprintln!("  Selected {} packages", total);

    let names: Vec<String> = packages.iter().map(|p| p.name.clone()).collect();

    eprintln!("  Batch-fetching package metadata ({} RPC calls)...",
        (names.len() + RPC_BATCH_SIZE - 1) / RPC_BATCH_SIZE);
    let metadata = batch_fetch_metadata(&names);
    eprintln!("  Got metadata for {} packages", metadata.len());

    let maintainer_packages = prefetch_maintainer_packages(&metadata);

    let prefetch_time = start.elapsed();
    eprintln!("  Prefetch done in {:.1}s\n", prefetch_time.as_secs_f64());

    // Phase 2: parallel git clone + analysis
    eprintln!("{}", format!("Phase 2: Scanning {} packages ({} threads)...", total, jobs).bold());

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

    let scan_start = Instant::now();

    let error_count = AtomicU64::new(0);
    let tier_counts: [AtomicU64; 5] = std::array::from_fn(|_| AtomicU64::new(0));
    let clone_time_us = AtomicU64::new(0);
    let analysis_time_us = AtomicU64::new(0);
    let error_samples = std::sync::Mutex::new(Vec::<(String, String)>::new());
    let flagged = std::sync::Mutex::new(Vec::<ScanResult>::new());

    pool.install(|| {
        packages.par_iter().for_each(|pkg| {
            let name = &pkg.name;

            let result = if let Some(meta) = metadata.get(name).cloned() {
                let maint_pkgs = meta
                    .maintainer
                    .as_deref()
                    .and_then(|m| maintainer_packages.get(m))
                    .cloned()
                    .unwrap_or_default();

                // Time clone separately from analysis
                let t0 = Instant::now();
                let ctx = clone_with_retry(name, meta, maint_pkgs);
                clone_time_us.fetch_add(t0.elapsed().as_micros() as u64, Ordering::Relaxed);

                match ctx {
                    Ok(ctx) => {
                        let t1 = Instant::now();
                        let scan = coordinator::run_analysis(&ctx);
                        analysis_time_us.fetch_add(t1.elapsed().as_micros() as u64, Ordering::Relaxed);
                        Ok(scan)
                    }
                    Err(e) => Err(e),
                }
            } else {
                Err("metadata not found in batch fetch".to_string())
            };

            match result {
                Ok(scan) => {
                    let idx = tier_to_index(scan.tier);
                    tier_counts[idx].fetch_add(1, Ordering::Relaxed);

                    if scan.tier >= Tier::High {
                        flagged.lock().unwrap().push(scan);
                    }
                }
                Err(e) => {
                    error_count.fetch_add(1, Ordering::Relaxed);
                    let mut samples = error_samples.lock().unwrap();
                    if samples.len() < 10 {
                        samples.push((name.clone(), e));
                    }
                }
            }

            pb.inc(1);
        });
    });

    pb.finish_and_clear();
    let scan_wall_time = scan_start.elapsed();
    let total_time = start.elapsed();

    let stats = BenchStats {
        total,
        scanned: total - error_count.load(Ordering::Relaxed) as usize,
        errors: error_count.load(Ordering::Relaxed) as usize,
        tier_counts: std::array::from_fn(|i| tier_counts[i].load(Ordering::Relaxed) as usize),
        total_time,
        prefetch_time,
        clone_time_us: clone_time_us.load(Ordering::Relaxed),
        analysis_time_us: analysis_time_us.load(Ordering::Relaxed),
        scan_wall_time,
        error_samples: error_samples.into_inner().unwrap(),
    };

    print_report(&stats);

    // Print detailed output for HIGH/CRITICAL/MALICIOUS packages
    let mut flagged = flagged.into_inner().unwrap();
    if !flagged.is_empty() {
        flagged.sort_by(|a, b| b.score.cmp(&a.score));
        println!();
        println!("{}", format!("=== {} flagged packages (HIGH+) ===", flagged.len()).bold());
        for result in &flagged {
            println!();
            output::print_text(result);
        }
    }

    0
}

fn tier_to_index(tier: Tier) -> usize {
    match tier {
        Tier::Low => 0,
        Tier::Medium => 1,
        Tier::High => 2,
        Tier::Critical => 3,
        Tier::Malicious => 4,
    }
}

fn print_report(stats: &BenchStats) {
    let pct = |n: usize| -> f64 {
        if stats.scanned == 0 {
            0.0
        } else {
            n as f64 / stats.scanned as f64 * 100.0
        }
    };

    let clone_secs = stats.clone_time_us as f64 / 1_000_000.0;
    let analysis_secs = stats.analysis_time_us as f64 / 1_000_000.0;
    let avg_clone_ms = if stats.scanned > 0 {
        stats.clone_time_us as f64 / stats.scanned as f64 / 1_000.0
    } else {
        0.0
    };
    let avg_analysis_ms = if stats.scanned > 0 {
        stats.analysis_time_us as f64 / stats.scanned as f64 / 1_000.0
    } else {
        0.0
    };

    println!();
    println!("{}", "=== traur bench results ===".bold());
    println!();
    println!(
        "  Packages:    {} requested, {} scanned, {} errors",
        stats.total, stats.scanned, stats.errors
    );
    println!();
    println!("{}", "  Timing:".bold());
    println!(
        "    Prefetch:    {:>7.1}s  (metadata + maintainer data)",
        stats.prefetch_time.as_secs_f64()
    );
    println!(
        "    Git clone:   {:>7.1}s cumulative, {:>7.1}ms avg/pkg",
        clone_secs, avg_clone_ms
    );
    println!(
        "    Analysis:    {:>7.1}s cumulative, {:>7.1}ms avg/pkg",
        analysis_secs, avg_analysis_ms
    );
    println!(
        "    Wall clock:  {:>7.1}s  (scan phase)",
        stats.scan_wall_time.as_secs_f64()
    );
    println!(
        "    Total:       {:>7.1}s",
        stats.total_time.as_secs_f64()
    );
    println!(
        "    Throughput:  {:>7.1} pkg/s",
        stats.scanned as f64 / stats.scan_wall_time.as_secs_f64()
    );
    println!();
    println!("{}", "  Tier distribution:".bold());
    println!("    LOW:       {:>5}  ({:.1}%)", stats.tier_counts[0], pct(stats.tier_counts[0]));
    println!("    MEDIUM:    {:>5}  ({:.1}%)", stats.tier_counts[1], pct(stats.tier_counts[1]));
    println!("    HIGH:      {:>5}  ({:.1}%)", stats.tier_counts[2], pct(stats.tier_counts[2]));
    println!("    CRITICAL:  {:>5}  ({:.1}%)", stats.tier_counts[3], pct(stats.tier_counts[3]));
    println!("    MALICIOUS: {:>5}  ({:.1}%)", stats.tier_counts[4], pct(stats.tier_counts[4]));

    if !stats.error_samples.is_empty() {
        println!();
        println!("{}", "  Sample errors:".bold());
        for (name, err) in &stats.error_samples {
            println!("    {name}: {err}");
        }
    }
}
