//! Offline corpus harness.
//!
//! Every other quality claim in this repository depends on being able to run
//! the detector over real PKGBUILDs with no network. Before this file, the only
//! empirical data was a hand-run scan against whatever happened to be in a
//! developer's cache, and no test ever exercised `build_context`; four closed
//! false-positive reports (#12, #13, #27, #11) were therefore unfixable by CI.
//!
//! Two corpora, both required:
//!
//! - **benign**: real AUR packages, which set the false-positive budget. A case
//!   declares `max_tier`, so the assertion is a policy ("this normal package
//!   must stay at OK or better"), not a snapshot of whatever the detector
//!   happened to output when the test was written.
//! - **malicious**: samples derived from AUR incidents, which set the recall
//!   floor. A case declares `min_tier` and the signals that must fire.
//!
//! Case files live in `tests/corpus/<kind>/<name>/` as a PKGBUILD plus optional
//! `.install` and committed sources, so a case can reproduce a directory-shaped
//! package exactly as `makepkg` would see it.
//!
//! Run `cargo test --test corpus_cases -- --nocapture` to print the report.

use std::path::{Path, PathBuf};
use traur::coordinator;
use traur::shared::local_scan;
use traur::shared::scoring::{Tier, TierName};

/// Parsed case metadata from a `CASE` file next to the PKGBUILD.
#[derive(Debug, Default)]
struct Case {
    name: String,
    max_tier: Option<Tier>,
    min_tier: Option<Tier>,
    required: Vec<String>,
    forbidden: Vec<String>,
    /// Why this case exists. Shown in the report so the intent survives.
    note: String,
}

fn parse_case(dir: &Path) -> Case {
    let mut case = Case {
        name: dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<unnamed>")
            .to_string(),
        ..Default::default()
    };
    let Ok(text) = std::fs::read_to_string(dir.join("CASE")) else {
        return case;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "max_tier" => case.max_tier = TierName::parse(value),
            "min_tier" => case.min_tier = TierName::parse(value),
            "required" => case.required = split_list(value),
            "forbidden" => case.forbidden = split_list(value),
            "note" => case.note = value.to_string(),
            // Provenance, recorded but not an assertion.
            "revision" | "source" | "incident" | "date" => {}
            other => panic!("unknown key `{other}` in CASE file for {}", case.name),
        }
    }
    case
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn case_dirs(kind: &str) -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
        .join(kind);
    let Ok(entries) = std::fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir() && p.join("PKGBUILD").is_file())
        .collect();
    dirs.sort();
    dirs
}

fn scan_case(dir: &Path) -> Option<traur::shared::scoring::ScanResult> {
    let name = dir.file_name()?.to_str()?;
    let loaded = local_scan::load_dir(name, dir).ok()?;
    Some(coordinator::run_analysis(&loaded.context))
}

#[test]
fn benign_corpus_stays_within_the_false_positive_budget() {
    let dirs = case_dirs("benign");
    if dirs.is_empty() {
        eprintln!("no benign cases committed yet");
        return;
    }

    let mut flagged = Vec::new();
    let mut failures = Vec::new();

    for dir in &dirs {
        let case = parse_case(dir);
        let Some(result) = scan_case(dir) else {
            failures.push(format!("{}: could not scan", case.name));
            continue;
        };

        eprintln!(
            "  benign  {:<32} {:3}  {:<18} {}",
            case.name,
            result.score,
            result.tier.to_string(),
            result
                .signals
                .iter()
                .map(|s| s.id.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        );

        if let Some(max) = case.max_tier
            && result.tier > max
        {
            failures.push(format!(
                "{}: scored {} ({}), must be at most {} — {}",
                case.name,
                result.tier,
                result.score,
                max,
                case.note
            ));
        }
        for id in &case.forbidden {
            if result.signals.iter().any(|s| s.id == *id) {
                failures.push(format!("{}: forbidden signal {id} fired", case.name));
            }
        }
        if result.tier >= Tier::Sketchy {
            flagged.push(case.name.clone());
        }
    }

    eprintln!(
        "\n  benign false positives (SKETCHY+): {} of {}",
        flagged.len(),
        dirs.len()
    );
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn malicious_corpus_meets_the_recall_floor() {
    let dirs = case_dirs("malicious");
    if dirs.is_empty() {
        eprintln!("no malicious cases committed yet");
        return;
    }

    let mut failures = Vec::new();

    for dir in &dirs {
        let case = parse_case(dir);
        let Some(result) = scan_case(dir) else {
            failures.push(format!("{}: could not scan", case.name));
            continue;
        };

        eprintln!(
            "  malicious {:<30} {:3}  {:<18} {}",
            case.name,
            result.score,
            result.tier.to_string(),
            result
                .signals
                .iter()
                .map(|s| s.id.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        );

        if let Some(min) = case.min_tier
            && result.tier < min
        {
            failures.push(format!(
                "{}: scored {} ({}), must be at least {} — {}",
                case.name,
                result.tier,
                result.score,
                min,
                case.note
            ));
        }
        for id in &case.required {
            // A case may name a family (`SA-PIPE-`) or one id.
            let hit = result.signals.iter().any(|s| s.id.contains(id.as_str()));
            if !hit {
                failures.push(format!(
                    "{}: required signal {id} did not fire (got: {})",
                    case.name,
                    result
                        .signals
                        .iter()
                        .map(|s| s.id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
    }

    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}
