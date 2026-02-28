use std::io::Write;
use crate::shared::scoring::ScanResult;
use crate::shared::rules::Verdict;
use colored::Colorize;

/// Print scan result as colored terminal text to stderr.
pub fn print_text(result: &ScanResult, verbose: bool) {
    write_text(&mut std::io::stderr(), result, verbose);
}

/// Write scan result as colored terminal text to an arbitrary writer.
pub fn write_text(w: &mut dyn Write, result: &ScanResult, verbose: bool) {
    let verdict_colored = match result.verdict {
        Verdict::Trusted => result.verdict.to_string().green(),
        Verdict::Ok => result.verdict.to_string().yellow(),
        Verdict::Suspicious => result.verdict.to_string().truecolor(255, 165, 0), // orange
        Verdict::Malicious => result.verdict.to_string().red().bold(),
    };

    let _ = writeln!(
        w,
        "{} {}",
        "traur:".bold(),
        result.package.bold(),
    );
    let _ = writeln!(w, "  Verdict: {verdict_colored}");

    if let Some(ref rule) = result.fired_rule {
        let _ = writeln!(w, "  Fired rule: {rule}");
    }

    if result.detections.is_empty() {
        let _ = writeln!(w, "  No detections.");
    } else {
        let _ = writeln!(w, "  Detections:");
        for detection in &result.detections {
            let _ = writeln!(
                w,
                "    {} [{:?}]: {} (salience: {})",
                detection.rule_id, detection.verdict, detection.description, detection.salience
            );
            if verbose {
                if let Some(ref line) = detection.matched_line {
                    let _ = writeln!(w, "         {} {}", ">".dimmed(), line.dimmed());
                }
            }
        }
    }
}

/// Print scan result as JSON.
pub fn print_json(result: &ScanResult) {
    let json = serde_json::to_string_pretty(result).expect("Failed to serialize");
    println!("{json}");
}
