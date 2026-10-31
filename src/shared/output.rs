use std::io::Write;
use crate::shared::scoring::{ScanResult, Tier};
use colored::Colorize;

/// Print scan result as colored terminal text to stderr.
pub fn print_text(result: &ScanResult, verbose: bool) {
    write_text(&mut std::io::stderr(), result, verbose);
}

/// Write scan result as colored terminal text to an arbitrary writer.
pub fn write_text(w: &mut dyn Write, result: &ScanResult, verbose: bool) {
    let tier_colored = match result.tier {
        Tier::Trusted => result.tier.to_string().green(),
        Tier::Ok => result.tier.to_string().yellow(),
        Tier::Sketchy => result.tier.to_string().truecolor(255, 165, 0), // orange
        Tier::Suspicious => result.tier.to_string().red(),
        Tier::Malicious => result.tier.to_string().red().bold(),
        // Not a judgement. Yellow-cyan on purpose: it must not read as a
        // verdict in either direction (issues #24, PLAN.md N4.4).
        Tier::Unknown => result.tier.to_string().cyan(),
    };

    let _ = writeln!(
        w,
        "{} {} (trust: {}/100)",
        "traur:".bold(),
        result.package.bold(),
        result.score
    );
    let _ = writeln!(w, "  Trust: {tier_colored}");

    if result.status == crate::shared::scoring::ScanStatus::Incomplete {
        let reason = result.reason.as_deref().unwrap_or("inputs were missing");
        let _ = writeln!(w, "  {} the scan could not conclude: {reason}", "??".cyan());
        let _ = writeln!(
            w,
            "     This is not a verdict. The package was neither verified nor\n     found suspicious; run the scan again once the inputs are available."
        );
        if !result.signals.is_empty() {
            let _ = writeln!(w, "  What could be checked:");
        }
    }

    if let Some(ref gate) = result.override_gate_fired {
        let _ = writeln!(w, "  {} Override gate fired: {gate}", "!!".red().bold());
    }

    if result.signals.is_empty() {
        if result.status == crate::shared::scoring::ScanStatus::Complete {
            let _ = writeln!(w, "  No negative signals found.");
        }
    } else {
        if result.status == crate::shared::scoring::ScanStatus::Complete {
            let _ = writeln!(w, "  Negative signals:");
        }
        for signal in &result.signals {
            // Facts describe what the package is, not what it does. They are
            // shown for completeness but marked so nobody reads a lifecycle
            // convention as a finding (PLAN.md N4.1).
            let prefix = if signal.is_override_gate {
                "!!".red().bold().to_string()
            } else if signal.role == crate::shared::scoring::SignalRole::Fact {
                "--".dimmed().to_string()
            } else if signal.points >= 60 {
                "!!".red().to_string()
            } else if signal.points >= 30 {
                " !".yellow().to_string()
            } else {
                "  ".to_string()
            };
            let label = if signal.role == crate::shared::scoring::SignalRole::Fact {
                format!("{} {}", signal.id, signal.description.dimmed())
            } else {
                format!("{}: {}", signal.id, signal.description)
            };
            let _ = writeln!(w, "    {prefix} {label}");
            if verbose {
                if let Some(ref line) = signal.matched_line {
                    let _ = writeln!(w, "         {} {}", ">".dimmed(), line.dimmed());
                }
            }
        }
        if result.signals.iter().any(|s| s.role == crate::shared::scoring::SignalRole::Fact) {
            let _ = writeln!(
                w,
                "    {} declared as facts: normal for this package shape; they do not lower the score",
                "--".dimmed()
            );
        }
    }
}

/// Print scan result as JSON.
pub fn print_json(result: &ScanResult) {
    let json = serde_json::to_string_pretty(result).expect("Failed to serialize");
    println!("{json}");
}
