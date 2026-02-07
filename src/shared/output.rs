use crate::shared::scoring::{ScanResult, Tier};
use colored::Colorize;

/// Print scan result as colored terminal text.
pub fn print_text(result: &ScanResult, verbose: bool) {
    let tier_colored = match result.tier {
        Tier::Low => result.tier.to_string().green(),
        Tier::Medium => result.tier.to_string().yellow(),
        Tier::High => result.tier.to_string().truecolor(255, 165, 0), // orange
        Tier::Critical => result.tier.to_string().red(),
        Tier::Malicious => result.tier.to_string().red().bold(),
    };

    eprintln!(
        "{} {} (score: {}/100)",
        "traur:".bold(),
        result.package.bold(),
        result.score
    );
    eprintln!("  Tier: {tier_colored}");

    if let Some(ref gate) = result.override_gate_fired {
        eprintln!("  {} Override gate fired: {gate}", "!!".red().bold());
    }

    if !result.signals.is_empty() {
        eprintln!("  Signals:");
        for signal in &result.signals {
            let prefix = if signal.is_override_gate {
                "!!".red().bold().to_string()
            } else if signal.points >= 60 {
                "!!".red().to_string()
            } else if signal.points >= 30 {
                " !".yellow().to_string()
            } else {
                "  ".to_string()
            };
            eprintln!(
                "    {prefix} [{:>3}] {}: {}",
                signal.points, signal.id, signal.description
            );
            if verbose {
                if let Some(ref line) = signal.matched_line {
                    eprintln!("             {} {}", ">".dimmed(), line.dimmed());
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
