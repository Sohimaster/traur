use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory};
use strsim::levenshtein;

/// Suspicious suffixes that indicate impersonation attempts.
const IMPERSONATION_SUFFIXES: &[&str] = &[
    "-fix",
    "-fixed",
    "-patch",
    "-patched",
    "-updated",
    "-secure",
    "-plus",
    "-mod",
    "-modded",
];

/// Popular brand names commonly targeted for impersonation.
const BRAND_NAMES: &[&str] = &[
    "firefox",
    "chromium",
    "chrome",
    "brave",
    "librewolf",
    "zen-browser",
    "discord",
    "slack",
    "telegram",
    "signal",
    "vscode",
    "code",
    "steam",
    "spotify",
    "obsidian",
    "1password",
    "bitwarden",
    "keepass",
];

pub struct NameAnalysis;

impl Feature for NameAnalysis {
    fn name(&self) -> &str {
        "name_analysis"
    }

    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        let mut signals = Vec::new();
        let name = &ctx.name;

        // Check impersonation suffixes against brand names
        for brand in BRAND_NAMES {
            for suffix in IMPERSONATION_SUFFIXES {
                let impersonation = format!("{brand}{suffix}");
                if name == &impersonation
                    || name == &format!("{impersonation}-bin")
                    || name == &format!("{impersonation}-git")
                {
                    signals.push(Signal {
                        id: "B-NAME-IMPERSONATE".to_string(),
                        category: SignalCategory::Behavioral,
                        points: 65,
                        description: format!(
                            "Name '{name}' looks like impersonation of '{brand}' with suspicious suffix"
                        ),
                        is_override_gate: false,
                    });
                    // Only fire once per package
                    return signals;
                }
            }
        }

        // Check typosquatting against top packages
        let top_packages = top_package_names();
        for top in &top_packages {
            if top == name {
                continue;
            }
            let dist = levenshtein(name, top);
            if dist > 0 && dist <= 2 {
                signals.push(Signal {
                    id: "B-TYPOSQUAT".to_string(),
                    category: SignalCategory::Behavioral,
                    points: 55,
                    description: format!(
                        "Name '{name}' is {dist} edit(s) away from popular package '{top}'"
                    ),
                    is_override_gate: false,
                });
                break;
            }
        }

        signals
    }
}

/// Returns a list of well-known popular package names for comparison.
/// In production this would be fetched/cached from AUR + official repos.
fn top_package_names() -> Vec<String> {
    // Hardcoded seed list of popular AUR + official packages.
    // TODO: auto-update from AUR RPC + pacman -Sql
    [
        "yay", "paru", "google-chrome", "spotify", "visual-studio-code-bin",
        "brave-bin", "discord", "slack-desktop", "zoom", "teams",
        "librewolf-bin", "zen-browser-bin", "firefox", "chromium",
        "steam", "lutris", "mangohud", "gamemode", "proton-ge-custom",
        "timeshift", "pamac-aur", "octopi", "downgrade",
        "nerd-fonts-complete", "ttf-ms-fonts", "obs-studio",
        "vlc", "mpv", "neovim", "vim", "emacs",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
