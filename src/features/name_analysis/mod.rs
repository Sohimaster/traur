use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory};
use std::sync::LazyLock;
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
    "-pro",
    "-premium",
    "-free",
    "-cracked",
    "-hack",
    "-custom",
    "-lite",
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
    "vlc",
    "mpv",
    "neovim",
    "gimp",
    "blender",
    "thunderbird",
    "protonvpn",
    "mullvad",
    "nordvpn",
    "tor-browser",
];

static TOP_PACKAGES: LazyLock<Vec<String>> = LazyLock::new(|| {
    [
        "yay",
        "paru",
        "google-chrome",
        "spotify",
        "visual-studio-code-bin",
        "brave-bin",
        "discord",
        "slack-desktop",
        "zoom",
        "teams",
        "librewolf-bin",
        "zen-browser-bin",
        "firefox",
        "chromium",
        "steam",
        "lutris",
        "mangohud",
        "gamemode",
        "proton-ge-custom",
        "timeshift",
        "pamac-aur",
        "octopi",
        "downgrade",
        "nerd-fonts-complete",
        "ttf-ms-fonts",
        "obs-studio",
        "vlc",
        "mpv",
        "neovim",
        "vim",
        "emacs",
        "gimp",
        "blender",
        "thunderbird",
        "protonvpn",
        "mullvad-vpn",
        "nordvpn-bin",
        "tor-browser",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
});

pub struct NameAnalysis;

impl Feature for NameAnalysis {
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
                        matched_line: None,
                    });
                    // Only fire once per package
                    return signals;
                }
            }
        }

        // Check typosquatting against top packages
        for top in TOP_PACKAGES.iter() {
            if top == name {
                continue;
            }
            let dist = levenshtein(name, top);
            if dist == 1 {
                signals.push(Signal {
                    id: "B-TYPOSQUAT".to_string(),
                    category: SignalCategory::Behavioral,
                    points: 55,
                    description: format!(
                        "Name '{name}' is {dist} edit(s) away from popular package '{top}'"
                    ),
                    is_override_gate: false,
                    matched_line: None,
                });
                break;
            }
        }

        // Check if name embeds a popular package as prefix/suffix (no hyphen boundary)
        for top in TOP_PACKAGES.iter() {
            if name == top.as_str() || name.len() <= top.len() {
                continue;
            }
            let is_prefix = name.starts_with(top.as_str());
            let is_suffix = name.ends_with(top.as_str());
            if is_prefix || is_suffix {
                signals.push(Signal {
                    id: "B-TYPOSQUAT".to_string(),
                    category: SignalCategory::Behavioral,
                    points: 55,
                    description: format!(
                        "Name '{name}' embeds popular package '{top}'"
                    ),
                    is_override_gate: false,
                    matched_line: None,
                });
                break;
            }
        }

        signals
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze(name: &str) -> Vec<String> {
        let ctx = PackageContext {
            name: name.into(),
            metadata: None,
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
        };
        NameAnalysis.analyze(&ctx).iter().map(|s| s.id.clone()).collect()
    }

    fn has(ids: &[String], id: &str) -> bool {
        ids.iter().any(|s| s == id)
    }

    #[test]
    fn impersonate_suffix() {
        assert!(has(&analyze("firefox-fix"), "B-NAME-IMPERSONATE"));
        assert!(has(&analyze("discord-cracked-bin"), "B-NAME-IMPERSONATE"));
        assert!(has(&analyze("librewolf-patched-bin"), "B-NAME-IMPERSONATE"));
    }

    #[test]
    fn typosquat_edit_distance() {
        assert!(has(&analyze("pary"), "B-TYPOSQUAT")); // 1 edit from "paru"
        assert!(!has(&analyze("rad"), "B-TYPOSQUAT"), "2 edits from 'yay', should not flag");
    }

    #[test]
    fn typosquat_containment() {
        assert!(has(&analyze("yay2"), "B-TYPOSQUAT")); // prefix
        assert!(has(&analyze("2vim"), "B-TYPOSQUAT")); // suffix
        assert!(has(&analyze("yay-bin"), "B-TYPOSQUAT")); // prefix with hyphen
        assert!(!has(&analyze("myay-bin"), "B-TYPOSQUAT"), "No prefix/suffix match");
    }

    #[test]
    fn exact_match_no_typosquat() {
        assert!(!has(&analyze("yay"), "B-TYPOSQUAT"), "Exact match should not flag");
        assert!(!has(&analyze("firefox"), "B-TYPOSQUAT"));
    }

    #[test]
    fn normal_name_no_signals() {
        let ids = analyze("my-custom-tool");
        assert!(ids.is_empty(), "Normal name should trigger no signals, got: {ids:?}");
    }
}
