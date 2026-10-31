use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory, SignalRole};
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

/// Suffixes and infixes that AUR uses to mark a *legitimate* variant of a
/// package: a prebuilt binary, a VCS snapshot, a desktop-specific build.
///
/// `slack-desktop-wayland` embeds `slack-desktop` and `vim-git` embeds `vim`;
/// reporting those as typosquats was a false positive (FIX.md item 2). A name
/// that is a top package plus shape suffixes is a variant, not an impostor.
const VARIANT_SUFFIXES: &[&str] = &[
    "-bin", "-git", "-svn", "-hg", "-bzr", "-cvs", "-nightly", "-stable",
    "-beta", "-alpha", "-dev", "-debug", "-headers", "-libs", "-docs", "-doc",
    "-wayland", "-x11", "-vulkan", "-cuda", "-rocm", "-opencl", "-gles",
    "-qt5", "-qt6", "-gtk3", "-gtk4", "-lite", "-full", "-minimal",
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
        if let Some(ref meta) = ctx.metadata {
            if meta.num_votes >= 10 {
                return Vec::new();
            }
        }

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
                        role: SignalRole::Provenance,
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
                    role: SignalRole::Provenance,
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

        // Check if the name embeds a popular package.
        //
        // Only an *impostor* shape counts. `top` plus recognised variant
        // suffixes (`-bin`, `-git`, `-wayland`, ...) is how AUR names real
        // variants, so it is reported as a fact at zero points. Anything else
        // that merely embeds a popular name keeps the behavioural signal.
        for top in TOP_PACKAGES.iter() {
            if name == top.as_str() || name.len() <= top.len() {
                continue;
            }
            let is_prefix = name.starts_with(top.as_str());
            let is_suffix = name.ends_with(top.as_str());
            if !(is_prefix || is_suffix) {
                continue;
            }
            let remainder = if is_prefix {
                &name[top.len()..]
            } else {
                &name[..name.len() - top.len()]
            };
            if stripped_variant_suffixes(remainder).is_none() {
                signals.push(Signal {
                    id: "B-TYPOSQUAT".to_string(),
                    category: SignalCategory::Behavioral,
                    role: SignalRole::Provenance,
                    points: 55,
                    description: format!("Name '{name}' embeds popular package '{top}'"),
                    is_override_gate: false,
                    matched_line: None,
                });
                break;
            }
        }

        signals
    }
}

/// Strip recognised variant suffixes from `remainder`.
///
/// Returns `Some(())` when nothing is left, i.e. the name is exactly a top
/// package plus shape markers. Returns `None` when unrecognised text remains,
/// which keeps genuine typosquats scored.
fn stripped_variant_suffixes(remainder: &str) -> Option<()> {
    let mut rest = remainder;
    if rest.is_empty() {
        return Some(());
    }
    // Allow a leading separator so `-bin` and `bin` both reduce to nothing.
    loop {
        if rest.is_empty() {
            return Some(());
        }
        if let Some(stripped) = VARIANT_SUFFIXES
            .iter()
            .find_map(|s| rest.strip_prefix(s))
        {
            rest = stripped;
            continue;
        }
        return None;
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
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
            local_sources: vec![],
            source_path: None,
            incomplete: vec![],
        };
        NameAnalysis.analyze(&ctx).iter().map(|s| s.id.clone()).collect()
    }

    fn analyze_with_votes(name: &str, votes: u32) -> Vec<String> {
        use crate::shared::models::AurPackage;
        let ctx = PackageContext {
            name: name.into(),
            metadata: Some(AurPackage {
                name: name.into(),
                package_base: None,
                url: None,
                num_votes: votes,
                popularity: 0.0,
                out_of_date: None,
                maintainer: None,
                submitter: None,
                first_submitted: 0,
                last_modified: 0,
                license: None,
            }),
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
            local_sources: vec![],
            source_path: None,
            incomplete: vec![],
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
        assert!(!has(&analyze("myay-bin"), "B-TYPOSQUAT"), "No prefix/suffix match");
        // A shape suffix is how AUR names a real variant, not an impostor.
        // This used to fire; FIX.md item 2 reports it as a false positive.
        assert!(!has(&analyze("yay-bin"), "B-TYPOSQUAT"));
        assert!(!has(&analyze("slack-desktop-wayland"), "B-TYPOSQUAT"));
        assert!(!has(&analyze("vim-git"), "B-TYPOSQUAT"));
        assert!(!has(&analyze("proton-ge-custom-bin"), "B-TYPOSQUAT"));
        // A real impersonation suffix still fires.
        assert!(has(&analyze("yay-fixed"), "B-TYPOSQUAT"));
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

    #[test]
    fn established_packages_skip_all_name_signals() {
        // Packages with enough votes skip all name-based checks
        assert!(analyze_with_votes("pary", 50).is_empty());
        assert!(analyze_with_votes("firefox-fix", 50).is_empty());
        assert!(analyze_with_votes("yay2", 50).is_empty());
        assert!(analyze_with_votes("python-steam", 37).is_empty());
        assert!(analyze_with_votes("proton-ge-custom-bin", 267).is_empty());
    }

    #[test]
    fn new_packages_still_checked() {
        assert!(has(&analyze_with_votes("pary", 0), "B-TYPOSQUAT"));
        assert!(has(&analyze_with_votes("firefox-fix", 0), "B-NAME-IMPERSONATE"));
        assert!(has(&analyze_with_votes("yay2", 0), "B-TYPOSQUAT"));
    }

    #[test]
    fn no_metadata_runs_all_checks() {
        // analyze() uses metadata: None — all string checks run
        assert!(has(&analyze("pary"), "B-TYPOSQUAT"));
        assert!(has(&analyze("firefox-fix"), "B-NAME-IMPERSONATE"));
        assert!(has(&analyze("yay2"), "B-TYPOSQUAT"));
    }
}
