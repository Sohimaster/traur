// Family: reputation
// Agenda: name-check
// Description: Intelligent typosquatting and brand impersonation detection with reputation context.

fn scan(pkg) {
    let name = pkg.name;
    let has_votes = pkg.metadata != () && pkg.metadata.num_votes > 0;
    let established = pkg.metadata != () && pkg.metadata.num_votes >= 10;
    let new_pkg = pkg.metadata != () && pkg.metadata.first_submitted > (now_timestamp() - 7*24*3600);
    
    // Skip analysis for established packages (low false positive rate)
    if established {
        return [];
    }

    let brand_names = ["firefox", "chromium", "chrome", "brave", "librewolf", "zen-browser", "discord", "slack", "telegram", "signal", "vscode", "code", "steam", "spotify", "obsidian", "1password", "bitwarden", "keepass", "vlc", "mpv", "neovim", "gimp", "blender", "thunderbird", "protonvpn", "mullvad", "nordvpn", "tor-browser"];
    let impersonation_suffixes = ["-fix", "-fixed", "-patch", "-patched", "-updated", "-secure", "-plus", "-mod", "-modded", "-pro", "-premium", "-free", "-cracked", "-hack", "-custom", "-lite"];
    let top_packages = ["yay", "paru", "google-chrome", "spotify", "visual-studio-code-bin", "brave-bin", "discord", "slack-desktop", "zoom", "teams", "librewolf-bin", "zen-browser-bin", "firefox", "chromium", "steam", "lutris", "mangohud", "gamemode", "proton-ge-custom", "timeshift", "pamac-aur", "octopi", "downgrade", "nerd-fonts-complete", "ttf-ms-fonts", "obs-studio", "vlc", "mpv", "neovim", "vim", "emacs", "gimp", "blender", "thunderbird", "protonvpn", "mullvad-vpn", "nordvpn-bin", "tor-browser"];

    // HIGH CONFIDENCE: Brand impersonation with suspicious suffix
    for brand in brand_names {
        for suffix in impersonation_suffixes {
            let imp = brand + suffix;
            if name == imp || name == imp + "-bin" || name == imp + "-git" {
                // Context: new package + impersonation = very suspicious
                if new_pkg {
                    return [#{id: "R-NAME-IMPERSONATE-NEW", verdict: "malicious", reason: "New package '" + name + "' impersonates '" + brand + "'"}];
                }
                // Without votes or recent = suspicious
                if !has_votes {
                    return [#{id: "R-NAME-IMPERSONATE", verdict: "suspicious", reason: "Package '" + name + "' impersonates '" + brand + "' with no community adoption"}];
                }
            }
        }
    }

    // MEDIUM CONFIDENCE: Levenshtein edit distance = 1 from top package
    for top in top_packages {
        if top == name { continue; }
        if levenshtein(name, top) == 1 {
            if new_pkg {
                return [#{id: "R-TYPOSQUAT-NEW", verdict: "suspicious", reason: "New package '" + name + "' one char away from '" + top + "'"}];
            }
            if !has_votes {
                return [#{id: "R-TYPOSQUAT", verdict: "suspicious", reason: "Package '" + name + "' appears to be typosquat of '" + top + "'"}];
            }
        }
    }

    // LOW-MEDIUM CONFIDENCE: Name embedding (contains popular package name)
    for top in top_packages {
        if name == top || name.len() <= top.len() { continue; }
        if name.contains(top) {
            if new_pkg {
                return [#{id: "R-NAME-EMBEDDING-NEW", verdict: "suspicious", reason: "New package '" + name + "' embeds popular name '" + top + "'"}];
            }
            if !has_votes {
                return [#{id: "R-NAME-EMBEDDING", verdict: "ok", reason: "Package '" + name + "' embeds popular package '" + top + "'"}];
            }
        }
    }

    return [];
}
