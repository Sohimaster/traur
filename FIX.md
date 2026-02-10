# Complaints & Issues to Fix

Collected from [Reddit r/archlinux](https://www.reddit.com/r/archlinux/comments/1qyl2b4/aur_malware_scanner_in_rust/) and [EndeavourOS forum](https://forum.endeavouros.com/t/new-rust-tool-traur-analyzes-arch-aur-packages-for-hidden-risks/78001/22).

## High Priority

### ~~1. megasync `nc -c` false positive (MALICIOUS on legit package)~~
- ~~`P-REVSHELL-NC` fires on `git -C MEGAsync -c protocol.file.allow='always' submodule update` because it contains `nc -c`~~
- ~~Flags megasync as MALICIOUS via override gate~~
- ~~Source: EndeavourOS (dalto identified root cause)~~
- **Fixed**: Added `\b` word boundary before `(nc|ncat)` in P-REVSHELL-NC and G-BINDSHELL-NC patterns

### 2. Typosquat false positives on `-bin` variants and `python-*` wrappers
- `python-steam` flagged for embedding "steam"
- `proton-ge-custom-bin` flagged for embedding "proton-ge-custom"
- `-bin` suffix packages of real packages shouldn't trigger typosquat
- `python-*` prefix packages wrapping upstream libs shouldn't trigger typosquat
- Source: EndeavourOS (multiple users), Reddit

### ~~3. Hook asks confirmation for every package, even clean ones~~
- ~~Should only prompt on SKETCHY+ results, not TRUSTED/OK~~
- ~~"That hook is pretty annoying if you have a lot of AUR packages. It asks for confirmation one at a time for every AUR package you update even if there are no issues flagged." — dalto (EOS maintainer)~~
- ~~Source: EndeavourOS~~
- **Fixed**: Hook now collects results silently, shows tier summary, only prints detail for SKETCHY+ packages, and skips the prompt entirely when all packages are TRUSTED/OK. Only MALICIOUS hard-blocks.

### ~~4. Flag spacing bypass (`rm -r -f` vs `rm -rf`)~~
- ~~`rm -r -f /var/log` is not detected, only `rm -rf /var/log`~~
- ~~Patterns need to handle flag variations with spaces~~
- ~~Source: Reddit (ang-p)~~
- **Fixed**: Added flag-absorber regex fragments (`(-\S+\s+)*`, `(\S+\s+)*`, `[^;&|]*`) to 13 patterns across pkgbuild_analysis and install_script_analysis to handle split flags (`rm -r -f`), intervening flags (`chmod -v +x`), and flag+value pairs (`base64 -w 0 -d`)

## Medium Priority

### 5. SA-VAR-CONCAT-CMD too noisy
- Fires on nearly every package that uses `sh` or `python` in build scripts
- radarr, sonarr, peazip, python-ewmh, shell-color-scripts, python-steam, proton-ge-custom-bin all flagged
- Needs better heuristic to distinguish suspicious from normal build usage
- Source: EndeavourOS (appears in almost every user's results)

### 6. Checksum mismatch wording is confusing/alarming
- `source count (7) != sha256sums count (5)` — users think this means missing checksums are malicious
- Doesn't account for `source_x86_64`/`source_aarch64` having their own checksum arrays
- Doesn't account for SKIP entries
- Wording should be less alarming for common benign cases
- Source: EndeavourOS (fred666, multiple users)

### 7. freetube-bin checksum mismatch false positive
- `-bin` packages commonly use `source_x86_64` and `source_aarch64` with separate checksum arrays
- Cross-array count comparison is wrong for these
- Source: EndeavourOS (thefrog), Reddit

## Low Priority / Messaging

### 8. "Just a big grep against patterns.toml" perception
- Highlight shell_analysis, gtfobins_analysis, behavioral features more prominently
- ang-p: "essentially a big grep against patterns.toml"
- Source: Reddit

### 9. Branding as "trust engine" not "malware scanner"
- Reddit title said "malware scanner" — sets wrong expectations
- FanClubof5 (24 upvotes): "You might have better luck branding it as a trust engine"
- Source: Reddit

### 10. ALPM hook not "yay/paru hook"
- Hook is an ALPM hook (works with pacman too), not specific to AUR helpers
- Documentation should use correct terminology
- Source: Reddit (Hermocrates)

### 11. Rust packaging guidelines not followed in PKGBUILD
- Missing `prepare()` steps from Arch Rust package guidelines
- `--frozen` flag caused build failures for users with different dependency versions
- Source: Reddit (Hermocrates, NeKon69)
