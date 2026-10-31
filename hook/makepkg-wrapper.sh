#!/bin/bash
# Scan AUR PKGBUILDs with traur before makepkg builds them.
#
# Install as /usr/local/bin/makepkg (it shadows /usr/bin/makepkg in PATH).
# Only fires inside an AUR helper's build cache, so local builds are untouched.
#
# Why this exists: the ALPM hook is PreTransaction, which runs after makepkg has
# already executed build(). A payload in build() has run by then. Scanning here
# happens before the build starts.
#
# Reported issues this handles:
#  - only scan real build invocations, not yay's metadata/query passes, so we
#    never corrupt the stdout yay parses (#19)
#  - fall back to pkgname[0] when pkgbase is unset
#  - read the verdict from --json so a failed scan is not treated as trusted

set -o pipefail

if [[ -t 2 ]]; then
    ALL_OFF="$(tput sgr0)"; BOLD="$(tput bold)"; GREEN="${BOLD}$(tput setaf 2)"; YELLOW="${BOLD}$(tput setaf 3)"
else
    ALL_OFF=""; BOLD=""; GREEN=""; YELLOW=""
fi
tmsg()  { printf '%s==>%s%s %s%s\n' "$GREEN"  "$ALL_OFF" "$BOLD" "$1" "$ALL_OFF" >&2; }
twarn() { printf '%s==> WARNING:%s%s %s%s\n' "$YELLOW" "$ALL_OFF" "$BOLD" "$1" "$ALL_OFF" >&2; }

# Commands always passed straight through. Anything that queries the PKGBUILD
# rather than building it must not be intercepted.
for arg in "$@"; do
    case "$arg" in
        --printsrcinfo|--packagelist|--verifysource|--nobuild|-o|--allsource|-S|--source|--geninteg|-g)
            exec /usr/bin/makepkg "$@";;
    esac
done

[[ -f PKGBUILD ]] || exec /usr/bin/makepkg "$@"

# Only scan inside an AUR helper's build directory.
yay_cache="${XDG_CACHE_HOME:-$HOME/.cache}/yay"
paru_cache="${XDG_CACHE_HOME:-$HOME/.cache}/paru"
case "$PWD/" in
    "$yay_cache/"*|"$paru_cache/"*) ;;
    *) exec /usr/bin/makepkg "$@";;
esac

# Resolve the package name the way makepkg does.
pkgbase=$(bash -c 'source PKGBUILD >/dev/null 2>&1; printf "%s" "${pkgbase:-${pkgname[0]}}"' 2>/dev/null)
[[ -n "$pkgbase" ]] || exec /usr/bin/makepkg "$@"

tmsg "traur: scanning $pkgbase..."
# Scan the whole directory once: the PKGBUILD alone misses the .install script
# pacman will run and any committed source=() file that build() can source.
# One scan only: a second invocation would repeat the work and the prompt.
# stdout from traur stays captured so yay's own parsing is never disturbed.
scan_json=$(traur scan --dir "$PWD" --json 2>/dev/null)
# Render the report from the same JSON so the summary and the decision cannot
# disagree.
tier=$(printf '%s\n' "$scan_json" | sed -n 's/.*"tier"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
score=$(printf '%s\n' "$scan_json" | sed -n 's/.*"score"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' | head -1)
reason=$(printf '%s\n' "$scan_json" | sed -n 's/.*"reason"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
tmsg "traur: $pkgbase — ${tier:-no verdict} (trust: ${score:-?}/100)"

case "$tier" in
    Trusted)
        exec /usr/bin/makepkg "$@";;
    Ok|Sketchy)
        printf '%s==>%s %s is %s. Continue? [Y/n]%s ' "$YELLOW" "$ALL_OFF" "$pkgbase" "$tier" "$ALL_OFF" >/dev/tty
        read -r reply < /dev/tty
        [[ "$reply" =~ ^[Nn]$ ]] && { tmsg "aborted"; exit 1; }
        ;;
    Suspicious|Malicious)
        twarn "$pkgbase is $tier"
        printf '%s==> WARNING:%s Continue anyway? [y/N]%s ' "$YELLOW" "$ALL_OFF" "$ALL_OFF" >/dev/tty
        read -r reply < /dev/tty
        [[ "$reply" =~ ^[Yy]$ ]] || { tmsg "aborted"; exit 1; }
        ;;
    Unknown)
        # The scan could not conclude: this is not a verdict in either
        # direction. Say why, and do not imply the package is suspicious.
        twarn "traur could not conclude for $pkgbase${reason:+: $reason}"
        printf '%s==>%s This is not a verdict; the package was neither verified nor found suspicious.%s\n' \
            "$YELLOW" "$ALL_OFF" "$ALL_OFF" >/dev/tty
        printf '%s==> WARNING:%s Continue without a verdict? [y/N]%s ' "$YELLOW" "$ALL_OFF" "$ALL_OFF" >/dev/tty
        read -r reply < /dev/tty
        [[ "$reply" =~ ^[Yy]$ ]] || { tmsg "aborted"; exit 1; }
        ;;
    *)
        twarn "traur could not determine a verdict for $pkgbase"
        printf '%s==> WARNING:%s Continue without a scan? [y/N]%s ' "$YELLOW" "$ALL_OFF" "$ALL_OFF" >/dev/tty
        read -r reply < /dev/tty
        [[ "$reply" =~ ^[Yy]$ ]] || { tmsg "aborted"; exit 1; }
        ;;
esac

exec /usr/bin/makepkg "$@"
