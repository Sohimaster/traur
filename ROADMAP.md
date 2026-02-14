# Roadmap

## ~~`-bin` source verification~~ (done)
Cross-reference PKGBUILD `url=` (upstream project) against `source=()` download domains. Flag when a `-bin` package downloads from a different GitHub org/domain than the declared upstream. Catches fork impersonation and attacker-controlled repos masquerading as official releases.

## ~~Hook fail-open fix~~ (done)
The ALPM hook continues the transaction if `build_context` errors (e.g. git clone hangs). Add timeouts to git operations and fail closed — block the transaction on scan failure rather than silently bypassing. This is a security bug, not a feature.

## GitHub stars checking
Fetch star count from the upstream GitHub repo (parsed from PKGBUILD `url=`). Low or zero stars on a package claiming to be popular is a trust signal. Helps distinguish legitimate projects from throwaway repos.

## Recent AUR comments checking
Pull recent comments from the AUR package page and scan for keywords indicating bugs, errors, or malware reports. User reports are an early warning signal that often surfaces before maintainers act.

## Show signals report for all packages
Currently the detailed signals breakdown only appears for sketchy/suspicious/malicious tiers. Show it for all packages (including trusted/ok) so users always see what was analyzed.

## PKGBUILD diff checking
On update, diff the new PKGBUILD against the previously cached version. Flag newly introduced suspicious patterns, removed checksums, or significant structural changes. Catches supply-chain attacks that slip malicious lines into an otherwise trusted package.
