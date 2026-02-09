# Roadmap

## ~~`-bin` source verification~~ (done)
Cross-reference PKGBUILD `url=` (upstream project) against `source=()` download domains. Flag when a `-bin` package downloads from a different GitHub org/domain than the declared upstream. Catches fork impersonation and attacker-controlled repos masquerading as official releases.

## ~~Hook fail-open fix~~ (done)
The ALPM hook continues the transaction if `build_context` errors (e.g. git clone hangs). Add timeouts to git operations and fail closed — block the transaction on scan failure rather than silently bypassing. This is a security bug, not a feature.
