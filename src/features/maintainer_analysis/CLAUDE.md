# Maintainer Analysis

Evaluates maintainer reputation using their AUR package portfolio and timing patterns.

## What it detects

- **New single-package maintainer** (B-MAINTAINER-NEW, +30): Maintainer has only 1 package, created <30 days ago
- **Single-package maintainer** (B-MAINTAINER-SINGLE, +15): Maintainer has only 1 package (older)
- **Batch upload** (B-MAINTAINER-BATCH, +45): Maintainer created 3+ packages within 48 hours — the CHAOS RAT pattern (danikpapas uploaded 3 malicious packages on the same day)

## Signals emitted

All signals use `SignalCategory::Behavioral` (weight 0.25).

## Dependencies

- `PackageContext.metadata` — for `first_submitted` timestamp
- `PackageContext.maintainer_packages` — list of all packages by this maintainer (fetched via `shared/aur_rpc.rs` `fetch_maintainer_packages()`)

## Known false positives

- `B-MAINTAINER-SINGLE` (~25%): Many legitimate first-time AUR contributors maintain a single package. Low points (15) reflect this.
- `B-MAINTAINER-BATCH` (~5%): Maintainers who package a software suite (e.g., multiple related tools) may trigger this. Moderate points (45) because batch uploads by new accounts are genuinely suspicious.
