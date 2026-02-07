# Git History Analysis

Temporal signals from the AUR package git repository history.

## What it detects

- **Single commit** (T-SINGLE-COMMIT, +20): Only 1 commit in history — brand new, no iteration
- **New package** (T-NEW-PACKAGE, +25): Created within last 7 days (uses `metadata.first_submitted`, falls back to oldest commit)
- **Malicious diff** (T-MALICIOUS-DIFF, +55): Latest commit introduces network-related code (curl, wget, nc, socat) where none existed in the prior PKGBUILD version — the Xeactor attack pattern
- **Author change** (T-AUTHOR-CHANGE, +25): Multiple different authors in git history — possible account compromise or handoff

## Signals emitted

All signals use `SignalCategory::Temporal` (weight 0.15).

## Dependencies

- `PackageContext.git_log` — list of `GitCommit` structs with hash, author, timestamp, message, and optional diff
- `PackageContext.metadata` — for `first_submitted` timestamp (T-NEW-PACKAGE)
- `PackageContext.prior_pkgbuild_content` — PKGBUILD from HEAD~1 for diff comparison (T-MALICIOUS-DIFF)
- `shared/aur_git.rs` — git clone/pull/log/diff operations, `read_pkgbuild_at_revision()`

## Known false positives

- `T-AUTHOR-CHANGE` (~15%): Legitimate co-maintained packages have multiple authors. Moderate points.
- `T-NEW-PACKAGE` (~30%): Every package is new at some point. Low-weight category (0.15) ensures this alone doesn't cause false alarms.

## Performance

All regexes are compiled once via `LazyLock` statics and reused across invocations.
