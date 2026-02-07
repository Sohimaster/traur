# Name Analysis

Detects typosquatting and impersonation through package name similarity analysis.

## What it detects

- **Impersonation** (B-NAME-IMPERSONATE, +65): Popular package name + suspicious suffix like `-fix`, `-patch`, `-cracked`, `-secure`, `-pro`, `-hack`, etc. This is the exact CHAOS RAT pattern (librewolf-fix-bin, firefox-patch-bin).
- **Typosquatting** (B-TYPOSQUAT, +55): Levenshtein edit distance <= 2 from a top popular package name.

## Signals emitted

All signals use `SignalCategory::Behavioral` (weight 0.25).

## Dependencies

- `PackageContext.name` — the package name to analyze
- `strsim` crate — Levenshtein distance computation
- Internal `TOP_PACKAGES` static — reference list of popular packages

## Known false positives

- `B-TYPOSQUAT` (~20%): Legitimate packages with similar names. The 2-edit threshold is conservative.
- `B-NAME-IMPERSONATE`: The suffix list is curated to minimize false positives. Normal AUR suffixes like `-bin`, `-git` are not flagged alone.

## Performance

`TOP_PACKAGES` is initialized once via `LazyLock` and reused across invocations.
