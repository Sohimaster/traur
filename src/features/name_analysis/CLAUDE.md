# Name Analysis

Detects typosquatting and impersonation through package name similarity analysis.

## What it detects

- **Impersonation** (B-NAME-IMPERSONATE, +65): Popular package name + suspicious suffix like `-fix`, `-patch`, `-patched`, `-secure`, `-plus`. This is the exact CHAOS RAT pattern (librewolf-fix-bin, firefox-patch-bin).
- **Typosquatting** (B-TYPOSQUAT, +55): Levenshtein edit distance <= 2 from a top-500 popular package name.

## Signals emitted

All signals use `SignalCategory::Behavioral` (weight 0.25).

## Dependencies

- `PackageContext.name` — the package name to analyze
- `strsim` crate — Levenshtein distance computation
- Internal `top_package_names()` — reference list of popular packages (TODO: auto-update from AUR RPC + `pacman -Sql`)

## Known false positives

- `B-TYPOSQUAT` (~20%): Legitimate packages with similar names (e.g., `vim-plug` vs `vim-pluf`). The 2-edit threshold is conservative.
- `B-NAME-IMPERSONATE`: The suffix list (`-fix`, `-patch`, etc.) is curated to minimize false positives. Normal AUR suffixes like `-bin`, `-git` are not flagged.
