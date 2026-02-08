# Name Analysis

Detects typosquatting and impersonation through package name similarity analysis.

## What it detects

- **Impersonation** (B-NAME-IMPERSONATE, +65): Popular package name + suspicious suffix like `-fix`, `-patch`, `-cracked`, `-secure`, `-pro`, `-hack`, etc. This is the exact CHAOS RAT pattern (librewolf-fix-bin, firefox-patch-bin).
- **Typosquatting** (B-TYPOSQUAT, +55): Two detection methods:
  1. Levenshtein edit distance == 1 from a top popular package name (catches single-char typos like "pary"→"paru").
  2. Prefix/suffix containment — name starts or ends with a popular package name (catches "yay2", "yay-bin", "2vim").

## Signals emitted

All signals use `SignalCategory::Behavioral` (weight 0.25).

## Dependencies

- `PackageContext.name` — the package name to analyze
- `strsim` crate — Levenshtein distance computation
- Internal `TOP_PACKAGES` static — reference list of popular packages

## Known false positives

- `B-TYPOSQUAT`: Containment check may flag legitimate derivative packages that don't use hyphen-separated naming.
- `B-NAME-IMPERSONATE`: The suffix list is curated to minimize false positives. Normal AUR suffixes like `-bin`, `-git` are not flagged alone.

## Performance

`TOP_PACKAGES` is initialized once via `LazyLock` and reused across invocations.
