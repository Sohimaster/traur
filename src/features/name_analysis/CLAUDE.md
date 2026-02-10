# Name Analysis

Detects typosquatting and impersonation through package name similarity analysis.

## Metadata gate

All checks are skipped for packages with `num_votes >= 10`. Established packages with community validation cannot be typosquats — AUR names are unique and a real typosquat never survives to 10 votes. When metadata is `None` (offline mode), all string checks run.

## What it detects (new packages only)

- **Impersonation** (B-NAME-IMPERSONATE, +65): Popular package name + suspicious suffix like `-fix`, `-patch`, `-cracked`, `-secure`, `-pro`, `-hack`, etc. This is the exact CHAOS RAT pattern (librewolf-fix-bin, firefox-patch-bin).
- **Typosquatting** (B-TYPOSQUAT, +55): Two detection methods:
  1. Levenshtein edit distance == 1 from a top popular package name (catches single-char typos like "pary"→"paru").
  2. Prefix/suffix containment — name starts or ends with a popular package name (catches "yay2", "2vim").

## Signals emitted

All signals use `SignalCategory::Behavioral` (weight 0.25).

## Dependencies

- `PackageContext.name` — the package name to analyze
- `PackageContext.metadata` — AUR metadata for the vote gate
- `strsim` crate — Levenshtein distance computation
- Internal `TOP_PACKAGES` static — reference list of popular packages

## Performance

`TOP_PACKAGES` is initialized once via `LazyLock` and reused across invocations.
