# Metadata Analysis

Analyzes AUR RPC metadata for reputation and completeness signals.

## What it detects

- **Zero votes** (M-VOTES-ZERO, +30): No community vetting at all
- **Low votes** (M-VOTES-LOW, +20): Minimal community vetting (<5)
- **Zero popularity** (M-POP-ZERO, +25): No recent usage (popularity uses 0.98^days decay)
- **Orphaned** (M-NO-MAINTAINER, +20): No maintainer — Xeactor attack vector
- **No URL** (M-NO-URL, +15): Missing upstream project URL
- **No license** (M-NO-LICENSE, +10): Missing license
- **Out of date** (M-OUT-OF-DATE, +5): Flagged as outdated

## Signals emitted

All signals use `SignalCategory::Metadata` (weight 0.15).

## Dependencies

- `PackageContext.metadata` — `AurPackage` from AUR RPC API

## Known false positives

HIGH rate (~40%). Many legitimate niche packages have zero votes and zero popularity. This category serves as supporting context, not standalone evidence. Weight is only 0.15.
