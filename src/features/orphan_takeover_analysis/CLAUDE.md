# Orphan Takeover Analysis

Detects packages where the current maintainer is not the original submitter, a pattern used in the acroread AUR attack (2018).

## What it detects

- **Submitter changed** (B-SUBMITTER-CHANGED, +15): Current AUR maintainer differs from the original submitter. Low points because legitimate adoption is common.
- **Orphan takeover** (B-ORPHAN-TAKEOVER, +50): Composite signal requiring ALL of: submitter != maintainer, latest git author differs from prior authors, and the package is established (>90 days old). High-confidence indicator of malicious takeover.

## Signals emitted

All signals use `SignalCategory::Behavioral` (weight 0.25).

## Dependencies

- `PackageContext.metadata` — `submitter` and `maintainer` fields from AUR RPC
- `PackageContext.git_log` — git commit authors for composite signal

## Known false positives

- `B-SUBMITTER-CHANGED` (~30%): Many packages are legitimately adopted by new maintainers. Low points (15) reflect this.
- `B-ORPHAN-TAKEOVER` (~5%): Rare false positive — requires the specific combination of adoption + new git author + established package.
