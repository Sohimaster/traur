# Checksum Analysis

Verifies integrity of source checksum declarations in PKGBUILDs.

## What it detects

- **No checksums**: No checksum array at all (P-NO-CHECKSUMS, +30)
- **All SKIP**: Every checksum is 'SKIP' on non-VCS packages (P-SKIP-ALL, +25)
- **Weak algorithms**: md5sums without stronger alternative (P-WEAK-CHECKSUMS, +10)
- **Count mismatch**: Source count != checksum count (P-CHECKSUM-MISMATCH, +40)

## Signals emitted

All signals use `SignalCategory::Pkgbuild` (weight 0.45). Implemented directly in code (not patterns.toml) because checksum analysis requires counting logic beyond simple regex.

## Dependencies

- `PackageContext.pkgbuild_content` — the PKGBUILD content to analyze

## Known false positives

- VCS packages (`-git`, `-svn`, `-hg`, `-bzr`) legitimately use `SKIP` checksums. The feature exempts these.
- `P-WEAK-CHECKSUMS` (+10): Some older upstream projects only provide md5 hashes. Low points reflect this.
