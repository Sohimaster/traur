# Changelog

## Unreleased

### Fixed
- **Hook fail-closed**: the ALPM hook now blocks the transaction when scans fail (git timeout, network error, etc.) instead of silently allowing unscanned packages through. Git clone/pull operations have a 30-second timeout to prevent indefinite hangs.

### Added
- **`-bin` source verification** (`bin_source_verification`): cross-references a `-bin` package's declared upstream URL against its `source=()` download domains. Detects fork impersonation when a package claims one GitHub org as upstream but downloads binaries from a different org. Emits `B-BIN-GITHUB-ORG-MISMATCH` (+50) and `B-BIN-DOMAIN-MISMATCH` (+30) behavioral signals.
- **Orphan takeover detection** (`orphan_takeover_analysis`): New feature that deserializes the `Submitter` field from AUR RPC and compares it against the current `Maintainer`. Emits `B-SUBMITTER-CHANGED` (+15, Behavioral) when they differ, and `B-ORPHAN-TAKEOVER` (+50, Behavioral) when combined with a git author change on an established package (>90 days). Detects the acroread-style attack vector where an attacker adopts an orphaned package and injects malicious code.
- `AurPackage` now deserializes `submitter` and `last_modified` from AUR RPC v5 responses.
