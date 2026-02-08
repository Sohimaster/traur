# Changelog

## Unreleased

### Added
- **Orphan takeover detection** (`orphan_takeover_analysis`): New feature that deserializes the `Submitter` field from AUR RPC and compares it against the current `Maintainer`. Emits `B-SUBMITTER-CHANGED` (+15, Behavioral) when they differ, and `B-ORPHAN-TAKEOVER` (+50, Behavioral) when combined with a git author change on an established package (>90 days). Detects the acroread-style attack vector where an attacker adopts an orphaned package and injects malicious code.
- `AurPackage` now deserializes `submitter` and `last_modified` from AUR RPC v5 responses.
