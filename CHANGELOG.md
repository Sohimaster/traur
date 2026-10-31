# Changelog

## 0.5.0

### Fixed

- **False SKETCHY on packages with long checksums** (#11, #27): the Monero branch of
  `P-CRYPTO-WALLET` had no word boundaries, so a 95-character run inside a `sha512sums`
  entry matched. `google-chrome` scored 60/100 with a phantom "cryptocurrency wallet"
  signal. The regex now requires word boundaries, and no pattern is matched against
  checksum arrays at all.
- **Quote-splitting bypassed the download-and-execute gate** (#23): `cu""rl ... | ba""sh`
  scored SKETCHY because patterns match literal text. Quote removal now runs before
  matching, so split command names resolve to `curl ... | bash` and fire `P-CURL-PIPE`.
  New `SA-QUOTE-SPLIT-EXEC` signal covers the shell-analysis path.
- **The hook silently allowed unscanned installs when the AUR was unreachable** (#24):
  an HTTP failure was indistinguishable from "not on the AUR", so every package was
  skipped and the transaction continued. The hook now blocks, with
  `TRAUR_ALLOW_OFFLINE=1` as an escape hatch for environments that isolate hook
  networking (CachyOS).
- **`source=("$file"::"$url")` counted as three entries** (#13): the `name::url` form
  produced a bogus `P-CHECKSUM-MISMATCH`. It now counts as one.
- **Heredoc entropy fired on generated shell scripts** (#13): byte entropy is high for
  any text using many distinct ASCII characters, so heredocs that write out bash
  wrappers looked like payloads. `SA-HIGH-ENTROPY-HEREDOC` now also requires a body
  that looks encoded (under 5% whitespace, over 85% base64-like characters).
- **`P-BASE64` fired on base64-encoded maintainer addresses** (#12): the leading
  comment block is skipped when matching, so `# Maintainer: x <$(echo ... | base64 -d)>`
  no longer scores 60 points. The same call in `build()` or `package()` still does.
- **AUR comment analysis returned nothing for every package**: the live page emits
  `<div id="comment-..." class="article-content">`, but the regex required `class` to
  come first. Contributed by @joaovitorbf (#15).
- **`traur clean <name>` could delete arbitrary directories**: the package name was
  joined onto the cache path unchecked, so `traur clean ../../../x` removed `x`. Names
  are now validated and the resolved path must stay inside the cache (PR #21).

### Added

- **Atomic Arch (2026) coverage** (#25): build-time `npm`/`bun`/`yarn`/`pnpm` installs,
  installs from remote tarball URLs, the `atomic-lockfile` and `js-digest` payload
  names (override gate), eBPF program loading and BPF filesystem writes, and access to
  `.aws`, `.docker`, `.npmrc`, `.netrc`, gh, kube and gcloud credential stores.
- **Published compromise list** (#17): packages on the shared list of compromised AUR
  packages score 0/100 through `B-MALICIOUS-LIST`. The list is cached for 12 hours and
  degrades to no signal when offline.
- **New dependency detection** in PKGBUILD diffs (`T-DIFF-NEW-DEP-NPM-BUN`, +50):
  contributed by @hirak99 (#20).
- **`traur clean [package]`**: removes one cached clone, or the whole git cache.
- **`traur scan --notify`** and a packaged `traur-scan.timer` for unattended daily
  scanning that only reports when something is flagged (#8).
- **`makepkg` wrapper** (`/usr/share/traur/makepkg-wrapper.sh`): scans the PKGBUILD
  before `build()` runs, for yay and paru, since the ALPM hook fires after the build
  (#16, #19).
- **CI release workflow** (`.github/workflows/release.yml`): release binaries are built
  from the tag on GitHub's runners and published with a `.sha256` file (#10).
  `CONTRIBUTING.md` documents how to verify a download.

### Changed

- Packaging sets the executable bit explicitly and adds `rust` to `makedepends` (#3).
- `.gitignore` covers makepkg output.

## 0.4.1

### Fixed
- **Hook fail-closed**: the ALPM hook now blocks the transaction when scans fail (git timeout, network error, etc.) instead of silently allowing unscanned packages through. Git clone/pull operations have a 30-second timeout to prevent indefinite hangs.

### Added
- **`-bin` source verification** (`bin_source_verification`): cross-references a `-bin` package's declared upstream URL against its `source=()` download domains. Detects fork impersonation when a package claims one GitHub org as upstream but downloads binaries from a different org. Emits `B-BIN-GITHUB-ORG-MISMATCH` (+50) and `B-BIN-DOMAIN-MISMATCH` (+30) behavioral signals.
- **Orphan takeover detection** (`orphan_takeover_analysis`): New feature that deserializes the `Submitter` field from AUR RPC and compares it against the current `Maintainer`. Emits `B-SUBMITTER-CHANGED` (+15, Behavioral) when they differ, and `B-ORPHAN-TAKEOVER` (+50, Behavioral) when combined with a git author change on an established package (>90 days). Detects the acroread-style attack vector where an attacker adopts an orphaned package and injects malicious code.
- `AurPackage` now deserializes `submitter` and `last_modified` from AUR RPC v5 responses.
